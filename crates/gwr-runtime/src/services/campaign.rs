//! Campaign-stage standing services (S-2): propose, admit, consume, record
//! outcome, adjudicate.
//!
//! These services coordinate the store; the law lives in `gwr_core::campaign`.
//! Burn-before-effect is structural: `consume` makes the one consumption
//! durable before the caller runs any effect, and a second consumption hits
//! the crash-recovery classification and refuses — ambiguous states are never
//! guessed and re-run.
//!
//! The former campaign-stage `exact_repair` issuance/export path is retired.
//! Its persisted rows and artifact codecs remain readable as historical
//! evidence, but every live proposal, adjudication, standing, and export
//! entrypoint refuses that route.

use crate::ports::store::{CampaignBurn, Store, StoreError};
use gwr_core::campaign::adjudication::{
    AdjudicationReceipt, AdjudicationVerdict, ResidualStatement,
};
use gwr_core::campaign::authority::RepairAuthorityV1;
use gwr_core::campaign::proposal::CampaignStageProposal;
use gwr_core::campaign::standing::{
    classify, reexecution_decision, CampaignStageConsumption, CampaignStageStanding,
    ExecutionContext,
};
use gwr_core::digest::Sha256Digest;
use gwr_core::refusal::CampaignRefusal;
use gwr_core::work_request::ClockReading;

#[derive(Debug, PartialEq, Eq)]
pub enum CampaignError {
    Store(StoreError),
    Refusal(CampaignRefusal),
    /// The named proposal or standing is not recorded.
    NotFound(String),
}

impl From<StoreError> for CampaignError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<CampaignRefusal> for CampaignError {
    fn from(e: CampaignRefusal) -> Self {
        Self::Refusal(e)
    }
}

/// Record an exact stage proposal. Idempotent for an identical proposal; the
/// digest is the content address, so a rebind is impossible by construction.
/// Creates no standing.
pub fn propose_stage(
    store: &mut dyn Store,
    proposal: &CampaignStageProposal,
) -> Result<Sha256Digest, CampaignError> {
    refuse_legacy_repair_proposal(proposal)?;
    store.record_campaign_proposal(proposal)?;
    Ok(proposal.digest)
}

/// Admit a recorded proposal and issue the standing it justifies.
///
/// Historical campaign-stage repair proposals are readable from the store,
/// but admission refuses them. Current repair custody enters through the
/// separate governed-repair protocol.
pub fn admit(
    store: &mut dyn Store,
    proposal_digest: &Sha256Digest,
    now: ClockReading,
) -> Result<CampaignStageStanding, CampaignError> {
    let proposal = store
        .get_campaign_proposal(proposal_digest)?
        .ok_or_else(|| CampaignError::NotFound(format!("proposal {proposal_digest}")))?;
    refuse_legacy_repair_proposal(&proposal)?;
    let standing = CampaignStageStanding::issue(&proposal, now)?;
    store.record_campaign_standing(&standing)?;
    Ok(standing)
}

/// Retired campaign-stage repair-authority export.
///
/// The old artifact remains parseable by the archive codec, but there is no
/// current derivation/export office and archived bytes never regain authority.
pub fn export_repair_authority(
    _store: &mut dyn Store,
    _standing_digest: &Sha256Digest,
    _now: ClockReading,
    _verifier: &str,
) -> Result<RepairAuthorityV1, CampaignError> {
    Err(CampaignRefusal::LegacyRepairRouteRetired.into())
}

/// Retired campaign-stage repair-authority verification.
///
/// Archive parsing may check historical byte/content integrity. It is
/// deliberately not a current state-correspondence verifier.
pub fn verify_repair_authority(
    _store: &mut dyn Store,
    _bundle: &RepairAuthorityV1,
    _now: ClockReading,
    _verifier: &str,
) -> Result<(), CampaignError> {
    Err(CampaignRefusal::LegacyRepairRouteRetired.into())
}

/// Burn standing before the stage's effect runs. The consumption record is
/// durable before this call returns; the effect happens afterwards, outside
/// this runtime.
///
/// Refusals, in order: supersession (a newer standing exists for this stage;
/// the presented one is historical), the crash-recovery classification of any
/// existing burn (replay, ambiguous outcome, duplicate effect), then the
/// standing's own scope, expiry, and one-use validation. The fast-path reads
/// preserve this exact refusal vocabulary; the atomic burn re-decides
/// supersession and existence inside one immediate transaction, so exactly
/// one concurrent consumer — across threads, processes, and service
/// instances — receives success, and every other consumer receives the exact
/// classification of the durable winner's row.
pub fn consume(
    store: &mut dyn Store,
    standing_digest: &Sha256Digest,
    context: &ExecutionContext,
    now: ClockReading,
) -> Result<CampaignStageConsumption, CampaignError> {
    let standing = store
        .get_campaign_standing(standing_digest)?
        .ok_or_else(|| CampaignError::NotFound(format!("standing {standing_digest}")))?;
    if standing.stage_class().is_historical_repair() {
        return Err(CampaignRefusal::LegacyRepairRouteRetired.into());
    }
    if let Some(latest) = store.latest_campaign_standing(standing.campaign(), standing.stage())? {
        if standing.superseded_by(&latest) {
            return Err(CampaignRefusal::Superseded.into());
        }
    }
    let existing = store.get_campaign_consumption(standing_digest)?;
    reexecution_decision(classify(existing.as_ref()))?;
    let record = standing.preflight(context, now)?;
    match store.burn_campaign_standing(&standing, &record)? {
        CampaignBurn::Burned => Ok(record),
        CampaignBurn::Superseded => Err(CampaignRefusal::Superseded.into()),
        CampaignBurn::Existing(row) => Err(existing_burn_refusal(&row).into()),
    }
}

/// The exact refusal for a burn that already exists: the four-state
/// recovery classification of the durable row. A row is never
/// `EffectNotBegun`; the unreachable arm fails closed as `AlreadyConsumed`
/// rather than panic.
fn existing_burn_refusal(row: &CampaignStageConsumption) -> CampaignRefusal {
    match reexecution_decision(classify(Some(row))) {
        Err(refusal) => refusal,
        Ok(()) => CampaignRefusal::AlreadyConsumed,
    }
}

/// Record that the effect of a consumed standing completed, with the receipt
/// not yet known. Moves the durable classification from
/// consumed-outcome-unresolved to effect-completed-receipt-missing; both are
/// ambiguous and refuse re-execution.
pub fn record_effect_completed(
    store: &mut dyn Store,
    standing_digest: &Sha256Digest,
) -> Result<(), CampaignError> {
    if store.get_campaign_consumption(standing_digest)?.is_none() {
        return Err(CampaignError::NotFound(format!(
            "consumption for standing {standing_digest}"
        )));
    }
    let standing = store
        .get_campaign_standing(standing_digest)?
        .ok_or_else(|| CampaignError::NotFound(format!("standing {standing_digest}")))?;
    if standing.stage_class().is_historical_repair() {
        return Err(CampaignRefusal::LegacyRepairRouteRetired.into());
    }
    store.mark_campaign_effect_completed(standing_digest)?;
    Ok(())
}

/// Record the consuming receipt's digest (AG-NG effect/runtime receipt or
/// sidecar execution-envelope vocabulary), verbatim, once known. Implies
/// effect completion.
pub fn record_receipt(
    store: &mut dyn Store,
    standing_digest: &Sha256Digest,
    receipt: &Sha256Digest,
) -> Result<(), CampaignError> {
    if store.get_campaign_consumption(standing_digest)?.is_none() {
        return Err(CampaignError::NotFound(format!(
            "consumption for standing {standing_digest}"
        )));
    }
    let standing = store
        .get_campaign_standing(standing_digest)?
        .ok_or_else(|| CampaignError::NotFound(format!("standing {standing_digest}")))?;
    if standing.stage_class().is_historical_repair() {
        return Err(CampaignRefusal::LegacyRepairRouteRetired.into());
    }
    store.record_campaign_receipt(standing_digest, receipt)?;
    Ok(())
}

/// Adjudicate a review receipt for a stage as continue or refuse.
/// Historical `exact_repair` verdicts remain decodable but cannot be newly
/// recorded. The adjudicated review receipt must be one
/// this runtime recorded as the outcome of a consumed standing for this
/// campaign and stage — adjudicating a fictitious review refuses.
#[allow(clippy::too_many_arguments)]
pub fn adjudicate(
    store: &mut dyn Store,
    campaign: &str,
    stage: &str,
    review_receipt: &Sha256Digest,
    verdict: AdjudicationVerdict,
    adjudicator: &str,
    findings: Vec<String>,
    residuals: Vec<ResidualStatement>,
    now: ClockReading,
) -> Result<AdjudicationReceipt, CampaignError> {
    if verdict == AdjudicationVerdict::ExactRepair {
        return Err(CampaignRefusal::LegacyRepairRouteRetired.into());
    }
    let known = store.campaign_stage_receipts(campaign, stage)?;
    if !known.contains(review_receipt) {
        return Err(CampaignRefusal::AdjudicationSubjectUnknown.into());
    }
    let receipt = AdjudicationReceipt::adjudicate(
        campaign.to_string(),
        stage.to_string(),
        *review_receipt,
        verdict,
        adjudicator.to_string(),
        findings,
        residuals,
        now,
    )?;
    store.record_campaign_adjudication(&receipt)?;
    Ok(receipt)
}

fn refuse_legacy_repair_proposal(proposal: &CampaignStageProposal) -> Result<(), CampaignError> {
    if proposal.stage_class.is_historical_repair() || proposal.repair.is_some() {
        Err(CampaignRefusal::LegacyRepairRouteRetired.into())
    } else {
        Ok(())
    }
}
