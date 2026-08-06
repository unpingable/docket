//! Campaign-stage standing services (S-2): propose, admit, consume, record
//! outcome, adjudicate.
//!
//! These services coordinate the store; the law lives in `gwr_core::campaign`.
//! Burn-before-effect is structural: `consume` makes the one consumption
//! durable before the caller runs any effect, and a second consumption hits
//! the crash-recovery classification and refuses — ambiguous states are never
//! guessed and re-run.

use crate::ports::store::{CampaignBurn, Store, StoreError};
use gwr_core::campaign::adjudication::{
    AdjudicationReceipt, AdjudicationVerdict, ResidualStatement,
};
use gwr_core::campaign::proposal::{CampaignStageProposal, StageBasis};
use gwr_core::campaign::repair::validate_repair;
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
    store.record_campaign_proposal(proposal)?;
    Ok(proposal.digest)
}

/// Admit a recorded proposal and issue the standing it justifies.
///
/// For repair stage classes this is where the subset decision is made, and
/// the anchor is exact: the repair's predecessor basis cites the authorizing
/// adjudication by digest; the adjudication's rejected review receipt
/// resolves, through the durable consumption row that carries it, to the one
/// consumed standing of the original stage; that standing's
/// `proposal_digest` names the original stage authority. The subset check
/// runs against that proposal — never against the newest, earliest, or any
/// same-name record-only proposal, which carry no authority. The sidecar
/// never makes this decision.
pub fn admit(
    store: &mut dyn Store,
    proposal_digest: &Sha256Digest,
    now: ClockReading,
) -> Result<CampaignStageStanding, CampaignError> {
    let proposal = store
        .get_campaign_proposal(proposal_digest)?
        .ok_or_else(|| CampaignError::NotFound(format!("proposal {proposal_digest}")))?;
    if let Some(basis) = &proposal.repair {
        // The repair must cite the authorizing adjudication by exact digest
        // in its predecessor basis, naming the original stage.
        let cited = match &proposal.basis {
            StageBasis::PredecessorStage {
                stage,
                adjudication_digest,
            } if stage == &basis.original_stage => *adjudication_digest,
            _ => return Err(CampaignRefusal::RepairOriginalStageMismatch.into()),
        };
        let adjudication = store
            .get_campaign_adjudication(&cited)?
            .ok_or(CampaignRefusal::RepairAdjudicationUnknown)?;
        // A cited adjudication superseded by a newer adjudication of the
        // same review receipt authorizes nothing current.
        for other in store.get_campaign_adjudications(&proposal.campaign, &basis.original_stage)? {
            if other.digest != adjudication.digest
                && other.review_receipt == adjudication.review_receipt
                && other.adjudicated_at >= adjudication.adjudicated_at
            {
                return Err(CampaignRefusal::Superseded.into());
            }
        }
        // The original authority chain: the adjudicated review receipt is
        // carried by exactly one durable burn of the original stage; that
        // burn's standing names the exact proposal that was executed. No
        // stage-name query may substitute for any edge of this chain.
        let burns = store.find_campaign_consumptions_by_receipt(
            &proposal.campaign,
            &basis.original_stage,
            &basis.rejected_review_receipt,
        )?;
        let [burn] = burns.as_slice() else {
            return Err(if burns.is_empty() {
                CampaignRefusal::AdjudicationSubjectUnknown.into()
            } else {
                CampaignRefusal::RepairOriginalStandingAmbiguous.into()
            });
        };
        let original_standing = store
            .get_campaign_standing(&burn.standing)?
            .ok_or_else(|| CampaignError::NotFound(format!("standing {}", burn.standing)))?;
        let original = store
            .get_campaign_proposal(&original_standing.proposal_digest())?
            .ok_or_else(|| {
                CampaignError::NotFound(format!("proposal {}", original_standing.proposal_digest()))
            })?;
        validate_repair(&proposal, &original, &adjudication)?;
    }
    let standing = CampaignStageStanding::issue(&proposal, now)?;
    store.record_campaign_standing(&standing)?;
    Ok(standing)
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
    store.record_campaign_receipt(standing_digest, receipt)?;
    Ok(())
}

/// Adjudicate a review receipt for a stage: continue, exact repair, or
/// refuse, as a durable receipt. The adjudicated review receipt must be one
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
