//! The canonical attempt dossier: one read model for everything the runtime
//! already recorded about an attempt.
//!
//! The dossier exposes records; it manufactures no facts. Every field is read
//! from the store's ledger and projections, and both operator surfaces — the
//! human rendering and the versioned JSON rendering — are pure functions of the
//! same assembled value, so they cannot drift apart.
//!
//! Recovery verdicts are presented **qualified**: the verdict, its proof basis,
//! the asserted `ExclusiveRefCustody` premise, the observed ref, the expected
//! result commit, and whether those records agree. `ProvenNotCommitted` is
//! never rendered as unconditional historical proof, because it is not one:
//! external mutation of the target ref between dispatch and the recovery
//! observation makes the same evidence consistent with an effect that landed
//! and was reverted (`docs/governed-runtime/trust-model.md` §2).

use crate::ports::store::{RelianceRefusalRecord, Store, StoreError, TimelineEntry};
use gwr_core::domain::standing::{GrantState, StandingAct, StandingGrant};
use gwr_core::ids::*;
use gwr_core::lifecycle::{AttemptState, RecoveryVerdict};
use gwr_core::observation_plan::ObservationRecord;
use gwr_core::outcome::{Commitment, DispatchRefusalRecord, IndeterminateRecord};
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::receipt::{RatificationReceipt, ReviewQueueAdmission};
use gwr_core::reconciliation::{Reconciliation, ResidualObligation};
use gwr_core::recovery::{RecoveryFact, RecoveryResolution};
use gwr_core::work_request::{ClockReading, WorkRequest};

/// The dossier format identifier, carried in every JSON rendering. Any change
/// to the JSON key set or value encodings is a version bump here, not an edit.
pub const DOSSIER_FORMAT: &str = "gwr:attempt-dossier:v1";

#[derive(Debug, PartialEq, Eq)]
pub enum DossierError {
    Store(StoreError),
    /// The projection asserts a stage whose ledger record is absent — an
    /// incomplete store is a typed read error, never a defaulted dossier.
    MissingRecord {
        expected: &'static str,
    },
}

impl From<StoreError> for DossierError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// How the attempt settled, derived from its execution state alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settlement {
    /// No dispatch exists yet.
    NotDispatched,
    /// Broker acknowledged the atomic ref update in the normal path.
    Normal,
    /// Broker definitively refused; no effect occurred.
    Refused,
    /// Dispatched, outcome unknown, not yet resolved.
    Unresolved,
    /// Settled from indeterminacy by separately authorized recovery.
    Recovered,
}

impl Settlement {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::NotDispatched => "not_dispatched",
            Self::Normal => "normal",
            Self::Refused => "refused",
            Self::Unresolved => "unresolved",
            Self::Recovered => "recovered",
        }
    }
}

/// The stable state tag for an execution state — the same vocabulary the store
/// projection and the timeline use.
pub fn state_tag(state: &AttemptState) -> &'static str {
    match state {
        AttemptState::Prepared => "prepared",
        AttemptState::Ratified { .. } => "ratified",
        AttemptState::Reserved { .. } => "reserved",
        AttemptState::Dispatching { .. } => "dispatching",
        AttemptState::Committed { .. } => "committed",
        AttemptState::DispatchRefused { .. } => "dispatch_refused",
        AttemptState::Indeterminate { .. } => "indeterminate",
        AttemptState::CommittedViaRecovery { .. } => "committed_via_recovery",
        AttemptState::ProvenNotCommitted { .. } => "proven_not_committed",
    }
}

fn settlement(state: &AttemptState) -> Settlement {
    match state {
        AttemptState::Prepared | AttemptState::Ratified { .. } | AttemptState::Reserved { .. } => {
            Settlement::NotDispatched
        }
        // Dispatching means a dispatch exists whose outcome was never recorded;
        // until re-entry settles it, its outcome is not established.
        AttemptState::Dispatching { .. } | AttemptState::Indeterminate { .. } => {
            Settlement::Unresolved
        }
        AttemptState::Committed { .. } => Settlement::Normal,
        AttemptState::DispatchRefused { .. } => Settlement::Refused,
        AttemptState::CommittedViaRecovery { .. } | AttemptState::ProvenNotCommitted { .. } => {
            Settlement::Recovered
        }
    }
}

/// A standing grant as the ledger records it: scope, expiry, and consumption.
/// Identifiers and scope only — a grant row confers nothing without the token,
/// and no token or MAC material is ever persisted or exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSummary {
    pub grant: StandingGrantId,
    pub actor: ActorId,
    pub act: StandingAct,
    pub attempt_digest_binding: gwr_core::digest::Sha256Digest,
    pub expires_at: ClockReading,
    pub consumed_by: Option<StandingUseId>,
    pub used_at: Option<ClockReading>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationSummary {
    pub reservation: ReservationId,
    pub basis: gwr_core::work_request::CommitHash,
    pub expires_at: ClockReading,
    pub consumed_by: Option<ReservationUseId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchSummary {
    pub dispatch: DispatchId,
    pub created_at: ClockReading,
}

/// Authority and reservation: who bound themselves to what, under which grant,
/// and how the one use of each authority was spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySection {
    pub ratification: Option<RatificationReceipt>,
    pub ratifying_grant: Option<GrantSummary>,
    pub reservation: Option<ReservationSummary>,
    pub dispatch: Option<DispatchSummary>,
    pub recovery_grant: Option<GrantSummary>,
}

/// Execution and settlement records, exactly as persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionSection {
    pub settlement: Settlement,
    pub commitment: Option<Commitment>,
    pub dispatch_refusal: Option<DispatchRefusalRecord>,
    pub indeterminate: Option<IndeterminateRecord>,
    pub recovery_facts: Vec<RecoveryFact>,
    pub resolution: Option<RecoveryResolution>,
}

/// Observation, reliance, and the closing account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationSection {
    pub observations: Vec<ObservationRecord>,
    pub reliance_admissions: Vec<ReviewQueueAdmission>,
    pub reliance_refusals: Vec<RelianceRefusalRecord>,
    pub residual_obligations: Vec<ResidualObligation>,
    pub reconciliation: Option<Reconciliation>,
}

/// Whether the records behind a recovery verdict agree with one another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceConcordance {
    /// The observed ref holds exactly the commit the digest-verified journal
    /// recorded creating.
    ObservedMatchesExpectedResult,
    /// The digest-verified journal recorded no effect commit, and the ref holds
    /// the basis.
    NoEffectCommitRecorded,
    /// The digest-verified journal recorded an effect commit that the observed
    /// ref does not hold. The records disagree about occurrence: under intact
    /// custody this is a commit object that never landed; under violated
    /// custody it is equally consistent with a landed effect that was reverted.
    EffectCommitRecordedButNotObserved,
}

impl EvidenceConcordance {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::ObservedMatchesExpectedResult => "observed_matches_expected_result",
            Self::NoEffectCommitRecorded => "no_effect_commit_recorded",
            Self::EffectCommitRecordedButNotObserved => "effect_commit_recorded_but_not_observed",
        }
    }

    pub fn agrees(&self) -> bool {
        !matches!(self, Self::EffectCommitRecordedButNotObserved)
    }
}

/// The qualification of a recovery verdict: its proof basis, the environmental
/// premise it rests on, and whether the evidence is concordant. Present exactly
/// when a recovery resolution exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationSection {
    pub verdict: RecoveryVerdict,
    /// The fact the resolution applied — the runtime's recorded reading of the
    /// world, already validated against the runtime's own records.
    pub fact: RecoveryFact,
    /// The commitment ledger's attribution of the observed commit, if any.
    pub observed_ref_owner: Option<AttemptId>,
    pub concordance: EvidenceConcordance,
}

/// Everything the runtime recorded about one attempt, in one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptDossier {
    pub attempt: PreparedAttempt,
    pub state: AttemptState,
    pub version: u64,
    pub work_request: WorkRequest,
    pub preparation_run: PreparationRunId,
    pub candidate_ingested_at: ClockReading,
    pub timeline: Vec<TimelineEntry>,
    pub authority: AuthoritySection,
    pub execution: ExecutionSection,
    pub observation: ObservationSection,
    pub qualification: Option<QualificationSection>,
}

fn optional<T>(r: Result<T, StoreError>) -> Result<Option<T>, StoreError> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(StoreError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

fn required<T>(
    r: Result<Option<T>, StoreError>,
    expected: &'static str,
) -> Result<T, DossierError> {
    r?.ok_or(DossierError::MissingRecord { expected })
}

fn grant_summary(
    store: &mut dyn Store,
    standing_use: StandingUseId,
) -> Result<GrantSummary, DossierError> {
    let use_record = required(store.get_standing_use(standing_use), "standing_use")?;
    let grant: StandingGrant = store.get_standing_grant(use_record.grant).map_err(|e| {
        if e == StoreError::NotFound {
            DossierError::MissingRecord {
                expected: "standing_grant",
            }
        } else {
            DossierError::Store(e)
        }
    })?;
    let consumed_by = match grant.state() {
        GrantState::Available => None,
        GrantState::Consumed { used_as } => Some(*used_as),
    };
    Ok(GrantSummary {
        grant: grant.id(),
        actor: grant.scope().actor,
        act: grant.scope().act,
        attempt_digest_binding: grant.scope().attempt_digest,
        expires_at: grant.expires_at(),
        consumed_by,
        used_at: Some(use_record.used_at),
    })
}

/// Assemble the canonical dossier for an attempt from the store alone. Reads
/// only; nothing here consults the repository, the clock, or the provider.
pub fn assemble(
    store: &mut dyn Store,
    attempt_id: AttemptId,
) -> Result<AttemptDossier, DossierError> {
    let projected = store.get_attempt(attempt_id)?;
    let work_request = store.get_work_request(projected.attempt.work_request)?;
    let candidate = store.get_candidate(projected.attempt.candidate)?;
    let timeline = store.timeline(attempt_id)?;

    // Authority. Each block is present exactly when its ledger record is.
    let ratification = store.get_ratification(attempt_id)?;
    let ratifying_grant = match &ratification {
        Some(receipt) => Some(grant_summary(store, receipt.standing_use)?),
        None => None,
    };
    let reservation = match &projected.state {
        AttemptState::Prepared | AttemptState::Ratified { .. } => None,
        AttemptState::Reserved { reservation, .. } => Some(*reservation),
        AttemptState::Dispatching { reservation, .. }
        | AttemptState::Committed { reservation, .. }
        | AttemptState::DispatchRefused { reservation, .. }
        | AttemptState::Indeterminate { reservation, .. }
        | AttemptState::CommittedViaRecovery { reservation, .. }
        | AttemptState::ProvenNotCommitted { reservation, .. } => Some(reservation.reservation),
    };
    let reservation = match reservation {
        Some(id) => {
            let claim = store.get_reservation(id)?;
            let consumed_by = match claim.state() {
                gwr_core::domain::reservation::ClaimState::Active => None,
                gwr_core::domain::reservation::ClaimState::Consumed { used_as } => Some(*used_as),
            };
            Some(ReservationSummary {
                reservation: claim.id(),
                basis: claim.basis().clone(),
                expires_at: claim.expires_at(),
                consumed_by,
            })
        }
        None => None,
    };
    let dispatch = match store.find_attempt_dispatch(attempt_id)? {
        Some(_) => {
            let envelope = store.get_dispatch_envelope(attempt_id)?;
            Some(DispatchSummary {
                dispatch: envelope.dispatch,
                created_at: envelope.created_at,
            })
        }
        None => None,
    };

    // Execution and settlement, cross-checked against the projected state: a
    // terminal state whose ledger record is missing is an incomplete store.
    let commitment = optional(store.get_commitment(attempt_id))?;
    let dispatch_refusal = store.get_dispatch_refusal(attempt_id)?;
    let indeterminate = optional(store.get_indeterminate(attempt_id))?;
    let recovery_facts = store.get_recovery_facts(attempt_id)?;
    let resolution = store.get_recovery_resolution(attempt_id)?;
    match &projected.state {
        AttemptState::Committed { .. } if commitment.is_none() => {
            return Err(DossierError::MissingRecord {
                expected: "commitment",
            });
        }
        AttemptState::DispatchRefused { .. } if dispatch_refusal.is_none() => {
            return Err(DossierError::MissingRecord {
                expected: "dispatch_refusal",
            });
        }
        AttemptState::Indeterminate { .. } if indeterminate.is_none() => {
            return Err(DossierError::MissingRecord {
                expected: "indeterminate_outcome",
            });
        }
        AttemptState::CommittedViaRecovery { .. } | AttemptState::ProvenNotCommitted { .. }
            if resolution.is_none() =>
        {
            return Err(DossierError::MissingRecord {
                expected: "recovery_resolution",
            });
        }
        _ => {}
    }

    let recovery_grant = match &resolution {
        Some(r) => Some(grant_summary(store, r.recovery_standing_use)?),
        None => None,
    };

    // Qualification: present exactly when a recovery resolution exists. The
    // applied fact is the resolution's named fact, found in the ledger.
    let qualification = match &resolution {
        Some(r) => {
            let fact = recovery_facts
                .iter()
                .find(|f| f.id == r.fact)
                .cloned()
                .ok_or(DossierError::MissingRecord {
                    expected: "recovery_fact",
                })?;
            let observed_ref_owner = store.find_commitment_owner(&fact.observed_ref)?;
            let concordance = match &fact.expected_result_commit {
                None => EvidenceConcordance::NoEffectCommitRecorded,
                Some(expected) if *expected == fact.observed_ref => {
                    EvidenceConcordance::ObservedMatchesExpectedResult
                }
                Some(_) => EvidenceConcordance::EffectCommitRecordedButNotObserved,
            };
            Some(QualificationSection {
                verdict: r.verdict,
                fact,
                observed_ref_owner,
                concordance,
            })
        }
        None => None,
    };

    let observations = store.get_observations(attempt_id)?;
    let reliance_admissions = store.get_reliance_admissions(attempt_id)?;
    let reliance_refusals = store.get_reliance_refusals(attempt_id)?;
    let residual_obligations = store.get_residual_obligations(attempt_id)?;
    let reconciliation = store.get_reconciliation(attempt_id)?;
    let settlement = settlement(&projected.state);

    Ok(AttemptDossier {
        attempt: projected.attempt,
        state: projected.state,
        version: projected.version,
        work_request,
        preparation_run: candidate.preparation_run,
        candidate_ingested_at: candidate.ingested_at,
        timeline,
        authority: AuthoritySection {
            ratification,
            ratifying_grant,
            reservation,
            dispatch,
            recovery_grant,
        },
        execution: ExecutionSection {
            settlement,
            commitment,
            dispatch_refusal,
            indeterminate,
            recovery_facts,
            resolution,
        },
        observation: ObservationSection {
            observations,
            reliance_admissions,
            reliance_refusals,
            residual_obligations,
            reconciliation,
        },
        qualification,
    })
}

// ---------------------------------------------------------------------------
// Rendering. Both surfaces are pure functions of the same `AttemptDossier`;
// there is no second assembly path for either.
// ---------------------------------------------------------------------------

fn hx(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// JSON string escaping per RFC 8259: quote, backslash, and control characters.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn js(s: &str) -> String {
    format!("\"{}\"", esc(s))
}

fn js_opt(s: Option<String>) -> String {
    match s {
        Some(v) => js(&v),
        None => "null".into(),
    }
}

fn js_arr(items: Vec<String>) -> String {
    format!("[{}]", items.join(","))
}

fn js_str_arr(items: &[String]) -> String {
    js_arr(items.iter().map(|s| js(s)).collect())
}

/// What each recovery verdict establishes and does not establish, relative to
/// the custody premise. Fixed statements of the domain contract, not per-case
/// improvisation; the same text feeds both renderings.
fn verdict_statements(q: &QualificationSection) -> (&'static str, &'static str) {
    match q.verdict {
        RecoveryVerdict::CommittedViaRecovery => (
            "the target ref was observed holding exactly the commit the digest-verified broker \
             journal recorded creating for this dispatch; under the asserted custody premise the \
             effect committed exactly once",
            "correctness, completion, merge safety, or obligation discharge; and the observation \
             is a reading of the ref, so it too is relative to the custody premise",
        ),
        RecoveryVerdict::ProvenNotCommitted => (
            "the effect is not presently reflected in the target ref; under the asserted custody \
             premise (no writer but the governed broker between dispatch and the recovery \
             observation), that the effect never committed",
            "unconditional non-occurrence: external mutation of the target ref between dispatch \
             and the recovery observation would make this same evidence consistent with an \
             effect that landed and was later reverted, and no retained evidence would \
             distinguish the two",
        ),
    }
}

fn concordance_statement(q: &QualificationSection) -> String {
    match q.concordance {
        EvidenceConcordance::ObservedMatchesExpectedResult => {
            "records agree: the observed ref holds exactly the commit the digest-verified \
             journal recorded creating"
                .into()
        }
        EvidenceConcordance::NoEffectCommitRecorded => {
            "records agree: the digest-verified journal records no effect commit, and the \
             observed ref holds the basis"
                .into()
        }
        EvidenceConcordance::EffectCommitRecordedButNotObserved => format!(
            "records disagree: the digest-verified journal records effect commit {} which the \
             observed ref does not hold. Under intact custody this is a commit object that never \
             landed; if custody was not exclusive, the same records are consistent with a landed \
             effect that was externally reverted",
            q.fact
                .expected_result_commit
                .as_ref()
                .map(|c| c.as_str().to_string())
                .unwrap_or_default()
        ),
    }
}

fn grant_json(g: &Option<GrantSummary>) -> String {
    match g {
        None => "null".into(),
        Some(g) => format!(
            "{{\"grant\":{},\"actor\":{},\"act\":{},\"attempt_digest_binding\":{},\
             \"expires_at_ms\":{},\"consumed_by\":{},\"used_at_ms\":{}}}",
            js(&hx(g.grant.as_bytes())),
            js(&hx(g.actor.as_bytes())),
            js(g.act.tag()),
            js(&g.attempt_digest_binding.to_hex()),
            g.expires_at.0,
            js_opt(g.consumed_by.map(|u| hx(u.as_bytes()))),
            g.used_at.map(|t| t.0.to_string()).unwrap_or("null".into()),
        ),
    }
}

/// The versioned JSON rendering of the dossier.
pub fn render_json(d: &AttemptDossier) -> String {
    let a = &d.attempt;
    let identity = format!(
        "{{\"work_request\":{},\"goal\":{},\"repository\":{},\"target_ref\":{},\"basis\":{},\
         \"effect_class\":{},\"settlement_premises\":{},\"allowed_paths\":{},\
         \"candidate\":{},\"candidate_digest\":{},\
         \"patch_digest\":{},\"preparation_run\":{},\"candidate_ingested_at_ms\":{},\
         \"prepared_attempt_digest\":{},\"observation_plan\":{{\"argv\":{},\"environment\":{}}},\
         \"request_created_at_ms\":{},\"admitted_at_ms\":{}}}",
        js(&hx(d.work_request.id.as_bytes())),
        js(&d.work_request.goal),
        js(a.repository.as_str()),
        js(a.effect.target_ref.as_str()),
        js(a.basis.as_str()),
        js(gwr_core::effect_spec::GitRefEffect::KIND),
        js_arr(
            gwr_core::effect_spec::GitRefEffect::SETTLEMENT_PREMISES
                .iter()
                .map(|p| js(p.tag()))
                .collect()
        ),
        js_str_arr(&a.effect.allowed_paths),
        js(&hx(a.candidate.as_bytes())),
        js(&a.artifact_digest.to_hex()),
        js(&a.effect.patch_digest.to_hex()),
        js(&hx(d.preparation_run.as_bytes())),
        d.candidate_ingested_at.0,
        js(&a.prepared_attempt_digest.to_hex()),
        js_str_arr(&a.observation_plan.argv),
        js(&a.observation_plan.environment_description),
        d.work_request.created_at.0,
        a.admitted_at.0,
    );

    let ratification = match &d.authority.ratification {
        None => "null".into(),
        Some(r) => format!(
            "{{\"ratification\":{},\"actor\":{},\"standing_use\":{},\"at_ms\":{}}}",
            js(&hx(r.ratification.as_bytes())),
            js(&hx(r.actor.as_bytes())),
            js(&hx(r.standing_use.as_bytes())),
            r.clock_reading.0,
        ),
    };
    let reservation = match &d.authority.reservation {
        None => "null".into(),
        Some(r) => format!(
            "{{\"reservation\":{},\"basis\":{},\"expires_at_ms\":{},\"consumed_by\":{}}}",
            js(&hx(r.reservation.as_bytes())),
            js(r.basis.as_str()),
            r.expires_at.0,
            js_opt(r.consumed_by.map(|u| hx(u.as_bytes()))),
        ),
    };
    let dispatch = match &d.authority.dispatch {
        None => "null".into(),
        Some(x) => format!(
            "{{\"dispatch\":{},\"created_at_ms\":{}}}",
            js(&hx(x.dispatch.as_bytes())),
            x.created_at.0,
        ),
    };
    let authority = format!(
        "{{\"ratification\":{},\"ratifying_grant\":{},\"reservation\":{},\"dispatch\":{},\
         \"recovery_grant\":{}}}",
        ratification,
        grant_json(&d.authority.ratifying_grant),
        reservation,
        dispatch,
        grant_json(&d.authority.recovery_grant),
    );

    let timeline = js_arr(
        d.timeline
            .iter()
            .map(|t| {
                format!(
                    "{{\"seq\":{},\"kind\":{},\"at_ms\":{}}}",
                    t.seq,
                    js(&t.kind),
                    t.at.0
                )
            })
            .collect(),
    );

    let commitment = match &d.execution.commitment {
        None => "null".into(),
        Some(c) => format!(
            "{{\"result_commit\":{},\"previous_value\":{},\"target_ref\":{},\
             \"journal_digest\":{},\"committed_at_ms\":{}}}",
            js(c.result_commit.as_str()),
            js(c.previous_value.as_str()),
            js(c.target_ref.as_str()),
            js(&c.journal_digest.to_hex()),
            c.committed_at.0,
        ),
    };
    let dispatch_refusal = match &d.execution.dispatch_refusal {
        None => "null".into(),
        Some(r) => format!(
            "{{\"ground\":{},\"journal_digest\":{},\"refused_at_ms\":{}}}",
            js(r.ground.tag()),
            js(&r.journal_digest.to_hex()),
            r.refused_at.0,
        ),
    };
    let indeterminate = match &d.execution.indeterminate {
        None => "null".into(),
        Some(i) => format!(
            "{{\"last_journal_digest\":{},\"recorded_at_ms\":{}}}",
            js_opt(i.last_journal_digest.as_ref().map(|x| x.to_hex())),
            i.recorded_at.0,
        ),
    };
    let facts = js_arr(
        d.execution
            .recovery_facts
            .iter()
            .map(|f| {
                let (source_kind, source_detail) = f.source.tags();
                format!(
                    "{{\"fact\":{},\"source\":{},\"source_detail\":{},\"observed_ref\":{},\
                     \"expected_result_commit\":{},\"journal_digest\":{},\"recorded_at_ms\":{}}}",
                    js(&hx(f.id.as_bytes())),
                    js(source_kind),
                    js_opt(source_detail),
                    js(f.observed_ref.as_str()),
                    js_opt(
                        f.expected_result_commit
                            .as_ref()
                            .map(|c| c.as_str().to_string())
                    ),
                    js(&f.journal_digest.to_hex()),
                    f.recorded_at.0,
                )
            })
            .collect(),
    );
    let resolution = match &d.execution.resolution {
        None => "null".into(),
        Some(r) => format!(
            "{{\"resolution\":{},\"fact\":{},\"verdict\":{},\"recovery_standing_use\":{},\
             \"resolved_at_ms\":{}}}",
            js(&hx(r.id.as_bytes())),
            js(&hx(r.fact.as_bytes())),
            js(r.verdict.tag()),
            js(&hx(r.recovery_standing_use.as_bytes())),
            r.resolved_at.0,
        ),
    };
    let execution = format!(
        "{{\"settlement\":{},\"commitment\":{},\"dispatch_refusal\":{},\"indeterminate\":{},\
         \"recovery_facts\":{},\"resolution\":{}}}",
        js(d.execution.settlement.tag()),
        commitment,
        dispatch_refusal,
        indeterminate,
        facts,
        resolution,
    );

    let observations = js_arr(
        d.observation
            .observations
            .iter()
            .map(|o| {
                format!(
                    "{{\"observation\":{},\"argv\":{},\"working_directory\":{},\
                     \"result_commit\":{},\"environment\":{},\"exit_status\":{},\
                     \"stdout_digest\":{},\"stderr_digest\":{},\"observed_at_ms\":{}}}",
                    js(&hx(o.id.as_bytes())),
                    js_str_arr(&o.argv),
                    js(&o.working_directory_identity),
                    js(o.result_commit.as_str()),
                    js(&o.environment_description),
                    o.exit_status,
                    js(&o.stdout_digest.to_hex()),
                    js(&o.stderr_digest.to_hex()),
                    o.observed_at.0,
                )
            })
            .collect(),
    );
    let admissions = js_arr(
        d.observation
            .reliance_admissions
            .iter()
            .map(|a| {
                format!(
                    "{{\"observation\":{},\"result_commit\":{},\"at_ms\":{}}}",
                    js(&hx(a.observation.as_bytes())),
                    js(a.result_commit.as_str()),
                    a.admitted_at.0,
                )
            })
            .collect(),
    );
    let refusals = js_arr(
        d.observation
            .reliance_refusals
            .iter()
            .map(|r| {
                let (kind, detail) = r.refusal.tags();
                let subject = match &r.subject {
                    None => "null".into(),
                    Some(s) => format!(
                        "{{\"observation\":{},\"consumer\":{},\"claim\":{}}}",
                        js(&hx(s.observation.as_bytes())),
                        js(&s.consumer),
                        js(s.claim.tag()),
                    ),
                };
                format!(
                    "{{\"kind\":{},\"detail\":{},\"subject\":{},\"at_ms\":{}}}",
                    js(kind),
                    js_opt(detail),
                    subject,
                    r.at.0,
                )
            })
            .collect(),
    );
    let obligations = js_arr(
        d.observation
            .residual_obligations
            .iter()
            .map(|ob| {
                format!(
                    "{{\"obligation\":{},\"kind\":{},\"recorded_at_ms\":{}}}",
                    js(&hx(ob.id.as_bytes())),
                    js(ob.kind.tag()),
                    ob.recorded_at.0,
                )
            })
            .collect(),
    );
    let reconciliation = match &d.observation.reconciliation {
        None => "null".into(),
        Some(r) => format!(
            "{{\"retained_obligations\":{},\"reconciled_at_ms\":{}}}",
            js_arr(
                r.retained_obligations
                    .iter()
                    .map(|o| js(&hx(o.as_bytes())))
                    .collect()
            ),
            r.reconciled_at.0,
        ),
    };
    let observation = format!(
        "{{\"observations\":{},\"reliance_admissions\":{},\"reliance_refusals\":{},\
         \"residual_obligations\":{},\"reconciliation\":{}}}",
        observations, admissions, refusals, obligations, reconciliation,
    );

    let qualification =
        match &d.qualification {
            None => "null".into(),
            Some(q) => {
                let (establishes, does_not) = verdict_statements(q);
                let (source_kind, _) = q.fact.source.tags();
                format!(
                "{{\"verdict\":{},\"proof_basis\":{},\"fact\":{},\"fact_source\":{},\
                 \"custody_premise\":\"ExclusiveRefCustody\",\
                 \"custody_premise_asserted_not_verified\":true,\
                 \"observed_ref\":{},\"expected_result_commit\":{},\"observed_ref_owner\":{},\
                 \"journal_digest\":{},\"evidence_concordance\":{},\"evidence_agrees\":{},\
                 \"establishes\":{},\"does_not_establish\":{}}}",
                js(q.verdict.tag()),
                js("runtime reading of the target ref plus the broker journal verified against \
                    the digest recorded at indeterminacy"),
                js(&hx(q.fact.id.as_bytes())),
                js(source_kind),
                js(q.fact.observed_ref.as_str()),
                js_opt(
                    q.fact
                        .expected_result_commit
                        .as_ref()
                        .map(|c| c.as_str().to_string())
                ),
                js_opt(q.observed_ref_owner.map(|a| hx(a.as_bytes()))),
                js(&q.fact.journal_digest.to_hex()),
                js(q.concordance.tag()),
                q.concordance.agrees(),
                js(establishes),
                js(does_not),
            )
            }
        };

    format!(
        "{{\"dossier_format\":{},\"attempt\":{},\"state\":{},\"version\":{},\"settlement\":{},\
         \"identity\":{},\"authority\":{},\"timeline\":{},\"execution\":{},\"observation\":{},\
         \"qualification\":{}}}",
        js(DOSSIER_FORMAT),
        js(&hx(d.attempt.attempt_id.as_bytes())),
        js(state_tag(&d.state)),
        d.version,
        js(d.execution.settlement.tag()),
        identity,
        authority,
        timeline,
        execution,
        observation,
        qualification,
    )
}

/// The human rendering of the dossier. Same source value as the JSON rendering.
pub fn render_text(d: &AttemptDossier) -> String {
    use std::fmt::Write as _;
    let a = &d.attempt;
    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(w, "attempt {}", hx(a.attempt_id.as_bytes()));
    let _ = writeln!(w, "state {}", state_tag(&d.state));
    let _ = writeln!(w, "version {}", d.version);
    let _ = writeln!(w, "settlement {}", d.execution.settlement.tag());

    let _ = writeln!(w, "\nidentity");
    let _ = writeln!(w, "  goal {}", d.work_request.goal);
    let _ = writeln!(w, "  work_request {}", hx(d.work_request.id.as_bytes()));
    let _ = writeln!(w, "  repository {}", a.repository.as_str());
    let _ = writeln!(w, "  target_ref {}", a.effect.target_ref.as_str());
    let _ = writeln!(w, "  basis {}", a.basis.as_str());
    let _ = writeln!(
        w,
        "  effect_class {}",
        gwr_core::effect_spec::GitRefEffect::KIND
    );
    let premises: Vec<&str> = gwr_core::effect_spec::GitRefEffect::SETTLEMENT_PREMISES
        .iter()
        .map(|p| p.tag())
        .collect();
    let _ = writeln!(
        w,
        "  settlement_premises {} (properties of this effect class, not universal guarantees)",
        premises.join(" ")
    );
    for p in &a.effect.allowed_paths {
        let _ = writeln!(w, "  allowed_path {p}");
    }
    let _ = writeln!(
        w,
        "  candidate {} preparation_run {} ingested_at_ms {}",
        hx(a.candidate.as_bytes()),
        hx(d.preparation_run.as_bytes()),
        d.candidate_ingested_at.0
    );
    let _ = writeln!(w, "  candidate_digest {}", a.artifact_digest.to_hex());
    let _ = writeln!(w, "  patch_digest {}", a.effect.patch_digest.to_hex());
    let _ = writeln!(
        w,
        "  prepared_attempt_digest {}",
        a.prepared_attempt_digest.to_hex()
    );
    let _ = writeln!(
        w,
        "  observation_plan {} (environment: {})",
        a.observation_plan.argv.join(" "),
        a.observation_plan.environment_description
    );
    let _ = writeln!(
        w,
        "  request_created_at_ms {} admitted_at_ms {}",
        d.work_request.created_at.0, a.admitted_at.0
    );

    let _ = writeln!(w, "\nauthority");
    match (&d.authority.ratification, &d.authority.ratifying_grant) {
        (Some(r), grant) => {
            let _ = writeln!(
                w,
                "  ratification {} actor {} at_ms {}",
                hx(r.ratification.as_bytes()),
                hx(r.actor.as_bytes()),
                r.clock_reading.0
            );
            if let Some(g) = grant {
                let _ = writeln!(
                    w,
                    "  ratifying_grant {} act {} expires_at_ms {} consumed_by {} used_at_ms {}",
                    hx(g.grant.as_bytes()),
                    g.act.tag(),
                    g.expires_at.0,
                    g.consumed_by
                        .map(|u| hx(u.as_bytes()))
                        .unwrap_or_else(|| "none".into()),
                    g.used_at.map(|t| t.0.to_string()).unwrap_or("none".into()),
                );
                let _ = writeln!(
                    w,
                    "  grant_digest_binding {}{}",
                    g.attempt_digest_binding.to_hex(),
                    if g.attempt_digest_binding == a.prepared_attempt_digest {
                        " (matches prepared_attempt_digest)"
                    } else {
                        " (DOES NOT MATCH prepared_attempt_digest)"
                    }
                );
            }
        }
        _ => {
            let _ = writeln!(w, "  not ratified");
        }
    }
    match &d.authority.reservation {
        Some(r) => {
            let _ = writeln!(
                w,
                "  reservation {} basis {} expires_at_ms {} consumed_by {}",
                hx(r.reservation.as_bytes()),
                r.basis.as_str(),
                r.expires_at.0,
                r.consumed_by
                    .map(|u| hx(u.as_bytes()))
                    .unwrap_or_else(|| "none".into()),
            );
        }
        None => {
            let _ = writeln!(w, "  no reservation");
        }
    }
    match &d.authority.dispatch {
        Some(x) => {
            let _ = writeln!(
                w,
                "  dispatch {} created_at_ms {}",
                hx(x.dispatch.as_bytes()),
                x.created_at.0
            );
        }
        None => {
            let _ = writeln!(w, "  no dispatch");
        }
    }
    if let Some(g) = &d.authority.recovery_grant {
        let _ = writeln!(
            w,
            "  recovery_grant {} actor {} act {} (separate authority) used_at_ms {}",
            hx(g.grant.as_bytes()),
            hx(g.actor.as_bytes()),
            g.act.tag(),
            g.used_at.map(|t| t.0.to_string()).unwrap_or("none".into()),
        );
    }

    let _ = writeln!(w, "\ntimeline");
    for t in &d.timeline {
        let _ = writeln!(w, "  {} {} at_ms {}", t.seq, t.kind, t.at.0);
    }

    let _ = writeln!(w, "\nexecution");
    if let Some(c) = &d.execution.commitment {
        let _ = writeln!(
            w,
            "  committed {} -> {} on {} at_ms {}",
            c.previous_value.as_str(),
            c.result_commit.as_str(),
            c.target_ref.as_str(),
            c.committed_at.0
        );
        let _ = writeln!(w, "  result_commit {}", c.result_commit.as_str());
        let _ = writeln!(w, "  journal_digest {}", c.journal_digest.to_hex());
    }
    if let Some(r) = &d.execution.dispatch_refusal {
        let _ = writeln!(
            w,
            "  dispatch_refused ground {} journal_digest {} at_ms {}",
            r.ground.tag(),
            r.journal_digest.to_hex(),
            r.refused_at.0
        );
    }
    if let Some(i) = &d.execution.indeterminate {
        let _ = writeln!(
            w,
            "  indeterminate last_journal_digest {} at_ms {}",
            i.last_journal_digest
                .as_ref()
                .map(|x| x.to_hex())
                .unwrap_or_else(|| "none".into()),
            i.recorded_at.0
        );
    }
    for f in &d.execution.recovery_facts {
        let (source_kind, _) = f.source.tags();
        let _ = writeln!(
            w,
            "  recovery_fact {} source {} observed_ref {} expected_result_commit {} at_ms {}",
            hx(f.id.as_bytes()),
            source_kind,
            f.observed_ref.as_str(),
            f.expected_result_commit
                .as_ref()
                .map(|c| c.as_str().to_string())
                .unwrap_or_else(|| "none".into()),
            f.recorded_at.0
        );
    }
    if let Some(r) = &d.execution.resolution {
        let _ = writeln!(
            w,
            "  resolution {} verdict {} fact {} at_ms {}",
            hx(r.id.as_bytes()),
            r.verdict.tag(),
            hx(r.fact.as_bytes()),
            r.resolved_at.0
        );
    }
    if d.execution.commitment.is_none()
        && d.execution.dispatch_refusal.is_none()
        && d.execution.indeterminate.is_none()
        && d.execution.resolution.is_none()
    {
        let _ = writeln!(w, "  no execution outcome recorded");
    }

    let _ = writeln!(w, "\nobservation");
    for o in &d.observation.observations {
        let _ = writeln!(
            w,
            "  observation {} argv {} exit_status {} result_commit {} at_ms {}",
            hx(o.id.as_bytes()),
            o.argv.join(" "),
            o.exit_status,
            o.result_commit.as_str(),
            o.observed_at.0
        );
    }
    for adm in &d.observation.reliance_admissions {
        let _ = writeln!(
            w,
            "  reliance_admitted observation {} result_commit {} at_ms {}",
            hx(adm.observation.as_bytes()),
            adm.result_commit.as_str(),
            adm.admitted_at.0
        );
    }
    for r in &d.observation.reliance_refusals {
        let (kind, detail) = r.refusal.tags();
        let subject = match &r.subject {
            Some(s) => format!(
                "claim {} observation {} consumer {}",
                s.claim.tag(),
                hx(s.observation.as_bytes()),
                s.consumer
            ),
            None => "subject not recorded".into(),
        };
        let _ = writeln!(
            w,
            "  reliance_refused {} {}{} at_ms {}",
            kind,
            subject,
            detail.map(|x| format!(" detail {x}")).unwrap_or_default(),
            r.at.0
        );
    }
    for ob in &d.observation.residual_obligations {
        let _ = writeln!(
            w,
            "  residual_obligation {} kind {} recorded_at_ms {} (outstanding: no discharge \
             mechanism exists in this runtime)",
            hx(ob.id.as_bytes()),
            ob.kind.tag(),
            ob.recorded_at.0
        );
    }
    match &d.observation.reconciliation {
        Some(r) => {
            let _ = writeln!(
                w,
                "  reconciliation retained {} obligation(s) at_ms {}",
                r.retained_obligations.len(),
                r.reconciled_at.0
            );
        }
        None => {
            let _ = writeln!(w, "  not reconciled");
        }
    }

    if let Some(q) = &d.qualification {
        let (establishes, does_not) = verdict_statements(q);
        let _ = writeln!(w, "\nqualification");
        let _ = writeln!(w, "  verdict {}", q.verdict.tag());
        let _ = writeln!(
            w,
            "  proof_basis: runtime reading of the target ref plus the broker journal verified \
             against the digest recorded at indeterminacy"
        );
        let _ = writeln!(
            w,
            "  custody_premise: ExclusiveRefCustody -- asserted by the deployment at resolution, \
             not verified by the runtime"
        );
        let _ = writeln!(w, "  observed_ref {}", q.fact.observed_ref.as_str());
        let _ = writeln!(
            w,
            "  expected_result_commit {}",
            q.fact
                .expected_result_commit
                .as_ref()
                .map(|c| c.as_str().to_string())
                .unwrap_or_else(|| "none".into())
        );
        let _ = writeln!(
            w,
            "  observed_ref_owner {}",
            q.observed_ref_owner
                .map(|a| hx(a.as_bytes()))
                .unwrap_or_else(|| "none".into())
        );
        let _ = writeln!(w, "  evidence: {}", concordance_statement(q));
        let _ = writeln!(w, "  establishes: {establishes}");
        let _ = writeln!(w, "  does_not_establish: {does_not}");
    }
    out
}
