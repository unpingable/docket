//! Docket-owned custody for canonical AG governed-loop issuances.
//!
//! This is intentionally a separate authority domain from AG admission,
//! campaign-stage standing, and executor idempotency.  An authenticated AG
//! issuance is exact evidence of an already-spent AG decision authorization.
//! Docket freshly resolves and consumes its own execution standing, assigns
//! one canonical attempt, persists custody before invoking mechanics, and is
//! the sole producer of the settlement AG may consume.

use crate::governed_repair::{
    self, EffectJournalEntryWireV1, ExecutorGovernedRepairRequirementWireV1,
    ImmutableWorkCheckpointWireV1, StoreSealedGovernedRepairResultV1,
};
use gwr_core::digest::{Sha256Digest, Transcript};
use ring::signature::{UnparsedPublicKey, ED25519};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{
    de::{DeserializeOwned, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use sha2::{Digest as _, Sha256};
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SIGNED_ISSUANCE_SCHEMA_V2: &str = "ag.governed-loop.signed-issuance/v2";
pub const AG_ISSUANCE_SCHEMA_V2: &str = "ag.governed-loop.issuance/v2";
pub const CUSTODY_SCHEMA_V1: &str = "ag.governed-loop.docket-custody/v1";
pub const SETTLEMENT_SCHEMA_V1: &str = "ag.governed-loop.docket-settlement/v1";
pub const ISSUANCE_REFUSAL_SCHEMA_V1: &str = "docket.governed-loop.issuance-refusal/v1";
pub const SIGNED_RECONCILIATION_ROUND_REQUEST_SCHEMA_V1: &str =
    "ag.governed-loop.signed-reconciliation-round-request/v1";
pub const RECONCILIATION_ROUND_REQUEST_SCHEMA_V1: &str =
    "ag.governed-loop.reconciliation-round-request/v1";
pub const RECONCILIATION_ROUND_RESPONSE_SCHEMA_V1: &str =
    "docket.governed-loop.reconciliation-round-response/v1";
pub const RECONCILIATION_ROUND_RESERVATION_SCHEMA_V1: &str =
    "docket.governed-loop.reconciliation-round-reservation/v1";
pub const RECONCILIATION_ROUND_COMPLETION_SCHEMA_V1: &str =
    "docket.governed-loop.reconciliation-round-completion/v1";
pub const EXECUTOR_RECONCILIATION_DISPATCH_SCHEMA_V1: &str =
    "docket.governed-loop.executor-reconciliation-dispatch/v1";

#[cfg(test)]
thread_local! {
    /// Logical process-loss seam used only to prove reopen behaviour after an
    /// executor response exists in memory but before Docket seals it. This is
    /// not a claim about physical power-loss durability.
    static CRASH_AFTER_EXECUTOR_RESULT_BEFORE_SEAL: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// Transaction-local fault used to prove that journal/settlement writes
    /// and round completion roll back as one cut. It fires only after the
    /// response has been validated and staged in the open transaction.
    static ABORT_ROUND_COMPLETION_BEFORE_ROUND_ROW: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}
pub const STANDING_REQUEST_SCHEMA_V1: &str = "docket.governed-loop.execution-standing-request/v1";
pub const STANDING_RESOLUTION_SCHEMA_V1: &str =
    "docket.governed-loop.execution-standing-resolution/v1";

const SIGNATURE_PREFIX_V2: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v2\0";
const RECONCILIATION_ROUND_SIGNATURE_PREFIX_V1: &[u8] =
    b"ag-ng\0governed-loop-reconciliation-round-signature\0v1\0";
const MAX_JCS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_EXECUTOR_PROGRAM_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXECUTOR_CONFIG_BYTES: u64 = 512 * 1024 * 1024;
static NEXT_EXECUTOR_SNAPSHOT: AtomicU64 = AtomicU64::new(1);

pub(crate) fn deserialize_present_some<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)?.map_or_else(
        || Err(serde::de::Error::custom("explicit null is not canonical")),
        |value| Ok(Some(value)),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutorBindingV1 {
    identity: String,
    program_digest: String,
    config_digest: String,
    plan: String,
}

/// One private read-only executor snapshot. Both `plan-id` and the
/// consequence-bearing operation execute these exact copied bytes rather than
/// reopening caller-controlled paths. Docket's documented same-UID trusted-code
/// premise remains the outer boundary for the private snapshot directory.
struct RetainedExecutorV1 {
    program: PathBuf,
    config: PathBuf,
    display_path: PathBuf,
    snapshot_root: PathBuf,
}

struct PreparedExecutorV1 {
    retained: RetainedExecutorV1,
    binding: ExecutorBindingV1,
}

impl Drop for RetainedExecutorV1 {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.snapshot_root);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceKeyWireV1 {
    pub campaign: String,
    pub occurrence: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalEffectOperationWireV1 {
    Read,
    Create,
    Modify,
    Delete,
    Execute,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEffectResourceWireV1 {
    pub resource: String,
    pub path: String,
    pub operations: Vec<CanonicalEffectOperationWireV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEffectScopeWireV1 {
    pub schema: String,
    pub effect_class: String,
    pub resources: Vec<CanonicalEffectResourceWireV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRepairCheckpointEvidenceWireV1 {
    pub repository: String,
    pub commit: String,
    pub tree: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub diff_identity: Option<String>,
    pub content_manifest: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub docket_checkpoint: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDispositionWireV1 {
    Admitted,
    Refused,
    Contradiction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDecisionWireV1 {
    pub decision: String,
    pub key: OccurrenceKeyWireV1,
    pub observation: String,
    pub proposal: String,
    pub standing_resolution: String,
    pub disposition: AdmissionDispositionWireV1,
    pub policy_basis: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgIssuanceWireV2 {
    pub schema: String,
    pub issuance: String,
    pub key: OccurrenceKeyWireV1,
    pub program: String,
    pub proposal: String,
    pub work_schema: String,
    pub work: String,
    pub nonclaims: Vec<String>,
    pub expires_at_unix_ms: u64,
    pub subject: String,
    pub effect_scope: CanonicalEffectScopeWireV1,
    pub effect_scope_digest: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub governed_repair_checkpoint: Option<GovernedRepairCheckpointEvidenceWireV1>,
    pub observation: String,
    pub standing_resolution: String,
    pub admission_decision: AdmissionDecisionWireV1,
    pub mandate: String,
    pub spend: String,
}

#[derive(Serialize)]
struct AgIssuanceIdentityBasisV2<'a> {
    key: &'a OccurrenceKeyWireV1,
    program: &'a str,
    proposal: &'a str,
    work_schema: &'a str,
    work: &'a str,
    nonclaims: &'a [String],
    expires_at_unix_ms: u64,
    subject: &'a str,
    effect_scope: &'a CanonicalEffectScopeWireV1,
    effect_scope_digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    governed_repair_checkpoint: Option<&'a GovernedRepairCheckpointEvidenceWireV1>,
    observation: &'a str,
    standing_resolution: &'a str,
    admission_decision: &'a AdmissionDecisionWireV1,
    mandate: &'a str,
    spend: &'a str,
}

fn ag_issuance_identity(issuance: &AgIssuanceWireV2) -> Result<String, String> {
    let basis = AgIssuanceIdentityBasisV2 {
        key: &issuance.key,
        program: &issuance.program,
        proposal: &issuance.proposal,
        work_schema: &issuance.work_schema,
        work: &issuance.work,
        nonclaims: &issuance.nonclaims,
        expires_at_unix_ms: issuance.expires_at_unix_ms,
        subject: &issuance.subject,
        effect_scope: &issuance.effect_scope,
        effect_scope_digest: &issuance.effect_scope_digest,
        governed_repair_checkpoint: issuance.governed_repair_checkpoint.as_ref(),
        observation: &issuance.observation,
        standing_resolution: &issuance.standing_resolution,
        admission_decision: &issuance.admission_decision,
        mandate: &issuance.mandate,
        spend: &issuance.spend,
    };
    let canonical =
        serde_jcs::to_vec(&basis).map_err(|error| format!("governed-issuance-basis:{error}"))?;
    Ok(hash_domain("ag.governed-loop.issuance/v2", &canonical))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceAuthenticationWireV1 {
    pub issuer_principal: String,
    pub signer_key_id: String,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedIssuanceEnvelopeWireV1 {
    pub schema: String,
    pub body_b64: String,
    pub authentication: IssuanceAuthenticationWireV1,
}

/// One AG-authorized reconciliation observation.  The idempotency value is a
/// caller-selected non-authorizing replay key.  Both identities bind it; it is
/// deliberately not derived from either identity (which would be circular).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationRoundRequestWireV1 {
    pub schema: String,
    pub request: String,
    pub round: String,
    pub issuance: String,
    pub attempt: String,
    pub caller_state_digest: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub predecessor_round: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub predecessor_reconciliation: Option<String>,
    pub idempotency: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReconciliationRoundRequestEnvelopeWireV1 {
    pub schema: String,
    pub body_b64: String,
    pub authentication: IssuanceAuthenticationWireV1,
}

#[derive(Serialize)]
struct ReconciliationRoundIdentityBasisV1<'a> {
    schema: &'a str,
    issuance: &'a str,
    attempt: &'a str,
    caller_state_digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_round: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_reconciliation: Option<&'a str>,
    idempotency: &'a str,
}

#[derive(Serialize)]
struct ReconciliationRequestIdentityBasisV1<'a> {
    schema: &'a str,
    round: &'a str,
    issuance: &'a str,
    attempt: &'a str,
    caller_state_digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_round: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_reconciliation: Option<&'a str>,
    idempotency: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedAgIssuerV1 {
    pub issuer_principal: String,
    pub key_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgIssuerTrustConfigV1 {
    pub issuers: Vec<TrustedAgIssuerV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStandingStatusV1 {
    Current,
    Absent,
    Revoked,
    Superseded,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStandingRequestV1 {
    pub schema: String,
    pub issuance: AgIssuanceWireV2,
    pub now_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStandingResolutionV1 {
    pub schema: String,
    pub resolution: String,
    pub currentness: String,
    pub execution_standing: String,
    pub issuance: String,
    pub campaign: String,
    pub occurrence: String,
    pub subject: String,
    pub scope: String,
    pub status: ExecutionStandingStatusV1,
    pub resolved_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointVerificationRequestWireV1 {
    schema: String,
    issuance: String,
    checkpoint: GovernedRepairCheckpointEvidenceWireV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CheckpointVerificationStatusWireV1 {
    Current,
    Absent,
    Mismatch,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointVerificationResultWireV1 {
    schema: String,
    verification: String,
    issuance: String,
    checkpoint: GovernedRepairCheckpointEvidenceWireV1,
    status: CheckpointVerificationStatusWireV1,
    verified_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketCustodyWireV1 {
    pub schema: String,
    pub issuance: String,
    pub ag_spend: String,
    pub execution_standing: String,
    pub standing_currentness: String,
    pub attempt: String,
    pub executor_marker: String,
    pub accepted_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorDispatchWireV1 {
    pub attempt: String,
    pub marker: String,
    pub work_schema: String,
    pub work: String,
    pub subject: String,
    pub effect_scope: CanonicalEffectScopeWireV1,
    pub effect_scope_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorOutcomeClassWireV1 {
    Success,
    Failure,
    Indeterminate,
    ScopeExpansionRequired,
    ReadjudicationRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorOutcomeWireV1 {
    pub attempt: String,
    pub marker: String,
    pub receipt: String,
    pub outcome: ExecutorOutcomeClassWireV1,
    pub effect_journal: Vec<EffectJournalEntryWireV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub immutable_work_checkpoint: Option<ImmutableWorkCheckpointWireV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub governed_repair: Option<ExecutorGovernedRepairRequirementWireV1>,
}

/// Terminal Docket result for one authenticated canonical AG issuance that
/// was refused before custody. It is sealed evidence, never standing or a
/// continuation permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocketIssuanceRefusalClassWireV1 {
    IssuanceInvalid,
    IssuanceExpired,
    CheckpointInvalid,
    StandingInvalid,
    InstrumentSubstitution,
}

impl DocketIssuanceRefusalClassWireV1 {
    const fn tag(self) -> &'static str {
        match self {
            Self::IssuanceInvalid => "issuance_invalid",
            Self::IssuanceExpired => "issuance_expired",
            Self::CheckpointInvalid => "checkpoint_invalid",
            Self::StandingInvalid => "standing_invalid",
            Self::InstrumentSubstitution => "instrument_substitution",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketIssuanceRefusalWireV1 {
    pub schema: String,
    pub refusal: String,
    pub issuance: String,
    pub campaign: String,
    pub occurrence: String,
    pub refusal_class: DocketIssuanceRefusalClassWireV1,
    pub reason_code: String,
    pub evidence: String,
    pub refused_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DocketExecutionResponseWireV1 {
    Custody(DocketCustodyWireV1),
    Refused(DocketIssuanceRefusalWireV1),
    GovernedRepairRequired {
        custody: DocketCustodyWireV1,
        result: Box<StoreSealedGovernedRepairResultV1>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketSettlementWireV1 {
    pub schema: String,
    pub settlement: String,
    pub issuance: String,
    pub attempt: String,
    pub executor_marker: String,
    pub receipt: String,
    pub outcome: KnownOutcomeWireV1,
    pub cumulative_effect_journal_identity: String,
    pub settled_at_unix_ms: u64,
}

/// Derives the settlement identity from every canonical settlement field
/// except the identity itself. Keeping this as a remove-one-field operation
/// makes a later wire-field addition fail closed instead of silently falling
/// outside the identity basis.
fn docket_settlement_identity(settlement: &DocketSettlementWireV1) -> Result<String, String> {
    let mut body = serde_json::to_value(settlement)
        .map_err(|error| format!("governed-settlement-canonical-value:{error}"))?;
    let object = body
        .as_object_mut()
        .ok_or_else(|| "governed-settlement-canonical-shape".to_owned())?;
    if object.remove("settlement").is_none() {
        return Err("governed-settlement-identity-field-missing".to_owned());
    }
    let canonical = serde_jcs::to_vec(&body)
        .map_err(|error| format!("governed-settlement-canonical:{error}"))?;
    Ok(hash_domain(
        "docket.governed-loop.settlement/v1",
        &canonical,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnownOutcomeWireV1 {
    Success,
    Failure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndeterminateOutcomeWireV1 {
    pub issuance: String,
    pub attempt: String,
    pub reconciliation: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DocketReconciliationWireV1 {
    NotAccepted,
    Refused(DocketIssuanceRefusalWireV1),
    Accepted(DocketCustodyWireV1),
    Settled {
        custody: DocketCustodyWireV1,
        settlement: DocketSettlementWireV1,
    },
    Indeterminate {
        custody: DocketCustodyWireV1,
        indeterminate: IndeterminateOutcomeWireV1,
    },
    GovernedRepairRequired {
        custody: DocketCustodyWireV1,
        result: Box<StoreSealedGovernedRepairResultV1>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationRoundReservationWireV1 {
    pub schema: String,
    pub reservation: String,
    pub request: String,
    pub round: String,
    pub issuance: String,
    pub attempt: String,
    pub caller_state_digest: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub predecessor_round: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub predecessor_reconciliation: Option<String>,
    pub source_cut: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    pub checkpoint_identity: Option<String>,
    pub executor_binding: String,
    pub claimed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationRoundCompletionWireV1 {
    pub schema: String,
    pub completion: String,
    pub reservation: String,
    pub round: String,
    pub result_identity: String,
    pub completed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorReconciliationDispatchWireV1 {
    pub schema: String,
    pub request: String,
    pub round: String,
    pub reservation: String,
    pub source_cut: String,
    pub dispatch: ExecutorDispatchWireV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DocketReconciliationRoundStateWireV1 {
    NotAccepted,
    Refused(DocketIssuanceRefusalWireV1),
    Unresolved(ReconciliationRoundReservationWireV1),
    Completed {
        reservation: ReconciliationRoundReservationWireV1,
        completion: ReconciliationRoundCompletionWireV1,
        response: Box<DocketReconciliationWireV1>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketReconciliationRoundResponseWireV1 {
    pub schema: String,
    pub request: String,
    pub round: String,
    #[serde(flatten)]
    pub state: DocketReconciliationRoundStateWireV1,
}

#[derive(Clone, Debug)]
struct ReconciliationRoundRecordV1 {
    reservation: ReconciliationRoundReservationWireV1,
    signed_body_b64: String,
    authentication: IssuanceAuthenticationWireV1,
    state: String,
    completion: Option<ReconciliationRoundCompletionWireV1>,
    result_kind: Option<String>,
    result_reconciliation: Option<String>,
    result_evidence: Option<String>,
}

enum ReconciliationRoundClaimV1 {
    Winner(Box<ReconciliationRoundReservationWireV1>),
    Existing(Box<ReconciliationRoundRecordV1>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationSourceCutWireV1 {
    issuance: String,
    attempt: String,
    custody: String,
    status: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    checkpoint_identity: Option<String>,
    executor_binding: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    latest_executor_result: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    latest_executor_outcome: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    latest_cumulative_journal: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    latest_completed_round: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    latest_completed_result: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    terminal_result_kind: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    terminal_result_identity: Option<String>,
}

struct ReconciliationSourceCutV1 {
    identity: String,
    canonical_bytes: Vec<u8>,
    basis: ReconciliationSourceCutWireV1,
    terminal_result: Option<(String, String)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DurableReconciliationResultV1 {
    kind: String,
    identity: String,
    reconciliation: Option<String>,
    evidence: Option<String>,
}

enum ReconciliationSourceAdvanceV1 {
    Unchanged,
    Monotone(DurableReconciliationResultV1),
}

#[derive(Serialize)]
struct ReconciliationReservationIdentityBasisV1<'a> {
    schema: &'a str,
    request: &'a str,
    round: &'a str,
    issuance: &'a str,
    attempt: &'a str,
    caller_state_digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_round: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_reconciliation: Option<&'a str>,
    source_cut: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint_identity: Option<&'a str>,
    executor_binding: &'a str,
    claimed_at_unix_ms: u64,
}

#[derive(Serialize)]
struct ReconciliationCompletionIdentityBasisV1<'a> {
    schema: &'a str,
    reservation: &'a str,
    round: &'a str,
    result_identity: &'a str,
    completed_at_unix_ms: u64,
}

#[derive(Clone, Debug)]
struct CustodyRecordV1 {
    issuance: AgIssuanceWireV2,
    custody: DocketCustodyWireV1,
    signed_body_b64: String,
    authentication: IssuanceAuthenticationWireV1,
    executor_binding: String,
    executor_program_digest: String,
    executor_config_digest: String,
    executor_plan: String,
    status: String,
    settlement: Option<DocketSettlementWireV1>,
    indeterminate: Option<IndeterminateOutcomeWireV1>,
}

#[derive(Clone, Debug)]
struct IssuanceRefusalRecordV1 {
    refusal: DocketIssuanceRefusalWireV1,
    signed_body_b64: String,
    authentication: IssuanceAuthenticationWireV1,
}

#[derive(Clone, Debug)]
struct RefusalDraftV1 {
    refusal_class: DocketIssuanceRefusalClassWireV1,
    reason_code: String,
    evidence: String,
}

enum IntakeValidationErrorV1 {
    Transient(String),
    Refusal(RefusalDraftV1),
}

enum JsonInvocationErrorV1 {
    Unavailable(String),
    InvalidResponse {
        reason_code: String,
        evidence: String,
    },
}

/// Authenticates the exact AG issuance bytes against explicit Docket trust.
pub fn verify_signed_issuance(
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
) -> Result<(SignedIssuanceEnvelopeWireV1, AgIssuanceWireV2), String> {
    let (envelope, issuance, _) = authenticate_signed_issuance(envelope_bytes, trust_bytes)?;
    validate_issuance(&issuance)?;
    Ok((envelope, issuance))
}

/// Authenticates one exact AG reconciliation-round request.  Certificate
/// bytes are evidence only: custody is not touched until the Store later
/// claims the exact round against its current durable source cut.
pub fn verify_signed_reconciliation_round_request(
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
) -> Result<
    (
        SignedReconciliationRoundRequestEnvelopeWireV1,
        ReconciliationRoundRequestWireV1,
    ),
    String,
> {
    let envelope: SignedReconciliationRoundRequestEnvelopeWireV1 =
        strict_json(envelope_bytes, "reconciliation-round-envelope")?;
    let canonical_envelope = serde_jcs::to_vec(
        &serde_json::to_value(&envelope)
            .map_err(|error| format!("reconciliation-round-envelope-value:{error}"))?,
    )
    .map_err(|error| format!("reconciliation-round-envelope-canonical:{error}"))?;
    if canonical_envelope != envelope_bytes {
        return Err("governed-reconciliation-round-envelope-not-canonical".to_owned());
    }
    if envelope.schema != SIGNED_RECONCILIATION_ROUND_REQUEST_SCHEMA_V1 {
        return Err("governed-reconciliation-round-envelope-schema".to_owned());
    }
    let trust: AgIssuerTrustConfigV1 = strict_json(trust_bytes, "issuer-trust")?;
    let trusted = trust
        .issuers
        .iter()
        .find(|candidate| {
            candidate.issuer_principal == envelope.authentication.issuer_principal
                && candidate.key_id == envelope.authentication.signer_key_id
        })
        .ok_or_else(|| "governed-reconciliation-round-untrusted-issuer".to_owned())?;
    if trusted.public_key != envelope.authentication.signer_public_key {
        return Err("governed-reconciliation-round-public-key-substitution".to_owned());
    }
    let body = b64_decode(&envelope.body_b64)?;
    let public_key = b64_decode(&trusted.public_key)?;
    let signature = b64_decode(&envelope.authentication.signature)?;
    let mut signed =
        Vec::with_capacity(RECONCILIATION_ROUND_SIGNATURE_PREFIX_V1.len() + body.len());
    signed.extend_from_slice(RECONCILIATION_ROUND_SIGNATURE_PREFIX_V1);
    signed.extend_from_slice(&body);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signed, &signature)
        .map_err(|_| "governed-reconciliation-round-signature-invalid".to_owned())?;
    let request: ReconciliationRoundRequestWireV1 =
        strict_json(&body, "reconciliation-round-body")?;
    let canonical_body = serde_jcs::to_vec(
        &serde_json::to_value(&request)
            .map_err(|error| format!("reconciliation-round-body-value:{error}"))?,
    )
    .map_err(|error| format!("reconciliation-round-body-canonical:{error}"))?;
    if canonical_body != body {
        return Err("governed-reconciliation-round-body-not-canonical".to_owned());
    }
    validate_reconciliation_round_request(&request)?;
    Ok((envelope, request))
}

fn validate_reconciliation_round_request(
    request: &ReconciliationRoundRequestWireV1,
) -> Result<(), String> {
    if request.schema != RECONCILIATION_ROUND_REQUEST_SCHEMA_V1 {
        return Err("governed-reconciliation-round-schema".to_owned());
    }
    for (value, label) in [
        (&request.request, "request"),
        (&request.round, "round"),
        (&request.issuance, "issuance"),
        (&request.attempt, "attempt"),
        (&request.caller_state_digest, "caller state"),
        (&request.idempotency, "idempotency"),
    ] {
        require_digest(value, label)?;
    }
    match (
        request.predecessor_round.as_deref(),
        request.predecessor_reconciliation.as_deref(),
    ) {
        (None, None) => {}
        (Some(round), Some(reconciliation)) => {
            require_digest(round, "predecessor round")?;
            require_digest(reconciliation, "predecessor reconciliation")?;
        }
        _ => return Err("governed-reconciliation-round-predecessor-shape".to_owned()),
    }
    let round_basis = ReconciliationRoundIdentityBasisV1 {
        schema: &request.schema,
        issuance: &request.issuance,
        attempt: &request.attempt,
        caller_state_digest: &request.caller_state_digest,
        predecessor_round: request.predecessor_round.as_deref(),
        predecessor_reconciliation: request.predecessor_reconciliation.as_deref(),
        idempotency: &request.idempotency,
    };
    let round_bytes = serde_jcs::to_vec(&round_basis)
        .map_err(|error| format!("governed-reconciliation-round-basis:{error}"))?;
    if request.round != hash_domain("ag.governed-loop.reconciliation-round/v1", &round_bytes) {
        return Err("governed-reconciliation-round-identity".to_owned());
    }
    let request_basis = ReconciliationRequestIdentityBasisV1 {
        schema: &request.schema,
        round: &request.round,
        issuance: &request.issuance,
        attempt: &request.attempt,
        caller_state_digest: &request.caller_state_digest,
        predecessor_round: request.predecessor_round.as_deref(),
        predecessor_reconciliation: request.predecessor_reconciliation.as_deref(),
        idempotency: &request.idempotency,
    };
    let request_bytes = serde_jcs::to_vec(&request_basis)
        .map_err(|error| format!("governed-reconciliation-request-basis:{error}"))?;
    if request.request
        != hash_domain(
            "ag.governed-loop.reconciliation-round-request/v1",
            &request_bytes,
        )
    {
        return Err("governed-reconciliation-request-identity".to_owned());
    }
    Ok(())
}

fn authenticate_signed_issuance(
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
) -> Result<(SignedIssuanceEnvelopeWireV1, AgIssuanceWireV2, Vec<u8>), String> {
    let envelope: SignedIssuanceEnvelopeWireV1 = strict_json(envelope_bytes, "issuance-envelope")?;
    let canonical_envelope = serde_jcs::to_vec(
        &serde_json::to_value(&envelope)
            .map_err(|error| format!("issuance-envelope-canonical-value:{error}"))?,
    )
    .map_err(|error| format!("issuance-envelope-canonical:{error}"))?;
    if canonical_envelope != envelope_bytes {
        return Err("governed-issuance-envelope-not-canonical".to_owned());
    }
    if envelope.schema != SIGNED_ISSUANCE_SCHEMA_V2 {
        return Err("governed-issuance-envelope-schema".to_owned());
    }
    let trust: AgIssuerTrustConfigV1 = strict_json(trust_bytes, "issuer-trust")?;
    let trusted = trust
        .issuers
        .iter()
        .find(|candidate| {
            candidate.issuer_principal == envelope.authentication.issuer_principal
                && candidate.key_id == envelope.authentication.signer_key_id
        })
        .ok_or_else(|| "governed-issuance-untrusted-issuer".to_owned())?;
    if trusted.public_key != envelope.authentication.signer_public_key {
        return Err("governed-issuance-public-key-substitution".to_owned());
    }
    let body = b64_decode(&envelope.body_b64)?;
    let public_key = b64_decode(&trusted.public_key)?;
    let signature = b64_decode(&envelope.authentication.signature)?;
    let mut signed = Vec::with_capacity(SIGNATURE_PREFIX_V2.len() + body.len());
    signed.extend_from_slice(SIGNATURE_PREFIX_V2);
    signed.extend_from_slice(&body);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signed, &signature)
        .map_err(|_| "governed-issuance-signature-invalid".to_owned())?;
    let issuance: AgIssuanceWireV2 = strict_json(&body, "issuance-body")?;
    let canonical_value: serde_json::Value = strict_json(&body, "issuance-canonical-value")?;
    if canonical_value
        .get("governed_repair_checkpoint")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|checkpoint| {
            ["diff_identity", "docket_checkpoint"].iter().any(|field| {
                checkpoint
                    .get(*field)
                    .is_some_and(serde_json::Value::is_null)
            })
        })
    {
        return Err("governed-checkpoint-null-diff-noncanonical".to_owned());
    }
    let canonical = serde_jcs::to_vec(&canonical_value)
        .map_err(|error| format!("issuance-canonical:{error}"))?;
    if canonical != body {
        return Err("governed-issuance-body-not-canonical".to_owned());
    }
    Ok((envelope, issuance, body))
}

/// Accepts one exact issuance, consumes fresh Docket standing transactionally,
/// persists custody, and then invokes exactly one executor delivery.
pub fn accept(
    database: &Path,
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
    standing_resolver: &Path,
    executor: &Path,
    executor_config: &Path,
) -> Result<DocketExecutionResponseWireV1, String> {
    accept_with_checkpoint_verifier(
        database,
        envelope_bytes,
        trust_bytes,
        standing_resolver,
        executor,
        executor_config,
        None,
    )
}

/// Accepts an issuance with an explicit verifier for an optional immutable
/// starting work checkpoint. The verifier establishes exact repository object
/// correspondence; serialized checkpoint evidence alone grants nothing.
pub fn accept_with_checkpoint_verifier(
    database: &Path,
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
    standing_resolver: &Path,
    executor: &Path,
    executor_config: &Path,
    checkpoint_verifier: Option<&Path>,
) -> Result<DocketExecutionResponseWireV1, String> {
    let (envelope, issuance, authenticated_body) =
        authenticate_signed_issuance(envelope_bytes, trust_bytes)?;
    let mut store = GovernedCustodyStoreV1::open(database)?;
    if let Err(reason_code) = validate_issuance(&issuance) {
        validate_refusable_issuance_identity(&issuance)?;
        if let Some(existing) = store.get_refusal(&issuance.issuance)? {
            require_same_refusal_envelope(&existing, &envelope, &issuance)?;
            return Ok(DocketExecutionResponseWireV1::Refused(existing.refusal));
        }
        return store.refuse(
            &envelope,
            &issuance,
            RefusalDraftV1 {
                refusal_class: DocketIssuanceRefusalClassWireV1::IssuanceInvalid,
                evidence: refusal_evidence(
                    &issuance,
                    DocketIssuanceRefusalClassWireV1::IssuanceInvalid,
                    &reason_code,
                    &authenticated_body,
                )?,
                reason_code,
            },
            now_unix_ms()?,
        );
    }
    if let Some(existing) = store.get_refusal(&issuance.issuance)? {
        require_same_refusal_envelope(&existing, &envelope, &issuance)?;
        return Ok(DocketExecutionResponseWireV1::Refused(existing.refusal));
    }
    if let Some(existing) = store.get(&issuance.issuance)? {
        require_same_envelope(&existing, &envelope, &issuance)?;
        // Starting-checkpoint correspondence is process-local evidence.  It
        // must be freshly re-established before an old custody record is
        // returned after restart/re-entry.
        verify_starting_checkpoint(&issuance, checkpoint_verifier, now_unix_ms()?)?;
        if let Some(result) =
            governed_repair::read_sealed_result(&store.connection, &issuance.issuance)?
        {
            require_result_custody(&result, &existing.custody)?;
            return Ok(DocketExecutionResponseWireV1::GovernedRepairRequired {
                custody: existing.custody,
                result: Box::new(result),
            });
        }
        return Ok(DocketExecutionResponseWireV1::Custody(existing.custody));
    }

    let now = now_unix_ms()?;
    if let Err(reason_code) = validate_fresh_issuance(&issuance, now) {
        return store.refuse(
            &envelope,
            &issuance,
            RefusalDraftV1 {
                refusal_class: DocketIssuanceRefusalClassWireV1::IssuanceExpired,
                evidence: refusal_evidence(
                    &issuance,
                    DocketIssuanceRefusalClassWireV1::IssuanceExpired,
                    &reason_code,
                    &issuance.expires_at_unix_ms.to_be_bytes(),
                )?,
                reason_code,
            },
            now,
        );
    }
    if let Err(error) = verify_starting_checkpoint_for_intake(&issuance, checkpoint_verifier, now) {
        return match error {
            IntakeValidationErrorV1::Transient(error) => Err(error),
            IntakeValidationErrorV1::Refusal(draft) => {
                store.refuse(&envelope, &issuance, draft, now)
            }
        };
    }
    let (standing, standing_bytes): (ExecutionStandingResolutionV1, Vec<u8>) =
        match invoke_json_classified(
            standing_resolver,
            &[],
            &ExecutionStandingRequestV1 {
                schema: STANDING_REQUEST_SCHEMA_V1.to_owned(),
                issuance: issuance.clone(),
                now_unix_ms: now,
            },
        ) {
            Ok(value) => value,
            Err(JsonInvocationErrorV1::Unavailable(error)) => return Err(error),
            Err(JsonInvocationErrorV1::InvalidResponse {
                reason_code,
                evidence,
            }) => {
                return store.refuse(
                    &envelope,
                    &issuance,
                    RefusalDraftV1 {
                        refusal_class: DocketIssuanceRefusalClassWireV1::StandingInvalid,
                        reason_code,
                        evidence,
                    },
                    now,
                )
            }
        };
    if let Err(reason_code) = validate_standing(&issuance, &standing, now) {
        return store.refuse(
            &envelope,
            &issuance,
            RefusalDraftV1 {
                refusal_class: DocketIssuanceRefusalClassWireV1::StandingInvalid,
                evidence: refusal_evidence(
                    &issuance,
                    DocketIssuanceRefusalClassWireV1::StandingInvalid,
                    &reason_code,
                    &standing_bytes,
                )?,
                reason_code,
            },
            now,
        );
    }
    let attempt = digest_json_string("ag.governed-loop.docket-attempt/v1", &issuance.issuance)?;
    let marker = hash_domain(
        "docket.governed-loop.executor-marker/v1",
        attempt.as_bytes(),
    );
    if standing.execution_standing.as_str() == issuance.spend.as_str()
        || standing.execution_standing.as_str() == attempt.as_str()
        || standing.execution_standing.as_str() == marker.as_str()
        || issuance.spend.as_str() == attempt.as_str()
        || issuance.spend.as_str() == marker.as_str()
        || attempt.as_str() == marker.as_str()
    {
        let reason_code = "governed-instrument-substitution".to_owned();
        return store.refuse(
            &envelope,
            &issuance,
            RefusalDraftV1 {
                refusal_class: DocketIssuanceRefusalClassWireV1::InstrumentSubstitution,
                evidence: refusal_evidence(
                    &issuance,
                    DocketIssuanceRefusalClassWireV1::InstrumentSubstitution,
                    &reason_code,
                    &standing_bytes,
                )?,
                reason_code,
            },
            now,
        );
    }
    let prepared_executor = prepare_executor(executor, executor_config, &issuance.work)?;
    let executor_binding = prepared_executor.binding.clone();
    let custody = DocketCustodyWireV1 {
        schema: CUSTODY_SCHEMA_V1.to_owned(),
        issuance: issuance.issuance.clone(),
        ag_spend: issuance.spend.clone(),
        execution_standing: standing.execution_standing.clone(),
        standing_currentness: standing.currentness.clone(),
        attempt,
        executor_marker: marker,
        accepted_at_unix_ms: now,
    };
    match store.insert_custody(&envelope, &issuance, &standing, &custody, &executor_binding) {
        Ok(()) => {}
        Err(error) => {
            if let Some(existing) = store.get(&issuance.issuance)? {
                require_same_envelope(&existing, &envelope, &issuance)?;
                return Ok(DocketExecutionResponseWireV1::Custody(existing.custody));
            }
            if let Some(existing) = store.get_refusal(&issuance.issuance)? {
                require_same_refusal_envelope(&existing, &envelope, &issuance)?;
                return Ok(DocketExecutionResponseWireV1::Refused(existing.refusal));
            }
            return Err(error);
        }
    }

    // The custody transaction above is committed before any mechanics call.
    // A process loss here leaves an exact accepted attempt and can never make
    // this issuance dispatchable as a second attempt.
    let dispatch = executor_dispatch(&issuance, &custody);
    match invoke_retained_json::<_, ExecutorOutcomeWireV1>(
        &prepared_executor.retained,
        "execute",
        &dispatch,
    ) {
        Ok(outcome) => {
            #[cfg(test)]
            CRASH_AFTER_EXECUTOR_RESULT_BEFORE_SEAL.with(|failpoint| {
                assert!(
                    !failpoint.replace(false),
                    "injected logical crash after executor result before Docket seal"
                );
            });
            store.record_executor_outcome(&issuance.issuance, &custody, outcome, now_unix_ms()?)?
        }
        Err(error) => store.record_indeterminate(
            &issuance.issuance,
            &custody,
            &hash_domain(
                "docket.governed-loop.executor-unavailable/v1",
                error.as_bytes(),
            ),
        )?,
    }
    if let Some(result) =
        governed_repair::read_sealed_result(&store.connection, &issuance.issuance)?
    {
        require_result_custody(&result, &custody)?;
        Ok(DocketExecutionResponseWireV1::GovernedRepairRequired {
            custody,
            result: Box::new(result),
        })
    } else {
        Ok(DocketExecutionResponseWireV1::Custody(custody))
    }
}

/// Consequence-free durable issuance/custody lookup used by AG recovery before
/// it has (or may lawfully create) an explicit reconciliation round.  This
/// operation never prepares or invokes an executor.
pub fn observe_issuance_with_checkpoint_verifier(
    database: &Path,
    issuance: &str,
    checkpoint_verifier: Option<&Path>,
) -> Result<DocketReconciliationWireV1, String> {
    require_digest(issuance, "issuance")?;
    let mut store = GovernedCustodyStoreV1::open(database)?;
    let Some(record) = store.get(issuance)? else {
        if let Some(refusal) = store.get_refusal(issuance)? {
            return Ok(DocketReconciliationWireV1::Refused(refusal.refusal));
        }
        return Ok(DocketReconciliationWireV1::NotAccepted);
    };
    verify_starting_checkpoint(&record.issuance, checkpoint_verifier, now_unix_ms()?)?;
    if let Some(result) = governed_repair::read_sealed_result(&store.connection, issuance)? {
        require_result_custody(&result, &record.custody)?;
        return Ok(DocketReconciliationWireV1::GovernedRepairRequired {
            custody: record.custody,
            result: Box::new(result),
        });
    }
    response_from_record(record)
}

/// Authenticates and durably resolves one exact reconciliation round.
/// A nonterminal claim commits before the external boundary. A first round at
/// an already-terminal initial-attempt cut is claimed and completed locally in
/// one transaction, with no executor invocation. Exact duplicate delivery
/// observes the durable completed or unresolved round and never calls the
/// executor again.
pub fn reconcile_signed_round_with_checkpoint_verifier(
    database: &Path,
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
    executor: &Path,
    executor_config: &Path,
    checkpoint_verifier: Option<&Path>,
) -> Result<DocketReconciliationRoundResponseWireV1, String> {
    let (envelope, request) =
        verify_signed_reconciliation_round_request(envelope_bytes, trust_bytes)?;
    let mut store = GovernedCustodyStoreV1::open(database)?;
    if let Some(mut existing) = store.read_reconciliation_round(&request.request)? {
        if existing.signed_body_b64 != envelope.body_b64
            || existing.authentication != envelope.authentication
        {
            return Err("governed-reconciliation-request-replay-collision".to_owned());
        }
        let record = store
            .get(&request.issuance)?
            .ok_or_else(|| "governed-reconciliation-custody-missing".to_owned())?;
        if existing.authentication.issuer_principal != record.authentication.issuer_principal
            || existing.authentication.signer_key_id != record.authentication.signer_key_id
            || existing.authentication.signer_public_key != record.authentication.signer_public_key
        {
            return Err("governed-reconciliation-issuance-issuer-substitution".to_owned());
        }
        verify_starting_checkpoint(&record.issuance, checkpoint_verifier, now_unix_ms()?)?;
        // A process crash with an unchanged source cut stays explicitly
        // unresolved. If the independently running initial dispatch advanced
        // the exact attempt after this round claimed, resolve the round from
        // that durable monotone result without another executor call.
        if store.resolve_claimed_round_from_durable_source(&existing, &record, now_unix_ms()?)? {
            existing = store
                .read_reconciliation_round(&request.request)?
                .ok_or_else(|| "governed-reconciliation-round-disappeared".to_owned())?;
        }
        return store.reconciliation_round_response(existing);
    }
    let Some(record) = store.get(&request.issuance)? else {
        let result = if let Some(refusal) = store.get_refusal(&request.issuance)? {
            DocketReconciliationRoundStateWireV1::Refused(refusal.refusal)
        } else {
            DocketReconciliationRoundStateWireV1::NotAccepted
        };
        return Ok(DocketReconciliationRoundResponseWireV1 {
            schema: RECONCILIATION_ROUND_RESPONSE_SCHEMA_V1.to_owned(),
            request: request.request,
            round: request.round,
            state: result,
        });
    };
    if request.attempt != record.custody.attempt {
        return Err("governed-reconciliation-attempt-substitution".to_owned());
    }
    verify_starting_checkpoint(&record.issuance, checkpoint_verifier, now_unix_ms()?)?;
    let expected_binding = ExecutorBindingV1 {
        identity: record.executor_binding.clone(),
        program_digest: record.executor_program_digest.clone(),
        config_digest: record.executor_config_digest.clone(),
        plan: record.executor_plan.clone(),
    };
    // Revalidate and retain the exact executor/config bytes without crossing
    // the executor process boundary.  The round reservation must commit
    // before *any* external reconciliation process is invoked.  Acceptance
    // already bound the plan identity to these exact byte digests; reproducing
    // the complete binding here therefore needs no pre-claim `plan-id` call.
    let retained_executor = retain_bound_executor(executor, executor_config, &expected_binding)?;
    let reservation = match store.claim_reconciliation_round(
        &envelope,
        &request,
        &record,
        &expected_binding,
        now_unix_ms()?,
    )? {
        ReconciliationRoundClaimV1::Existing(existing) => {
            return store.reconciliation_round_response(*existing)
        }
        ReconciliationRoundClaimV1::Winner(reservation) => *reservation,
    };
    let dispatch =
        executor_reconciliation_dispatch(&request, &reservation, &record.issuance, &record.custody);
    let outcome = match invoke_retained_json::<_, ExecutorOutcomeWireV1>(
        &retained_executor,
        "reconcile",
        &dispatch,
    ) {
        Ok(outcome) => outcome,
        Err(error) => ExecutorOutcomeWireV1 {
            attempt: record.custody.attempt.clone(),
            marker: record.custody.executor_marker.clone(),
            receipt: hash_domain(
                "docket.governed-loop.reconciliation-unavailable/v1",
                format!("{}:{error}", request.round).as_bytes(),
            ),
            outcome: ExecutorOutcomeClassWireV1::Indeterminate,
            effect_journal: Vec::new(),
            immutable_work_checkpoint: None,
            governed_repair: None,
        },
    };
    store.complete_reconciliation_round(
        &request,
        &reservation,
        &record,
        outcome,
        now_unix_ms()?,
    )?;
    let completed = store
        .read_reconciliation_round(&request.request)?
        .ok_or_else(|| "governed-reconciliation-round-disappeared".to_owned())?;
    store.reconciliation_round_response(completed)
}

/// Legacy raw reconciliation exists only for internal R3 regression tests. It
/// is absent from ordinary production builds; production callers must present
/// an authenticated explicit round request.
#[cfg(test)]
fn reconcile_with_checkpoint_verifier(
    database: &Path,
    issuance: &str,
    expected_attempt: Option<&str>,
    executor: &Path,
    executor_config: &Path,
    checkpoint_verifier: Option<&Path>,
) -> Result<DocketReconciliationWireV1, String> {
    require_digest(issuance, "issuance")?;
    let mut store = GovernedCustodyStoreV1::open(database)?;
    let Some(mut record) = store.get(issuance)? else {
        if let Some(refusal) = store.get_refusal(issuance)? {
            if expected_attempt.is_some() {
                return Err("governed-refusal-has-no-attempt".to_owned());
            }
            return Ok(DocketReconciliationWireV1::Refused(refusal.refusal));
        }
        return Ok(DocketReconciliationWireV1::NotAccepted);
    };
    if expected_attempt.is_some_and(|expected| expected != record.custody.attempt) {
        return Err("governed-reconciliation-attempt-substitution".to_owned());
    }
    if let Some(result) = governed_repair::read_sealed_result(&store.connection, issuance)? {
        // A sealed result is durable evidence, not inherited checkpoint
        // correspondence. Re-emission after process re-entry must freshly
        // verify the exact starting checkpoint before returning the result.
        // Refusal invokes no executor and leaves custody/result bytes intact.
        verify_starting_checkpoint(&record.issuance, checkpoint_verifier, now_unix_ms()?)?;
        require_result_custody(&result, &record.custody)?;
        return Ok(DocketReconciliationWireV1::GovernedRepairRequired {
            custody: record.custody,
            result: Box::new(result),
        });
    }
    if record.status == "settled" {
        // A known settlement remains terminal evidence, not inherited
        // checkpoint correspondence. Successor settlement replay therefore
        // observes the same fresh verifier boundary as governed-result replay.
        verify_starting_checkpoint(&record.issuance, checkpoint_verifier, now_unix_ms()?)?;
        return response_from_record(record);
    }

    // A starting checkpoint is evidence, never inherited authority. Every
    // process entry that may call the executor freshly verifies the exact
    // immutable bytes before mechanics. A refusal therefore advances neither
    // custody nor executor state and makes zero executor calls.
    verify_starting_checkpoint(&record.issuance, checkpoint_verifier, now_unix_ms()?)?;

    let expected_binding = ExecutorBindingV1 {
        identity: record.executor_binding.clone(),
        program_digest: record.executor_program_digest.clone(),
        config_digest: record.executor_config_digest.clone(),
        plan: record.executor_plan.clone(),
    };
    let prepared_executor = prepare_executor(executor, executor_config, &expected_binding.plan)?;
    if prepared_executor.binding != expected_binding {
        return Err("governed-executor-binding-substitution".to_owned());
    }

    let dispatch = executor_dispatch(&record.issuance, &record.custody);
    match invoke_retained_json::<_, ExecutorOutcomeWireV1>(
        &prepared_executor.retained,
        "reconcile",
        &dispatch,
    ) {
        Ok(outcome) => {
            store.record_executor_outcome(issuance, &record.custody, outcome, now_unix_ms()?)?
        }
        Err(error) if record.status == "accepted" => store.record_indeterminate(
            issuance,
            &record.custody,
            &hash_domain(
                "docket.governed-loop.reconciliation-unavailable/v1",
                error.as_bytes(),
            ),
        )?,
        Err(_) => {}
    }
    if let Some(result) = governed_repair::read_sealed_result(&store.connection, issuance)? {
        require_result_custody(&result, &record.custody)?;
        return Ok(DocketReconciliationWireV1::GovernedRepairRequired {
            custody: record.custody,
            result: Box::new(result),
        });
    }
    record = store
        .get(issuance)?
        .ok_or_else(|| "governed-custody-disappeared".to_owned())?;
    response_from_record(record)
}

/// Test-only R3 compatibility wrapper.
#[cfg(test)]
fn reconcile(
    database: &Path,
    issuance: &str,
    expected_attempt: Option<&str>,
    executor: &Path,
    executor_config: &Path,
) -> Result<DocketReconciliationWireV1, String> {
    reconcile_with_checkpoint_verifier(
        database,
        issuance,
        expected_attempt,
        executor,
        executor_config,
        None,
    )
}

fn response_from_record(record: CustodyRecordV1) -> Result<DocketReconciliationWireV1, String> {
    match record.status.as_str() {
        "accepted" => Ok(DocketReconciliationWireV1::Accepted(record.custody)),
        "settled" => Ok(DocketReconciliationWireV1::Settled {
            custody: record.custody,
            settlement: record
                .settlement
                .ok_or_else(|| "governed-settlement-columns-missing".to_owned())?,
        }),
        "indeterminate" => Ok(DocketReconciliationWireV1::Indeterminate {
            custody: record.custody,
            indeterminate: record
                .indeterminate
                .ok_or_else(|| "governed-indeterminate-columns-missing".to_owned())?,
        }),
        _ => Err("governed-custody-status-corrupt".to_owned()),
    }
}

fn executor_dispatch(
    issuance: &AgIssuanceWireV2,
    custody: &DocketCustodyWireV1,
) -> ExecutorDispatchWireV1 {
    ExecutorDispatchWireV1 {
        attempt: custody.attempt.clone(),
        marker: custody.executor_marker.clone(),
        work_schema: issuance.work_schema.clone(),
        work: issuance.work.clone(),
        subject: issuance.subject.clone(),
        effect_scope: issuance.effect_scope.clone(),
        effect_scope_digest: issuance.effect_scope_digest.clone(),
    }
}

fn executor_reconciliation_dispatch(
    request: &ReconciliationRoundRequestWireV1,
    reservation: &ReconciliationRoundReservationWireV1,
    issuance: &AgIssuanceWireV2,
    custody: &DocketCustodyWireV1,
) -> ExecutorReconciliationDispatchWireV1 {
    ExecutorReconciliationDispatchWireV1 {
        schema: EXECUTOR_RECONCILIATION_DISPATCH_SCHEMA_V1.to_owned(),
        request: request.request.clone(),
        round: request.round.clone(),
        reservation: reservation.reservation.clone(),
        source_cut: reservation.source_cut.clone(),
        dispatch: executor_dispatch(issuance, custody),
    }
}

fn starting_checkpoint_identity(issuance: &AgIssuanceWireV2) -> Result<Option<String>, String> {
    issuance
        .governed_repair_checkpoint
        .as_ref()
        .map(|checkpoint| {
            let bytes = serde_jcs::to_vec(checkpoint)
                .map_err(|error| format!("governed-starting-checkpoint-canonical:{error}"))?;
            Ok(hash_domain(
                "docket.governed-loop.starting-checkpoint/v1",
                &bytes,
            ))
        })
        .transpose()
}

fn reservation_identity(
    reservation: &ReconciliationRoundReservationWireV1,
) -> Result<String, String> {
    let basis = ReconciliationReservationIdentityBasisV1 {
        schema: &reservation.schema,
        request: &reservation.request,
        round: &reservation.round,
        issuance: &reservation.issuance,
        attempt: &reservation.attempt,
        caller_state_digest: &reservation.caller_state_digest,
        predecessor_round: reservation.predecessor_round.as_deref(),
        predecessor_reconciliation: reservation.predecessor_reconciliation.as_deref(),
        source_cut: &reservation.source_cut,
        checkpoint_identity: reservation.checkpoint_identity.as_deref(),
        executor_binding: &reservation.executor_binding,
        claimed_at_unix_ms: reservation.claimed_at_unix_ms,
    };
    let bytes = serde_jcs::to_vec(&basis)
        .map_err(|error| format!("governed-reconciliation-reservation-canonical:{error}"))?;
    Ok(hash_domain(
        "docket.governed-loop.reconciliation-round-reservation/v1",
        &bytes,
    ))
}

fn completion_identity(completion: &ReconciliationRoundCompletionWireV1) -> Result<String, String> {
    let basis = ReconciliationCompletionIdentityBasisV1 {
        schema: &completion.schema,
        reservation: &completion.reservation,
        round: &completion.round,
        result_identity: &completion.result_identity,
        completed_at_unix_ms: completion.completed_at_unix_ms,
    };
    let bytes = serde_jcs::to_vec(&basis)
        .map_err(|error| format!("governed-reconciliation-completion-canonical:{error}"))?;
    Ok(hash_domain(
        "docket.governed-loop.reconciliation-round-completion/v1",
        &bytes,
    ))
}

fn require_result_custody(
    result: &StoreSealedGovernedRepairResultV1,
    custody: &DocketCustodyWireV1,
) -> Result<(), String> {
    let expected = governed_repair::ag_custody_reference(custody)?;
    if result.checkpoint.issuance != custody.issuance
        || result.checkpoint.attempt != custody.attempt
        || result.checkpoint.custody != expected
    {
        return Err("governed-repair-custody-substitution".to_owned());
    }
    Ok(())
}

fn build_refusal(
    issuance: &AgIssuanceWireV2,
    draft: RefusalDraftV1,
    refused_at_unix_ms: u64,
) -> Result<DocketIssuanceRefusalWireV1, String> {
    require_digest(&draft.evidence, "issuance refusal evidence")?;
    if draft.reason_code.is_empty()
        || draft.reason_code.len() > 256
        || !draft
            .reason_code
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        || refused_at_unix_ms > MAX_JCS_SAFE_INTEGER
    {
        return Err("governed-refusal-constraints".to_owned());
    }
    let mut refusal = DocketIssuanceRefusalWireV1 {
        schema: ISSUANCE_REFUSAL_SCHEMA_V1.to_owned(),
        refusal: String::new(),
        issuance: issuance.issuance.clone(),
        campaign: issuance.key.campaign.clone(),
        occurrence: issuance.key.occurrence.clone(),
        refusal_class: draft.refusal_class,
        reason_code: draft.reason_code,
        evidence: draft.evidence,
        refused_at_unix_ms,
    };
    refusal.refusal = refusal_identity(&refusal)?;
    Ok(refusal)
}

fn refusal_identity(refusal: &DocketIssuanceRefusalWireV1) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        Transcript::new(ISSUANCE_REFUSAL_SCHEMA_V1)
            .text_field("schema", &refusal.schema)
            .text_field("issuance", &refusal.issuance)
            .text_field("campaign", &refusal.campaign)
            .text_field("occurrence", &refusal.occurrence)
            .text_field("refusal_class", refusal.refusal_class.tag())
            .text_field("reason_code", &refusal.reason_code)
            .text_field("evidence", &refusal.evidence)
            .text_field(
                "refused_at_unix_ms",
                &refusal.refused_at_unix_ms.to_string(),
            )
            .finalize()
    ))
}

fn refusal_evidence(
    issuance: &AgIssuanceWireV2,
    refusal_class: DocketIssuanceRefusalClassWireV1,
    reason_code: &str,
    exact_evidence_bytes: &[u8],
) -> Result<String, String> {
    let evidence_bytes = format!("sha256:{}", Sha256Digest::of_bytes(exact_evidence_bytes));
    Ok(format!(
        "sha256:{}",
        Transcript::new("docket.governed-loop.issuance-refusal-evidence/v1")
            .text_field("issuance", &issuance.issuance)
            .text_field("refusal_class", refusal_class.tag())
            .text_field("reason_code", reason_code)
            .text_field("evidence_bytes", &evidence_bytes)
            .finalize()
    ))
}

fn require_same_refusal_envelope(
    stored: &IssuanceRefusalRecordV1,
    envelope: &SignedIssuanceEnvelopeWireV1,
    issuance: &AgIssuanceWireV2,
) -> Result<(), String> {
    if stored.refusal.issuance != issuance.issuance
        || stored.signed_body_b64 != envelope.body_b64
        || stored.authentication != envelope.authentication
    {
        return Err("governed-refusal-envelope-substitution".to_owned());
    }
    Ok(())
}

fn validate_stored_refusal(
    connection: &Connection,
    record: &IssuanceRefusalRecordV1,
) -> Result<(), String> {
    let refusal = &record.refusal;
    if refusal.schema != ISSUANCE_REFUSAL_SCHEMA_V1
        || refusal.campaign.is_empty()
        || refusal.occurrence.is_empty()
        || refusal.reason_code.is_empty()
        || refusal.reason_code.len() > 256
        || !refusal
            .reason_code
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        || refusal.refused_at_unix_ms > MAX_JCS_SAFE_INTEGER
    {
        return Err("governed-stored-refusal-constraints".to_owned());
    }
    for (value, label) in [
        (&refusal.refusal, "stored refusal"),
        (&refusal.issuance, "stored refusal issuance"),
        (&refusal.campaign, "stored refusal campaign"),
        (&refusal.evidence, "stored refusal evidence"),
    ] {
        require_digest(value, label)?;
    }
    require_uuid(&refusal.occurrence)?;
    if refusal_identity(refusal)? != refusal.refusal {
        return Err("governed-stored-refusal-identity".to_owned());
    }
    let disposition: Option<(String, String)> = connection
        .query_row(
            "SELECT disposition,artifact FROM governed_loop_issuance_disposition
             WHERE issuance=?1",
            params![refusal.issuance],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| format!("governed-refusal-disposition-read:{error}"))?;
    if disposition != Some(("refused".to_owned(), refusal.refusal.clone())) {
        return Err("governed-stored-refusal-disposition".to_owned());
    }
    let custody_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM governed_loop_attempt WHERE issuance=?1",
            params![refusal.issuance],
            |row| row.get(0),
        )
        .map_err(|error| format!("governed-refusal-custody-census:{error}"))?;
    if custody_count != 0 {
        return Err("governed-refusal-custody-collision".to_owned());
    }
    Ok(())
}

fn refusal_class_from_tag(value: &str) -> Result<DocketIssuanceRefusalClassWireV1, String> {
    match value {
        "issuance_invalid" => Ok(DocketIssuanceRefusalClassWireV1::IssuanceInvalid),
        "issuance_expired" => Ok(DocketIssuanceRefusalClassWireV1::IssuanceExpired),
        "checkpoint_invalid" => Ok(DocketIssuanceRefusalClassWireV1::CheckpointInvalid),
        "standing_invalid" => Ok(DocketIssuanceRefusalClassWireV1::StandingInvalid),
        "instrument_substitution" => Ok(DocketIssuanceRefusalClassWireV1::InstrumentSubstitution),
        _ => Err("governed-refusal-class-corrupt".to_owned()),
    }
}

struct SettlementMigrationRowV1 {
    issuance: String,
    attempt: String,
    executor_marker: String,
    legacy_settlement: String,
    receipt: String,
    outcome: String,
    settled_at: i64,
    signed_body_b64: String,
}

#[derive(Serialize)]
struct LegacyR1DocketSettlementWireV1<'a> {
    schema: &'a str,
    settlement: &'a str,
    issuance: &'a str,
    attempt: &'a str,
    executor_marker: &'a str,
    receipt: &'a str,
    outcome: KnownOutcomeWireV1,
    settled_at_unix_ms: u64,
}

/// Adds the settlement-level cumulative-journal binding to rejected-R1
/// development rows. Cumulative executor journals must already be backfilled.
/// A row whose terminal executor observation cannot prove the exact stored
/// receipt/outcome is refused rather than assigned a synthetic identity.
pub(crate) fn backfill_settlement_journal_identities(
    connection: &Connection,
) -> Result<(), String> {
    let rows: Vec<SettlementMigrationRowV1> = connection
        .prepare(
            "SELECT issuance,attempt,executor_marker,settlement,receipt,outcome,settled_at,
                    signed_body_b64
             FROM governed_loop_attempt WHERE status='settled' ORDER BY issuance",
        )
        .map_err(|error| format!("governed-settlement-migration-read:{error}"))?
        .query_map([], |row| {
            Ok(SettlementMigrationRowV1 {
                issuance: row.get(0)?,
                attempt: row.get(1)?,
                executor_marker: row.get(2)?,
                legacy_settlement: row.get(3)?,
                receipt: row.get(4)?,
                outcome: row.get(5)?,
                settled_at: row.get(6)?,
                signed_body_b64: row.get(7)?,
            })
        })
        .map_err(|error| format!("governed-settlement-migration-read:{error}"))?
        .collect::<Result<_, _>>()
        .map_err(|error| format!("governed-settlement-migration-read:{error}"))?;

    for row in rows {
        require_digest(&row.legacy_settlement, "legacy settlement")?;
        require_digest(&row.receipt, "legacy settlement receipt")?;
        let body = b64_decode(&row.signed_body_b64)
            .map_err(|error| format!("governed-settlement-migration-body:{error}"))?;
        let issuance: AgIssuanceWireV2 = strict_json(&body, "settlement-migration-issuance")?;
        if issuance.issuance != row.issuance {
            return Err("governed-settlement-migration-issuance-substitution".to_owned());
        }
        governed_repair::validate_ordinary_executor_result(
            connection,
            &row.issuance,
            &row.attempt,
            "settled",
            &issuance.effect_scope,
        )?;
        let terminal: Option<(String, String)> = connection
            .query_row(
                "SELECT outcome,receipt FROM governed_executor_result
                 WHERE issuance=?1 AND attempt=?2 ORDER BY sequence DESC LIMIT 1",
                params![row.issuance, row.attempt],
                |terminal| Ok((terminal.get(0)?, terminal.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("governed-settlement-migration-terminal-read:{error}"))?;
        if terminal != Some((row.outcome.clone(), row.receipt.clone()))
            || !matches!(row.outcome.as_str(), "success" | "failure")
        {
            return Err("governed-settlement-migration-terminal-incomplete".to_owned());
        }
        let expected_legacy = hash_domain(
            "docket.governed-loop.settlement/v1",
            format!(
                "{}:{}:{}:{}",
                row.issuance, row.attempt, row.receipt, row.outcome
            )
            .as_bytes(),
        );
        if row.legacy_settlement != expected_legacy {
            return Err("governed-settlement-migration-legacy-identity".to_owned());
        }
        let cumulative_effect_journal_identity =
            governed_repair::latest_cumulative_effect_journal_identity(
                connection,
                &row.issuance,
                &row.attempt,
                &issuance.effect_scope,
            )?
            .ok_or_else(|| "governed-settlement-migration-journal-missing".to_owned())?;
        let settled_at_unix_ms = u64::try_from(row.settled_at)
            .ok()
            .filter(|value| *value <= MAX_JCS_SAFE_INTEGER)
            .ok_or_else(|| "governed-settlement-migration-time".to_owned())?;
        let legacy_outcome = match row.outcome.as_str() {
            "success" => KnownOutcomeWireV1::Success,
            "failure" => KnownOutcomeWireV1::Failure,
            _ => unreachable!(),
        };
        let legacy_r1_settlement_jcs = String::from_utf8(
            serde_jcs::to_vec(&LegacyR1DocketSettlementWireV1 {
                schema: SETTLEMENT_SCHEMA_V1,
                settlement: &row.legacy_settlement,
                issuance: &row.issuance,
                attempt: &row.attempt,
                executor_marker: &row.executor_marker,
                receipt: &row.receipt,
                outcome: legacy_outcome,
                settled_at_unix_ms,
            })
            .map_err(|error| format!("governed-settlement-migration-legacy-jcs:{error}"))?,
        )
        .map_err(|error| format!("governed-settlement-migration-legacy-jcs:{error}"))?;
        let mut settlement = DocketSettlementWireV1 {
            schema: SETTLEMENT_SCHEMA_V1.to_owned(),
            settlement: String::new(),
            issuance: row.issuance.clone(),
            attempt: row.attempt.clone(),
            executor_marker: row.executor_marker,
            receipt: row.receipt,
            outcome: legacy_outcome,
            cumulative_effect_journal_identity: cumulative_effect_journal_identity.clone(),
            settled_at_unix_ms,
        };
        settlement.settlement = docket_settlement_identity(&settlement)?;
        let changed = connection
            .execute(
                "UPDATE governed_loop_attempt
                 SET settlement=?1,settlement_cumulative_effect_journal_identity=?2,
                     legacy_r1_settlement_identity=?3,legacy_r1_settlement_jcs=?4
                 WHERE issuance=?5 AND status='settled'",
                params![
                    settlement.settlement,
                    cumulative_effect_journal_identity,
                    row.legacy_settlement,
                    legacy_r1_settlement_jcs,
                    row.issuance
                ],
            )
            .map_err(|error| format!("governed-settlement-migration-write:{error}"))?;
        if changed != 1 {
            return Err("governed-settlement-migration-row-race".to_owned());
        }
    }
    Ok(())
}

struct GovernedCustodyStoreV1 {
    connection: Connection,
}

impl GovernedCustodyStoreV1 {
    fn open(database: &Path) -> Result<Self, String> {
        // Every public custody operation reaches this owner.  Retain the same
        // connection that performed canonical migration and the exact schema
        // object census; a direct library caller therefore cannot bypass the
        // gate that the `docket` CLI establishes during `State::open`.
        let connection = crate::store::SqliteStore::open(database)
            .map_err(|error| format!("governed-custody-store:{error:?}"))?
            .into_validated_connection();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|error| format!("governed-custody-foreign-keys:{error}"))?;
        connection
            .pragma_update(None, "busy_timeout", 5_000_u32)
            .map_err(|error| format!("governed-custody-busy-timeout:{error}"))?;
        let mut store = Self { connection };
        let requests = store
            .connection
            .prepare("SELECT request FROM governed_reconciliation_round ORDER BY rowid")
            .map_err(|error| format!("governed-reconciliation-round-census:{error}"))?
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| format!("governed-reconciliation-round-census:{error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("governed-reconciliation-round-census:{error}"))?;
        for request in requests {
            store
                .read_reconciliation_round(&request)?
                .ok_or_else(|| "governed-reconciliation-round-census-gap".to_owned())?;
        }
        Ok(store)
    }

    fn read_reconciliation_round(
        &mut self,
        request: &str,
    ) -> Result<Option<ReconciliationRoundRecordV1>, String> {
        let row = self
            .connection
            .query_row(
                "SELECT round,issuance,attempt,caller_state_digest,idempotency,
                        predecessor_round,predecessor_reconciliation,source_cut,
                        checkpoint_identity,executor_binding,reservation,signed_body_b64,
                        issuer_principal,signer_key_id,signer_public_key,signature,
                        claimed_at,state,completion,result_kind,result_identity,
                        result_reconciliation,result_evidence,completed_at,source_cut_jcs
                 FROM governed_reconciliation_round WHERE request=?1",
                [request],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, String>(12)?,
                        row.get::<_, String>(13)?,
                        row.get::<_, String>(14)?,
                        row.get::<_, String>(15)?,
                        row.get::<_, i64>(16)?,
                        row.get::<_, String>(17)?,
                        row.get::<_, Option<String>>(18)?,
                        row.get::<_, Option<String>>(19)?,
                        row.get::<_, Option<String>>(20)?,
                        row.get::<_, Option<String>>(21)?,
                        row.get::<_, Option<String>>(22)?,
                        row.get::<_, Option<i64>>(23)?,
                        row.get::<_, Vec<u8>>(24)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| format!("governed-reconciliation-round-read:{error}"))?;
        let Some((
            round,
            issuance,
            attempt,
            caller_state_digest,
            idempotency,
            predecessor_round,
            predecessor_reconciliation,
            source_cut,
            checkpoint_identity,
            executor_binding,
            reservation_identity_value,
            signed_body_b64,
            issuer_principal,
            signer_key_id,
            signer_public_key,
            signature,
            claimed_at,
            state,
            completion_identity_value,
            result_kind,
            result_identity,
            result_reconciliation,
            result_evidence,
            completed_at,
            source_cut_jcs,
        )) = row
        else {
            return Ok(None);
        };
        let body = b64_decode(&signed_body_b64)?;
        let parsed: ReconciliationRoundRequestWireV1 =
            strict_json(&body, "stored-reconciliation-round")?;
        validate_reconciliation_round_request(&parsed)?;
        let canonical = serde_jcs::to_vec(&parsed)
            .map_err(|error| format!("stored-reconciliation-round-canonical:{error}"))?;
        if canonical != body
            || parsed.request != request
            || parsed.round != round
            || parsed.issuance != issuance
            || parsed.attempt != attempt
            || parsed.caller_state_digest != caller_state_digest
            || parsed.idempotency != idempotency
            || parsed.predecessor_round != predecessor_round
            || parsed.predecessor_reconciliation != predecessor_reconciliation
        {
            return Err("governed-reconciliation-round-stored-substitution".to_owned());
        }
        let mut reservation = ReconciliationRoundReservationWireV1 {
            schema: RECONCILIATION_ROUND_RESERVATION_SCHEMA_V1.to_owned(),
            reservation: String::new(),
            request: request.to_owned(),
            round,
            issuance,
            attempt,
            caller_state_digest,
            predecessor_round,
            predecessor_reconciliation,
            source_cut,
            checkpoint_identity,
            executor_binding,
            claimed_at_unix_ms: read_u64(claimed_at, 16)
                .map_err(|error| format!("governed-reconciliation-claimed-at:{error}"))?,
        };
        reservation.reservation = reservation_identity(&reservation)?;
        if reservation.reservation != reservation_identity_value {
            return Err("governed-reconciliation-reservation-substitution".to_owned());
        }
        let completion = match (
            state.as_str(),
            completion_identity_value,
            result_identity,
            completed_at,
        ) {
            ("claimed", None, None, None) => None,
            ("completed", Some(identity), Some(result_identity), Some(completed_at)) => {
                let mut completion = ReconciliationRoundCompletionWireV1 {
                    schema: RECONCILIATION_ROUND_COMPLETION_SCHEMA_V1.to_owned(),
                    completion: String::new(),
                    reservation: reservation.reservation.clone(),
                    round: reservation.round.clone(),
                    result_identity,
                    completed_at_unix_ms: read_u64(completed_at, 23)
                        .map_err(|error| format!("governed-reconciliation-completed-at:{error}"))?,
                };
                completion.completion = completion_identity(&completion)?;
                if completion.completion != identity {
                    return Err("governed-reconciliation-completion-substitution".to_owned());
                }
                Some(completion)
            }
            _ => return Err("governed-reconciliation-round-state-corrupt".to_owned()),
        };
        if (result_kind.as_deref() == Some("indeterminate"))
            != (result_reconciliation.is_some() && result_evidence.is_some())
        {
            return Err("governed-reconciliation-round-result-shape".to_owned());
        }
        let public_key = b64_decode(&signer_public_key)?;
        let signature_bytes = b64_decode(&signature)?;
        let mut signed =
            Vec::with_capacity(RECONCILIATION_ROUND_SIGNATURE_PREFIX_V1.len() + body.len());
        signed.extend_from_slice(RECONCILIATION_ROUND_SIGNATURE_PREFIX_V1);
        signed.extend_from_slice(&body);
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&signed, &signature_bytes)
            .map_err(|_| "governed-stored-reconciliation-round-signature-invalid".to_owned())?;
        let custody_record = self
            .get(&reservation.issuance)?
            .ok_or_else(|| "governed-reconciliation-custody-missing".to_owned())?;
        if issuer_principal != custody_record.authentication.issuer_principal
            || signer_key_id != custody_record.authentication.signer_key_id
            || signer_public_key != custody_record.authentication.signer_public_key
        {
            return Err("governed-reconciliation-issuance-issuer-substitution".to_owned());
        }
        Self::validate_reconciliation_source_cut(
            &self.connection,
            &custody_record,
            &reservation,
            &source_cut_jcs,
            &state,
        )?;
        Ok(Some(ReconciliationRoundRecordV1 {
            reservation,
            signed_body_b64,
            authentication: IssuanceAuthenticationWireV1 {
                issuer_principal,
                signer_key_id,
                signer_public_key,
                signature,
            },
            state,
            completion,
            result_kind,
            result_reconciliation,
            result_evidence,
        }))
    }

    fn current_reconciliation_terminal(
        connection: &Connection,
        record: &CustodyRecordV1,
    ) -> Result<(String, Option<(String, String)>), String> {
        let (current_status, settlement_identity): (String, Option<String>) = connection
            .query_row(
                "SELECT status,settlement FROM governed_loop_attempt
                 WHERE issuance=?1 AND attempt=?2",
                params![record.issuance.issuance, record.custody.attempt],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| format!("governed-reconciliation-source-status:{error}"))?;
        let sealed = governed_repair::read_sealed_result(connection, &record.issuance.issuance)?;
        let terminal_result = match (
            current_status.as_str(),
            settlement_identity,
            sealed.as_ref(),
        ) {
            ("accepted" | "indeterminate", None, None) => None,
            ("accepted" | "indeterminate", None, Some(result)) => {
                Some(("governed_repair".to_owned(), result.sealed_result.clone()))
            }
            ("settled", Some(settlement), None) => {
                require_digest(&settlement, "terminal settlement")?;
                Some(("settled".to_owned(), settlement))
            }
            _ => return Err("governed-reconciliation-source-terminal-shape".to_owned()),
        };
        Ok((current_status, terminal_result))
    }

    fn reconciliation_source_cut(
        connection: &Connection,
        record: &CustodyRecordV1,
    ) -> Result<ReconciliationSourceCutV1, String> {
        let (current_status, terminal_result) =
            Self::current_reconciliation_terminal(connection, record)?;
        let latest_executor: Option<(String, String, String)> = connection
            .query_row(
                "SELECT result_identity,outcome,cumulative_effect_journal_digest
                 FROM governed_executor_result WHERE issuance=?1 AND attempt=?2
                 ORDER BY sequence DESC LIMIT 1",
                params![record.issuance.issuance, record.custody.attempt],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| format!("governed-reconciliation-source-result:{error}"))?;
        let latest_round: Option<(String, String)> = connection
            .query_row(
                "SELECT round,result_identity FROM governed_reconciliation_round
                 WHERE issuance=?1 AND attempt=?2 AND state='completed'
                 ORDER BY rowid DESC LIMIT 1",
                params![record.issuance.issuance, record.custody.attempt],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("governed-reconciliation-source-round:{error}"))?;
        let custody = governed_repair::ag_custody_reference(&record.custody)?;
        let checkpoint = starting_checkpoint_identity(&record.issuance)?;
        let basis = ReconciliationSourceCutWireV1 {
            issuance: record.issuance.issuance.clone(),
            attempt: record.custody.attempt.clone(),
            custody,
            status: current_status,
            checkpoint_identity: checkpoint,
            executor_binding: record.executor_binding.clone(),
            latest_executor_result: latest_executor.as_ref().map(|value| value.0.clone()),
            latest_executor_outcome: latest_executor.as_ref().map(|value| value.1.clone()),
            latest_cumulative_journal: latest_executor.as_ref().map(|value| value.2.clone()),
            latest_completed_round: latest_round.as_ref().map(|value| value.0.clone()),
            latest_completed_result: latest_round.as_ref().map(|value| value.1.clone()),
            terminal_result_kind: terminal_result.as_ref().map(|value| value.0.clone()),
            terminal_result_identity: terminal_result.as_ref().map(|value| value.1.clone()),
        };
        let bytes = serde_jcs::to_vec(&basis)
            .map_err(|error| format!("governed-reconciliation-source-cut:{error}"))?;
        Ok(ReconciliationSourceCutV1 {
            identity: hash_domain("docket.governed-loop.reconciliation-source-cut/v1", &bytes),
            canonical_bytes: bytes,
            basis,
            terminal_result,
        })
    }

    fn durable_reconciliation_result(
        connection: &Connection,
        record: &CustodyRecordV1,
    ) -> Result<Option<DurableReconciliationResultV1>, String> {
        let (status, settlement, reconciliation, evidence): (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = connection
            .query_row(
                "SELECT status,settlement,reconciliation,indeterminate_evidence
                 FROM governed_loop_attempt WHERE issuance=?1 AND attempt=?2",
                params![record.issuance.issuance, record.custody.attempt],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|error| format!("governed-reconciliation-durable-result-read:{error}"))?;
        let sealed = governed_repair::read_sealed_result(connection, &record.issuance.issuance)?;
        match (
            status.as_str(),
            settlement,
            reconciliation,
            evidence,
            sealed,
        ) {
            ("accepted" | "indeterminate", None, _, _, Some(result)) => {
                require_result_custody(&result, &record.custody)?;
                Ok(Some(DurableReconciliationResultV1 {
                    kind: "governed_repair".to_owned(),
                    identity: result.sealed_result,
                    reconciliation: None,
                    evidence: None,
                }))
            }
            ("settled", Some(settlement), None, None, None) => {
                require_digest(&settlement, "durable reconciliation settlement")?;
                Ok(Some(DurableReconciliationResultV1 {
                    kind: "settled".to_owned(),
                    identity: settlement,
                    reconciliation: None,
                    evidence: None,
                }))
            }
            ("indeterminate", None, Some(reconciliation), Some(evidence), None) => {
                require_digest(&reconciliation, "durable reconciliation identity")?;
                require_digest(&evidence, "durable reconciliation evidence")?;
                if reconciliation
                    != hash_domain(
                        "docket.governed-loop.reconciliation/v1",
                        format!(
                            "{}:{}:{evidence}",
                            record.issuance.issuance, record.custody.attempt
                        )
                        .as_bytes(),
                    )
                {
                    return Err("governed-reconciliation-durable-result-identity".to_owned());
                }
                let observed: Option<(String, String)> = connection
                    .query_row(
                        "SELECT outcome,receipt FROM governed_executor_result
                         WHERE issuance=?1 AND attempt=?2 AND receipt=?3",
                        params![record.issuance.issuance, record.custody.attempt, evidence],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .map_err(|error| {
                        format!("governed-reconciliation-durable-result-evidence:{error}")
                    })?;
                if observed != Some(("indeterminate".to_owned(), evidence.clone())) {
                    return Err("governed-reconciliation-durable-result-evidence".to_owned());
                }
                Ok(Some(DurableReconciliationResultV1 {
                    kind: "indeterminate".to_owned(),
                    identity: reconciliation.clone(),
                    reconciliation: Some(reconciliation),
                    evidence: Some(evidence),
                }))
            }
            ("accepted", None, None, None, None) => Ok(None),
            _ => Err("governed-reconciliation-durable-result-shape".to_owned()),
        }
    }

    fn require_executor_history_monotone(
        connection: &Connection,
        reservation: &ReconciliationRoundReservationWireV1,
        source: &ReconciliationSourceCutWireV1,
        current: &ReconciliationSourceCutWireV1,
    ) -> Result<(), String> {
        match (
            source.latest_executor_result.as_deref(),
            current.latest_executor_result.as_deref(),
        ) {
            (None, Some(_)) | (None, None) => Ok(()),
            (Some(source_result), Some(current_result)) if source_result == current_result => {
                Ok(())
            }
            (Some(source_result), Some(current_result)) => {
                let source_sequence: Option<i64> = connection
                    .query_row(
                        "SELECT sequence FROM governed_executor_result
                         WHERE issuance=?1 AND attempt=?2 AND result_identity=?3",
                        params![reservation.issuance, reservation.attempt, source_result],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|error| {
                        format!("governed-reconciliation-source-sequence-read:{error}")
                    })?;
                let current_sequence: Option<i64> = connection
                    .query_row(
                        "SELECT sequence FROM governed_executor_result
                         WHERE issuance=?1 AND attempt=?2 AND result_identity=?3",
                        params![reservation.issuance, reservation.attempt, current_result],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|error| {
                        format!("governed-reconciliation-current-sequence-read:{error}")
                    })?;
                if !matches!((source_sequence, current_sequence), (Some(source), Some(current)) if current > source)
                {
                    return Err("governed-reconciliation-source-history-nonmonotone".to_owned());
                }
                Ok(())
            }
            (Some(_), None) => Err("governed-reconciliation-source-history-nonmonotone".to_owned()),
        }
    }

    fn classify_reconciliation_source_advance(
        connection: &Connection,
        record: &CustodyRecordV1,
        reservation: &ReconciliationRoundReservationWireV1,
        source: &ReconciliationSourceCutWireV1,
        current: &ReconciliationSourceCutV1,
    ) -> Result<ReconciliationSourceAdvanceV1, String> {
        if current.identity == reservation.source_cut {
            return Ok(ReconciliationSourceAdvanceV1::Unchanged);
        }
        let current_basis = &current.basis;
        if source.issuance != current_basis.issuance
            || source.attempt != current_basis.attempt
            || source.custody != current_basis.custody
            || source.checkpoint_identity != current_basis.checkpoint_identity
            || source.executor_binding != current_basis.executor_binding
            || source.latest_completed_round != current_basis.latest_completed_round
            || source.latest_completed_result != current_basis.latest_completed_result
            || source.terminal_result_kind.is_some()
            || source.terminal_result_identity.is_some()
        {
            return Err("governed-reconciliation-source-advance-substitution".to_owned());
        }
        Self::require_executor_history_monotone(connection, reservation, source, current_basis)?;
        let allowed_status = match (source.status.as_str(), current_basis.status.as_str()) {
            ("accepted", "indeterminate" | "settled")
            | ("indeterminate", "indeterminate" | "settled") => true,
            ("accepted" | "indeterminate", "accepted") => {
                current_basis.terminal_result_kind.as_deref() == Some("governed_repair")
            }
            _ => false,
        };
        if !allowed_status {
            return Err("governed-reconciliation-source-advance-nonmonotone".to_owned());
        }
        let result = Self::durable_reconciliation_result(connection, record)?
            .ok_or_else(|| "governed-reconciliation-source-advance-result-missing".to_owned())?;
        if current_basis.terminal_result_kind.as_deref()
            != (result.kind != "indeterminate").then_some(result.kind.as_str())
            || current_basis.terminal_result_identity.as_deref()
                != (result.kind != "indeterminate").then_some(result.identity.as_str())
        {
            return Err("governed-reconciliation-source-advance-result-substitution".to_owned());
        }
        Ok(ReconciliationSourceAdvanceV1::Monotone(result))
    }

    fn complete_claimed_round_row(
        transaction: &Transaction<'_>,
        reservation: &ReconciliationRoundReservationWireV1,
        result: &DurableReconciliationResultV1,
        completed_at: u64,
    ) -> Result<(), String> {
        let mut completion = ReconciliationRoundCompletionWireV1 {
            schema: RECONCILIATION_ROUND_COMPLETION_SCHEMA_V1.to_owned(),
            completion: String::new(),
            reservation: reservation.reservation.clone(),
            round: reservation.round.clone(),
            result_identity: result.identity.clone(),
            completed_at_unix_ms: completed_at,
        };
        completion.completion = completion_identity(&completion)?;
        let changed = transaction
            .execute(
                "UPDATE governed_reconciliation_round
                 SET state='completed',completion=?1,result_kind=?2,result_identity=?3,
                     result_reconciliation=?4,result_evidence=?5,completed_at=?6
                 WHERE request=?7 AND round=?8 AND reservation=?9 AND state='claimed'",
                params![
                    completion.completion,
                    result.kind,
                    result.identity,
                    result.reconciliation,
                    result.evidence,
                    u64_to_i64(completed_at)?,
                    reservation.request,
                    reservation.round,
                    reservation.reservation,
                ],
            )
            .map_err(|error| format!("governed-reconciliation-local-completion-write:{error}"))?;
        if changed != 1 {
            return Err("governed-reconciliation-local-completion-race".to_owned());
        }
        Ok(())
    }

    fn resolve_claimed_round_from_durable_source(
        &mut self,
        round: &ReconciliationRoundRecordV1,
        record: &CustodyRecordV1,
        completed_at: u64,
    ) -> Result<bool, String> {
        if round.state != "claimed" {
            return Ok(false);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                format!("governed-reconciliation-local-completion-transaction:{error}")
            })?;
        let (state, reservation, source_cut_jcs): (String, String, Vec<u8>) = transaction
            .query_row(
                "SELECT state,reservation,source_cut_jcs FROM governed_reconciliation_round
                 WHERE request=?1 AND round=?2",
                params![round.reservation.request, round.reservation.round],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| format!("governed-reconciliation-local-completion-read:{error}"))?;
        if reservation != round.reservation.reservation {
            return Err("governed-reconciliation-local-completion-claim-substitution".to_owned());
        }
        if state == "completed" {
            transaction.commit().map_err(|error| {
                format!("governed-reconciliation-local-completion-commit:{error}")
            })?;
            return Ok(true);
        }
        if state != "claimed" {
            return Err("governed-reconciliation-local-completion-state".to_owned());
        }
        let source: ReconciliationSourceCutWireV1 =
            strict_json(&source_cut_jcs, "stored-reconciliation-source-cut")?;
        let current = Self::reconciliation_source_cut(&transaction, record)?;
        match Self::classify_reconciliation_source_advance(
            &transaction,
            record,
            &round.reservation,
            &source,
            &current,
        )? {
            ReconciliationSourceAdvanceV1::Unchanged => {
                transaction.commit().map_err(|error| {
                    format!("governed-reconciliation-local-completion-commit:{error}")
                })?;
                Ok(false)
            }
            ReconciliationSourceAdvanceV1::Monotone(result) => {
                Self::complete_claimed_round_row(
                    &transaction,
                    &round.reservation,
                    &result,
                    completed_at,
                )?;
                transaction.commit().map_err(|error| {
                    format!("governed-reconciliation-local-completion-commit:{error}")
                })?;
                Ok(true)
            }
        }
    }

    fn validate_reconciliation_source_cut(
        connection: &Connection,
        record: &CustodyRecordV1,
        reservation: &ReconciliationRoundReservationWireV1,
        source_cut_jcs: &[u8],
        round_state: &str,
    ) -> Result<(), String> {
        let source: ReconciliationSourceCutWireV1 =
            strict_json(source_cut_jcs, "stored-reconciliation-source-cut")?;
        let canonical = serde_jcs::to_vec(&source)
            .map_err(|error| format!("governed-reconciliation-source-cut-canonical:{error}"))?;
        if canonical != source_cut_jcs {
            return Err("governed-reconciliation-source-cut-noncanonical".to_owned());
        }
        let source_identity = hash_domain(
            "docket.governed-loop.reconciliation-source-cut/v1",
            source_cut_jcs,
        );
        if source_identity != reservation.source_cut {
            return Err("governed-reconciliation-source-cut-substitution".to_owned());
        }
        let executor_shape = (
            source.latest_executor_result.is_some(),
            source.latest_executor_outcome.is_some(),
            source.latest_cumulative_journal.is_some(),
        );
        if !matches!(executor_shape, (false, false, false) | (true, true, true)) {
            return Err("governed-reconciliation-source-executor-shape".to_owned());
        }
        let completed_shape = (
            source.latest_completed_round.is_some(),
            source.latest_completed_result.is_some(),
        );
        if !matches!(completed_shape, (false, false) | (true, true)) {
            return Err("governed-reconciliation-source-round-shape".to_owned());
        }
        let terminal_shape = (
            source.terminal_result_kind.as_deref(),
            source.terminal_result_identity.as_deref(),
        );
        match terminal_shape {
            (None, None) if source.status != "settled" => {}
            (Some("settled"), Some(identity)) if source.status == "settled" => {
                require_digest(identity, "stored terminal settlement")?;
            }
            (Some("governed_repair"), Some(identity))
                if matches!(source.status.as_str(), "accepted" | "indeterminate") =>
            {
                require_digest(identity, "stored terminal governed result")?;
            }
            _ => return Err("governed-reconciliation-source-terminal-shape".to_owned()),
        }
        let custody = governed_repair::ag_custody_reference(&record.custody)?;
        if source.issuance != reservation.issuance
            || source.issuance != record.issuance.issuance
            || source.attempt != reservation.attempt
            || source.attempt != record.custody.attempt
            || source.custody != custody
            || source.checkpoint_identity != reservation.checkpoint_identity
            || source.checkpoint_identity != starting_checkpoint_identity(&record.issuance)?
            || source.executor_binding != reservation.executor_binding
            || source.executor_binding != record.executor_binding
            || !matches!(
                source.status.as_str(),
                "accepted" | "indeterminate" | "settled"
            )
        {
            return Err("governed-reconciliation-source-static-substitution".to_owned());
        }
        if let (Some(kind), Some(identity)) = terminal_shape {
            let (_, current_terminal) = Self::current_reconciliation_terminal(connection, record)?;
            if current_terminal
                .as_ref()
                .map(|value| (value.0.as_str(), value.1.as_str()))
                != Some((kind, identity))
            {
                return Err("governed-reconciliation-source-terminal-substitution".to_owned());
            }
        }
        if source.latest_completed_round != reservation.predecessor_round
            || source.latest_completed_result != reservation.predecessor_reconciliation
        {
            return Err("governed-reconciliation-source-predecessor-substitution".to_owned());
        }

        let source_executor: Option<(String, String, String, String)> = match &source
            .latest_executor_result
        {
            Some(identity) => connection
                .query_row(
                    "SELECT outcome,cumulative_effect_journal_digest,receipt,attempt
                         FROM governed_executor_result
                         WHERE issuance=?1 AND result_identity=?2",
                    params![reservation.issuance, identity],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|error| format!("governed-reconciliation-source-executor-read:{error}"))?,
            None => None,
        };
        match (
            source_executor,
            &source.latest_executor_outcome,
            &source.latest_cumulative_journal,
        ) {
            (None, None, None) if source.status == "accepted" => {}
            (
                Some((outcome, cumulative, _receipt, attempt)),
                Some(source_outcome),
                Some(source_cumulative),
            ) if attempt == reservation.attempt
                && outcome == *source_outcome
                && cumulative == *source_cumulative
                && ((source.status == "indeterminate" && outcome == "indeterminate")
                    || (source.status == "settled"
                        && matches!(outcome.as_str(), "success" | "failure"))) => {}
            _ => return Err("governed-reconciliation-source-executor-substitution".to_owned()),
        }

        match (
            &reservation.predecessor_round,
            &reservation.predecessor_reconciliation,
        ) {
            (None, None) => {
                let earlier: i64 = connection
                    .query_row(
                        "SELECT COUNT(*) FROM governed_reconciliation_round
                         WHERE issuance=?1 AND attempt=?2 AND rowid <
                           (SELECT rowid FROM governed_reconciliation_round WHERE request=?3)",
                        params![
                            reservation.issuance,
                            reservation.attempt,
                            reservation.request
                        ],
                        |row| row.get(0),
                    )
                    .map_err(|error| {
                        format!("governed-reconciliation-source-first-round:{error}")
                    })?;
                if earlier != 0 {
                    return Err("governed-reconciliation-source-predecessor-gap".to_owned());
                }
            }
            (Some(round), Some(reconciliation)) => {
                let predecessor: Option<(String, String, String, String, String, String)> =
                    connection
                        .query_row(
                            "SELECT issuance,attempt,result_kind,result_identity,
                                    result_reconciliation,result_evidence
                             FROM governed_reconciliation_round
                             WHERE round=?1 AND state='completed'",
                            [round],
                            |row| {
                                Ok((
                                    row.get(0)?,
                                    row.get(1)?,
                                    row.get(2)?,
                                    row.get(3)?,
                                    row.get(4)?,
                                    row.get(5)?,
                                ))
                            },
                        )
                        .optional()
                        .map_err(|error| {
                            format!("governed-reconciliation-source-predecessor-read:{error}")
                        })?;
                let Some((issuance, attempt, kind, result, stored_reconciliation, evidence)) =
                    predecessor
                else {
                    return Err("governed-reconciliation-source-predecessor-missing".to_owned());
                };
                if issuance != reservation.issuance
                    || attempt != reservation.attempt
                    || kind != "indeterminate"
                    || result != *reconciliation
                    || stored_reconciliation != *reconciliation
                {
                    return Err(
                        "governed-reconciliation-source-predecessor-substitution".to_owned()
                    );
                }
                let immediate: Option<String> = connection
                    .query_row(
                        "SELECT round FROM governed_reconciliation_round
                         WHERE issuance=?1 AND attempt=?2 AND state='completed'
                           AND rowid < (SELECT rowid FROM governed_reconciliation_round WHERE request=?3)
                         ORDER BY rowid DESC LIMIT 1",
                        params![reservation.issuance, reservation.attempt, reservation.request],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|error| {
                        format!("governed-reconciliation-source-immediate-predecessor:{error}")
                    })?;
                // The predecessor's indeterminate observation must remain
                // durable, but it need not remain the latest executor row: an
                // independently running initial dispatch may have advanced the
                // same attempt after that explicit round completed.
                let predecessor_receipt: Option<String> = connection
                    .query_row(
                        "SELECT receipt FROM governed_executor_result
                         WHERE issuance=?1 AND attempt=?2 AND receipt=?3
                           AND outcome='indeterminate'",
                        params![reservation.issuance, reservation.attempt, evidence],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|error| format!("governed-reconciliation-source-receipt:{error}"))?;
                if immediate.as_deref() != Some(round.as_str())
                    || predecessor_receipt.as_deref() != Some(evidence.as_str())
                {
                    return Err("governed-reconciliation-source-predecessor-gap".to_owned());
                }
            }
            _ => return Err("governed-reconciliation-source-predecessor-shape".to_owned()),
        }

        if round_state == "claimed" {
            let current = Self::reconciliation_source_cut(connection, record)?;
            Self::classify_reconciliation_source_advance(
                connection,
                record,
                reservation,
                &source,
                &current,
            )?;
        }
        Ok(())
    }

    fn claim_reconciliation_round(
        &mut self,
        envelope: &SignedReconciliationRoundRequestEnvelopeWireV1,
        request: &ReconciliationRoundRequestWireV1,
        record: &CustodyRecordV1,
        expected_executor: &ExecutorBindingV1,
        claimed_at: u64,
    ) -> Result<ReconciliationRoundClaimV1, String> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("governed-reconciliation-claim-transaction:{error}"))?;
        if let Some(existing_request) = transaction
            .query_row(
                "SELECT request FROM governed_reconciliation_round WHERE request=?1",
                [&request.request],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| format!("governed-reconciliation-claim-read:{error}"))?
        {
            transaction
                .commit()
                .map_err(|error| format!("governed-reconciliation-claim-commit:{error}"))?;
            let existing = self
                .read_reconciliation_round(&existing_request)?
                .ok_or_else(|| "governed-reconciliation-round-disappeared".to_owned())?;
            if existing.signed_body_b64 != envelope.body_b64
                || existing.authentication != envelope.authentication
            {
                return Err("governed-reconciliation-request-replay-collision".to_owned());
            }
            return Ok(ReconciliationRoundClaimV1::Existing(Box::new(existing)));
        }
        if transaction
            .query_row(
                "SELECT request FROM governed_reconciliation_round
                 WHERE issuance=?1 AND attempt=?2 AND state='claimed' LIMIT 1",
                params![request.issuance, request.attempt],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| format!("governed-reconciliation-outstanding-read:{error}"))?
            .is_some()
        {
            return Err("governed-reconciliation-outstanding-round-unresolved".to_owned());
        }
        let current: (String, String, String, String, String, String, String) = transaction
            .query_row(
                "SELECT attempt,status,executor_binding,executor_marker,
                        issuer_principal,signer_key_id,signer_public_key
                 FROM governed_loop_attempt WHERE issuance=?1",
                [&request.issuance],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .map_err(|error| format!("governed-reconciliation-current-read:{error}"))?;
        if current.0 != request.attempt || current.0 != record.custody.attempt {
            return Err("governed-reconciliation-attempt-substitution".to_owned());
        }
        if !matches!(current.1.as_str(), "accepted" | "indeterminate" | "settled") {
            return Err("governed-reconciliation-terminal-attempt".to_owned());
        }
        if current.2 != expected_executor.identity || current.3 != record.custody.executor_marker {
            return Err("governed-reconciliation-executor-binding-substitution".to_owned());
        }
        if current.4 != envelope.authentication.issuer_principal
            || current.5 != envelope.authentication.signer_key_id
            || current.6 != envelope.authentication.signer_public_key
        {
            return Err("governed-reconciliation-issuance-issuer-substitution".to_owned());
        }
        let mut current_record = record.clone();
        current_record.status = current.1;
        let source_cut = Self::reconciliation_source_cut(&transaction, &current_record)?;
        let latest_completed: Option<(String, String, Option<String>)> = transaction
            .query_row(
                "SELECT round,result_kind,result_reconciliation
                 FROM governed_reconciliation_round
                 WHERE issuance=?1 AND attempt=?2 AND state='completed'
                 ORDER BY rowid DESC LIMIT 1",
                params![request.issuance, request.attempt],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| format!("governed-reconciliation-predecessor-read:{error}"))?;
        if source_cut.terminal_result.is_some() {
            match (
                latest_completed,
                &request.predecessor_round,
                &request.predecessor_reconciliation,
            ) {
                (None, None, None) => {}
                (
                    Some((round, kind, Some(reconciliation))),
                    Some(request_round),
                    Some(request_result),
                ) if kind == "indeterminate"
                    && round == *request_round
                    && reconciliation == *request_result => {}
                (Some((_round, kind, _)), _, _) if kind != "indeterminate" => {
                    return Err("governed-reconciliation-new-round-after-terminal".to_owned())
                }
                _ => return Err("governed-reconciliation-predecessor-substitution".to_owned()),
            }
        } else {
            match (
                latest_completed,
                &request.predecessor_round,
                &request.predecessor_reconciliation,
            ) {
                (None, None, None) => {}
                (
                    Some((round, kind, Some(reconciliation))),
                    Some(request_round),
                    Some(request_result),
                ) if kind == "indeterminate"
                    && round == *request_round
                    && reconciliation == *request_result => {}
                (Some((_round, kind, _)), _, _) if kind != "indeterminate" => {
                    return Err("governed-reconciliation-predecessor-terminal".to_owned())
                }
                _ => return Err("governed-reconciliation-predecessor-substitution".to_owned()),
            }
        }
        let checkpoint_identity = starting_checkpoint_identity(&record.issuance)?;
        let mut reservation = ReconciliationRoundReservationWireV1 {
            schema: RECONCILIATION_ROUND_RESERVATION_SCHEMA_V1.to_owned(),
            reservation: String::new(),
            request: request.request.clone(),
            round: request.round.clone(),
            issuance: request.issuance.clone(),
            attempt: request.attempt.clone(),
            caller_state_digest: request.caller_state_digest.clone(),
            predecessor_round: request.predecessor_round.clone(),
            predecessor_reconciliation: request.predecessor_reconciliation.clone(),
            source_cut: source_cut.identity,
            checkpoint_identity,
            executor_binding: expected_executor.identity.clone(),
            claimed_at_unix_ms: claimed_at,
        };
        reservation.reservation = reservation_identity(&reservation)?;
        let terminal_completion = source_cut
            .terminal_result
            .as_ref()
            .map(|(_, result_identity)| {
                let mut completion = ReconciliationRoundCompletionWireV1 {
                    schema: RECONCILIATION_ROUND_COMPLETION_SCHEMA_V1.to_owned(),
                    completion: String::new(),
                    reservation: reservation.reservation.clone(),
                    round: reservation.round.clone(),
                    result_identity: result_identity.clone(),
                    completed_at_unix_ms: claimed_at,
                };
                completion.completion = completion_identity(&completion)?;
                Ok::<_, String>(completion)
            })
            .transpose()?;
        transaction
            .execute(
                "INSERT INTO governed_reconciliation_round
                 (request,round,issuance,attempt,caller_state_digest,idempotency,
                  predecessor_round,predecessor_reconciliation,source_cut,source_cut_jcs,checkpoint_identity,
                  executor_binding,reservation,signed_body_b64,issuer_principal,signer_key_id,
                  signer_public_key,signature,claimed_at,state,completion,result_kind,result_identity,completed_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,
                         ?20,?21,?22,?23,?24)",
                params![
                    request.request,
                    request.round,
                    request.issuance,
                    request.attempt,
                    request.caller_state_digest,
                    request.idempotency,
                    request.predecessor_round,
                    request.predecessor_reconciliation,
                    reservation.source_cut,
                    source_cut.canonical_bytes,
                    reservation.checkpoint_identity,
                    expected_executor.identity,
                    reservation.reservation,
                    envelope.body_b64,
                    envelope.authentication.issuer_principal,
                    envelope.authentication.signer_key_id,
                    envelope.authentication.signer_public_key,
                    envelope.authentication.signature,
                    u64_to_i64(claimed_at)?,
                    if terminal_completion.is_some() { "completed" } else { "claimed" },
                    terminal_completion.as_ref().map(|value| &value.completion),
                    source_cut.terminal_result.as_ref().map(|value| &value.0),
                    source_cut.terminal_result.as_ref().map(|value| &value.1),
                    terminal_completion
                        .as_ref()
                        .map(|_| u64_to_i64(claimed_at))
                        .transpose()?,
                ],
            )
            .map_err(|error| format!("governed-reconciliation-claim-write:{error}"))?;
        transaction
            .commit()
            .map_err(|error| format!("governed-reconciliation-claim-commit:{error}"))?;
        if terminal_completion.is_some() {
            let completed = self
                .read_reconciliation_round(&request.request)?
                .ok_or_else(|| "governed-reconciliation-round-disappeared".to_owned())?;
            Ok(ReconciliationRoundClaimV1::Existing(Box::new(completed)))
        } else {
            Ok(ReconciliationRoundClaimV1::Winner(Box::new(reservation)))
        }
    }

    fn complete_reconciliation_round(
        &mut self,
        request: &ReconciliationRoundRequestWireV1,
        reservation: &ReconciliationRoundReservationWireV1,
        record: &CustodyRecordV1,
        outcome: ExecutorOutcomeWireV1,
        completed_at: u64,
    ) -> Result<DocketReconciliationWireV1, String> {
        if outcome.attempt != record.custody.attempt
            || outcome.marker != record.custody.executor_marker
        {
            return Err("governed-reconciliation-executor-result-binding".to_owned());
        }
        governed_repair::validate_effect_journal_for_issuance(
            &record.issuance.effect_scope,
            &outcome.effect_journal,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("governed-reconciliation-completion-transaction:{error}"))?;
        let round_state: (String, String, String, String, Vec<u8>) = transaction
            .query_row(
                "SELECT state,reservation,source_cut,executor_binding,source_cut_jcs
                 FROM governed_reconciliation_round WHERE request=?1 AND round=?2",
                params![request.request, request.round],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .map_err(|error| format!("governed-reconciliation-completion-claim:{error}"))?;
        if round_state.0 != "claimed"
            || round_state.1.as_str() != reservation.reservation
            || round_state.2.as_str() != reservation.source_cut
            || round_state.3.as_str() != reservation.executor_binding
        {
            return Err("governed-reconciliation-completion-claim-substitution".to_owned());
        }
        let current_status: String = transaction
            .query_row(
                "SELECT status FROM governed_loop_attempt
                 WHERE issuance=?1 AND attempt=?2 AND executor_binding=?3",
                params![
                    request.issuance,
                    request.attempt,
                    reservation.executor_binding
                ],
                |row| row.get(0),
            )
            .map_err(|error| format!("governed-reconciliation-completion-current:{error}"))?;
        let mut current_record = record.clone();
        current_record.status = current_status;
        let current_source = Self::reconciliation_source_cut(&transaction, &current_record)?;
        if current_source.identity != reservation.source_cut {
            let source: ReconciliationSourceCutWireV1 =
                strict_json(&round_state.4, "stored-reconciliation-source-cut")?;
            let result = match Self::classify_reconciliation_source_advance(
                &transaction,
                &current_record,
                reservation,
                &source,
                &current_source,
            )? {
                ReconciliationSourceAdvanceV1::Unchanged => {
                    return Err("governed-reconciliation-completion-source-cut-stale".to_owned())
                }
                ReconciliationSourceAdvanceV1::Monotone(result) => result,
            };
            // The raced executor response is no longer allowed to extend the
            // durable attempt. It must nevertheless be consistent with the
            // effects already recorded at the independently durable cut.
            governed_repair::require_reported_journal_already_durable(
                &transaction,
                &request.issuance,
                &request.attempt,
                &record.issuance.effect_scope,
                &outcome.effect_journal,
            )?;
            Self::complete_claimed_round_row(&transaction, reservation, &result, completed_at)?;
            transaction
                .commit()
                .map_err(|error| format!("governed-reconciliation-completion-commit:{error}"))?;
            let completed = self
                .read_reconciliation_round(&request.request)?
                .ok_or_else(|| "governed-reconciliation-round-disappeared".to_owned())?;
            let response = self.reconciliation_round_response(completed)?;
            let DocketReconciliationRoundStateWireV1::Completed { response, .. } = response.state
            else {
                return Err("governed-reconciliation-local-completion-missing".to_owned());
            };
            return Ok(*response);
        }

        let (result_kind, result_identity, result_reconciliation, result_evidence, response) =
            match (&outcome.outcome, &outcome.governed_repair) {
                (
                    ExecutorOutcomeClassWireV1::ScopeExpansionRequired,
                    Some(ExecutorGovernedRepairRequirementWireV1::ScopeExpansionRequired {
                        ..
                    }),
                )
                | (
                    ExecutorOutcomeClassWireV1::ReadjudicationRequired,
                    Some(ExecutorGovernedRepairRequirementWireV1::ReadjudicationRequired {
                        ..
                    }),
                ) => {
                    let result = governed_repair::seal_requirement_in_transaction(
                        &transaction,
                        governed_repair::SealRequirementInputV1 {
                            issuance: &record.issuance,
                            custody: &record.custody,
                            executor_binding: &record.executor_binding,
                            executor_receipt: &outcome.receipt,
                            draft: outcome
                                .governed_repair
                                .clone()
                                .ok_or_else(|| "governed-repair-requirement-missing".to_owned())?,
                            journal: &outcome.effect_journal,
                            immutable_work_checkpoint: outcome.immutable_work_checkpoint.as_ref(),
                            now_unix_ms: completed_at,
                        },
                    )?;
                    require_result_custody(&result, &record.custody)?;
                    (
                        "governed_repair".to_owned(),
                        result.sealed_result.clone(),
                        None,
                        None,
                        DocketReconciliationWireV1::GovernedRepairRequired {
                            custody: record.custody.clone(),
                            result: Box::new(result),
                        },
                    )
                }
                (
                    ExecutorOutcomeClassWireV1::ScopeExpansionRequired
                    | ExecutorOutcomeClassWireV1::ReadjudicationRequired,
                    _,
                )
                | (
                    ExecutorOutcomeClassWireV1::Success
                    | ExecutorOutcomeClassWireV1::Failure
                    | ExecutorOutcomeClassWireV1::Indeterminate,
                    Some(_),
                ) => return Err("governed-repair-outcome-shape".to_owned()),
                (
                    ExecutorOutcomeClassWireV1::Success | ExecutorOutcomeClassWireV1::Failure,
                    None,
                ) => {
                    require_digest(&outcome.receipt, "executor receipt")?;
                    let known = if outcome.outcome == ExecutorOutcomeClassWireV1::Success {
                        "success"
                    } else {
                        "failure"
                    };
                    governed_repair::append_ordinary_executor_result(
                        &transaction,
                        governed_repair::OrdinaryExecutorResultInputV1 {
                            issuance: &request.issuance,
                            attempt: &request.attempt,
                            outcome: known,
                            receipt: &outcome.receipt,
                            scope: &record.issuance.effect_scope,
                            entries: &outcome.effect_journal,
                            recorded_at: completed_at,
                        },
                    )?;
                    let cumulative_effect_journal_identity =
                        governed_repair::latest_cumulative_effect_journal_identity(
                            &transaction,
                            &request.issuance,
                            &request.attempt,
                            &record.issuance.effect_scope,
                        )?
                        .ok_or_else(|| "governed-settlement-journal-missing".to_owned())?;
                    let mut settlement = DocketSettlementWireV1 {
                        schema: SETTLEMENT_SCHEMA_V1.to_owned(),
                        settlement: String::new(),
                        issuance: request.issuance.clone(),
                        attempt: request.attempt.clone(),
                        executor_marker: record.custody.executor_marker.clone(),
                        receipt: outcome.receipt.clone(),
                        outcome: if known == "success" {
                            KnownOutcomeWireV1::Success
                        } else {
                            KnownOutcomeWireV1::Failure
                        },
                        cumulative_effect_journal_identity: cumulative_effect_journal_identity
                            .clone(),
                        settled_at_unix_ms: completed_at,
                    };
                    settlement.settlement = docket_settlement_identity(&settlement)?;
                    let changed = transaction
                        .execute(
                            "UPDATE governed_loop_attempt
                             SET status='settled',settlement=?1,receipt=?2,outcome=?3,settled_at=?4,
                                 settlement_cumulative_effect_journal_identity=?5
                             WHERE issuance=?6 AND attempt=?7 AND executor_marker=?8
                               AND status IN ('accepted','indeterminate')
                               AND NOT EXISTS (
                                 SELECT 1 FROM governed_repair_checkpoint
                                 WHERE governed_repair_checkpoint.issuance=governed_loop_attempt.issuance
                               )",
                            params![
                                settlement.settlement,
                                outcome.receipt,
                                known,
                                u64_to_i64(completed_at)?,
                                cumulative_effect_journal_identity,
                                request.issuance,
                                request.attempt,
                                record.custody.executor_marker,
                            ],
                        )
                        .map_err(|error| format!("governed-settlement-write:{error}"))?;
                    if changed != 1 {
                        return Err("governed-reconciliation-settlement-race".to_owned());
                    }
                    (
                        "settled".to_owned(),
                        settlement.settlement.clone(),
                        None,
                        None,
                        DocketReconciliationWireV1::Settled {
                            custody: record.custody.clone(),
                            settlement,
                        },
                    )
                }
                (ExecutorOutcomeClassWireV1::Indeterminate, None) => {
                    require_digest(&outcome.receipt, "indeterminate evidence")?;
                    governed_repair::append_ordinary_executor_result(
                        &transaction,
                        governed_repair::OrdinaryExecutorResultInputV1 {
                            issuance: &request.issuance,
                            attempt: &request.attempt,
                            outcome: "indeterminate",
                            receipt: &outcome.receipt,
                            scope: &record.issuance.effect_scope,
                            entries: &outcome.effect_journal,
                            recorded_at: completed_at,
                        },
                    )?;
                    let reconciliation = hash_domain(
                        "docket.governed-loop.reconciliation/v1",
                        format!(
                            "{}:{}:{}",
                            request.issuance, request.attempt, outcome.receipt
                        )
                        .as_bytes(),
                    );
                    let changed = transaction
                        .execute(
                            "UPDATE governed_loop_attempt
                             SET status='indeterminate',reconciliation=?1,indeterminate_evidence=?2
                             WHERE issuance=?3 AND attempt=?4 AND executor_marker=?5
                               AND status IN ('accepted','indeterminate')
                               AND NOT EXISTS (
                                 SELECT 1 FROM governed_repair_checkpoint
                                 WHERE governed_repair_checkpoint.issuance=governed_loop_attempt.issuance
                               )",
                            params![
                                reconciliation,
                                outcome.receipt,
                                request.issuance,
                                request.attempt,
                                record.custody.executor_marker,
                            ],
                        )
                        .map_err(|error| format!("governed-indeterminate-write:{error}"))?;
                    if changed != 1 {
                        return Err("governed-reconciliation-indeterminate-race".to_owned());
                    }
                    let indeterminate = IndeterminateOutcomeWireV1 {
                        issuance: request.issuance.clone(),
                        attempt: request.attempt.clone(),
                        reconciliation: reconciliation.clone(),
                        evidence: outcome.receipt.clone(),
                    };
                    (
                        "indeterminate".to_owned(),
                        reconciliation.clone(),
                        Some(reconciliation),
                        Some(outcome.receipt.clone()),
                        DocketReconciliationWireV1::Indeterminate {
                            custody: record.custody.clone(),
                            indeterminate,
                        },
                    )
                }
            };
        #[cfg(test)]
        if ABORT_ROUND_COMPLETION_BEFORE_ROUND_ROW.with(|failpoint| failpoint.replace(false)) {
            return Err("injected round completion failure".to_owned());
        }
        let mut completion = ReconciliationRoundCompletionWireV1 {
            schema: RECONCILIATION_ROUND_COMPLETION_SCHEMA_V1.to_owned(),
            completion: String::new(),
            reservation: reservation.reservation.clone(),
            round: reservation.round.clone(),
            result_identity: result_identity.clone(),
            completed_at_unix_ms: completed_at,
        };
        completion.completion = completion_identity(&completion)?;
        let changed = transaction
            .execute(
                "UPDATE governed_reconciliation_round
                 SET state='completed',completion=?1,result_kind=?2,result_identity=?3,
                     result_reconciliation=?4,result_evidence=?5,completed_at=?6
                 WHERE request=?7 AND round=?8 AND reservation=?9 AND state='claimed'",
                params![
                    completion.completion,
                    result_kind,
                    result_identity,
                    result_reconciliation,
                    result_evidence,
                    u64_to_i64(completed_at)?,
                    request.request,
                    request.round,
                    reservation.reservation,
                ],
            )
            .map_err(|error| format!("governed-reconciliation-completion-write:{error}"))?;
        if changed != 1 {
            return Err("governed-reconciliation-completion-race".to_owned());
        }
        transaction
            .commit()
            .map_err(|error| format!("governed-reconciliation-completion-commit:{error}"))?;
        Ok(response)
    }

    fn reconciliation_round_response(
        &mut self,
        round: ReconciliationRoundRecordV1,
    ) -> Result<DocketReconciliationRoundResponseWireV1, String> {
        let request = round.reservation.request.clone();
        let round_identity = round.reservation.round.clone();
        let result = if round.state == "claimed" {
            if round.completion.is_some() || round.result_kind.is_some() {
                return Err("governed-reconciliation-claimed-result-corrupt".to_owned());
            }
            DocketReconciliationRoundStateWireV1::Unresolved(round.reservation)
        } else if round.state == "completed" {
            let completion = round
                .completion
                .ok_or_else(|| "governed-reconciliation-completion-missing".to_owned())?;
            let custody_record = self
                .get(&round.reservation.issuance)?
                .ok_or_else(|| "governed-reconciliation-custody-missing".to_owned())?;
            let response = match round.result_kind.as_deref() {
                Some("indeterminate") => {
                    let reconciliation = round.result_reconciliation.ok_or_else(|| {
                        "governed-reconciliation-historical-reconciliation-missing".to_owned()
                    })?;
                    let evidence = round.result_evidence.ok_or_else(|| {
                        "governed-reconciliation-historical-evidence-missing".to_owned()
                    })?;
                    let stored: Option<(String, String, String)> = self
                        .connection
                        .query_row(
                            "SELECT result_identity,outcome,receipt FROM governed_executor_result
                             WHERE issuance=?1 AND attempt=?2 AND receipt=?3",
                            params![
                                round.reservation.issuance,
                                round.reservation.attempt,
                                evidence,
                            ],
                            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                        )
                        .optional()
                        .map_err(|error| {
                            format!("governed-reconciliation-historical-result:{error}")
                        })?;
                    if !matches!(stored, Some((_, ref outcome, ref receipt))
                        if outcome == "indeterminate" && receipt == &evidence)
                        || reconciliation
                            != hash_domain(
                                "docket.governed-loop.reconciliation/v1",
                                format!(
                                    "{}:{}:{}",
                                    round.reservation.issuance, round.reservation.attempt, evidence
                                )
                                .as_bytes(),
                            )
                        || completion.result_identity != reconciliation
                    {
                        return Err(
                            "governed-reconciliation-historical-result-substitution".to_owned()
                        );
                    }
                    DocketReconciliationWireV1::Indeterminate {
                        custody: custody_record.custody,
                        indeterminate: IndeterminateOutcomeWireV1 {
                            issuance: round.reservation.issuance.clone(),
                            attempt: round.reservation.attempt.clone(),
                            reconciliation,
                            evidence,
                        },
                    }
                }
                Some("settled") => {
                    let settlement = custody_record
                        .settlement
                        .ok_or_else(|| "governed-settlement-columns-missing".to_owned())?;
                    if settlement.settlement != completion.result_identity {
                        return Err("governed-reconciliation-settlement-substitution".to_owned());
                    }
                    DocketReconciliationWireV1::Settled {
                        custody: custody_record.custody,
                        settlement,
                    }
                }
                Some("governed_repair") => {
                    let sealed = governed_repair::read_sealed_result(
                        &self.connection,
                        &round.reservation.issuance,
                    )?
                    .ok_or_else(|| "governed-repair-checkpoint-disappeared".to_owned())?;
                    if sealed.sealed_result != completion.result_identity {
                        return Err(
                            "governed-reconciliation-governed-result-substitution".to_owned()
                        );
                    }
                    require_result_custody(&sealed, &custody_record.custody)?;
                    DocketReconciliationWireV1::GovernedRepairRequired {
                        custody: custody_record.custody,
                        result: Box::new(sealed),
                    }
                }
                _ => return Err("governed-reconciliation-result-kind-corrupt".to_owned()),
            };
            DocketReconciliationRoundStateWireV1::Completed {
                reservation: round.reservation,
                completion,
                response: Box::new(response),
            }
        } else {
            return Err("governed-reconciliation-round-state-corrupt".to_owned());
        };
        Ok(DocketReconciliationRoundResponseWireV1 {
            schema: RECONCILIATION_ROUND_RESPONSE_SCHEMA_V1.to_owned(),
            request,
            round: round_identity,
            state: result,
        })
    }

    fn refuse(
        &mut self,
        envelope: &SignedIssuanceEnvelopeWireV1,
        issuance: &AgIssuanceWireV2,
        draft: RefusalDraftV1,
        refused_at_unix_ms: u64,
    ) -> Result<DocketExecutionResponseWireV1, String> {
        let refusal = build_refusal(issuance, draft, refused_at_unix_ms)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| format!("governed-refusal-transaction:{error}"))?;
        let inserted = (|| {
            transaction
                .execute(
                    "INSERT INTO governed_loop_issuance_disposition
                     (issuance,disposition,artifact) VALUES (?1,'refused',?2)",
                    params![issuance.issuance, refusal.refusal],
                )
                .map_err(|error| format!("governed-refusal-disposition:{error}"))?;
            transaction
                .execute(
                    "INSERT INTO governed_loop_issuance_refusal
                     (issuance,refusal,signed_body_b64,issuer_principal,signer_key_id,
                      signer_public_key,signature,campaign,occurrence,refusal_class,
                      reason_code,evidence,refused_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                    params![
                        refusal.issuance,
                        refusal.refusal,
                        envelope.body_b64,
                        envelope.authentication.issuer_principal,
                        envelope.authentication.signer_key_id,
                        envelope.authentication.signer_public_key,
                        envelope.authentication.signature,
                        refusal.campaign,
                        refusal.occurrence,
                        refusal.refusal_class.tag(),
                        refusal.reason_code,
                        refusal.evidence,
                        u64_to_i64(refusal.refused_at_unix_ms)?,
                    ],
                )
                .map_err(|error| format!("governed-refusal-insert:{error}"))?;
            transaction
                .commit()
                .map_err(|error| format!("governed-refusal-commit:{error}"))
        })();
        if let Err(error) = inserted {
            if let Some(existing) = self.get_refusal(&issuance.issuance)? {
                require_same_refusal_envelope(&existing, envelope, issuance)?;
                if existing.refusal.issuance != refusal.issuance
                    || existing.refusal.campaign != refusal.campaign
                    || existing.refusal.occurrence != refusal.occurrence
                    || existing.refusal.refusal_class != refusal.refusal_class
                    || existing.refusal.reason_code != refusal.reason_code
                    || existing.refusal.evidence != refusal.evidence
                {
                    return Err("governed-refusal-exact-replay-collision".to_owned());
                }
                return Ok(DocketExecutionResponseWireV1::Refused(existing.refusal));
            }
            if self.get(&issuance.issuance)?.is_some() {
                return Err("governed-refusal-after-custody".to_owned());
            }
            return Err(error);
        }
        Ok(DocketExecutionResponseWireV1::Refused(refusal))
    }

    fn get_refusal(&self, issuance: &str) -> Result<Option<IssuanceRefusalRecordV1>, String> {
        let record = self
            .connection
            .query_row(
                "SELECT refusal,signed_body_b64,issuer_principal,signer_key_id,
                        signer_public_key,signature,campaign,occurrence,refusal_class,
                        reason_code,evidence,refused_at
                 FROM governed_loop_issuance_refusal WHERE issuance=?1",
                params![issuance],
                |row| {
                    let refusal_class = refusal_class_from_tag(&row.get::<_, String>(8)?)
                        .map_err(|detail| sql_decode(&detail))?;
                    Ok(IssuanceRefusalRecordV1 {
                        refusal: DocketIssuanceRefusalWireV1 {
                            schema: ISSUANCE_REFUSAL_SCHEMA_V1.to_owned(),
                            refusal: row.get(0)?,
                            issuance: issuance.to_owned(),
                            campaign: row.get(6)?,
                            occurrence: row.get(7)?,
                            refusal_class,
                            reason_code: row.get(9)?,
                            evidence: row.get(10)?,
                            refused_at_unix_ms: read_u64(row.get(11)?, 11)?,
                        },
                        signed_body_b64: row.get(1)?,
                        authentication: IssuanceAuthenticationWireV1 {
                            issuer_principal: row.get(2)?,
                            signer_key_id: row.get(3)?,
                            signer_public_key: row.get(4)?,
                            signature: row.get(5)?,
                        },
                    })
                },
            )
            .optional()
            .map_err(|error| format!("governed-refusal-read:{error}"))?;
        record
            .map(|record| {
                validate_stored_refusal(&self.connection, &record)?;
                Ok(record)
            })
            .transpose()
    }

    fn insert_custody(
        &mut self,
        envelope: &SignedIssuanceEnvelopeWireV1,
        issuance: &AgIssuanceWireV2,
        standing: &ExecutionStandingResolutionV1,
        custody: &DocketCustodyWireV1,
        executor_binding: &ExecutorBindingV1,
    ) -> Result<(), String> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| format!("governed-custody-transaction:{error}"))?;
        transaction
            .execute(
                "INSERT INTO governed_loop_issuance_disposition
                 (issuance,disposition,artifact) VALUES (?1,'custody',?2)",
                params![issuance.issuance, custody.attempt],
            )
            .map_err(|error| format!("governed-custody-disposition:{error}"))?;
        transaction
            .execute(
                "INSERT INTO governed_execution_standing_use
                 (execution_standing,issuance,standing_resolution,standing_currentness,consumed_at)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    standing.execution_standing,
                    issuance.issuance,
                    standing.resolution,
                    standing.currentness,
                    u64_to_i64(custody.accepted_at_unix_ms)?
                ],
            )
            .map_err(|error| format!("governed-execution-standing-consume:{error}"))?;
        transaction
            .execute(
                "INSERT INTO governed_loop_attempt
                 (issuance,signed_body_b64,issuer_principal,signer_key_id,signer_public_key,
                  signature,campaign,occurrence,program,proposal,work_schema,work,subject,scope,
                  observation,ag_standing_resolution,mandate,ag_spend,execution_standing,
                  standing_currentness,attempt,executor_marker,executor_binding,
                  executor_program_digest,executor_config_digest,executor_plan,accepted_at,status)
                 VALUES
                 (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,
                  ?19,?20,?21,?22,?23,?24,?25,?26,?27,'accepted')",
                params![
                    issuance.issuance,
                    envelope.body_b64,
                    envelope.authentication.issuer_principal,
                    envelope.authentication.signer_key_id,
                    envelope.authentication.signer_public_key,
                    envelope.authentication.signature,
                    issuance.key.campaign,
                    issuance.key.occurrence,
                    issuance.program,
                    issuance.proposal,
                    issuance.work_schema,
                    issuance.work,
                    issuance.subject,
                    issuance.effect_scope_digest,
                    issuance.observation,
                    issuance.standing_resolution,
                    issuance.mandate,
                    issuance.spend,
                    custody.execution_standing,
                    custody.standing_currentness,
                    custody.attempt,
                    custody.executor_marker,
                    executor_binding.identity,
                    executor_binding.program_digest,
                    executor_binding.config_digest,
                    executor_binding.plan,
                    u64_to_i64(custody.accepted_at_unix_ms)?
                ],
            )
            .map_err(|error| format!("governed-attempt-insert:{error}"))?;
        transaction
            .commit()
            .map_err(|error| format!("governed-custody-commit:{error}"))
    }

    fn get(&mut self, issuance: &str) -> Result<Option<CustodyRecordV1>, String> {
        let record = self
            .connection
            .query_row(
                "SELECT signed_body_b64,issuer_principal,signer_key_id,signer_public_key,signature,
                        campaign,occurrence,program,proposal,work_schema,work,subject,scope,
                        observation,ag_standing_resolution,mandate,ag_spend,execution_standing,
                        standing_currentness,attempt,executor_marker,executor_binding,
                        executor_program_digest,executor_config_digest,executor_plan,accepted_at,status,
                        settlement,receipt,outcome,settled_at,reconciliation,indeterminate_evidence,
                        settlement_cumulative_effect_journal_identity
                 FROM governed_loop_attempt WHERE issuance=?1",
                [issuance],
                |row| {
                    let accepted_at = read_u64(row.get::<_, i64>(25)?, 25)?;
                    let status: String = row.get(26)?;
                    let settlement_ref: Option<String> = row.get(27)?;
                    let receipt: Option<String> = row.get(28)?;
                    let outcome: Option<String> = row.get(29)?;
                    let settled_at: Option<i64> = row.get(30)?;
                    let reconciliation: Option<String> = row.get(31)?;
                    let evidence: Option<String> = row.get(32)?;
                    let settlement_journal: Option<String> = row.get(33)?;
                    let signed_body_b64: String = row.get(0)?;
                    let body = b64_decode(&signed_body_b64).map_err(|error| sql_decode(&error))?;
                    let body_record: AgIssuanceWireV2 =
                        strict_json(&body, "stored-issuance-body").map_err(|error| sql_decode(&error))?;
                    let issuance_record = AgIssuanceWireV2 {
                        schema: AG_ISSUANCE_SCHEMA_V2.to_owned(),
                        issuance: issuance.to_owned(),
                        key: OccurrenceKeyWireV1 {
                            campaign: row.get(5)?,
                            occurrence: row.get(6)?,
                        },
                        program: row.get(7)?,
                        proposal: row.get(8)?,
                        work_schema: row.get(9)?,
                        work: row.get(10)?,
                        nonclaims: body_record.nonclaims,
                        expires_at_unix_ms: body_record.expires_at_unix_ms,
                        subject: row.get(11)?,
                        effect_scope: body_record.effect_scope,
                        effect_scope_digest: row.get(12)?,
                        governed_repair_checkpoint: body_record.governed_repair_checkpoint,
                        observation: row.get(13)?,
                        standing_resolution: row.get(14)?,
                        admission_decision: body_record.admission_decision,
                        mandate: row.get(15)?,
                        spend: row.get(16)?,
                    };
                    let custody = DocketCustodyWireV1 {
                        schema: CUSTODY_SCHEMA_V1.to_owned(),
                        issuance: issuance.to_owned(),
                        ag_spend: issuance_record.spend.clone(),
                        execution_standing: row.get(17)?,
                        standing_currentness: row.get(18)?,
                        attempt: row.get(19)?,
                        executor_marker: row.get(20)?,
                        accepted_at_unix_ms: accepted_at,
                    };
                    let known = match (
                        &settlement_ref,
                        &receipt,
                        &outcome,
                        settled_at,
                        &settlement_journal,
                    ) {
                        (
                            Some(settlement),
                            Some(receipt),
                            Some(outcome),
                            Some(at),
                            Some(cumulative_effect_journal_identity),
                        ) => {
                            Some(DocketSettlementWireV1 {
                                schema: SETTLEMENT_SCHEMA_V1.to_owned(),
                                settlement: settlement.clone(),
                                issuance: issuance.to_owned(),
                                attempt: custody.attempt.clone(),
                                executor_marker: custody.executor_marker.clone(),
                                receipt: receipt.clone(),
                                outcome: match outcome.as_str() {
                                    "success" => KnownOutcomeWireV1::Success,
                                    "failure" => KnownOutcomeWireV1::Failure,
                                    _ => return Err(sql_decode("governed outcome")),
                                },
                                cumulative_effect_journal_identity:
                                    cumulative_effect_journal_identity.clone(),
                                settled_at_unix_ms: read_u64(at, 30)?,
                            })
                        }
                        (None, None, None, None, None) => None,
                        _ => return Err(sql_decode("partial governed settlement")),
                    };
                    let indeterminate = match (reconciliation, evidence) {
                        (Some(reconciliation), Some(evidence)) => {
                            Some(IndeterminateOutcomeWireV1 {
                                issuance: issuance.to_owned(),
                                attempt: custody.attempt.clone(),
                                reconciliation,
                                evidence,
                            })
                        }
                        (None, None) => None,
                        _ => return Err(sql_decode("partial governed indeterminate")),
                    };
                    Ok(CustodyRecordV1 {
                        issuance: issuance_record,
                        custody,
                        signed_body_b64,
                        authentication: IssuanceAuthenticationWireV1 {
                            issuer_principal: row.get(1)?,
                            signer_key_id: row.get(2)?,
                            signer_public_key: row.get(3)?,
                            signature: row.get(4)?,
                        },
                        executor_binding: row.get(21)?,
                        executor_program_digest: row.get(22)?,
                        executor_config_digest: row.get(23)?,
                        executor_plan: row.get(24)?,
                        status,
                        settlement: known,
                        indeterminate,
                    })
                },
            )
            .optional()
            .map_err(|error| format!("governed-custody-read:{error}"))?;
        record
            .map(|record| {
                validate_stored_record(&record)?;
                governed_repair::validate_ordinary_executor_result(
                    &self.connection,
                    &record.issuance.issuance,
                    &record.custody.attempt,
                    &record.status,
                    &record.issuance.effect_scope,
                )?;
                if let Some(settlement) = &record.settlement {
                    let latest = governed_repair::latest_cumulative_effect_journal_identity(
                        &self.connection,
                        &record.issuance.issuance,
                        &record.custody.attempt,
                        &record.issuance.effect_scope,
                    )?
                    .ok_or_else(|| "governed-stored-settlement-journal-missing".to_owned())?;
                    if latest != settlement.cumulative_effect_journal_identity {
                        return Err("governed-stored-settlement-journal-substitution".to_owned());
                    }
                    let terminal: Option<(String, String)> = self
                        .connection
                        .query_row(
                            "SELECT outcome,receipt FROM governed_executor_result
                             WHERE issuance=?1 AND attempt=?2
                             ORDER BY sequence DESC LIMIT 1",
                            params![record.issuance.issuance, record.custody.attempt],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()
                        .map_err(|error| {
                            format!("governed-stored-settlement-terminal-read:{error}")
                        })?;
                    let expected_outcome = match settlement.outcome {
                        KnownOutcomeWireV1::Success => "success",
                        KnownOutcomeWireV1::Failure => "failure",
                    };
                    if terminal != Some((expected_outcome.to_owned(), settlement.receipt.clone())) {
                        return Err("governed-stored-settlement-terminal-substitution".to_owned());
                    }
                }
                Ok(record)
            })
            .transpose()
    }

    fn record_executor_outcome(
        &mut self,
        issuance: &str,
        custody: &DocketCustodyWireV1,
        outcome: ExecutorOutcomeWireV1,
        at: u64,
    ) -> Result<(), String> {
        if outcome.attempt != custody.attempt || outcome.marker != custody.executor_marker {
            return self.record_indeterminate(
                issuance,
                custody,
                &hash_domain(
                    "docket.governed-loop.executor-binding-refusal/v1",
                    format!("{}:{}", outcome.attempt, outcome.marker).as_bytes(),
                ),
            );
        }
        let record = self
            .get(issuance)?
            .ok_or_else(|| "governed-outcome-attempt-missing".to_owned())?;
        // Every executor outcome is evidence about effects, including ordinary
        // success/failure.  Refuse before settlement if any recorded effect was
        // outside the exact AG-issued scope.
        governed_repair::validate_effect_journal_for_issuance(
            &record.issuance.effect_scope,
            &outcome.effect_journal,
        )?;
        match (&outcome.outcome, &outcome.governed_repair) {
            (
                ExecutorOutcomeClassWireV1::ScopeExpansionRequired,
                Some(ExecutorGovernedRepairRequirementWireV1::ScopeExpansionRequired { .. }),
            )
            | (
                ExecutorOutcomeClassWireV1::ReadjudicationRequired,
                Some(ExecutorGovernedRepairRequirementWireV1::ReadjudicationRequired { .. }),
            ) => {
                governed_repair::seal_requirement(
                    &mut self.connection,
                    governed_repair::SealRequirementInputV1 {
                        issuance: &record.issuance,
                        custody,
                        executor_binding: &record.executor_binding,
                        executor_receipt: &outcome.receipt,
                        draft: outcome
                            .governed_repair
                            .ok_or_else(|| "governed-repair-requirement-missing".to_owned())?,
                        // The sealer opens an immediate transaction and joins
                        // these latest reported effects to the durable prior
                        // journal inside that same transaction.  Reading the
                        // cumulative journal here would leave a late-observer
                        // race between the read and terminal seal.
                        journal: &outcome.effect_journal,
                        immutable_work_checkpoint: outcome.immutable_work_checkpoint.as_ref(),
                        now_unix_ms: at,
                    },
                )?;
                return Ok(());
            }
            (
                ExecutorOutcomeClassWireV1::ScopeExpansionRequired
                | ExecutorOutcomeClassWireV1::ReadjudicationRequired,
                _,
            )
            | (
                ExecutorOutcomeClassWireV1::Success
                | ExecutorOutcomeClassWireV1::Failure
                | ExecutorOutcomeClassWireV1::Indeterminate,
                Some(_),
            ) => return Err("governed-repair-outcome-shape".to_owned()),
            _ => {}
        }
        require_digest(&outcome.receipt, "executor receipt")?;
        match outcome.outcome {
            ExecutorOutcomeClassWireV1::Success | ExecutorOutcomeClassWireV1::Failure => {
                let known = match outcome.outcome {
                    ExecutorOutcomeClassWireV1::Success => "success",
                    ExecutorOutcomeClassWireV1::Failure => "failure",
                    ExecutorOutcomeClassWireV1::Indeterminate => unreachable!(),
                    ExecutorOutcomeClassWireV1::ScopeExpansionRequired
                    | ExecutorOutcomeClassWireV1::ReadjudicationRequired => unreachable!(),
                };
                let tx = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|error| format!("governed-settlement-transaction:{error}"))?;
                let exact_replay = governed_repair::append_ordinary_executor_result(
                    &tx,
                    governed_repair::OrdinaryExecutorResultInputV1 {
                        issuance,
                        attempt: &custody.attempt,
                        outcome: known,
                        receipt: &outcome.receipt,
                        scope: &record.issuance.effect_scope,
                        entries: &outcome.effect_journal,
                        recorded_at: at,
                    },
                )?;
                // Settlement is derived only after the executor observation
                // has extended the cumulative journal in this same immediate
                // transaction. The settlement artifact therefore names the
                // complete effect history at its exact terminal cut.
                let cumulative_effect_journal_identity =
                    governed_repair::latest_cumulative_effect_journal_identity(
                        &tx,
                        issuance,
                        &custody.attempt,
                        &record.issuance.effect_scope,
                    )?
                    .ok_or_else(|| "governed-settlement-journal-missing".to_owned())?;
                if exact_replay && record.status == "settled" {
                    let existing = record
                        .settlement
                        .as_ref()
                        .ok_or_else(|| "governed-stored-settlement-missing".to_owned())?;
                    if existing.receipt != outcome.receipt
                        || existing.outcome
                            != match known {
                                "success" => KnownOutcomeWireV1::Success,
                                "failure" => KnownOutcomeWireV1::Failure,
                                _ => unreachable!(),
                            }
                        || existing.cumulative_effect_journal_identity
                            != cumulative_effect_journal_identity
                    {
                        return Err("governed-settlement-exact-replay-collision".to_owned());
                    }
                    return Ok(());
                }
                let mut settlement = DocketSettlementWireV1 {
                    schema: SETTLEMENT_SCHEMA_V1.to_owned(),
                    settlement: String::new(),
                    issuance: issuance.to_owned(),
                    attempt: custody.attempt.clone(),
                    executor_marker: custody.executor_marker.clone(),
                    receipt: outcome.receipt.clone(),
                    outcome: match known {
                        "success" => KnownOutcomeWireV1::Success,
                        "failure" => KnownOutcomeWireV1::Failure,
                        _ => unreachable!(),
                    },
                    cumulative_effect_journal_identity: cumulative_effect_journal_identity.clone(),
                    settled_at_unix_ms: at,
                };
                settlement.settlement = docket_settlement_identity(&settlement)?;
                let changed = tx
                    .execute(
                        "UPDATE governed_loop_attempt
                         SET status='settled',settlement=?1,receipt=?2,outcome=?3,settled_at=?4,
                             settlement_cumulative_effect_journal_identity=?5
                         WHERE issuance=?6 AND attempt=?7 AND executor_marker=?8
                           AND status IN ('accepted','indeterminate')
                           AND NOT EXISTS (
                             SELECT 1 FROM governed_repair_checkpoint
                             WHERE governed_repair_checkpoint.issuance=governed_loop_attempt.issuance
                           )",
                        params![
                            settlement.settlement,
                            outcome.receipt,
                            known,
                            u64_to_i64(at)?,
                            cumulative_effect_journal_identity,
                            issuance,
                            custody.attempt,
                            custody.executor_marker
                        ],
                    )
                    .map_err(|error| format!("governed-settlement-write:{error}"))?;
                if changed == 0 {
                    return if exact_replay {
                        Ok(())
                    } else {
                        Err("governed-settlement-raced-terminal-result".to_owned())
                    };
                }
                tx.commit()
                    .map_err(|error| format!("governed-settlement-commit:{error}"))
            }
            ExecutorOutcomeClassWireV1::Indeterminate => self.record_indeterminate_with_journal(
                issuance,
                custody,
                &outcome.receipt,
                &record.issuance.effect_scope,
                &outcome.effect_journal,
                at,
            ),
            ExecutorOutcomeClassWireV1::ScopeExpansionRequired
            | ExecutorOutcomeClassWireV1::ReadjudicationRequired => unreachable!(),
        }
    }

    fn record_indeterminate(
        &mut self,
        issuance: &str,
        custody: &DocketCustodyWireV1,
        evidence: &str,
    ) -> Result<(), String> {
        let record = self
            .get(issuance)?
            .ok_or_else(|| "governed-indeterminate-attempt-missing".to_owned())?;
        self.record_indeterminate_with_journal(
            issuance,
            custody,
            evidence,
            &record.issuance.effect_scope,
            &[],
            now_unix_ms()?,
        )
    }

    fn record_indeterminate_with_journal(
        &mut self,
        issuance: &str,
        custody: &DocketCustodyWireV1,
        evidence: &str,
        scope: &CanonicalEffectScopeWireV1,
        journal: &[EffectJournalEntryWireV1],
        at: u64,
    ) -> Result<(), String> {
        require_digest(evidence, "indeterminate evidence")?;
        let reconciliation = hash_domain(
            "docket.governed-loop.reconciliation/v1",
            format!("{issuance}:{}:{evidence}", custody.attempt).as_bytes(),
        );
        let tx = self
            .connection
            .transaction()
            .map_err(|error| format!("governed-indeterminate-transaction:{error}"))?;
        let exact_replay = governed_repair::append_ordinary_executor_result(
            &tx,
            governed_repair::OrdinaryExecutorResultInputV1 {
                issuance,
                attempt: &custody.attempt,
                outcome: "indeterminate",
                receipt: evidence,
                scope,
                entries: journal,
                recorded_at: at,
            },
        )?;
        let changed = tx
            .execute(
                "UPDATE governed_loop_attempt
                 SET status='indeterminate',reconciliation=?1,indeterminate_evidence=?2
                 WHERE issuance=?3 AND attempt=?4 AND executor_marker=?5
                   AND status='accepted'
                   AND NOT EXISTS (
                     SELECT 1 FROM governed_repair_checkpoint
                     WHERE governed_repair_checkpoint.issuance=governed_loop_attempt.issuance
                   )",
                params![
                    reconciliation,
                    evidence,
                    issuance,
                    custody.attempt,
                    custody.executor_marker
                ],
            )
            .map_err(|error| format!("governed-indeterminate-write:{error}"))?;
        if changed == 0 {
            let status: String = tx
                .query_row(
                    "SELECT status FROM governed_loop_attempt WHERE issuance=?1",
                    [issuance],
                    |row| row.get(0),
                )
                .map_err(|error| format!("governed-indeterminate-status-read:{error}"))?;
            let checkpoint_exists: i64 = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM governed_repair_checkpoint WHERE issuance=?1)",
                    [issuance],
                    |row| row.get(0),
                )
                .map_err(|error| format!("governed-indeterminate-terminal-read:{error}"))?;
            return if status == "indeterminate" && checkpoint_exists == 0 {
                // Multiple evidence observations may be appended while the
                // attempt remains unknown; none causes another execution.
                tx.commit()
                    .map_err(|error| format!("governed-indeterminate-commit:{error}"))
            } else if exact_replay {
                Ok(())
            } else {
                Err("governed-indeterminate-raced-terminal-result".to_owned())
            };
        }
        tx.commit()
            .map_err(|error| format!("governed-indeterminate-commit:{error}"))
    }
}

fn validate_stored_record(record: &CustodyRecordV1) -> Result<(), String> {
    validate_issuance(&record.issuance)?;
    let body = b64_decode(&record.signed_body_b64)?;
    let public_key = b64_decode(&record.authentication.signer_public_key)?;
    let signature = b64_decode(&record.authentication.signature)?;
    let mut signed = Vec::with_capacity(SIGNATURE_PREFIX_V2.len() + body.len());
    signed.extend_from_slice(SIGNATURE_PREFIX_V2);
    signed.extend_from_slice(&body);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signed, &signature)
        .map_err(|_| "governed-stored-issuance-signature-invalid".to_owned())?;
    let parsed: AgIssuanceWireV2 = strict_json(&body, "stored-issuance-body")?;
    let canonical = serde_jcs::to_vec(
        &serde_json::to_value(&parsed)
            .map_err(|error| format!("stored-issuance-canonical-value:{error}"))?,
    )
    .map_err(|error| format!("stored-issuance-canonical:{error}"))?;
    if parsed != record.issuance || canonical != body {
        return Err("governed-stored-issuance-substitution".to_owned());
    }
    if record.custody.schema != CUSTODY_SCHEMA_V1
        || record.custody.issuance != record.issuance.issuance
        || record.custody.ag_spend != record.issuance.spend
        || record.custody.attempt
            != digest_json_string(
                "ag.governed-loop.docket-attempt/v1",
                &record.issuance.issuance,
            )?
        || record.custody.executor_marker
            != hash_domain(
                "docket.governed-loop.executor-marker/v1",
                record.custody.attempt.as_bytes(),
            )
    {
        return Err("governed-stored-custody-substitution".to_owned());
    }
    for (value, label) in [
        (
            &record.custody.execution_standing,
            "stored execution standing",
        ),
        (
            &record.custody.standing_currentness,
            "stored standing currentness",
        ),
        (&record.executor_program_digest, "stored executor program"),
        (&record.executor_config_digest, "stored executor config"),
        (&record.executor_plan, "stored executor plan"),
        (&record.executor_binding, "stored executor binding"),
    ] {
        require_digest(value, label)?;
    }
    let binding = serde_json::to_vec(&serde_json::json!({
        "plan": record.executor_plan,
        "program_digest": record.executor_program_digest,
        "config_digest": record.executor_config_digest,
    }))
    .map_err(|error| format!("stored-executor-binding-canonical:{error}"))?;
    if record.executor_binding != hash_domain("docket.governed-loop.executor-binding/v1", &binding)
    {
        return Err("governed-stored-executor-binding-substitution".to_owned());
    }
    match record.status.as_str() {
        "accepted" if record.settlement.is_none() && record.indeterminate.is_none() => Ok(()),
        "settled" => {
            let settlement = record
                .settlement
                .as_ref()
                .ok_or_else(|| "governed-stored-settlement-missing".to_owned())?;
            if settlement.schema != SETTLEMENT_SCHEMA_V1
                || settlement.issuance != record.issuance.issuance
                || settlement.attempt != record.custody.attempt
                || settlement.executor_marker != record.custody.executor_marker
            {
                return Err("governed-stored-settlement-substitution".to_owned());
            }
            require_digest(&settlement.receipt, "stored settlement receipt")?;
            require_digest(
                &settlement.cumulative_effect_journal_identity,
                "stored settlement cumulative journal",
            )?;
            if settlement.settled_at_unix_ms > MAX_JCS_SAFE_INTEGER
                || settlement.settlement != docket_settlement_identity(settlement)?
            {
                return Err("governed-stored-settlement-identity".to_owned());
            }
            if let Some(indeterminate) = &record.indeterminate {
                validate_stored_indeterminate(record, indeterminate)?;
            }
            Ok(())
        }
        "indeterminate" => {
            let indeterminate = record
                .indeterminate
                .as_ref()
                .ok_or_else(|| "governed-stored-indeterminate-missing".to_owned())?;
            if record.settlement.is_some() {
                return Err("governed-stored-indeterminate-substitution".to_owned());
            }
            validate_stored_indeterminate(record, indeterminate)
        }
        _ => Err("governed-stored-status-shape".to_owned()),
    }
}

fn validate_stored_indeterminate(
    record: &CustodyRecordV1,
    indeterminate: &IndeterminateOutcomeWireV1,
) -> Result<(), String> {
    if indeterminate.issuance != record.issuance.issuance
        || indeterminate.attempt != record.custody.attempt
    {
        return Err("governed-stored-indeterminate-substitution".to_owned());
    }
    require_digest(&indeterminate.evidence, "stored indeterminate evidence")?;
    let expected = hash_domain(
        "docket.governed-loop.reconciliation/v1",
        format!(
            "{}:{}:{}",
            record.issuance.issuance, record.custody.attempt, indeterminate.evidence
        )
        .as_bytes(),
    );
    if indeterminate.reconciliation != expected {
        return Err("governed-stored-reconciliation-identity".to_owned());
    }
    Ok(())
}

fn require_same_envelope(
    existing: &CustodyRecordV1,
    envelope: &SignedIssuanceEnvelopeWireV1,
    issuance: &AgIssuanceWireV2,
) -> Result<(), String> {
    if existing.issuance != *issuance
        || existing.signed_body_b64 != envelope.body_b64
        || existing.authentication != envelope.authentication
    {
        return Err("governed-issuance-immutable-rebind".to_owned());
    }
    Ok(())
}

fn validate_issuance(issuance: &AgIssuanceWireV2) -> Result<(), String> {
    if issuance.schema != AG_ISSUANCE_SCHEMA_V2 {
        return Err("governed-issuance-schema".to_owned());
    }
    for (value, label) in [
        (&issuance.issuance, "issuance"),
        (&issuance.key.campaign, "campaign"),
        (&issuance.program, "program"),
        (&issuance.proposal, "proposal"),
        (&issuance.work, "work"),
        (&issuance.subject, "subject"),
        (&issuance.effect_scope_digest, "effect scope"),
        (&issuance.observation, "observation"),
        (&issuance.standing_resolution, "standing resolution"),
        (&issuance.mandate, "mandate"),
        (&issuance.spend, "AG spend"),
    ] {
        require_digest(value, label)?;
    }
    for (value, label) in [
        (&issuance.admission_decision.decision, "admission decision"),
        (
            &issuance.admission_decision.policy_basis,
            "admission policy",
        ),
    ] {
        require_digest(value, label)?;
    }
    if issuance.admission_decision.key != issuance.key
        || issuance.admission_decision.observation != issuance.observation
        || issuance.admission_decision.proposal != issuance.proposal
        || issuance.admission_decision.standing_resolution != issuance.standing_resolution
        || issuance.admission_decision.disposition != AdmissionDispositionWireV1::Admitted
    {
        return Err("governed-admission-decision-binding".to_owned());
    }
    governed_repair::validate_ag_effect_scope_identity(
        &issuance.effect_scope,
        &issuance.effect_scope_digest,
    )?;
    require_uuid(&issuance.key.occurrence)?;
    if !is_canonical_wire_label(&issuance.work_schema) {
        return Err("governed-issuance-work-schema".to_owned());
    }
    if issuance.expires_at_unix_ms == 0
        || issuance.expires_at_unix_ms > MAX_JCS_SAFE_INTEGER
        || issuance.nonclaims.is_empty()
    {
        return Err("governed-issuance-constraints".to_owned());
    }
    let mut previous_nonclaim: Option<&str> = None;
    for nonclaim in &issuance.nonclaims {
        require_digest(nonclaim, "issuance nonclaim")?;
        if previous_nonclaim.is_some_and(|previous| previous >= nonclaim.as_str()) {
            return Err("governed-issuance-nonclaims-not-canonical".to_owned());
        }
        previous_nonclaim = Some(nonclaim);
    }
    let expected = ag_issuance_identity(issuance)?;
    if expected != issuance.issuance {
        return Err("governed-issuance-identity-mismatch".to_owned());
    }
    Ok(())
}

fn is_canonical_wire_label(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 {
        return false;
    }
    let mut prior_separator = true;
    for byte in value.bytes() {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            prior_separator = false;
        } else if matches!(byte, b'-' | b'.' | b'_' | b'/' | b':') && !prior_separator {
            prior_separator = true;
        } else {
            return false;
        }
    }
    !prior_separator
}

fn validate_fresh_issuance(issuance: &AgIssuanceWireV2, now_unix_ms: u64) -> Result<(), String> {
    if now_unix_ms >= issuance.expires_at_unix_ms {
        return Err("governed-issuance-expired".to_owned());
    }
    Ok(())
}

fn validate_refusable_issuance_identity(issuance: &AgIssuanceWireV2) -> Result<(), String> {
    require_digest(&issuance.issuance, "refusable issuance")?;
    require_digest(&issuance.key.campaign, "refusable campaign")?;
    require_uuid(&issuance.key.occurrence)
}

fn validate_standing(
    issuance: &AgIssuanceWireV2,
    standing: &ExecutionStandingResolutionV1,
    now: u64,
) -> Result<(), String> {
    if standing.schema != STANDING_RESOLUTION_SCHEMA_V1 {
        return Err("governed-execution-standing-schema".to_owned());
    }
    for (value, label) in [
        (&standing.resolution, "Docket standing resolution"),
        (&standing.currentness, "Docket standing currentness"),
        (&standing.execution_standing, "Docket execution standing"),
    ] {
        require_digest(value, label)?;
    }
    if standing.issuance != issuance.issuance
        || standing.campaign != issuance.key.campaign
        || standing.occurrence != issuance.key.occurrence
        || standing.subject != issuance.subject
        || standing.scope != issuance.effect_scope_digest
    {
        return Err("governed-execution-standing-binding-mismatch".to_owned());
    }
    if standing.status != ExecutionStandingStatusV1::Current
        || standing.resolved_at_unix_ms > now
        || now >= standing.expires_at_unix_ms
    {
        return Err("governed-execution-standing-not-current".to_owned());
    }
    Ok(())
}

fn verify_starting_checkpoint(
    issuance: &AgIssuanceWireV2,
    verifier: Option<&Path>,
    now_unix_ms: u64,
) -> Result<(), String> {
    verify_starting_checkpoint_for_intake(issuance, verifier, now_unix_ms).map_err(|error| {
        match error {
            IntakeValidationErrorV1::Transient(error) => error,
            IntakeValidationErrorV1::Refusal(draft) => draft.reason_code,
        }
    })
}

fn verify_starting_checkpoint_for_intake(
    issuance: &AgIssuanceWireV2,
    verifier: Option<&Path>,
    now_unix_ms: u64,
) -> Result<(), IntakeValidationErrorV1> {
    let Some(checkpoint) = &issuance.governed_repair_checkpoint else {
        return Ok(());
    };
    if validate_checkpoint_evidence(checkpoint).is_err() {
        let reason_code = "governed-checkpoint-evidence-invalid".to_owned();
        let bytes = serde_json::to_vec(checkpoint).map_err(|error| {
            IntakeValidationErrorV1::Transient(format!(
                "governed-checkpoint-evidence-canonical:{error}"
            ))
        })?;
        return Err(IntakeValidationErrorV1::Refusal(RefusalDraftV1 {
            refusal_class: DocketIssuanceRefusalClassWireV1::CheckpointInvalid,
            evidence: refusal_evidence(
                issuance,
                DocketIssuanceRefusalClassWireV1::CheckpointInvalid,
                &reason_code,
                &bytes,
            )
            .map_err(IntakeValidationErrorV1::Transient)?,
            reason_code,
        }));
    }
    let verifier = verifier.ok_or_else(|| {
        IntakeValidationErrorV1::Transient("governed-checkpoint-verifier-required".to_owned())
    })?;
    let (result, result_bytes): (CheckpointVerificationResultWireV1, Vec<u8>) =
        match invoke_json_classified(
            verifier,
            &[],
            &CheckpointVerificationRequestWireV1 {
                schema: "docket.governed-repair.checkpoint-verification-request/v1".to_owned(),
                issuance: issuance.issuance.clone(),
                checkpoint: checkpoint.clone(),
            },
        ) {
            Ok(value) => value,
            Err(JsonInvocationErrorV1::Unavailable(error)) => {
                return Err(IntakeValidationErrorV1::Transient(error))
            }
            Err(JsonInvocationErrorV1::InvalidResponse {
                reason_code,
                evidence,
            }) => {
                return Err(IntakeValidationErrorV1::Refusal(RefusalDraftV1 {
                    refusal_class: DocketIssuanceRefusalClassWireV1::CheckpointInvalid,
                    evidence: refusal_evidence(
                        issuance,
                        DocketIssuanceRefusalClassWireV1::CheckpointInvalid,
                        &reason_code,
                        evidence.as_bytes(),
                    )
                    .map_err(IntakeValidationErrorV1::Transient)?,
                    reason_code,
                }))
            }
        };
    if result.schema != "docket.governed-repair.checkpoint-verification/v1"
        || result.issuance != issuance.issuance
        || result.checkpoint != *checkpoint
        || result.status != CheckpointVerificationStatusWireV1::Current
        || result.verified_at_unix_ms > now_unix_ms
        || now_unix_ms >= result.expires_at_unix_ms
    {
        let reason_code = "governed-checkpoint-verification-mismatch".to_owned();
        return Err(IntakeValidationErrorV1::Refusal(RefusalDraftV1 {
            refusal_class: DocketIssuanceRefusalClassWireV1::CheckpointInvalid,
            evidence: refusal_evidence(
                issuance,
                DocketIssuanceRefusalClassWireV1::CheckpointInvalid,
                &reason_code,
                &result_bytes,
            )
            .map_err(IntakeValidationErrorV1::Transient)?,
            reason_code,
        }));
    }
    if require_digest(&result.verification, "checkpoint verification").is_err() {
        let reason_code = "governed-checkpoint-verification-identity-invalid".to_owned();
        return Err(IntakeValidationErrorV1::Refusal(RefusalDraftV1 {
            refusal_class: DocketIssuanceRefusalClassWireV1::CheckpointInvalid,
            evidence: refusal_evidence(
                issuance,
                DocketIssuanceRefusalClassWireV1::CheckpointInvalid,
                &reason_code,
                &result_bytes,
            )
            .map_err(IntakeValidationErrorV1::Transient)?,
            reason_code,
        }));
    }
    Ok(())
}

fn validate_checkpoint_evidence(
    checkpoint: &GovernedRepairCheckpointEvidenceWireV1,
) -> Result<(), String> {
    require_digest(&checkpoint.repository, "checkpoint repository")?;
    require_digest(&checkpoint.content_manifest, "checkpoint content manifest")?;
    if let Some(value) = &checkpoint.diff_identity {
        require_digest(value, "checkpoint diff")?;
    }
    if let Some(value) = &checkpoint.docket_checkpoint {
        require_digest(value, "prior Docket checkpoint")?;
    }
    for (value, label) in [
        (&checkpoint.commit, "checkpoint commit"),
        (&checkpoint.tree, "checkpoint tree"),
    ] {
        if value.len() != 40
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!("governed-{label}"));
        }
    }
    Ok(())
}

/// Parses consequence-bearing Docket JSON with recursive duplicate-member,
/// safe-integer, and typed unknown-field refusal.
pub fn strict_json<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let StrictJsonValue(value) = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|error| format!("{label}-json:{error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("{label}-json:{error}"))?;
    validate_safe_json_numbers(&value).map_err(|error| format!("{label}-json:{error}"))?;
    serde_json::from_value(value).map_err(|error| format!("{label}-json:{error}"))
}

/// JSON value decoded with duplicate-member refusal at every object depth.
/// `serde_json::Value` alone is insufficient because its map decoder keeps the
/// last duplicate member, which could turn altered signed bytes into a typed
/// record with ambiguous source meaning.
struct StrictJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonValueVisitor)
    }
}

struct StrictJsonValueVisitor;

impl<'de> Visitor<'de> for StrictJsonValueVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(|number| StrictJsonValue(serde_json::Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictJsonValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJsonValue(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON object member: {key}"
                )));
            }
            let StrictJsonValue(value) = map.next_value()?;
            values.insert(key, value);
        }
        Ok(StrictJsonValue(serde_json::Value::Object(values)))
    }
}

fn validate_safe_json_numbers(value: &serde_json::Value) -> Result<(), &'static str> {
    match value {
        serde_json::Value::Number(number) => {
            if number
                .as_u64()
                .is_some_and(|value| value <= MAX_JCS_SAFE_INTEGER)
                || number.as_i64().is_some_and(|value| {
                    value >= -(MAX_JCS_SAFE_INTEGER as i64) && value <= MAX_JCS_SAFE_INTEGER as i64
                })
            {
                Ok(())
            } else {
                Err("number-outside-jcs-safe-integer-domain")
            }
        }
        serde_json::Value::Array(values) => values.iter().try_for_each(validate_safe_json_numbers),
        serde_json::Value::Object(values) => {
            values.values().try_for_each(validate_safe_json_numbers)
        }
        _ => Ok(()),
    }
}

fn prepare_executor(
    program: &Path,
    config: &Path,
    expected_plan: &str,
) -> Result<PreparedExecutorV1, String> {
    require_digest(expected_plan, "executor plan")?;
    let (retained, program_digest, config_digest) = retain_executor(program, config)?;
    let plan = invoke_plan_id(&retained)?;
    if plan != expected_plan {
        return Err("governed-executor-plan-substitution".to_owned());
    }
    let canonical = serde_json::to_vec(&serde_json::json!({
        "config_digest": config_digest,
        "plan": plan,
        "program_digest": program_digest,
    }))
    .map_err(|error| format!("governed-executor-binding-canonical:{error}"))?;
    Ok(PreparedExecutorV1 {
        retained,
        binding: ExecutorBindingV1 {
            identity: hash_domain("docket.governed-loop.executor-binding/v1", &canonical),
            program_digest,
            config_digest,
            plan,
        },
    })
}

fn retain_bound_executor(
    program: &Path,
    config: &Path,
    expected: &ExecutorBindingV1,
) -> Result<RetainedExecutorV1, String> {
    require_digest(&expected.identity, "executor binding")?;
    require_digest(&expected.program_digest, "executor program")?;
    require_digest(&expected.config_digest, "executor config")?;
    require_digest(&expected.plan, "executor plan")?;
    let (retained, program_digest, config_digest) = retain_executor(program, config)?;
    let canonical = serde_json::to_vec(&serde_json::json!({
        "config_digest": config_digest,
        "plan": expected.plan,
        "program_digest": program_digest,
    }))
    .map_err(|error| format!("governed-executor-binding-canonical:{error}"))?;
    let observed = ExecutorBindingV1 {
        identity: hash_domain("docket.governed-loop.executor-binding/v1", &canonical),
        program_digest,
        config_digest,
        plan: expected.plan.clone(),
    };
    if &observed != expected {
        return Err("governed-executor-binding-substitution".to_owned());
    }
    Ok(retained)
}

fn retain_executor(
    program: &Path,
    config: &Path,
) -> Result<(RetainedExecutorV1, String, String), String> {
    if !program.is_absolute() || !config.is_absolute() {
        return Err("governed-executor-path-not-absolute".to_owned());
    }
    // Preserve the existing UTF-8 path refusal even though the retained launch
    // exposes only descriptor locators to the child.
    let _ = config
        .to_str()
        .ok_or_else(|| "executor-config-path-not-utf8".to_owned())?;
    let program_bytes =
        read_exact_regular_file(program, MAX_EXECUTOR_PROGRAM_BYTES, "executor", true)?;
    let config_bytes =
        read_exact_regular_file(config, MAX_EXECUTOR_CONFIG_BYTES, "executor-config", false)?;
    let program_digest = hash_domain("docket.governed-loop.executor-program/v1", &program_bytes);
    let config_digest = hash_domain("docket.governed-loop.executor-config/v1", &config_bytes);
    let retained = materialize_executor_snapshot(program, &program_bytes, &config_bytes)?;
    Ok((retained, program_digest, config_digest))
}

fn read_exact_regular_file(
    path: &Path,
    maximum_bytes: u64,
    label: &str,
    require_executable: bool,
) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("governed-{label}-metadata:{}:{error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("governed-{label}-not-regular-nonsymlink"));
    }
    if metadata.len() > maximum_bytes {
        return Err(format!("governed-{label}-too-large"));
    }
    let mut opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("governed-{label}-open:{}:{error}", path.display()))?;
    let opened_metadata = opened
        .metadata()
        .map_err(|error| format!("governed-{label}-opened-metadata:{error}"))?;
    if !opened_metadata.is_file()
        || opened_metadata.len() != metadata.len()
        || opened_metadata.len() > maximum_bytes
    {
        return Err(format!("governed-{label}-file-raced"));
    }
    if require_executable && opened_metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!("governed-{label}-not-executable"));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened_metadata.len())
            .map_err(|_| format!("governed-{label}-size-overflow"))?,
    );
    opened
        .read_to_end(&mut bytes)
        .map_err(|error| format!("governed-{label}-read:{error}"))?;
    if bytes.len() as u64 != opened_metadata.len() {
        return Err(format!("governed-{label}-file-raced"));
    }
    Ok(bytes)
}

fn materialize_executor_snapshot(
    source_program: &Path,
    program_bytes: &[u8],
    config_bytes: &[u8],
) -> Result<RetainedExecutorV1, String> {
    let snapshot_root = loop {
        let nonce = NEXT_EXECUTOR_SNAPSHOT.fetch_add(1, Ordering::Relaxed);
        let candidate = std::env::temp_dir().join(format!(
            "docket-governed-executor-{}-{nonce}",
            std::process::id()
        ));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("governed-executor-snapshot-dir:{error}")),
        }
    };
    let result = (|| {
        let program = snapshot_root.join("executor");
        let config = snapshot_root.join("config");
        write_snapshot_file(&program, program_bytes, 0o500)?;
        write_snapshot_file(&config, config_bytes, 0o400)?;
        Ok(RetainedExecutorV1 {
            program,
            config,
            display_path: source_program.to_path_buf(),
            snapshot_root: snapshot_root.clone(),
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&snapshot_root);
    }
    result
}

fn write_snapshot_file(path: &Path, bytes: &[u8], final_mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("governed-executor-snapshot-create:{error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("governed-executor-snapshot-write:{error}"))?;
    file.sync_all()
        .map_err(|error| format!("governed-executor-snapshot-sync:{error}"))?;
    let mut permissions = file
        .metadata()
        .map_err(|error| format!("governed-executor-snapshot-metadata:{error}"))?
        .permissions();
    permissions.set_mode(final_mode);
    file.set_permissions(permissions)
        .map_err(|error| format!("governed-executor-snapshot-mode:{error}"))?;
    if std::fs::read(path).map_err(|error| format!("governed-executor-snapshot-read:{error}"))?
        != bytes
    {
        return Err("governed-executor-snapshot-substitution".to_owned());
    }
    Ok(())
}

impl RetainedExecutorV1 {
    fn command(&self, operation: &str) -> Command {
        let mut command = Command::new(&self.program);
        command.arg(operation).arg(&self.config);
        command
    }
}

fn invoke_plan_id(executor: &RetainedExecutorV1) -> Result<String, String> {
    let output = executor
        .command("plan-id")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| {
            format!(
                "executor-plan-id-spawn:{}:{error}",
                executor.display_path.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "executor-plan-id-refused:{}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(512)
                .collect::<String>()
        ));
    }
    let body = output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout);
    if body.is_empty() || body.contains(&b'\n') || body.contains(&b'\r') {
        return Err("executor-plan-id-not-exact".to_owned());
    }
    let plan = std::str::from_utf8(body)
        .map_err(|_| "executor-plan-id-not-utf8".to_owned())?
        .to_owned();
    require_digest(&plan, "executor plan")?;
    Ok(plan)
}

fn invoke_retained_json<I: Serialize + ?Sized, O: DeserializeOwned>(
    executor: &RetainedExecutorV1,
    operation: &str,
    input: &I,
) -> Result<O, String> {
    let bytes =
        serde_jcs::to_vec(input).map_err(|error| format!("process-request-canonical:{error}"))?;
    let mut child = executor
        .command(operation)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("process-spawn:{}:{error}", executor.display_path.display()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "process-stdin-unavailable".to_owned())?
        .write_all(&bytes)
        .map_err(|error| format!("process-stdin:{error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("process-wait:{error}"))?;
    if !output.status.success() {
        return Err(format!(
            "process-refused:{}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(512)
                .collect::<String>()
        ));
    }
    strict_json(&output.stdout, "process-response")
}

fn invoke_json_classified<I: Serialize + ?Sized, O: DeserializeOwned>(
    program: &Path,
    arguments: &[&str],
    input: &I,
) -> Result<(O, Vec<u8>), JsonInvocationErrorV1> {
    let bytes = serde_json::to_vec(input)
        .map_err(|error| JsonInvocationErrorV1::Unavailable(format!("process-request:{error}")))?;
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            JsonInvocationErrorV1::Unavailable(format!(
                "process-spawn:{}:{error}",
                program.display()
            ))
        })?;
    child
        .stdin
        .take()
        .ok_or_else(|| JsonInvocationErrorV1::Unavailable("process-stdin-unavailable".to_owned()))?
        .write_all(&bytes)
        .map_err(|error| JsonInvocationErrorV1::Unavailable(format!("process-stdin:{error}")))?;
    let output = child
        .wait_with_output()
        .map_err(|error| JsonInvocationErrorV1::Unavailable(format!("process-wait:{error}")))?;
    if !output.status.success() {
        return Err(JsonInvocationErrorV1::Unavailable(format!(
            "process-refused:{}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(512)
                .collect::<String>()
        )));
    }
    let parsed = strict_json(&output.stdout, "process-response").map_err(|_| {
        JsonInvocationErrorV1::InvalidResponse {
            reason_code: "governed-process-response-invalid".to_owned(),
            evidence: hash_domain(
                "docket.governed-loop.invalid-process-response/v1",
                &output.stdout,
            ),
        }
    })?;
    Ok((parsed, output.stdout))
}

fn b64_decode(value: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    for byte in value.bytes() {
        let index = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or_else(|| "noncanonical-base64url".to_owned())? as u32;
        accumulator = (accumulator << 6) | index;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    if bits >= 6 || (accumulator & ((1 << bits) - 1)) != 0 {
        return Err("noncanonical-base64url".to_owned());
    }
    Ok(output)
}

fn hash_domain(domain: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ag-ng\0digest\0v1\0");
    hasher.update((domain.len() as u128).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((payload.len() as u128).to_be_bytes());
    hasher.update(payload);
    format!("sha256:{}", lower_hex(&hasher.finalize()))
}

fn digest_json_string(domain: &str, value: &str) -> Result<String, String> {
    let payload = serde_json::to_vec(value).map_err(|error| format!("digest-string:{error}"))?;
    Ok(hash_domain(domain, &payload))
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn require_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("governed-{label}-digest"));
    }
    Ok(())
}

fn require_uuid(value: &str) -> Result<(), String> {
    if value.len() != 36
        || value.bytes().enumerate().any(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte != b'-',
            _ => !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        })
    {
        return Err("governed-occurrence-uuid".to_owned());
    }
    Ok(())
}

fn now_unix_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system-clock-before-epoch".to_owned())?;
    u64::try_from(duration.as_millis()).map_err(|_| "system-clock-overflow".to_owned())
}

fn u64_to_i64(value: u64) -> Result<i64, String> {
    if value > MAX_JCS_SAFE_INTEGER {
        return Err("governed-clock-outside-jcs-safe-integer-domain".to_owned());
    }
    i64::try_from(value).map_err(|_| "governed-clock-out-of-range".to_owned())
}

fn read_u64(value: i64, column: usize) -> rusqlite::Result<u64> {
    let value =
        u64::try_from(value).map_err(|_| sql_decode(&format!("negative u64 column {column}")))?;
    if value > MAX_JCS_SAFE_INTEGER {
        return Err(sql_decode(&format!(
            "unsafe JSON integer in u64 column {column}"
        )));
    }
    Ok(value)
}

fn sql_decode(detail: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        std::io::Error::new(std::io::ErrorKind::InvalidData, detail.to_owned()).into(),
    )
}

#[cfg(test)]
#[path = "governed_wire_conformance_tests.rs"]
mod governed_wire_conformance_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governed_repair::validate_effect_journal_for_issuance as effect_journal_identity;
    use crate::store::SqliteStore;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    const R2_CONTRACT: &[u8] =
        include_bytes!("../../../conformance/governed-repair-r2/contract.v1.json");
    const R2_MANIFEST: &[u8] =
        include_bytes!("../../../conformance/governed-repair-r2/manifest.v1.json");
    const R2_LABELS: &[u8] =
        include_bytes!("../../../conformance/governed-repair-r2/labels.v1.json");
    const R2_SCOPES: &[u8] =
        include_bytes!("../../../conformance/governed-repair-r2/scopes.v1.json");
    const R2_WIRE_HOSTILES: &[u8] =
        include_bytes!("../../../conformance/governed-repair-r2/wire-hostiles.v1.json");
    const R2_WIRE_VECTORS: &[u8] =
        include_bytes!("../../../conformance/governed-repair-r2/wire-vectors.v1.json");
    const R5_RECONCILIATION_ROUNDS: &[u8] =
        include_bytes!("../../../conformance/governed-repair-r2/reconciliation-rounds.v1.json");

    fn raw_sha256(bytes: &[u8]) -> String {
        format!("sha256:{}", lower_hex(&Sha256::digest(bytes)))
    }

    fn assert_pinned_canonical_corpus(bytes: &[u8], expected: &str) {
        assert_eq!(raw_sha256(bytes), expected);
        let (canonical, newline) = bytes.split_at(bytes.len() - 1);
        assert_eq!(newline, b"\n");
        let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(serde_jcs::to_vec(&value).unwrap(), canonical);
    }

    #[test]
    fn r2_shared_contract_corpus_has_exact_pinned_bytes() {
        assert_pinned_canonical_corpus(
            R2_MANIFEST,
            "sha256:74c429d8d32341fc31fba45e4cdd1a0b6d994bace4c7d4d8ccfccfc9dad8aded",
        );
        assert_pinned_canonical_corpus(
            R2_CONTRACT,
            "sha256:d3fc470761d8550f733e2528f0a2589e93717bd120e9b1ffbae687942168458b",
        );
        assert_pinned_canonical_corpus(
            R2_LABELS,
            "sha256:47a2a8d97e700c0296044d5bb7d795e51b609860875062aaa633ced7498215b6",
        );
        assert_pinned_canonical_corpus(
            R2_SCOPES,
            "sha256:905e9b96ba81a2dcc072f243b3bb1b8a02381377b2cebf61e98eaff033c3abaa",
        );
        assert_pinned_canonical_corpus(
            R2_WIRE_HOSTILES,
            "sha256:9862a1e38bb9db11cd39aebe04b3bd8ffaed7d315b67becc1e164176a20858b9",
        );
        assert_pinned_canonical_corpus(
            R2_WIRE_VECTORS,
            "sha256:ff75b856fd1a3076809d26f40d987b114046226aa15e7eeeb46db3388f36ea90",
        );
        assert_pinned_canonical_corpus(
            R5_RECONCILIATION_ROUNDS,
            "sha256:408a2fe3ddf75621c43da441cbdcd33c7fe0845abadd9b02adc72038d01496fc",
        );
    }

    #[test]
    fn r2_docket_validator_consumes_shared_label_corpus() {
        let corpus: serde_json::Value = serde_json::from_slice(R2_LABELS).unwrap();
        let scope_for = |effect_class: &str, resource: &str| CanonicalEffectScopeWireV1 {
            schema: "ag.governed-loop.canonical-effect-scope/v1".to_owned(),
            effect_class: effect_class.to_owned(),
            resources: vec![CanonicalEffectResourceWireV1 {
                resource: resource.to_owned(),
                path: "bounded/path".to_owned(),
                operations: vec![CanonicalEffectOperationWireV1::Read],
            }],
        };
        let validate = |scope: &CanonicalEffectScopeWireV1| {
            let identity = hash_domain(
                "ag.governed-loop.canonical-effect-scope/v1",
                &serde_jcs::to_vec(scope).unwrap(),
            );
            governed_repair::validate_ag_effect_scope_identity(scope, &identity)
        };

        for value in corpus["accepted"].as_array().unwrap() {
            let value = value.as_str().unwrap();
            assert!(
                validate(&scope_for(value, "repository")).is_ok(),
                "shared accepted label refused: {value:?}"
            );
            let mut issuance = fixture(ExecutorOutcomeClassWireV1::Success)
                .issuance
                .clone();
            issuance.work_schema = value.to_owned();
            refresh_issuance_identity(&mut issuance);
            assert!(
                validate_issuance(&issuance).is_ok(),
                "shared accepted work-schema label refused: {value:?}"
            );
        }
        for value in corpus["rejected"].as_array().unwrap() {
            let value = value.as_str().unwrap();
            assert!(
                validate(&scope_for(value, "repository")).is_err(),
                "shared rejected label accepted: {value:?}"
            );
            let mut issuance = fixture(ExecutorOutcomeClassWireV1::Success)
                .issuance
                .clone();
            issuance.work_schema = value.to_owned();
            refresh_issuance_identity(&mut issuance);
            assert!(
                validate_issuance(&issuance).is_err(),
                "shared rejected work-schema label accepted: {value:?}"
            );
        }
        for value in corpus["effect_class_accepted_resource_rejected"]
            .as_array()
            .unwrap()
        {
            let value = value.as_str().unwrap();
            assert!(validate(&scope_for(value, "repository")).is_ok());
            assert!(
                validate(&scope_for("repository-read/v1", value)).is_err(),
                "mutable-ref resource unexpectedly accepted: {value:?}"
            );
        }
    }

    #[test]
    fn r2_docket_scope_identity_matches_shared_corpus() {
        let corpus: serde_json::Value = serde_json::from_slice(R2_SCOPES).unwrap();
        for vector in corpus["vectors"].as_array().unwrap() {
            let scope: CanonicalEffectScopeWireV1 =
                serde_json::from_value(vector["value"].clone()).unwrap();
            let canonical = serde_jcs::to_vec(&scope).unwrap();
            assert_eq!(
                std::str::from_utf8(&canonical).unwrap(),
                vector["canonical"]
            );
            let identity = vector["identity"].as_str().unwrap();
            assert_eq!(
                hash_domain("ag.governed-loop.canonical-effect-scope/v1", &canonical),
                identity
            );
            governed_repair::validate_ag_effect_scope_identity(&scope, identity).unwrap();
        }
    }

    #[test]
    fn r2_checkpoint_optionals_are_omitted_and_explicit_null_refuses() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let absent = serde_jcs::to_vec(&fixture.issuance).unwrap();
        let absent_value: serde_json::Value = serde_json::from_slice(&absent).unwrap();
        assert!(!absent_value
            .as_object()
            .unwrap()
            .contains_key("governed_repair_checkpoint"));

        let mut issuance = fixture.issuance.clone();
        issuance.governed_repair_checkpoint = Some(GovernedRepairCheckpointEvidenceWireV1 {
            repository: digest("checkpoint-repository"),
            commit: "1".repeat(40),
            tree: "2".repeat(40),
            diff_identity: None,
            content_manifest: digest("checkpoint-manifest"),
            docket_checkpoint: None,
        });
        let encoded = serde_jcs::to_vec(&issuance).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        let checkpoint = value["governed_repair_checkpoint"].as_object().unwrap();
        assert!(!checkpoint.contains_key("diff_identity"));
        assert!(!checkpoint.contains_key("docket_checkpoint"));
        assert!(checkpoint.contains_key("content_manifest"));

        let mut explicit_null = value.clone();
        explicit_null["governed_repair_checkpoint"]["diff_identity"] = serde_json::Value::Null;
        assert!(strict_json::<AgIssuanceWireV2>(
            &serde_jcs::to_vec(&explicit_null).unwrap(),
            "explicit-null"
        )
        .is_err());

        let mut missing_manifest = value;
        missing_manifest["governed_repair_checkpoint"]
            .as_object_mut()
            .unwrap()
            .remove("content_manifest");
        assert!(strict_json::<AgIssuanceWireV2>(
            &serde_jcs::to_vec(&missing_manifest).unwrap(),
            "missing-manifest"
        )
        .is_err());
    }

    #[test]
    fn issuance_refusal_identity_matches_frozen_cross_repository_vector() {
        let refusal = DocketIssuanceRefusalWireV1 {
            schema: ISSUANCE_REFUSAL_SCHEMA_V1.to_owned(),
            refusal: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
            issuance: format!("sha256:{}", "11".repeat(32)),
            campaign: format!("sha256:{}", "22".repeat(32)),
            occurrence: "00000000-0000-0000-0000-000000000001".to_owned(),
            refusal_class: DocketIssuanceRefusalClassWireV1::StandingInvalid,
            reason_code: "standing_invalid".to_owned(),
            evidence: format!("sha256:{}", "33".repeat(32)),
            refused_at_unix_ms: 42,
        };
        assert_eq!(
            refusal_identity(&refusal).unwrap(),
            "sha256:14e18c3d74be772ed6e72de25eb735fa26d5154c333a45aba0585f9a09306ce6"
        );
    }

    struct Fixture {
        root: std::path::PathBuf,
        database: std::path::PathBuf,
        trust: Vec<u8>,
        envelope: Vec<u8>,
        signing_key_pkcs8: Vec<u8>,
        issuance: AgIssuanceWireV2,
        custody: DocketCustodyWireV1,
        standing_program: std::path::PathBuf,
        executor_program: std::path::PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn fixture(executor_outcome: ExecutorOutcomeClassWireV1) -> Fixture {
        fixture_with_expiry(executor_outcome, 4_000_000_000_000)
    }

    fn fixture_with_expiry(
        executor_outcome: ExecutorOutcomeClassWireV1,
        expires_at_unix_ms: u64,
    ) -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "docket-governed-loop-test-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let database = root.join("state.sqlite");
        drop(SqliteStore::open(&database).unwrap());

        let effect_scope = CanonicalEffectScopeWireV1 {
            schema: "ag.governed-loop.canonical-effect-scope/v1".to_owned(),
            effect_class: "repository-write/v1".to_owned(),
            resources: vec![CanonicalEffectResourceWireV1 {
                resource: "repository".to_owned(),
                path: "crates/nq-store/src/lib.rs".to_owned(),
                operations: vec![CanonicalEffectOperationWireV1::Modify],
            }],
        };
        let effect_scope_digest = hash_domain(
            "ag.governed-loop.canonical-effect-scope/v1",
            &serde_jcs::to_vec(&effect_scope).unwrap(),
        );
        let mut issuance = AgIssuanceWireV2 {
            schema: AG_ISSUANCE_SCHEMA_V2.to_owned(),
            issuance: digest("placeholder"),
            key: OccurrenceKeyWireV1 {
                campaign: digest("campaign"),
                occurrence: "00000000-0000-0000-0000-000000000001".to_owned(),
            },
            program: digest("program"),
            proposal: digest("proposal"),
            work_schema: "test.executor/v1".to_owned(),
            work: digest("work"),
            nonclaims: vec![digest("fixture-is-not-authority")],
            expires_at_unix_ms,
            subject: digest("subject"),
            effect_scope,
            effect_scope_digest,
            governed_repair_checkpoint: None,
            observation: digest("observation"),
            standing_resolution: digest("ag-standing-resolution"),
            admission_decision: AdmissionDecisionWireV1 {
                decision: digest("admission-decision"),
                key: OccurrenceKeyWireV1 {
                    campaign: digest("campaign"),
                    occurrence: "00000000-0000-0000-0000-000000000001".to_owned(),
                },
                observation: digest("observation"),
                proposal: digest("proposal"),
                standing_resolution: digest("ag-standing-resolution"),
                disposition: AdmissionDispositionWireV1::Admitted,
                policy_basis: digest("policy-basis"),
            },
            mandate: digest("mandate"),
            spend: digest("ag-spend"),
        };
        refresh_issuance_identity(&mut issuance);
        let body = serde_jcs::to_vec(&issuance).unwrap();
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let mut signed = SIGNATURE_PREFIX_V2.to_vec();
        signed.extend_from_slice(&body);
        let public_key = b64_encode(key.public_key().as_ref());
        let envelope = SignedIssuanceEnvelopeWireV1 {
            schema: SIGNED_ISSUANCE_SCHEMA_V2.to_owned(),
            body_b64: b64_encode(&body),
            authentication: IssuanceAuthenticationWireV1 {
                issuer_principal: "ag.test".to_owned(),
                signer_key_id: "ag-test-key".to_owned(),
                signer_public_key: public_key.clone(),
                signature: b64_encode(key.sign(&signed).as_ref()),
            },
        };
        let trust = serde_json::to_vec(&AgIssuerTrustConfigV1 {
            issuers: vec![TrustedAgIssuerV1 {
                issuer_principal: "ag.test".to_owned(),
                key_id: "ag-test-key".to_owned(),
                public_key,
            }],
        })
        .unwrap();

        let attempt =
            digest_json_string("ag.governed-loop.docket-attempt/v1", &issuance.issuance).unwrap();
        let custody = DocketCustodyWireV1 {
            schema: CUSTODY_SCHEMA_V1.to_owned(),
            issuance: issuance.issuance.clone(),
            ag_spend: issuance.spend.clone(),
            execution_standing: digest("execution-standing"),
            standing_currentness: digest("execution-standing-currentness"),
            attempt: attempt.clone(),
            executor_marker: hash_domain(
                "docket.governed-loop.executor-marker/v1",
                attempt.as_bytes(),
            ),
            accepted_at_unix_ms: 0,
        };
        let standing = ExecutionStandingResolutionV1 {
            schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
            resolution: digest("execution-standing-resolution"),
            currentness: custody.standing_currentness.clone(),
            execution_standing: custody.execution_standing.clone(),
            issuance: issuance.issuance.clone(),
            campaign: issuance.key.campaign.clone(),
            occurrence: issuance.key.occurrence.clone(),
            subject: issuance.subject.clone(),
            scope: issuance.effect_scope_digest.clone(),
            status: ExecutionStandingStatusV1::Current,
            resolved_at_unix_ms: 0,
            expires_at_unix_ms: MAX_JCS_SAFE_INTEGER,
        };
        let standing_program = root.join("standing-resolver");
        write_static_program(
            &standing_program,
            &serde_json::to_string(&standing).unwrap(),
        );
        let executor_program = root.join("executor");
        std::fs::write(root.join("executor-config"), issuance.work.as_bytes()).unwrap();
        write_executor(
            &executor_program,
            &custody,
            executor_outcome,
            &digest("executor-receipt"),
        );
        Fixture {
            root,
            database,
            trust,
            envelope: canonical_json(&envelope),
            signing_key_pkcs8: document.as_ref().to_vec(),
            issuance,
            custody,
            standing_program,
            executor_program,
        }
    }

    fn canonical_json<T: Serialize>(value: &T) -> Vec<u8> {
        serde_jcs::to_vec(value).unwrap()
    }

    fn refresh_issuance_identity(issuance: &mut AgIssuanceWireV2) {
        issuance.issuance = ag_issuance_identity(issuance).unwrap();
    }

    fn signed_envelope(fixture: &Fixture, issuance: &AgIssuanceWireV2) -> Vec<u8> {
        let body = canonical_json(issuance);
        let key = Ed25519KeyPair::from_pkcs8(&fixture.signing_key_pkcs8).unwrap();
        let mut signed = SIGNATURE_PREFIX_V2.to_vec();
        signed.extend_from_slice(&body);
        canonical_json(&SignedIssuanceEnvelopeWireV1 {
            schema: SIGNED_ISSUANCE_SCHEMA_V2.to_owned(),
            body_b64: b64_encode(&body),
            authentication: IssuanceAuthenticationWireV1 {
                issuer_principal: "ag.test".to_owned(),
                signer_key_id: "ag-test-key".to_owned(),
                signer_public_key: b64_encode(key.public_key().as_ref()),
                signature: b64_encode(key.sign(&signed).as_ref()),
            },
        })
    }

    fn signed_round(
        fixture: &Fixture,
        idempotency_label: &str,
        predecessor: Option<(&str, &str)>,
    ) -> (Vec<u8>, ReconciliationRoundRequestWireV1) {
        let key = Ed25519KeyPair::from_pkcs8(&fixture.signing_key_pkcs8).unwrap();
        let mut request = ReconciliationRoundRequestWireV1 {
            schema: RECONCILIATION_ROUND_REQUEST_SCHEMA_V1.to_owned(),
            request: String::new(),
            round: String::new(),
            issuance: fixture.issuance.issuance.clone(),
            attempt: fixture.custody.attempt.clone(),
            caller_state_digest: digest(&format!("caller-state-{idempotency_label}")),
            predecessor_round: predecessor.map(|value| value.0.to_owned()),
            predecessor_reconciliation: predecessor.map(|value| value.1.to_owned()),
            idempotency: digest(idempotency_label),
        };
        let round_basis = ReconciliationRoundIdentityBasisV1 {
            schema: &request.schema,
            issuance: &request.issuance,
            attempt: &request.attempt,
            caller_state_digest: &request.caller_state_digest,
            predecessor_round: request.predecessor_round.as_deref(),
            predecessor_reconciliation: request.predecessor_reconciliation.as_deref(),
            idempotency: &request.idempotency,
        };
        request.round = hash_domain(
            "ag.governed-loop.reconciliation-round/v1",
            &serde_jcs::to_vec(&round_basis).unwrap(),
        );
        let request_basis = ReconciliationRequestIdentityBasisV1 {
            schema: &request.schema,
            round: &request.round,
            issuance: &request.issuance,
            attempt: &request.attempt,
            caller_state_digest: &request.caller_state_digest,
            predecessor_round: request.predecessor_round.as_deref(),
            predecessor_reconciliation: request.predecessor_reconciliation.as_deref(),
            idempotency: &request.idempotency,
        };
        request.request = hash_domain(
            "ag.governed-loop.reconciliation-round-request/v1",
            &serde_jcs::to_vec(&request_basis).unwrap(),
        );
        let body = canonical_json(&request);
        let mut signed = RECONCILIATION_ROUND_SIGNATURE_PREFIX_V1.to_vec();
        signed.extend_from_slice(&body);
        (
            canonical_json(&SignedReconciliationRoundRequestEnvelopeWireV1 {
                schema: SIGNED_RECONCILIATION_ROUND_REQUEST_SCHEMA_V1.to_owned(),
                body_b64: b64_encode(&body),
                authentication: IssuanceAuthenticationWireV1 {
                    issuer_principal: "ag.test".to_owned(),
                    signer_key_id: "ag-test-key".to_owned(),
                    signer_public_key: b64_encode(key.public_key().as_ref()),
                    signature: b64_encode(key.sign(&signed).as_ref()),
                },
            }),
            request,
        )
    }

    /// Corrupts one immutable round row while restoring the byte-exact
    /// production trigger before any Store reopen.  The exact schema census
    /// is a separate, earlier production gate; these fixtures intentionally
    /// exercise the row decoder that follows it, rather than weakening that
    /// gate and accidentally testing only its (correct) early refusal.
    fn mutate_immutable_round_fixture(connection: &Connection, mutation: impl FnOnce(&Connection)) {
        let trigger_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type='trigger'
                   AND name='governed_reconciliation_round_identity_immutable'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        connection
            .execute_batch("DROP TRIGGER governed_reconciliation_round_identity_immutable;")
            .unwrap();
        mutation(connection);
        connection.execute_batch(&trigger_sql).unwrap();
        let restored_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type='trigger'
                   AND name='governed_reconciliation_round_identity_immutable'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(restored_sql, trigger_sql);
    }

    #[test]
    fn authenticated_rounds_are_single_flight_and_historical_replay_is_exact() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let first_receipt = digest("explicit-round-one");
        write_executor_response(
            &fixture.executor_program,
            &ExecutorOutcomeWireV1 {
                attempt: fixture.custody.attempt.clone(),
                marker: fixture.custody.executor_marker.clone(),
                receipt: first_receipt.clone(),
                outcome: ExecutorOutcomeClassWireV1::Indeterminate,
                effect_journal: vec![],
                immutable_work_checkpoint: None,
                governed_repair: None,
            },
        );
        let (round_one_bytes, round_one) = signed_round(&fixture, "round-one", None);
        let first = reconcile_signed_round_with_checkpoint_verifier(
            &fixture.database,
            &round_one_bytes,
            &fixture.trust,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            None,
        )
        .unwrap();
        let DocketReconciliationRoundStateWireV1::Completed { response, .. } = &first.state else {
            panic!("first explicit round must complete indeterminate")
        };
        let DocketReconciliationWireV1::Indeterminate {
            indeterminate: first_indeterminate,
            ..
        } = response.as_ref()
        else {
            panic!("first explicit round must complete indeterminate")
        };
        assert_eq!(first_indeterminate.evidence, first_receipt);
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("reconciliations")).unwrap(),
            b"x"
        );

        // Exact duplicate delivery returns the completed durable round and
        // never crosses the executor boundary a second time.
        assert_eq!(
            reconcile_signed_round_with_checkpoint_verifier(
                &fixture.database,
                &round_one_bytes,
                &fixture.trust,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
                None,
            )
            .unwrap(),
            first
        );
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("reconciliations")).unwrap(),
            b"x"
        );

        let second_receipt = digest("explicit-round-two");
        write_executor_response(
            &fixture.executor_program,
            &ExecutorOutcomeWireV1 {
                attempt: fixture.custody.attempt.clone(),
                marker: fixture.custody.executor_marker.clone(),
                receipt: second_receipt,
                outcome: ExecutorOutcomeClassWireV1::Success,
                effect_journal: vec![],
                immutable_work_checkpoint: None,
                governed_repair: None,
            },
        );
        let (round_two_bytes, _) = signed_round(
            &fixture,
            "round-two",
            Some((&round_one.round, &first_indeterminate.reconciliation)),
        );
        let second = reconcile_signed_round_with_checkpoint_verifier(
            &fixture.database,
            &round_two_bytes,
            &fixture.trust,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            None,
        )
        .unwrap();
        let DocketReconciliationRoundStateWireV1::Completed { response, .. } = &second.state else {
            panic!("second explicit round must complete")
        };
        assert!(matches!(
            response.as_ref(),
            DocketReconciliationWireV1::Settled { .. }
        ));
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("reconciliations")).unwrap(),
            b"xx"
        );

        // Later global terminal state cannot rewrite the exact response of an
        // earlier round.
        let historical = reconcile_signed_round_with_checkpoint_verifier(
            &fixture.database,
            &round_one_bytes,
            &fixture.trust,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            None,
        )
        .unwrap();
        assert_eq!(historical, first);
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("reconciliations")).unwrap(),
            b"xx"
        );
    }

    #[test]
    fn first_round_observes_preexisting_terminal_result_without_executor_reinvocation() {
        for outcome in [
            ExecutorOutcomeClassWireV1::Success,
            ExecutorOutcomeClassWireV1::ScopeExpansionRequired,
        ] {
            let fixture = fixture(outcome);
            if outcome == ExecutorOutcomeClassWireV1::ScopeExpansionRequired {
                write_scope_expansion_executor(&fixture.executor_program, &fixture.custody);
            }
            let initial = accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap();
            assert!(matches!(
                (&outcome, &initial),
                (
                    ExecutorOutcomeClassWireV1::Success,
                    DocketExecutionResponseWireV1::Custody(_)
                ) | (
                    ExecutorOutcomeClassWireV1::ScopeExpansionRequired,
                    DocketExecutionResponseWireV1::GovernedRepairRequired { .. }
                )
            ));

            let (envelope, _request) = signed_round(&fixture, "terminal-observation", None);
            let observed = reconcile_signed_round_with_checkpoint_verifier(
                &fixture.database,
                &envelope,
                &fixture.trust,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
                None,
            )
            .unwrap();
            let DocketReconciliationRoundStateWireV1::Completed { response, .. } = &observed.state
            else {
                panic!("terminal observation must complete locally")
            };
            assert!(matches!(
                (&outcome, response.as_ref()),
                (
                    ExecutorOutcomeClassWireV1::Success,
                    DocketReconciliationWireV1::Settled { .. }
                ) | (
                    ExecutorOutcomeClassWireV1::ScopeExpansionRequired,
                    DocketReconciliationWireV1::GovernedRepairRequired { .. }
                )
            ));
            assert_eq!(
                std::fs::read(fixture.executor_program.with_extension("reconciliations"))
                    .unwrap_or_default(),
                b"",
                "local terminal observation must not invoke executor reconciliation"
            );
            assert_eq!(
                reconcile_signed_round_with_checkpoint_verifier(
                    &fixture.database,
                    &envelope,
                    &fixture.trust,
                    &fixture.executor_program,
                    &fixture.root.join("executor-config"),
                    None,
                )
                .unwrap(),
                observed
            );
            let (later, _) = signed_round(&fixture, "second-terminal-observation", None);
            assert_eq!(
                reconcile_signed_round_with_checkpoint_verifier(
                    &fixture.database,
                    &later,
                    &fixture.trust,
                    &fixture.executor_program,
                    &fixture.root.join("executor-config"),
                    None,
                )
                .unwrap_err(),
                "governed-reconciliation-new-round-after-terminal"
            );
        }
    }

    #[test]
    fn claimed_round_resolves_from_concurrent_initial_indeterminate_without_reinvocation() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        let initial_entry = EffectJournalEntryWireV1 {
            resource: "repository".to_owned(),
            path: "crates/nq-store/src/lib.rs".to_owned(),
            operation: CanonicalEffectOperationWireV1::Modify,
            effect_identity: digest("mixed-initial-effect"),
        };
        let initial_receipt = digest("mixed-initial-indeterminate");
        write_blocking_mixed_executor(
            &fixture.executor_program,
            &ExecutorOutcomeWireV1 {
                attempt: fixture.custody.attempt.clone(),
                marker: fixture.custody.executor_marker.clone(),
                receipt: initial_receipt.clone(),
                outcome: ExecutorOutcomeClassWireV1::Indeterminate,
                effect_journal: vec![initial_entry.clone()],
                immutable_work_checkpoint: None,
                governed_repair: None,
            },
            &ExecutorOutcomeWireV1 {
                attempt: fixture.custody.attempt.clone(),
                marker: fixture.custody.executor_marker.clone(),
                receipt: digest("mixed-raced-round-response"),
                outcome: ExecutorOutcomeClassWireV1::Indeterminate,
                effect_journal: vec![initial_entry.clone()],
                immutable_work_checkpoint: None,
                governed_repair: None,
            },
        );
        let database = fixture.database.clone();
        let issuance = fixture.envelope.clone();
        let trust = fixture.trust.clone();
        let standing = fixture.standing_program.clone();
        let executor = fixture.executor_program.clone();
        let config = fixture.root.join("executor-config");
        let initial = std::thread::spawn(move || {
            accept(&database, &issuance, &trust, &standing, &executor, &config)
        });
        wait_for_test_path(&fixture.executor_program.with_extension("execute-started"));

        let (round_bytes, _) = signed_round(&fixture, "mixed-initial-round", None);
        let database = fixture.database.clone();
        let trust = fixture.trust.clone();
        let executor = fixture.executor_program.clone();
        let config = fixture.root.join("executor-config");
        let submitted_round = round_bytes.clone();
        let round = std::thread::spawn(move || {
            reconcile_signed_round_with_checkpoint_verifier(
                &database,
                &submitted_round,
                &trust,
                &executor,
                &config,
                None,
            )
        });
        wait_for_test_path(&fixture.executor_program.with_extension("reconcile-started"));

        std::fs::write(
            fixture.executor_program.with_extension("execute-release"),
            b"release",
        )
        .unwrap();
        assert!(matches!(
            initial.join().unwrap().unwrap(),
            DocketExecutionResponseWireV1::Custody(_)
        ));
        std::fs::write(
            fixture.executor_program.with_extension("reconcile-release"),
            b"release",
        )
        .unwrap();
        let resolved = round.join().unwrap().unwrap();
        let DocketReconciliationRoundStateWireV1::Completed { response, .. } = &resolved.state
        else {
            panic!("monotone initial result must complete the claimed round locally")
        };
        let DocketReconciliationWireV1::Indeterminate { indeterminate, .. } = response.as_ref()
        else {
            panic!("initial indeterminate result must win the mixed-source race")
        };
        assert_eq!(indeterminate.evidence, initial_receipt);
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("execute-calls")).unwrap(),
            b"x"
        );
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("reconcile-calls")).unwrap(),
            b"x"
        );
        assert_eq!(
            reconcile_signed_round_with_checkpoint_verifier(
                &fixture.database,
                &round_bytes,
                &fixture.trust,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
                None,
            )
            .unwrap(),
            resolved
        );
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("reconcile-calls")).unwrap(),
            b"x",
            "completed replay must not invoke reconciliation again"
        );
        let durable = governed_repair::cumulative_effect_journal_with(
            &Connection::open(&fixture.database).unwrap(),
            &fixture.issuance.issuance,
            &fixture.custody.attempt,
            &[],
        )
        .unwrap();
        assert_eq!(durable, vec![initial_entry]);
    }

    #[test]
    fn superseded_round_response_cannot_introduce_a_novel_effect() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let (envelope_bytes, request) = signed_round(&fixture, "superseded-journal", None);
        let (envelope, _) =
            verify_signed_reconciliation_round_request(&envelope_bytes, &fixture.trust).unwrap();
        let mut store = GovernedCustodyStoreV1::open(&fixture.database).unwrap();
        let record = store.get(&fixture.issuance.issuance).unwrap().unwrap();
        let binding = ExecutorBindingV1 {
            identity: record.executor_binding.clone(),
            program_digest: record.executor_program_digest.clone(),
            config_digest: record.executor_config_digest.clone(),
            plan: record.executor_plan.clone(),
        };
        let reservation = match store
            .claim_reconciliation_round(&envelope, &request, &record, &binding, 7)
            .unwrap()
        {
            ReconciliationRoundClaimV1::Winner(value) => *value,
            ReconciliationRoundClaimV1::Existing(_) => panic!("fresh round replayed"),
        };
        let durable_entry = EffectJournalEntryWireV1 {
            resource: "repository".to_owned(),
            path: "crates/nq-store/src/lib.rs".to_owned(),
            operation: CanonicalEffectOperationWireV1::Modify,
            effect_identity: digest("durable-raced-effect"),
        };
        store
            .record_indeterminate_with_journal(
                &fixture.issuance.issuance,
                &fixture.custody,
                &digest("durable-raced-observation"),
                &fixture.issuance.effect_scope,
                std::slice::from_ref(&durable_entry),
                8,
            )
            .unwrap();
        let novel_entry = EffectJournalEntryWireV1 {
            effect_identity: digest("novel-superseded-effect"),
            ..durable_entry
        };
        let error = store
            .complete_reconciliation_round(
                &request,
                &reservation,
                &record,
                ExecutorOutcomeWireV1 {
                    attempt: fixture.custody.attempt.clone(),
                    marker: fixture.custody.executor_marker.clone(),
                    receipt: digest("superseded-response"),
                    outcome: ExecutorOutcomeClassWireV1::Indeterminate,
                    effect_journal: vec![novel_entry],
                    immutable_work_checkpoint: None,
                    governed_repair: None,
                },
                9,
            )
            .unwrap_err();
        assert_eq!(
            error,
            "governed-reconciliation-superseded-effect-not-durable"
        );
        let state: String = Connection::open(&fixture.database)
            .unwrap()
            .query_row(
                "SELECT state FROM governed_reconciliation_round WHERE request=?1",
                [&request.request],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "claimed");
    }

    #[test]
    fn completed_indeterminate_round_may_observe_one_later_initial_terminal_locally() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        write_blocking_mixed_executor(
            &fixture.executor_program,
            &ExecutorOutcomeWireV1 {
                attempt: fixture.custody.attempt.clone(),
                marker: fixture.custody.executor_marker.clone(),
                receipt: digest("mixed-initial-terminal"),
                outcome: ExecutorOutcomeClassWireV1::Success,
                effect_journal: vec![],
                immutable_work_checkpoint: None,
                governed_repair: None,
            },
            &ExecutorOutcomeWireV1 {
                attempt: fixture.custody.attempt.clone(),
                marker: fixture.custody.executor_marker.clone(),
                receipt: digest("mixed-round-indeterminate"),
                outcome: ExecutorOutcomeClassWireV1::Indeterminate,
                effect_journal: vec![],
                immutable_work_checkpoint: None,
                governed_repair: None,
            },
        );
        let database = fixture.database.clone();
        let issuance = fixture.envelope.clone();
        let trust = fixture.trust.clone();
        let standing = fixture.standing_program.clone();
        let executor = fixture.executor_program.clone();
        let config = fixture.root.join("executor-config");
        let initial = std::thread::spawn(move || {
            accept(&database, &issuance, &trust, &standing, &executor, &config)
        });
        wait_for_test_path(&fixture.executor_program.with_extension("execute-started"));

        let (first_bytes, first_request) = signed_round(&fixture, "mixed-first-round", None);
        let database = fixture.database.clone();
        let trust = fixture.trust.clone();
        let executor = fixture.executor_program.clone();
        let config = fixture.root.join("executor-config");
        let submitted = first_bytes.clone();
        let first = std::thread::spawn(move || {
            reconcile_signed_round_with_checkpoint_verifier(
                &database, &submitted, &trust, &executor, &config, None,
            )
        });
        wait_for_test_path(&fixture.executor_program.with_extension("reconcile-started"));
        std::fs::write(
            fixture.executor_program.with_extension("reconcile-release"),
            b"release",
        )
        .unwrap();
        let first = first.join().unwrap().unwrap();
        let DocketReconciliationRoundStateWireV1::Completed { response, .. } = &first.state else {
            panic!("first round must complete indeterminate")
        };
        let DocketReconciliationWireV1::Indeterminate { indeterminate, .. } = response.as_ref()
        else {
            panic!("first round must provide an indeterminate predecessor")
        };

        std::fs::write(
            fixture.executor_program.with_extension("execute-release"),
            b"release",
        )
        .unwrap();
        assert!(matches!(
            initial.join().unwrap().unwrap(),
            DocketExecutionResponseWireV1::Custody(_)
        ));
        let (terminal_bytes, _) = signed_round(
            &fixture,
            "mixed-terminal-observation",
            Some((&first_request.round, &indeterminate.reconciliation)),
        );
        let observed = reconcile_signed_round_with_checkpoint_verifier(
            &fixture.database,
            &terminal_bytes,
            &fixture.trust,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            None,
        )
        .unwrap();
        assert!(matches!(
            observed.state,
            DocketReconciliationRoundStateWireV1::Completed {
                response,
                ..
            } if matches!(response.as_ref(), DocketReconciliationWireV1::Settled { .. })
        ));
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("reconcile-calls")).unwrap(),
            b"x",
            "predecessor-bound terminal observation is local"
        );
        let (illegal, _) = signed_round(&fixture, "mixed-third-round", None);
        assert_eq!(
            reconcile_signed_round_with_checkpoint_verifier(
                &fixture.database,
                &illegal,
                &fixture.trust,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
                None,
            )
            .unwrap_err(),
            "governed-reconciliation-new-round-after-terminal"
        );
    }

    #[test]
    fn reconciliation_round_wire_refuses_null_partial_and_unknown_predecessors() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        let (_, request) = signed_round(&fixture, "round-wire-hostile", None);
        let mut null = serde_json::to_value(&request).unwrap();
        null["predecessor_round"] = serde_json::Value::Null;
        assert!(strict_json::<ReconciliationRoundRequestWireV1>(
            &serde_jcs::to_vec(&null).unwrap(),
            "round-explicit-null"
        )
        .is_err());
        let mut partial = request.clone();
        partial.predecessor_round = Some(digest("predecessor"));
        assert_eq!(
            validate_reconciliation_round_request(&partial).unwrap_err(),
            "governed-reconciliation-round-predecessor-shape"
        );
        let mut unknown = serde_json::to_value(&request).unwrap();
        unknown["ambient_retry"] = serde_json::Value::Bool(true);
        assert!(strict_json::<ReconciliationRoundRequestWireV1>(
            &serde_jcs::to_vec(&unknown).unwrap(),
            "round-unknown-field"
        )
        .is_err());
    }

    #[test]
    fn claimed_round_reopens_unresolved_without_executor_reinvocation() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let (envelope_bytes, request) = signed_round(&fixture, "crashed-round", None);
        let (envelope, _) =
            verify_signed_reconciliation_round_request(&envelope_bytes, &fixture.trust).unwrap();
        let mut store = GovernedCustodyStoreV1::open(&fixture.database).unwrap();
        let record = store.get(&fixture.issuance.issuance).unwrap().unwrap();
        let durable_indeterminate = record
            .indeterminate
            .as_ref()
            .expect("fixture starts indeterminate")
            .clone();
        let binding = ExecutorBindingV1 {
            identity: record.executor_binding.clone(),
            program_digest: record.executor_program_digest.clone(),
            config_digest: record.executor_config_digest.clone(),
            plan: record.executor_plan.clone(),
        };
        let reservation = match store
            .claim_reconciliation_round(&envelope, &request, &record, &binding, 7)
            .unwrap()
        {
            ReconciliationRoundClaimV1::Winner(value) => *value,
            ReconciliationRoundClaimV1::Existing(_) => panic!("fresh claim replayed"),
        };
        drop(store);
        let reopened = reconcile_signed_round_with_checkpoint_verifier(
            &fixture.database,
            &envelope_bytes,
            &fixture.trust,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            None,
        )
        .unwrap();
        assert_eq!(
            reopened.state,
            DocketReconciliationRoundStateWireV1::Unresolved(reservation)
        );
        assert!(!fixture
            .executor_program
            .with_extension("reconciliations")
            .exists());

        // An unresolved claim is not a predecessor permitting another poll.
        let (next, _) = signed_round(&fixture, "illegal-later-round", None);
        let error = reconcile_signed_round_with_checkpoint_verifier(
            &fixture.database,
            &next,
            &fixture.trust,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            None,
        )
        .unwrap_err();
        assert_eq!(
            error,
            "governed-reconciliation-outstanding-round-unresolved"
        );
        assert!(!fixture
            .executor_program
            .with_extension("reconciliations")
            .exists());

        // If the independently running initial attempt later establishes a
        // new exact indeterminate cut, reopen may complete this already
        // claimed round locally. It still must not reacquire the executor.
        let later_evidence = digest("later-durable-initial-observation");
        let mut store = GovernedCustodyStoreV1::open(&fixture.database).unwrap();
        store
            .record_indeterminate_with_journal(
                &fixture.issuance.issuance,
                &fixture.custody,
                &later_evidence,
                &fixture.issuance.effect_scope,
                &[],
                8,
            )
            .unwrap();
        drop(store);
        let resolved = reconcile_signed_round_with_checkpoint_verifier(
            &fixture.database,
            &envelope_bytes,
            &fixture.trust,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            None,
        )
        .unwrap();
        let DocketReconciliationRoundStateWireV1::Completed { response, .. } = resolved.state
        else {
            panic!("durable monotone source advance must resolve the claimed round")
        };
        assert!(matches!(
            response.as_ref(),
            DocketReconciliationWireV1::Indeterminate { indeterminate, .. }
                if indeterminate == &durable_indeterminate
        ));
        assert!(!fixture
            .executor_program
            .with_extension("reconciliations")
            .exists());
    }

    #[test]
    fn executor_response_lost_before_round_completion_remains_unresolved_without_reinvocation() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let response_receipt = digest("response-before-durable-completion");
        write_executor_response(
            &fixture.executor_program,
            &ExecutorOutcomeWireV1 {
                attempt: fixture.custody.attempt.clone(),
                marker: fixture.custody.executor_marker.clone(),
                receipt: response_receipt.clone(),
                outcome: ExecutorOutcomeClassWireV1::Indeterminate,
                effect_journal: vec![],
                immutable_work_checkpoint: None,
                governed_repair: None,
            },
        );
        let (envelope_bytes, request) = signed_round(&fixture, "lost-response-round", None);
        let (envelope, _) =
            verify_signed_reconciliation_round_request(&envelope_bytes, &fixture.trust).unwrap();
        let mut store = GovernedCustodyStoreV1::open(&fixture.database).unwrap();
        let record = store.get(&fixture.issuance.issuance).unwrap().unwrap();
        let binding = ExecutorBindingV1 {
            identity: record.executor_binding.clone(),
            program_digest: record.executor_program_digest.clone(),
            config_digest: record.executor_config_digest.clone(),
            plan: record.executor_plan.clone(),
        };
        let retained = retain_bound_executor(
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            &binding,
        )
        .unwrap();
        let reservation = match store
            .claim_reconciliation_round(&envelope, &request, &record, &binding, 7)
            .unwrap()
        {
            ReconciliationRoundClaimV1::Winner(value) => *value,
            ReconciliationRoundClaimV1::Existing(_) => panic!("fresh claim replayed"),
        };
        let dispatch = executor_reconciliation_dispatch(
            &request,
            &reservation,
            &record.issuance,
            &record.custody,
        );
        let response =
            invoke_retained_json::<_, ExecutorOutcomeWireV1>(&retained, "reconcile", &dispatch)
                .unwrap();
        assert_eq!(response.receipt, response_receipt);
        // Model process loss after the physical response has arrived but before
        // Docket can append the journal or complete the durable round.
        drop(response);
        drop(store);
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("reconciliations")).unwrap(),
            b"x"
        );

        let replay = reconcile_signed_round_with_checkpoint_verifier(
            &fixture.database,
            &envelope_bytes,
            &fixture.trust,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            None,
        )
        .unwrap();
        assert_eq!(
            replay.state,
            DocketReconciliationRoundStateWireV1::Unresolved(reservation)
        );
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("reconciliations")).unwrap(),
            b"x",
            "an ambiguous claimed round is never silently reinvoked"
        );
    }

    #[test]
    fn reconciliation_uses_retained_executor_after_source_path_substitution() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        write_inline_executor(
            &fixture.executor_program,
            &fixture.custody,
            ExecutorOutcomeClassWireV1::Indeterminate,
            &digest("retained-executor-result"),
        );
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let (envelope_bytes, request) = signed_round(&fixture, "retained-executor-round", None);
        let (envelope, _) =
            verify_signed_reconciliation_round_request(&envelope_bytes, &fixture.trust).unwrap();
        let mut store = GovernedCustodyStoreV1::open(&fixture.database).unwrap();
        let record = store.get(&fixture.issuance.issuance).unwrap().unwrap();
        let binding = ExecutorBindingV1 {
            identity: record.executor_binding.clone(),
            program_digest: record.executor_program_digest.clone(),
            config_digest: record.executor_config_digest.clone(),
            plan: record.executor_plan.clone(),
        };
        let retained = retain_bound_executor(
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            &binding,
        )
        .unwrap();

        // The caller-controlled source path changes after exact local byte
        // validation but before the durable claim.  The claim winner must use
        // the retained snapshot, not reopen this path.
        write_refusing_program(&fixture.executor_program);
        let reservation = match store
            .claim_reconciliation_round(&envelope, &request, &record, &binding, 7)
            .unwrap()
        {
            ReconciliationRoundClaimV1::Winner(value) => *value,
            ReconciliationRoundClaimV1::Existing(_) => panic!("fresh claim replayed"),
        };
        let dispatch = executor_reconciliation_dispatch(
            &request,
            &reservation,
            &record.issuance,
            &record.custody,
        );
        let outcome =
            invoke_retained_json::<_, ExecutorOutcomeWireV1>(&retained, "reconcile", &dispatch)
                .unwrap();
        assert_eq!(outcome.receipt, digest("retained-executor-result"));
        store
            .complete_reconciliation_round(&request, &reservation, &record, outcome, 8)
            .unwrap();
        let stored_round = store
            .read_reconciliation_round(&request.request)
            .unwrap()
            .unwrap();
        assert!(matches!(
            store
                .reconciliation_round_response(stored_round)
                .unwrap()
                .state,
            DocketReconciliationRoundStateWireV1::Completed { .. }
        ));
    }

    #[test]
    fn round_issuer_must_equal_the_exact_custodied_issuance_issuer() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let (_, request) = signed_round(&fixture, "issuer-substitution", None);
        let body = canonical_json(&request);
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let mut signed = RECONCILIATION_ROUND_SIGNATURE_PREFIX_V1.to_vec();
        signed.extend_from_slice(&body);
        let second_public_key = b64_encode(key.public_key().as_ref());
        let envelope = canonical_json(&SignedReconciliationRoundRequestEnvelopeWireV1 {
            schema: SIGNED_RECONCILIATION_ROUND_REQUEST_SCHEMA_V1.to_owned(),
            body_b64: b64_encode(&body),
            authentication: IssuanceAuthenticationWireV1 {
                issuer_principal: "ag.other".to_owned(),
                signer_key_id: "ag-other-key".to_owned(),
                signer_public_key: second_public_key.clone(),
                signature: b64_encode(key.sign(&signed).as_ref()),
            },
        });
        let original: AgIssuerTrustConfigV1 = serde_json::from_slice(&fixture.trust).unwrap();
        let mut issuers = original.issuers;
        issuers.push(TrustedAgIssuerV1 {
            issuer_principal: "ag.other".to_owned(),
            key_id: "ag-other-key".to_owned(),
            public_key: second_public_key,
        });
        let trust = canonical_json(&AgIssuerTrustConfigV1 { issuers });
        assert_eq!(
            reconcile_signed_round_with_checkpoint_verifier(
                &fixture.database,
                &envelope,
                &trust,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
                None,
            )
            .unwrap_err(),
            "governed-reconciliation-issuance-issuer-substitution"
        );
        let connection = Connection::open(&fixture.database).unwrap();
        let rounds: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM governed_reconciliation_round",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rounds, 0);
        assert!(!fixture
            .executor_program
            .with_extension("reconciliations")
            .exists());
    }

    #[test]
    fn issuance_observation_is_consequence_free_and_never_reconciles() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        write_refusing_program(&fixture.executor_program);
        assert!(matches!(
            observe_issuance_with_checkpoint_verifier(
                &fixture.database,
                &fixture.issuance.issuance,
                None,
            )
            .unwrap(),
            DocketReconciliationWireV1::Indeterminate { .. }
        ));
        assert!(!fixture
            .executor_program
            .with_extension("reconciliations")
            .exists());
        let connection = Connection::open(&fixture.database).unwrap();
        let rounds: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM governed_reconciliation_round",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rounds, 0);
    }

    #[test]
    fn r3_database_migrates_to_empty_round_ledger_and_partial_migration_refuses() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        let connection = Connection::open(&fixture.database).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER governed_reconciliation_round_no_delete;
                 DROP TRIGGER governed_reconciliation_round_monotone;
                 DROP TRIGGER governed_reconciliation_round_identity_immutable;
                 DROP TABLE governed_reconciliation_round;",
            )
            .unwrap();
        drop(connection);
        drop(SqliteStore::open(&fixture.database).unwrap());
        let connection = Connection::open(&fixture.database).unwrap();
        let objects: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name LIKE 'governed_reconciliation_round%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM governed_reconciliation_round",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((objects, rows), (4, 0));

        connection
            .execute_batch(
                "DROP TRIGGER governed_reconciliation_round_no_delete;
                 DROP TRIGGER governed_reconciliation_round_monotone;
                 DROP TRIGGER governed_reconciliation_round_identity_immutable;
                 DROP TABLE governed_reconciliation_round;
                 CREATE TABLE governed_reconciliation_round(request TEXT PRIMARY KEY) STRICT;",
            )
            .unwrap();
        drop(connection);
        let error = match SqliteStore::open(&fixture.database) {
            Ok(_) => panic!("partial migration unexpectedly reopened"),
            Err(error) => format!("{error:?}"),
        };
        assert!(error.contains("governed reconciliation round schema mismatch"));
    }

    #[test]
    fn public_custody_entries_refuse_weakened_round_schema_before_external_work() {
        let acceptance = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        let connection = Connection::open(&acceptance.database).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER governed_reconciliation_round_no_delete;
                 CREATE TRIGGER governed_reconciliation_round_no_delete
                 BEFORE DELETE ON governed_reconciliation_round
                 BEGIN SELECT 1; END;",
            )
            .unwrap();
        drop(connection);
        let error = accept(
            &acceptance.database,
            &acceptance.envelope,
            &acceptance.trust,
            &acceptance.standing_program,
            &acceptance.executor_program,
            &acceptance.root.join("executor-config"),
        )
        .unwrap_err();
        assert!(error.contains("governed reconciliation round schema mismatch"));
        assert!(!acceptance
            .executor_program
            .with_extension("invocations")
            .exists());
        let attempts: i64 = Connection::open(&acceptance.database)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(attempts, 0);

        let reconciliation = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &reconciliation.database,
            &reconciliation.envelope,
            &reconciliation.trust,
            &reconciliation.standing_program,
            &reconciliation.executor_program,
            &reconciliation.root.join("executor-config"),
        )
        .unwrap();
        let (round_envelope, round) = signed_round(&reconciliation, "schema-gate", None);
        let connection = Connection::open(&reconciliation.database).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER governed_reconciliation_round_no_delete;
                 CREATE TRIGGER governed_reconciliation_round_no_delete
                 BEFORE DELETE ON governed_reconciliation_round
                 BEGIN SELECT 1; END;",
            )
            .unwrap();
        drop(connection);
        let error = reconcile_signed_round_with_checkpoint_verifier(
            &reconciliation.database,
            &round_envelope,
            &reconciliation.trust,
            &reconciliation.executor_program,
            &reconciliation.root.join("executor-config"),
            None,
        )
        .unwrap_err();
        assert!(error.contains("governed reconciliation round schema mismatch"));
        assert!(!reconciliation
            .executor_program
            .with_extension("reconciliations")
            .exists());
        let rounds: i64 = Connection::open(&reconciliation.database)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM governed_reconciliation_round WHERE request=?1",
                [&round.request],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rounds, 0);
    }

    #[test]
    fn reconciliation_round_timestamps_are_sql_and_reopen_safe() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let (envelope_bytes, request) = signed_round(&fixture, "unsafe-time", None);
        let (envelope, _) =
            verify_signed_reconciliation_round_request(&envelope_bytes, &fixture.trust).unwrap();
        let mut store = GovernedCustodyStoreV1::open(&fixture.database).unwrap();
        let record = store.get(&fixture.issuance.issuance).unwrap().unwrap();
        let binding = ExecutorBindingV1 {
            identity: record.executor_binding.clone(),
            program_digest: record.executor_program_digest.clone(),
            config_digest: record.executor_config_digest.clone(),
            plan: record.executor_plan.clone(),
        };
        let unsafe_error = match store.claim_reconciliation_round(
            &envelope,
            &request,
            &record,
            &binding,
            MAX_JCS_SAFE_INTEGER + 1,
        ) {
            Ok(_) => panic!("unsafe timestamp was accepted"),
            Err(error) => error,
        };
        assert!(unsafe_error.contains("clock-outside-jcs-safe-integer-domain"));
        let reservation = match store
            .claim_reconciliation_round(&envelope, &request, &record, &binding, 9)
            .unwrap()
        {
            ReconciliationRoundClaimV1::Winner(value) => *value,
            ReconciliationRoundClaimV1::Existing(_) => panic!("unexpected replay"),
        };
        drop(store);
        let connection = Connection::open(&fixture.database).unwrap();
        mutate_immutable_round_fixture(&connection, |connection| {
            connection
                .pragma_update(None, "ignore_check_constraints", "ON")
                .unwrap();
            connection
                .execute(
                    "UPDATE governed_reconciliation_round SET claimed_at=?1 WHERE reservation=?2",
                    params![(MAX_JCS_SAFE_INTEGER + 1) as i64, reservation.reservation],
                )
                .unwrap();
            connection
                .pragma_update(None, "ignore_check_constraints", "OFF")
                .unwrap();
        });
        drop(connection);
        let reopen_error = match GovernedCustodyStoreV1::open(&fixture.database) {
            Ok(_) => panic!("unsafe timestamp reopened"),
            Err(error) => error,
        };
        assert!(reopen_error.contains("unsafe JSON integer"));
    }

    #[test]
    fn corrupt_round_and_reservation_rows_refuse_on_reopen() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let (envelope_bytes, request) = signed_round(&fixture, "corrupt-round", None);
        let (envelope, _) =
            verify_signed_reconciliation_round_request(&envelope_bytes, &fixture.trust).unwrap();
        let mut store = GovernedCustodyStoreV1::open(&fixture.database).unwrap();
        let record = store.get(&fixture.issuance.issuance).unwrap().unwrap();
        let binding = ExecutorBindingV1 {
            identity: record.executor_binding.clone(),
            program_digest: record.executor_program_digest.clone(),
            config_digest: record.executor_config_digest.clone(),
            plan: record.executor_plan.clone(),
        };
        let reservation = match store
            .claim_reconciliation_round(&envelope, &request, &record, &binding, 7)
            .unwrap()
        {
            ReconciliationRoundClaimV1::Winner(value) => *value,
            ReconciliationRoundClaimV1::Existing(_) => panic!("fresh claim replayed"),
        };
        drop(store);

        let connection = Connection::open(&fixture.database).unwrap();
        mutate_immutable_round_fixture(&connection, |connection| {
            connection
                .execute(
                    "UPDATE governed_reconciliation_round SET reservation=?1 WHERE request=?2",
                    params![digest("substituted-reservation"), request.request],
                )
                .unwrap();
        });
        drop(connection);
        assert_eq!(
            GovernedCustodyStoreV1::open(&fixture.database)
                .err()
                .unwrap(),
            "governed-reconciliation-reservation-substitution"
        );

        let connection = Connection::open(&fixture.database).unwrap();
        mutate_immutable_round_fixture(&connection, |connection| {
            connection
                .execute(
                    "UPDATE governed_reconciliation_round SET reservation=?1,round=?2 WHERE request=?3",
                    params![
                        reservation.reservation,
                        digest("substituted-round"),
                        request.request
                    ],
                )
                .unwrap();
        });
        drop(connection);
        assert_eq!(
            GovernedCustodyStoreV1::open(&fixture.database)
                .err()
                .unwrap(),
            "governed-reconciliation-round-stored-substitution"
        );
    }

    #[test]
    fn stored_round_reopen_joins_exact_issuance_issuer_and_source_cut_bytes() {
        fn claim_one(fixture: &Fixture, label: &str) -> ReconciliationRoundRequestWireV1 {
            accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap();
            let (envelope_bytes, request) = signed_round(fixture, label, None);
            let (envelope, _) =
                verify_signed_reconciliation_round_request(&envelope_bytes, &fixture.trust)
                    .unwrap();
            let mut store = GovernedCustodyStoreV1::open(&fixture.database).unwrap();
            let record = store.get(&fixture.issuance.issuance).unwrap().unwrap();
            let binding = ExecutorBindingV1 {
                identity: record.executor_binding.clone(),
                program_digest: record.executor_program_digest.clone(),
                config_digest: record.executor_config_digest.clone(),
                plan: record.executor_plan.clone(),
            };
            assert!(matches!(
                store
                    .claim_reconciliation_round(&envelope, &request, &record, &binding, 7)
                    .unwrap(),
                ReconciliationRoundClaimV1::Winner(_)
            ));
            request
        }

        let issuer_fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        let issuer_request = claim_one(&issuer_fixture, "corrupt-stored-issuer");
        let connection = Connection::open(&issuer_fixture.database).unwrap();
        mutate_immutable_round_fixture(&connection, |connection| {
            connection
                .execute(
                    "UPDATE governed_reconciliation_round SET issuer_principal='ag.substituted'
                     WHERE request=?1",
                    [&issuer_request.request],
                )
                .unwrap();
        });
        drop(connection);
        assert_eq!(
            GovernedCustodyStoreV1::open(&issuer_fixture.database)
                .err()
                .unwrap(),
            "governed-reconciliation-issuance-issuer-substitution"
        );

        let source_fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        let source_request = claim_one(&source_fixture, "corrupt-stored-source-cut");
        let connection = Connection::open(&source_fixture.database).unwrap();
        let source_bytes: Vec<u8> = connection
            .query_row(
                "SELECT source_cut_jcs FROM governed_reconciliation_round WHERE request=?1",
                [&source_request.request],
                |row| row.get(0),
            )
            .unwrap();
        let mut source: serde_json::Value = serde_json::from_slice(&source_bytes).unwrap();
        source["issuance"] = serde_json::Value::String(digest("substituted-source-issuance"));
        let substituted = serde_jcs::to_vec(&source).unwrap();
        mutate_immutable_round_fixture(&connection, |connection| {
            connection
                .execute(
                    "UPDATE governed_reconciliation_round SET source_cut_jcs=?1 WHERE request=?2",
                    params![substituted, source_request.request],
                )
                .unwrap();
        });
        drop(connection);
        assert_eq!(
            GovernedCustodyStoreV1::open(&source_fixture.database)
                .err()
                .unwrap(),
            "governed-reconciliation-source-cut-substitution"
        );
    }

    #[test]
    fn round_completion_journal_and_settlement_are_one_atomic_cut() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        write_executor_response(
            &fixture.executor_program,
            &ExecutorOutcomeWireV1 {
                attempt: fixture.custody.attempt.clone(),
                marker: fixture.custody.executor_marker.clone(),
                receipt: digest("atomic-terminal"),
                outcome: ExecutorOutcomeClassWireV1::Success,
                effect_journal: vec![],
                immutable_work_checkpoint: None,
                governed_repair: None,
            },
        );
        let (envelope, request) = signed_round(&fixture, "atomic-round", None);
        ABORT_ROUND_COMPLETION_BEFORE_ROUND_ROW.with(|failpoint| failpoint.set(true));
        let error = reconcile_signed_round_with_checkpoint_verifier(
            &fixture.database,
            &envelope,
            &fixture.trust,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            None,
        )
        .unwrap_err();
        assert!(error.contains("injected round completion failure"));
        let connection = Connection::open(&fixture.database).unwrap();
        let (status, round_state, observations): (String, String, i64) = connection
            .query_row(
                "SELECT a.status,r.state,
                        (SELECT COUNT(*) FROM governed_executor_result e
                         WHERE e.issuance=a.issuance)
                 FROM governed_loop_attempt a
                 JOIN governed_reconciliation_round r ON r.issuance=a.issuance
                 WHERE r.request=?1",
                [&request.request],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (status.as_str(), round_state.as_str(), observations),
            ("indeterminate", "claimed", 1)
        );
        drop(connection);
        let replay = reconcile_signed_round_with_checkpoint_verifier(
            &fixture.database,
            &envelope,
            &fixture.trust,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            None,
        )
        .unwrap();
        assert!(matches!(
            replay.state,
            DocketReconciliationRoundStateWireV1::Unresolved(_)
        ));
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("reconciliations")).unwrap(),
            b"x",
            "claimed-round replay must not invoke external reconciliation again"
        );
    }

    #[test]
    fn authenticated_issuance_consumes_one_distinct_standing_and_settles_once() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let first = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let DocketExecutionResponseWireV1::Custody(first_custody) = &first else {
            panic!("ordinary success must return custody")
        };
        assert_eq!(first_custody.attempt, fixture.custody.attempt);
        assert_ne!(first_custody.ag_spend, first_custody.execution_standing);
        assert_ne!(
            first_custody.execution_standing,
            first_custody.executor_marker
        );

        // An identical delivery is custody replay, not another executor call.
        write_refusing_program(&fixture.executor_program);
        let duplicate = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert_eq!(duplicate, first);
        let result = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(result, DocketReconciliationWireV1::Settled { .. }));

        let connection = Connection::open(&fixture.database).unwrap();
        let attempts: i64 = connection
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        let standing_uses: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM governed_execution_standing_use",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((attempts, standing_uses), (1, 1));
    }

    #[test]
    fn pre_refusal_schema_custody_reopen_backfills_shared_disposition_guard() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let first = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(first, DocketExecutionResponseWireV1::Custody(_)));

        // Recreate the durable shape as it existed after migration 0008: the
        // exact custody row survives, while the 0009 refusal/disposition
        // tables and triggers do not yet exist.
        let connection = Connection::open(&fixture.database).unwrap();
        connection
            .execute_batch(
                "DROP TABLE governed_loop_issuance_refusal;
                 DROP TABLE governed_loop_issuance_disposition;",
            )
            .unwrap();
        drop(connection);

        // Ordinary store reopen applies 0009 and derives only the disposition
        // membrane from the already durable attempt identity. It mints no new
        // custody, standing use, attempt, or refusal.
        drop(SqliteStore::open(&fixture.database).unwrap());
        drop(SqliteStore::open(&fixture.database).unwrap());
        let connection = Connection::open(&fixture.database).unwrap();
        let disposition: (String, String) = connection
            .query_row(
                "SELECT disposition,artifact FROM governed_loop_issuance_disposition
                 WHERE issuance=?1",
                params![fixture.issuance.issuance],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let counts: (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM governed_loop_attempt),
                   (SELECT COUNT(*) FROM governed_execution_standing_use),
                   (SELECT COUNT(*) FROM governed_loop_issuance_disposition),
                   (SELECT COUNT(*) FROM governed_loop_issuance_refusal)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            disposition,
            ("custody".to_owned(), fixture.custody.attempt.clone())
        );
        assert_eq!(counts, (1, 1, 1, 0));
        drop(connection);

        write_refusing_program(&fixture.executor_program);
        assert_eq!(
            accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap(),
            first
        );
    }

    #[test]
    fn pre_r2_executor_rows_reopen_with_deterministic_cumulative_journal() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let connection = Connection::open(&fixture.database).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER governed_executor_result_immutable_update;
                 DROP TRIGGER governed_executor_result_cumulative_required_insert;
                 ALTER TABLE governed_repair_checkpoint
                   RENAME COLUMN no_unauthorized_effect_reported
                   TO unauthorized_effect_not_performed;
                 ALTER TABLE governed_repair_checkpoint
                   RENAME COLUMN reported_authorized_effects_occurred
                   TO authorized_effects_occurred;
                 ALTER TABLE governed_executor_result
                   DROP COLUMN cumulative_effect_journal_digest;
                 ALTER TABLE governed_executor_result
                   DROP COLUMN cumulative_effect_journal_entries;",
            )
            .unwrap();
        drop(connection);
        drop(SqliteStore::open(&fixture.database).unwrap());
        let connection = Connection::open(&fixture.database).unwrap();
        let migrated: (String, String) = connection
            .query_row(
                "SELECT cumulative_effect_journal_digest,
                        cumulative_effect_journal_entries
                 FROM governed_executor_result",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(!migrated.0.is_empty());
        assert_eq!(migrated.1, "");
        let narrowed_column: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('governed_repair_checkpoint')
                 WHERE name='no_unauthorized_effect_reported'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(narrowed_column, 1);
    }

    #[test]
    fn rejected_r1_settlement_is_preserved_and_reprojected_with_cumulative_journal() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let connection = Connection::open(&fixture.database).unwrap();
        let (receipt, outcome): (String, String) = connection
            .query_row(
                "SELECT receipt,outcome FROM governed_loop_attempt",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let legacy = hash_domain(
            "docket.governed-loop.settlement/v1",
            format!(
                "{}:{}:{}:{}",
                fixture.issuance.issuance, fixture.custody.attempt, receipt, outcome
            )
            .as_bytes(),
        );
        connection
            .execute_batch(
                "DROP TRIGGER governed_loop_settlement_immutable_update;
                 DROP TRIGGER governed_loop_settlement_journal_required_insert;
                 DROP TRIGGER governed_loop_settlement_journal_required_update;
                 DROP TRIGGER governed_executor_result_immutable_update;
                 DROP TRIGGER governed_executor_result_cumulative_required_insert;
                 ALTER TABLE governed_repair_checkpoint
                   RENAME COLUMN no_unauthorized_effect_reported
                   TO unauthorized_effect_not_performed;
                 ALTER TABLE governed_repair_checkpoint
                   RENAME COLUMN reported_authorized_effects_occurred
                   TO authorized_effects_occurred;",
            )
            .unwrap();
        connection
            .execute("UPDATE governed_loop_attempt SET settlement=?1", [&legacy])
            .unwrap();
        connection
            .execute_batch(
                "ALTER TABLE governed_loop_attempt
                   DROP COLUMN settlement_cumulative_effect_journal_identity;
                 ALTER TABLE governed_loop_attempt
                   DROP COLUMN legacy_r1_settlement_identity;
                 ALTER TABLE governed_loop_attempt
                   DROP COLUMN legacy_r1_settlement_jcs;",
            )
            .unwrap();
        connection
            .execute_batch(
                "ALTER TABLE governed_executor_result
                   DROP COLUMN cumulative_effect_journal_digest;
                 ALTER TABLE governed_executor_result
                   DROP COLUMN cumulative_effect_journal_entries;",
            )
            .unwrap();
        drop(connection);

        drop(SqliteStore::open(&fixture.database).unwrap());
        let connection = Connection::open(&fixture.database).unwrap();
        let (active, journal, retained_identity, retained_jcs): (String, String, String, String) =
            connection
                .query_row(
                    "SELECT settlement,settlement_cumulative_effect_journal_identity,
                            legacy_r1_settlement_identity,legacy_r1_settlement_jcs
                     FROM governed_loop_attempt",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
        assert_ne!(active, legacy);
        assert_eq!(retained_identity, legacy);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&retained_jcs).unwrap()["settlement"],
            legacy
        );
        assert_eq!(
            journal,
            governed_repair::latest_cumulative_effect_journal_identity(
                &connection,
                &fixture.issuance.issuance,
                &fixture.custody.attempt,
                &fixture.issuance.effect_scope,
            )
            .unwrap()
            .unwrap()
        );
    }

    #[test]
    fn rejected_r1_settlement_backfill_refuses_false_legacy_identity_atomically() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let false_legacy = digest("false-r1-settlement");
        let connection = Connection::open(&fixture.database).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER governed_loop_settlement_immutable_update;
                 DROP TRIGGER governed_loop_settlement_journal_required_insert;
                 DROP TRIGGER governed_loop_settlement_journal_required_update;",
            )
            .unwrap();
        connection
            .execute(
                "UPDATE governed_loop_attempt SET settlement=?1",
                [&false_legacy],
            )
            .unwrap();
        connection
            .execute_batch(
                "ALTER TABLE governed_loop_attempt
                   DROP COLUMN settlement_cumulative_effect_journal_identity;
                 ALTER TABLE governed_loop_attempt
                   DROP COLUMN legacy_r1_settlement_identity;
                 ALTER TABLE governed_loop_attempt
                   DROP COLUMN legacy_r1_settlement_jcs;",
            )
            .unwrap();
        drop(connection);

        let error = match SqliteStore::open(&fixture.database) {
            Ok(_) => panic!("false rejected-R1 settlement unexpectedly migrated"),
            Err(error) => format!("{error:?}"),
        };
        assert!(error.contains("governed-settlement-migration-legacy-identity"));
        let connection = Connection::open(&fixture.database).unwrap();
        let columns: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('governed_loop_attempt')
                 WHERE name='settlement_cumulative_effect_journal_identity'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let retained: String = connection
            .query_row("SELECT settlement FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(columns, 0);
        assert_eq!(retained, false_legacy);
    }

    #[test]
    fn failed_r2_backfill_rolls_back_and_clean_retry_succeeds() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let connection = Connection::open(&fixture.database).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER governed_executor_result_immutable_update;
                 DROP TRIGGER governed_executor_result_cumulative_required_insert;
                 UPDATE governed_executor_result SET effect_journal_entries='not-an-encoding';
                 ALTER TABLE governed_repair_checkpoint
                   RENAME COLUMN no_unauthorized_effect_reported
                   TO unauthorized_effect_not_performed;
                 ALTER TABLE governed_repair_checkpoint
                   RENAME COLUMN reported_authorized_effects_occurred
                   TO authorized_effects_occurred;
                 ALTER TABLE governed_executor_result
                   DROP COLUMN cumulative_effect_journal_digest;
                 ALTER TABLE governed_executor_result
                   DROP COLUMN cumulative_effect_journal_entries;",
            )
            .unwrap();
        drop(connection);
        assert!(SqliteStore::open(&fixture.database).is_err());
        let connection = Connection::open(&fixture.database).unwrap();
        let schema: (i64, i64) = connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM pragma_table_info('governed_executor_result')
                    WHERE name='cumulative_effect_journal_digest'),
                   (SELECT COUNT(*) FROM pragma_table_info('governed_repair_checkpoint')
                    WHERE name='unauthorized_effect_not_performed')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(schema, (0, 1));
        connection
            .execute_batch(
                "DROP TRIGGER governed_executor_result_immutable_update;
                 UPDATE governed_executor_result SET effect_journal_entries='';",
            )
            .unwrap();
        drop(connection);
        drop(SqliteStore::open(&fixture.database).unwrap());
        let connection = Connection::open(&fixture.database).unwrap();
        let migrated: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('governed_executor_result')
                 WHERE name='cumulative_effect_journal_digest'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migrated, 1);
    }

    #[test]
    fn r2_migration_refuses_pre_r2_terminal_that_omits_prior_reported_effects() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        let prior = EffectJournalEntryWireV1 {
            resource: "repository".to_owned(),
            path: "crates/nq-store/src/lib.rs".to_owned(),
            operation: CanonicalEffectOperationWireV1::Modify,
            effect_identity: digest("pre-r2-prior-effect"),
        };
        let mut first: ExecutorOutcomeWireV1 = serde_json::from_slice(
            &std::fs::read(fixture.executor_program.with_extension("response")).unwrap(),
        )
        .unwrap();
        first.effect_journal = vec![prior];
        write_executor_response(&fixture.executor_program, &first);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        write_scope_expansion_executor(&fixture.executor_program, &fixture.custody);
        assert!(matches!(
            reconcile(
                &fixture.database,
                &fixture.issuance.issuance,
                Some(&fixture.custody.attempt),
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap(),
            DocketReconciliationWireV1::GovernedRepairRequired { .. }
        ));

        let connection = Connection::open(&fixture.database).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER governed_executor_result_immutable_update;
                 DROP TRIGGER governed_executor_result_cumulative_required_insert;
                 DROP TRIGGER governed_repair_checkpoint_immutable_update;
                 ALTER TABLE governed_repair_checkpoint
                   RENAME COLUMN no_unauthorized_effect_reported
                   TO unauthorized_effect_not_performed;
                 ALTER TABLE governed_repair_checkpoint
                   RENAME COLUMN reported_authorized_effects_occurred
                   TO authorized_effects_occurred;
                 ALTER TABLE governed_executor_result
                   DROP COLUMN cumulative_effect_journal_digest;
                 ALTER TABLE governed_executor_result
                   DROP COLUMN cumulative_effect_journal_entries;",
            )
            .unwrap();
        let empty_digest = effect_journal_identity(&fixture.issuance.effect_scope, &[]).unwrap();
        connection
            .execute(
                "UPDATE governed_repair_checkpoint
                 SET effect_journal_entries='',effect_journal_digest=?1",
                [&empty_digest],
            )
            .unwrap();
        drop(connection);

        let error = match SqliteStore::open(&fixture.database) {
            Ok(_) => panic!("incomplete historical terminal unexpectedly migrated"),
            Err(error) => format!("{error:?}"),
        };
        assert!(error.contains("governed-cumulative-migration-terminal-journal-incomplete"));
        let connection = Connection::open(&fixture.database).unwrap();
        let rolled_back: (i64, i64) = connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM pragma_table_info('governed_executor_result')
                    WHERE name='cumulative_effect_journal_digest'),
                   (SELECT COUNT(*) FROM pragma_table_info('governed_repair_checkpoint')
                    WHERE name='authorized_effects_occurred')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(rolled_back, (0, 1));
    }

    #[test]
    fn r2_migration_preserves_pre_r2_terminal_that_already_contains_prior_effects() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        let prior = EffectJournalEntryWireV1 {
            resource: "repository".to_owned(),
            path: "crates/nq-store/src/lib.rs".to_owned(),
            operation: CanonicalEffectOperationWireV1::Modify,
            effect_identity: digest("pre-r2-complete-prior-effect"),
        };
        let mut first: ExecutorOutcomeWireV1 = serde_json::from_slice(
            &std::fs::read(fixture.executor_program.with_extension("response")).unwrap(),
        )
        .unwrap();
        first.effect_journal = vec![prior];
        write_executor_response(&fixture.executor_program, &first);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        write_scope_expansion_executor(&fixture.executor_program, &fixture.custody);
        assert!(matches!(
            reconcile(
                &fixture.database,
                &fixture.issuance.issuance,
                Some(&fixture.custody.attempt),
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap(),
            DocketReconciliationWireV1::GovernedRepairRequired { .. }
        ));
        let connection = Connection::open(&fixture.database).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER governed_executor_result_immutable_update;
                 DROP TRIGGER governed_executor_result_cumulative_required_insert;
                 ALTER TABLE governed_repair_checkpoint
                   RENAME COLUMN no_unauthorized_effect_reported
                   TO unauthorized_effect_not_performed;
                 ALTER TABLE governed_repair_checkpoint
                   RENAME COLUMN reported_authorized_effects_occurred
                   TO authorized_effects_occurred;
                 ALTER TABLE governed_executor_result
                   DROP COLUMN cumulative_effect_journal_digest;
                 ALTER TABLE governed_executor_result
                   DROP COLUMN cumulative_effect_journal_entries;",
            )
            .unwrap();
        drop(connection);

        drop(SqliteStore::open(&fixture.database).unwrap());
        let reopened = GovernedCustodyStoreV1::open(&fixture.database).unwrap();
        let reported: i64 = reopened
            .connection
            .query_row(
                "SELECT reported_authorized_effects_occurred
                 FROM governed_repair_checkpoint",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reported, 1);
        assert!(governed_repair::read_sealed_result(
            &reopened.connection,
            &fixture.issuance.issuance
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn fresh_custody_requires_closed_nonclaims_and_unexpired_issuance() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        assert!(validate_issuance(&fixture.issuance).is_ok());
        assert!(validate_fresh_issuance(&fixture.issuance, 0).is_ok());
        assert_eq!(
            validate_fresh_issuance(&fixture.issuance, fixture.issuance.expires_at_unix_ms,)
                .unwrap_err(),
            "governed-issuance-expired"
        );

        let mut missing = fixture.issuance.clone();
        missing.nonclaims.clear();
        assert_eq!(
            validate_issuance(&missing).unwrap_err(),
            "governed-issuance-constraints"
        );
        let mut duplicated = fixture.issuance.clone();
        duplicated.nonclaims.push(duplicated.nonclaims[0].clone());
        assert_eq!(
            validate_issuance(&duplicated).unwrap_err(),
            "governed-issuance-nonclaims-not-canonical"
        );

        let mut maximum = fixture.issuance.clone();
        maximum.expires_at_unix_ms = MAX_JCS_SAFE_INTEGER;
        refresh_issuance_identity(&mut maximum);
        assert!(validate_issuance(&maximum).is_ok());
        maximum.expires_at_unix_ms = MAX_JCS_SAFE_INTEGER + 1;
        assert_eq!(
            validate_issuance(&maximum).unwrap_err(),
            "governed-issuance-constraints"
        );
    }

    #[test]
    fn outer_signed_envelope_requires_exact_canonical_bytes() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        assert!(verify_signed_issuance(&fixture.envelope, &fixture.trust).is_ok());
        let value: serde_json::Value = serde_json::from_slice(&fixture.envelope).unwrap();
        let altered_spelling = serde_json::to_vec_pretty(&value).unwrap();
        assert_ne!(altered_spelling, fixture.envelope);
        assert_eq!(
            verify_signed_issuance(&altered_spelling, &fixture.trust).unwrap_err(),
            "governed-issuance-envelope-not-canonical"
        );
    }

    #[test]
    fn authenticated_semantically_invalid_issuance_is_sealed_but_unkeyable_input_is_not() {
        let first = fixture(ExecutorOutcomeClassWireV1::Success);
        let mut invalid = first.issuance.clone();
        invalid.admission_decision.disposition = AdmissionDispositionWireV1::Refused;
        refresh_issuance_identity(&mut invalid);
        let envelope = signed_envelope(&first, &invalid);
        assert_eq!(
            verify_signed_issuance(&envelope, &first.trust).unwrap_err(),
            "governed-admission-decision-binding"
        );
        let response = accept(
            &first.database,
            &envelope,
            &first.trust,
            &first.standing_program,
            &first.executor_program,
            &first.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(
            response,
            DocketExecutionResponseWireV1::Refused(DocketIssuanceRefusalWireV1 {
                refusal_class: DocketIssuanceRefusalClassWireV1::IssuanceInvalid,
                ..
            })
        ));

        let second = fixture(ExecutorOutcomeClassWireV1::Success);
        let mut unkeyable = second.issuance.clone();
        unkeyable.issuance = "caller-selected-not-a-digest".to_owned();
        let envelope = signed_envelope(&second, &unkeyable);
        assert_eq!(
            accept(
                &second.database,
                &envelope,
                &second.trust,
                &second.standing_program,
                &second.executor_program,
                &second.root.join("executor-config"),
            )
            .unwrap_err(),
            "governed-refusable issuance-digest"
        );
        let connection = Connection::open(&second.database).unwrap();
        let refusals: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM governed_loop_issuance_refusal",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(refusals, 0);
    }

    #[test]
    fn expired_signed_issuance_refuses_before_custody_standing_or_executor() {
        let fixture = fixture_with_expiry(ExecutorOutcomeClassWireV1::Success, 1);
        write_refusing_program(&fixture.standing_program);
        write_refusing_program(&fixture.executor_program);
        let response = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let DocketExecutionResponseWireV1::Refused(refusal) = &response else {
            panic!("expired issuance must return a sealed refusal")
        };
        assert_eq!(
            refusal.refusal_class,
            DocketIssuanceRefusalClassWireV1::IssuanceExpired
        );
        assert_eq!(refusal.reason_code, "governed-issuance-expired");
        assert_eq!(refusal_identity(refusal).unwrap(), refusal.refusal);
        assert_eq!(
            accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap(),
            response
        );
        assert_eq!(
            reconcile(
                &fixture.database,
                &fixture.issuance.issuance,
                None,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap(),
            DocketReconciliationWireV1::Refused(refusal.clone())
        );
        let connection = Connection::open(&fixture.database).unwrap();
        let attempts: i64 = connection
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        let standing_uses: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM governed_execution_standing_use",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let refusals: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM governed_loop_issuance_refusal",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((attempts, standing_uses, refusals), (0, 0, 1));
        assert!(!fixture
            .executor_program
            .with_extension("invocations")
            .exists());
    }

    #[test]
    fn invalid_standing_is_sealed_and_exact_replay_does_not_reinvoke_resolver() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let invalid = ExecutionStandingResolutionV1 {
            schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
            resolution: digest("invalid-standing-resolution"),
            currentness: digest("invalid-standing-currentness"),
            execution_standing: digest("invalid-execution-standing"),
            issuance: fixture.issuance.issuance.clone(),
            campaign: fixture.issuance.key.campaign.clone(),
            occurrence: fixture.issuance.key.occurrence.clone(),
            subject: fixture.issuance.subject.clone(),
            scope: digest("wrong-scope"),
            status: ExecutionStandingStatusV1::Current,
            resolved_at_unix_ms: 0,
            expires_at_unix_ms: MAX_JCS_SAFE_INTEGER,
        };
        write_static_program(
            &fixture.standing_program,
            &serde_json::to_string(&invalid).unwrap(),
        );
        let first = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(
            first,
            DocketExecutionResponseWireV1::Refused(DocketIssuanceRefusalWireV1 {
                refusal_class: DocketIssuanceRefusalClassWireV1::StandingInvalid,
                ..
            })
        ));
        write_refusing_program(&fixture.standing_program);
        assert_eq!(
            accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap(),
            first
        );
        assert!(!fixture
            .executor_program
            .with_extension("invocations")
            .exists());
    }

    #[test]
    fn standing_transport_or_process_failure_remains_retryable_and_unrecorded() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        write_refusing_program(&fixture.standing_program);
        let error = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap_err();
        assert!(
            error.starts_with("process-refused:") || error.starts_with("process-stdin:"),
            "{error}"
        );
        let connection = Connection::open(&fixture.database).unwrap();
        let refusals: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM governed_loop_issuance_refusal",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(refusals, 0);
    }

    #[test]
    fn semantic_checkpoint_failure_is_a_sealed_pre_custody_refusal() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let mut issuance = fixture.issuance.clone();
        issuance.governed_repair_checkpoint = Some(GovernedRepairCheckpointEvidenceWireV1 {
            repository: digest("checkpoint-repository"),
            commit: "1".repeat(40),
            tree: "2".repeat(40),
            diff_identity: None,
            content_manifest: digest("checkpoint-manifest"),
            docket_checkpoint: None,
        });
        refresh_issuance_identity(&mut issuance);
        let envelope = signed_envelope(&fixture, &issuance);
        let verifier = fixture.root.join("checkpoint-verifier");
        let result = CheckpointVerificationResultWireV1 {
            schema: "docket.governed-repair.checkpoint-verification/v1".to_owned(),
            verification: digest("checkpoint-verification"),
            issuance: issuance.issuance.clone(),
            checkpoint: issuance.governed_repair_checkpoint.clone().unwrap(),
            status: CheckpointVerificationStatusWireV1::Mismatch,
            verified_at_unix_ms: 0,
            expires_at_unix_ms: MAX_JCS_SAFE_INTEGER,
        };
        write_static_program(&verifier, &serde_json::to_string(&result).unwrap());
        let response = accept_with_checkpoint_verifier(
            &fixture.database,
            &envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            Some(&verifier),
        )
        .unwrap();
        assert!(matches!(
            response,
            DocketExecutionResponseWireV1::Refused(DocketIssuanceRefusalWireV1 {
                refusal_class: DocketIssuanceRefusalClassWireV1::CheckpointInvalid,
                ..
            })
        ));
    }

    #[test]
    fn altered_durable_refusal_bytes_fail_closed_on_replay() {
        let fixture = fixture_with_expiry(ExecutorOutcomeClassWireV1::Success, 1);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let connection = Connection::open(&fixture.database).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER governed_loop_issuance_refusal_no_update;
                 UPDATE governed_loop_issuance_refusal
                 SET evidence='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';",
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap_err(),
            "governed-stored-refusal-identity"
        );
    }

    #[test]
    fn concurrent_identical_pre_custody_refusal_has_one_durable_winner() {
        let fixture = fixture_with_expiry(ExecutorOutcomeClassWireV1::Success, 1);
        let database = std::sync::Arc::new(fixture.database.clone());
        let envelope = std::sync::Arc::new(fixture.envelope.clone());
        let trust = std::sync::Arc::new(fixture.trust.clone());
        let standing = std::sync::Arc::new(fixture.standing_program.clone());
        let executor = std::sync::Arc::new(fixture.executor_program.clone());
        let config = std::sync::Arc::new(fixture.root.join("executor-config"));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let database = database.clone();
                let envelope = envelope.clone();
                let trust = trust.clone();
                let standing = standing.clone();
                let executor = executor.clone();
                let config = config.clone();
                std::thread::spawn(move || {
                    accept(&database, &envelope, &trust, &standing, &executor, &config).unwrap()
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
        let connection = Connection::open(&*database).unwrap();
        let rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM governed_loop_issuance_refusal",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[test]
    fn exact_durable_custody_replay_remains_read_only_after_issuance_expiry() {
        let expiry = now_unix_ms().unwrap() + 2_000;
        let fixture = fixture_with_expiry(ExecutorOutcomeClassWireV1::Success, expiry);
        let first = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        while now_unix_ms().unwrap() < expiry {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        write_refusing_program(&fixture.standing_program);
        write_refusing_program(&fixture.executor_program);
        let replay = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert_eq!(replay, first);
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("invocations")).unwrap(),
            b"x"
        );
    }

    #[test]
    fn nonclaim_or_expiry_substitution_under_same_issuance_identity_refuses() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let mut changed_nonclaim = fixture.issuance.clone();
        changed_nonclaim.nonclaims = vec![digest("different-nonclaim")];
        let envelope = signed_envelope(&fixture, &changed_nonclaim);
        assert_eq!(
            verify_signed_issuance(&envelope, &fixture.trust).unwrap_err(),
            "governed-issuance-identity-mismatch"
        );

        let mut changed_expiry = fixture.issuance.clone();
        changed_expiry.expires_at_unix_ms += 1;
        let envelope = signed_envelope(&fixture, &changed_expiry);
        assert_eq!(
            verify_signed_issuance(&envelope, &fixture.trust).unwrap_err(),
            "governed-issuance-identity-mismatch"
        );
    }

    #[test]
    fn unknown_outcome_reconciles_read_only_and_never_executes_again() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let unknown = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            None,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(
            &unknown,
            DocketReconciliationWireV1::Indeterminate { .. }
        ));

        write_executor(
            &fixture.executor_program,
            &fixture.custody,
            ExecutorOutcomeClassWireV1::Indeterminate,
            &digest("different-unknown-evidence"),
        );
        let repeated_unknown = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(
            repeated_unknown,
            DocketReconciliationWireV1::Indeterminate { .. }
        ));

        write_executor(
            &fixture.executor_program,
            &fixture.custody,
            ExecutorOutcomeClassWireV1::Failure,
            &digest("reconciled-receipt"),
        );
        let settled = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(
            settled,
            DocketReconciliationWireV1::Settled { .. }
        ));
    }

    #[test]
    fn signature_attempt_and_instrument_substitutions_refuse() {
        let first_fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let mut changed: serde_json::Value =
            serde_json::from_slice(&first_fixture.envelope).unwrap();
        changed["authentication"]["signature"] = serde_json::Value::String(b64_encode(&[0; 64]));
        assert!(verify_signed_issuance(
            &serde_json::to_vec(&changed).unwrap(),
            &first_fixture.trust,
        )
        .is_err());

        accept(
            &first_fixture.database,
            &first_fixture.envelope,
            &first_fixture.trust,
            &first_fixture.standing_program,
            &first_fixture.executor_program,
            &first_fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(reconcile(
            &first_fixture.database,
            &first_fixture.issuance.issuance,
            Some(&digest("wrong-attempt")),
            &first_fixture.executor_program,
            &first_fixture.root.join("executor-config"),
        )
        .is_err());

        let substituted = fixture(ExecutorOutcomeClassWireV1::Success);
        let standing = ExecutionStandingResolutionV1 {
            schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
            resolution: digest("substituted-standing-resolution"),
            currentness: digest("substituted-standing-currentness"),
            execution_standing: substituted.issuance.spend.clone(),
            issuance: substituted.issuance.issuance.clone(),
            campaign: substituted.issuance.key.campaign.clone(),
            occurrence: substituted.issuance.key.occurrence.clone(),
            subject: substituted.issuance.subject.clone(),
            scope: substituted.issuance.effect_scope_digest.clone(),
            status: ExecutionStandingStatusV1::Current,
            resolved_at_unix_ms: 0,
            expires_at_unix_ms: MAX_JCS_SAFE_INTEGER,
        };
        write_static_program(
            &substituted.standing_program,
            &serde_json::to_string(&standing).unwrap(),
        );
        let refusal = accept(
            &substituted.database,
            &substituted.envelope,
            &substituted.trust,
            &substituted.standing_program,
            &substituted.executor_program,
            &substituted.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(
            refusal,
            DocketExecutionResponseWireV1::Refused(DocketIssuanceRefusalWireV1 {
                refusal_class: DocketIssuanceRefusalClassWireV1::InstrumentSubstitution,
                ..
            })
        ));
        let connection = Connection::open(&substituted.database).unwrap();
        let attempts: i64 = connection
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(attempts, 0);
    }

    #[test]
    fn executor_and_plan_substitution_refuse_during_reconciliation() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();

        std::fs::write(fixture.root.join("executor-config"), digest("wrong-plan")).unwrap();
        let plan_error = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap_err();
        assert!(plan_error.contains("executor-plan-substitution"));

        // A configuration with different bytes can deliberately report the
        // same semantic plan: the fixture executor uses `cat`, whose command
        // substitution strips this trailing LF. Its independent byte binding
        // must still refuse after reopening the durable custody store.
        std::fs::write(
            fixture.root.join("executor-config"),
            format!("{}\n", fixture.issuance.work),
        )
        .unwrap();
        assert_eq!(
            invoke_plan_id(
                &prepare_executor(
                    &fixture.executor_program,
                    &fixture.root.join("executor-config"),
                    &fixture.issuance.work,
                )
                .unwrap()
                .retained
            )
            .unwrap(),
            fixture.issuance.work,
            "hostile fixture must preserve plan-id while changing config bytes"
        );
        assert_eq!(
            reconcile(
                &fixture.database,
                &fixture.issuance.issuance,
                Some(&fixture.custody.attempt),
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap_err(),
            "governed-executor-binding-substitution"
        );

        std::fs::write(
            fixture.root.join("executor-config"),
            fixture.issuance.work.as_bytes(),
        )
        .unwrap();
        let mut executable = OpenOptions::new()
            .append(true)
            .open(&fixture.executor_program)
            .unwrap();
        writeln!(executable, "# substituted executable").unwrap();
        drop(executable);
        let executable_error = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap_err();
        assert_eq!(executable_error, "governed-executor-binding-substitution");
    }

    #[test]
    fn prepared_executor_uses_one_exact_snapshot_for_plan_and_delivery() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let config = fixture.root.join("executor-config");
        let prepared =
            prepare_executor(&fixture.executor_program, &config, &fixture.issuance.work).unwrap();

        // Substitute both caller-controlled source paths after preparation.
        // Neither plan-id nor delivery may reopen those paths.
        write_refusing_program(&fixture.executor_program);
        std::fs::write(&config, digest("substituted-plan")).unwrap();

        assert_eq!(
            invoke_plan_id(&prepared.retained).unwrap(),
            fixture.issuance.work
        );
        let outcome: ExecutorOutcomeWireV1 = invoke_retained_json(
            &prepared.retained,
            "execute",
            &executor_dispatch(&fixture.issuance, &fixture.custody),
        )
        .unwrap();
        assert_eq!(outcome.outcome, ExecutorOutcomeClassWireV1::Success);
        assert_eq!(outcome.attempt, fixture.custody.attempt);
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("invocations")).unwrap(),
            b"x"
        );
    }

    #[test]
    fn concurrent_duplicate_custody_creates_one_attempt_and_one_delivery() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let (left, right) = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                accept(
                    &fixture.database,
                    &fixture.envelope,
                    &fixture.trust,
                    &fixture.standing_program,
                    &fixture.executor_program,
                    &fixture.root.join("executor-config"),
                )
            });
            let right = scope.spawn(|| {
                accept(
                    &fixture.database,
                    &fixture.envelope,
                    &fixture.trust,
                    &fixture.standing_program,
                    &fixture.executor_program,
                    &fixture.root.join("executor-config"),
                )
            });
            (left.join().unwrap(), right.join().unwrap())
        });
        assert_eq!(left.unwrap(), right.unwrap());

        let delivered = std::fs::read(fixture.executor_program.with_extension("invocations"))
            .unwrap_or_default();
        assert_eq!(delivered, b"x");
        let connection = Connection::open(&fixture.database).unwrap();
        let attempts: i64 = connection
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(attempts, 1);
    }

    #[test]
    fn restart_read_refuses_tampered_custody_and_settlement_rows() {
        for (label, statement) in [
            (
                "custody attempt",
                "UPDATE governed_loop_attempt SET attempt='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
            ),
            (
                "executor binding",
                "UPDATE governed_loop_attempt SET executor_binding='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
            ),
            (
                "executor config binding",
                "UPDATE governed_loop_attempt SET executor_config_digest=NULL",
            ),
            (
                "settlement",
                "UPDATE governed_loop_attempt SET receipt='sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
            ),
            (
                "settlement time under unchanged identity",
                "UPDATE governed_loop_attempt SET settled_at=settled_at+1",
            ),
            (
                "settlement cumulative journal under unchanged identity",
                "UPDATE governed_loop_attempt SET settlement_cumulative_effect_journal_identity='sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'",
            ),
        ] {
            let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
            accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap();
            let connection = Connection::open(&fixture.database).unwrap();
            connection
                .execute_batch("DROP TRIGGER governed_loop_settlement_immutable_update;")
                .unwrap();
            connection.execute(statement, []).unwrap();
            drop(connection);
            assert!(
                reconcile(
                    &fixture.database,
                    &fixture.issuance.issuance,
                    Some(&fixture.custody.attempt),
                    &fixture.executor_program,
                    &fixture.root.join("executor-config"),
                )
                .is_err(),
                "{label} substitution must fail closed"
            );
        }
    }

    #[test]
    fn changed_immutable_work_checkpoint_bytes_refuse_after_restart() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::ScopeExpansionRequired);
        write_scope_expansion_executor(&fixture.executor_program, &fixture.custody);
        let response_path = fixture.executor_program.with_extension("response");
        let mut response: ExecutorOutcomeWireV1 =
            serde_json::from_slice(&std::fs::read(&response_path).unwrap()).unwrap();
        response.immutable_work_checkpoint = Some(ImmutableWorkCheckpointWireV1 {
            repository_identity: digest("checkpoint-repository"),
            commit: "1".repeat(40),
            tree: "2".repeat(40),
            diff_identity: Some(digest("checkpoint-diff")),
            content_manifest_identity: digest("checkpoint-content-manifest"),
        });
        write_executor_response(&fixture.executor_program, &response);
        let first = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let DocketExecutionResponseWireV1::GovernedRepairRequired { result, .. } = first else {
            panic!("checkpoint-bearing scope halt must be sealed")
        };
        assert_eq!(
            result
                .checkpoint
                .immutable_work_checkpoint
                .as_ref()
                .expect("checkpoint must survive sealing")
                .tree,
            "2".repeat(40)
        );

        let connection = Connection::open(&fixture.database).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER governed_repair_checkpoint_immutable_update;
                 UPDATE governed_repair_checkpoint SET work_tree='3333333333333333333333333333333333333333';",
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            reconcile(
                &fixture.database,
                &fixture.issuance.issuance,
                Some(&fixture.custody.attempt),
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap_err(),
            "governed-repair-executor-result-substitution"
        );
    }

    #[test]
    fn governed_scope_halt_is_sealed_once_and_survives_restart() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::ScopeExpansionRequired);
        write_scope_expansion_executor(&fixture.executor_program, &fixture.custody);
        let first = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let DocketExecutionResponseWireV1::GovernedRepairRequired { result, .. } = &first else {
            panic!("scope expansion must seal a governed repair result")
        };
        assert!(matches!(
            result.outcome,
            governed_repair::SealedGovernedRepairRequirementWireV1::ScopeExpansionRequired(_)
        ));

        write_refusing_program(&fixture.executor_program);
        let replay = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert_eq!(replay, first);

        let reopened = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(
            reopened,
            DocketReconciliationWireV1::GovernedRepairRequired { .. }
        ));
    }

    #[test]
    fn logical_crash_after_executor_result_before_seal_reopens_without_repeat_execution() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::ScopeExpansionRequired);
        write_scope_expansion_executor(&fixture.executor_program, &fixture.custody);
        CRASH_AFTER_EXECUTOR_RESULT_BEFORE_SEAL.with(|failpoint| failpoint.set(true));

        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            );
        }));
        assert!(crashed.is_err(), "logical crash seam must be reached");
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("invocations")).unwrap(),
            b"x",
            "the consequence-bearing execute operation ran exactly once"
        );

        let connection = Connection::open(&fixture.database).unwrap();
        let status: String = connection
            .query_row("SELECT status FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        let checkpoints: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM governed_repair_checkpoint",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((status.as_str(), checkpoints), ("accepted", 0));
        drop(connection);

        let reopened = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(
            reopened,
            DocketReconciliationWireV1::GovernedRepairRequired { .. }
        ));
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("invocations")).unwrap(),
            b"x",
            "reopen uses reconcile and never repeats execute"
        );
    }

    #[test]
    fn governed_requirement_with_blocked_effect_in_journal_refuses_without_terminal_write() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::ScopeExpansionRequired);
        write_scope_expansion_executor(&fixture.executor_program, &fixture.custody);
        let response_path = fixture.executor_program.with_extension("response");
        let mut response: ExecutorOutcomeWireV1 =
            serde_json::from_slice(&std::fs::read(&response_path).unwrap()).unwrap();
        response.effect_journal.push(EffectJournalEntryWireV1 {
            resource: "repository".to_owned(),
            path: "crates/nq-store/src/new.rs".to_owned(),
            operation: CanonicalEffectOperationWireV1::Modify,
            effect_identity: digest("forbidden-blocked-effect"),
        });
        std::fs::write(&response_path, serde_json::to_vec(&response).unwrap()).unwrap();

        assert_eq!(
            accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap_err(),
            "governed-repair-unauthorized-effect-observed"
        );
        let connection = Connection::open(&fixture.database).unwrap();
        let status: String = connection
            .query_row("SELECT status FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        let checkpoints: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM governed_repair_checkpoint",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let executor_results: i64 = connection
            .query_row("SELECT COUNT(*) FROM governed_executor_result", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            (status.as_str(), checkpoints, executor_results),
            ("accepted", 0, 0),
            "an unauthorized observed effect must not be laundered into a sealed halt or settlement"
        );
    }

    #[test]
    fn ordinary_success_with_out_of_scope_journal_refuses_without_settlement() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let response = ExecutorOutcomeWireV1 {
            attempt: fixture.custody.attempt.clone(),
            marker: fixture.custody.executor_marker.clone(),
            receipt: digest("ordinary-receipt"),
            outcome: ExecutorOutcomeClassWireV1::Success,
            effect_journal: vec![EffectJournalEntryWireV1 {
                resource: "repository".to_owned(),
                path: "crates/outside/src/lib.rs".to_owned(),
                operation: CanonicalEffectOperationWireV1::Modify,
                effect_identity: digest("unauthorized-effect"),
            }],
            immutable_work_checkpoint: None,
            governed_repair: None,
        };
        write_executor_response(&fixture.executor_program, &response);
        assert_eq!(
            accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap_err(),
            "governed-repair-unauthorized-effect-observed"
        );
        let connection = Connection::open(&fixture.database).unwrap();
        let status: String = connection
            .query_row("SELECT status FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        let results: i64 = connection
            .query_row("SELECT COUNT(*) FROM governed_executor_result", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((status.as_str(), results), ("accepted", 0));
    }

    #[test]
    fn governed_repair_restart_reconstructs_and_refuses_tampered_rows() {
        for (trigger, statement) in [
            (
                "governed_repair_checkpoint_immutable_update",
                "UPDATE governed_repair_checkpoint SET executor_receipt='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
            ),
            (
                "governed_repair_scope_immutable_update",
                "UPDATE governed_repair_scope_expansion SET reason='sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
            ),
            (
                "governed_repair_scope_immutable_update",
                "UPDATE governed_repair_scope_expansion SET requested_delta_digest='sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
            ),
            (
                "governed_repair_checkpoint_immutable_update",
                "PRAGMA ignore_check_constraints=ON; UPDATE governed_repair_checkpoint SET no_unauthorized_effect_reported=0",
            ),
        ] {
            let fixture = fixture(ExecutorOutcomeClassWireV1::ScopeExpansionRequired);
            write_scope_expansion_executor(&fixture.executor_program, &fixture.custody);
            accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap();
            let connection = Connection::open(&fixture.database).unwrap();
            connection
                .execute_batch(&format!("DROP TRIGGER {trigger};{statement}"))
                .unwrap();
            drop(connection);
            assert!(
                reconcile(
                    &fixture.database,
                    &fixture.issuance.issuance,
                    Some(&fixture.custody.attempt),
                    &fixture.executor_program,
                    &fixture.root.join("executor-config"),
                )
                .is_err(),
                "tampered governed repair row must fail closed"
            );
        }
    }

    #[test]
    fn checkpoint_verification_requires_present_freshness() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let mut issuance = fixture.issuance.clone();
        issuance.governed_repair_checkpoint = Some(GovernedRepairCheckpointEvidenceWireV1 {
            repository: digest("repository"),
            commit: "1".repeat(40),
            tree: "2".repeat(40),
            diff_identity: None,
            content_manifest: digest("manifest"),
            docket_checkpoint: None,
        });
        let verifier = fixture.root.join("checkpoint-verifier");
        for (verified, expires) in [(101, 200), (10, 100)] {
            let result = CheckpointVerificationResultWireV1 {
                schema: "docket.governed-repair.checkpoint-verification/v1".to_owned(),
                verification: digest("verification"),
                issuance: issuance.issuance.clone(),
                checkpoint: issuance.governed_repair_checkpoint.clone().unwrap(),
                status: CheckpointVerificationStatusWireV1::Current,
                verified_at_unix_ms: verified,
                expires_at_unix_ms: expires,
            };
            write_static_program(&verifier, &serde_json::to_string(&result).unwrap());
            assert!(verify_starting_checkpoint(&issuance, Some(&verifier), 100).is_err());
        }
        let current = CheckpointVerificationResultWireV1 {
            schema: "docket.governed-repair.checkpoint-verification/v1".to_owned(),
            verification: digest("verification"),
            issuance: issuance.issuance.clone(),
            checkpoint: issuance.governed_repair_checkpoint.clone().unwrap(),
            status: CheckpointVerificationStatusWireV1::Current,
            verified_at_unix_ms: 99,
            expires_at_unix_ms: 101,
        };
        write_static_program(&verifier, &serde_json::to_string(&current).unwrap());
        assert!(verify_starting_checkpoint(&issuance, Some(&verifier), 100).is_ok());
    }

    #[test]
    fn same_executor_evidence_with_changed_journal_is_a_collision() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let mut connection = Connection::open(&fixture.database).unwrap();
        let transaction = connection.transaction().unwrap();
        let input = governed_repair::OrdinaryExecutorResultInputV1 {
            issuance: &fixture.issuance.issuance,
            attempt: &fixture.custody.attempt,
            outcome: "indeterminate",
            receipt: &digest("executor-receipt"),
            scope: &fixture.issuance.effect_scope,
            entries: &[EffectJournalEntryWireV1 {
                resource: "repository".to_owned(),
                path: "crates/nq-store/src/lib.rs".to_owned(),
                operation: CanonicalEffectOperationWireV1::Modify,
                effect_identity: digest("changed-journal"),
            }],
            recorded_at: 1,
        };
        assert_eq!(
            governed_repair::append_ordinary_executor_result(&transaction, input).unwrap_err(),
            "governed-executor-result-replay-collision"
        );
    }

    #[test]
    fn one_receipt_cannot_change_indeterminate_into_known_outcome() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        write_executor(
            &fixture.executor_program,
            &fixture.custody,
            ExecutorOutcomeClassWireV1::Failure,
            &digest("executor-receipt"),
        );
        assert_eq!(
            reconcile(
                &fixture.database,
                &fixture.issuance.issuance,
                Some(&fixture.custody.attempt),
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap_err(),
            "governed-executor-result-replay-collision"
        );
    }

    #[test]
    fn one_receipt_cannot_change_success_into_failure() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let mut connection = Connection::open(&fixture.database).unwrap();
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            governed_repair::append_ordinary_executor_result(
                &transaction,
                governed_repair::OrdinaryExecutorResultInputV1 {
                    issuance: &fixture.issuance.issuance,
                    attempt: &fixture.custody.attempt,
                    outcome: "failure",
                    receipt: &digest("executor-receipt"),
                    scope: &fixture.issuance.effect_scope,
                    entries: &[],
                    recorded_at: 0,
                },
            )
            .unwrap_err(),
            "governed-executor-result-replay-collision"
        );
    }

    #[test]
    fn executor_observation_order_is_sequence_based_despite_clock_regression() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let mut connection = Connection::open(&fixture.database).unwrap();
        let transaction = connection.transaction().unwrap();
        governed_repair::append_ordinary_executor_result(
            &transaction,
            governed_repair::OrdinaryExecutorResultInputV1 {
                issuance: &fixture.issuance.issuance,
                attempt: &fixture.custody.attempt,
                outcome: "indeterminate",
                receipt: &digest("later-observation-with-regressed-clock"),
                scope: &fixture.issuance.effect_scope,
                entries: &[],
                recorded_at: 0,
            },
        )
        .unwrap();
        transaction.commit().unwrap();
        let rows: Vec<(i64, i64)> = connection
            .prepare("SELECT sequence,recorded_at FROM governed_executor_result ORDER BY sequence")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].0 < rows[1].0);
        assert!(rows[0].1 > rows[1].1);
        governed_repair::validate_ordinary_executor_result(
            &connection,
            &fixture.issuance.issuance,
            &fixture.custody.attempt,
            "indeterminate",
            &fixture.issuance.effect_scope,
        )
        .unwrap();
    }

    #[test]
    fn readjudication_halt_is_distinct_and_restart_stable() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::ReadjudicationRequired);
        write_readjudication_executor(&fixture.executor_program, &fixture.custody);
        let first = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let DocketExecutionResponseWireV1::GovernedRepairRequired { result, .. } = first else {
            panic!("readjudication must seal a governed repair result")
        };
        assert!(matches!(
            result.outcome,
            governed_repair::SealedGovernedRepairRequirementWireV1::ReadjudicationRequired(_)
        ));
        write_refusing_program(&fixture.executor_program);
        assert!(matches!(
            reconcile(
                &fixture.database,
                &fixture.issuance.issuance,
                Some(&fixture.custody.attempt),
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap(),
            DocketReconciliationWireV1::GovernedRepairRequired { .. }
        ));
    }

    #[test]
    fn altered_scope_identity_refuses_before_standing_or_custody() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let mut issuance = fixture.issuance.clone();
        issuance.effect_scope_digest = digest("substituted-scope-identity");
        refresh_issuance_identity(&mut issuance);
        let envelope = signed_envelope(&fixture, &issuance);
        let response = accept(
            &fixture.database,
            &envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(
            response,
            DocketExecutionResponseWireV1::Refused(DocketIssuanceRefusalWireV1 {
                refusal_class: DocketIssuanceRefusalClassWireV1::IssuanceInvalid,
                ..
            })
        ));
        let connection = Connection::open(&fixture.database).unwrap();
        let attempts: i64 = connection
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(attempts, 0);
    }

    #[test]
    fn reconcile_reverifies_checkpoint_before_any_executor_or_state_advance() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        let mut issuance = fixture.issuance.clone();
        issuance.governed_repair_checkpoint = Some(GovernedRepairCheckpointEvidenceWireV1 {
            repository: digest("checkpoint-repository"),
            commit: "1".repeat(40),
            tree: "2".repeat(40),
            diff_identity: Some(digest("checkpoint-diff")),
            content_manifest: digest("checkpoint-manifest"),
            docket_checkpoint: None,
        });
        refresh_issuance_identity(&mut issuance);
        let attempt =
            digest_json_string("ag.governed-loop.docket-attempt/v1", &issuance.issuance).unwrap();
        let custody = DocketCustodyWireV1 {
            schema: CUSTODY_SCHEMA_V1.to_owned(),
            issuance: issuance.issuance.clone(),
            ag_spend: issuance.spend.clone(),
            execution_standing: digest("successor-execution-standing"),
            standing_currentness: digest("successor-standing-currentness"),
            attempt: attempt.clone(),
            executor_marker: hash_domain(
                "docket.governed-loop.executor-marker/v1",
                attempt.as_bytes(),
            ),
            accepted_at_unix_ms: 0,
        };
        write_static_program(
            &fixture.standing_program,
            &serde_json::to_string(&ExecutionStandingResolutionV1 {
                schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
                resolution: digest("successor-standing-resolution"),
                currentness: custody.standing_currentness.clone(),
                execution_standing: custody.execution_standing.clone(),
                issuance: issuance.issuance.clone(),
                campaign: issuance.key.campaign.clone(),
                occurrence: issuance.key.occurrence.clone(),
                subject: issuance.subject.clone(),
                scope: issuance.effect_scope_digest.clone(),
                status: ExecutionStandingStatusV1::Current,
                resolved_at_unix_ms: 0,
                expires_at_unix_ms: MAX_JCS_SAFE_INTEGER,
            })
            .unwrap(),
        );
        write_executor(
            &fixture.executor_program,
            &custody,
            ExecutorOutcomeClassWireV1::Indeterminate,
            &digest("successor-indeterminate"),
        );
        let envelope = signed_envelope(&fixture, &issuance);
        let verifier = fixture.root.join("checkpoint-verifier");
        let mut verification = CheckpointVerificationResultWireV1 {
            schema: "docket.governed-repair.checkpoint-verification/v1".to_owned(),
            verification: digest("checkpoint-verification"),
            issuance: issuance.issuance.clone(),
            checkpoint: issuance.governed_repair_checkpoint.clone().unwrap(),
            status: CheckpointVerificationStatusWireV1::Current,
            verified_at_unix_ms: 0,
            expires_at_unix_ms: MAX_JCS_SAFE_INTEGER,
        };
        write_static_program(&verifier, &serde_json::to_string(&verification).unwrap());
        accept_with_checkpoint_verifier(
            &fixture.database,
            &envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
            Some(&verifier),
        )
        .unwrap();
        let before: (String, i64) = Connection::open(&fixture.database)
            .unwrap()
            .query_row(
                "SELECT status,(SELECT COUNT(*) FROM governed_executor_result)
                 FROM governed_loop_attempt",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        verification.status = CheckpointVerificationStatusWireV1::Mismatch;
        write_static_program(&verifier, &serde_json::to_string(&verification).unwrap());
        assert_eq!(
            observe_issuance_with_checkpoint_verifier(
                &fixture.database,
                &issuance.issuance,
                Some(&verifier),
            )
            .unwrap_err(),
            "governed-checkpoint-verification-mismatch"
        );
        assert!(!fixture
            .executor_program
            .with_extension("reconciliations")
            .exists());
        let after_observation_refusal: (String, i64) = Connection::open(&fixture.database)
            .unwrap()
            .query_row(
                "SELECT status,(SELECT COUNT(*) FROM governed_executor_result)
                 FROM governed_loop_attempt",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(after_observation_refusal, before);
        write_refusing_program(&fixture.executor_program);
        assert_eq!(
            reconcile_with_checkpoint_verifier(
                &fixture.database,
                &issuance.issuance,
                Some(&custody.attempt),
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
                Some(&verifier),
            )
            .unwrap_err(),
            "governed-checkpoint-verification-mismatch"
        );
        let after: (String, i64) = Connection::open(&fixture.database)
            .unwrap()
            .query_row(
                "SELECT status,(SELECT COUNT(*) FROM governed_executor_result)
                 FROM governed_loop_attempt",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn sealed_successor_result_requires_fresh_checkpoint_before_reemission() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::ScopeExpansionRequired);
        let mut issuance = fixture.issuance.clone();
        issuance.governed_repair_checkpoint = Some(GovernedRepairCheckpointEvidenceWireV1 {
            repository: digest("sealed-successor-repository"),
            commit: "1".repeat(40),
            tree: "2".repeat(40),
            diff_identity: None,
            content_manifest: digest("sealed-successor-manifest"),
            docket_checkpoint: None,
        });
        refresh_issuance_identity(&mut issuance);
        let attempt =
            digest_json_string("ag.governed-loop.docket-attempt/v1", &issuance.issuance).unwrap();
        let custody = DocketCustodyWireV1 {
            schema: CUSTODY_SCHEMA_V1.to_owned(),
            issuance: issuance.issuance.clone(),
            ag_spend: issuance.spend.clone(),
            execution_standing: digest("sealed-successor-execution-standing"),
            standing_currentness: digest("sealed-successor-standing-currentness"),
            attempt: attempt.clone(),
            executor_marker: hash_domain(
                "docket.governed-loop.executor-marker/v1",
                attempt.as_bytes(),
            ),
            accepted_at_unix_ms: 0,
        };
        write_static_program(
            &fixture.standing_program,
            &serde_json::to_string(&ExecutionStandingResolutionV1 {
                schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
                resolution: digest("sealed-successor-standing-resolution"),
                currentness: custody.standing_currentness.clone(),
                execution_standing: custody.execution_standing.clone(),
                issuance: issuance.issuance.clone(),
                campaign: issuance.key.campaign.clone(),
                occurrence: issuance.key.occurrence.clone(),
                subject: issuance.subject.clone(),
                scope: issuance.effect_scope_digest.clone(),
                status: ExecutionStandingStatusV1::Current,
                resolved_at_unix_ms: 0,
                expires_at_unix_ms: MAX_JCS_SAFE_INTEGER,
            })
            .unwrap(),
        );
        write_scope_expansion_executor(&fixture.executor_program, &custody);
        let envelope = signed_envelope(&fixture, &issuance);
        let verifier = fixture.root.join("sealed-checkpoint-verifier");
        let mut verification = CheckpointVerificationResultWireV1 {
            schema: "docket.governed-repair.checkpoint-verification/v1".to_owned(),
            verification: digest("sealed-checkpoint-verification"),
            issuance: issuance.issuance.clone(),
            checkpoint: issuance.governed_repair_checkpoint.clone().unwrap(),
            status: CheckpointVerificationStatusWireV1::Current,
            verified_at_unix_ms: 0,
            expires_at_unix_ms: MAX_JCS_SAFE_INTEGER,
        };
        write_static_program(&verifier, &serde_json::to_string(&verification).unwrap());
        assert!(matches!(
            accept_with_checkpoint_verifier(
                &fixture.database,
                &envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
                Some(&verifier),
            )
            .unwrap(),
            DocketExecutionResponseWireV1::GovernedRepairRequired { .. }
        ));
        let before: (i64, i64) = Connection::open(&fixture.database)
            .unwrap()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM governed_repair_checkpoint),
                        (SELECT COUNT(*) FROM governed_executor_result)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        verification.status = CheckpointVerificationStatusWireV1::Mismatch;
        write_static_program(&verifier, &serde_json::to_string(&verification).unwrap());
        let forbidden_executor = fixture.root.join("sealed-result-must-not-invoke-executor");
        let forbidden_counter = forbidden_executor.with_extension("invocations");
        write_counting_refusing_program(&forbidden_executor, &forbidden_counter);
        assert_eq!(
            reconcile_with_checkpoint_verifier(
                &fixture.database,
                &issuance.issuance,
                Some(&custody.attempt),
                &forbidden_executor,
                &fixture.root.join("executor-config"),
                Some(&verifier),
            )
            .unwrap_err(),
            "governed-checkpoint-verification-mismatch"
        );
        assert!(!forbidden_counter.exists());
        let after: (i64, i64) = Connection::open(&fixture.database)
            .unwrap()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM governed_repair_checkpoint),
                        (SELECT COUNT(*) FROM governed_executor_result)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn indeterminate_then_terminal_preserves_one_cumulative_ordered_journal() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        let first_entry = EffectJournalEntryWireV1 {
            resource: "repository".to_owned(),
            path: "crates/nq-store/src/lib.rs".to_owned(),
            operation: CanonicalEffectOperationWireV1::Modify,
            effect_identity: digest("first-effect"),
        };
        let second_entry = EffectJournalEntryWireV1 {
            resource: "repository".to_owned(),
            path: "crates/nq-store/src/lib.rs".to_owned(),
            operation: CanonicalEffectOperationWireV1::Modify,
            effect_identity: digest("second-effect"),
        };
        let mut first: ExecutorOutcomeWireV1 = serde_json::from_slice(
            &std::fs::read(fixture.executor_program.with_extension("response")).unwrap(),
        )
        .unwrap();
        first.effect_journal = vec![first_entry.clone()];
        write_executor_response(&fixture.executor_program, &first);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        write_executor(
            &fixture.executor_program,
            &fixture.custody,
            ExecutorOutcomeClassWireV1::Failure,
            &digest("terminal-receipt"),
        );
        let mut terminal: ExecutorOutcomeWireV1 = serde_json::from_slice(
            &std::fs::read(fixture.executor_program.with_extension("response")).unwrap(),
        )
        .unwrap();
        terminal.effect_journal = vec![second_entry.clone()];
        write_executor_response(&fixture.executor_program, &terminal);
        let reconciliation = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let expected =
            effect_journal_identity(&fixture.issuance.effect_scope, &[first_entry, second_entry])
                .unwrap();
        let connection = Connection::open(&fixture.database).unwrap();
        let stored: String = connection
            .query_row(
                "SELECT cumulative_effect_journal_digest
                 FROM governed_executor_result ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, expected);
        let DocketReconciliationWireV1::Settled { settlement, .. } = &reconciliation else {
            panic!("known terminal result must emit exact settlement")
        };
        assert_eq!(settlement.cumulative_effect_journal_identity, expected);
        assert_eq!(
            settlement.settlement,
            docket_settlement_identity(settlement).unwrap()
        );
        governed_repair::validate_ordinary_executor_result(
            &connection,
            &fixture.issuance.issuance,
            &fixture.custody.attempt,
            "settled",
            &fixture.issuance.effect_scope,
        )
        .unwrap();
        drop(connection);
        let connection = Connection::open(&fixture.database).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER governed_executor_result_immutable_update;
                 UPDATE governed_executor_result
                 SET cumulative_effect_journal_digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                 WHERE sequence=(SELECT MAX(sequence) FROM governed_executor_result);",
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            reconcile(
                &fixture.database,
                &fixture.issuance.issuance,
                Some(&fixture.custody.attempt),
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap_err(),
            "governed-executor-cumulative-journal-substitution"
        );
    }

    #[test]
    fn cumulative_journal_is_idempotent_and_effect_identity_is_non_substitutable() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let entry = EffectJournalEntryWireV1 {
            resource: "repository".to_owned(),
            path: "crates/nq-store/src/lib.rs".to_owned(),
            operation: CanonicalEffectOperationWireV1::Modify,
            effect_identity: digest("one-exact-effect"),
        };
        let two_coordinate_scope = CanonicalEffectScopeWireV1 {
            schema: "ag.governed-loop.canonical-effect-scope/v1".to_owned(),
            effect_class: "repository-write/v1".to_owned(),
            resources: vec![
                CanonicalEffectResourceWireV1 {
                    resource: "repository".to_owned(),
                    path: "crates/nq-store/src/lib.rs".to_owned(),
                    operations: vec![CanonicalEffectOperationWireV1::Modify],
                },
                CanonicalEffectResourceWireV1 {
                    resource: "repository".to_owned(),
                    path: "neighboring/path".to_owned(),
                    operations: vec![CanonicalEffectOperationWireV1::Modify],
                },
            ],
        };
        let mut connection = Connection::open(&fixture.database).unwrap();

        let append = |tx: &rusqlite::Transaction<'_>,
                      receipt: &str,
                      entries: &[EffectJournalEntryWireV1]| {
            governed_repair::append_ordinary_executor_result(
                tx,
                governed_repair::OrdinaryExecutorResultInputV1 {
                    issuance: &fixture.issuance.issuance,
                    attempt: &fixture.custody.attempt,
                    outcome: "indeterminate",
                    receipt,
                    scope: &two_coordinate_scope,
                    entries,
                    recorded_at: 1,
                },
            )
        };

        let first_receipt = digest("first-distinct-observation");
        let tx = connection.transaction().unwrap();
        assert!(!append(&tx, &first_receipt, std::slice::from_ref(&entry)).unwrap());
        // Exact receipt and exact bytes are idempotent and append no row.
        assert!(append(&tx, &first_receipt, std::slice::from_ref(&entry)).unwrap());
        tx.commit().unwrap();

        let second_receipt = digest("second-distinct-observation");
        let tx = connection.transaction().unwrap();
        assert!(!append(&tx, &second_receipt, std::slice::from_ref(&entry)).unwrap());
        tx.commit().unwrap();
        let rows_and_latest_digest: (i64, String) = connection
            .query_row(
                "SELECT COUNT(*),
                        (SELECT cumulative_effect_journal_digest
                         FROM governed_executor_result ORDER BY sequence DESC LIMIT 1)
                 FROM governed_executor_result",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        // One fixture row plus two distinct observations; the repeated exact
        // effect appears once in the occurrence's cumulative sequence.
        assert_eq!(rows_and_latest_digest.0, 3);
        assert_eq!(
            rows_and_latest_digest.1,
            effect_journal_identity(&two_coordinate_scope, std::slice::from_ref(&entry)).unwrap()
        );

        let changed = EffectJournalEntryWireV1 {
            path: "neighboring/path".to_owned(),
            ..entry
        };
        let tx = connection.transaction().unwrap();
        assert_eq!(
            append(&tx, &digest("third-conflicting-observation"), &[changed]).unwrap_err(),
            "governed-executor-effect-identity-collision"
        );
        assert_eq!(
            tx.query_row("SELECT COUNT(*) FROM governed_executor_result", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            3
        );
    }

    #[test]
    fn terminal_seal_and_late_indeterminate_observation_are_one_atomic_journal_cut() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();

        let late_effect = EffectJournalEntryWireV1 {
            resource: "repository".to_owned(),
            path: "crates/nq-store/src/lib.rs".to_owned(),
            operation: CanonicalEffectOperationWireV1::Modify,
            effect_identity: digest("concurrent-late-effect"),
        };
        let late = ExecutorOutcomeWireV1 {
            attempt: fixture.custody.attempt.clone(),
            marker: fixture.custody.executor_marker.clone(),
            receipt: digest("concurrent-late-receipt"),
            outcome: ExecutorOutcomeClassWireV1::Indeterminate,
            effect_journal: vec![late_effect.clone()],
            immutable_work_checkpoint: None,
            governed_repair: None,
        };
        let delta = CanonicalEffectScopeWireV1 {
            schema: "ag.governed-loop.canonical-effect-scope/v1".to_owned(),
            effect_class: "repository-write/v1".to_owned(),
            resources: vec![CanonicalEffectResourceWireV1 {
                resource: "repository".to_owned(),
                path: "crates/nq-store/src/new.rs".to_owned(),
                operations: vec![CanonicalEffectOperationWireV1::Modify],
            }],
        };
        let terminal = ExecutorOutcomeWireV1 {
            attempt: fixture.custody.attempt.clone(),
            marker: fixture.custody.executor_marker.clone(),
            receipt: digest("concurrent-terminal-receipt"),
            outcome: ExecutorOutcomeClassWireV1::ScopeExpansionRequired,
            effect_journal: vec![],
            immutable_work_checkpoint: None,
            governed_repair: Some(
                ExecutorGovernedRepairRequirementWireV1::ScopeExpansionRequired {
                    requested_delta_digest: hash_domain(
                        "ag.governed-loop.canonical-effect-scope/v1",
                        &serde_jcs::to_vec(&delta).unwrap(),
                    ),
                    requested_delta: delta,
                    blocked_effect: governed_repair::BlockedEffectWireV1 {
                        effect_class: "repository-write/v1".to_owned(),
                        resource: "repository".to_owned(),
                        path: "crates/nq-store/src/new.rs".to_owned(),
                        operation: CanonicalEffectOperationWireV1::Modify,
                    },
                    reason: digest("concurrent-scope-reason"),
                    dependency_evidence: vec![digest("concurrent-dependency")],
                    created_at_unix_ms: 0,
                    expires_at_unix_ms: MAX_JCS_SAFE_INTEGER,
                    idempotency: digest("concurrent-idempotency"),
                    limitations: vec![digest("concurrent-limitation")],
                },
            ),
        };
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let spawn = |outcome: ExecutorOutcomeWireV1| {
            let database = fixture.database.clone();
            let issuance = fixture.issuance.issuance.clone();
            let custody = fixture.custody.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut store = GovernedCustodyStoreV1::open(&database).unwrap();
                barrier.wait();
                store.record_executor_outcome(&issuance, &custody, outcome, 100)
            })
        };
        let late_thread = spawn(late.clone());
        let terminal_thread = spawn(terminal);
        barrier.wait();
        let late_result = late_thread.join().unwrap();
        terminal_thread.join().unwrap().unwrap();

        let connection = Connection::open(&fixture.database).unwrap();
        let sealed_entries: String = connection
            .query_row(
                "SELECT effect_journal_entries FROM governed_repair_checkpoint",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let sealed_entries = governed_repair::decode_journal_for_test(&sealed_entries).unwrap();
        assert_eq!(sealed_entries.contains(&late_effect), late_result.is_ok());
        drop(connection);

        // A new observation after the terminal checkpoint is neither appended
        // nor mistaken for an idempotent replay, including after reopen.
        let before: i64 = Connection::open(&fixture.database)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM governed_executor_result", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut reopened = GovernedCustodyStoreV1::open(&fixture.database).unwrap();
        let mut changed = late;
        changed.receipt = digest("after-terminal-new-receipt");
        assert_eq!(
            reopened
                .record_executor_outcome(
                    &fixture.issuance.issuance,
                    &fixture.custody,
                    changed,
                    101,
                )
                .unwrap_err(),
            "governed-executor-result-after-terminal"
        );
        let after: i64 = Connection::open(&fixture.database)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM governed_executor_result", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn strict_json_rejects_recursive_unsafe_numbers_and_nested_unknown_fields() {
        assert!(strict_json::<serde_json::Value>(
            br#"{"outer":{"unsafe":9007199254740992}}"#,
            "unsafe"
        )
        .unwrap_err()
        .contains("number-outside-jcs-safe-integer-domain"));
        let fixture = fixture(ExecutorOutcomeClassWireV1::ScopeExpansionRequired);
        write_scope_expansion_executor(&fixture.executor_program, &fixture.custody);
        let response: serde_json::Value = serde_json::from_slice(
            &std::fs::read(fixture.executor_program.with_extension("response")).unwrap(),
        )
        .unwrap();
        let mut response = response;
        response["governed_repair"]["unexpected_nested_field"] = serde_json::Value::Bool(true);
        assert!(strict_json::<ExecutorOutcomeWireV1>(
            &serde_json::to_vec(&response).unwrap(),
            "nested"
        )
        .is_err());
        assert!(strict_json::<serde_json::Value>(
            br#"{"requested_delta":{"effect_class":"one","effect_class":"two"}}"#,
            "nested-duplicate"
        )
        .unwrap_err()
        .contains("duplicate JSON object member: effect_class"));
        assert!(strict_json::<serde_json::Value>(
            br#"{"checkpoint":{"diff_identity":null,"diff_identity":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#,
            "null-valid-duplicate"
        )
        .unwrap_err()
        .contains("duplicate JSON object member: diff_identity"));

        let plain = ExecutorOutcomeWireV1 {
            attempt: digest("canonical-outcome-attempt"),
            marker: digest("canonical-outcome-marker"),
            receipt: digest("canonical-outcome-receipt"),
            outcome: ExecutorOutcomeClassWireV1::Indeterminate,
            effect_journal: vec![],
            immutable_work_checkpoint: None,
            governed_repair: None,
        };
        let canonical = serde_jcs::to_vec(&plain).unwrap();
        let canonical_value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        assert!(!canonical_value
            .as_object()
            .unwrap()
            .contains_key("immutable_work_checkpoint"));
        assert!(!canonical_value
            .as_object()
            .unwrap()
            .contains_key("governed_repair"));
        for field in ["immutable_work_checkpoint", "governed_repair"] {
            let mut explicit_null = canonical_value.clone();
            explicit_null[field] = serde_json::Value::Null;
            assert!(strict_json::<ExecutorOutcomeWireV1>(
                &serde_jcs::to_vec(&explicit_null).unwrap(),
                "executor-outcome-explicit-null"
            )
            .unwrap_err()
            .contains("explicit null is not canonical"));
        }
    }

    #[test]
    fn docket_persistence_rejects_times_outside_jcs_safe_integer_domain() {
        assert_eq!(
            u64_to_i64(MAX_JCS_SAFE_INTEGER).unwrap(),
            9_007_199_254_740_991
        );
        assert_eq!(
            u64_to_i64(MAX_JCS_SAFE_INTEGER + 1).unwrap_err(),
            "governed-clock-outside-jcs-safe-integer-domain"
        );
        assert!(read_u64(9_007_199_254_740_991, 0).is_ok());
        assert!(read_u64(9_007_199_254_740_992, 0).is_err());
    }

    #[test]
    fn sealed_requirement_uses_honest_executor_report_observation_label() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::ScopeExpansionRequired);
        write_scope_expansion_executor(&fixture.executor_program, &fixture.custody);
        let response = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let encoded = serde_json::to_value(response).unwrap();
        let text = serde_json::to_string(&encoded).unwrap();
        assert!(text.contains("no_unauthorized_effect_reported"));
        assert!(!text.contains("unauthorized_effect_not_performed"));
    }

    #[test]
    fn ag_custody_reference_matches_frozen_cross_repository_vector() {
        let value = DocketCustodyWireV1 {
            schema: CUSTODY_SCHEMA_V1.to_owned(),
            issuance: format!("sha256:{}", "11".repeat(32)),
            ag_spend: format!("sha256:{}", "22".repeat(32)),
            execution_standing: format!("sha256:{}", "33".repeat(32)),
            standing_currentness: format!("sha256:{}", "44".repeat(32)),
            attempt: format!("sha256:{}", "55".repeat(32)),
            executor_marker: format!("sha256:{}", "66".repeat(32)),
            accepted_at_unix_ms: 7,
        };
        assert_eq!(
            governed_repair::ag_custody_reference(&value).unwrap(),
            "sha256:c5bdcb05b94d54e7443d06445dc30a73f6c80c8708699296df0e441e86792261"
        );
    }

    fn digest(label: &str) -> String {
        hash_domain("docket-governed-loop-test/v1", label.as_bytes())
    }

    fn write_executor(
        path: &Path,
        custody: &DocketCustodyWireV1,
        outcome: ExecutorOutcomeClassWireV1,
        receipt: &str,
    ) {
        let output = serde_json::to_string(&ExecutorOutcomeWireV1 {
            attempt: custody.attempt.clone(),
            marker: custody.executor_marker.clone(),
            receipt: receipt.to_owned(),
            outcome,
            effect_journal: vec![],
            immutable_work_checkpoint: None,
            governed_repair: None,
        })
        .unwrap();
        let response = path.with_extension("response");
        let invocations = path.with_extension("invocations");
        let reconciliations = path.with_extension("reconciliations");
        std::fs::write(&response, output).unwrap();
        if path.exists() {
            return;
        }
        let response = response.display().to_string().replace('\'', "'\\''");
        let invocations = invocations.display().to_string().replace('\'', "'\\''");
        let reconciliations = reconciliations.display().to_string().replace('\'', "'\\''");
        std::fs::write(
            path,
            format!(
                "#!/bin/sh\nif [ \"$1\" = plan-id ]; then cat \"$2\"; exit $?; fi\nif [ \"$1\" = execute ]; then cat >/dev/null; printf x >> '{invocations}'; cat '{response}'; exit $?; fi\nif [ \"$1\" = reconcile ]; then cat >/dev/null; printf x >> '{reconciliations}'; cat '{response}'; exit $?; fi\nexit 64\n"
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn write_blocking_mixed_executor(
        path: &Path,
        initial: &ExecutorOutcomeWireV1,
        reconciliation: &ExecutorOutcomeWireV1,
    ) {
        let initial_response = path.with_extension("initial-response");
        let reconciliation_response = path.with_extension("reconciliation-response");
        std::fs::write(&initial_response, serde_jcs::to_vec(initial).unwrap()).unwrap();
        std::fs::write(
            &reconciliation_response,
            serde_jcs::to_vec(reconciliation).unwrap(),
        )
        .unwrap();
        let escaped = |value: &Path| value.display().to_string().replace('\'', "'\\''");
        let execute_started = escaped(&path.with_extension("execute-started"));
        let execute_release = escaped(&path.with_extension("execute-release"));
        let execute_calls = escaped(&path.with_extension("execute-calls"));
        let reconcile_started = escaped(&path.with_extension("reconcile-started"));
        let reconcile_release = escaped(&path.with_extension("reconcile-release"));
        let reconcile_calls = escaped(&path.with_extension("reconcile-calls"));
        let initial_response = escaped(&initial_response);
        let reconciliation_response = escaped(&reconciliation_response);
        std::fs::write(
            path,
            format!(
                "#!/bin/sh\nif [ \"$1\" = plan-id ]; then cat \"$2\"; exit $?; fi\nif [ \"$1\" = execute ]; then cat >/dev/null; printf x >> '{execute_calls}'; : > '{execute_started}'; while [ ! -f '{execute_release}' ]; do sleep 0.01; done; cat '{initial_response}'; exit $?; fi\nif [ \"$1\" = reconcile ]; then cat >/dev/null; printf x >> '{reconcile_calls}'; : > '{reconcile_started}'; while [ ! -f '{reconcile_release}' ]; do sleep 0.01; done; cat '{reconciliation_response}'; exit $?; fi\nexit 64\n"
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn wait_for_test_path(path: &Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !path.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {}",
                path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn write_inline_executor(
        path: &Path,
        custody: &DocketCustodyWireV1,
        outcome: ExecutorOutcomeClassWireV1,
        receipt: &str,
    ) {
        let response = serde_json::to_string(&ExecutorOutcomeWireV1 {
            attempt: custody.attempt.clone(),
            marker: custody.executor_marker.clone(),
            receipt: receipt.to_owned(),
            outcome,
            effect_journal: vec![],
            immutable_work_checkpoint: None,
            governed_repair: None,
        })
        .unwrap();
        std::fs::write(
            path,
            format!(
                "#!/bin/sh\nif [ \"$1\" = plan-id ]; then cat \"$2\"; exit $?; fi\nif [ \"$1\" = execute ] || [ \"$1\" = reconcile ]; then cat >/dev/null; printf '%s' '{}'; exit $?; fi\nexit 64\n",
                response.replace('\'', "'\\''")
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn write_scope_expansion_executor(path: &Path, custody: &DocketCustodyWireV1) {
        let delta = CanonicalEffectScopeWireV1 {
            schema: "ag.governed-loop.canonical-effect-scope/v1".to_owned(),
            effect_class: "repository-write/v1".to_owned(),
            resources: vec![CanonicalEffectResourceWireV1 {
                resource: "repository".to_owned(),
                path: "crates/nq-store/src/new.rs".to_owned(),
                operations: vec![CanonicalEffectOperationWireV1::Modify],
            }],
        };
        let delta_digest = hash_domain(
            "ag.governed-loop.canonical-effect-scope/v1",
            &serde_jcs::to_vec(&delta).unwrap(),
        );
        let response = ExecutorOutcomeWireV1 {
            attempt: custody.attempt.clone(),
            marker: custody.executor_marker.clone(),
            receipt: digest("scope-expansion-receipt"),
            outcome: ExecutorOutcomeClassWireV1::ScopeExpansionRequired,
            effect_journal: vec![],
            immutable_work_checkpoint: None,
            governed_repair: Some(
                ExecutorGovernedRepairRequirementWireV1::ScopeExpansionRequired {
                    requested_delta: delta,
                    requested_delta_digest: delta_digest,
                    blocked_effect: governed_repair::BlockedEffectWireV1 {
                        effect_class: "repository-write/v1".to_owned(),
                        resource: "repository".to_owned(),
                        path: "crates/nq-store/src/new.rs".to_owned(),
                        operation: CanonicalEffectOperationWireV1::Modify,
                    },
                    reason: digest("scope-reason"),
                    dependency_evidence: vec![digest("scope-dependency")],
                    created_at_unix_ms: 0,
                    expires_at_unix_ms: MAX_JCS_SAFE_INTEGER,
                    idempotency: digest("scope-idempotency"),
                    limitations: vec![digest("scope-limitation")],
                },
            ),
        };
        write_executor_response(path, &response);
    }

    fn write_readjudication_executor(path: &Path, custody: &DocketCustodyWireV1) {
        let response = ExecutorOutcomeWireV1 {
            attempt: custody.attempt.clone(),
            marker: custody.executor_marker.clone(),
            receipt: digest("readjudication-receipt"),
            outcome: ExecutorOutcomeClassWireV1::ReadjudicationRequired,
            effect_journal: vec![],
            immutable_work_checkpoint: None,
            governed_repair: Some(
                ExecutorGovernedRepairRequirementWireV1::ReadjudicationRequired {
                    question: digest("question"),
                    evidence_census: vec![digest("evidence")],
                    diagnostic_census: vec![digest("diagnostic")],
                    bounded_alternatives: vec![digest("alternative")],
                    unresolved_facts: vec![digest("fact")],
                    adjudication_scope: CanonicalEffectScopeWireV1 {
                        schema: "ag.governed-loop.canonical-effect-scope/v1".to_owned(),
                        effect_class: "repository-read/v1".to_owned(),
                        resources: vec![CanonicalEffectResourceWireV1 {
                            resource: "repository".to_owned(),
                            path: "crates/nq-store/src/lib.rs".to_owned(),
                            operations: vec![CanonicalEffectOperationWireV1::Read],
                        }],
                    },
                    created_at_unix_ms: 0,
                    expires_at_unix_ms: MAX_JCS_SAFE_INTEGER,
                    idempotency: digest("readjudication-idempotency"),
                    limitations: vec![digest("readjudication-limitation")],
                },
            ),
        };
        write_executor_response(path, &response);
    }

    fn write_executor_response(path: &Path, response: &ExecutorOutcomeWireV1) {
        std::fs::write(
            path.with_extension("response"),
            serde_json::to_string(response).unwrap(),
        )
        .unwrap();
    }

    fn write_static_program(path: &Path, output: &str) {
        let escaped = output.replace('\'', "'\\''");
        std::fs::write(
            path,
            format!("#!/bin/sh\ncat >/dev/null\nprintf '%s' '{escaped}'\n"),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn write_refusing_program(path: &Path) {
        std::fs::write(path, "#!/bin/sh\nexit 77\n").unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn write_counting_refusing_program(path: &Path, counter: &Path) {
        let counter = counter.display().to_string().replace('\'', "'\\''");
        std::fs::write(
            path,
            format!("#!/bin/sh\nprintf x >> '{counter}'\nexit 77\n"),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn b64_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let value = (u32::from(chunk[0]) << 16)
                | (chunk.get(1).copied().map_or(0, u32::from) << 8)
                | chunk.get(2).copied().map_or(0, u32::from);
            output.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
            output.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
            if chunk.len() > 1 {
                output.push(ALPHABET[((value >> 6) & 0x3f) as usize] as char);
            }
            if chunk.len() > 2 {
                output.push(ALPHABET[(value & 0x3f) as usize] as char);
            }
        }
        output
    }
}
