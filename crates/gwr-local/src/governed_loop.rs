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
use rusqlite::{params, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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

#[cfg(test)]
thread_local! {
    /// Logical process-loss seam used only to prove reopen behaviour after an
    /// executor response exists in memory but before Docket seals it. This is
    /// not a claim about physical power-loss durability.
    static CRASH_AFTER_EXECUTOR_RESULT_BEFORE_SEAL: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}
pub const STANDING_REQUEST_SCHEMA_V1: &str = "docket.governed-loop.execution-standing-request/v1";
pub const STANDING_RESOLUTION_SCHEMA_V1: &str =
    "docket.governed-loop.execution-standing-resolution/v1";

const SIGNATURE_PREFIX_V2: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v2\0";
const MAX_JCS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_EXECUTOR_PROGRAM_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXECUTOR_CONFIG_BYTES: u64 = 512 * 1024 * 1024;
static NEXT_EXECUTOR_SNAPSHOT: AtomicU64 = AtomicU64::new(1);

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
    pub content_manifest: String,
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
    pub governed_repair_checkpoint: Option<GovernedRepairCheckpointEvidenceWireV1>,
    pub observation: String,
    pub standing_resolution: String,
    pub admission_decision: AdmissionDecisionWireV1,
    pub mandate: String,
    pub spend: String,
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
    pub immutable_work_checkpoint: Option<ImmutableWorkCheckpointWireV1>,
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
#[serde(tag = "status", content = "record", rename_all = "snake_case")]
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
    pub settled_at_unix_ms: u64,
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

fn authenticate_signed_issuance(
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
) -> Result<(SignedIssuanceEnvelopeWireV1, AgIssuanceWireV2, Vec<u8>), String> {
    let envelope: SignedIssuanceEnvelopeWireV1 = strict_json(envelope_bytes, "issuance-envelope")?;
    let canonical_envelope = serde_json::to_vec(
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
    let canonical = serde_json::to_vec(&canonical_value)
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

/// Reconciles one already-custodied issuance.  The executor command receives
/// the explicit `reconcile` operation; this path never calls `execute`.
pub fn reconcile(
    database: &Path,
    issuance: &str,
    expected_attempt: Option<&str>,
    executor: &Path,
    executor_config: &Path,
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
    if let Some(result) = governed_repair::read_sealed_result(&store.connection, issuance)? {
        require_result_custody(&result, &record.custody)?;
        return Ok(DocketReconciliationWireV1::GovernedRepairRequired {
            custody: record.custody,
            result: Box::new(result),
        });
    }
    if expected_attempt.is_some_and(|expected| expected != record.custody.attempt) {
        return Err("governed-reconciliation-attempt-substitution".to_owned());
    }
    if record.status == "settled" {
        return response(record);
    }

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
    response(record)
}

fn response(record: CustodyRecordV1) -> Result<DocketReconciliationWireV1, String> {
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

struct GovernedCustodyStoreV1 {
    connection: Connection,
}

impl GovernedCustodyStoreV1 {
    fn open(database: &Path) -> Result<Self, String> {
        let connection =
            Connection::open(database).map_err(|error| format!("governed-custody-open:{error}"))?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|error| format!("governed-custody-foreign-keys:{error}"))?;
        connection
            .pragma_update(None, "busy_timeout", 5_000_u32)
            .map_err(|error| format!("governed-custody-busy-timeout:{error}"))?;
        Ok(Self { connection })
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
                        settlement,receipt,outcome,settled_at,reconciliation,indeterminate_evidence
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
                    let signed_body_b64: String = row.get(0)?;
                    let body = b64_decode(&signed_body_b64).map_err(|error| sql_decode(&error))?;
                    let body_record: AgIssuanceWireV2 = serde_json::from_slice(&body)
                        .map_err(|error| sql_decode(&format!("governed issuance body: {error}")))?;
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
                    let known = match (&settlement_ref, &receipt, &outcome, settled_at) {
                        (Some(settlement), Some(receipt), Some(outcome), Some(at)) => {
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
                                settled_at_unix_ms: read_u64(at, 30)?,
                            })
                        }
                        (None, None, None, None) => None,
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
                let settlement = hash_domain(
                    "docket.governed-loop.settlement/v1",
                    format!("{issuance}:{}:{}:{known}", custody.attempt, outcome.receipt)
                        .as_bytes(),
                );
                let tx = self
                    .connection
                    .transaction()
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
                let changed = tx
                    .execute(
                        "UPDATE governed_loop_attempt
                         SET status='settled',settlement=?1,receipt=?2,outcome=?3,settled_at=?4
                         WHERE issuance=?5 AND attempt=?6 AND executor_marker=?7
                           AND status IN ('accepted','indeterminate')
                           AND NOT EXISTS (
                             SELECT 1 FROM governed_repair_checkpoint
                             WHERE governed_repair_checkpoint.issuance=governed_loop_attempt.issuance
                           )",
                        params![
                            settlement,
                            outcome.receipt,
                            known,
                            u64_to_i64(at)?,
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
            return if status == "indeterminate" {
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
    let canonical = serde_json::to_vec(
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
            let outcome = match settlement.outcome {
                KnownOutcomeWireV1::Success => "success",
                KnownOutcomeWireV1::Failure => "failure",
            };
            let expected = hash_domain(
                "docket.governed-loop.settlement/v1",
                format!(
                    "{}:{}:{}:{outcome}",
                    record.issuance.issuance, record.custody.attempt, settlement.receipt
                )
                .as_bytes(),
            );
            if settlement.settlement != expected {
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
    require_uuid(&issuance.key.occurrence)?;
    if issuance.work_schema.is_empty()
        || issuance.work_schema.len() > 128
        || !issuance.work_schema.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
    {
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
    let basis = serde_json::json!({
        "key": {
            "campaign": issuance.key.campaign,
            "occurrence": issuance.key.occurrence,
        },
        "mandate": issuance.mandate,
        "observation": issuance.observation,
        "admission_decision": issuance.admission_decision,
        "program": issuance.program,
        "proposal": issuance.proposal,
        "effect_scope": issuance.effect_scope,
        "effect_scope_digest": issuance.effect_scope_digest,
        "governed_repair_checkpoint": issuance.governed_repair_checkpoint,
        "spend": issuance.spend,
        "standing_resolution": issuance.standing_resolution,
        "subject": issuance.subject,
        "work": issuance.work,
        "work_schema": issuance.work_schema,
        "nonclaims": issuance.nonclaims,
        "expires_at_unix_ms": issuance.expires_at_unix_ms,
    });
    let canonical =
        serde_json::to_vec(&basis).map_err(|error| format!("governed-issuance-basis:{error}"))?;
    let expected = hash_domain("ag.governed-loop.issuance/v2", &canonical);
    if expected != issuance.issuance {
        return Err("governed-issuance-identity-mismatch".to_owned());
    }
    Ok(())
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

fn strict_json<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("{label}-json:{error}"))
}

fn prepare_executor(
    program: &Path,
    config: &Path,
    expected_plan: &str,
) -> Result<PreparedExecutorV1, String> {
    require_digest(expected_plan, "executor plan")?;
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
    let bytes = serde_json::to_vec(input).map_err(|error| format!("process-request:{error}"))?;
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
    i64::try_from(value).map_err(|_| "governed-clock-out-of-range".to_owned())
}

fn read_u64(value: i64, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| sql_decode(&format!("negative u64 column {column}")))
}

fn sql_decode(detail: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        std::io::Error::new(std::io::ErrorKind::InvalidData, detail.to_owned()).into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SqliteStore;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

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
            &serde_json::to_vec(&serde_json::to_value(&effect_scope).unwrap()).unwrap(),
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
        let body = serde_json::to_vec(&serde_json::to_value(&issuance).unwrap()).unwrap();
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
            expires_at_unix_ms: i64::MAX as u64,
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
        serde_json::to_vec(&serde_json::to_value(value).unwrap()).unwrap()
    }

    fn refresh_issuance_identity(issuance: &mut AgIssuanceWireV2) {
        let basis = serde_json::json!({
            "key": {
                "campaign": issuance.key.campaign,
                "occurrence": issuance.key.occurrence,
            },
            "mandate": issuance.mandate,
            "observation": issuance.observation,
            "program": issuance.program,
            "proposal": issuance.proposal,
            "effect_scope": issuance.effect_scope,
            "effect_scope_digest": issuance.effect_scope_digest,
            "governed_repair_checkpoint": issuance.governed_repair_checkpoint,
            "admission_decision": issuance.admission_decision,
            "spend": issuance.spend,
            "standing_resolution": issuance.standing_resolution,
            "subject": issuance.subject,
            "work": issuance.work,
            "work_schema": issuance.work_schema,
            "nonclaims": issuance.nonclaims,
            "expires_at_unix_ms": issuance.expires_at_unix_ms,
        });
        issuance.issuance = hash_domain(
            "ag.governed-loop.issuance/v2",
            &serde_json::to_vec(&basis).unwrap(),
        );
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
            expires_at_unix_ms: i64::MAX as u64,
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
        assert!(accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap_err()
        .starts_with("process-refused:"));
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
            expires_at_unix_ms: i64::MAX as u64,
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
            expires_at_unix_ms: i64::MAX as u64,
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
            content_manifest_identity: Some(digest("checkpoint-content-manifest")),
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
        std::fs::write(&response, output).unwrap();
        if path.exists() {
            return;
        }
        let response = response.display().to_string().replace('\'', "'\\''");
        let invocations = invocations.display().to_string().replace('\'', "'\\''");
        std::fs::write(
            path,
            format!(
                "#!/bin/sh\nif [ \"$1\" = plan-id ]; then cat \"$2\"; exit $?; fi\nif [ \"$1\" = execute ]; then cat >/dev/null; printf x >> '{invocations}'; cat '{response}'; exit $?; fi\nif [ \"$1\" = reconcile ]; then cat >/dev/null; cat '{response}'; exit $?; fi\nexit 64\n"
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
            &serde_json::to_vec(&serde_json::to_value(&delta).unwrap()).unwrap(),
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
                    expires_at_unix_ms: i64::MAX as u64,
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
                    expires_at_unix_ms: i64::MAX as u64,
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
