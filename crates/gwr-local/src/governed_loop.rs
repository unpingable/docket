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
pub const STANDING_REQUEST_SCHEMA_V1: &str = "docket.governed-loop.execution-standing-request/v1";
pub const STANDING_RESOLUTION_SCHEMA_V1: &str =
    "docket.governed-loop.execution-standing-resolution/v1";

const SIGNATURE_PREFIX_V2: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v2\0";
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "record", rename_all = "snake_case")]
pub enum DocketExecutionResponseWireV1 {
    Custody(DocketCustodyWireV1),
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

/// Authenticates the exact AG issuance bytes against explicit Docket trust.
pub fn verify_signed_issuance(
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
) -> Result<(SignedIssuanceEnvelopeWireV1, AgIssuanceWireV2), String> {
    let envelope: SignedIssuanceEnvelopeWireV1 = strict_json(envelope_bytes, "issuance-envelope")?;
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
    validate_issuance(&issuance)?;
    let canonical_value: serde_json::Value = strict_json(&body, "issuance-canonical-value")?;
    let canonical = serde_json::to_vec(&canonical_value)
        .map_err(|error| format!("issuance-canonical:{error}"))?;
    if canonical != body {
        return Err("governed-issuance-body-not-canonical".to_owned());
    }
    Ok((envelope, issuance))
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
    let (envelope, issuance) = verify_signed_issuance(envelope_bytes, trust_bytes)?;
    let mut store = GovernedCustodyStoreV1::open(database)?;
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
    let prepared_executor = prepare_executor(executor, executor_config, &issuance.work)?;
    let executor_binding = prepared_executor.binding.clone();
    verify_starting_checkpoint(&issuance, checkpoint_verifier, now)?;
    let standing: ExecutionStandingResolutionV1 = invoke_json(
        standing_resolver,
        &[],
        &ExecutionStandingRequestV1 {
            schema: STANDING_REQUEST_SCHEMA_V1.to_owned(),
            issuance: issuance.clone(),
            now_unix_ms: now,
        },
    )?;
    validate_standing(&issuance, &standing, now)?;
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
        return Err("governed-instrument-substitution".to_owned());
    }
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
    });
    let canonical =
        serde_json::to_vec(&basis).map_err(|error| format!("governed-issuance-basis:{error}"))?;
    let expected = hash_domain("ag.governed-loop.issuance/v2", &canonical);
    if expected != issuance.issuance {
        return Err("governed-issuance-identity-mismatch".to_owned());
    }
    Ok(())
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
    let Some(checkpoint) = &issuance.governed_repair_checkpoint else {
        return Ok(());
    };
    validate_checkpoint_evidence(checkpoint)?;
    let verifier = verifier.ok_or_else(|| "governed-checkpoint-verifier-required".to_owned())?;
    let result: CheckpointVerificationResultWireV1 = invoke_json(
        verifier,
        &[],
        &CheckpointVerificationRequestWireV1 {
            schema: "docket.governed-repair.checkpoint-verification-request/v1".to_owned(),
            issuance: issuance.issuance.clone(),
            checkpoint: checkpoint.clone(),
        },
    )?;
    if result.schema != "docket.governed-repair.checkpoint-verification/v1"
        || result.issuance != issuance.issuance
        || result.checkpoint != *checkpoint
        || result.status != CheckpointVerificationStatusWireV1::Current
        || result.verified_at_unix_ms > now_unix_ms
        || now_unix_ms >= result.expires_at_unix_ms
    {
        return Err("governed-checkpoint-verification-mismatch".to_owned());
    }
    require_digest(&result.verification, "checkpoint verification")
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

fn invoke_json<I: Serialize + ?Sized, O: DeserializeOwned>(
    program: &Path,
    arguments: &[&str],
    input: &I,
) -> Result<O, String> {
    let bytes = serde_json::to_vec(input).map_err(|error| format!("process-request:{error}"))?;
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("process-spawn:{}:{error}", program.display()))?;
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

    struct Fixture {
        root: std::path::PathBuf,
        database: std::path::PathBuf,
        trust: Vec<u8>,
        envelope: Vec<u8>,
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
        });
        issuance.issuance = hash_domain(
            "ag.governed-loop.issuance/v2",
            &serde_json::to_vec(&basis).unwrap(),
        );
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
            envelope: serde_json::to_vec(&envelope).unwrap(),
            issuance,
            custody,
            standing_program,
            executor_program,
        }
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
        assert_eq!(
            accept(
                &substituted.database,
                &substituted.envelope,
                &substituted.trust,
                &substituted.standing_program,
                &substituted.executor_program,
                &substituted.root.join("executor-config"),
            )
            .unwrap_err(),
            "governed-instrument-substitution"
        );
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
                "custody",
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
