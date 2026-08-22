//! Docket-owned custody for canonical AG governed-loop issuances.
//!
//! This is intentionally a separate authority domain from AG admission,
//! campaign-stage standing, and executor idempotency.  An authenticated AG
//! issuance is exact evidence of an already-spent AG decision authorization.
//! Docket freshly resolves and consumes its own execution standing, assigns
//! one canonical attempt, persists custody before invoking mechanics, and is
//! the sole producer of the settlement AG may consume.

use ring::signature::{UnparsedPublicKey, ED25519};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SIGNED_ISSUANCE_SCHEMA_V1: &str = "ag.governed-loop.signed-issuance/v1";
pub const AG_ISSUANCE_SCHEMA_V1: &str = "ag.governed-loop.issuance/v1";
pub const CUSTODY_SCHEMA_V1: &str = "ag.governed-loop.docket-custody/v1";
pub const SETTLEMENT_SCHEMA_V1: &str = "ag.governed-loop.docket-settlement/v1";
pub const STANDING_REQUEST_SCHEMA_V1: &str = "docket.governed-loop.execution-standing-request/v1";
pub const STANDING_RESOLUTION_SCHEMA_V1: &str =
    "docket.governed-loop.execution-standing-resolution/v1";
pub const INSPECTION_SCHEMA_V1: &str = "docket.governed-loop.inspection/v1";

const SIGNATURE_PREFIX_V1: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v1\0";
const MAX_EXECUTOR_PROGRAM_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutorBindingV1 {
    identity: String,
    program_digest: String,
    plan: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceKeyWireV1 {
    pub campaign: String,
    pub occurrence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgIssuanceWireV1 {
    pub schema: String,
    pub issuance: String,
    pub key: OccurrenceKeyWireV1,
    pub program: String,
    pub proposal: String,
    pub work_schema: String,
    pub work: String,
    pub subject: String,
    pub scope: String,
    pub observation: String,
    pub standing_resolution: String,
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
    pub issuance: AgIssuanceWireV1,
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
    pub scope: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorOutcomeClassWireV1 {
    Success,
    Failure,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorOutcomeWireV1 {
    pub attempt: String,
    pub marker: String,
    pub receipt: String,
    pub outcome: ExecutorOutcomeClassWireV1,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedRecordStatusV1 {
    Accepted,
    Settled,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRecordInspectionV1 {
    pub issuance: AgIssuanceWireV1,
    pub authentication: IssuanceAuthenticationWireV1,
    pub custody: DocketCustodyWireV1,
    pub status: GovernedRecordStatusV1,
    pub settlement: Option<DocketSettlementWireV1>,
    pub indeterminate: Option<IndeterminateOutcomeWireV1>,
    pub executor_binding: String,
    pub executor_program_digest: String,
    pub executor_plan: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedLoopInspectionV1 {
    pub schema: String,
    pub requested_issuance: String,
    pub record: Option<GovernedRecordInspectionV1>,
}

#[derive(Clone, Debug)]
struct CustodyRecordV1 {
    issuance: AgIssuanceWireV1,
    custody: DocketCustodyWireV1,
    signed_body_b64: String,
    authentication: IssuanceAuthenticationWireV1,
    executor_binding: String,
    executor_program_digest: String,
    executor_plan: String,
    status: String,
    settlement: Option<DocketSettlementWireV1>,
    indeterminate: Option<IndeterminateOutcomeWireV1>,
}

/// Authenticates the exact AG issuance bytes against explicit Docket trust.
pub fn verify_signed_issuance(
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
) -> Result<(SignedIssuanceEnvelopeWireV1, AgIssuanceWireV1), String> {
    let envelope: SignedIssuanceEnvelopeWireV1 = strict_json(envelope_bytes, "issuance-envelope")?;
    if envelope.schema != SIGNED_ISSUANCE_SCHEMA_V1 {
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
    let mut signed = Vec::with_capacity(SIGNATURE_PREFIX_V1.len() + body.len());
    signed.extend_from_slice(SIGNATURE_PREFIX_V1);
    signed.extend_from_slice(&body);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signed, &signature)
        .map_err(|_| "governed-issuance-signature-invalid".to_owned())?;
    let issuance: AgIssuanceWireV1 = strict_json(&body, "issuance-body")?;
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
) -> Result<DocketCustodyWireV1, String> {
    let (envelope, issuance) = verify_signed_issuance(envelope_bytes, trust_bytes)?;
    let mut store = GovernedCustodyStoreV1::open(database)?;
    if let Some(existing) = store.get(&issuance.issuance)? {
        require_same_envelope(&existing, &envelope, &issuance)?;
        return Ok(existing.custody);
    }

    let executor_binding = resolve_executor_binding(executor, executor_config, &issuance.work)?;

    let now = now_unix_ms()?;
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
                return Ok(existing.custody);
            }
            return Err(error);
        }
    }

    // The custody transaction above is committed before any mechanics call.
    // A process loss here leaves an exact accepted attempt and can never make
    // this issuance dispatchable as a second attempt.
    if let Err(error) = require_executor_binding(executor, executor_config, &executor_binding) {
        store.record_indeterminate(
            &issuance.issuance,
            &custody,
            &hash_domain(
                "docket.governed-loop.executor-binding-changed/v1",
                error.as_bytes(),
            ),
        )?;
        return Ok(custody);
    }
    let dispatch = executor_dispatch(&issuance, &custody);
    let config = executor_config
        .to_str()
        .ok_or_else(|| "executor-config-path-not-utf8".to_owned())?;
    match invoke_json::<_, ExecutorOutcomeWireV1>(executor, &["execute", config], &dispatch) {
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
    Ok(custody)
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
    if expected_attempt.is_some_and(|expected| expected != record.custody.attempt) {
        return Err("governed-reconciliation-attempt-substitution".to_owned());
    }
    if record.status == "settled" {
        return response(record);
    }

    require_executor_binding(
        executor,
        executor_config,
        &ExecutorBindingV1 {
            identity: record.executor_binding.clone(),
            program_digest: record.executor_program_digest.clone(),
            plan: record.executor_plan.clone(),
        },
    )?;

    let dispatch = executor_dispatch(&record.issuance, &record.custody);
    let config = executor_config
        .to_str()
        .ok_or_else(|| "executor-config-path-not-utf8".to_owned())?;
    match invoke_json::<_, ExecutorOutcomeWireV1>(executor, &["reconcile", config], &dispatch) {
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
    record = store
        .get(issuance)?
        .ok_or_else(|| "governed-custody-disappeared".to_owned())?;
    response(record)
}

/// Returns Docket's exact persisted governed-loop record for one issuance.
/// This opens the existing database read-only, invokes no resolver or
/// executor, and never creates or updates state.
pub fn inspect(database: &Path, issuance: &str) -> Result<GovernedLoopInspectionV1, String> {
    require_digest(issuance, "issuance")?;
    let mut store = GovernedCustodyStoreV1::open_read_only(database)?;
    let Some(record) = store.get(issuance)? else {
        return Ok(GovernedLoopInspectionV1 {
            schema: INSPECTION_SCHEMA_V1.to_owned(),
            requested_issuance: issuance.to_owned(),
            record: None,
        });
    };
    let status = match record.status.as_str() {
        "accepted" => GovernedRecordStatusV1::Accepted,
        "settled" => GovernedRecordStatusV1::Settled,
        "indeterminate" => GovernedRecordStatusV1::Indeterminate,
        _ => return Err("governed-custody-status-corrupt".to_owned()),
    };
    Ok(GovernedLoopInspectionV1 {
        schema: INSPECTION_SCHEMA_V1.to_owned(),
        requested_issuance: issuance.to_owned(),
        record: Some(GovernedRecordInspectionV1 {
            issuance: record.issuance,
            authentication: record.authentication,
            custody: record.custody,
            status,
            settlement: record.settlement,
            indeterminate: record.indeterminate,
            executor_binding: record.executor_binding,
            executor_program_digest: record.executor_program_digest,
            executor_plan: record.executor_plan,
        }),
    })
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
    issuance: &AgIssuanceWireV1,
    custody: &DocketCustodyWireV1,
) -> ExecutorDispatchWireV1 {
    ExecutorDispatchWireV1 {
        attempt: custody.attempt.clone(),
        marker: custody.executor_marker.clone(),
        work_schema: issuance.work_schema.clone(),
        work: issuance.work.clone(),
        subject: issuance.subject.clone(),
        scope: issuance.scope.clone(),
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

    fn open_read_only(database: &Path) -> Result<Self, String> {
        let connection = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| format!("governed-custody-read-open:{error}"))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| format!("governed-custody-read-timeout:{error}"))?;
        Ok(Self { connection })
    }

    fn insert_custody(
        &mut self,
        envelope: &SignedIssuanceEnvelopeWireV1,
        issuance: &AgIssuanceWireV1,
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
                  executor_program_digest,executor_plan,accepted_at,status)
                 VALUES
                 (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,
                  ?19,?20,?21,?22,?23,?24,?25,?26,'accepted')",
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
                    issuance.scope,
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
                        executor_program_digest,executor_plan,accepted_at,status,
                        settlement,receipt,outcome,settled_at,reconciliation,indeterminate_evidence
                 FROM governed_loop_attempt WHERE issuance=?1",
                [issuance],
                |row| {
                    let accepted_at = read_u64(row.get::<_, i64>(24)?, 24)?;
                    let status: String = row.get(25)?;
                    let settlement_ref: Option<String> = row.get(26)?;
                    let receipt: Option<String> = row.get(27)?;
                    let outcome: Option<String> = row.get(28)?;
                    let settled_at: Option<i64> = row.get(29)?;
                    let reconciliation: Option<String> = row.get(30)?;
                    let evidence: Option<String> = row.get(31)?;
                    let issuance_record = AgIssuanceWireV1 {
                        schema: AG_ISSUANCE_SCHEMA_V1.to_owned(),
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
                        scope: row.get(12)?,
                        observation: row.get(13)?,
                        standing_resolution: row.get(14)?,
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
                                settled_at_unix_ms: read_u64(at, 29)?,
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
                        signed_body_b64: row.get(0)?,
                        authentication: IssuanceAuthenticationWireV1 {
                            issuer_principal: row.get(1)?,
                            signer_key_id: row.get(2)?,
                            signer_public_key: row.get(3)?,
                            signature: row.get(4)?,
                        },
                        executor_binding: row.get(21)?,
                        executor_program_digest: row.get(22)?,
                        executor_plan: row.get(23)?,
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
        require_digest(&outcome.receipt, "executor receipt")?;
        match outcome.outcome {
            ExecutorOutcomeClassWireV1::Success | ExecutorOutcomeClassWireV1::Failure => {
                let known = match outcome.outcome {
                    ExecutorOutcomeClassWireV1::Success => "success",
                    ExecutorOutcomeClassWireV1::Failure => "failure",
                    ExecutorOutcomeClassWireV1::Indeterminate => unreachable!(),
                };
                let settlement = hash_domain(
                    "docket.governed-loop.settlement/v1",
                    format!("{issuance}:{}:{}:{known}", custody.attempt, outcome.receipt)
                        .as_bytes(),
                );
                let changed = self
                    .connection
                    .execute(
                        "UPDATE governed_loop_attempt
                         SET status='settled',settlement=?1,receipt=?2,outcome=?3,settled_at=?4
                         WHERE issuance=?5 AND attempt=?6 AND executor_marker=?7
                           AND status IN ('accepted','indeterminate')",
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
                    let existing = self
                        .get(issuance)?
                        .ok_or_else(|| "governed-settlement-attempt-missing".to_owned())?;
                    if existing.settlement.as_ref().is_some_and(|value| {
                        value.receipt == outcome.receipt
                            && value.outcome
                                == match known {
                                    "success" => KnownOutcomeWireV1::Success,
                                    _ => KnownOutcomeWireV1::Failure,
                                }
                    }) {
                        return Ok(());
                    }
                    return Err("governed-settlement-substitution".to_owned());
                }
                Ok(())
            }
            ExecutorOutcomeClassWireV1::Indeterminate => {
                self.record_indeterminate(issuance, custody, &outcome.receipt)
            }
        }
    }

    fn record_indeterminate(
        &mut self,
        issuance: &str,
        custody: &DocketCustodyWireV1,
        evidence: &str,
    ) -> Result<(), String> {
        require_digest(evidence, "indeterminate evidence")?;
        let reconciliation = hash_domain(
            "docket.governed-loop.reconciliation/v1",
            format!("{issuance}:{}:{evidence}", custody.attempt).as_bytes(),
        );
        let changed = self
            .connection
            .execute(
                "UPDATE governed_loop_attempt
                 SET status='indeterminate',reconciliation=?1,indeterminate_evidence=?2
                 WHERE issuance=?3 AND attempt=?4 AND executor_marker=?5
                   AND status='accepted'",
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
            let existing = self
                .get(issuance)?
                .ok_or_else(|| "governed-indeterminate-attempt-missing".to_owned())?;
            if existing.status == "settled" || existing.status == "indeterminate" {
                return Ok(());
            }
            return Err("governed-indeterminate-substitution".to_owned());
        }
        Ok(())
    }
}

fn validate_stored_record(record: &CustodyRecordV1) -> Result<(), String> {
    validate_issuance(&record.issuance)?;
    let body = b64_decode(&record.signed_body_b64)?;
    let public_key = b64_decode(&record.authentication.signer_public_key)?;
    let signature = b64_decode(&record.authentication.signature)?;
    let mut signed = Vec::with_capacity(SIGNATURE_PREFIX_V1.len() + body.len());
    signed.extend_from_slice(SIGNATURE_PREFIX_V1);
    signed.extend_from_slice(&body);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signed, &signature)
        .map_err(|_| "governed-stored-issuance-signature-invalid".to_owned())?;
    let parsed: AgIssuanceWireV1 = strict_json(&body, "stored-issuance-body")?;
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
        (&record.executor_plan, "stored executor plan"),
        (&record.executor_binding, "stored executor binding"),
    ] {
        require_digest(value, label)?;
    }
    let binding = serde_json::to_vec(&serde_json::json!({
        "plan": record.executor_plan,
        "program_digest": record.executor_program_digest,
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
    issuance: &AgIssuanceWireV1,
) -> Result<(), String> {
    if existing.issuance != *issuance
        || existing.signed_body_b64 != envelope.body_b64
        || existing.authentication != envelope.authentication
    {
        return Err("governed-issuance-immutable-rebind".to_owned());
    }
    Ok(())
}

fn validate_issuance(issuance: &AgIssuanceWireV1) -> Result<(), String> {
    if issuance.schema != AG_ISSUANCE_SCHEMA_V1 {
        return Err("governed-issuance-schema".to_owned());
    }
    for (value, label) in [
        (&issuance.issuance, "issuance"),
        (&issuance.key.campaign, "campaign"),
        (&issuance.program, "program"),
        (&issuance.proposal, "proposal"),
        (&issuance.work, "work"),
        (&issuance.subject, "subject"),
        (&issuance.scope, "scope"),
        (&issuance.observation, "observation"),
        (&issuance.standing_resolution, "standing resolution"),
        (&issuance.mandate, "mandate"),
        (&issuance.spend, "AG spend"),
    ] {
        require_digest(value, label)?;
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
        "program": issuance.program,
        "proposal": issuance.proposal,
        "scope": issuance.scope,
        "spend": issuance.spend,
        "standing_resolution": issuance.standing_resolution,
        "subject": issuance.subject,
        "work": issuance.work,
        "work_schema": issuance.work_schema,
    });
    let canonical =
        serde_json::to_vec(&basis).map_err(|error| format!("governed-issuance-basis:{error}"))?;
    let expected = hash_domain("ag.governed-loop.issuance/v1", &canonical);
    if expected != issuance.issuance {
        return Err("governed-issuance-identity-mismatch".to_owned());
    }
    Ok(())
}

fn validate_standing(
    issuance: &AgIssuanceWireV1,
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
        || standing.scope != issuance.scope
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

fn strict_json<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("{label}-json:{error}"))
}

fn resolve_executor_binding(
    program: &Path,
    config: &Path,
    expected_plan: &str,
) -> Result<ExecutorBindingV1, String> {
    require_digest(expected_plan, "executor plan")?;
    if !program.is_absolute() || !config.is_absolute() {
        return Err("governed-executor-path-not-absolute".to_owned());
    }
    let metadata = std::fs::symlink_metadata(program)
        .map_err(|error| format!("governed-executor-metadata:{}:{error}", program.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("governed-executor-not-regular-nonsymlink".to_owned());
    }
    if metadata.len() > MAX_EXECUTOR_PROGRAM_BYTES {
        return Err("governed-executor-program-too-large".to_owned());
    }
    let mut executable = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(program)
        .map_err(|error| format!("governed-executor-open:{}:{error}", program.display()))?;
    let opened_metadata = executable
        .metadata()
        .map_err(|error| format!("governed-executor-opened-metadata:{error}"))?;
    if !opened_metadata.is_file() || opened_metadata.len() != metadata.len() {
        return Err("governed-executor-file-raced".to_owned());
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened_metadata.len())
            .map_err(|_| "governed-executor-program-size-overflow".to_owned())?,
    );
    executable
        .read_to_end(&mut bytes)
        .map_err(|error| format!("governed-executor-read:{error}"))?;
    if bytes.len() as u64 != opened_metadata.len() {
        return Err("governed-executor-file-raced".to_owned());
    }
    let program_digest = hash_domain("docket.governed-loop.executor-program/v1", &bytes);
    let plan = invoke_plan_id(program, config)?;
    if plan != expected_plan {
        return Err("governed-executor-plan-substitution".to_owned());
    }
    let canonical = serde_json::to_vec(&serde_json::json!({
        "plan": plan,
        "program_digest": program_digest,
    }))
    .map_err(|error| format!("governed-executor-binding-canonical:{error}"))?;
    Ok(ExecutorBindingV1 {
        identity: hash_domain("docket.governed-loop.executor-binding/v1", &canonical),
        program_digest,
        plan,
    })
}

fn require_executor_binding(
    program: &Path,
    config: &Path,
    expected: &ExecutorBindingV1,
) -> Result<(), String> {
    let current = resolve_executor_binding(program, config, &expected.plan)?;
    if current != *expected {
        return Err("governed-executor-binding-substitution".to_owned());
    }
    Ok(())
}

fn invoke_plan_id(program: &Path, config: &Path) -> Result<String, String> {
    let output = Command::new(program)
        .arg("plan-id")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("executor-plan-id-spawn:{}:{error}", program.display()))?;
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
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: std::path::PathBuf,
        database: std::path::PathBuf,
        trust: Vec<u8>,
        envelope: Vec<u8>,
        issuance: AgIssuanceWireV1,
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

        let mut issuance = AgIssuanceWireV1 {
            schema: AG_ISSUANCE_SCHEMA_V1.to_owned(),
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
            scope: digest("scope"),
            observation: digest("observation"),
            standing_resolution: digest("ag-standing-resolution"),
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
            "scope": issuance.scope,
            "spend": issuance.spend,
            "standing_resolution": issuance.standing_resolution,
            "subject": issuance.subject,
            "work": issuance.work,
            "work_schema": issuance.work_schema,
        });
        issuance.issuance = hash_domain(
            "ag.governed-loop.issuance/v1",
            &serde_json::to_vec(&basis).unwrap(),
        );
        let body = serde_json::to_vec(&serde_json::to_value(&issuance).unwrap()).unwrap();
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let mut signed = SIGNATURE_PREFIX_V1.to_vec();
        signed.extend_from_slice(&body);
        let public_key = b64_encode(key.public_key().as_ref());
        let envelope = SignedIssuanceEnvelopeWireV1 {
            schema: SIGNED_ISSUANCE_SCHEMA_V1.to_owned(),
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
            scope: issuance.scope.clone(),
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
        assert_eq!(first.attempt, fixture.custody.attempt);
        assert_ne!(first.ag_spend, first.execution_standing);
        assert_ne!(first.execution_standing, first.executor_marker);

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
    fn read_only_inspection_retains_issuer_custody_and_outcome_without_mutation() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let accepted = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();

        let before = std::fs::metadata(&fixture.database).unwrap().len();
        let inspection = inspect(&fixture.database, &fixture.issuance.issuance).unwrap();
        let record = inspection.record.expect("accepted issuance is visible");
        assert_eq!(inspection.schema, INSPECTION_SCHEMA_V1);
        assert_eq!(inspection.requested_issuance, fixture.issuance.issuance);
        assert_eq!(record.issuance, fixture.issuance);
        assert_eq!(record.authentication.issuer_principal, "ag.test");
        assert_eq!(record.authentication.signer_key_id, "ag-test-key");
        assert_eq!(record.custody, accepted);
        assert_eq!(record.status, GovernedRecordStatusV1::Settled);
        assert!(record.settlement.is_some());
        assert!(record.indeterminate.is_none());
        assert_eq!(std::fs::metadata(&fixture.database).unwrap().len(), before);
    }

    #[test]
    fn read_only_inspection_refuses_a_missing_store_instead_of_creating_it() {
        let root = std::env::temp_dir().join(format!(
            "docket-governed-inspect-missing-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let database = root.join("missing.sqlite");
        let result = inspect(&database, &digest("missing-issuance"));
        assert!(result.is_err());
        assert!(!database.exists());
        std::fs::remove_dir_all(root).unwrap();
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
        assert_eq!(repeated_unknown, unknown);

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
            scope: substituted.issuance.scope.clone(),
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
