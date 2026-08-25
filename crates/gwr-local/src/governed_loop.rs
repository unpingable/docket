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
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
#[cfg(target_os = "freebsd")]
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
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
pub const INSPECTION_SCHEMA_V2: &str = "docket.governed-loop.inspection/v2";
pub const INSPECTION_SCHEMA_V3: &str = "docket.governed-loop.inspection/v3";
pub const INSPECTION_SCHEMA_V4: &str = "docket.governed-loop.inspection/v4";
pub const EXECUTOR_SELECTION_SCHEMA_V1: &str = "docket.governed-loop.executor-selection/v1";
pub const DESCRIPTOR_INVOCATION_V1: &str = "freebsd_fexecve_preopened_descriptor";
pub const REPRESENTATION_INVOCATION_V1: &str = "freebsd_fexecve_private_unlinked_regular_vnode_v1";
pub const STANDING_RESOLVER_LAUNCH_RECORD_SCHEMA_V1: &str =
    "civil.docket.standing-resolver-launch-record/v1";
pub const STANDING_RESOLVER_LAUNCH_RECORD_SCHEMA_V2: &str =
    "civil.docket.standing-resolver-launch-record/v2";
pub const STANDING_RESOLVER_INPUT_SET_SCHEMA_V1: &str =
    "civil.docket.standing-resolver-input-set/v1";

const SIGNATURE_PREFIX_V1: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v1\0";
const MAX_EXECUTOR_PROGRAM_BYTES: u64 = 512 * 1024 * 1024;
// The qualified external resolver is a narrowly scoped static helper. 16 MiB
// leaves ample native-build headroom without importing the executor's broader
// 512 MiB bound into this bootstrap surface.
#[cfg(target_os = "freebsd")]
const MAX_STANDING_RESOLVER_BYTES: u64 = 16 * 1024 * 1024;

/// FreeBSD-only exact-content custody for the external standing authority.
///
/// This is deployment/runtime configuration, not an AG work field and not a
/// judgment that the selected resolver is trustworthy. The expected digest
/// identifies the exact resolver content Docket is willing to invoke for this
/// runtime; the upstream process retains all standing semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandingResolverExactCustodyV1 {
    pub expected_content: String,
    pub journal: PathBuf,
}

/// M10 exact semantic-input closure for the already-custodied resolver.
///
/// TTL and custody directory are deployment/runtime inputs. They do not
/// become AG work semantics: Docket binds and transports their exact values to
/// the external standing authority without interpreting the standing result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandingResolverExactCustodyV2 {
    pub expected_content: String,
    pub journal: PathBuf,
    pub ttl_ms: u64,
    pub custody_directory: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandingResolverCustodyDirectoryProjectionV1 {
    pub object_type: String,
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u64,
    pub semantic_role: String,
    pub access_method: String,
    pub inherited_fd: i32,
    pub request_entry: String,
    pub response_entry: String,
    pub update_semantics: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandingResolverInputSetV1 {
    pub schema: String,
    pub request_sha256: String,
    pub now_unix_ms: u64,
    pub ttl_ms: u64,
    pub time_source: String,
    pub custody_directory_locator: String,
    pub custody_directory_projection: StandingResolverCustodyDirectoryProjectionV1,
    pub argv: Vec<String>,
    pub environment: Vec<String>,
    pub working_directory: String,
    pub inherited_descriptor_profile: String,
    pub umask_octal: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
enum StandingResolverLaunchStageV1 {
    Prepared,
    Refused,
    Entered,
    Completed,
    Accepted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StandingResolverLaunchRecordV1 {
    schema: String,
    launch: String,
    sequence: u8,
    stage: StandingResolverLaunchStageV1,
    prior_record_sha256: Option<String>,
    issuance: String,
    request_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    standing_input_set_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    standing_input_set: Option<StandingResolverInputSetV1>,
    expected_resolver_content: String,
    source_candidate_content: Option<String>,
    private_representation_content: Option<String>,
    representation_method: Option<String>,
    representation_device: Option<u64>,
    representation_inode: Option<u64>,
    representation_links: Option<u64>,
    representation_authority: Option<ExecutionRepresentationAuthorityClosureWireV1>,
    invocation_method: String,
    content_match: Option<bool>,
    descriptor_exec_accepted: Option<bool>,
    stdout_sha256: Option<String>,
    stderr_sha256: Option<String>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    exec_errno: Option<i32>,
    standing_resolution: Option<String>,
    standing_currentness: Option<String>,
    execution_standing: Option<String>,
    docket_attempt: Option<String>,
    executor_marker: Option<String>,
    refusal: Option<String>,
}

struct StandingResolverJournalV1 {
    file: File,
    launch: String,
    issuance: String,
    request_sha256: String,
    schema: String,
    standing_input_set_sha256: Option<String>,
    standing_input_set: Option<StandingResolverInputSetV1>,
    expected_resolver_content: String,
    sequence: u8,
    prior_record_sha256: Option<String>,
}

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
struct StandingResolverInvocationV1 {
    journal: StandingResolverJournalV1,
    source_candidate_content: String,
    representation_content: String,
    representation_method: String,
    representation_device: u64,
    representation_inode: u64,
    representation_links: u64,
    representation_authority: ExecutionRepresentationAuthorityClosureWireV1,
    output: gwr_freebsd_exec::DescriptorExecOutput,
}

#[cfg(target_os = "freebsd")]
struct PreparedStandingResolverInputsV1 {
    input_set: StandingResolverInputSetV1,
    input_set_sha256: String,
    custody_directory: File,
    environment: Vec<CString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutorBindingV1 {
    identity: String,
    program_digest: String,
    plan: String,
    program_content: Option<String>,
    expected_content: Option<String>,
    representation_content: Option<String>,
    representation_method: Option<String>,
    representation_authority: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRepresentationAuthorityClosureWireV1 {
    pub schema: String,
    pub creator: String,
    pub representation_method: String,
    pub writer_descriptors_created: u16,
    pub writer_descriptors_duplicated: u16,
    pub writer_descriptors_closed_before_measurement: u16,
    pub writable_descriptors_surviving_finalization: u16,
    pub writable_descriptors_inherited: u16,
    pub representation_links_at_finalization: u64,
    pub surviving_descriptor_access: String,
    pub surviving_rights_profile: String,
    pub direct_write_probe_errno: i32,
    pub write_reacquisition_method: String,
    pub write_reacquisition_errno: i32,
    pub finalization_sequence: u8,
    pub measurement_sequence: u8,
    pub invocation_sequence: u8,
    pub descriptor_transfer: String,
}

#[derive(Debug)]
struct ResolvedExecutorV1 {
    binding: ExecutorBindingV1,
    opened_program: Option<File>,
}

struct PreparedExecutionRepresentation {
    executable: File,
    content: Option<String>,
    method: Option<String>,
    authority: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutorSelectionWireV1 {
    schema: String,
    expected_content: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_program_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_expected_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_representation_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_representation_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_representation_authority: Option<ExecutionRepresentationAuthorityClosureWireV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_invocation_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_launch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_dispatch_content: Option<String>,
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
    executor_program_content: Option<String>,
    executor_expected_content: Option<String>,
    executor_representation_content: Option<String>,
    executor_representation_method: Option<String>,
    executor_representation_authority: Option<String>,
    executor_invocation_method: Option<String>,
    executor_launch: Option<String>,
    executor_dispatch_content: Option<String>,
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

impl StandingResolverJournalV1 {
    #[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
    fn create(
        path: &Path,
        launch: String,
        issuance: String,
        request_sha256: String,
        expected_resolver_content: String,
    ) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("standing-resolver-journal-path-not-absolute".to_owned());
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| format!("standing-resolver-journal-create:{error}"))?;
        Ok(Self {
            file,
            launch,
            issuance,
            request_sha256,
            schema: STANDING_RESOLVER_LAUNCH_RECORD_SCHEMA_V1.to_owned(),
            standing_input_set_sha256: None,
            standing_input_set: None,
            expected_resolver_content,
            sequence: 0,
            prior_record_sha256: None,
        })
    }

    #[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
    fn create_v2(
        path: &Path,
        launch: String,
        issuance: String,
        request_sha256: String,
        expected_resolver_content: String,
        standing_input_set_sha256: String,
        standing_input_set: StandingResolverInputSetV1,
    ) -> Result<Self, String> {
        let mut journal = Self::create(
            path,
            launch,
            issuance,
            request_sha256,
            expected_resolver_content,
        )?;
        journal.schema = STANDING_RESOLVER_LAUNCH_RECORD_SCHEMA_V2.to_owned();
        journal.standing_input_set_sha256 = Some(standing_input_set_sha256);
        journal.standing_input_set = Some(standing_input_set);
        Ok(journal)
    }

    fn base_record(&self, stage: StandingResolverLaunchStageV1) -> StandingResolverLaunchRecordV1 {
        StandingResolverLaunchRecordV1 {
            schema: self.schema.clone(),
            launch: self.launch.clone(),
            sequence: 0,
            stage,
            prior_record_sha256: None,
            issuance: self.issuance.clone(),
            request_sha256: self.request_sha256.clone(),
            standing_input_set_sha256: self.standing_input_set_sha256.clone(),
            standing_input_set: self.standing_input_set.clone(),
            expected_resolver_content: self.expected_resolver_content.clone(),
            source_candidate_content: None,
            private_representation_content: None,
            representation_method: None,
            representation_device: None,
            representation_inode: None,
            representation_links: None,
            representation_authority: None,
            invocation_method: REPRESENTATION_INVOCATION_V1.to_owned(),
            content_match: None,
            descriptor_exec_accepted: None,
            stdout_sha256: None,
            stderr_sha256: None,
            exit_code: None,
            signal: None,
            exec_errno: None,
            standing_resolution: None,
            standing_currentness: None,
            execution_standing: None,
            docket_attempt: None,
            executor_marker: None,
            refusal: None,
        }
    }

    fn append(&mut self, mut record: StandingResolverLaunchRecordV1) -> Result<(), String> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| "standing-resolver-journal-sequence-overflow".to_owned())?;
        if self.sequence > 8 {
            return Err("standing-resolver-journal-record-bound".to_owned());
        }
        record.sequence = self.sequence;
        record.prior_record_sha256 = self.prior_record_sha256.clone();
        let bytes = serde_jcs::to_vec(&record)
            .map_err(|error| format!("standing-resolver-journal-canonical:{error}"))?;
        if bytes.len() > 128 * 1024 {
            return Err("standing-resolver-journal-record-size".to_owned());
        }
        self.file
            .write_all(&bytes)
            .and_then(|()| self.file.write_all(b"\n"))
            .and_then(|()| self.file.sync_all())
            .map_err(|error| format!("standing-resolver-journal-write:{error}"))?;
        self.prior_record_sha256 = Some(file_content_digest(&bytes));
        Ok(())
    }

    fn append_refusal(&mut self, refusal: &str) -> Result<(), String> {
        let mut record = self.base_record(StandingResolverLaunchStageV1::Refused);
        record.refusal = Some(refusal.to_owned());
        self.append(record)
    }

    fn append_accepted(
        &mut self,
        standing: &ExecutionStandingResolutionV1,
        custody: &DocketCustodyWireV1,
    ) -> Result<(), String> {
        let mut record = self.base_record(StandingResolverLaunchStageV1::Accepted);
        record.standing_resolution = Some(standing.resolution.clone());
        record.standing_currentness = Some(standing.currentness.clone());
        record.execution_standing = Some(standing.execution_standing.clone());
        record.docket_attempt = Some(custody.attempt.clone());
        record.executor_marker = Some(custody.executor_marker.clone());
        self.append(record)
    }
}

fn decode_exact_standing_response(
    invocation: &mut StandingResolverInvocationV1,
    issuance: &AgIssuanceWireV1,
    now: u64,
) -> Result<ExecutionStandingResolutionV1, String> {
    if !invocation.output.descriptor_exec_accepted {
        return Err(format!(
            "standing-resolver-descriptor-invocation-refused:{}",
            invocation.output.exec_errno.unwrap_or(libc::EIO)
        ));
    }
    if invocation.output.exit_code != Some(0) || invocation.output.signal.is_some() {
        invocation
            .journal
            .append_refusal("resolver_process_refused")?;
        return Err(format!(
            "standing-resolver-refused:exit={:?}:signal={:?}:{}",
            invocation.output.exit_code,
            invocation.output.signal,
            String::from_utf8_lossy(&invocation.output.stderr)
                .chars()
                .take(512)
                .collect::<String>()
        ));
    }
    let standing = match strict_json(&invocation.output.stdout, "process-response") {
        Ok(parsed) => parsed,
        Err(error) => {
            invocation
                .journal
                .append_refusal("resolver_response_decode_refused")?;
            return Err(error);
        }
    };
    if let Err(error) = validate_standing(issuance, &standing, now) {
        invocation
            .journal
            .append_refusal("resolver_response_semantics_refused")?;
        return Err(error);
    }
    Ok(standing)
}

#[cfg(target_os = "freebsd")]
fn read_standing_resolver_candidate(path: &Path) -> Result<Vec<u8>, String> {
    if !path.is_absolute() {
        return Err("standing-resolver-path-not-absolute".to_owned());
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("standing-resolver-metadata:{error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_STANDING_RESOLVER_BYTES
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o022 != 0
    {
        return Err("standing-resolver-candidate-custody".to_owned());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("standing-resolver-open:{error}"))?;
    let before = file
        .metadata()
        .map_err(|error| format!("standing-resolver-opened-metadata:{error}"))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len()).map_err(|_| "standing-resolver-size-overflow".to_owned())?,
    );
    std::io::Read::by_ref(&mut file)
        .take(MAX_STANDING_RESOLVER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("standing-resolver-read:{error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("standing-resolver-reread-metadata:{error}"))?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err("standing-resolver-candidate-changed-while-read".to_owned());
    }
    Ok(bytes)
}

#[cfg(target_os = "freebsd")]
fn resolver_authority_wire(
    authority: &gwr_freebsd_exec::ExecutionRepresentationAuthorityClosure,
) -> Result<ExecutionRepresentationAuthorityClosureWireV1, String> {
    let wire = authority_wire(authority);
    if wire.schema != gwr_freebsd_exec::AUTHORITY_CLOSURE_SCHEMA_V1
        || wire.creator != "docket_standing_resolver"
        || wire.representation_method != gwr_freebsd_exec::PRIVATE_UNLINKED_REGULAR_VNODE_V1
        || wire.writer_descriptors_created != 1
        || wire.writer_descriptors_duplicated != 0
        || wire.writer_descriptors_closed_before_measurement != 1
        || wire.writable_descriptors_surviving_finalization != 0
        || wire.writable_descriptors_inherited != 0
        || wire.representation_links_at_finalization != 0
        || wire.surviving_descriptor_access != "read_only"
        || wire.surviving_rights_profile != gwr_freebsd_exec::FIRST_STAGE_RIGHTS_PROFILE_V1
        || (wire.direct_write_probe_errno != libc::EBADF
            && wire.direct_write_probe_errno != libc::ENOTCAPABLE)
        || wire.write_reacquisition_method != "openat_empty_path_rdwr"
        || wire.write_reacquisition_errno != libc::ENOTCAPABLE
        || wire.finalization_sequence >= wire.measurement_sequence
        || wire.measurement_sequence >= wire.invocation_sequence
        || wire.descriptor_transfer != "read_only_reader_fork_inherited_for_fexecve"
    {
        return Err("standing-resolver-authority-closure-invalid".to_owned());
    }
    Ok(wire)
}

#[cfg(target_os = "freebsd")]
fn add_representation_to_record(
    record: &mut StandingResolverLaunchRecordV1,
    invocation: &StandingResolverInvocationV1,
) {
    record.source_candidate_content = Some(invocation.source_candidate_content.clone());
    record.private_representation_content = Some(invocation.representation_content.clone());
    record.representation_method = Some(invocation.representation_method.clone());
    record.representation_device = Some(invocation.representation_device);
    record.representation_inode = Some(invocation.representation_inode);
    record.representation_links = Some(invocation.representation_links);
    record.representation_authority = Some(invocation.representation_authority.clone());
    record.content_match = Some(
        invocation.source_candidate_content == invocation.representation_content
            && invocation.representation_content == invocation.journal.expected_resolver_content,
    );
}

#[cfg(all(target_os = "freebsd", feature = "fault-injection"))]
fn pause_after_standing_resolver_custody(launch: &str) -> Result<(), String> {
    let ready = std::env::var_os("GWR_M9_STANDING_RESOLVER_READY");
    let resume = std::env::var_os("GWR_M9_STANDING_RESOLVER_RESUME");
    if ready.is_some() != resume.is_some() {
        return Err("standing-resolver-custody-coordination-incomplete".to_owned());
    }
    let Some((ready, resume)) = ready.zip(resume) else {
        return Ok(());
    };
    let ready = PathBuf::from(ready);
    let resume = PathBuf::from(resume);
    if !ready.is_absolute() || !resume.is_absolute() {
        return Err("standing-resolver-custody-coordination-path-not-absolute".to_owned());
    }
    let witness = format!("{launch}\n");
    let mut ready_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&ready)
        .map_err(|error| format!("standing-resolver-custody-ready:{error}"))?;
    ready_file
        .write_all(witness.as_bytes())
        .and_then(|()| ready_file.sync_all())
        .map_err(|error| format!("standing-resolver-custody-ready:{error}"))?;
    for _ in 0..6_000 {
        match std::fs::read(&resume) {
            Ok(bytes) if bytes == witness.as_bytes() => return Ok(()),
            Ok(_) => return Err("standing-resolver-custody-resume-mismatch".to_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("standing-resolver-custody-resume:{error}")),
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err("standing-resolver-custody-coordination-timeout".to_owned())
}

#[cfg(all(target_os = "freebsd", not(feature = "fault-injection")))]
fn pause_after_standing_resolver_custody(_launch: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn prepare_standing_resolver_inputs(
    custody: &StandingResolverExactCustodyV2,
    request: &ExecutionStandingRequestV1,
    request_sha256: &str,
) -> Result<PreparedStandingResolverInputsV1, String> {
    if custody.ttl_ms == 0 {
        return Err("standing-resolver-ttl-must-be-positive".to_owned());
    }
    let locator = exact_standing_custody_locator(&custody.custody_directory)?;
    let before = std::fs::symlink_metadata(&custody.custody_directory)
        .map_err(|error| format!("standing-resolver-custody-directory-metadata:{error}"))?;
    if before.file_type().is_symlink() || !before.is_dir() || before.mode() & 0o077 != 0 {
        return Err("standing-resolver-custody-directory-not-private-directory".to_owned());
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&custody.custody_directory)
        .map_err(|error| format!("standing-resolver-custody-directory-open:{error}"))?;
    let observed = directory
        .metadata()
        .map_err(|error| format!("standing-resolver-custody-directory-fstat:{error}"))?;
    if !observed.is_dir()
        || before.dev() != observed.dev()
        || before.ino() != observed.ino()
        || before.mode() != observed.mode()
        || before.uid() != observed.uid()
        || before.gid() != observed.gid()
        || before.nlink() != observed.nlink()
    {
        return Err("standing-resolver-custody-directory-changed-while-open".to_owned());
    }

    let environment_values = vec![
        format!(
            "CIVIL_M3_DOCKET_STANDING_CUSTODY_FD={}",
            gwr_freebsd_exec::EXACT_CUSTODY_DIRECTORY_FD_V1
        ),
        format!("CIVIL_M3_STANDING_TTL_MS={}", custody.ttl_ms),
    ];
    let environment = environment_values
        .iter()
        .map(|value| {
            CString::new(value.as_bytes())
                .map_err(|_| "standing-resolver-exact-environment-contains-nul".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let input_set = StandingResolverInputSetV1 {
        schema: STANDING_RESOLVER_INPUT_SET_SCHEMA_V1.to_owned(),
        request_sha256: request_sha256.to_owned(),
        now_unix_ms: request.now_unix_ms,
        ttl_ms: custody.ttl_ms,
        time_source: "docket_system_time_unix_epoch_ms".to_owned(),
        custody_directory_locator: locator,
        custody_directory_projection: StandingResolverCustodyDirectoryProjectionV1 {
            object_type: "directory".to_owned(),
            device: observed.dev(),
            inode: observed.ino(),
            mode: observed.mode(),
            uid: observed.uid(),
            gid: observed.gid(),
            links: observed.nlink(),
            semantic_role: "exact_request_response_custody".to_owned(),
            access_method: "fixed_inherited_directory_fd_openat_nofollow_v1".to_owned(),
            inherited_fd: gwr_freebsd_exec::EXACT_CUSTODY_DIRECTORY_FD_V1,
            request_entry: "docket-standing-request.json".to_owned(),
            response_entry: "docket-standing-response.json".to_owned(),
            update_semantics: "create_exclusive_or_byte_identical_v1".to_owned(),
        },
        argv: vec!["docket-standing-resolver".to_owned()],
        environment: environment_values,
        working_directory: "/".to_owned(),
        inherited_descriptor_profile:
            "stdio_exact_custody_directory_plus_unobserved_inherited_descriptors_v1".to_owned(),
        umask_octal: "0077".to_owned(),
    };
    let input_set_sha256 = standing_resolver_input_set_digest(&input_set)?;
    Ok(PreparedStandingResolverInputsV1 {
        input_set,
        input_set_sha256,
        custody_directory: directory,
        environment,
    })
}

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
fn exact_standing_custody_locator(path: &Path) -> Result<String, String> {
    if !path.is_absolute() {
        return Err("standing-resolver-custody-directory-path-not-absolute".to_owned());
    }
    let locator = path
        .to_str()
        .ok_or_else(|| "standing-resolver-custody-directory-path-not-utf8".to_owned())?;
    if locator
        .split('/')
        .any(|component| matches!(component, "." | ".."))
    {
        return Err("standing-resolver-custody-directory-path-has-dot-component".to_owned());
    }
    Ok(locator.to_owned())
}

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
fn standing_resolver_input_set_digest(
    input_set: &StandingResolverInputSetV1,
) -> Result<String, String> {
    let input_set_bytes = serde_jcs::to_vec(input_set)
        .map_err(|error| format!("standing-resolver-input-set-canonical:{error}"))?;
    Ok(file_content_digest(&input_set_bytes))
}

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
fn standing_resolver_launch_identity_v2(
    expected_content: &str,
    issuance: &str,
    request_sha256: &str,
    standing_input_set_sha256: &str,
) -> Result<String, String> {
    let launch_basis = serde_jcs::to_vec(&serde_json::json!({
        "expected_resolver_content": expected_content,
        "issuance": issuance,
        "request_sha256": request_sha256,
        "standing_input_set_sha256": standing_input_set_sha256,
    }))
    .map_err(|error| format!("standing-resolver-launch-basis:{error}"))?;
    Ok(hash_domain(
        "docket.governed-loop.standing-resolver-launch/v2",
        &launch_basis,
    ))
}

#[cfg(target_os = "freebsd")]
fn invoke_exact_standing_resolver_common(
    program: &Path,
    representation_base: &Path,
    expected_content: &str,
    journal_path: &Path,
    exact_inputs: Option<&StandingResolverExactCustodyV2>,
    request: &ExecutionStandingRequestV1,
) -> Result<StandingResolverInvocationV1, String> {
    require_digest(expected_content, "standing resolver expected content")?;
    let request_bytes = serde_json::to_vec(request)
        .map_err(|error| format!("standing-resolver-request:{error}"))?;
    let request_sha256 = file_content_digest(&request_bytes);
    let prepared_inputs = exact_inputs
        .map(|custody| prepare_standing_resolver_inputs(custody, request, &request_sha256))
        .transpose()?;
    let (launch, journal) = if let Some(prepared) = prepared_inputs.as_ref() {
        let launch = standing_resolver_launch_identity_v2(
            expected_content,
            &request.issuance.issuance,
            &request_sha256,
            &prepared.input_set_sha256,
        )?;
        let journal = StandingResolverJournalV1::create_v2(
            journal_path,
            launch.clone(),
            request.issuance.issuance.clone(),
            request_sha256.clone(),
            expected_content.to_owned(),
            prepared.input_set_sha256.clone(),
            prepared.input_set.clone(),
        )?;
        (launch, journal)
    } else {
        let launch_basis = serde_jcs::to_vec(&serde_json::json!({
            "expected_resolver_content": expected_content,
            "issuance": request.issuance.issuance,
            "request_sha256": request_sha256,
        }))
        .map_err(|error| format!("standing-resolver-launch-basis:{error}"))?;
        let launch = hash_domain(
            "docket.governed-loop.standing-resolver-launch/v1",
            &launch_basis,
        );
        let journal = StandingResolverJournalV1::create(
            journal_path,
            launch.clone(),
            request.issuance.issuance.clone(),
            request_sha256.clone(),
            expected_content.to_owned(),
        )?;
        (launch, journal)
    };
    debug_assert_eq!(journal.launch, launch);
    let mut journal = journal;
    let source_bytes = match read_standing_resolver_candidate(program) {
        Ok(bytes) => bytes,
        Err(error) => {
            journal.append_refusal("candidate_acquisition_refused")?;
            return Err(error);
        }
    };
    let source_candidate_content = file_content_digest(&source_bytes);
    let mut representation = match gwr_freebsd_exec::prepare_execution_representation_for(
        representation_base,
        &source_bytes,
        "docket_standing_resolver",
    ) {
        Ok(representation) => representation,
        Err(error) => {
            journal.append_refusal("representation_establishment_refused")?;
            return Err(format!("standing-resolver-representation:{error}"));
        }
    };
    representation
        .executable
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("standing-resolver-representation-rewind:{error}"))?;
    let mut measured = Vec::new();
    std::io::Read::by_ref(&mut representation.executable)
        .take(MAX_STANDING_RESOLVER_BYTES + 1)
        .read_to_end(&mut measured)
        .map_err(|error| format!("standing-resolver-representation-read:{error}"))?;
    representation
        .executable
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("standing-resolver-representation-rewind:{error}"))?;
    if measured.len() as u64 > MAX_STANDING_RESOLVER_BYTES {
        journal.append_refusal("representation_size_refused")?;
        return Err("standing-resolver-representation-too-large".to_owned());
    }
    let representation_content = file_content_digest(&measured);
    let representation_authority = match resolver_authority_wire(&representation.authority) {
        Ok(authority) => authority,
        Err(error) => {
            journal.append_refusal("representation_authority_closure_refused")?;
            return Err(error);
        }
    };
    let mut invocation = StandingResolverInvocationV1 {
        journal,
        source_candidate_content,
        representation_content,
        representation_method: representation.method.to_owned(),
        representation_device: representation.device,
        representation_inode: representation.inode,
        representation_links: representation.links,
        representation_authority,
        output: gwr_freebsd_exec::DescriptorExecOutput {
            descriptor_exec_accepted: false,
            exit_code: None,
            signal: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            exec_errno: None,
        },
    };
    let content_match = invocation.source_candidate_content == invocation.representation_content
        && invocation.representation_content == expected_content;
    let mut prepared = invocation
        .journal
        .base_record(StandingResolverLaunchStageV1::Prepared);
    add_representation_to_record(&mut prepared, &invocation);
    invocation.journal.append(prepared)?;
    if !content_match {
        let mut refused = invocation
            .journal
            .base_record(StandingResolverLaunchStageV1::Refused);
        add_representation_to_record(&mut refused, &invocation);
        refused.refusal = Some("resolver_content_identity_mismatch".to_owned());
        invocation.journal.append(refused)?;
        return Err("standing-resolver-content-identity-mismatch".to_owned());
    }
    if let Err(error) = pause_after_standing_resolver_custody(&invocation.journal.launch) {
        let mut refused = invocation
            .journal
            .base_record(StandingResolverLaunchStageV1::Refused);
        add_representation_to_record(&mut refused, &invocation);
        refused.refusal = Some(error.clone());
        invocation.journal.append(refused)?;
        return Err(error);
    }
    let argv = [CString::new("docket-standing-resolver").expect("static argv has no NUL")];
    let mut on_exec_accepted = || {
        let mut entered = invocation
            .journal
            .base_record(StandingResolverLaunchStageV1::Entered);
        add_representation_to_record(&mut entered, &invocation);
        entered.descriptor_exec_accepted = Some(true);
        invocation
            .journal
            .append(entered)
            .map_err(std::io::Error::other)
    };
    let output = if let Some(prepared) = prepared_inputs.as_ref() {
        gwr_freebsd_exec::invoke_with_exact_process_inputs_and_exec_observer(
            &representation.executable,
            &argv,
            &request_bytes,
            &prepared.environment,
            &prepared.custody_directory,
            &mut on_exec_accepted,
        )
    } else {
        gwr_freebsd_exec::invoke_with_exec_observer(
            &representation.executable,
            &argv,
            &request_bytes,
            &mut on_exec_accepted,
        )
    }
    .map_err(|error| format!("standing-resolver-descriptor-invoke:{error}"))?;
    invocation.output = output;
    let stage = if invocation.output.descriptor_exec_accepted {
        StandingResolverLaunchStageV1::Completed
    } else {
        StandingResolverLaunchStageV1::Refused
    };
    let mut completed = invocation.journal.base_record(stage);
    add_representation_to_record(&mut completed, &invocation);
    completed.descriptor_exec_accepted = Some(invocation.output.descriptor_exec_accepted);
    completed.stdout_sha256 = Some(file_content_digest(&invocation.output.stdout));
    completed.stderr_sha256 = Some(file_content_digest(&invocation.output.stderr));
    completed.exit_code = invocation.output.exit_code;
    completed.signal = invocation.output.signal;
    completed.exec_errno = invocation.output.exec_errno;
    if !invocation.output.descriptor_exec_accepted {
        completed.refusal = Some("descriptor_invocation_refused".to_owned());
    }
    invocation.journal.append(completed)?;
    Ok(invocation)
}

#[cfg(target_os = "freebsd")]
fn invoke_exact_standing_resolver(
    program: &Path,
    representation_base: &Path,
    custody: &StandingResolverExactCustodyV1,
    request: &ExecutionStandingRequestV1,
) -> Result<StandingResolverInvocationV1, String> {
    invoke_exact_standing_resolver_common(
        program,
        representation_base,
        &custody.expected_content,
        &custody.journal,
        None,
        request,
    )
}

#[cfg(target_os = "freebsd")]
fn invoke_exact_standing_resolver_v2(
    program: &Path,
    representation_base: &Path,
    custody: &StandingResolverExactCustodyV2,
    request: &ExecutionStandingRequestV1,
) -> Result<StandingResolverInvocationV1, String> {
    invoke_exact_standing_resolver_common(
        program,
        representation_base,
        &custody.expected_content,
        &custody.journal,
        Some(custody),
        request,
    )
}

#[cfg(not(target_os = "freebsd"))]
fn invoke_exact_standing_resolver(
    _program: &Path,
    _representation_base: &Path,
    _custody: &StandingResolverExactCustodyV1,
    _request: &ExecutionStandingRequestV1,
) -> Result<StandingResolverInvocationV1, String> {
    Err("standing-resolver-exact-content-mode-requires-freebsd".to_owned())
}

#[cfg(not(target_os = "freebsd"))]
fn invoke_exact_standing_resolver_v2(
    _program: &Path,
    _representation_base: &Path,
    _custody: &StandingResolverExactCustodyV2,
    _request: &ExecutionStandingRequestV1,
) -> Result<StandingResolverInvocationV1, String> {
    Err("standing-resolver-exact-input-mode-requires-freebsd".to_owned())
}

/// Accepts one exact issuance, consumes fresh Docket standing transactionally,
/// persists custody, and then invokes exactly one executor delivery.
pub fn accept(
    database: &Path,
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
    standing_resolver: &Path,
    executor_program: &Path,
    executor_config: &Path,
) -> Result<DocketCustodyWireV1, String> {
    accept_with_standing_resolver_custody(
        database,
        envelope_bytes,
        trust_bytes,
        standing_resolver,
        None,
        executor_program,
        executor_config,
    )
}

/// Accept with an optional FreeBSD exact-content custody boundary around the
/// external standing authority. The legacy path remains the default so host
/// behavior and already-qualified deployments are unchanged.
pub fn accept_with_standing_resolver_custody(
    database: &Path,
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
    standing_resolver: &Path,
    standing_resolver_custody: Option<&StandingResolverExactCustodyV1>,
    executor_program: &Path,
    executor_config: &Path,
) -> Result<DocketCustodyWireV1, String> {
    accept_with_standing_resolver_mode(
        database,
        envelope_bytes,
        trust_bytes,
        standing_resolver,
        standing_resolver_custody.map(StandingResolverCustodyMode::V1),
        executor_program,
        executor_config,
    )
}

/// Accept with M10 exact semantic-input closure around the external standing
/// authority. Standing request/response v1 and Docket attempt semantics remain
/// unchanged; this version binds the exact runtime inputs to launch v2.
pub fn accept_with_standing_resolver_input_closure(
    database: &Path,
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
    standing_resolver: &Path,
    standing_resolver_custody: &StandingResolverExactCustodyV2,
    executor_program: &Path,
    executor_config: &Path,
) -> Result<DocketCustodyWireV1, String> {
    accept_with_standing_resolver_mode(
        database,
        envelope_bytes,
        trust_bytes,
        standing_resolver,
        Some(StandingResolverCustodyMode::V2(standing_resolver_custody)),
        executor_program,
        executor_config,
    )
}

#[derive(Clone, Copy)]
enum StandingResolverCustodyMode<'a> {
    V1(&'a StandingResolverExactCustodyV1),
    V2(&'a StandingResolverExactCustodyV2),
}

fn accept_with_standing_resolver_mode(
    database: &Path,
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
    standing_resolver: &Path,
    standing_resolver_custody: Option<StandingResolverCustodyMode<'_>>,
    executor_program: &Path,
    executor_config: &Path,
) -> Result<DocketCustodyWireV1, String> {
    let (envelope, issuance) = verify_signed_issuance(envelope_bytes, trust_bytes)?;
    let mut store = GovernedCustodyStoreV1::open(database)?;
    if let Some(existing) = store.get(&issuance.issuance)? {
        require_same_envelope(&existing, &envelope, &issuance)?;
        return Ok(existing.custody);
    }

    let mut executor = resolve_executor_binding(
        executor_program,
        executor_config,
        database.parent().unwrap_or_else(|| Path::new(".")),
        &issuance.work_schema,
        &issuance.work,
    )?;

    let now = now_unix_ms()?;
    let standing_request = ExecutionStandingRequestV1 {
        schema: STANDING_REQUEST_SCHEMA_V1.to_owned(),
        issuance: issuance.clone(),
        now_unix_ms: now,
    };
    let mut standing_invocation = None;
    let standing: ExecutionStandingResolutionV1 = match standing_resolver_custody {
        Some(StandingResolverCustodyMode::V1(custody)) => {
            let mut invocation = invoke_exact_standing_resolver(
                standing_resolver,
                database.parent().unwrap_or_else(|| Path::new(".")),
                custody,
                &standing_request,
            )?;
            let parsed = decode_exact_standing_response(&mut invocation, &issuance, now)?;
            standing_invocation = Some(invocation);
            parsed
        }
        Some(StandingResolverCustodyMode::V2(custody)) => {
            let mut invocation = invoke_exact_standing_resolver_v2(
                standing_resolver,
                database.parent().unwrap_or_else(|| Path::new(".")),
                custody,
                &standing_request,
            )?;
            let parsed = decode_exact_standing_response(&mut invocation, &issuance, now)?;
            let expected_expiry = now
                .checked_add(custody.ttl_ms)
                .ok_or_else(|| "standing-resolver-ttl-expiry-overflow".to_owned())?;
            if parsed.resolved_at_unix_ms != now || parsed.expires_at_unix_ms != expected_expiry {
                invocation
                    .journal
                    .append_refusal("resolver_exact_time_input_mismatch")?;
                return Err("standing-resolver-exact-time-input-mismatch".to_owned());
            }
            standing_invocation = Some(invocation);
            parsed
        }
        None => invoke_json(standing_resolver, &[], &standing_request)?,
    };
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
        if let Some(invocation) = standing_invocation.as_mut() {
            invocation
                .journal
                .append_refusal("governed_instrument_substitution")?;
        }
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
    match store.insert_custody(&envelope, &issuance, &standing, &custody, &executor.binding) {
        Ok(()) => {
            if let Some(invocation) = standing_invocation.as_mut() {
                invocation.journal.append_accepted(&standing, &custody)?;
            }
        }
        Err(error) => {
            if let Some(existing) = store.get(&issuance.issuance)? {
                require_same_envelope(&existing, &envelope, &issuance)?;
                if let Some(invocation) = standing_invocation.as_mut() {
                    invocation
                        .journal
                        .append_refusal("custody_already_inserted")?;
                }
                return Ok(existing.custody);
            }
            if let Some(invocation) = standing_invocation.as_mut() {
                invocation
                    .journal
                    .append_refusal("custody_insertion_refused")?;
            }
            return Err(error);
        }
    }

    // The custody transaction above is committed before any mechanics call.
    // A process loss here leaves an exact accepted attempt and can never make
    // this issuance dispatchable as a second attempt.
    if executor
        .binding
        .expected_content
        .as_ref()
        .zip(
            executor
                .binding
                .representation_content
                .as_ref()
                .or(executor.binding.program_content.as_ref()),
        )
        .is_some_and(|(expected, measured)| expected != measured)
    {
        let evidence = hash_domain(
            "docket.governed-loop.executor-content-mismatch/v1",
            format!(
                "{}:{}:{}",
                executor.binding.plan,
                executor
                    .binding
                    .expected_content
                    .as_deref()
                    .unwrap_or_default(),
                executor
                    .binding
                    .program_content
                    .as_deref()
                    .unwrap_or_default()
            )
            .as_bytes(),
        );
        store.record_indeterminate(&issuance.issuance, &custody, &evidence)?;
        return Ok(custody);
    }
    if executor.opened_program.is_some() {
        pause_after_executor_custody()?;
    }
    if let Err(error) = require_executor_binding(
        &mut executor,
        executor_program,
        executor_config,
        database.parent().unwrap_or_else(|| Path::new(".")),
        &issuance.work_schema,
    ) {
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
    let outcome = if let Some(opened) = executor.opened_program.as_ref() {
        pause_after_executor_revalidation()?;
        invoke_descriptor_json(opened, &["execute", config], &dispatch).and_then(|invocation| {
            if invocation.descriptor_exec_accepted {
                let dispatch_content = file_content_digest(&invocation.input);
                store.record_executor_launch(
                    &issuance.issuance,
                    &custody,
                    &executor.binding,
                    &dispatch_content,
                    executor_invocation_method(&executor.binding),
                )?;
            }
            invocation.decode()
        })
    } else {
        invoke_json::<_, ExecutorOutcomeWireV1>(executor_program, &["execute", config], &dispatch)
    };
    match outcome {
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
    executor_program: &Path,
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

    let mut executor = resolve_executor_binding(
        executor_program,
        executor_config,
        database.parent().unwrap_or_else(|| Path::new(".")),
        &record.issuance.work_schema,
        &record.issuance.work,
    )?;
    let expected_binding = ExecutorBindingV1 {
        identity: record.executor_binding.clone(),
        program_digest: record.executor_program_digest.clone(),
        plan: record.executor_plan.clone(),
        program_content: record.executor_program_content.clone(),
        expected_content: record.executor_expected_content.clone(),
        representation_content: record.executor_representation_content.clone(),
        representation_method: record.executor_representation_method.clone(),
        representation_authority: record.executor_representation_authority.clone(),
    };
    if executor.binding != expected_binding {
        return Err("governed-executor-binding-substitution".to_owned());
    }
    require_executor_binding(
        &mut executor,
        executor_program,
        executor_config,
        database.parent().unwrap_or_else(|| Path::new(".")),
        &record.issuance.work_schema,
    )?;

    let dispatch = executor_dispatch(&record.issuance, &record.custody);
    let config = executor_config
        .to_str()
        .ok_or_else(|| "executor-config-path-not-utf8".to_owned())?;
    let outcome = if let Some(opened) = executor.opened_program.as_ref() {
        invoke_descriptor_json(opened, &["reconcile", config], &dispatch).and_then(|invocation| {
            if invocation.descriptor_exec_accepted {
                let dispatch_content = file_content_digest(&invocation.input);
                store.record_executor_launch(
                    issuance,
                    &record.custody,
                    &executor.binding,
                    &dispatch_content,
                    executor_invocation_method(&executor.binding),
                )?;
            }
            invocation.decode()
        })
    } else {
        invoke_json::<_, ExecutorOutcomeWireV1>(executor_program, &["reconcile", config], &dispatch)
    };
    match outcome {
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
    let schema = if record.executor_representation_authority.is_some() {
        INSPECTION_SCHEMA_V4
    } else if record.executor_representation_content.is_some() {
        INSPECTION_SCHEMA_V3
    } else if record.executor_program_content.is_some() {
        INSPECTION_SCHEMA_V2
    } else {
        INSPECTION_SCHEMA_V1
    };
    Ok(GovernedLoopInspectionV1 {
        schema: schema.to_owned(),
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
            executor_program_content: record.executor_program_content,
            executor_expected_content: record.executor_expected_content,
            executor_representation_content: record.executor_representation_content,
            executor_representation_method: record.executor_representation_method,
            executor_representation_authority: record
                .executor_representation_authority
                .as_deref()
                .map(parse_authority_closure)
                .transpose()?,
            executor_invocation_method: record.executor_invocation_method,
            executor_launch: record.executor_launch,
            executor_dispatch_content: record.executor_dispatch_content,
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
                  executor_program_digest,executor_plan,executor_program_content,
                  executor_expected_content,executor_representation_content,
                  executor_representation_method,executor_representation_authority,
                  accepted_at,status)
                 VALUES
                 (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,
                  ?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,'accepted')",
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
                    executor_binding.program_content,
                    executor_binding.expected_content,
                    executor_binding.representation_content,
                    executor_binding.representation_method,
                    executor_binding.representation_authority,
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
                        executor_program_digest,executor_plan,executor_program_content,
                        executor_expected_content,executor_representation_content,
                        executor_representation_method,executor_representation_authority,
                        executor_invocation_method,executor_launch,
                        executor_dispatch_content,accepted_at,status,
                        settlement,receipt,outcome,settled_at,reconciliation,indeterminate_evidence
                 FROM governed_loop_attempt WHERE issuance=?1",
                [issuance],
                |row| {
                    let accepted_at = read_u64(row.get::<_, i64>(32)?, 32)?;
                    let status: String = row.get(33)?;
                    let settlement_ref: Option<String> = row.get(34)?;
                    let receipt: Option<String> = row.get(35)?;
                    let outcome: Option<String> = row.get(36)?;
                    let settled_at: Option<i64> = row.get(37)?;
                    let reconciliation: Option<String> = row.get(38)?;
                    let evidence: Option<String> = row.get(39)?;
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
                                settled_at_unix_ms: read_u64(at, 37)?,
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
                        executor_program_content: row.get(24)?,
                        executor_expected_content: row.get(25)?,
                        executor_representation_content: row.get(26)?,
                        executor_representation_method: row.get(27)?,
                        executor_representation_authority: row.get(28)?,
                        executor_invocation_method: row.get(29)?,
                        executor_launch: row.get(30)?,
                        executor_dispatch_content: row.get(31)?,
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

    fn record_executor_launch(
        &mut self,
        issuance: &str,
        custody: &DocketCustodyWireV1,
        binding: &ExecutorBindingV1,
        dispatch_content: &str,
        method: &str,
    ) -> Result<String, String> {
        require_digest(dispatch_content, "executor dispatch content")?;
        let execution_content = binding
            .representation_content
            .as_ref()
            .or(binding.program_content.as_ref())
            .ok_or_else(|| "descriptor launch lacks measured program content".to_owned())?;
        require_digest(execution_content, "executor execution content")?;
        let expected_method = executor_invocation_method(binding);
        if method != expected_method {
            return Err("foreign executor invocation method".to_owned());
        }
        let canonical = if let (Some(content), Some(representation_method), Some(authority)) = (
            &binding.representation_content,
            &binding.representation_method,
            &binding.representation_authority,
        ) {
            serde_json::to_vec(&serde_json::json!({
                "attempt": custody.attempt,
                "binding": binding.identity,
                "dispatch_content": dispatch_content,
                "marker": custody.executor_marker,
                "method": method,
                "representation_content": content,
                "representation_method": representation_method,
                "representation_authority": authority,
            }))
            .map_err(|error| format!("executor-launch-canonical:{error}"))?
        } else if let (Some(content), Some(representation_method)) = (
            &binding.representation_content,
            &binding.representation_method,
        ) {
            serde_json::to_vec(&serde_json::json!({
                "attempt": custody.attempt,
                "binding": binding.identity,
                "dispatch_content": dispatch_content,
                "marker": custody.executor_marker,
                "method": method,
                "representation_content": content,
                "representation_method": representation_method,
            }))
            .map_err(|error| format!("executor-launch-canonical:{error}"))?
        } else {
            serde_json::to_vec(&serde_json::json!({
                "attempt": custody.attempt,
                "binding": binding.identity,
                "dispatch_content": dispatch_content,
                "marker": custody.executor_marker,
                "method": method,
                "program_content": execution_content,
            }))
            .map_err(|error| format!("executor-launch-canonical:{error}"))?
        };
        let launch_domain = if binding.representation_authority.is_some() {
            "docket.governed-loop.executor-launch/v3"
        } else if binding.representation_content.is_some() {
            "docket.governed-loop.executor-launch/v2"
        } else {
            "docket.governed-loop.executor-launch/v1"
        };
        let launch = hash_domain(launch_domain, &canonical);
        let changed = self
            .connection
            .execute(
                "UPDATE governed_loop_attempt
                 SET executor_invocation_method=?2,executor_launch=?3,
                     executor_dispatch_content=?4
                 WHERE issuance=?1 AND executor_launch IS NULL",
                params![issuance, method, launch, dispatch_content],
            )
            .map_err(|error| format!("governed-executor-launch-write:{error}"))?;
        if changed == 0 {
            let existing = self
                .get(issuance)?
                .ok_or_else(|| "governed-executor-launch-attempt-missing".to_owned())?;
            if existing.executor_invocation_method.as_deref() == Some(method)
                && existing.executor_launch.as_deref() == Some(launch.as_str())
                && existing.executor_dispatch_content.as_deref() == Some(dispatch_content)
            {
                return Ok(launch);
            }
            return Err("governed-executor-launch-substitution".to_owned());
        }
        Ok(launch)
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
    match (
        record.executor_program_content.as_ref(),
        record.executor_expected_content.as_ref(),
        record.executor_representation_content.as_ref(),
        record.executor_representation_method.as_ref(),
        record.executor_representation_authority.as_ref(),
    ) {
        (None, None, None, None, None) => {
            if record.executor_invocation_method.is_some()
                || record.executor_launch.is_some()
                || record.executor_dispatch_content.is_some()
            {
                return Err("legacy executor record fabricates descriptor custody".to_owned());
            }
            let binding = serde_json::to_vec(&serde_json::json!({
                "plan": record.executor_plan,
                "program_digest": record.executor_program_digest,
            }))
            .map_err(|error| format!("stored-executor-binding-canonical:{error}"))?;
            if record.executor_binding
                != hash_domain("docket.governed-loop.executor-binding/v1", &binding)
            {
                return Err("governed-stored-executor-binding-substitution".to_owned());
            }
        }
        (Some(program_content), Some(expected_content), None, None, None) => {
            require_digest(program_content, "stored executor content")?;
            require_digest(expected_content, "stored expected executor content")?;
            let binding = serde_json::to_vec(&serde_json::json!({
                "expected_content": expected_content,
                "plan": record.executor_plan,
                "program_content": program_content,
                "program_digest": record.executor_program_digest,
            }))
            .map_err(|error| format!("stored-executor-binding-canonical:{error}"))?;
            if record.executor_binding
                != hash_domain("docket.governed-loop.executor-binding/v2", &binding)
            {
                return Err("governed-stored-executor-binding-substitution".to_owned());
            }
            match (
                record.executor_invocation_method.as_deref(),
                record.executor_launch.as_ref(),
                record.executor_dispatch_content.as_ref(),
            ) {
                (None, None, None) => {}
                (Some(method), Some(launch), Some(dispatch_content)) => {
                    if method != DESCRIPTOR_INVOCATION_V1 {
                        return Err("stored executor invocation method".to_owned());
                    }
                    require_digest(launch, "stored executor launch")?;
                    require_digest(dispatch_content, "stored executor dispatch content")?;
                    let canonical = serde_json::to_vec(&serde_json::json!({
                        "attempt": record.custody.attempt,
                        "binding": record.executor_binding,
                        "dispatch_content": dispatch_content,
                        "marker": record.custody.executor_marker,
                        "method": method,
                        "program_content": program_content,
                    }))
                    .map_err(|error| format!("stored-executor-launch-canonical:{error}"))?;
                    if launch != &hash_domain("docket.governed-loop.executor-launch/v1", &canonical)
                    {
                        return Err("governed-stored-executor-launch-substitution".to_owned());
                    }
                }
                _ => return Err("partial stored executor descriptor custody".to_owned()),
            }
        }
        (
            Some(program_content),
            Some(expected_content),
            Some(representation_content),
            Some(representation_method),
            None,
        ) => {
            for (value, label) in [
                (program_content, "stored source candidate content"),
                (expected_content, "stored expected executor content"),
                (
                    representation_content,
                    "stored execution representation content",
                ),
            ] {
                require_digest(value, label)?;
            }
            if representation_method != gwr_freebsd_exec::PRIVATE_UNLINKED_REGULAR_VNODE_V1 {
                return Err("stored executor representation method".to_owned());
            }
            let binding = serde_json::to_vec(&serde_json::json!({
                "expected_content": expected_content,
                "plan": record.executor_plan,
                "program_content": program_content,
                "program_digest": record.executor_program_digest,
                "representation_content": representation_content,
                "representation_method": representation_method,
            }))
            .map_err(|error| format!("stored-executor-binding-canonical:{error}"))?;
            if record.executor_binding
                != hash_domain("docket.governed-loop.executor-binding/v3", &binding)
            {
                return Err("governed-stored-executor-binding-substitution".to_owned());
            }
            match (
                record.executor_invocation_method.as_deref(),
                record.executor_launch.as_ref(),
                record.executor_dispatch_content.as_ref(),
            ) {
                (None, None, None) => {}
                (Some(method), Some(launch), Some(dispatch_content)) => {
                    if method != REPRESENTATION_INVOCATION_V1 {
                        return Err("stored executor invocation method".to_owned());
                    }
                    require_digest(launch, "stored executor launch")?;
                    require_digest(dispatch_content, "stored executor dispatch content")?;
                    let canonical = serde_json::to_vec(&serde_json::json!({
                        "attempt": record.custody.attempt,
                        "binding": record.executor_binding,
                        "dispatch_content": dispatch_content,
                        "marker": record.custody.executor_marker,
                        "method": method,
                        "representation_content": representation_content,
                        "representation_method": representation_method,
                    }))
                    .map_err(|error| format!("stored-executor-launch-canonical:{error}"))?;
                    if launch != &hash_domain("docket.governed-loop.executor-launch/v2", &canonical)
                    {
                        return Err("governed-stored-executor-launch-substitution".to_owned());
                    }
                }
                _ => return Err("partial stored executor representation custody".to_owned()),
            }
        }
        (
            Some(program_content),
            Some(expected_content),
            Some(representation_content),
            Some(representation_method),
            Some(authority),
        ) => {
            for (value, label) in [
                (program_content, "stored source candidate content"),
                (expected_content, "stored expected executor content"),
                (
                    representation_content,
                    "stored execution representation content",
                ),
            ] {
                require_digest(value, label)?;
            }
            if representation_method != gwr_freebsd_exec::PRIVATE_UNLINKED_REGULAR_VNODE_V1 {
                return Err("stored executor representation method".to_owned());
            }
            validate_authority_closure_text(authority)?;
            let binding = serde_json::to_vec(&serde_json::json!({
                "expected_content": expected_content,
                "plan": record.executor_plan,
                "program_content": program_content,
                "program_digest": record.executor_program_digest,
                "representation_content": representation_content,
                "representation_method": representation_method,
                "representation_authority": authority,
            }))
            .map_err(|error| format!("stored-executor-binding-canonical:{error}"))?;
            if record.executor_binding
                != hash_domain("docket.governed-loop.executor-binding/v4", &binding)
            {
                return Err("governed-stored-executor-binding-substitution".to_owned());
            }
            match (
                record.executor_invocation_method.as_deref(),
                record.executor_launch.as_ref(),
                record.executor_dispatch_content.as_ref(),
            ) {
                (None, None, None) => {}
                (Some(method), Some(launch), Some(dispatch_content)) => {
                    if method != REPRESENTATION_INVOCATION_V1 {
                        return Err("stored executor invocation method".to_owned());
                    }
                    require_digest(launch, "stored executor launch")?;
                    require_digest(dispatch_content, "stored executor dispatch content")?;
                    let canonical = serde_json::to_vec(&serde_json::json!({
                        "attempt": record.custody.attempt,
                        "binding": record.executor_binding,
                        "dispatch_content": dispatch_content,
                        "marker": record.custody.executor_marker,
                        "method": method,
                        "representation_content": representation_content,
                        "representation_method": representation_method,
                        "representation_authority": authority,
                    }))
                    .map_err(|error| format!("stored-executor-launch-canonical:{error}"))?;
                    if launch != &hash_domain("docket.governed-loop.executor-launch/v3", &canonical)
                    {
                        return Err("governed-stored-executor-launch-substitution".to_owned());
                    }
                }
                _ => {
                    return Err(
                        "partial stored finalized executor representation custody".to_owned()
                    )
                }
            }
        }
        _ => return Err("partial stored executor content selection".to_owned()),
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

fn validate_authority_closure(
    authority: &ExecutionRepresentationAuthorityClosureWireV1,
) -> Result<(), String> {
    if authority.schema != gwr_freebsd_exec::AUTHORITY_CLOSURE_SCHEMA_V1
        || authority.creator != "docket_first_stage_adapter"
        || authority.representation_method != gwr_freebsd_exec::PRIVATE_UNLINKED_REGULAR_VNODE_V1
        || authority.writer_descriptors_created != 1
        || authority.writer_descriptors_duplicated != 0
        || authority.writer_descriptors_closed_before_measurement != 1
        || authority.writable_descriptors_surviving_finalization != 0
        || authority.writable_descriptors_inherited != 0
        || authority.representation_links_at_finalization != 0
        || authority.surviving_descriptor_access != "read_only"
        || authority.surviving_rights_profile != gwr_freebsd_exec::FIRST_STAGE_RIGHTS_PROFILE_V1
        || (authority.direct_write_probe_errno != libc::EBADF
            && authority.direct_write_probe_errno != 93)
        || authority.write_reacquisition_method != "openat_empty_path_rdwr"
        || authority.write_reacquisition_errno != 93
        || authority.finalization_sequence >= authority.measurement_sequence
        || authority.measurement_sequence >= authority.invocation_sequence
        || authority.descriptor_transfer != "read_only_reader_fork_inherited_for_fexecve"
    {
        return Err("execution-representation-authority-closure-invalid".to_owned());
    }
    Ok(())
}

fn authority_closure_text(
    authority: &ExecutionRepresentationAuthorityClosureWireV1,
) -> Result<String, String> {
    validate_authority_closure(authority)?;
    String::from_utf8(
        serde_jcs::to_vec(authority)
            .map_err(|error| format!("execution-representation-authority-canonical:{error}"))?,
    )
    .map_err(|_| "execution-representation-authority-not-utf8".to_owned())
}

fn parse_authority_closure(
    text: &str,
) -> Result<ExecutionRepresentationAuthorityClosureWireV1, String> {
    let authority: ExecutionRepresentationAuthorityClosureWireV1 =
        strict_json(text.as_bytes(), "execution-representation-authority")?;
    if authority_closure_text(&authority)? != text {
        return Err("execution-representation-authority-not-canonical".to_owned());
    }
    Ok(authority)
}

fn validate_authority_closure_text(text: &str) -> Result<(), String> {
    parse_authority_closure(text).map(|_| ())
}

#[cfg(target_os = "freebsd")]
fn authority_wire(
    authority: &gwr_freebsd_exec::ExecutionRepresentationAuthorityClosure,
) -> ExecutionRepresentationAuthorityClosureWireV1 {
    ExecutionRepresentationAuthorityClosureWireV1 {
        schema: authority.schema.to_owned(),
        creator: authority.creator.to_owned(),
        representation_method: authority.representation_method.to_owned(),
        writer_descriptors_created: authority.writer_descriptors_created,
        writer_descriptors_duplicated: authority.writer_descriptors_duplicated,
        writer_descriptors_closed_before_measurement: authority
            .writer_descriptors_closed_before_measurement,
        writable_descriptors_surviving_finalization: authority
            .writable_descriptors_surviving_finalization,
        writable_descriptors_inherited: authority.writable_descriptors_inherited,
        representation_links_at_finalization: authority.representation_links_at_finalization,
        surviving_descriptor_access: authority.surviving_descriptor_access.to_owned(),
        surviving_rights_profile: authority.surviving_rights_profile.to_owned(),
        direct_write_probe_errno: authority.direct_write_probe_errno,
        write_reacquisition_method: authority.write_reacquisition_method.to_owned(),
        write_reacquisition_errno: authority.write_reacquisition_errno,
        finalization_sequence: authority.finalization_sequence,
        measurement_sequence: authority.measurement_sequence,
        invocation_sequence: authority.invocation_sequence,
        descriptor_transfer: authority.descriptor_transfer.to_owned(),
    }
}

#[cfg(target_os = "freebsd")]
fn platform_authority_closure(
    authority: &gwr_freebsd_exec::ExecutionRepresentationAuthorityClosure,
) -> Result<String, String> {
    authority_closure_text(&authority_wire(authority))
}

fn resolve_executor_binding(
    program: &Path,
    config: &Path,
    representation_base: &Path,
    expected_work_schema: &str,
    expected_plan: &str,
) -> Result<ResolvedExecutorV1, String> {
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
    let program_content = file_content_digest(&bytes);
    let selection = resolve_executor_selection(config, expected_work_schema, expected_plan)?;
    match selection {
        Some(expected_content) => {
            let representation = execution_representation(executable, representation_base, &bytes)?;
            let opened_program = representation.executable;
            let representation_content = representation.content;
            let representation_method = representation.method;
            let representation_authority = representation.authority;
            let canonical = if let (Some(content), Some(method), Some(authority)) = (
                &representation_content,
                &representation_method,
                &representation_authority,
            ) {
                serde_json::to_vec(&serde_json::json!({
                    "expected_content": expected_content,
                    "plan": expected_plan,
                    "program_content": program_content,
                    "program_digest": program_digest,
                    "representation_content": content,
                    "representation_method": method,
                    "representation_authority": authority,
                }))
                .map_err(|error| format!("governed-executor-binding-canonical:{error}"))?
            } else {
                serde_json::to_vec(&serde_json::json!({
                    "expected_content": expected_content,
                    "plan": expected_plan,
                    "program_content": program_content,
                    "program_digest": program_digest,
                }))
                .map_err(|error| format!("governed-executor-binding-canonical:{error}"))?
            };
            let identity_domain = if representation_authority.is_some() {
                "docket.governed-loop.executor-binding/v4"
            } else if representation_content.is_some() {
                "docket.governed-loop.executor-binding/v3"
            } else {
                "docket.governed-loop.executor-binding/v2"
            };
            Ok(ResolvedExecutorV1 {
                binding: ExecutorBindingV1 {
                    identity: hash_domain(identity_domain, &canonical),
                    program_digest,
                    plan: expected_plan.to_owned(),
                    program_content: Some(program_content),
                    expected_content: Some(expected_content),
                    representation_content,
                    representation_method,
                    representation_authority,
                },
                opened_program: Some(opened_program),
            })
        }
        None => {
            let plan = invoke_plan_id(program, config)?;
            if plan != expected_plan {
                return Err("governed-executor-plan-substitution".to_owned());
            }
            let canonical = serde_json::to_vec(&serde_json::json!({
                "plan": plan,
                "program_digest": program_digest,
            }))
            .map_err(|error| format!("governed-executor-binding-canonical:{error}"))?;
            Ok(ResolvedExecutorV1 {
                binding: ExecutorBindingV1 {
                    identity: hash_domain("docket.governed-loop.executor-binding/v1", &canonical),
                    program_digest,
                    plan,
                    program_content: None,
                    expected_content: None,
                    representation_content: None,
                    representation_method: None,
                    representation_authority: None,
                },
                opened_program: None,
            })
        }
    }
}

fn require_executor_binding(
    resolved: &mut ResolvedExecutorV1,
    program_path: &Path,
    config: &Path,
    representation_base: &Path,
    expected_work_schema: &str,
) -> Result<(), String> {
    let Some(program) = resolved.opened_program.as_mut() else {
        let current = resolve_executor_binding(
            program_path,
            config,
            representation_base,
            expected_work_schema,
            &resolved.binding.plan,
        )?;
        if current.binding != resolved.binding {
            return Err("governed-executor-binding-substitution".to_owned());
        }
        return Ok(());
    };
    let opened_metadata = program
        .metadata()
        .map_err(|error| format!("governed-executor-opened-metadata:{error}"))?;
    program
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("governed-executor-rewind:{error}"))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened_metadata.len())
            .map_err(|_| "governed-executor-program-size-overflow".to_owned())?,
    );
    program
        .read_to_end(&mut bytes)
        .map_err(|error| format!("governed-executor-reread:{error}"))?;
    let current_content = file_content_digest(&bytes);
    if bytes.len() as u64 != opened_metadata.len()
        || Some(current_content.as_str())
            != resolved
                .binding
                .representation_content
                .as_deref()
                .or(resolved.binding.program_content.as_deref())
        || hash_domain("docket.governed-loop.executor-program/v1", &bytes)
            != resolved.binding.program_digest
        || resolve_executor_selection(config, expected_work_schema, &resolved.binding.plan)?
            != resolved.binding.expected_content
    {
        return Err("governed-executor-binding-substitution".to_owned());
    }
    program
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("governed-executor-rewind:{error}"))?;
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn execution_representation(
    _source: File,
    representation_base: &Path,
    bytes: &[u8],
) -> Result<PreparedExecutionRepresentation, String> {
    let mut representation =
        gwr_freebsd_exec::prepare_execution_representation(representation_base, bytes)
            .map_err(|error| format!("governed-executor-representation:{error}"))?;
    if representation.links != 0 {
        return Err("governed-executor-representation-still-linked".to_owned());
    }
    representation
        .executable
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("governed-executor-representation-rewind:{error}"))?;
    let mut measured = Vec::new();
    representation
        .executable
        .read_to_end(&mut measured)
        .map_err(|error| format!("governed-executor-representation-read:{error}"))?;
    if measured != bytes {
        return Err("governed-executor-representation-content-mismatch".to_owned());
    }
    representation
        .executable
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("governed-executor-representation-rewind:{error}"))?;
    let authority = platform_authority_closure(&representation.authority)?;
    Ok(PreparedExecutionRepresentation {
        executable: representation.executable,
        content: Some(file_content_digest(&measured)),
        method: Some(representation.method.to_owned()),
        authority: Some(authority),
    })
}

#[cfg(not(target_os = "freebsd"))]
fn execution_representation(
    mut source: File,
    _representation_base: &Path,
    _bytes: &[u8],
) -> Result<PreparedExecutionRepresentation, String> {
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("governed-executor-rewind:{error}"))?;
    Ok(PreparedExecutionRepresentation {
        executable: source,
        content: None,
        method: None,
        authority: None,
    })
}

fn executor_invocation_method(binding: &ExecutorBindingV1) -> &'static str {
    if binding.representation_method.as_deref()
        == Some(gwr_freebsd_exec::PRIVATE_UNLINKED_REGULAR_VNODE_V1)
    {
        REPRESENTATION_INVOCATION_V1
    } else {
        DESCRIPTOR_INVOCATION_V1
    }
}

fn resolve_executor_selection(
    config: &Path,
    _expected_work_schema: &str,
    expected_plan: &str,
) -> Result<Option<String>, String> {
    let metadata = std::fs::symlink_metadata(config)
        .map_err(|error| format!("governed-executor-config-metadata:{error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 16 * 1024 * 1024
    {
        return Err("governed-executor-config-not-bounded-regular-nonsymlink".to_owned());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(config)
        .map_err(|error| format!("governed-executor-config-open:{error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("governed-executor-config-opened-metadata:{error}"))?;
    if opened.len() != metadata.len() {
        return Err("governed-executor-config-raced".to_owned());
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len())
            .map_err(|_| "governed-executor-config-size-overflow".to_owned())?,
    );
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("governed-executor-config-read:{error}"))?;
    if bytes.len() as u64 != opened.len() {
        return Err("governed-executor-config-raced".to_owned());
    }
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        != Some(b'{')
    {
        return Ok(None);
    }
    let value: serde_json::Value = strict_json(&bytes, "governed-executor-config")?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "governed-executor-config-schema".to_owned())?;
    if schema.is_empty() || schema.len() > 256 || !schema.is_ascii() {
        return Err("governed-executor-config-schema".to_owned());
    }
    if value.get("governed_executor").is_none() {
        return Ok(None);
    }
    let canonical = serde_jcs::to_vec(&value)
        .map_err(|error| format!("governed-executor-config-canonical:{error}"))?;
    // The config's self-describing identity domain and AG's opaque catalog
    // work-schema are distinct contracts. AG binds the already-derived exact
    // work identity; Docket independently reproduces that identity here and
    // interprets only the generic nested executor-selection envelope.
    if hash_domain(schema, &canonical) != expected_plan {
        return Err("governed-executor-plan-substitution".to_owned());
    }
    let selection: ExecutorSelectionWireV1 = serde_json::from_value(
        value
            .get("governed_executor")
            .cloned()
            .ok_or_else(|| "governed-executor-selection-missing".to_owned())?,
    )
    .map_err(|error| format!("governed-executor-selection:{error}"))?;
    if selection.schema != EXECUTOR_SELECTION_SCHEMA_V1 {
        return Err("governed-executor-selection-schema".to_owned());
    }
    require_digest(&selection.expected_content, "expected executor content")?;
    Ok(Some(selection.expected_content))
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

struct DescriptorInvocationV1 {
    descriptor_exec_accepted: bool,
    input: Vec<u8>,
    output: gwr_freebsd_exec::DescriptorExecOutput,
}

impl DescriptorInvocationV1 {
    fn decode<O: DeserializeOwned>(self) -> Result<O, String> {
        if !self.descriptor_exec_accepted {
            return Err(format!(
                "descriptor-executor-not-invoked:{}",
                self.output.exec_errno.unwrap_or(libc::EIO)
            ));
        }
        if self.output.exit_code != Some(0) || self.output.signal.is_some() {
            return Err(format!(
                "descriptor-executor-refused:exit={:?}:signal={:?}:{}",
                self.output.exit_code,
                self.output.signal,
                String::from_utf8_lossy(&self.output.stderr)
                    .chars()
                    .take(512)
                    .collect::<String>()
            ));
        }
        strict_json(&self.output.stdout, "descriptor-executor-response")
    }
}

fn invoke_descriptor_json<I: Serialize + ?Sized>(
    program: &File,
    arguments: &[&str],
    input: &I,
) -> Result<DescriptorInvocationV1, String> {
    let input = serde_json::to_vec(input).map_err(|error| format!("process-request:{error}"))?;
    let argv = std::iter::once("docket-governed-executor")
        .chain(arguments.iter().copied())
        .map(|argument| {
            CString::new(argument.as_bytes())
                .map_err(|_| "descriptor executor argument contains NUL".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let output = gwr_freebsd_exec::invoke(program, &argv, &input)
        .map_err(|error| format!("descriptor-executor-invoke:{error}"))?;
    Ok(DescriptorInvocationV1 {
        descriptor_exec_accepted: output.descriptor_exec_accepted,
        input,
        output,
    })
}

fn file_content_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn pause_after_executor_custody() -> Result<(), String> {
    pause_for_fault_injection(
        "DOCKET_M5_EXECUTOR_READY_PATH",
        "DOCKET_M5_EXECUTOR_RESUME_PATH",
        "opened_and_measured",
    )
}

fn pause_after_executor_revalidation() -> Result<(), String> {
    pause_for_fault_injection(
        "DOCKET_M5_REVALIDATED_READY_PATH",
        "DOCKET_M5_REVALIDATED_RESUME_PATH",
        "revalidated_before_descriptor_invoke",
    )
}

fn pause_for_fault_injection(
    ready_variable: &str,
    resume_variable: &str,
    witness: &str,
) -> Result<(), String> {
    #[cfg(feature = "fault-injection")]
    {
        let ready = std::env::var_os(ready_variable);
        let resume = std::env::var_os(resume_variable);
        if ready.is_some() != resume.is_some() {
            return Err("M5 executor custody coordination is incomplete".to_owned());
        }
        if let Some((ready, resume)) = ready.zip(resume) {
            let ready = std::path::PathBuf::from(ready);
            let resume = std::path::PathBuf::from(resume);
            if !ready.is_absolute() || !resume.is_absolute() {
                return Err("M5 executor custody coordination paths must be absolute".to_owned());
            }
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&ready)
                .and_then(|mut file| {
                    file.write_all(witness.as_bytes())?;
                    file.write_all(b"\n")?;
                    file.sync_all()
                })
                .map_err(|error| format!("M5 executor custody ready witness:{error}"))?;
            for _ in 0..3_000 {
                if resume.is_file() {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            return Err("M5 executor custody coordination timed out".to_owned());
        }
    }
    #[cfg(not(feature = "fault-injection"))]
    let _ = (ready_variable, resume_variable, witness);
    Ok(())
}

fn invoke_json<I: Serialize + ?Sized, O: DeserializeOwned>(
    program: &Path,
    arguments: &[&str],
    input: &I,
) -> Result<O, String> {
    let bytes = serde_json::to_vec(input).map_err(|error| format!("process-request:{error}"))?;

    #[cfg(target_os = "freebsd")]
    let (stdout, stderr, success) = {
        use std::os::unix::ffi::OsStrExt as _;

        let mut argv = Vec::with_capacity(arguments.len() + 1);
        argv.push(
            CString::new(program.as_os_str().as_bytes())
                .map_err(|_| "process program path contains NUL".to_owned())?,
        );
        for argument in arguments {
            argv.push(
                CString::new(argument.as_bytes())
                    .map_err(|_| "process argument contains NUL".to_owned())?,
            );
        }
        let output = gwr_freebsd_exec::invoke_path(program, &argv, &bytes)
            .map_err(|error| format!("process-spawn:{}:{error}", program.display()))?;
        let success = output.exit_code == Some(0) && output.signal.is_none();
        (output.stdout, output.stderr, success)
    };

    #[cfg(not(target_os = "freebsd"))]
    let (stdout, stderr, success) = {
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
        (output.stdout, output.stderr, output.status.success())
    };

    if !success {
        return Err(format!(
            "process-refused:{}",
            String::from_utf8_lossy(&stderr)
                .chars()
                .take(512)
                .collect::<String>()
        ));
    }
    strict_json(&stdout, "process-response")
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
        standing: ExecutionStandingResolutionV1,
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
            standing,
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
    fn exact_resolver_mode_replay_returns_existing_custody_before_new_journal_or_launch() {
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
        let journal = fixture.root.join("must-not-exist.jsonl");
        let replay = accept_with_standing_resolver_custody(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.root.join("missing-standing-resolver"),
            Some(&StandingResolverExactCustodyV1 {
                expected_content: digest("not-consulted-on-replay"),
                journal: journal.clone(),
            }),
            &fixture.root.join("missing-executor"),
            &fixture.root.join("missing-config"),
        )
        .unwrap();
        assert_eq!(replay, accepted);
        assert!(!journal.exists());
    }

    fn test_exact_resolver_invocation(
        fixture: &Fixture,
        journal_name: &str,
        output: gwr_freebsd_exec::DescriptorExecOutput,
    ) -> StandingResolverInvocationV1 {
        let expected = digest("resolver-content");
        StandingResolverInvocationV1 {
            journal: StandingResolverJournalV1::create(
                &fixture.root.join(journal_name),
                digest("resolver-launch"),
                fixture.issuance.issuance.clone(),
                digest("resolver-request"),
                expected.clone(),
            )
            .unwrap(),
            source_candidate_content: expected.clone(),
            representation_content: expected,
            representation_method: gwr_freebsd_exec::PRIVATE_UNLINKED_REGULAR_VNODE_V1.to_owned(),
            representation_device: 1,
            representation_inode: 2,
            representation_links: 0,
            representation_authority: ExecutionRepresentationAuthorityClosureWireV1 {
                schema: gwr_freebsd_exec::AUTHORITY_CLOSURE_SCHEMA_V1.to_owned(),
                creator: "docket_standing_resolver".to_owned(),
                representation_method: gwr_freebsd_exec::PRIVATE_UNLINKED_REGULAR_VNODE_V1
                    .to_owned(),
                writer_descriptors_created: 1,
                writer_descriptors_duplicated: 0,
                writer_descriptors_closed_before_measurement: 1,
                writable_descriptors_surviving_finalization: 0,
                writable_descriptors_inherited: 0,
                representation_links_at_finalization: 0,
                surviving_descriptor_access: "read_only".to_owned(),
                surviving_rights_profile: gwr_freebsd_exec::FIRST_STAGE_RIGHTS_PROFILE_V1
                    .to_owned(),
                direct_write_probe_errno: libc::EBADF,
                write_reacquisition_method: "openat_empty_path_rdwr".to_owned(),
                write_reacquisition_errno: 93,
                finalization_sequence: 4,
                measurement_sequence: 5,
                invocation_sequence: 7,
                descriptor_transfer: "read_only_reader_fork_inherited_for_fexecve".to_owned(),
            },
            output,
        }
    }

    #[test]
    fn exact_resolver_nonzero_and_malformed_responses_append_explicit_refusals() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let mut nonzero = test_exact_resolver_invocation(
            &fixture,
            "resolver-nonzero.jsonl",
            gwr_freebsd_exec::DescriptorExecOutput {
                descriptor_exec_accepted: true,
                exit_code: Some(78),
                signal: None,
                stdout: Vec::new(),
                stderr: b"resolver refused".to_vec(),
                exec_errno: None,
            },
        );
        assert!(
            decode_exact_standing_response(&mut nonzero, &fixture.issuance, u64::MAX - 1)
                .unwrap_err()
                .starts_with("standing-resolver-refused")
        );
        drop(nonzero);
        let nonzero_journal =
            std::fs::read_to_string(fixture.root.join("resolver-nonzero.jsonl")).unwrap();
        assert!(nonzero_journal.contains("\"refusal\":\"resolver_process_refused\""));
        assert!(!nonzero_journal.contains("\"stage\":\"accepted\""));

        let mut malformed = test_exact_resolver_invocation(
            &fixture,
            "resolver-malformed.jsonl",
            gwr_freebsd_exec::DescriptorExecOutput {
                descriptor_exec_accepted: true,
                exit_code: Some(0),
                signal: None,
                stdout: b"{".to_vec(),
                stderr: Vec::new(),
                exec_errno: None,
            },
        );
        assert!(
            decode_exact_standing_response(&mut malformed, &fixture.issuance, u64::MAX - 1)
                .unwrap_err()
                .starts_with("process-response-json")
        );
        drop(malformed);
        let malformed_journal =
            std::fs::read_to_string(fixture.root.join("resolver-malformed.jsonl")).unwrap();
        assert!(malformed_journal.contains("\"refusal\":\"resolver_response_decode_refused\""));
        assert!(!malformed_journal.contains("\"stage\":\"accepted\""));
    }

    #[test]
    fn accepted_journal_record_exactly_binds_committed_attempt_and_standing() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let custody = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let connection = Connection::open(&fixture.database).unwrap();
        let stored_attempt: String = connection
            .query_row(
                "SELECT attempt FROM governed_loop_attempt WHERE issuance=?1",
                [&fixture.issuance.issuance],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_attempt, custody.attempt);
        drop(connection);

        let path = fixture.root.join("resolver-accepted.jsonl");
        let mut journal = StandingResolverJournalV1::create(
            &path,
            digest("resolver-launch"),
            fixture.issuance.issuance.clone(),
            digest("resolver-request"),
            digest("resolver-content"),
        )
        .unwrap();
        journal
            .append_accepted(&fixture.standing, &custody)
            .unwrap();
        drop(journal);
        let value: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(path).unwrap().trim()).unwrap();
        assert_eq!(value["stage"], "accepted");
        assert_eq!(value["docket_attempt"], custody.attempt);
        assert_eq!(value["executor_marker"], custody.executor_marker);
        assert_eq!(value["standing_resolution"], fixture.standing.resolution);
        assert_eq!(
            value["execution_standing"],
            fixture.standing.execution_standing
        );
        assert!(value.get("standing_input_set").is_none());
        assert!(value.get("standing_input_set_sha256").is_none());
    }

    fn exact_input_set(ttl_ms: u64, inode: u64) -> StandingResolverInputSetV1 {
        StandingResolverInputSetV1 {
            schema: STANDING_RESOLVER_INPUT_SET_SCHEMA_V1.to_owned(),
            request_sha256: digest("resolver-request"),
            now_unix_ms: 1_787_463_534_049,
            ttl_ms,
            time_source: "docket_system_time_unix_epoch_ms".to_owned(),
            custody_directory_locator: "/var/db/civild-standing/example".to_owned(),
            custody_directory_projection: StandingResolverCustodyDirectoryProjectionV1 {
                object_type: "directory".to_owned(),
                device: 7,
                inode,
                mode: libc::S_IFDIR | 0o700,
                uid: 1001,
                gid: 1001,
                links: 2,
                semantic_role: "exact_request_response_custody".to_owned(),
                access_method: "fixed_inherited_directory_fd_openat_nofollow_v1".to_owned(),
                inherited_fd: gwr_freebsd_exec::EXACT_CUSTODY_DIRECTORY_FD_V1,
                request_entry: "docket-standing-request.json".to_owned(),
                response_entry: "docket-standing-response.json".to_owned(),
                update_semantics: "create_exclusive_or_byte_identical_v1".to_owned(),
            },
            argv: vec!["docket-standing-resolver".to_owned()],
            environment: vec![
                "CIVIL_M3_DOCKET_STANDING_CUSTODY_FD=64".to_owned(),
                format!("CIVIL_M3_STANDING_TTL_MS={ttl_ms}"),
            ],
            working_directory: "/".to_owned(),
            inherited_descriptor_profile:
                "stdio_exact_custody_directory_plus_unobserved_inherited_descriptors_v1".to_owned(),
            umask_octal: "0077".to_owned(),
        }
    }

    #[test]
    fn exact_custody_locator_refuses_relative_and_dot_component_paths() {
        assert_eq!(
            exact_standing_custody_locator(Path::new("/var/db/civild-standing/occurrence"))
                .unwrap(),
            "/var/db/civild-standing/occurrence"
        );
        for refused in [
            "var/db/civild-standing/occurrence",
            "/var/db/./civild-standing/occurrence",
            "/var/db/civild-standing/../other",
        ] {
            assert!(exact_standing_custody_locator(Path::new(refused)).is_err());
        }
    }

    #[test]
    fn launch_v2_binds_exact_material_input_set_without_reinterpreting_v1() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let input = exact_input_set(60_000, 41);
        let digest_a = standing_resolver_input_set_digest(&input).unwrap();
        let ttl_changed = standing_resolver_input_set_digest(&exact_input_set(60_001, 41)).unwrap();
        let directory_changed =
            standing_resolver_input_set_digest(&exact_input_set(60_000, 42)).unwrap();
        assert_ne!(digest_a, ttl_changed);
        assert_ne!(digest_a, directory_changed);

        let launch = standing_resolver_launch_identity_v2(
            &digest("resolver-content"),
            &fixture.issuance.issuance,
            &input.request_sha256,
            &digest_a,
        )
        .unwrap();
        let substituted = standing_resolver_launch_identity_v2(
            &digest("resolver-content"),
            &fixture.issuance.issuance,
            &input.request_sha256,
            &ttl_changed,
        )
        .unwrap();
        assert_ne!(launch, substituted);

        let path = fixture.root.join("resolver-input-set-v2.jsonl");
        let mut journal = StandingResolverJournalV1::create_v2(
            &path,
            launch.clone(),
            fixture.issuance.issuance.clone(),
            input.request_sha256.clone(),
            digest("resolver-content"),
            digest_a.clone(),
            input.clone(),
        )
        .unwrap();
        journal
            .append(journal.base_record(StandingResolverLaunchStageV1::Prepared))
            .unwrap();
        drop(journal);
        let record: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(path).unwrap().trim()).unwrap();
        assert_eq!(record["schema"], STANDING_RESOLVER_LAUNCH_RECORD_SCHEMA_V2);
        assert_eq!(record["launch"], launch);
        assert_eq!(record["standing_input_set_sha256"], digest_a);
        assert_eq!(record["standing_input_set"]["ttl_ms"], 60_000);
        assert_eq!(
            record["standing_input_set"]["custody_directory_projection"]["inode"],
            41
        );
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn exact_resolver_content_mismatch_refuses_before_attempt_custody() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let journal = fixture.root.join("resolver-mismatch.jsonl");
        let error = accept_with_standing_resolver_custody(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            Some(&StandingResolverExactCustodyV1 {
                expected_content: digest("different-valid-resolver"),
                journal: journal.clone(),
            }),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap_err();
        assert_eq!(error, "standing-resolver-content-identity-mismatch");
        let records = std::fs::read_to_string(journal).unwrap();
        assert_eq!(records.lines().count(), 2);
        assert!(records.contains("\"stage\":\"prepared\""));
        assert!(records.contains("\"stage\":\"refused\""));
        let connection = Connection::open(&fixture.database).unwrap();
        let attempts: i64 = connection
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(attempts, 0);
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

    #[test]
    fn governed_selection_binds_exact_config_and_measures_without_execution() {
        let root = std::env::temp_dir().join(format!(
            "docket-governed-selection-test-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let program = root.join("valid-alternative");
        let marker = root.join("executed");
        std::fs::write(&program, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
        let actual = file_content_digest(&std::fs::read(&program).unwrap());
        let expected = digest("different-authorized-first-stage");
        let schema = "civil.managed-file.executor-plan/v3";
        let work_schema = "civil.managed-file.docket-work/v1";
        let config_value = serde_json::json!({
            "governed_executor": {
                "expected_content": expected,
                "schema": EXECUTOR_SELECTION_SCHEMA_V1,
            },
            "schema": schema,
            "subject": digest("subject"),
        });
        let config_bytes = serde_jcs::to_vec(&config_value).unwrap();
        let config = root.join("plan.json");
        std::fs::write(&config, &config_bytes).unwrap();
        let work = hash_domain(schema, &config_bytes);

        let resolved =
            resolve_executor_binding(&program, &config, &root, work_schema, &work).unwrap();
        assert_eq!(
            resolved.binding.program_content.as_deref(),
            Some(actual.as_str())
        );
        assert_eq!(
            resolved.binding.expected_content.as_deref(),
            config_value["governed_executor"]["expected_content"].as_str()
        );
        assert!(resolved.opened_program.is_some());
        assert!(
            !marker.exists(),
            "candidate must not run while being selected"
        );

        let mut substituted = config_value;
        substituted["subject"] = serde_json::Value::String(digest("other-subject"));
        std::fs::write(&config, serde_jcs::to_vec(&substituted).unwrap()).unwrap();
        assert!(resolve_executor_binding(&program, &config, &root, work_schema, &work).is_err());
        std::fs::remove_dir_all(root).unwrap();
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
