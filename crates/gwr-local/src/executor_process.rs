//! Durable local process host for the canonical governed-executor transport.
//!
//! The host implements Docket's frozen `plan-id`, `execute`, and `reconcile`
//! process surface. It durably reserves an exact dispatch before invoking an
//! adapter and never invokes the adapter's `execute` operation again for the
//! same attempt. The adapter receives the unchanged V1 dispatch and returns
//! the unchanged V1 outcome; no AG or Codex wire is introduced here.

use crate::governed_loop::{
    ExecutorDispatchWireV1, ExecutorOutcomeClassWireV1, ExecutorOutcomeWireV1,
    MAX_EXECUTOR_DOCUMENT_BYTES,
};
use gwr_runtime::governed_loop::{hash_domain, require_digest};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub const LOCAL_EXECUTOR_CONFIG_SCHEMA_V1: &str = "docket.local-governed-executor-config/v1";
pub const LOCAL_EXECUTOR_ADAPTER_SCHEMA_V1: &str = "docket.local-governed-executor-adapter/v1";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_ADAPTER_PROGRAM_BYTES: u64 = 512 * 1024 * 1024;
static NEXT_STAGE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalExecutorConfigV1 {
    pub schema: String,
    pub state_database: String,
    pub work_schema: String,
    pub subject: String,
    pub scope: String,
    pub adapter_program: String,
    pub adapter_config: String,
}

#[derive(Debug)]
struct ResolvedConfigV1 {
    config: LocalExecutorConfigV1,
    plan: String,
    program_bytes: Vec<u8>,
    program_digest: String,
    adapter_config_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AttemptRowV1 {
    plan: String,
    dispatch: ExecutorDispatchWireV1,
    fence_device: i64,
    fence_inode: i64,
    status: String,
    outcome: Option<ExecutorOutcomeWireV1>,
}

/// Reads one bounded, strict V1 dispatch document and validates digest syntax.
pub fn decode_dispatch(bytes: &[u8]) -> Result<ExecutorDispatchWireV1, String> {
    if bytes.is_empty() || bytes.len() > MAX_EXECUTOR_DOCUMENT_BYTES {
        return Err("local-executor-dispatch-size".to_owned());
    }
    let dispatch: ExecutorDispatchWireV1 = strict_json(bytes, "local-executor-dispatch")?;
    for (value, label) in [
        (&dispatch.attempt, "dispatch attempt"),
        (&dispatch.marker, "dispatch marker"),
        (&dispatch.work, "dispatch work"),
        (&dispatch.subject, "dispatch subject"),
        (&dispatch.scope, "dispatch scope"),
    ] {
        require_digest(value, label)?;
    }
    if dispatch.work_schema.is_empty() {
        return Err("local-executor-work-schema-empty".to_owned());
    }
    Ok(dispatch)
}

/// Resolves the exact content-derived plan identity without opening state.
pub fn plan_id(config_path: &Path) -> Result<String, String> {
    Ok(resolve_config(config_path)?.plan)
}

/// Reserves one exact dispatch durably, then invokes adapter mechanics once.
pub fn execute(
    config_path: &Path,
    dispatch: &ExecutorDispatchWireV1,
) -> Result<ExecutorOutcomeWireV1, String> {
    let resolved = resolve_config(config_path)?;
    validate_dispatch_binding(&resolved, dispatch)?;
    let staged_adapter = stage_adapter(&resolved)?;
    let (mut connection, _state_identity) =
        open_execute_store(Path::new(&resolved.config.state_database))?;

    let operation_fence = {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("local-executor-reservation-transaction:{error}"))?;
        if let Some(existing) = load_attempt(&transaction, &dispatch.attempt)? {
            validate_existing(&existing, &resolved.plan, dispatch)?;
            let result = match existing.status.as_str() {
                "settled" | "indeterminate" => existing
                    .outcome
                    .ok_or_else(|| "local-executor-stored-outcome-missing".to_owned()),
                "dispatched" => Err("local-executor-reconciliation-required".to_owned()),
                _ => Err("local-executor-stored-status".to_owned()),
            };
            transaction
                .commit()
                .map_err(|error| format!("local-executor-reservation-commit:{error}"))?;
            return result;
        }
        let operation_fence = open_operation_fence(&resolved, dispatch)?;
        let (fence_device, fence_inode) = operation_fence_identity(&operation_fence)?;
        transaction
            .execute(
                "INSERT INTO local_governed_executor_attempt
                 (attempt,plan,marker,work_schema,work,subject,scope,fence_device,fence_inode,status)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'dispatched')",
                params![
                    dispatch.attempt,
                    resolved.plan,
                    dispatch.marker,
                    dispatch.work_schema,
                    dispatch.work,
                    dispatch.subject,
                    dispatch.scope,
                    fence_device,
                    fence_inode,
                ],
            )
            .map_err(|error| format!("local-executor-reservation-insert:{error}"))?;
        transaction
            .commit()
            .map_err(|error| format!("local-executor-reservation-commit:{error}"))?;
        operation_fence
    };

    let transaction = begin_operation_fence(&mut connection)?;
    let current = load_attempt(&transaction, &dispatch.attempt)?
        .ok_or_else(|| "local-executor-attempt-disappeared".to_owned())?;
    validate_existing(&current, &resolved.plan, dispatch)?;
    validate_operation_fence_identity(&current, &operation_fence)?;
    if current.status != "dispatched" {
        let retained = current
            .outcome
            .ok_or_else(|| "local-executor-stored-outcome-missing".to_owned())?;
        transaction
            .commit()
            .map_err(|error| format!("local-executor-operation-fence-commit:{error}"))?;
        return Ok(retained);
    }
    let proposed = invoke_adapter(
        &resolved,
        &staged_adapter,
        operation_fence,
        "execute",
        dispatch,
    )?;
    let retained = persist_outcome(&transaction, &resolved.plan, dispatch, &proposed)?;
    transaction
        .commit()
        .map_err(|error| format!("local-executor-operation-fence-commit:{error}"))?;
    Ok(retained)
}

/// Reads retained evidence through the adapter's distinct reconcile operation.
/// This function can settle the host journal but can never invoke mechanics.
pub fn reconcile(
    config_path: &Path,
    dispatch: &ExecutorDispatchWireV1,
) -> Result<ExecutorOutcomeWireV1, String> {
    let resolved = resolve_config(config_path)?;
    validate_dispatch_binding(&resolved, dispatch)?;
    let staged_adapter = stage_adapter(&resolved)?;
    let (mut connection, _state_identity) =
        open_reconcile_store(Path::new(&resolved.config.state_database))?;
    let transaction = begin_operation_fence(&mut connection)?;
    let existing = load_attempt(&transaction, &dispatch.attempt)?
        .ok_or_else(|| "local-executor-attempt-not-reserved".to_owned())?;
    validate_existing(&existing, &resolved.plan, dispatch)?;
    if existing.status == "settled" {
        let retained = existing
            .outcome
            .ok_or_else(|| "local-executor-stored-outcome-missing".to_owned())?;
        transaction
            .commit()
            .map_err(|error| format!("local-executor-operation-fence-commit:{error}"))?;
        return Ok(retained);
    }
    if existing.status != "dispatched" && existing.status != "indeterminate" {
        return Err("local-executor-stored-status".to_owned());
    }
    let operation_fence = open_operation_fence(&resolved, dispatch)?;
    validate_operation_fence_identity(&existing, &operation_fence)?;
    let proposed = invoke_adapter(
        &resolved,
        &staged_adapter,
        operation_fence,
        "reconcile",
        dispatch,
    )?;
    let retained = persist_outcome(&transaction, &resolved.plan, dispatch, &proposed)?;
    transaction
        .commit()
        .map_err(|error| format!("local-executor-operation-fence-commit:{error}"))?;
    Ok(retained)
}

/// Emits the integer-only canonical JSON projection required by transport V1.
pub fn encode_outcome(outcome: &ExecutorOutcomeWireV1) -> Result<Vec<u8>, String> {
    let value = serde_json::json!({
        "attempt": outcome.attempt,
        "marker": outcome.marker,
        "outcome": outcome.outcome,
        "receipt": outcome.receipt,
    });
    let mut bytes = serde_json::to_vec(&value)
        .map_err(|error| format!("local-executor-outcome-encode:{error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn resolve_config(path: &Path) -> Result<ResolvedConfigV1, String> {
    if !path.is_absolute() {
        return Err("local-executor-config-path-not-absolute".to_owned());
    }
    let config_bytes = read_regular_nonsymlink(path, MAX_CONFIG_BYTES, "config")?;
    let config: LocalExecutorConfigV1 = strict_json(&config_bytes, "local-executor-config")?;
    if config.schema != LOCAL_EXECUTOR_CONFIG_SCHEMA_V1 {
        return Err("local-executor-config-schema".to_owned());
    }
    if config.work_schema.is_empty() || config.work_schema.len() > 128 {
        return Err("local-executor-config-work-schema".to_owned());
    }
    require_digest(&config.subject, "configured subject")?;
    require_digest(&config.scope, "configured scope")?;
    for (value, label) in [
        (&config.state_database, "state-database"),
        (&config.adapter_program, "adapter-program"),
        (&config.adapter_config, "adapter-config"),
    ] {
        if !Path::new(value).is_absolute() {
            return Err(format!("local-executor-{label}-path-not-absolute"));
        }
    }
    let adapter_program = Path::new(&config.adapter_program);
    let metadata = std::fs::symlink_metadata(adapter_program)
        .map_err(|error| format!("local-executor-adapter-program-metadata:{error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err("local-executor-adapter-program-not-executable-regular".to_owned());
    }
    let program_bytes = read_regular_nonsymlink(
        adapter_program,
        MAX_ADAPTER_PROGRAM_BYTES,
        "adapter-program",
    )?;
    let adapter_config_bytes = read_regular_nonsymlink(
        Path::new(&config.adapter_config),
        MAX_CONFIG_BYTES,
        "adapter-config",
    )?;
    let program_digest = hash_domain(
        "docket.local-governed-executor.adapter-program/v1",
        &program_bytes,
    );
    let basis = serde_json::json!({
        "adapter_config": config.adapter_config,
        "adapter_config_digest": hash_domain(
            "docket.local-governed-executor.adapter-config/v1",
            &adapter_config_bytes,
        ),
        "adapter_program": config.adapter_program,
        "adapter_program_digest": program_digest,
        "scope": config.scope,
        "schema": config.schema,
        "state_database": config.state_database,
        "subject": config.subject,
        "work_schema": config.work_schema,
    });
    let canonical = serde_json::to_vec(&basis)
        .map_err(|error| format!("local-executor-plan-canonical:{error}"))?;
    let plan = hash_domain("docket.local-governed-executor.plan/v1", &canonical);
    Ok(ResolvedConfigV1 {
        config,
        plan,
        program_bytes,
        program_digest,
        adapter_config_bytes,
    })
}

fn validate_dispatch_binding(
    resolved: &ResolvedConfigV1,
    dispatch: &ExecutorDispatchWireV1,
) -> Result<(), String> {
    for (value, label) in [
        (&dispatch.attempt, "dispatch attempt"),
        (&dispatch.marker, "dispatch marker"),
        (&dispatch.work, "dispatch work"),
        (&dispatch.subject, "dispatch subject"),
        (&dispatch.scope, "dispatch scope"),
    ] {
        require_digest(value, label)?;
    }
    if dispatch.work != resolved.plan
        || dispatch.work_schema != resolved.config.work_schema
        || dispatch.subject != resolved.config.subject
        || dispatch.scope != resolved.config.scope
    {
        return Err("local-executor-plan-binding-substitution".to_owned());
    }
    Ok(())
}

fn load_attempt(connection: &Connection, attempt: &str) -> Result<Option<AttemptRowV1>, String> {
    let raw = connection
        .query_row(
            "SELECT plan,marker,work_schema,work,subject,scope,fence_device,fence_inode,status,receipt,outcome
             FROM local_governed_executor_attempt WHERE attempt=?1",
            [attempt],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            },
        )
        .optional()
        .map_err(|error| format!("local-executor-attempt-read:{error}"))?;
    let Some((
        plan,
        marker,
        work_schema,
        work,
        subject,
        scope,
        fence_device,
        fence_inode,
        status,
        receipt,
        outcome,
    )) = raw
    else {
        return Ok(None);
    };
    let parsed_outcome = match (receipt, outcome) {
        (None, None) => None,
        (Some(receipt), Some(outcome)) => Some(ExecutorOutcomeWireV1 {
            attempt: attempt.to_owned(),
            marker: marker.clone(),
            receipt,
            outcome: parse_outcome(&outcome)?,
        }),
        _ => return Err("local-executor-stored-outcome-shape".to_owned()),
    };
    Ok(Some(AttemptRowV1 {
        plan,
        dispatch: ExecutorDispatchWireV1 {
            attempt: attempt.to_owned(),
            marker,
            work_schema,
            work,
            subject,
            scope,
        },
        fence_device,
        fence_inode,
        status,
        outcome: parsed_outcome,
    }))
}

fn validate_existing(
    existing: &AttemptRowV1,
    plan: &str,
    dispatch: &ExecutorDispatchWireV1,
) -> Result<(), String> {
    if existing.plan != plan || existing.dispatch != *dispatch {
        return Err("local-executor-attempt-substitution".to_owned());
    }
    match (existing.status.as_str(), existing.outcome.is_some()) {
        ("dispatched", false) | ("settled" | "indeterminate", true) => Ok(()),
        _ => Err("local-executor-stored-status-shape".to_owned()),
    }
}

fn invoke_adapter(
    resolved: &ResolvedConfigV1,
    staged_adapter: &File,
    operation_fence: File,
    operation: &str,
    dispatch: &ExecutorDispatchWireV1,
) -> Result<ExecutorOutcomeWireV1, String> {
    let dispatch_bytes = serde_json::to_vec(dispatch)
        .map_err(|error| format!("local-executor-adapter-request:{error}"))?;
    let config_length = u64::try_from(resolved.adapter_config_bytes.len())
        .map_err(|_| "local-executor-adapter-config-size-overflow".to_owned())?;
    let mut input_bytes =
        Vec::with_capacity(8 + resolved.adapter_config_bytes.len() + dispatch_bytes.len());
    input_bytes.extend_from_slice(&config_length.to_be_bytes());
    input_bytes.extend_from_slice(&resolved.adapter_config_bytes);
    input_bytes.extend_from_slice(&dispatch_bytes);
    let input = acquire_child_held_operation_fence(operation_fence, &input_bytes)?;
    let child_input = input
        .try_clone()
        .map_err(|error| format!("local-executor-operation-fence-clone:{error}"))?;
    let executable = format!("/proc/self/fd/{}", staged_adapter.as_raw_fd());
    let mut child = Command::new(executable)
        .arg(operation)
        .stdin(Stdio::from(child_input))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("local-executor-adapter-spawn:{error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "local-executor-adapter-stdout-unavailable".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "local-executor-adapter-stderr-unavailable".to_owned())?;
    let stdout_reader =
        std::thread::spawn(move || read_bounded_draining(stdout, MAX_EXECUTOR_DOCUMENT_BYTES));
    let stderr_reader = std::thread::spawn(move || read_bounded_draining(stderr, 2048));
    let status = child
        .wait()
        .map_err(|error| format!("local-executor-adapter-wait:{error}"))?;
    let (stdout, stdout_overflow) = stdout_reader
        .join()
        .map_err(|_| "local-executor-adapter-stdout-reader-panicked".to_owned())?
        .map_err(|error| format!("local-executor-adapter-stdout:{error}"))?;
    let (stderr, _) = stderr_reader
        .join()
        .map_err(|_| "local-executor-adapter-stderr-reader-panicked".to_owned())?
        .map_err(|error| format!("local-executor-adapter-stderr:{error}"))?;
    if !status.success() {
        return Err(format!(
            "local-executor-adapter-refused:{}",
            String::from_utf8_lossy(&stderr)
                .chars()
                .take(512)
                .collect::<String>()
        ));
    }
    if stdout_overflow {
        return Err("local-executor-adapter-response-exceeds-1-mib".to_owned());
    }
    let outcome: ExecutorOutcomeWireV1 = strict_json(&stdout, "local-executor-adapter-response")?;
    if outcome.attempt != dispatch.attempt || outcome.marker != dispatch.marker {
        return Err("local-executor-adapter-outcome-substitution".to_owned());
    }
    require_digest(&outcome.receipt, "adapter receipt")?;
    Ok(outcome)
}

fn open_operation_fence(
    resolved: &ResolvedConfigV1,
    dispatch: &ExecutorDispatchWireV1,
) -> Result<File, String> {
    let state_path = Path::new(&resolved.config.state_database);
    let parent = state_path
        .parent()
        .ok_or_else(|| "local-executor-state-database-parent-missing".to_owned())?;
    require_private_directory(parent, "state-parent")?;
    let fence_root = parent.join(".docket-governed-executor-operation-fences");
    match std::fs::create_dir(&fence_root) {
        Ok(()) => std::fs::set_permissions(&fence_root, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("local-executor-operation-fence-permissions:{error}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("local-executor-operation-fence-create:{error}")),
    }
    require_private_directory(&fence_root, "operation-fence-directory")?;
    let name = dispatch
        .attempt
        .strip_prefix("sha256:")
        .ok_or_else(|| "local-executor-operation-fence-attempt-digest".to_owned())?;
    let path = fence_root.join(name);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|error| format!("local-executor-operation-fence-open:{error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("local-executor-operation-fence-metadata:{error}"))?;
    let named = std::fs::symlink_metadata(&path)
        .map_err(|error| format!("local-executor-operation-fence-named-metadata:{error}"))?;
    if !metadata.is_file()
        || named.file_type().is_symlink()
        || !named.is_file()
        || metadata.dev() != named.dev()
        || metadata.ino() != named.ino()
        || named.permissions().mode() & 0o077 != 0
    {
        return Err("local-executor-operation-fence-pathname-replacement".to_owned());
    }
    Ok(file)
}

fn operation_fence_identity(file: &File) -> Result<(i64, i64), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("local-executor-operation-fence-metadata:{error}"))?;
    let device = i64::try_from(metadata.dev())
        .map_err(|_| "local-executor-operation-fence-device-overflow".to_owned())?;
    let inode = i64::try_from(metadata.ino())
        .map_err(|_| "local-executor-operation-fence-inode-overflow".to_owned())?;
    Ok((device, inode))
}

fn validate_operation_fence_identity(existing: &AttemptRowV1, file: &File) -> Result<(), String> {
    if operation_fence_identity(file)? != (existing.fence_device, existing.fence_inode) {
        return Err("local-executor-operation-fence-substitution".to_owned());
    }
    Ok(())
}

/// Takes an exclusive file-description lock before spawn. The child receives
/// a duplicate of this same opened file as stdin, so the Linux lock remains
/// held if the host dies while the adapter is still live.
fn acquire_child_held_operation_fence(mut file: File, input: &[u8]) -> Result<File, String> {
    file.try_lock()
        .map_err(|error| format!("local-executor-operation-in-flight:{error}"))?;
    file.set_len(0)
        .map_err(|error| format!("local-executor-operation-fence-truncate:{error}"))?;
    file.write_all(input)
        .map_err(|error| format!("local-executor-operation-fence-write:{error}"))?;
    file.sync_all()
        .map_err(|error| format!("local-executor-operation-fence-sync:{error}"))?;
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|error| format!("local-executor-operation-fence-seek:{error}"))?;
    Ok(file)
}
fn outcome_label(outcome: ExecutorOutcomeClassWireV1) -> &'static str {
    match outcome {
        ExecutorOutcomeClassWireV1::Success => "success",
        ExecutorOutcomeClassWireV1::Failure => "failure",
        ExecutorOutcomeClassWireV1::Indeterminate => "indeterminate",
    }
}
fn begin_operation_fence(connection: &mut Connection) -> Result<Transaction<'_>, String> {
    connection
        .busy_timeout(Duration::ZERO)
        .map_err(|error| format!("local-executor-operation-fence-timeout:{error}"))?;
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| format!("local-executor-operation-in-flight:{error}"))
}

fn persist_outcome(
    transaction: &Transaction<'_>,
    plan: &str,
    dispatch: &ExecutorDispatchWireV1,
    proposed: &ExecutorOutcomeWireV1,
) -> Result<ExecutorOutcomeWireV1, String> {
    let existing = load_attempt(transaction, &dispatch.attempt)?
        .ok_or_else(|| "local-executor-attempt-disappeared".to_owned())?;
    validate_existing(&existing, plan, dispatch)?;
    if let Some(retained) = existing.outcome {
        if retained == *proposed
            || existing.status == "settled"
            || (existing.status == "indeterminate"
                && proposed.outcome == ExecutorOutcomeClassWireV1::Indeterminate)
        {
            return Ok(retained);
        }
    }
    let status = match proposed.outcome {
        ExecutorOutcomeClassWireV1::Success | ExecutorOutcomeClassWireV1::Failure => "settled",
        ExecutorOutcomeClassWireV1::Indeterminate => "indeterminate",
    };
    let changed = transaction
        .execute(
            "UPDATE local_governed_executor_attempt
             SET status=?1,receipt=?2,outcome=?3
             WHERE attempt=?4 AND plan=?5
               AND (status='dispatched' OR status='indeterminate')",
            params![
                status,
                proposed.receipt,
                outcome_label(proposed.outcome),
                dispatch.attempt,
                plan
            ],
        )
        .map_err(|error| format!("local-executor-outcome-write:{error}"))?;
    if changed != 1 {
        return Err(format!(
            "local-executor-outcome-update-cardinality:{changed}"
        ));
    }
    Ok(proposed.clone())
}

fn parse_outcome(value: &str) -> Result<ExecutorOutcomeClassWireV1, String> {
    match value {
        "success" => Ok(ExecutorOutcomeClassWireV1::Success),
        "failure" => Ok(ExecutorOutcomeClassWireV1::Failure),
        "indeterminate" => Ok(ExecutorOutcomeClassWireV1::Indeterminate),
        _ => Err("local-executor-stored-outcome-class".to_owned()),
    }
}

fn strict_json<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("{label}-json:{error}"))
}

fn read_regular_nonsymlink(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let before = std::fs::symlink_metadata(path)
        .map_err(|error| format!("local-executor-{label}-metadata:{error}"))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(format!("local-executor-{label}-not-regular-nonsymlink"));
    }
    if before.len() > limit {
        return Err(format!("local-executor-{label}-too-large"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("local-executor-{label}-open:{error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("local-executor-{label}-opened-metadata:{error}"))?;
    if !opened.is_file() || opened.len() != before.len() {
        return Err(format!("local-executor-{label}-file-raced"));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len())
            .map_err(|_| format!("local-executor-{label}-size-overflow"))?,
    );
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("local-executor-{label}-read:{error}"))?;
    if bytes.len() as u64 != opened.len() {
        return Err(format!("local-executor-{label}-file-raced"));
    }
    Ok(bytes)
}

fn read_bounded_draining<R: Read>(mut reader: R, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::with_capacity(limit.min(8192));
    let mut overflow = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(retained.len());
        let keep = remaining.min(count);
        retained.extend_from_slice(&buffer[..keep]);
        overflow |= keep != count;
    }
    Ok((retained, overflow))
}

pub fn read_dispatch_stdin() -> Result<ExecutorDispatchWireV1, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_EXECUTOR_DOCUMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("local-executor-stdin:{error}"))?;
    decode_dispatch(&bytes)
}

pub fn write_outcome_stdout(outcome: &ExecutorOutcomeWireV1) -> Result<(), String> {
    std::io::stdout()
        .write_all(&encode_outcome(outcome)?)
        .map_err(|error| format!("local-executor-stdout:{error}"))
}

pub fn config_path(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err("local-executor-config-path-not-absolute".to_owned());
    }
    Ok(path)
}
fn open_execute_store(path: &Path) -> Result<(Connection, File), String> {
    let identity = open_state_identity(path, true)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .map_err(|error| format!("local-executor-store-open:{error}"))?;
    require_same_state_identity(path, &identity)?;
    configure_connection(&connection)?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS local_governed_executor_attempt (
                attempt TEXT PRIMARY KEY,
                plan TEXT NOT NULL,
                marker TEXT NOT NULL,
                work_schema TEXT NOT NULL,
                work TEXT NOT NULL,
                subject TEXT NOT NULL,
                scope TEXT NOT NULL,
                fence_device INTEGER NOT NULL,
                fence_inode INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('dispatched','settled','indeterminate')),
                receipt TEXT,
                outcome TEXT CHECK(outcome IN ('success','failure','indeterminate')),
                CHECK((status='dispatched' AND receipt IS NULL AND outcome IS NULL)
                   OR (status!='dispatched' AND receipt IS NOT NULL AND outcome IS NOT NULL))
            );",
        )
        .map_err(|error| format!("local-executor-store-schema:{error}"))?;
    require_same_state_identity(path, &identity)?;
    Ok((connection, identity))
}

fn open_reconcile_store(path: &Path) -> Result<(Connection, File), String> {
    let identity = open_state_identity(path, false)?;
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|error| format!("local-executor-store-open:{error}"))?;
    require_same_state_identity(path, &identity)?;
    configure_connection(&connection)?;
    let table: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='local_governed_executor_attempt'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("local-executor-store-schema-read:{error}"))?;
    if table.is_none() {
        return Err("local-executor-store-schema-missing".to_owned());
    }
    require_same_state_identity(path, &identity)?;
    Ok((connection, identity))
}

fn configure_connection(connection: &Connection) -> Result<(), String> {
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| format!("local-executor-store-busy-timeout:{error}"))?;
    connection
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
        .map_err(|error| format!("local-executor-store-pragmas:{error}"))
}

fn open_state_identity(path: &Path, may_create: bool) -> Result<File, String> {
    if !path.is_absolute() {
        return Err("local-executor-state-database-path-not-absolute".to_owned());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "local-executor-state-database-parent-missing".to_owned())?;
    require_private_directory(parent, "state-parent")?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600);
    if may_create {
        options.create(true);
    }
    let identity = options
        .open(path)
        .map_err(|error| format!("local-executor-state-database-open:{error}"))?;
    let metadata = identity
        .metadata()
        .map_err(|error| format!("local-executor-state-database-opened-metadata:{error}"))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("local-executor-state-database-permission-boundary".to_owned());
    }
    require_same_state_identity(path, &identity)?;
    Ok(identity)
}

fn require_same_state_identity(path: &Path, identity: &File) -> Result<(), String> {
    let opened = identity
        .metadata()
        .map_err(|error| format!("local-executor-state-database-opened-metadata:{error}"))?;
    let named = std::fs::symlink_metadata(path)
        .map_err(|error| format!("local-executor-state-database-named-metadata:{error}"))?;
    if named.file_type().is_symlink()
        || !named.is_file()
        || opened.dev() != named.dev()
        || opened.ino() != named.ino()
        || named.permissions().mode() & 0o077 != 0
    {
        return Err("local-executor-state-database-pathname-replacement".to_owned());
    }
    Ok(())
}

fn require_private_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("local-executor-{label}-metadata:{error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(format!("local-executor-{label}-permission-boundary"));
    }
    Ok(())
}

fn stage_adapter(resolved: &ResolvedConfigV1) -> Result<File, String> {
    let state_path = Path::new(&resolved.config.state_database);
    let parent = state_path
        .parent()
        .ok_or_else(|| "local-executor-state-database-parent-missing".to_owned())?;
    require_private_directory(parent, "state-parent")?;
    if !resolved.program_bytes.starts_with(b"\x7fELF") {
        return Err("local-executor-adapter-program-not-native-elf".to_owned());
    }
    let stage_root = parent.join(".docket-governed-executor-programs");
    match std::fs::create_dir(&stage_root) {
        Ok(()) => std::fs::set_permissions(&stage_root, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("local-executor-stage-permissions:{error}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("local-executor-stage-create:{error}")),
    }
    require_private_directory(&stage_root, "stage-directory")?;
    let name = resolved
        .program_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| "local-executor-stage-program-digest".to_owned())?;
    let staged = stage_root.join(name);
    if !staged.exists() {
        let temporary = stage_root.join(format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o700)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|error| format!("local-executor-stage-temp-open:{error}"))?;
        file.write_all(&resolved.program_bytes)
            .map_err(|error| format!("local-executor-stage-write:{error}"))?;
        file.sync_all()
            .map_err(|error| format!("local-executor-stage-sync:{error}"))?;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o500))
            .map_err(|error| format!("local-executor-stage-temp-permissions:{error}"))?;
        match std::fs::hard_link(&temporary, &staged) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(format!("local-executor-stage-publish:{error}"));
            }
        }
        std::fs::remove_file(&temporary)
            .map_err(|error| format!("local-executor-stage-temp-remove:{error}"))?;
    }
    let mut staged_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&staged)
        .map_err(|error| format!("local-executor-staged-program-open:{error}"))?;
    let metadata = staged_file
        .metadata()
        .map_err(|error| format!("local-executor-staged-program-metadata:{error}"))?;
    let mut staged_bytes = Vec::new();
    staged_file
        .read_to_end(&mut staged_bytes)
        .map_err(|error| format!("local-executor-staged-program-read:{error}"))?;
    if staged_bytes != resolved.program_bytes
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.permissions().mode() & 0o100 == 0
    {
        return Err("local-executor-staged-program-substitution".to_owned());
    }
    Ok(staged_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_pathname_replacement_is_detected_against_opened_identity() {
        let root = std::env::temp_dir().join(format!(
            "docket-state-identity-{}-{}",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join("executor.sqlite");
        let moved = root.join("executor-original.sqlite");
        let identity = open_state_identity(&state, true).unwrap();
        std::fs::rename(&state, &moved).unwrap();
        let replacement = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&state)
            .unwrap();
        drop(replacement);

        assert_eq!(
            require_same_state_identity(&state, &identity).unwrap_err(),
            "local-executor-state-database-pathname-replacement"
        );
        drop(identity);
        std::fs::remove_dir_all(root).unwrap();
    }
}
