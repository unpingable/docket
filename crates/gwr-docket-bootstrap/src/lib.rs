//! A deliberately small FreeBSD bootstrap for one exact Docket executable.
//!
//! This crate does not authorize work or interpret Docket domain records. It
//! consumes a deployment-custody selection, creates a finalized private
//! execution representation, measures that exact representation, refuses a
//! content mismatch, and invokes the same descriptor. The bootstrap itself is
//! the declared initial native TCB; it does not claim to bootstrap itself.

#![cfg_attr(not(target_os = "freebsd"), allow(dead_code))]

use gwr_freebsd_exec::{
    invoke_with_exec_observer, prepare_execution_representation_for,
    ExecutionRepresentationAuthorityClosure,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::ffi::{CString, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

pub const SELECTION_SCHEMA_V1: &str = "civil.docket.bootstrap-selection/v1";
pub const LAUNCH_RECORD_SCHEMA_V1: &str = "civil.docket.bootstrap-launch-record/v1";
pub const INVOCATION_METHOD_V1: &str = "freebsd_fexecve_private_unlinked_regular_vnode_v1";
pub const BOOTSTRAP_LINKAGE: &str = "static";
pub const BOOTSTRAP_CREATOR: &str = "docket_static_bootstrap";
const MAX_SELECTION_BYTES: usize = 64 * 1024;
const MAX_STDIN_BYTES: usize = 1024 * 1024;
const MAX_EXECUTABLE_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapSelection {
    pub schema: String,
    pub launch_id: String,
    pub expected_docket_content: String,
    pub signed_issuance_sha256: String,
    pub executor_plan_sha256: String,
    pub docket_trust_sha256: String,
    pub argv_sha256: String,
    pub stdin_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Options {
    selection: PathBuf,
    candidate: PathBuf,
    representation_base: PathBuf,
    journal: PathBuf,
    stdin: PathBuf,
    docket_argv: Vec<OsString>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthorityClosureWire {
    schema: String,
    creator: String,
    representation_method: String,
    writer_descriptors_created: u16,
    writer_descriptors_duplicated: u16,
    writer_descriptors_closed_before_measurement: u16,
    writable_descriptors_surviving_finalization: u16,
    writable_descriptors_inherited: u16,
    representation_links_at_finalization: u64,
    surviving_descriptor_access: String,
    surviving_rights_profile: String,
    direct_write_probe_errno: i32,
    write_reacquisition_method: String,
    write_reacquisition_errno: i32,
    finalization_sequence: u8,
    measurement_sequence: u8,
    invocation_sequence: u8,
    descriptor_transfer: String,
}

impl From<&ExecutionRepresentationAuthorityClosure> for AuthorityClosureWire {
    fn from(value: &ExecutionRepresentationAuthorityClosure) -> Self {
        Self {
            schema: value.schema.to_owned(),
            creator: value.creator.to_owned(),
            representation_method: value.representation_method.to_owned(),
            writer_descriptors_created: value.writer_descriptors_created,
            writer_descriptors_duplicated: value.writer_descriptors_duplicated,
            writer_descriptors_closed_before_measurement: value
                .writer_descriptors_closed_before_measurement,
            writable_descriptors_surviving_finalization: value
                .writable_descriptors_surviving_finalization,
            writable_descriptors_inherited: value.writable_descriptors_inherited,
            representation_links_at_finalization: value.representation_links_at_finalization,
            surviving_descriptor_access: value.surviving_descriptor_access.to_owned(),
            surviving_rights_profile: value.surviving_rights_profile.to_owned(),
            direct_write_probe_errno: value.direct_write_probe_errno,
            write_reacquisition_method: value.write_reacquisition_method.to_owned(),
            write_reacquisition_errno: value.write_reacquisition_errno,
            finalization_sequence: value.finalization_sequence,
            measurement_sequence: value.measurement_sequence,
            invocation_sequence: value.invocation_sequence,
            descriptor_transfer: value.descriptor_transfer.to_owned(),
        }
    }
}

#[derive(Debug, Serialize)]
struct LaunchRecord<'a> {
    schema: &'static str,
    launch_id: &'a str,
    sequence: u8,
    stage: &'static str,
    prior_record_sha256: Option<String>,
    selection_sha256: &'a str,
    expected_docket_content: &'a str,
    source_candidate_content: Option<&'a str>,
    private_representation_content: Option<&'a str>,
    argv_sha256: &'a str,
    stdin_sha256: &'a str,
    environment_sha256: &'a str,
    environment_transfer: &'static str,
    representation_method: Option<&'a str>,
    representation_device: Option<u64>,
    representation_inode: Option<u64>,
    representation_links: Option<u64>,
    authority_closure: Option<&'a AuthorityClosureWire>,
    invocation_method: &'static str,
    bootstrap_linkage: &'static str,
    content_match: Option<bool>,
    descriptor_exec_accepted: bool,
    child_stdout_sha256: Option<&'a str>,
    child_stderr_sha256: Option<&'a str>,
    child_exit_code: Option<i32>,
    child_signal: Option<i32>,
    exec_errno: Option<i32>,
    refusal: Option<&'a str>,
}

struct Journal {
    file: File,
    prior_record_sha256: Option<String>,
}

impl Journal {
    fn create(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        Ok(Self {
            file,
            prior_record_sha256: None,
        })
    }

    fn append(&mut self, record: &mut LaunchRecord<'_>) -> io::Result<()> {
        record.prior_record_sha256 = self.prior_record_sha256.clone();
        let bytes = serde_jcs::to_vec(record).map_err(io::Error::other)?;
        self.file.write_all(&bytes)?;
        self.file.write_all(b"\n")?;
        self.file.sync_all()?;
        self.prior_record_sha256 = Some(digest(&bytes));
        Ok(())
    }
}

#[derive(Debug)]
enum BootstrapError {
    Usage(String),
    Refusal(String),
    Io(io::Error),
}

impl From<io::Error> for BootstrapError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) | Self::Refusal(message) => formatter.write_str(message),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

fn require_absolute_bounded_path(value: OsString, label: &str) -> Result<PathBuf, BootstrapError> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(BootstrapError::Usage(format!(
            "{label} must be an absolute path without dot components"
        )));
    }
    Ok(path)
}

fn parse_options<I>(arguments: I) -> Result<Options, BootstrapError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut values = arguments.into_iter();
    let _program = values.next();
    let mut selection = None;
    let mut candidate = None;
    let mut representation_base = None;
    let mut journal = None;
    let mut stdin = None;
    let mut docket_argv = Vec::new();
    while let Some(value) = values.next() {
        if value == "--" {
            docket_argv.extend(values);
            break;
        }
        let slot = match value.to_str() {
            Some("--selection") => &mut selection,
            Some("--candidate") => &mut candidate,
            Some("--representation-base") => &mut representation_base,
            Some("--journal") => &mut journal,
            Some("--stdin") => &mut stdin,
            _ => {
                return Err(BootstrapError::Usage(format!(
                    "unknown bootstrap argument {:?}",
                    value
                )))
            }
        };
        if slot.is_some() {
            return Err(BootstrapError::Usage(
                "duplicate bootstrap argument".to_owned(),
            ));
        }
        *slot = values.next();
        if slot.is_none() {
            return Err(BootstrapError::Usage(
                "missing bootstrap argument value".to_owned(),
            ));
        }
    }
    if docket_argv.is_empty() {
        return Err(BootstrapError::Usage(
            "missing Docket argv after --".to_owned(),
        ));
    }
    Ok(Options {
        selection: require_absolute_bounded_path(
            selection.ok_or_else(|| BootstrapError::Usage("missing --selection".to_owned()))?,
            "selection",
        )?,
        candidate: require_absolute_bounded_path(
            candidate.ok_or_else(|| BootstrapError::Usage("missing --candidate".to_owned()))?,
            "candidate",
        )?,
        representation_base: require_absolute_bounded_path(
            representation_base
                .ok_or_else(|| BootstrapError::Usage("missing --representation-base".to_owned()))?,
            "representation base",
        )?,
        journal: require_absolute_bounded_path(
            journal.ok_or_else(|| BootstrapError::Usage("missing --journal".to_owned()))?,
            "journal",
        )?,
        stdin: require_absolute_bounded_path(
            stdin.ok_or_else(|| BootstrapError::Usage("missing --stdin".to_owned()))?,
            "stdin",
        )?,
        docket_argv,
    })
}

fn read_regular_no_follow(
    path: &Path,
    limit: usize,
    require_executable: bool,
) -> io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded regular file required",
        ));
    }
    if require_executable && before.mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable mode required",
        ));
    }
    if require_executable
        && (before.mode() & 0o022 != 0 || before.uid() != unsafe { libc::geteuid() })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable candidate custody",
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() > limit
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file changed while read",
        ));
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn framed_digest(values: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((values.len() as u64).to_be_bytes());
    for value in values {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn argv_digest(argv: &[OsString]) -> String {
    framed_digest(
        &argv
            .iter()
            .map(|value| value.as_os_str().as_bytes().to_vec())
            .collect::<Vec<_>>(),
    )
}

fn environment_digest() -> String {
    let mut values = std::env::vars_os()
        .map(|(name, value)| {
            let mut bytes = name.as_os_str().as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_os_str().as_bytes());
            bytes
        })
        .collect::<Vec<_>>();
    values.sort();
    framed_digest(&values)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_selection(selection: &BootstrapSelection) -> Result<(), BootstrapError> {
    if selection.schema != SELECTION_SCHEMA_V1 {
        return Err(BootstrapError::Refusal(
            "unsupported selection schema".to_owned(),
        ));
    }
    if selection.launch_id.is_empty() || selection.launch_id.len() > 256 {
        return Err(BootstrapError::Refusal(
            "invalid launch identity".to_owned(),
        ));
    }
    if !selection
        .launch_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(BootstrapError::Refusal(
            "invalid launch identity spelling".to_owned(),
        ));
    }
    for (label, value) in [
        (
            "expected Docket content",
            &selection.expected_docket_content,
        ),
        ("signed issuance", &selection.signed_issuance_sha256),
        ("executor plan", &selection.executor_plan_sha256),
        ("Docket trust", &selection.docket_trust_sha256),
        ("argv", &selection.argv_sha256),
        ("stdin", &selection.stdin_sha256),
    ] {
        if !valid_digest(value) {
            return Err(BootstrapError::Refusal(format!("invalid {label} digest")));
        }
    }
    Ok(())
}

fn c_argv(values: &[OsString]) -> Result<Vec<CString>, BootstrapError> {
    values
        .iter()
        .map(|value| {
            CString::new(value.as_os_str().as_bytes())
                .map_err(|_| BootstrapError::Refusal("Docket argv contains NUL".to_owned()))
        })
        .collect()
}

#[cfg(feature = "fault-injection")]
fn pause_after_custody(launch_id: &str) -> Result<(), BootstrapError> {
    use std::time::{Duration, Instant};

    let ready = std::env::var_os("GWR_DOCKET_BOOTSTRAP_CUSTODY_READY");
    let resume = std::env::var_os("GWR_DOCKET_BOOTSTRAP_CUSTODY_RESUME");
    let (Some(ready), Some(resume)) = (&ready, &resume) else {
        if ready.is_some() || resume.is_some() {
            return Err(BootstrapError::Refusal(
                "incomplete custody qualification synchronization pair".to_owned(),
            ));
        }
        return Ok(());
    };
    let ready = require_absolute_bounded_path(ready.clone(), "custody ready")?;
    let resume = require_absolute_bounded_path(resume.clone(), "custody resume")?;
    let marker = format!("{launch_id}\n");
    let mut ready_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&ready)?;
    ready_file.write_all(marker.as_bytes())?;
    ready_file.sync_all()?;
    drop(ready_file);

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match read_regular_no_follow(&resume, 1024, false) {
            Ok(bytes) if bytes == marker.as_bytes() => return Ok(()),
            Ok(_) => {
                return Err(BootstrapError::Refusal(
                    "custody resume marker mismatch".to_owned(),
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err(BootstrapError::Refusal(
                "custody qualification synchronization timed out".to_owned(),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(not(feature = "fault-injection"))]
fn pause_after_custody(_launch_id: &str) -> Result<(), BootstrapError> {
    Ok(())
}

fn run(options: Options) -> Result<i32, BootstrapError> {
    let selection_bytes = read_regular_no_follow(&options.selection, MAX_SELECTION_BYTES, false)?;
    let selection_sha256 = digest(&selection_bytes);
    let selection: BootstrapSelection = serde_json::from_slice(&selection_bytes)
        .map_err(|error| BootstrapError::Refusal(format!("invalid selection: {error}")))?;
    validate_selection(&selection)?;

    let stdin = read_regular_no_follow(&options.stdin, MAX_STDIN_BYTES, false)?;
    let stdin_sha256 = digest(&stdin);
    let argv_sha256 = argv_digest(&options.docket_argv);
    let environment_sha256 = environment_digest();
    let mut journal = Journal::create(&options.journal)?;
    let base_record = |sequence, stage| LaunchRecord {
        schema: LAUNCH_RECORD_SCHEMA_V1,
        launch_id: &selection.launch_id,
        sequence,
        stage,
        prior_record_sha256: None,
        selection_sha256: &selection_sha256,
        expected_docket_content: &selection.expected_docket_content,
        source_candidate_content: None,
        private_representation_content: None,
        argv_sha256: &argv_sha256,
        stdin_sha256: &stdin_sha256,
        environment_sha256: &environment_sha256,
        environment_transfer: "same_key_value_environment_reencoded_for_fexecve_v1",
        representation_method: None,
        representation_device: None,
        representation_inode: None,
        representation_links: None,
        authority_closure: None,
        invocation_method: INVOCATION_METHOD_V1,
        bootstrap_linkage: BOOTSTRAP_LINKAGE,
        content_match: None,
        descriptor_exec_accepted: false,
        child_stdout_sha256: None,
        child_stderr_sha256: None,
        child_exit_code: None,
        child_signal: None,
        exec_errno: None,
        refusal: None,
    };

    if selection.stdin_sha256 != stdin_sha256
        || selection.signed_issuance_sha256 != stdin_sha256
        || selection.argv_sha256 != argv_sha256
    {
        let mut record = base_record(1, "refused");
        record.refusal = Some("bounded_input_identity_mismatch");
        journal.append(&mut record)?;
        return Ok(65);
    }

    let source_bytes = match read_regular_no_follow(&options.candidate, MAX_EXECUTABLE_BYTES, true)
    {
        Ok(bytes) => bytes,
        Err(error) => {
            let mut record = base_record(1, "refused");
            record.refusal = Some("candidate_acquisition_refused");
            record.exec_errno = error.raw_os_error();
            journal.append(&mut record)?;
            return Ok(65);
        }
    };
    let source_content = digest(&source_bytes);
    let mut representation = match prepare_execution_representation_for(
        &options.representation_base,
        &source_bytes,
        BOOTSTRAP_CREATOR,
    ) {
        Ok(representation) => representation,
        Err(error) => {
            let mut record = base_record(1, "refused");
            record.source_candidate_content = Some(&source_content);
            record.refusal = Some("representation_establishment_refused");
            record.exec_errno = error.raw_os_error();
            journal.append(&mut record)?;
            return Ok(65);
        }
    };
    representation.executable.seek(SeekFrom::Start(0))?;
    let mut representation_bytes = Vec::new();
    std::io::Read::by_ref(&mut representation.executable)
        .take(MAX_EXECUTABLE_BYTES as u64 + 1)
        .read_to_end(&mut representation_bytes)?;
    representation.executable.seek(SeekFrom::Start(0))?;
    if representation_bytes.len() > MAX_EXECUTABLE_BYTES {
        return Err(BootstrapError::Refusal(
            "private representation exceeds bound".to_owned(),
        ));
    }
    let representation_content = digest(&representation_bytes);
    let authority = AuthorityClosureWire::from(&representation.authority);
    let content_match = source_content == representation_content
        && representation_content == selection.expected_docket_content;
    let mut prepared = base_record(1, "prepared");
    prepared.source_candidate_content = Some(&source_content);
    prepared.private_representation_content = Some(&representation_content);
    prepared.representation_method = Some(representation.method);
    prepared.representation_device = Some(representation.device);
    prepared.representation_inode = Some(representation.inode);
    prepared.representation_links = Some(representation.links);
    prepared.authority_closure = Some(&authority);
    prepared.content_match = Some(content_match);
    journal.append(&mut prepared)?;
    if !content_match {
        let mut refused = base_record(2, "refused");
        refused.source_candidate_content = Some(&source_content);
        refused.private_representation_content = Some(&representation_content);
        refused.representation_method = Some(representation.method);
        refused.representation_device = Some(representation.device);
        refused.representation_inode = Some(representation.inode);
        refused.representation_links = Some(representation.links);
        refused.authority_closure = Some(&authority);
        refused.content_match = Some(false);
        refused.refusal = Some("docket_content_identity_mismatch");
        journal.append(&mut refused)?;
        return Ok(65);
    }

    if let Err(error) = pause_after_custody(&selection.launch_id) {
        let refusal = error.to_string();
        let mut refused = base_record(2, "refused");
        refused.source_candidate_content = Some(&source_content);
        refused.private_representation_content = Some(&representation_content);
        refused.representation_method = Some(representation.method);
        refused.representation_device = Some(representation.device);
        refused.representation_inode = Some(representation.inode);
        refused.representation_links = Some(representation.links);
        refused.authority_closure = Some(&authority);
        refused.content_match = Some(true);
        refused.refusal = Some(&refusal);
        journal.append(&mut refused)?;
        return Ok(65);
    }

    let argv = c_argv(&options.docket_argv)?;
    let output = invoke_with_exec_observer(&representation.executable, &argv, &stdin, || {
        let mut entered = base_record(2, "entered");
        entered.source_candidate_content = Some(&source_content);
        entered.private_representation_content = Some(&representation_content);
        entered.representation_method = Some(representation.method);
        entered.representation_device = Some(representation.device);
        entered.representation_inode = Some(representation.inode);
        entered.representation_links = Some(representation.links);
        entered.authority_closure = Some(&authority);
        entered.content_match = Some(true);
        entered.descriptor_exec_accepted = true;
        journal.append(&mut entered)
    })?;
    let stdout_sha256 = digest(&output.stdout);
    let stderr_sha256 = digest(&output.stderr);
    if !output.descriptor_exec_accepted {
        let mut refused = base_record(2, "refused");
        refused.source_candidate_content = Some(&source_content);
        refused.private_representation_content = Some(&representation_content);
        refused.representation_method = Some(representation.method);
        refused.representation_device = Some(representation.device);
        refused.representation_inode = Some(representation.inode);
        refused.representation_links = Some(representation.links);
        refused.authority_closure = Some(&authority);
        refused.content_match = Some(true);
        refused.child_stdout_sha256 = Some(&stdout_sha256);
        refused.child_stderr_sha256 = Some(&stderr_sha256);
        refused.child_exit_code = output.exit_code;
        refused.child_signal = output.signal;
        refused.exec_errno = output.exec_errno;
        refused.refusal = Some("descriptor_invocation_refused");
        journal.append(&mut refused)?;
        std::io::stdout().write_all(&output.stdout)?;
        std::io::stdout().flush()?;
        std::io::stderr().write_all(&output.stderr)?;
        std::io::stderr().flush()?;
        return Ok(output.exit_code.unwrap_or(126));
    }
    let mut completed = base_record(3, "completed");
    completed.source_candidate_content = Some(&source_content);
    completed.private_representation_content = Some(&representation_content);
    completed.representation_method = Some(representation.method);
    completed.representation_device = Some(representation.device);
    completed.representation_inode = Some(representation.inode);
    completed.representation_links = Some(representation.links);
    completed.authority_closure = Some(&authority);
    completed.content_match = Some(true);
    completed.descriptor_exec_accepted = output.descriptor_exec_accepted;
    completed.child_stdout_sha256 = Some(&stdout_sha256);
    completed.child_stderr_sha256 = Some(&stderr_sha256);
    completed.child_exit_code = output.exit_code;
    completed.child_signal = output.signal;
    completed.exec_errno = output.exec_errno;
    journal.append(&mut completed)?;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stdout().flush()?;
    std::io::stderr().write_all(&output.stderr)?;
    std::io::stderr().flush()?;
    if let Some(signal) = output.signal {
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        }
        return Ok(128 + signal);
    }
    Ok(output.exit_code.unwrap_or(126))
}

pub fn main_entry<I>(arguments: I) -> i32
where
    I: IntoIterator<Item = OsString>,
{
    #[cfg(not(target_os = "freebsd"))]
    {
        let _ = arguments;
        eprintln!("gwr-docket-bootstrap: supported only on FreeBSD");
        69
    }
    #[cfg(target_os = "freebsd")]
    {
        match parse_options(arguments).and_then(run) {
            Ok(code) => code,
            Err(BootstrapError::Usage(error)) => {
                eprintln!("gwr-docket-bootstrap: {error}");
                64
            }
            Err(error) => {
                eprintln!("gwr-docket-bootstrap: {error}");
                74
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        argv_digest, parse_options, valid_digest, validate_selection, BootstrapSelection,
        SELECTION_SCHEMA_V1,
    };
    use std::ffi::OsString;

    #[test]
    fn parses_exact_bounded_interface() {
        let values = [
            "bootstrap",
            "--selection",
            "/tmp/selection.json",
            "--candidate",
            "/tmp/docket",
            "--representation-base",
            "/tmp/base",
            "--journal",
            "/tmp/journal.jsonl",
            "--stdin",
            "/tmp/stdin",
            "--",
            "docket",
            "governed-loop",
            "accept",
        ];
        let parsed = parse_options(values.map(OsString::from)).unwrap();
        assert_eq!(parsed.docket_argv.len(), 3);
    }

    #[test]
    fn rejects_relative_and_incomplete_interfaces() {
        let relative = [
            "bootstrap",
            "--selection",
            "selection.json",
            "--candidate",
            "/tmp/docket",
            "--representation-base",
            "/tmp/base",
            "--journal",
            "/tmp/journal",
            "--stdin",
            "/tmp/stdin",
            "--",
            "docket",
        ];
        assert!(parse_options(relative.map(OsString::from)).is_err());
        assert!(parse_options([OsString::from("bootstrap")]).is_err());
    }

    #[test]
    fn digest_format_and_argv_framing_are_strict() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert!(valid_digest(&digest));
        assert!(!valid_digest(&digest.to_uppercase()));
        assert_ne!(
            argv_digest(&[OsString::from("ab"), OsString::from("c")]),
            argv_digest(&[OsString::from("a"), OsString::from("bc")])
        );
    }

    #[test]
    fn selection_schema_is_explicit() {
        let json = format!(
            r#"{{"schema":"{SELECTION_SCHEMA_V1}","launch_id":"launch-1","expected_docket_content":"sha256:{0}","signed_issuance_sha256":"sha256:{0}","executor_plan_sha256":"sha256:{0}","docket_trust_sha256":"sha256:{0}","argv_sha256":"sha256:{0}","stdin_sha256":"sha256:{0}"}}"#,
            "0".repeat(64)
        );
        let parsed: BootstrapSelection = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema, SELECTION_SCHEMA_V1);
        validate_selection(&parsed).unwrap();
    }

    #[test]
    fn selection_rejects_unknown_schema_and_noncanonical_digest() {
        let digest = format!("sha256:{}", "0".repeat(64));
        let mut selection = BootstrapSelection {
            schema: "civil.docket.bootstrap-selection/v2".to_owned(),
            launch_id: "launch-1".to_owned(),
            expected_docket_content: digest.clone(),
            signed_issuance_sha256: digest.clone(),
            executor_plan_sha256: digest.clone(),
            docket_trust_sha256: digest.clone(),
            argv_sha256: digest.clone(),
            stdin_sha256: digest,
        };
        assert!(validate_selection(&selection).is_err());
        selection.schema = SELECTION_SCHEMA_V1.to_owned();
        selection.expected_docket_content = format!("sha256:{}", "A".repeat(64));
        assert!(validate_selection(&selection).is_err());
    }
}

#[cfg(all(test, target_os = "freebsd"))]
mod freebsd_tests {
    use super::{digest, BOOTSTRAP_CREATOR};
    use gwr_freebsd_exec::prepare_execution_representation_for;
    use std::io::{Read as _, Seek as _, SeekFrom};
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn representation_is_remeasured_after_authority_probes() {
        let root = std::env::temp_dir().join(format!(
            "gwr-m8-bootstrap-representation-{}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bytes = b"M8 finalized bootstrap representation";
        let mut representation =
            prepare_execution_representation_for(&root, bytes, BOOTSTRAP_CREATOR).unwrap();
        assert_eq!(representation.authority.creator, BOOTSTRAP_CREATOR);
        assert_eq!(
            representation
                .authority
                .writable_descriptors_surviving_finalization,
            0
        );
        representation.executable.seek(SeekFrom::Start(0)).unwrap();
        let mut measured = Vec::new();
        representation
            .executable
            .read_to_end(&mut measured)
            .unwrap();
        assert_eq!(digest(&measured), digest(bytes));
        std::fs::remove_dir_all(root).unwrap();
    }
}
