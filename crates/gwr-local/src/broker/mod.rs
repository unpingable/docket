//! The Git effect broker: applies one persisted dispatch envelope as an atomic
//! target-ref transition, journaling every phase.
//!
//! The broker never retries and never repeats: an existing journal for a
//! dispatch is inspected, not re-executed. Definite outcomes (committed,
//! refused) exit cleanly; anything else — death, kill, lost pipe — leaves an
//! incomplete journal, and the adapter reports uncertainty.

use gwr_core::digest::Sha256Digest;
use gwr_core::receipt::DispatchEnvelope;
use gwr_core::refusal::DispatchRefusalGround;
use gwr_core::work_request::CommitHash;
use gwr_runtime::ports::effect_broker::{BrokerOutcome, EffectBroker};
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;

const ENVELOPE_PREFIX: &str = "gwr-envelope-v1";

/// Serialize an envelope to the explicit on-disk format the broker binary
/// reads. One `key=value` per line; `allowed_path` repeats.
pub fn envelope_to_file(env: &DispatchEnvelope) -> String {
    let mut out = String::new();
    out.push_str(ENVELOPE_PREFIX);
    out.push('\n');
    let mut push = |k: &str, v: &str| {
        out.push_str(k);
        out.push('=');
        out.push_str(v);
        out.push('\n');
    };
    push("dispatch", &hex16(env.dispatch.as_bytes()));
    push("attempt", &hex16(env.attempt.as_bytes()));
    push("prepared_digest", &env.prepared_attempt_digest.to_hex());
    push("repository", env.repository.as_str());
    push("target_ref", env.target_ref.as_str());
    push("expected_basis", env.expected_basis.as_str());
    push("patch_digest", &env.patch_digest.to_hex());
    for p in &env.allowed_paths {
        push("allowed_path", p);
    }
    out
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The fields the broker binary needs, parsed back from the envelope file.
#[derive(Debug, Clone)]
pub struct EnvelopeFile {
    pub dispatch: String,
    pub repository: String,
    pub target_ref: String,
    pub expected_basis: String,
    pub patch_digest: String,
    pub allowed_paths: Vec<String>,
}

pub fn parse_envelope_file(content: &str) -> Result<EnvelopeFile, String> {
    let mut lines = content.lines();
    if lines.next() != Some(ENVELOPE_PREFIX) {
        return Err("bad envelope prefix".into());
    }
    let mut env = EnvelopeFile {
        dispatch: String::new(),
        repository: String::new(),
        target_ref: String::new(),
        expected_basis: String::new(),
        patch_digest: String::new(),
        allowed_paths: Vec::new(),
    };
    for line in lines {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "dispatch" => env.dispatch = v.into(),
            "repository" => env.repository = v.into(),
            "target_ref" => env.target_ref = v.into(),
            "expected_basis" => env.expected_basis = v.into(),
            "patch_digest" => env.patch_digest = v.into(),
            "allowed_path" => env.allowed_paths.push(v.into()),
            _ => {}
        }
    }
    Ok(env)
}

/// Append-only phase journal for one dispatch.
pub struct Journal {
    path: PathBuf,
}

impl Journal {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn append(&mut self, line: &str) -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        writeln!(f, "{line}").map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn read(&self) -> Result<String, String> {
        std::fs::read_to_string(&self.path).map_err(|e| e.to_string())
    }

    pub fn digest(&self) -> Option<Sha256Digest> {
        std::fs::read(&self.path)
            .ok()
            .map(|b| Sha256Digest::of_bytes(&b))
    }
}

/// The definite results the broker logic can produce in-process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerRun {
    Committed { previous: String, result: String },
    Refused { ground: DispatchRefusalGround },
}

fn git(repo: &str, args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| e.to_string())
}

fn git_env(
    repo: &str,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<std::process::Output, String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().map_err(|e| e.to_string())
}

/// Paths a unified diff touches, from its `diff --git` headers.
pub fn patch_paths(patch: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git a/") {
            if let Some((a, _b)) = rest.split_once(" b/") {
                paths.push(a.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("+++ b/") {
            if !paths.contains(&rest.to_string()) {
                paths.push(rest.to_string());
            }
        }
    }
    paths
}

/// Execute one envelope against the repository. `crash_after` names a journal
/// phase after which the process aborts — the failure-injection hook.
pub fn execute_envelope(
    env: &EnvelopeFile,
    patch: &[u8],
    journal: &mut Journal,
    crash_after: Option<&str>,
) -> Result<BrokerRun, String> {
    let phase = |journal: &mut Journal, line: &str| -> Result<(), String> {
        journal.append(line)?;
        if let Some(c) = crash_after {
            if line.starts_with(c) {
                std::process::abort();
            }
        }
        Ok(())
    };

    phase(journal, "received")?;

    // Verify the envelope against the exact bytes.
    let digest = Sha256Digest::of_bytes(patch);
    if digest.to_hex() != env.patch_digest {
        phase(journal, "refused envelope_mismatch")?;
        return Ok(BrokerRun::Refused {
            ground: DispatchRefusalGround::EnvelopeMismatch,
        });
    }
    let patch_text = String::from_utf8_lossy(patch);
    let touched = patch_paths(&patch_text);
    if touched.is_empty() || touched.iter().any(|p| !env.allowed_paths.contains(p)) {
        phase(journal, "refused forbidden_path")?;
        return Ok(BrokerRun::Refused {
            ground: DispatchRefusalGround::ForbiddenPath,
        });
    }
    phase(journal, "verified")?;

    // The ref must currently hold the expected basis. This pre-check gives the
    // typed refusal; the compare-and-swap at the end guarantees atomicity.
    let current = git(&env.repository, &["rev-parse", "--verify", &env.target_ref])?;
    if !current.status.success() {
        phase(journal, "refused basis_moved")?;
        return Ok(BrokerRun::Refused {
            ground: DispatchRefusalGround::BasisMoved,
        });
    }
    let current = String::from_utf8_lossy(&current.stdout).trim().to_string();
    if current != env.expected_basis {
        phase(journal, "refused basis_moved")?;
        return Ok(BrokerRun::Refused {
            ground: DispatchRefusalGround::BasisMoved,
        });
    }

    // Temporary index: the governed repository's worktree and index are never
    // touched. Only objects are written until the ref transition.
    let tmp_index = std::env::temp_dir().join(format!("gwr-index-{}", env.dispatch));
    let _ = std::fs::remove_file(&tmp_index);
    let index_str = tmp_index.to_string_lossy().to_string();
    let envs = [("GIT_INDEX_FILE", index_str.as_str())];

    let read_tree = git_env(&env.repository, &["read-tree", &env.expected_basis], &envs)?;
    if !read_tree.status.success() {
        return Err("read-tree failed".into());
    }

    // Apply the patch to the temporary index.
    let patch_file = std::env::temp_dir().join(format!("gwr-patch-{}", env.dispatch));
    std::fs::write(&patch_file, patch).map_err(|e| e.to_string())?;
    let apply = git_env(
        &env.repository,
        &[
            "apply",
            "--cached",
            "--check",
            patch_file.to_string_lossy().as_ref(),
        ],
        &envs,
    )?;
    if !apply.status.success() {
        phase(journal, "refused invalid_patch")?;
        return Ok(BrokerRun::Refused {
            ground: DispatchRefusalGround::InvalidPatch,
        });
    }
    let apply = git_env(
        &env.repository,
        &["apply", "--cached", patch_file.to_string_lossy().as_ref()],
        &envs,
    )?;
    if !apply.status.success() {
        phase(journal, "refused invalid_patch")?;
        return Ok(BrokerRun::Refused {
            ground: DispatchRefusalGround::InvalidPatch,
        });
    }
    phase(journal, "patch_applied")?;

    let tree = git_env(&env.repository, &["write-tree"], &envs)?;
    if !tree.status.success() {
        return Err("write-tree failed".into());
    }
    let tree = String::from_utf8_lossy(&tree.stdout).trim().to_string();
    phase(journal, "tree_written")?;

    let msg = format!("gwr governed effect {}", env.dispatch);
    let commit = git_env(
        &env.repository,
        &["commit-tree", &tree, "-p", &env.expected_basis, "-m", &msg],
        &[
            ("GIT_AUTHOR_NAME", "gwr-broker"),
            ("GIT_AUTHOR_EMAIL", "broker@gwr.local"),
            ("GIT_COMMITTER_NAME", "gwr-broker"),
            ("GIT_COMMITTER_EMAIL", "broker@gwr.local"),
            ("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z"),
            ("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z"),
        ],
    )?;
    if !commit.status.success() {
        return Err("commit-tree failed".into());
    }
    let result = String::from_utf8_lossy(&commit.stdout).trim().to_string();
    phase(journal, &format!("commit_created {result}"))?;

    // The governed effect: an atomic compare-and-swap on the dedicated ref.
    phase(journal, "ref_updating")?;
    let update = git(
        &env.repository,
        &["update-ref", &env.target_ref, &result, &env.expected_basis],
    )?;
    if !update.status.success() {
        phase(journal, "refused basis_moved")?;
        return Ok(BrokerRun::Refused {
            ground: DispatchRefusalGround::BasisMoved,
        });
    }
    phase(journal, &format!("ref_updated {current} {result}"))?;

    phase(journal, "acknowledged")?;
    let _ = std::fs::remove_file(&tmp_index);
    let _ = std::fs::remove_file(&patch_file);
    Ok(BrokerRun::Committed {
        previous: current,
        result,
    })
}

/// Inspect an existing journal for a definite prior result.
pub fn inspect_journal(content: &str) -> Option<BrokerRun> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("ref_updated ") {
            let mut parts = rest.split_whitespace();
            let previous = parts.next()?.to_string();
            let result = parts.next()?.to_string();
            return Some(BrokerRun::Committed { previous, result });
        }
        if let Some(ground) = line.strip_prefix("refused ") {
            let ground = match ground {
                "basis_moved" => DispatchRefusalGround::BasisMoved,
                "forbidden_path" => DispatchRefusalGround::ForbiddenPath,
                "invalid_patch" => DispatchRefusalGround::InvalidPatch,
                _ => DispatchRefusalGround::EnvelopeMismatch,
            };
            return Some(BrokerRun::Refused { ground });
        }
    }
    None
}

/// Subprocess broker adapter: runs the `gwr-git-broker` binary so broker death
/// is a real process death, and reads the outcome from exit status, stdout,
/// and the journal.
pub struct SubprocessGitBroker {
    pub broker_bin: PathBuf,
    pub journal_dir: PathBuf,
    pub artifact_root: PathBuf,
    /// Failure injection: passed to the broker as GWR_BROKER_CRASH_AFTER.
    pub crash_after: Option<String>,
}

impl SubprocessGitBroker {
    pub fn new(broker_bin: PathBuf, journal_dir: PathBuf, artifact_root: PathBuf) -> Self {
        std::fs::create_dir_all(&journal_dir).ok();
        Self {
            broker_bin,
            journal_dir,
            artifact_root,
            crash_after: None,
        }
    }

    fn journal_path(&self, env: &DispatchEnvelope) -> PathBuf {
        self.journal_dir
            .join(format!("{}.journal", hex16(env.dispatch.as_bytes())))
    }
}

impl EffectBroker for SubprocessGitBroker {
    fn execute(&mut self, envelope: &DispatchEnvelope) -> BrokerOutcome {
        let journal = Journal::new(self.journal_path(envelope));

        // Same DispatchId: inspect, never repeat. An existing journal without a
        // definite result is an uncertain prior run.
        if journal.exists() {
            let content = journal.read().unwrap_or_default();
            return match inspect_journal(&content) {
                Some(BrokerRun::Committed { previous, result }) => BrokerOutcome::Committed {
                    previous: CommitHash::new(previous),
                    result_commit: CommitHash::new(result),
                    journal_digest: journal.digest().unwrap_or(Sha256Digest::of_bytes(b"")),
                },
                Some(BrokerRun::Refused { ground }) => BrokerOutcome::Refused {
                    ground,
                    journal_digest: journal.digest().unwrap_or(Sha256Digest::of_bytes(b"")),
                },
                None => BrokerOutcome::Uncertain {
                    last_journal_digest: journal.digest(),
                },
            };
        }

        // Materialize envelope and patch for the subprocess.
        let env_file = self
            .journal_dir
            .join(format!("{}.envelope", hex16(envelope.dispatch.as_bytes())));
        if std::fs::write(&env_file, envelope_to_file(envelope)).is_err() {
            return BrokerOutcome::Uncertain {
                last_journal_digest: None,
            };
        }
        let patch_file = self.artifact_root.join(envelope.patch_digest.to_hex());
        if !patch_file.exists() {
            // Without the exact patch bytes nothing was attempted: this is a
            // definite refusal, not uncertainty.
            let mut j = Journal::new(self.journal_path(envelope));
            let _ = j.append("received");
            let _ = j.append("refused envelope_mismatch");
            return BrokerOutcome::Refused {
                ground: DispatchRefusalGround::EnvelopeMismatch,
                journal_digest: j.digest().unwrap_or(Sha256Digest::of_bytes(b"")),
            };
        }

        let mut cmd = Command::new(&self.broker_bin);
        cmd.arg(&env_file)
            .arg(&patch_file)
            .arg(self.journal_path(envelope));
        if let Some(c) = &self.crash_after {
            cmd.env("GWR_BROKER_CRASH_AFTER", c);
        }
        let output = cmd.output();

        let journal = Journal::new(self.journal_path(envelope));
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let last = stdout.lines().last().unwrap_or("");
                if let Some(rest) = last.strip_prefix("COMMITTED ") {
                    let mut parts = rest.split_whitespace();
                    let result = parts.next().unwrap_or("").to_string();
                    let previous = parts.next().unwrap_or("").to_string();
                    BrokerOutcome::Committed {
                        previous: CommitHash::new(previous),
                        result_commit: CommitHash::new(result),
                        journal_digest: journal.digest().unwrap_or(Sha256Digest::of_bytes(b"")),
                    }
                } else if let Some(ground) = last.strip_prefix("REFUSED ") {
                    let ground = match ground {
                        "basis_moved" => DispatchRefusalGround::BasisMoved,
                        "forbidden_path" => DispatchRefusalGround::ForbiddenPath,
                        "invalid_patch" => DispatchRefusalGround::InvalidPatch,
                        _ => DispatchRefusalGround::EnvelopeMismatch,
                    };
                    BrokerOutcome::Refused {
                        ground,
                        journal_digest: journal.digest().unwrap_or(Sha256Digest::of_bytes(b"")),
                    }
                } else {
                    // Clean exit without a definite last line: uncertain.
                    BrokerOutcome::Uncertain {
                        last_journal_digest: journal.digest(),
                    }
                }
            }
            // Killed, crashed, or unreachable: acknowledgement is lost.
            _ => BrokerOutcome::Uncertain {
                last_journal_digest: journal.digest(),
            },
        }
    }
}
