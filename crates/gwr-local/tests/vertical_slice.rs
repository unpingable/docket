//! Task 9: the complete vertical slice — fake provider through reconciliation
//! for one exact repository effect, driven through the docket CLI.

use gwr_core::digest::Sha256Digest;
use gwr_core::domain::evidence::Claim;
use gwr_core::ids::{AttemptId, ObservationId};
use gwr_core::observation_plan::ObservationRecord;
use gwr_core::refusal::{ObservationRefusal, RelianceRefusal};
use gwr_core::work_request::{ClockReading, CommitHash};
use gwr_local::adapters::FixedClock;
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::reliance::{rely_review_queue, RelyError};
use std::path::{Path, PathBuf};
use std::process::Command;

const TARGET_REF: &str = "refs/gwr/target";

fn sh(dir: &Path, args: &[&str]) -> String {
    let out = Command::new(args[0])
        .args(&args[1..])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

const BROKEN_LIB: &str = r#"pub fn canonicalize(s: &str) -> String {
    s.to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn canonicalizes_whitespace() {
        assert_eq!(super::canonicalize("a  b\t c"), "a b c");
    }
}
"#;

const FIXED_LIB: &str = r#"pub fn canonicalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    #[test]
    fn canonicalizes_whitespace() {
        assert_eq!(super::canonicalize("a  b\t c"), "a b c");
    }
}
"#;

/// A disposable target repository: a real Rust crate whose test
/// `canonicalizes_whitespace` fails at the basis commit, plus a real unified
/// diff that makes it pass.
fn fixture_repo(name: &str) -> (PathBuf, String, Vec<u8>) {
    let dir = std::env::temp_dir().join(format!("gwr-slice-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("src/lib.rs"), BROKEN_LIB).unwrap();
    sh(&dir, &["cargo", "generate-lockfile"]);
    std::fs::write(dir.join(".gitignore"), "/target\n").unwrap();
    sh(&dir, &["git", "init", "-q"]);
    sh(&dir, &["git", "add", "-A"]);
    sh(
        &dir,
        &[
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "-m",
            "basis",
        ],
    );
    let basis = sh(&dir, &["git", "rev-parse", "HEAD"]);
    sh(&dir, &["git", "update-ref", TARGET_REF, &basis]);
    std::fs::write(dir.join("src/lib.rs"), FIXED_LIB).unwrap();
    let patch = Command::new("git")
        .args(["diff"])
        .current_dir(&dir)
        .output()
        .unwrap()
        .stdout;
    sh(&dir, &["git", "checkout", "-q", "--", "src/lib.rs"]);
    (dir, basis, patch)
}

/// Run the docket CLI; return stdout. Panics on nonzero exit unless
/// `allow_fail`.
fn docket(state: &Path, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_docket"))
        .args(args)
        .args(["--state", state.to_string_lossy().as_ref()])
        .env("GWR_BROKER_BIN", env!("CARGO_BIN_EXE_gwr-git-broker"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "docket {args:?} failed: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn value_of<'a>(output: &'a str, key: &str) -> &'a str {
    output
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")))
        .unwrap_or_else(|| panic!("missing {key} in output:\n{output}"))
}

#[test]
fn complete_happy_path_through_the_cli() {
    let (repo, basis, patch) = fixture_repo("happy");
    let state = repo.join(".gwr-state");
    let patch_file = repo.join("candidate.patch");
    std::fs::write(&patch_file, &patch).unwrap();

    // request create
    let out = docket(
        &state,
        &[
            "request",
            "create",
            "--repo",
            repo.to_string_lossy().as_ref(),
            "--target-ref",
            TARGET_REF,
            "--goal",
            "make canonicalizes_whitespace pass",
        ],
    );
    let request = value_of(&out, "work_request").to_string();

    // prepare start (bounded fake provider) + poll
    let out = docket(
        &state,
        &[
            "prepare",
            "start",
            "--request",
            &request,
            "--fake-patch",
            patch_file.to_string_lossy().as_ref(),
            "--basis",
            &basis,
        ],
    );
    let run = value_of(&out, "preparation_run").to_string();
    let candidate = value_of(&out, "candidate").to_string();
    let out = docket(&state, &["prepare", "poll", "--run", &run]);
    assert!(out.contains("CandidateProduced"), "{out}");

    // candidate admit → exact attempt
    let out = docket(
        &state,
        &[
            "candidate",
            "admit",
            "--request",
            &request,
            "--candidate",
            &candidate,
            "--basis",
            &basis,
            "--allow",
            "src/lib.rs",
            "--observe",
            "cargo test --locked canonicalizes_whitespace",
        ],
    );
    let attempt = value_of(&out, "attempt").to_string();
    let digest = value_of(&out, "prepared_attempt_digest").to_string();

    // standing → ratify (exact digest, exact basis)
    let out = docket(
        &state,
        &[
            "grant",
            "standing",
            "--attempt",
            &attempt,
            "--actor",
            "operator",
        ],
    );
    let token = value_of(&out, "token").to_string();
    docket(
        &state,
        &[
            "ratify",
            "--attempt",
            &attempt,
            "--token",
            &token,
            "--actor",
            "operator",
            "--digest",
            &digest,
            "--basis",
            &basis,
        ],
    );

    // reserve → dispatch (broker-mediated atomic ref update)
    docket(&state, &["reserve", "--attempt", &attempt]);
    let out = docket(&state, &["dispatch", "--attempt", &attempt]);
    assert_eq!(value_of(&out, "outcome"), "committed");
    let result_commit = value_of(&out, "result_commit").to_string();
    // The disposable target ref changed only through the broker, to the result.
    assert_eq!(sh(&repo, &["git", "rev-parse", TARGET_REF]), result_commit);

    // observe: the exact ratified command against the exact result commit.
    let out = docket(&state, &["observe", "--attempt", &attempt]);
    let observation = value_of(&out, "observation").to_string();
    assert_eq!(value_of(&out, "exit_status"), "0");

    // rely review-queue: the one admissible claim admits...
    let out = docket(
        &state,
        &[
            "rely",
            "review-queue",
            "--attempt",
            &attempt,
            "--observation",
            &observation,
            "--claim",
            "effect-and-command",
        ],
    );
    assert!(out.contains("reliance: admitted"), "{out}");
    // ...and merge safety is refused. No composite success receipt exists.
    let out = docket(
        &state,
        &[
            "rely",
            "review-queue",
            "--attempt",
            &attempt,
            "--observation",
            &observation,
            "--claim",
            "safe-to-merge",
        ],
    );
    assert!(out.contains("reliance: refused"), "{out}");
    assert!(out.contains("ClaimNotAdmissible"), "{out}");

    // reconcile: HumanReviewBeforeMerge survives commitment and observation.
    let out = docket(&state, &["reconcile", "--attempt", &attempt]);
    assert!(out.contains("HumanReviewBeforeMerge"), "{out}");

    // docket list/show: JSON and human output state the same facts.
    let human = docket(&state, &["docket", "list"]);
    let json = docket(&state, &["docket", "list", "--json"]);
    assert!(human.contains(&attempt));
    assert!(json.contains(&attempt));
    assert!(human.contains("committed"));
    assert!(json.contains("\"state\":\"committed\""));
    let human = docket(&state, &["docket", "show", "--attempt", &attempt]);
    let json = docket(&state, &["docket", "show", "--attempt", &attempt, "--json"]);
    for fact in ["committed", &attempt] {
        assert!(human.contains(fact), "human output missing {fact}");
        assert!(json.contains(fact), "json output missing {fact}");
    }
    assert!(human.contains("residual_obligation HumanReviewBeforeMerge"));
    assert!(json.contains("\"residual_obligations\":1"));

    let _ = std::fs::remove_dir_all(&repo);
}

/// Service-level slice tests for the observation/reliance failure paths, using
/// the state written by a fresh CLI-driven pipeline would be slow; instead
/// these drive the store directly against a committed attempt.
struct Committed {
    store: SqliteStore,
    attempt: AttemptId,
    result_commit: String,
    repo: PathBuf,
}

fn committed_fixture(name: &str) -> Committed {
    let (repo, basis, patch) = fixture_repo(name);
    let state = repo.join(".gwr-state");
    let patch_file = repo.join("candidate.patch");
    std::fs::write(&patch_file, &patch).unwrap();
    let out = docket(
        &state,
        &[
            "request",
            "create",
            "--repo",
            repo.to_string_lossy().as_ref(),
            "--target-ref",
            TARGET_REF,
            "--goal",
            "fix",
        ],
    );
    let request = value_of(&out, "work_request").to_string();
    let out = docket(
        &state,
        &[
            "prepare",
            "start",
            "--request",
            &request,
            "--fake-patch",
            patch_file.to_string_lossy().as_ref(),
            "--basis",
            &basis,
        ],
    );
    let candidate = value_of(&out, "candidate").to_string();
    let out = docket(
        &state,
        &[
            "candidate",
            "admit",
            "--request",
            &request,
            "--candidate",
            &candidate,
            "--basis",
            &basis,
            "--allow",
            "src/lib.rs",
            "--observe",
            "cargo test --locked canonicalizes_whitespace",
        ],
    );
    let attempt = value_of(&out, "attempt").to_string();
    let digest = value_of(&out, "prepared_attempt_digest").to_string();
    let out = docket(
        &state,
        &[
            "grant",
            "standing",
            "--attempt",
            &attempt,
            "--actor",
            "operator",
        ],
    );
    let token = value_of(&out, "token").to_string();
    docket(
        &state,
        &[
            "ratify",
            "--attempt",
            &attempt,
            "--token",
            &token,
            "--actor",
            "operator",
            "--digest",
            &digest,
            "--basis",
            &basis,
        ],
    );
    docket(&state, &["reserve", "--attempt", &attempt]);
    let out = docket(&state, &["dispatch", "--attempt", &attempt]);
    let result_commit = value_of(&out, "result_commit").to_string();

    let store = SqliteStore::open(&state.join("state.sqlite")).unwrap();
    let mut bytes = [0u8; 16];
    for (i, chunk) in attempt.as_bytes().chunks(2).enumerate() {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    Committed {
        store,
        attempt: AttemptId::from_bytes(bytes),
        result_commit,
        repo,
    }
}

impl Drop for Committed {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.repo);
    }
}

fn obs(attempt: AttemptId, commit: &str, exit: i32, byte: u8) -> ObservationRecord {
    ObservationRecord {
        id: ObservationId::from_bytes([byte; 16]),
        attempt,
        argv: vec!["cargo".into(), "test".into()],
        working_directory_identity: "manual".into(),
        result_commit: CommitHash::new(commit),
        environment_description: "test".into(),
        exit_status: exit,
        stdout_digest: Sha256Digest::of_bytes(b""),
        stderr_digest: Sha256Digest::of_bytes(b""),
        observed_at: ClockReading(100),
    }
}

#[test]
fn committed_effect_with_missing_observation_cannot_be_relied_on() {
    let mut f = committed_fixture("missing-obs");
    let clock = FixedClock(ClockReading(200));
    let err = rely_review_queue(
        &mut f.store,
        f.attempt,
        ObservationId::from_bytes([42; 16]),
        Claim::ExactResultCommitProducedAndCommandExitedZero,
        &clock,
    )
    .unwrap_err();
    assert!(matches!(err, RelyError::Store(_)), "{err:?}");
}

#[test]
fn committed_effect_with_failing_observation_is_refused_but_commitment_stands() {
    let mut f = committed_fixture("failing-obs");
    let record = obs(f.attempt, &f.result_commit.clone(), 101, 50);
    f.store.record_observation(&record).unwrap();
    let clock = FixedClock(ClockReading(200));
    let err = rely_review_queue(
        &mut f.store,
        f.attempt,
        record.id,
        Claim::ExactResultCommitProducedAndCommandExitedZero,
        &clock,
    )
    .unwrap_err();
    assert_eq!(
        err,
        RelyError::Refused(RelianceRefusal::Observation(
            ObservationRefusal::ObservationFailed
        ))
    );
    // The commitment is not rewritten by the failing observation.
    let commitment = f.store.get_commitment(f.attempt).unwrap();
    assert_eq!(commitment.result_commit.as_str(), f.result_commit);
    let projected = f.store.get_attempt(f.attempt).unwrap();
    assert!(matches!(
        projected.state,
        gwr_core::lifecycle::AttemptState::Committed { .. }
    ));
}

#[test]
fn wrong_commit_observation_is_rejected() {
    let mut f = committed_fixture("wrong-commit");
    let record = obs(f.attempt, "0000000000000000000000000000000000000000", 0, 51);
    f.store.record_observation(&record).unwrap();
    let clock = FixedClock(ClockReading(200));
    let err = rely_review_queue(
        &mut f.store,
        f.attempt,
        record.id,
        Claim::ExactResultCommitProducedAndCommandExitedZero,
        &clock,
    )
    .unwrap_err();
    assert_eq!(
        err,
        RelyError::Refused(RelianceRefusal::Observation(
            ObservationRefusal::ScopeMismatch
        ))
    );
}
