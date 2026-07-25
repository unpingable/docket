//! Task 8 broker tests: one inspectable consequential effect with an exact
//! ambiguity boundary. Crash tests use a real temporary Git repository and real
//! process termination.

use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::{GrantState, StandingAct, StandingGrant, StandingScope};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::AttemptState;
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::refusal::DispatchRefusalGround;
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryIdentity};
use gwr_local::adapters::{FixedClock, HashChainIds};
use gwr_local::broker::SubprocessGitBroker;
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::dispatch::{dispatch, DispatchOutcome};
use gwr_runtime::services::ratification::ratify;
use gwr_runtime::services::reservation::reserve;
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

/// A disposable Git repo with `src/lib.rs`, a basis commit, the dedicated
/// target ref, and a real unified diff produced by git itself.
fn fixture_repo(name: &str) -> (PathBuf, String, Vec<u8>) {
    let dir = std::env::temp_dir().join(format!("gwr-broker-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    sh(&dir, &["git", "init", "-q"]);
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn canonicalize(s: &str) -> String {\n    s.to_string()\n}\n",
    )
    .unwrap();
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
    // Produce a real diff, then restore the worktree.
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn canonicalize(s: &str) -> String {\n    s.split_whitespace().collect::<Vec<_>>().join(\" \")\n}\n",
    )
    .unwrap();
    let patch = Command::new("git")
        .args(["diff"])
        .current_dir(&dir)
        .output()
        .unwrap()
        .stdout;
    sh(&dir, &["git", "checkout", "-q", "--", "src/lib.rs"]);
    (dir, basis, patch)
}

struct Fx {
    store: SqliteStore,
    ids: HashChainIds,
    att: PreparedAttempt,
    broker: SubprocessGitBroker,
    repo: PathBuf,
    basis: String,
}

/// Full pipeline to `Reserved`, with the patch stored content-addressed where
/// the broker will look for it.
fn fixture(name: &str, patch_override: Option<Vec<u8>>) -> Fx {
    let (repo, basis, real_patch) = fixture_repo(name);
    let patch = patch_override.unwrap_or(real_patch);
    let patch_digest = Sha256Digest::of_bytes(&patch);
    let artifact_root = repo.join(".gwr-artifacts");
    std::fs::create_dir_all(&artifact_root).unwrap();
    std::fs::write(artifact_root.join(patch_digest.to_hex()), &patch).unwrap();

    let att = PreparedAttempt::admit(
        AttemptId::from_bytes([9; 16]),
        WorkRequestId::from_bytes([1; 16]),
        CandidateArtifactId::from_bytes([2; 16]),
        RepositoryIdentity::new(repo.to_string_lossy()),
        CommitHash::new(&basis),
        patch_digest,
        GitRefEffect {
            target_ref: RefName::new(TARGET_REF),
            expected_basis: CommitHash::new(&basis),
            patch_digest,
            allowed_paths: vec!["src/lib.rs".into()],
        },
        ObservationPlan {
            argv: vec!["true".into()],
            environment_description: "fixture".into(),
        },
        ClockReading(1),
    );

    let mut store = SqliteStore::open(&repo.join(".gwr-state.sqlite")).unwrap();
    let mut ids = HashChainIds::new();
    store.admit_attempt(&att).unwrap();
    let grant = StandingGrant {
        id: StandingGrantId::from_bytes([3; 16]),
        scope: StandingScope {
            actor: ActorId::from_bytes([4; 16]),
            act: StandingAct::Ratify,
            repository: att.repository.clone(),
            attempt_digest: att.prepared_attempt_digest,
        },
        expires_at: ClockReading(1_000_000),
        state: GrantState::Available,
    };
    store.create_standing_grant(&grant).unwrap();
    let clock = FixedClock(ClockReading(10));
    ratify(
        &mut store,
        att.attempt_id,
        grant.id,
        ActorId::from_bytes([4; 16]),
        att.prepared_attempt_digest,
        att.basis.clone(),
        &clock,
        &mut ids,
    )
    .unwrap();
    reserve(&mut store, att.attempt_id, 1_000_000, &clock, &mut ids).unwrap();

    let broker = SubprocessGitBroker::new(
        PathBuf::from(env!("CARGO_BIN_EXE_gwr-git-broker")),
        repo.join(".gwr-journals"),
        artifact_root,
    );
    Fx {
        store,
        ids,
        att,
        broker,
        repo,
        basis,
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.repo);
    }
}

fn ref_value(repo: &Path) -> String {
    sh(repo, &["git", "rev-parse", TARGET_REF])
}

#[test]
fn happy_path_atomic_ref_update() {
    let mut f = fixture("happy", None);
    let clock = FixedClock(ClockReading(20));
    let outcome = dispatch(
        &mut f.store,
        f.att.attempt_id,
        &mut f.broker,
        &clock,
        &mut f.ids,
    )
    .unwrap();
    let DispatchOutcome::Committed(commitment) = outcome else {
        panic!("expected commitment, got {outcome:?}");
    };
    assert_eq!(commitment.previous_value.as_str(), f.basis);
    // The ref moved to the result commit, whose parent is the exact basis.
    let now_at = ref_value(&f.repo);
    assert_eq!(now_at, commitment.result_commit.as_str());
    let parent = sh(&f.repo, &["git", "rev-parse", &format!("{now_at}^")]);
    assert_eq!(parent, f.basis);
    let projected = f.store.get_attempt(f.att.attempt_id).unwrap();
    assert!(matches!(projected.state, AttemptState::Committed { .. }));
}

#[test]
fn basis_moved_refuses_dispatch() {
    let mut f = fixture("moved", None);
    // Move the target ref before dispatch: the specification no longer
    // describes reality; the effect is not rebased.
    let other = sh(
        &f.repo,
        &[
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit-tree",
            &sh(&f.repo, &["git", "rev-parse", "HEAD^{tree}"]),
            "-m",
            "interloper",
        ],
    );
    sh(&f.repo, &["git", "update-ref", TARGET_REF, &other]);

    let clock = FixedClock(ClockReading(20));
    let outcome = dispatch(
        &mut f.store,
        f.att.attempt_id,
        &mut f.broker,
        &clock,
        &mut f.ids,
    )
    .unwrap();
    let DispatchOutcome::Refused(record) = outcome else {
        panic!("expected refusal, got {outcome:?}");
    };
    assert_eq!(record.ground, DispatchRefusalGround::BasisMoved);
    assert_eq!(ref_value(&f.repo), other, "ref untouched by refusal");
    let projected = f.store.get_attempt(f.att.attempt_id).unwrap();
    assert!(matches!(
        projected.state,
        AttemptState::DispatchRefused { .. }
    ));
}

#[test]
fn forbidden_path_refuses() {
    // A clean addition at an unadmitted path: it applies to the temporary index
    // without error, so the refusal must come from path authorization over what
    // the patch actually did — not from the patch failing to apply.
    let patch =
        b"diff --git a/evil/added.rs b/evil/added.rs\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/evil/added.rs\n@@ -0,0 +1 @@\n+pwned\n"
            .to_vec();
    let mut f = fixture("forbidden", Some(patch));
    let clock = FixedClock(ClockReading(20));
    let outcome = dispatch(
        &mut f.store,
        f.att.attempt_id,
        &mut f.broker,
        &clock,
        &mut f.ids,
    )
    .unwrap();
    let DispatchOutcome::Refused(record) = outcome else {
        panic!("expected refusal, got {outcome:?}");
    };
    assert_eq!(record.ground, DispatchRefusalGround::ForbiddenPath);
    assert_eq!(ref_value(&f.repo), f.basis);
}

#[test]
fn invalid_patch_refuses() {
    let patch =
        b"diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -99,1 +99,1 @@\n-nonexistent line\n+other\n"
            .to_vec();
    let mut f = fixture("invalid", Some(patch));
    let clock = FixedClock(ClockReading(20));
    let outcome = dispatch(
        &mut f.store,
        f.att.attempt_id,
        &mut f.broker,
        &clock,
        &mut f.ids,
    )
    .unwrap();
    let DispatchOutcome::Refused(record) = outcome else {
        panic!("expected refusal, got {outcome:?}");
    };
    assert_eq!(record.ground, DispatchRefusalGround::InvalidPatch);
    assert_eq!(ref_value(&f.repo), f.basis);
}

#[test]
fn duplicate_dispatch_inspects_rather_than_repeats() {
    let mut f = fixture("duplicate", None);
    let clock = FixedClock(ClockReading(20));
    let first = dispatch(
        &mut f.store,
        f.att.attempt_id,
        &mut f.broker,
        &clock,
        &mut f.ids,
    )
    .unwrap();
    let DispatchOutcome::Committed(commitment) = first else {
        panic!("expected commitment");
    };
    let ref_after_first = ref_value(&f.repo);

    // Dispatch again: the existing dispatch is inspected; the effect does not
    // repeat, the ref does not move again.
    let second = dispatch(
        &mut f.store,
        f.att.attempt_id,
        &mut f.broker,
        &clock,
        &mut f.ids,
    )
    .unwrap();
    let DispatchOutcome::AlreadyDispatched { state } = second else {
        panic!("expected inspection, got {second:?}");
    };
    assert!(matches!(state, AttemptState::Committed { .. }));
    assert_eq!(ref_value(&f.repo), ref_after_first);
    // Exactly one dispatch identity exists for the attempt.
    let existing = f.store.find_attempt_dispatch(f.att.attempt_id).unwrap();
    assert_eq!(existing, Some(commitment.dispatch));
}

#[test]
fn death_before_ref_update_becomes_indeterminate() {
    let mut f = fixture("death-before", None);
    f.broker.crash_after = Some("commit_created".into());
    let clock = FixedClock(ClockReading(20));
    let outcome = dispatch(
        &mut f.store,
        f.att.attempt_id,
        &mut f.broker,
        &clock,
        &mut f.ids,
    )
    .unwrap();
    let DispatchOutcome::Indeterminate(record) = outcome else {
        panic!("expected indeterminate, got {outcome:?}");
    };
    assert!(record.last_journal_digest.is_some());
    // The ref did not move — but the runtime does not claim to know that; the
    // state is indeterminate until recovery evidence plus standing resolve it.
    assert_eq!(ref_value(&f.repo), f.basis);
    let projected = f.store.get_attempt(f.att.attempt_id).unwrap();
    assert!(matches!(
        projected.state,
        AttemptState::Indeterminate { .. }
    ));
}

#[test]
fn death_after_ref_update_before_ack_requires_recovery() {
    let mut f = fixture("death-after", None);
    f.broker.crash_after = Some("ref_updated".into());
    let clock = FixedClock(ClockReading(20));
    let outcome = dispatch(
        &mut f.store,
        f.att.attempt_id,
        &mut f.broker,
        &clock,
        &mut f.ids,
    )
    .unwrap();
    let DispatchOutcome::Indeterminate(_) = outcome else {
        panic!("expected indeterminate, got {outcome:?}");
    };
    // The effect actually landed — the ref moved — but no success is minted
    // from that fact without recovery evidence plus recovery standing.
    assert_ne!(ref_value(&f.repo), f.basis);
    let projected = f.store.get_attempt(f.att.attempt_id).unwrap();
    assert!(matches!(
        projected.state,
        AttemptState::Indeterminate { .. }
    ));
}

/// V1 end-to-end: the blind review's witness. A rename patch whose destination
/// was never admitted must not reach the ref.
#[test]
fn rename_to_unadmitted_path_is_refused_end_to_end() {
    let patch = b"diff --git a/src/lib.rs b/evil/pwned.rs\nsimilarity index 100%\nrename from src/lib.rs\nrename to evil/pwned.rs\n".to_vec();
    let mut f = fixture("rename-escape", Some(patch));
    let clock = FixedClock(ClockReading(20));
    let outcome = dispatch(
        &mut f.store,
        f.att.attempt_id,
        &mut f.broker,
        &clock,
        &mut f.ids,
    )
    .unwrap();
    let DispatchOutcome::Refused(record) = outcome else {
        panic!("rename escaped the allowlist: {outcome:?}");
    };
    assert_eq!(record.ground, DispatchRefusalGround::ForbiddenPath);
    // The ref never moved, and the unadmitted path does not exist anywhere.
    assert_eq!(ref_value(&f.repo), f.basis);
    let tree = sh(
        &f.repo,
        &["git", "ls-tree", "-r", "--name-only", TARGET_REF],
    );
    assert!(!tree.contains("evil/pwned.rs"), "tree: {tree}");
    assert!(
        tree.contains("src/lib.rs"),
        "admitted file was deleted: {tree}"
    );
}
