//! Boundary specimen for the exclusive-ref-custody premise (finding N-1).
//!
//! This file is **not** a check that the runtime defends the boundary. It does
//! not defend it, and cannot: what else may write a Git ref is a property of the
//! deployment, not of this process. What follows asserts the *unsound* behaviour
//! that appears when the premise is violated, so the boundary is executable
//! rather than prose, and so that any future change to it is a deliberate edit
//! to a test that says exactly what it is.
//!
//! The premise, from `docs/governed-runtime/trust-model.md`:
//!
//! > `ProvenNotCommitted` is valid only while the target ref is exclusively
//! > controlled by the governed broker from dispatch through recovery
//! > observation.
//!
//! Violate it and two histories become observationally identical:
//!
//! ```text
//! H1: the effect never landed
//! H2: the effect landed, then the ref was returned to the basis
//! ```
//!
//! `refs/gwr/*` carries no reflog under Git's default `core.logAllRefUpdates`,
//! so no durable evidence separates them anywhere.

use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::{StandingAct, StandingGrant, StandingScope};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::{AttemptState, RecoveryVerdict};
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryLocator};
use gwr_local::adapters::{FixedClock, HashChainIds};
use gwr_local::broker::SubprocessGitBroker;
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::dispatch::{dispatch, DispatchOutcome};
use gwr_runtime::services::ratification::ratify;
use gwr_runtime::services::recovery::resolve;
use gwr_runtime::services::reservation::reserve;
use std::path::{Path, PathBuf};
use std::process::Command;

const TARGET_REF: &str = "refs/gwr/target";
const ACTOR: ActorId = ActorId::from_bytes([4; 16]);

fn sh(dir: &Path, args: &[&str]) -> String {
    let out = Command::new(args[0])
        .args(&args[1..])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct Fx {
    root: PathBuf,
    repo: PathBuf,
    store: SqliteStore,
    att: PreparedAttempt,
    basis: String,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture(name: &str) -> Fx {
    let root = std::env::temp_dir().join(format!("gwr-custody-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let repo = root.join("repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(root.join("journals")).unwrap();
    let artifacts = root.join("artifacts");
    std::fs::create_dir_all(&artifacts).unwrap();

    sh(&repo, &["git", "init", "-q"]);
    std::fs::write(repo.join("src/lib.rs"), "fn old() {}\n").unwrap();
    sh(&repo, &["git", "add", "-A"]);
    sh(
        &repo,
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
    let basis = sh(&repo, &["git", "rev-parse", "HEAD"]);
    sh(&repo, &["git", "update-ref", TARGET_REF, &basis]);
    std::fs::write(repo.join("src/lib.rs"), "fn new() {}\n").unwrap();
    let patch = Command::new("git")
        .args(["diff"])
        .current_dir(&repo)
        .output()
        .unwrap()
        .stdout;
    sh(&repo, &["git", "checkout", "--", "src/lib.rs"]);

    let patch_digest = Sha256Digest::of_bytes(&patch);
    std::fs::write(artifacts.join(patch_digest.to_hex()), &patch).unwrap();

    let att = PreparedAttempt::admit(
        AttemptId::from_bytes([9; 16]),
        WorkRequestId::from_bytes([1; 16]),
        CandidateArtifactId::from_bytes([2; 16]),
        RepositoryLocator::new(repo.to_string_lossy()),
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
    let mut store = SqliteStore::open(&root.join("state.sqlite")).unwrap();
    store.admit_attempt(&att).unwrap();

    Fx {
        root,
        repo,
        store,
        att,
        basis,
    }
}

fn grant(fx: &mut Fx, byte: u8, act: StandingAct) -> StandingGrant {
    let g = StandingGrant::issue(
        StandingGrantId::from_bytes([byte; 16]),
        StandingScope {
            actor: ACTOR,
            act,
            repository: fx.att.repository.clone(),
            attempt_digest: fx.att.prepared_attempt_digest,
        },
        ClockReading(1_000_000),
    );
    fx.store.create_standing_grant(&g).unwrap();
    g
}

/// Drive to `Indeterminate` with the journal recording `commit_created` and
/// `ref_updating` but no `ref_updated` — the state the design is actually for.
/// Returns the commit the broker created.
fn stage_ref_updating(fx: &mut Fx) -> String {
    let clock = FixedClock(ClockReading(10));
    let mut ids = HashChainIds::new();
    let g = grant(fx, 1, StandingAct::Ratify);
    ratify(
        &mut fx.store,
        fx.att.attempt_id,
        g.id(),
        ACTOR,
        fx.att.prepared_attempt_digest,
        CommitHash::new(&fx.basis),
        &clock,
        &mut ids,
    )
    .unwrap();
    reserve(
        &mut fx.store,
        fx.att.attempt_id,
        1_000_000,
        &clock,
        &mut ids,
    )
    .unwrap();

    let mut broker = SubprocessGitBroker::new(
        PathBuf::from(env!("CARGO_BIN_EXE_gwr-git-broker")),
        fx.root.join("journals"),
        fx.root.join("artifacts"),
    );
    broker.crash_after = Some("ref_updating".into());
    let out = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut broker,
        &clock,
        &mut ids,
    )
    .unwrap();
    assert!(matches!(out, DispatchOutcome::Indeterminate(_)));

    let dispatch_id = fx
        .store
        .find_attempt_dispatch(fx.att.attempt_id)
        .unwrap()
        .unwrap();
    let hex: String = dispatch_id
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let journal =
        std::fs::read_to_string(fx.root.join("journals").join(format!("{hex}.journal"))).unwrap();
    assert!(
        !journal.contains("ref_updated"),
        "the journal must not record a completed update"
    );
    assert_eq!(
        fx.target_ref(),
        fx.basis,
        "the abort happens before update-ref runs"
    );
    journal
        .lines()
        .find_map(|l| l.strip_prefix("commit_created "))
        .expect("the journal records the created commit")
        .to_string()
}

impl Fx {
    fn target_ref(&self) -> String {
        sh(&self.repo, &["git", "rev-parse", TARGET_REF])
    }

    fn resolve_now(&mut self) -> Result<RecoveryVerdict, String> {
        let clock = FixedClock(ClockReading(20));
        let mut ids = HashChainIds::new();
        let fact = gwr_local::recover::produce_fact(
            &mut self.store,
            self.att.attempt_id,
            &self.root.join("journals"),
            &clock,
            &mut ids,
        )
        .unwrap();
        let g = grant(self, 2, StandingAct::ResolveRecovery);
        let mut ev = gwr_local::recover::GitRecoveryEvidence::new(self.root.join("journals"));
        resolve(
            &mut self.store,
            self.att.attempt_id,
            fact.id,
            g.id(),
            ACTOR,
            &mut ev,
            &clock,
            &mut ids,
        )
        .map(|r| r.verdict)
        .map_err(|e| format!("{e:?}"))
    }
}

/// Custody **held**: the effect landed and was never disturbed. The verdict is
/// correct, and this is the case the premise makes sound.
#[test]
fn under_exclusive_custody_a_landed_effect_recovers_as_committed() {
    let mut fx = fixture("held");
    let created = stage_ref_updating(&mut fx);
    // Exactly what a successful update-ref would have done, with no journal line.
    sh(&fx.repo, &["git", "update-ref", TARGET_REF, &created]);

    assert_eq!(
        fx.resolve_now().unwrap(),
        RecoveryVerdict::CommittedViaRecovery
    );
    assert!(matches!(
        fx.store.get_attempt(fx.att.attempt_id).unwrap().state,
        AttemptState::CommittedViaRecovery { .. }
    ));
}

/// Custody **violated**: the effect landed, then a writer other than the broker
/// returned the ref to the basis.
///
/// The runtime mints `ProvenNotCommitted` for an effect that did land. This
/// assertion documents the boundary; it is not a defended property. If a future
/// change makes the runtime detect this, that change should rewrite this test
/// deliberately — and update `trust-model.md`, the invariant-table custody note,
/// and `RecoveryVerdict`'s documentation with it.
#[test]
fn without_exclusive_custody_proven_not_committed_is_not_sound() {
    let mut fx = fixture("violated");
    let created = stage_ref_updating(&mut fx);

    // H2: the effect lands...
    sh(&fx.repo, &["git", "update-ref", TARGET_REF, &created]);
    assert_ne!(fx.target_ref(), fx.basis, "the effect really landed");
    // ...and a third party reverts it.
    sh(&fx.repo, &["git", "update-ref", TARGET_REF, &fx.basis]);

    let verdict = fx.resolve_now().unwrap();
    assert_eq!(
        verdict,
        RecoveryVerdict::ProvenNotCommitted,
        "boundary specimen: with custody violated the runtime reports non-occurrence \
         for an effect that occurred"
    );

    // And nothing retained anywhere would have revealed it: the journal knows a
    // commit was created, but not whether the ref ever held it.
    assert!(
        !fx.root.join("repo/.git/logs/refs/gwr").exists(),
        "refs/gwr/* has no reflog under Git's defaults, so the intervening \
         update leaves no durable trace"
    );
}
