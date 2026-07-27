//! Stage-3 acceptance: the explicit effect-class boundary.
//!
//! v0 admits exactly one effect class, `git-ref-update:v1`. These tests prove
//! the pilot's run-N failure mode is closed: a proposal outside the admitted
//! class is refused at request creation / candidate admission with a typed
//! `EffectClassRefusal` — before any standing is issued or consumed, any
//! reservation is created, any dispatch identity is minted, any provider is
//! invoked, or any Git interpretation occurs. They also prove that provider
//! tool requests remain testimony with no path to admission, and that records
//! persisted before the boundary (the preserved pilot evidence) stay readable.

use gwr_core::digest::Sha256Digest;
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::AttemptState;
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::preparation::{CandidateArtifact, PreparationRun, PreparationStatus};
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryLocator, WorkRequest};
use gwr_local::adapters::{FixedClock, FsArtifactStore, FsProvenanceSink, HashChainIds};
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::labor_provider::{
    BoundedAssignment, LaborProvider, PreparationOutcome, PreparationReport, ProviderError,
    ProviderEvent, SequencedEvent,
};
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::preparation::run_preparation;
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
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Run the docket CLI, allowing failure; return (exit-zero, stdout+stderr).
fn docket(state: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_docket"))
        .args(args)
        .args(["--state", state.to_string_lossy().as_ref()])
        .env("GWR_BROKER_BIN", env!("CARGO_BIN_EXE_gwr-git-broker"))
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

struct Fx {
    root: PathBuf,
    repo: PathBuf,
    state: PathBuf,
    basis: String,
    patch_file: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture(name: &str) -> Fx {
    let root = std::env::temp_dir().join(format!("gwr-effect-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let repo = root.join("repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
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
    let patch_file = root.join("candidate.patch");
    std::fs::write(&patch_file, &patch).unwrap();
    Fx {
        state: root.join("state"),
        root,
        repo,
        basis,
        patch_file,
    }
}

/// Count rows in an authority-bearing table of a CLI state directory.
fn count(state: &Path, table: &str) -> i64 {
    let conn = rusqlite::Connection::open(state.join("state.sqlite")).unwrap();
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

fn assert_nothing_spent(state: &Path) {
    for table in [
        "attempt",
        "standing_grant",
        "standing_use",
        "reservation",
        "reservation_use",
        "dispatch",
        "commitment",
        "dispatch_refusal",
        "indeterminate_outcome",
    ] {
        assert_eq!(count(state, table), 0, "{table} must be empty");
    }
}

// The pilot's notification exercise, re-run. Expected now: refusal at request
// creation as an unsupported effect class; no request, no provider run, no
// standing, no reservation, no dispatch identity, no Git interpretation, no
// repository or ref mutation.
#[test]
fn a_notification_proposal_is_refused_before_anything_exists() {
    let fx = fixture("mailto");
    let (ok, out) = docket(
        &fx.state,
        &[
            "request",
            "create",
            "--repo",
            fx.repo.to_string_lossy().as_ref(),
            "--target-ref",
            "mailto:ops@example.com",
            "--goal",
            "Send a notification that the pilot finished",
        ],
    );
    assert!(!ok, "the proposal must be refused: {out}");
    assert!(out.contains("UnsupportedEffectClass"), "{out}");
    assert!(out.contains("mailto:ops@example.com"), "{out}");

    assert_eq!(count(&fx.state, "work_request"), 0, "no request recorded");
    assert_nothing_spent(&fx.state);
    assert!(
        !fx.state.join("journals").exists()
            || std::fs::read_dir(fx.state.join("journals"))
                .unwrap()
                .next()
                .is_none(),
        "no broker journal exists"
    );
    assert_eq!(
        sh(&fx.repo, &["git", "rev-parse", TARGET_REF]),
        fx.basis,
        "no ref mutation"
    );
}

// A request stored before the boundary existed (the pilot's run-N shape) must
// not reach provider execution: prepare start refuses it.
#[test]
fn a_pre_boundary_inexpressible_request_cannot_start_preparation() {
    let fx = fixture("stored-mailto");
    // Insert the request directly, as pilot-era state would hold it.
    let mut store = SqliteStore::open(&{
        std::fs::create_dir_all(&fx.state).unwrap();
        fx.state.join("state.sqlite")
    })
    .unwrap();
    let wr = WorkRequest {
        id: WorkRequestId::from_bytes([7; 16]),
        repository_id: None,
        repository: RepositoryLocator::new(fx.repo.to_string_lossy()),
        target_ref: RefName::new("mailto:ops@example.com"),
        goal: "Send a notification".into(),
        created_at: ClockReading(1),
    };
    store.create_work_request(&wr).unwrap();
    drop(store);

    let (ok, out) = docket(
        &fx.state,
        &[
            "prepare",
            "start",
            "--request",
            "07070707070707070707070707070707",
            "--fake-patch",
            fx.patch_file.to_string_lossy().as_ref(),
            "--basis",
            &fx.basis,
        ],
    );
    assert!(!ok, "preparation must refuse: {out}");
    assert!(out.contains("UnsupportedEffectClass"), "{out}");
    assert_eq!(count(&fx.state, "preparation_run"), 0, "no provider ran");
    assert_eq!(count(&fx.state, "candidate_artifact"), 0);
    assert_nothing_spent(&fx.state);
}

// Inexpressible admissions refuse at `candidate admit`, before an attempt is
// minted — so standing (which is granted per attempt) can never be issued for
// them, let alone consumed.
#[test]
fn inexpressible_admissions_refuse_before_an_attempt_is_minted() {
    let fx = fixture("admit");
    let (ok, registration) = docket(
        &fx.state,
        &[
            "repository",
            "register",
            "--repo",
            fx.repo.to_string_lossy().as_ref(),
        ],
    );
    assert!(ok, "{registration}");
    let repository_id = registration
        .lines()
        .find_map(|l| l.strip_prefix("repository_id: "))
        .unwrap()
        .to_string();
    let (ok, out) = docket(
        &fx.state,
        &[
            "request",
            "create",
            "--repository-id",
            &repository_id,
            "--repo",
            fx.repo.to_string_lossy().as_ref(),
            "--target-ref",
            TARGET_REF,
            "--goal",
            "legitimate git work",
        ],
    );
    assert!(ok, "{out}");
    let request = out
        .lines()
        .find_map(|l| l.strip_prefix("work_request: "))
        .unwrap()
        .to_string();
    let (ok, out) = docket(
        &fx.state,
        &[
            "prepare",
            "start",
            "--request",
            &request,
            "--fake-patch",
            fx.patch_file.to_string_lossy().as_ref(),
            "--basis",
            &fx.basis,
        ],
    );
    assert!(ok, "{out}");
    let candidate = out
        .lines()
        .find_map(|l| l.strip_prefix("candidate: "))
        .unwrap()
        .to_string();

    // Empty basis: run N accepted this; it now refuses as no exact effect.
    let (ok, out) = docket(
        &fx.state,
        &[
            "candidate",
            "admit",
            "--request",
            &request,
            "--candidate",
            &candidate,
            "--basis",
            "",
            "--allow",
            "src/lib.rs",
            "--observe",
            "true",
        ],
    );
    assert!(!ok);
    assert!(out.contains("BasisNotACommitHash"), "{out}");

    // No admitted paths.
    let (ok, out) = docket(
        &fx.state,
        &[
            "candidate",
            "admit",
            "--request",
            &request,
            "--candidate",
            &candidate,
            "--basis",
            &fx.basis,
            "--observe",
            "true",
        ],
    );
    assert!(!ok);
    assert!(out.contains("NoAdmittedPaths"), "{out}");

    // An absolute path is not a repository-relative authorization.
    let (ok, out) = docket(
        &fx.state,
        &[
            "candidate",
            "admit",
            "--request",
            &request,
            "--candidate",
            &candidate,
            "--basis",
            &fx.basis,
            "--allow",
            "/etc/passwd",
            "--observe",
            "true",
        ],
    );
    assert!(!ok);
    assert!(out.contains("PathNotAdmissible"), "{out}");

    assert_eq!(count(&fx.state, "attempt"), 0, "no attempt was minted");
    assert_eq!(count(&fx.state, "standing_grant"), 0);
    assert_eq!(count(&fx.state, "reservation"), 0);
    assert_eq!(count(&fx.state, "dispatch"), 0);

    // Compatibility: the same request and candidate still admit normally.
    let (ok, out) = docket(
        &fx.state,
        &[
            "candidate",
            "admit",
            "--request",
            &request,
            "--candidate",
            &candidate,
            "--basis",
            &fx.basis,
            "--allow",
            "src/lib.rs",
            "--observe",
            "true",
        ],
    );
    assert!(ok, "a well-formed Git admission still works: {out}");
    assert_eq!(count(&fx.state, "attempt"), 1);
}

/// A provider that demands an effect in valid-looking Git vocabulary through
/// its tool-request channel. The request is testimony; nothing turns it into a
/// proposal, an attempt, or authority.
struct DemandingProvider {
    patch: Vec<u8>,
}

impl LaborProvider for DemandingProvider {
    fn prepare(
        &mut self,
        assignment: &BoundedAssignment,
    ) -> Result<PreparationReport, ProviderError> {
        Ok(PreparationReport {
            events: vec![
                SequencedEvent {
                    seq: 0,
                    event: ProviderEvent::Started,
                },
                SequencedEvent {
                    seq: 1,
                    event: ProviderEvent::ToolRequest(format!(
                        "update-ref {TARGET_REF} to my commit at basis {}",
                        assignment.basis.as_str()
                    )),
                },
                SequencedEvent {
                    seq: 2,
                    event: ProviderEvent::CandidateReady,
                },
            ],
            outcome: PreparationOutcome::Candidate {
                patch: self.patch.clone(),
            },
            provenance: vec![gwr_runtime::ports::labor_provider::ProvenanceEntry {
                label: "tool_request".into(),
                content: format!(
                    "update-ref {TARGET_REF} to my commit at basis {}",
                    assignment.basis.as_str()
                ),
            }],
        })
    }
}

// ProviderEvent::ToolRequest remains provenance/testimony only: after a
// preparation whose provider demanded a Git effect in so many words, the store
// holds no attempt, no standing, no reservation, and no dispatch. The port has
// no admission operation, and the boundary change added none.
#[test]
fn provider_tool_requests_cannot_become_effect_proposals() {
    let fx = fixture("tool-request");
    std::fs::create_dir_all(&fx.state).unwrap();
    let mut store = SqliteStore::open(&fx.state.join("state.sqlite")).unwrap();
    let wr = WorkRequest {
        id: WorkRequestId::from_bytes([1; 16]),
        repository_id: None,
        repository: RepositoryLocator::new(fx.repo.to_string_lossy()),
        target_ref: RefName::new(TARGET_REF),
        goal: "goal".into(),
        created_at: ClockReading(1),
    };
    store.create_work_request(&wr).unwrap();
    let run = PreparationRun {
        id: PreparationRunId::from_bytes([2; 16]),
        work_request: wr.id,
        started_at: ClockReading(2),
        deadline: ClockReading(1_000_000),
        status: PreparationStatus::Running,
    };
    store.create_preparation_run(&run).unwrap();

    let assignment = BoundedAssignment {
        preparation_run: run.id,
        goal: wr.goal.clone(),
        basis: CommitHash::new(&fx.basis),
        workspace: fx.root.join("workspace"),
        deadline: run.deadline,
    };
    let mut provider = DemandingProvider {
        patch: std::fs::read(&fx.patch_file).unwrap(),
    };
    let mut artifacts = FsArtifactStore::new(fx.state.join("artifacts")).unwrap();
    let mut provenance = FsProvenanceSink::new(fx.state.join("provenance")).unwrap();
    let clock = FixedClock(ClockReading(3));
    let mut ids = HashChainIds::new();
    run_preparation(
        &mut store,
        &mut provider,
        &run,
        &assignment,
        &mut artifacts,
        &mut provenance,
        &clock,
        &mut ids,
    )
    .unwrap();

    // The demand exists — as recorded testimony.
    let mut found = false;
    for entry in std::fs::read_dir(fx.state.join("provenance")).unwrap() {
        let content = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        if content.contains("update-ref refs/gwr/target") {
            found = true;
        }
    }
    assert!(found, "the tool request is recorded as provenance");

    // And it authorized nothing.
    assert_eq!(store.list_attempts().unwrap().len(), 0);
    drop(store);
    assert_eq!(count(&fx.state, "standing_grant"), 0);
    assert_eq!(count(&fx.state, "reservation"), 0);
    assert_eq!(count(&fx.state, "dispatch"), 0);
    assert_eq!(
        sh(&fx.repo, &["git", "rev-parse", TARGET_REF]),
        fx.basis,
        "no ref mutation"
    );
}

// Records persisted before the boundary (the preserved pilot evidence, e.g.
// run N's admitted mailto attempt) remain readable: reconstruction and the
// dossier do not re-validate history, they expose it.
#[test]
fn pre_boundary_persisted_attempts_remain_readable() {
    let fx = fixture("pre-boundary");
    std::fs::create_dir_all(&fx.state).unwrap();
    let mut store = SqliteStore::open(&fx.state.join("state.sqlite")).unwrap();
    let wr = WorkRequest {
        id: WorkRequestId::from_bytes([1; 16]),
        repository_id: None,
        repository: RepositoryLocator::new(fx.repo.to_string_lossy()),
        target_ref: RefName::new("mailto:ops@example.com"),
        goal: "Send a notification".into(),
        created_at: ClockReading(1),
    };
    store.create_work_request(&wr).unwrap();
    let cand = CandidateArtifact {
        id: CandidateArtifactId::from_bytes([2; 16]),
        preparation_run: PreparationRunId::from_bytes([3; 16]),
        content_digest: Sha256Digest::of_bytes(b""),
        content_len: 0,
        ingested_at: ClockReading(2),
    };
    store.ingest_candidate(&cand).unwrap();
    // Exactly what run N persisted: an attempt whose "effect" is not
    // expressible in the admitted class. The store accepts it — history is
    // not re-litigated at the persistence port.
    let att = PreparedAttempt::admit(
        AttemptId::from_bytes([9; 16]),
        wr.id,
        cand.id,
        wr.repository.clone(),
        CommitHash::new(""),
        cand.content_digest,
        GitRefEffect {
            target_ref: RefName::new("mailto:ops@example.com"),
            expected_basis: CommitHash::new(""),
            patch_digest: cand.content_digest,
            allowed_paths: vec!["ops@example.com".into()],
        },
        ObservationPlan {
            argv: vec!["true".into()],
            environment_description: "operator workstation".into(),
        },
        ClockReading(3),
    );
    store.admit_attempt(&att).unwrap();

    let projected = store.get_attempt(att.attempt_id).unwrap();
    assert_eq!(projected.attempt, att, "byte-exact round trip");
    assert!(matches!(projected.state, AttemptState::Prepared));

    let d = gwr_runtime::services::dossier::assemble(&mut store, att.attempt_id).unwrap();
    let text = gwr_runtime::services::dossier::render_text(&d);
    assert!(
        text.contains("mailto:ops@example.com"),
        "the historical category error stays visible"
    );
}
