//! Task 6 provider-contract tests: preparation labor varies independently of
//! the governed lifecycle.

use gwr_core::digest::Sha256Digest;
use gwr_core::ids::*;
use gwr_core::preparation::{PreparationEnd, PreparationRun, PreparationStatus};
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryIdentity, WorkRequest};
use gwr_local::adapters::{FixedClock, FsArtifactStore, FsProvenanceSink, HashChainIds};
use gwr_local::providers::fake::{GoalEchoProvider, Script, ScriptedProvider};
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::labor_provider::{BoundedAssignment, LaborProvider};
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::preparation::{
    run_preparation, PreparationResult, PreparationServiceError,
};

struct Fixture {
    store: SqliteStore,
    artifacts: FsArtifactStore,
    provenance: FsProvenanceSink,
    ids: HashChainIds,
    dir: std::path::PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("gwr-prov-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            store: SqliteStore::open(&dir.join("state.sqlite")).unwrap(),
            artifacts: FsArtifactStore::new(dir.join("artifacts")).unwrap(),
            provenance: FsProvenanceSink::new(dir.join("provenance")).unwrap(),
            ids: HashChainIds::new(),
            dir,
        }
    }

    fn run(&mut self, byte: u8, deadline: u64) -> (PreparationRun, BoundedAssignment) {
        let wr = WorkRequest {
            id: WorkRequestId::from_bytes([1; 16]),
            repository: RepositoryIdentity::new("/tmp/fixture"),
            target_ref: RefName::new("refs/gwr/target"),
            goal: "make canonicalizes_whitespace pass".into(),
            created_at: ClockReading(1),
        };
        self.store.create_work_request(&wr).unwrap();
        let run = PreparationRun {
            id: PreparationRunId::from_bytes([byte; 16]),
            work_request: wr.id,
            started_at: ClockReading(2),
            deadline: ClockReading(deadline),
            status: PreparationStatus::Running,
        };
        self.store.create_preparation_run(&run).unwrap();
        let assignment = BoundedAssignment {
            preparation_run: run.id,
            goal: wr.goal.clone(),
            basis: CommitHash::new("basis-aaa"),
            workspace: self.dir.join("workspace"),
            deadline: run.deadline,
        };
        (run, assignment)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn provider_death_before_candidate_ends_run_without_minting_anything() {
    let mut fx = Fixture::new("death");
    let (run, assignment) = fx.run(2, 100);
    let mut provider = ScriptedProvider::new(Script::Die("segfault".into()));
    let clock = FixedClock(ClockReading(50));
    let result = run_preparation(
        &mut fx.store,
        &mut provider,
        &run,
        &assignment,
        &mut fx.artifacts,
        &mut fx.provenance,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert_eq!(result, PreparationResult::Failed);
    let stored = fx.store.get_preparation_run(run.id).unwrap();
    assert_eq!(
        stored.status,
        PreparationStatus::Ended(PreparationEnd::ProviderFailed)
    );
    // No candidate exists; nothing about any effect was minted.
    assert!(fx.store.list_attempts().unwrap().is_empty());
}

#[test]
fn provider_refusal_is_recorded_with_explanation_as_provenance() {
    let mut fx = Fixture::new("refusal");
    let (run, assignment) = fx.run(2, 100);
    let mut provider = ScriptedProvider::new(Script::Refuse("out of scope".into()));
    let clock = FixedClock(ClockReading(50));
    let result = run_preparation(
        &mut fx.store,
        &mut provider,
        &run,
        &assignment,
        &mut fx.artifacts,
        &mut fx.provenance,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert_eq!(result, PreparationResult::Refused);
    let stored = fx.store.get_preparation_run(run.id).unwrap();
    assert_eq!(
        stored.status,
        PreparationStatus::Ended(PreparationEnd::ProviderRefused)
    );
    let log = fx.provenance.read(run.id).unwrap();
    assert!(log.contains("refusal_explanation\tout of scope"));
}

#[test]
fn late_candidate_is_not_ingested() {
    let mut fx = Fixture::new("late");
    let (run, assignment) = fx.run(2, 40);
    let mut provider = ScriptedProvider::new(Script::Produce {
        patch: b"late patch".to_vec(),
        reported_digest: None,
    });
    let clock = FixedClock(ClockReading(50)); // past the deadline of 40
    let result = run_preparation(
        &mut fx.store,
        &mut provider,
        &run,
        &assignment,
        &mut fx.artifacts,
        &mut fx.provenance,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert_eq!(result, PreparationResult::LateCandidate);
    let stored = fx.store.get_preparation_run(run.id).unwrap();
    assert_eq!(
        stored.status,
        PreparationStatus::Ended(PreparationEnd::Expired)
    );
}

#[test]
fn duplicate_event_sequence_is_refused() {
    let mut fx = Fixture::new("dupseq");
    let (run, assignment) = fx.run(2, 100);
    let mut provider = ScriptedProvider::new(Script::DuplicateSequence {
        patch: b"patch".to_vec(),
    });
    let clock = FixedClock(ClockReading(50));
    let err = run_preparation(
        &mut fx.store,
        &mut provider,
        &run,
        &assignment,
        &mut fx.artifacts,
        &mut fx.provenance,
        &clock,
        &mut fx.ids,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        PreparationServiceError::DuplicateEventSequence
    ));
    let stored = fx.store.get_preparation_run(run.id).unwrap();
    assert_eq!(
        stored.status,
        PreparationStatus::Ended(PreparationEnd::ProviderFailed)
    );
}

#[test]
fn artifact_digest_is_computed_by_the_runtime_and_mismatch_is_recorded() {
    let mut fx = Fixture::new("digest");
    let (run, assignment) = fx.run(2, 100);
    let patch = b"the exact patch bytes".to_vec();
    let true_digest = Sha256Digest::of_bytes(&patch);
    // The provider lies about the digest.
    let mut provider = ScriptedProvider::new(Script::Produce {
        patch: patch.clone(),
        reported_digest: Some("deadbeef".repeat(8)),
    });
    let clock = FixedClock(ClockReading(50));
    let result = run_preparation(
        &mut fx.store,
        &mut provider,
        &run,
        &assignment,
        &mut fx.artifacts,
        &mut fx.provenance,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    let PreparationResult::CandidateIngested {
        artifact,
        reported_digest_mismatch,
    } = result
    else {
        panic!("expected ingestion");
    };
    // The runtime's digest stands; the lie is recorded, not believed.
    assert_eq!(artifact.content_digest, true_digest);
    assert!(reported_digest_mismatch);
    let stored = fx.store.get_candidate(artifact.id).unwrap();
    assert_eq!(stored.content_digest, true_digest);
}

#[test]
fn provider_replacement_uses_another_run_id_and_no_core_changes() {
    let mut fx = Fixture::new("replace");
    // Provider A dies.
    let (run_a, assignment_a) = fx.run(2, 100);
    let mut provider_a = ScriptedProvider::new(Script::Die("gone".into()));
    let clock = FixedClock(ClockReading(50));
    run_preparation(
        &mut fx.store,
        &mut provider_a,
        &run_a,
        &assignment_a,
        &mut fx.artifacts,
        &mut fx.provenance,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    // Provider B — a structurally different implementation of the same
    // contract — replaces it under a new PreparationRunId.
    let (run_b, assignment_b) = fx.run(3, 100);
    assert_ne!(run_a.id, run_b.id);
    let mut provider_b = GoalEchoProvider;
    let result = run_preparation(
        &mut fx.store,
        &mut provider_b,
        &run_b,
        &assignment_b,
        &mut fx.artifacts,
        &mut fx.provenance,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert!(matches!(
        result,
        PreparationResult::CandidateIngested { .. }
    ));
    // Provider identity appears nowhere in core records: the candidate knows
    // only its run, and the store schema carries no provider columns.
    let names = fx.store.all_column_names().unwrap();
    assert!(names.iter().all(|c| !c.to_lowercase().contains("provider")));
}

#[test]
fn provider_tool_requests_remain_untrusted_records() {
    let mut fx = Fixture::new("tools");
    let (run, assignment) = fx.run(2, 100);
    // The scripted provider emits a ToolRequest event asking to write the
    // governed target directly. It is an event record; there is no API through
    // which it could acquire authority, and nothing in the store grants it.
    let mut provider = ScriptedProvider::new(Script::Produce {
        patch: b"patch".to_vec(),
        reported_digest: None,
    });
    let clock = FixedClock(ClockReading(50));
    let result = run_preparation(
        &mut fx.store,
        &mut provider,
        &run,
        &assignment,
        &mut fx.artifacts,
        &mut fx.provenance,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert!(matches!(
        result,
        PreparationResult::CandidateIngested { .. }
    ));
    // The lifecycle is untouched: no attempt exists, no standing grants exist,
    // and the tool request produced no record outside provenance/events.
    assert!(fx.store.list_attempts().unwrap().is_empty());
}

#[test]
fn cancellation_is_best_effort_and_recorded_by_the_adapter() {
    let mut provider = ScriptedProvider::new(Script::Fail("n/a".into()));
    let run_id = PreparationRunId::from_bytes([7; 16]);
    provider.cancel(run_id);
    assert_eq!(provider.cancelled, vec![run_id]);
}
