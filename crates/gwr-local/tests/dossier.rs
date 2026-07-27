//! Stage-2 acceptance: the canonical attempt dossier.
//!
//! One read model sources both operator surfaces. These tests prove the dossier
//! exposes what the runtime already recorded — identity, authority, execution,
//! observation, reliance, obligations — and that the one premise-dependent
//! verdict class is rendered qualified, with its evidence and its custody
//! premise visible. They also prove the negative boundaries: no secret
//! authority material appears on any surface, and malformed persisted records
//! produce typed read errors rather than panics or invented defaults.

use gwr_core::digest::Sha256Digest;
use gwr_core::domain::evidence::Claim;
use gwr_core::domain::standing::{StandingAct, StandingGrant, StandingScope};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::{AttemptState, RecoveryVerdict};
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::preparation::CandidateArtifact;
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::repository::{RepositoryAlias, RepositoryAliasKind, RepositoryRegistration};
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryLocator, WorkRequest};
use gwr_local::adapters::{FixedClock, HashChainIds};
use gwr_local::broker::SubprocessGitBroker;
use gwr_local::capabilities::StandingTokenCodec;
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::{Store, StoreError};
use gwr_runtime::services::dispatch::{dispatch, DispatchOutcome};
use gwr_runtime::services::dossier::{
    assemble, render_json, render_text, DossierError, EvidenceConcordance, Settlement,
};
use gwr_runtime::services::ratification::ratify;
use gwr_runtime::services::recovery::resolve;
use gwr_runtime::services::reliance::{rely_review_queue, RelyError};
use gwr_runtime::services::reservation::reserve;
use std::path::{Path, PathBuf};
use std::process::Command;

const TARGET_REF: &str = "refs/gwr/target";
const ACTOR: ActorId = ActorId::from_bytes([4; 16]);
const GOAL: &str = "make the fixture test pass";

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
    ids: HashChainIds,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture(name: &str) -> Fx {
    let root = std::env::temp_dir().join(format!("gwr-dossier-{name}-{}", std::process::id()));
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

    let mut store = SqliteStore::open(&root.join("state.sqlite")).unwrap();

    // The full identity chain the dossier reads: work request, candidate,
    // admitted attempt.
    let wr = WorkRequest {
        id: WorkRequestId::from_bytes([1; 16]),
        repository_id: None,
        repository: RepositoryLocator::new(repo.to_string_lossy()),
        target_ref: RefName::new(TARGET_REF),
        goal: GOAL.into(),
        created_at: ClockReading(1),
    };
    store.create_work_request(&wr).unwrap();
    let cand = CandidateArtifact {
        id: CandidateArtifactId::from_bytes([2; 16]),
        preparation_run: PreparationRunId::from_bytes([3; 16]),
        content_digest: patch_digest,
        content_len: patch.len() as u64,
        ingested_at: ClockReading(2),
    };
    store.ingest_candidate(&cand).unwrap();

    let att = PreparedAttempt::admit(
        AttemptId::from_bytes([9; 16]),
        wr.id,
        cand.id,
        wr.repository.clone(),
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
        ClockReading(3),
    );
    store.admit_attempt(&att).unwrap();

    Fx {
        root,
        repo,
        store,
        att,
        basis,
        ids: HashChainIds::new(),
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

fn broker(fx: &Fx) -> SubprocessGitBroker {
    SubprocessGitBroker::new(
        PathBuf::from(env!("CARGO_BIN_EXE_gwr-git-broker")),
        fx.root.join("journals"),
        fx.root.join("artifacts"),
    )
}

fn ratify_and_reserve(fx: &mut Fx) {
    let clock = FixedClock(ClockReading(10));
    let g = grant(fx, 1, StandingAct::Ratify);
    let mut ids = HashChainIds::new();
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
}

/// Drive the attempt to normal `Committed`, with an observation, one admitted
/// and one refused reliance claim, and reconciliation.
fn drive_committed(fx: &mut Fx) -> ObservationId {
    ratify_and_reserve(fx);
    let clock = FixedClock(ClockReading(20));
    let mut b = broker(fx);
    let out = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut b,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert!(matches!(out, DispatchOutcome::Committed(_)));
    let obs = gwr_local::observe::observe(
        &mut fx.store,
        fx.att.attempt_id,
        &FixedClock(ClockReading(30)),
        &mut fx.ids,
    )
    .unwrap();
    rely_review_queue(
        &mut fx.store,
        fx.att.attempt_id,
        obs.id,
        Claim::ExactResultCommitProducedAndCommandExitedZero,
        &FixedClock(ClockReading(40)),
    )
    .unwrap();
    let refused = rely_review_queue(
        &mut fx.store,
        fx.att.attempt_id,
        obs.id,
        Claim::SafeToMerge,
        &FixedClock(ClockReading(41)),
    );
    assert!(matches!(refused, Err(RelyError::Refused(_))));
    gwr_runtime::services::reconcile::reconcile(
        &mut fx.store,
        fx.att.attempt_id,
        &FixedClock(ClockReading(50)),
        &mut fx.ids,
    )
    .unwrap();
    obs.id
}

/// Crash the broker immediately after `ref_updated` is journalled: the effect
/// lands, the acknowledgement is lost, the attempt is indeterminate.
fn drive_indeterminate_after_landing(fx: &mut Fx) {
    ratify_and_reserve(fx);
    let clock = FixedClock(ClockReading(20));
    let mut b = broker(fx);
    b.crash_after = Some("ref_updated".into());
    let out = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut b,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert!(matches!(out, DispatchOutcome::Indeterminate(_)));
    assert_ne!(
        sh(&fx.repo, &["git", "rev-parse", TARGET_REF]),
        fx.basis,
        "the effect really landed"
    );
}

fn recover_and_resolve(fx: &mut Fx, grant_byte: u8) -> RecoveryVerdict {
    let clock = FixedClock(ClockReading(60));
    let mut ids = HashChainIds::new();
    let fact = gwr_local::recover::produce_fact(
        &mut fx.store,
        fx.att.attempt_id,
        &fx.root.join("journals"),
        &clock,
        &mut ids,
    )
    .unwrap();
    let g = grant(fx, grant_byte, StandingAct::ResolveRecovery);
    let mut ev = gwr_local::recover::GitRecoveryEvidence::new(fx.root.join("journals"));
    resolve(
        &mut fx.store,
        fx.att.attempt_id,
        fact.id,
        g.id(),
        ACTOR,
        &mut ev,
        &clock,
        &mut ids,
    )
    .unwrap()
    .verdict
}

// 1 — a normal committed attempt: identity, authority, execution, observation,
//     and settlement are all exposed from the store alone.
#[test]
fn normal_committed_attempt_is_fully_legible() {
    let mut fx = fixture("normal");
    drive_committed(&mut fx);

    let d = assemble(&mut fx.store, fx.att.attempt_id).unwrap();
    assert_eq!(d.work_request.goal, GOAL);
    assert_eq!(d.attempt.repository, fx.att.repository);
    assert_eq!(d.attempt.effect.target_ref.as_str(), TARGET_REF);
    assert_eq!(d.attempt.basis.as_str(), fx.basis);
    assert_eq!(
        d.attempt.effect.allowed_paths,
        vec!["src/lib.rs".to_string()]
    );
    assert_eq!(d.execution.settlement, Settlement::Normal);
    assert!(d.qualification.is_none(), "no recovery verdict to qualify");

    let rat = d.authority.ratification.as_ref().expect("ratification");
    assert_eq!(rat.actor, ACTOR);
    let g = d.authority.ratifying_grant.as_ref().expect("grant");
    assert_eq!(g.attempt_digest_binding, fx.att.prepared_attempt_digest);
    assert!(g.consumed_by.is_some(), "the one use was spent");
    let rsv = d.authority.reservation.as_ref().expect("reservation");
    assert!(rsv.consumed_by.is_some());
    assert!(d.authority.dispatch.is_some());
    assert!(d.authority.recovery_grant.is_none());

    let c = d.execution.commitment.as_ref().expect("commitment");
    assert_eq!(c.previous_value.as_str(), fx.basis);
    assert_eq!(
        c.result_commit.as_str(),
        sh(&fx.repo, &["git", "rev-parse", TARGET_REF])
    );
    assert_eq!(d.observation.observations.len(), 1);
    assert_eq!(d.observation.reliance_admissions.len(), 1);
    assert!(d.timeline.iter().all(|t| t.at.0 > 0), "timestamps exposed");

    // Both surfaces state the load-bearing facts.
    let text = render_text(&d);
    let json = render_json(&d);
    for surface in [&text, &json] {
        assert!(surface.contains(GOAL), "goal missing");
        assert!(surface.contains(TARGET_REF), "target ref missing");
        assert!(surface.contains(&fx.basis), "basis missing");
        assert!(surface.contains(c.result_commit.as_str()), "result missing");
        assert!(
            surface.contains(&fx.att.prepared_attempt_digest.to_hex()),
            "prepared digest missing"
        );
        assert!(surface.contains("src/lib.rs"), "admitted path missing");
    }
    assert!(json.contains("\"settlement\":\"normal\""));
}

#[test]
fn legacy_dossier_is_not_path_migrated_and_explicit_registration_binds_v3_subject() {
    let mut fx = fixture("repository-migration");
    drive_committed(&mut fx);

    // Merely opening the migrated database did not infer an identity from the
    // path already stored in the attempt. Its legacy dossier remains exactly
    // the closed v2 shape.
    let legacy = assemble(&mut fx.store, fx.att.attempt_id).unwrap();
    assert_eq!(legacy.repository_id, None);
    assert_eq!(legacy.ref_continuity_subject, None);
    let legacy_bytes = render_json(&legacy).into_bytes();
    assert!(std::str::from_utf8(&legacy_bytes)
        .unwrap()
        .contains("\"dossier_format\":\"gwr:attempt-dossier:v2\""));

    // Migration is an explicit Docket registration: mint/register the opaque
    // ID and retain the old stored path as a locator.
    let repository_id = RepositoryId::from_bytes([0x5c; 16]);
    fx.store
        .register_repository(&RepositoryRegistration {
            id: repository_id,
            registered_at: ClockReading(60),
            aliases: vec![RepositoryAlias {
                kind: RepositoryAliasKind::Path,
                locator: fx.att.repository.clone(),
                registered_at: ClockReading(60),
                current: true,
            }],
        })
        .unwrap();

    let registered_only = assemble(&mut fx.store, fx.att.attempt_id).unwrap();
    assert_eq!(
        registered_only.repository_id, None,
        "registering a path alias must not silently migrate a historical dossier"
    );
    assert!(render_json(&registered_only).contains("\"dossier_format\":\"gwr:attempt-dossier:v2\""));

    fx.store
        .bind_work_request_repository(fx.att.work_request, repository_id)
        .unwrap();
    let promoted = assemble(&mut fx.store, fx.att.attempt_id).unwrap();
    assert_eq!(promoted.repository_id, Some(repository_id));
    let commitment = promoted.execution.commitment.as_ref().unwrap();
    let expected = format!(
        "gwr:ref-continuity:v0:{repository_id}#{TARGET_REF}@{}",
        commitment.result_commit.as_str()
    );
    assert_eq!(
        promoted.ref_continuity_subject.as_ref().unwrap().as_str(),
        expected
    );
    assert!(
        !expected.contains(fx.att.repository.as_str()),
        "the operational path must not enter the logical subject"
    );

    let v3 = render_json(&promoted);
    assert!(v3.contains("\"dossier_format\":\"gwr:attempt-dossier:v3\""));
    assert!(v3.contains(&format!("\"repository_id\":\"{repository_id}\"")));
    assert!(v3.contains(&format!("\"ref_continuity_subject\":\"{expected}\"")));
    assert!(v3.contains("\"repository_locator\":{\"kind\":\"path\""));
    assert!(
        !v3.contains("\"repository\":"),
        "v3 must label the stored path as a locator"
    );

    // Rendering the already-issued legacy read model after registration is
    // byte-identical: promotion creates a new v3 projection and rewrites no
    // historical artifact.
    assert_eq!(render_json(&legacy).as_bytes(), legacy_bytes);
}

// 2 — a `CommittedViaRecovery` attempt: recovery evidence, the separate
//     recovery grant, and the qualified verdict are exposed.
#[test]
fn committed_via_recovery_is_exposed_with_its_evidence() {
    let mut fx = fixture("recovery");
    drive_indeterminate_after_landing(&mut fx);
    assert_eq!(
        recover_and_resolve(&mut fx, 2),
        RecoveryVerdict::CommittedViaRecovery
    );

    let d = assemble(&mut fx.store, fx.att.attempt_id).unwrap();
    assert!(matches!(d.state, AttemptState::CommittedViaRecovery { .. }));
    assert_eq!(d.execution.settlement, Settlement::Recovered);
    assert_eq!(d.execution.recovery_facts.len(), 1);
    let rg = d.authority.recovery_grant.as_ref().expect("recovery grant");
    assert_eq!(rg.act, StandingAct::ResolveRecovery);

    let q = d.qualification.as_ref().expect("qualification");
    assert_eq!(q.verdict, RecoveryVerdict::CommittedViaRecovery);
    assert_eq!(
        q.concordance,
        EvidenceConcordance::ObservedMatchesExpectedResult
    );
    assert!(q.concordance.agrees());

    let text = render_text(&d);
    let json = render_json(&d);
    assert!(text.contains("ExclusiveRefCustody"));
    assert!(json.contains("\"custody_premise\":\"ExclusiveRefCustody\""));
    assert!(json.contains("\"evidence_agrees\":true"));
    assert!(json.contains("\"settlement\":\"recovered\""));
}

// 3 — a refused reliance claim is stored and exposed with its subject: which
//     observation, presented to which consumer, for which claim.
#[test]
fn refused_reliance_claim_preserves_its_subject() {
    let mut fx = fixture("reliance-subject");
    let obs = drive_committed(&mut fx);

    let d = assemble(&mut fx.store, fx.att.attempt_id).unwrap();
    let refusals = &d.observation.reliance_refusals;
    assert_eq!(refusals.len(), 1);
    let subject = refusals[0].subject.as_ref().expect("subject preserved");
    assert_eq!(subject.observation, obs);
    assert_eq!(subject.consumer, "review-queue");
    assert_eq!(subject.claim, Claim::SafeToMerge);

    let text = render_text(&d);
    let json = render_json(&d);
    assert!(text.contains("claim_not_admissible"));
    assert!(text.contains("safe-to-merge"));
    assert!(json.contains("\"claim\":\"safe-to-merge\""));
    assert!(json.contains("\"consumer\":\"review-queue\""));
}

// 4 — residual obligations are exposed with kind, identity, and the
//     reconciliation that retained them.
#[test]
fn residual_obligations_are_exposed() {
    let mut fx = fixture("obligations");
    drive_committed(&mut fx);

    let d = assemble(&mut fx.store, fx.att.attempt_id).unwrap();
    assert_eq!(d.observation.residual_obligations.len(), 1);
    let ob = &d.observation.residual_obligations[0];
    let rec = d.observation.reconciliation.as_ref().expect("reconciled");
    assert_eq!(rec.retained_obligations, vec![ob.id]);

    let text = render_text(&d);
    let json = render_json(&d);
    assert!(text.contains("human_review_before_merge"));
    assert!(json.contains("\"kind\":\"human_review_before_merge\""));
}

// 5 — the custody-boundary specimen: the effect landed, an external writer
//     reverted the ref, and the runtime recorded `proven_not_committed`. The
//     dossier must make visible: an effect commit exists in the digest-verified
//     journal, the ref was observed at the basis, the verdict rests on asserted
//     `ExclusiveRefCustody`, and the records disagree — so the verdict is not
//     sound as an unconditional occurrence-history claim.
#[test]
fn custody_boundary_specimen_shows_premise_and_conflicting_evidence() {
    let mut fx = fixture("custody");
    drive_indeterminate_after_landing(&mut fx);
    let landed = sh(&fx.repo, &["git", "rev-parse", TARGET_REF]);
    // The custody violation: a writer other than the governed broker.
    sh(&fx.repo, &["git", "update-ref", TARGET_REF, &fx.basis]);

    assert_eq!(
        recover_and_resolve(&mut fx, 2),
        RecoveryVerdict::ProvenNotCommitted
    );

    let d = assemble(&mut fx.store, fx.att.attempt_id).unwrap();
    let q = d.qualification.as_ref().expect("qualification");
    assert_eq!(q.verdict, RecoveryVerdict::ProvenNotCommitted);
    assert_eq!(
        q.concordance,
        EvidenceConcordance::EffectCommitRecordedButNotObserved
    );
    assert!(!q.concordance.agrees());
    assert_eq!(
        q.fact.expected_result_commit.as_ref().unwrap().as_str(),
        landed,
        "the landed effect commit is visible"
    );
    assert_eq!(q.fact.observed_ref.as_str(), fx.basis);

    for surface in [render_text(&d), render_json(&d)] {
        assert!(surface.contains("ExclusiveRefCustody"), "premise missing");
        assert!(surface.contains(&landed), "effect commit missing");
        assert!(surface.contains(&fx.basis), "observed basis missing");
    }
    let text = render_text(&d);
    assert!(text.contains("asserted"), "premise must read as asserted");
    assert!(text.contains("records disagree"));
    assert!(
        text.contains("does_not_establish"),
        "the verdict must be bounded explicitly"
    );
    let json = render_json(&d);
    assert!(json.contains("\"evidence_agrees\":false"));
    assert!(json.contains("\"custody_premise_asserted_not_verified\":true"));
    assert!(json.contains("effect_commit_recorded_but_not_observed"));
}

// 6 — both surfaces are rendered from the same assembled value: same
//     identifiers, same facts, no independent assembly path.
#[test]
fn human_and_json_render_from_one_model() {
    let mut fx = fixture("one-model");
    drive_committed(&mut fx);

    let d = assemble(&mut fx.store, fx.att.attempt_id).unwrap();
    let text = render_text(&d);
    let json = render_json(&d);
    assert!(json.contains("\"dossier_format\":\"gwr:attempt-dossier:v2\""));

    // Every identifier the model holds appears on both surfaces.
    let ids: Vec<String> = vec![
        format!("{:032x}", 9u128), // attempt id [9;16] is not hex of 9; use field
    ];
    drop(ids);
    let attempt_hex: String = fx
        .att
        .attempt_id
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let c = d.execution.commitment.as_ref().unwrap();
    for fact in [
        attempt_hex.as_str(),
        GOAL,
        TARGET_REF,
        c.result_commit.as_str(),
        "normal",
    ] {
        assert!(text.contains(fact), "human surface missing {fact}");
        assert!(json.contains(fact), "json surface missing {fact}");
    }
}

// 7 — no secret authority material on any surface: not the standing key, not
//     any issued token text.
#[test]
fn no_secret_authority_material_is_exposed() {
    let mut fx = fixture("secrets");
    drive_committed(&mut fx);

    // A real token over a real grant from this store's scope, issued with a
    // known key. Neither the token nor the key may appear on any surface.
    let key = [0x5a; 32];
    let codec = StandingTokenCodec::new(key);
    let g = grant(&mut fx, 7, StandingAct::Ratify);
    let token = codec.issue(&g);
    let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();

    let d = assemble(&mut fx.store, fx.att.attempt_id).unwrap();
    for surface in [render_text(&d), render_json(&d)] {
        assert!(!surface.contains(&token), "token text leaked");
        assert!(!surface.contains(&key_hex), "MAC key leaked");
        // The MAC tag alone must not appear either.
        let tag = token.rsplit('|').next().unwrap();
        assert!(!surface.contains(tag), "MAC tag leaked");
    }
}

// 8 — malformed or incomplete persisted records produce typed read errors,
//     never panics and never invented defaults.
#[test]
fn malformed_persisted_records_produce_typed_read_errors() {
    // Unknown projection tag.
    let mut fx = fixture("corrupt-tag");
    drive_committed(&mut fx);
    fx.store
        .execute_raw_for_test("UPDATE attempt_projection SET state='bogus'")
        .unwrap();
    match assemble(&mut fx.store, fx.att.attempt_id) {
        Err(DossierError::Store(StoreError::Corrupt(msg))) => {
            assert!(msg.contains("bogus"), "{msg}");
        }
        other => panic!("expected typed corrupt error, got {other:?}"),
    }
    drop(fx);

    // Corrupt hex in a ledger identity column.
    let mut fx = fixture("corrupt-hex");
    drive_committed(&mut fx);
    fx.store
        .execute_raw_for_test("UPDATE dispatch SET id='zz'")
        .unwrap();
    match assemble(&mut fx.store, fx.att.attempt_id) {
        Err(DossierError::Store(StoreError::Corrupt(_))) => {}
        other => panic!("expected typed corrupt error, got {other:?}"),
    }
    drop(fx);

    // A terminal state whose ledger record is missing.
    let mut fx = fixture("missing-record");
    drive_committed(&mut fx);
    fx.store
        .execute_raw_for_test("DELETE FROM commitment")
        .unwrap();
    match assemble(&mut fx.store, fx.att.attempt_id) {
        Err(DossierError::MissingRecord {
            expected: "commitment",
        }) => {}
        other => panic!("expected MissingRecord, got {other:?}"),
    }
    drop(fx);

    // A partial reliance-refusal subject is corrupt, not defaulted.
    let mut fx = fixture("partial-subject");
    drive_committed(&mut fx);
    fx.store
        .execute_raw_for_test("UPDATE reliance_refusal SET consumer=NULL")
        .unwrap();
    match assemble(&mut fx.store, fx.att.attempt_id) {
        Err(DossierError::Store(StoreError::Corrupt(msg))) => {
            assert!(msg.contains("subject"), "{msg}");
        }
        other => panic!("expected typed corrupt error, got {other:?}"),
    }
}
