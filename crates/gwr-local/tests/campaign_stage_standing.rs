//! Current campaign-stage standing integration.
//!
//! Operator/reviewer stages remain live. The former campaign-stage repair
//! classes and exact-repair adjudication remain decode-only history and are
//! structurally refused before persistence, issuance, or consumption.

use gwr_core::campaign::adjudication::AdjudicationVerdict;
use gwr_core::campaign::proposal::{CampaignStageProposal, RepairBasis, RepoPin, StageBasis};
use gwr_core::campaign::standing::{classify, ConsumptionState, ExecutionContext};
use gwr_core::campaign::{
    RepairScopeClass, ReviewRequirement, StageClass, StageEffectClass, WorkerRole,
};
use gwr_core::digest::Sha256Digest;
use gwr_core::refusal::CampaignRefusal;
use gwr_core::work_request::{ClockReading, CommitHash, RepositoryLocator};
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::campaign::{self as svc, CampaignError};

const COMMIT: &str = "72cb3b323fa286cd212378eadae4a42fe4dc093e";
const TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

fn proposal(class: StageClass, stage: &str, nonce: &str) -> CampaignStageProposal {
    CampaignStageProposal::propose(
        format!("upstream-{nonce}"),
        "campaign-1".into(),
        stage.into(),
        class,
        class.required_role(),
        class.required_effect_class(),
        StageBasis::RootAuthorization {
            identity: "root-authorization-1".into(),
        },
        vec![RepoPin {
            repository: RepositoryLocator::new("/repo"),
            commit: CommitHash::new(COMMIT),
            tree: TREE.into(),
        }],
        vec!["src/lib.rs".into()],
        "evidence-contract-1".into(),
        "handoff-schema-1".into(),
        ClockReading(10_000),
        nonce.into(),
        if class.is_review() {
            "/isolated/reviewer-worktree".into()
        } else {
            String::new()
        },
        ReviewRequirement::Required,
        vec!["does-not-establish-correctness".into()],
        None,
        ClockReading(1_000),
    )
    .unwrap()
}

fn context(standing: &gwr_core::campaign::standing::CampaignStageStanding) -> ExecutionContext {
    ExecutionContext {
        campaign: standing.campaign().into(),
        stage: standing.stage().into(),
        role: standing.role(),
        proposal_digest: standing.proposal_digest(),
    }
}

#[test]
fn operator_stage_is_persisted_admitted_and_burned_once() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let p = proposal(StageClass::OperatorStage, "operator-a", "nonce-a");
    assert_eq!(svc::propose_stage(&mut store, &p).unwrap(), p.digest);
    let standing = svc::admit(&mut store, &p.digest, ClockReading(2_000)).unwrap();
    let ctx = context(&standing);
    let burn = svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_000)).unwrap();
    assert_eq!(burn.standing, standing.digest());
    assert_eq!(
        classify(Some(&burn)),
        ConsumptionState::ConsumedOutcomeUnresolved
    );
    assert!(matches!(
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_001)),
        Err(CampaignError::Refusal(CampaignRefusal::OutcomeUnresolved))
    ));
}

#[test]
fn reviewer_stage_remains_read_only_and_role_bound() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let p = proposal(StageClass::ReviewerStage, "review-a", "nonce-review");
    svc::propose_stage(&mut store, &p).unwrap();
    let standing = svc::admit(&mut store, &p.digest, ClockReading(2_000)).unwrap();
    assert_eq!(standing.effect_class(), StageEffectClass::ReviewReadOnly);
    let mut wrong = context(&standing);
    wrong.role = WorkerRole::Operator;
    assert_eq!(
        svc::consume(&mut store, &standing.digest(), &wrong, ClockReading(3_000)),
        Err(CampaignError::Refusal(CampaignRefusal::RoleMismatch))
    );
    svc::consume(
        &mut store,
        &standing.digest(),
        &context(&standing),
        ClockReading(3_000),
    )
    .unwrap();
}

#[test]
fn current_continue_and_refuse_adjudications_remain_durable() {
    for (index, verdict) in [AdjudicationVerdict::Continue, AdjudicationVerdict::Refuse]
        .into_iter()
        .enumerate()
    {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let stage = format!("operator-{index}");
        let p = proposal(StageClass::OperatorStage, &stage, &format!("nonce-{index}"));
        svc::propose_stage(&mut store, &p).unwrap();
        let standing = svc::admit(&mut store, &p.digest, ClockReading(2_000)).unwrap();
        svc::consume(
            &mut store,
            &standing.digest(),
            &context(&standing),
            ClockReading(3_000),
        )
        .unwrap();
        let review = Sha256Digest::of_bytes(format!("review-{index}").as_bytes());
        svc::record_receipt(&mut store, &standing.digest(), &review).unwrap();
        let receipt = svc::adjudicate(
            &mut store,
            "campaign-1",
            &stage,
            &review,
            verdict,
            "adjudicator-1",
            vec![],
            vec![],
            ClockReading(4_000),
        )
        .unwrap();
        assert_eq!(
            store.get_campaign_adjudication(&receipt.digest).unwrap(),
            Some(receipt)
        );
    }
}

#[test]
fn exact_repair_and_both_repair_stage_classes_are_retired_before_write() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    assert_eq!(
        svc::adjudicate(
            &mut store,
            "campaign-1",
            "stage-a",
            &Sha256Digest::of_bytes(b"review"),
            AdjudicationVerdict::ExactRepair,
            "adjudicator-1",
            vec![],
            vec![],
            ClockReading(4_000),
        ),
        Err(CampaignError::Refusal(
            CampaignRefusal::LegacyRepairRouteRetired
        ))
    );

    for class in [
        StageClass::RecordsRepairStage,
        StageClass::ExistingSourceScopeRepairStage,
    ] {
        assert_eq!(
            StageClass::admit_tag(class.tag()),
            Err(CampaignRefusal::LegacyRepairRouteRetired)
        );
        let attempted = CampaignStageProposal::propose(
            "upstream-repair".into(),
            "campaign-1".into(),
            "repair-a".into(),
            class,
            class.required_role(),
            class.required_effect_class(),
            StageBasis::PredecessorStage {
                stage: "operator-a".into(),
                adjudication_digest: Sha256Digest::of_bytes(b"historical-adjudication"),
            },
            vec![RepoPin {
                repository: RepositoryLocator::new("/repo"),
                commit: CommitHash::new(COMMIT),
                tree: TREE.into(),
            }],
            vec!["src/lib.rs".into()],
            "evidence-contract-1".into(),
            "handoff-schema-1".into(),
            ClockReading(10_000),
            "repair-nonce".into(),
            String::new(),
            ReviewRequirement::Required,
            vec!["historical-only".into()],
            Some(RepairBasis {
                original_stage: "operator-a".into(),
                rejected_review_receipt: Sha256Digest::of_bytes(b"historical-review"),
                finding_ids: vec!["finding-1".into()],
                scope_class: match class {
                    StageClass::RecordsRepairStage => RepairScopeClass::RecordsOnly,
                    StageClass::ExistingSourceScopeRepairStage => {
                        RepairScopeClass::ExistingSourceScope
                    }
                    _ => unreachable!(),
                },
                nonclaims: vec!["historical-only".into()],
                review_requirement: ReviewRequirement::Required,
            }),
            ClockReading(1_000),
        );
        assert_eq!(attempted, Err(CampaignRefusal::LegacyRepairRouteRetired));
    }
}

#[test]
fn noncampaign_stage_classes_still_refuse_by_exact_name() {
    for class in ["new_source_scope", "qualification", "architecture"] {
        assert_eq!(
            StageClass::admit_tag(class),
            Err(CampaignRefusal::StageClassNeverAdmitted {
                class: class.into()
            })
        );
    }
}
