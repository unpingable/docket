//! NQ C1 historical specimens and campaign-stage repair retirement.
//!
//! Fixture success means exact archival bytes decode with their pinned
//! identities. It never means a legacy proposal, adjudication, standing, or
//! repair-authority artifact can become current authority.

use gwr_core::campaign::adjudication::{AdjudicationReceipt, AdjudicationVerdict};
use gwr_core::campaign::authority::RepairAuthorityV1;
use gwr_core::campaign::proposal::{CampaignStageProposal, RepairBasis, RepoPin, StageBasis};
use gwr_core::campaign::standing::{
    CampaignStageStanding, CampaignStandingState, ExecutionContext,
};
use gwr_core::campaign::{
    RepairScopeClass, ReviewRequirement, StageClass, StageEffectClass, WorkerRole,
};
use gwr_core::digest::Sha256Digest;
use gwr_core::refusal::CampaignRefusal;
use gwr_core::work_request::{ClockReading, CommitHash, RepositoryLocator};
use gwr_local::campaign_export;
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::{Store, StoreError};
use gwr_runtime::services::campaign::{self as campaign_svc, CampaignError};
use serde_json::Value;

const REJECTED: &[u8] =
    include_bytes!("../../../conformance/campaign/nq-c1/rejected-candidate.v1.json");
const PRE_SPEND: &[u8] =
    include_bytes!("../../../conformance/campaign/nq-c1/scope-discovery-pre-spend.v1.json");
const POST_SPEND: &[u8] =
    include_bytes!("../../../conformance/campaign/nq-c1/consumed-repair-hard-stop.v1.json");
const ARCHITECTURE: &[u8] =
    include_bytes!("../../../conformance/campaign/nq-c1/architectural-readjudication.v1.json");

const AG_REJECTED_IDENTITY: &str =
    "sha256:52b6d6ef41b8e0c96656cc1250cb0ae67b4d974ea29ddc561f3863e3f8ac8cbb";
const AG_PRE_SPEND_IDENTITY: &str =
    "sha256:d58c797690da977a367b84c56d2cf9e4223f1413fba9e58ae68c009a2541f6ac";
const AG_POST_SPEND_IDENTITY: &str =
    "sha256:1a04b287380d6082d5d13c97bc74f8f1ffca5c527c1e3d550817409bc59e4973";
const AG_ARCHITECTURE_IDENTITY: &str =
    "sha256:54e7ffa237b5df4f0606c8073e7ae6f60178406c1604761089ad845082242909";

fn fixture(bytes: &[u8], expected: &str) -> Value {
    assert!(bytes.ends_with(b"\n"));
    assert!(!bytes[..bytes.len() - 1].ends_with(b"\n"));
    assert_eq!(
        format!("sha256:{}", Sha256Digest::of_bytes(bytes).to_hex()),
        expected
    );
    let body = &bytes[..bytes.len() - 1];
    let value: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(serde_json::to_vec(&value).unwrap(), body);
    assert_eq!(value["authority_use"], "historical_evidence_only");
    value
}

fn paths(value: &Value) -> Vec<String> {
    value["authorized_paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap().to_owned())
        .collect()
}

fn pin(rejected: &Value) -> RepoPin {
    RepoPin {
        repository: RepositoryLocator::new("nq://local/immutable-rejected-candidate"),
        commit: CommitHash::new(rejected["candidate_commit"].as_str().unwrap()),
        tree: rejected["candidate_tree"].as_str().unwrap().to_owned(),
    }
}

fn operator_proposal(
    rejected: &Value,
    upstream: &str,
    allowed_paths: Vec<String>,
) -> CampaignStageProposal {
    CampaignStageProposal::propose(
        upstream.to_owned(),
        "nq-c1-boundary-conformance".into(),
        "historical-source-occurrence".into(),
        StageClass::OperatorStage,
        WorkerRole::Operator,
        StageEffectClass::WorkspaceMutation,
        StageBasis::RootAuthorization {
            identity: "synthetic-conformance-root-not-historical-authority".into(),
        },
        vec![pin(rejected)],
        allowed_paths,
        "nq-c1-immutable-specimens/v1".into(),
        "nq-c1-boundary-result/v1".into(),
        ClockReading(20_000),
        "synthetic-original-occurrence".into(),
        String::new(),
        ReviewRequirement::Required,
        vec!["does-not-claim-historical-docket-governance".into()],
        None,
        ClockReading(1_000),
    )
    .unwrap()
}

fn archived_repair_proposal(rejected: &Value, allowed_paths: Vec<String>) -> CampaignStageProposal {
    let mut archived = operator_proposal(rejected, AG_PRE_SPEND_IDENTITY, allowed_paths);
    archived.stage = "historical-source-occurrence-repair".into();
    archived.stage_class = StageClass::ExistingSourceScopeRepairStage;
    archived.role = WorkerRole::Repair;
    archived.effect_class = StageEffectClass::WorkspaceMutation;
    archived.basis = StageBasis::PredecessorStage {
        stage: "historical-source-occurrence".into(),
        adjudication_digest: Sha256Digest::of_bytes(b"historical-adjudication"),
    };
    archived.repair = Some(RepairBasis {
        original_stage: "historical-source-occurrence".into(),
        rejected_review_receipt: Sha256Digest::of_bytes(b"historical-review"),
        finding_ids: vec!["D01".into()],
        scope_class: RepairScopeClass::ExistingSourceScope,
        nonclaims: vec!["historical-only".into()],
        review_requirement: ReviewRequirement::Required,
    });
    archived.digest = archived.recompute_digest();
    archived
}

fn archived_bundle() -> RepairAuthorityV1 {
    let mut archived = RepairAuthorityV1 {
        digest: Sha256Digest::from_bytes([0; 32]),
        campaign: "historical-campaign".into(),
        repair_stage: "historical-repair".into(),
        role: WorkerRole::Repair,
        stage_class: StageClass::RecordsRepairStage,
        effect_class: StageEffectClass::RecordsOnly,
        standing: Sha256Digest::of_bytes(b"standing"),
        proposal_digest: Sha256Digest::of_bytes(b"proposal"),
        consumption: Some(Sha256Digest::of_bytes(b"consumption")),
        original_stage: "original-stage".into(),
        original_proposal_digest: Sha256Digest::of_bytes(b"original-proposal"),
        original_standing: Sha256Digest::of_bytes(b"original-standing"),
        original_consumption: Sha256Digest::of_bytes(b"original-consumption"),
        rejected_review_receipt: Sha256Digest::of_bytes(b"review"),
        adjudication: Sha256Digest::of_bytes(b"adjudication"),
        adjudication_verdict: AdjudicationVerdict::ExactRepair,
        finding_ids: vec!["D01".into()],
        scope_class: RepairScopeClass::RecordsOnly,
        repositories: vec![RepoPin {
            repository: RepositoryLocator::new("/historical/repo"),
            commit: CommitHash::new("72cb3b323fa286cd212378eadae4a42fe4dc093e"),
            tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
        }],
        allowed_paths: vec!["docs/history.md".into()],
        expires_at: ClockReading(10_000),
        nonce: "historical-nonce".into(),
        nonclaims: vec!["not-current-authority".into()],
        verifier: "historical-verifier".into(),
    };
    archived.digest = archived.recompute_digest();
    archived
}

#[test]
fn exact_fixture_bytes_are_pinned_and_ag_identities_remain_opaque() {
    for (bytes, exact, ag_identity) in [
        (
            REJECTED,
            "sha256:6f72de0980d193daa01c420ff89e381aac81e53ed5605d3b51405620bf3fde45",
            AG_REJECTED_IDENTITY,
        ),
        (
            PRE_SPEND,
            "sha256:c4071eb72f7c80b97c7eb7b9b1abafeaeea515241f5901df43e521806ada443f",
            AG_PRE_SPEND_IDENTITY,
        ),
        (
            POST_SPEND,
            "sha256:29fbc178281f9a9256f89def4c904ea124251979ee39a9aad965a4d68ecefedf",
            AG_POST_SPEND_IDENTITY,
        ),
        (
            ARCHITECTURE,
            "sha256:f886416da38cf10a1243f2c1fe8635ff3bce6db28c2ae1a0e1e7c18f7087d8c0",
            AG_ARCHITECTURE_IDENTITY,
        ),
    ] {
        fixture(bytes, exact);
        assert_ne!(exact, ag_identity);
    }
}

#[test]
fn immutable_specimens_preserve_hard_stops_without_minting_authority() {
    let before = fixture(
        PRE_SPEND,
        "sha256:c4071eb72f7c80b97c7eb7b9b1abafeaeea515241f5901df43e521806ada443f",
    );
    assert_eq!(before["authorization_consumed"], false);
    assert_eq!(before["source_mutation_attempted"], false);
    assert_eq!(before["authorized_path_count"], 28);

    let after = fixture(
        POST_SPEND,
        "sha256:29fbc178281f9a9256f89def4c904ea124251979ee39a9aad965a4d68ecefedf",
    );
    assert_eq!(after["authorization_consumed"], true);
    assert_eq!(after["authorization_reusable"], false);
    assert_eq!(after["authorization_consumed_at"], "2026-08-13T03:26:17Z");
    assert_eq!(
        after["checkpoint_commit"],
        "e9a3d371308562b6c8571215bfba95cfd4ccbc45"
    );
    assert_eq!(
        after["checkpoint_tree"],
        "6026c2ef51b156e81079085ef71711309a3416d9"
    );

    let architecture = fixture(
        ARCHITECTURE,
        "sha256:f886416da38cf10a1243f2c1fe8635ff3bce6db28c2ae1a0e1e7c18f7087d8c0",
    );
    assert_eq!(architecture["architecture_required"], true);
    assert_eq!(architecture["existing_source_scope_admissible"], false);
    assert_eq!(architecture["core_path_count"], 32);
    assert_eq!(architecture["diagnostic_reference_count"], 945);
    assert_eq!(architecture["diagnostic_file_count"], 33);
    assert_eq!(architecture["overlap_path_count"], 10);
    assert_eq!(architecture["additional_diagnostic_path_count"], 23);
}

#[test]
fn public_core_apis_cannot_recreate_campaign_stage_repair_authority() {
    let rejected = fixture(
        REJECTED,
        "sha256:6f72de0980d193daa01c420ff89e381aac81e53ed5605d3b51405620bf3fde45",
    );
    let before = fixture(
        PRE_SPEND,
        "sha256:c4071eb72f7c80b97c7eb7b9b1abafeaeea515241f5901df43e521806ada443f",
    );
    for tag in ["records_repair_stage", "existing_source_scope_repair_stage"] {
        assert_eq!(
            StageClass::admit_tag(tag),
            Err(CampaignRefusal::LegacyRepairRouteRetired)
        );
    }

    let archived = archived_repair_proposal(&rejected, paths(&before));
    assert_eq!(
        CampaignStageProposal::propose(
            archived.upstream_digest.clone(),
            archived.campaign.clone(),
            archived.stage.clone(),
            archived.stage_class,
            archived.role,
            archived.effect_class,
            archived.basis.clone(),
            archived.repositories.clone(),
            archived.allowed_paths.clone(),
            archived.evidence_contract.clone(),
            archived.handoff_schema.clone(),
            archived.expires_at,
            archived.nonce.clone(),
            archived.isolated_worktree.clone(),
            archived.review_requirement,
            archived.nonclaims.clone(),
            archived.repair.clone(),
            archived.proposed_at,
        ),
        Err(CampaignRefusal::LegacyRepairRouteRetired)
    );
    assert_eq!(
        CampaignStageStanding::issue(&archived, ClockReading(2_000)),
        Err(CampaignRefusal::LegacyRepairRouteRetired)
    );
    assert_eq!(
        AdjudicationReceipt::adjudicate(
            "campaign".into(),
            "stage".into(),
            Sha256Digest::of_bytes(b"review"),
            AdjudicationVerdict::ExactRepair,
            "adjudicator".into(),
            vec!["D01".into()],
            vec![],
            ClockReading(1),
        ),
        Err(CampaignRefusal::LegacyRepairRouteRetired)
    );

    let bundle = archived_bundle();
    assert!(matches!(
        RepairAuthorityV1::issue(
            bundle.campaign.clone(),
            bundle.repair_stage.clone(),
            bundle.role,
            bundle.stage_class,
            bundle.effect_class,
            bundle.standing,
            bundle.proposal_digest,
            bundle.consumption,
            bundle.original_stage.clone(),
            bundle.original_proposal_digest,
            bundle.original_standing,
            bundle.original_consumption,
            bundle.rejected_review_receipt,
            bundle.adjudication,
            bundle.adjudication_verdict,
            bundle.finding_ids.clone(),
            bundle.scope_class,
            bundle.repositories.clone(),
            bundle.allowed_paths.clone(),
            bundle.expires_at,
            bundle.nonce.clone(),
            bundle.nonclaims.clone(),
            bundle.verifier.clone(),
        ),
        Err(CampaignRefusal::LegacyRepairRouteRetired)
    ));

    let historical_standing = CampaignStageStanding::from_persisted(
        Sha256Digest::of_bytes(b"historical-standing"),
        archived.digest,
        archived.upstream_digest.clone(),
        archived.campaign.clone(),
        archived.stage.clone(),
        archived.stage_class,
        archived.role,
        archived.effect_class,
        archived.repositories.clone(),
        archived.allowed_paths.clone(),
        archived.expires_at,
        archived.nonce.clone(),
        ClockReading(2_000),
        CampaignStandingState::Available,
    );
    let context = ExecutionContext {
        campaign: archived.campaign,
        stage: archived.stage,
        role: archived.role,
        proposal_digest: archived.digest,
    };
    assert_eq!(
        historical_standing.consume(&context, ClockReading(3_000)),
        Err(CampaignRefusal::LegacyRepairRouteRetired)
    );
}

#[test]
fn runtime_services_refuse_legacy_values_before_mutation() {
    let rejected = fixture(
        REJECTED,
        "sha256:6f72de0980d193daa01c420ff89e381aac81e53ed5605d3b51405620bf3fde45",
    );
    let before = fixture(
        PRE_SPEND,
        "sha256:c4071eb72f7c80b97c7eb7b9b1abafeaeea515241f5901df43e521806ada443f",
    );
    let archived = archived_repair_proposal(&rejected, paths(&before));
    let mut store = SqliteStore::open_in_memory().unwrap();
    assert_eq!(
        campaign_svc::propose_stage(&mut store, &archived),
        Err(CampaignError::Refusal(
            CampaignRefusal::LegacyRepairRouteRetired
        ))
    );
    assert_eq!(
        store.record_campaign_proposal(&archived),
        Err(StoreError::LegacyCampaignRepairRouteRetired)
    );
    assert!(store
        .get_campaign_proposal(&archived.digest)
        .unwrap()
        .is_none());

    let archived_adjudication = AdjudicationReceipt {
        digest: Sha256Digest::of_bytes(b"historical-adjudication"),
        campaign: "campaign".into(),
        stage: "stage".into(),
        review_receipt: Sha256Digest::of_bytes(b"review"),
        verdict: AdjudicationVerdict::ExactRepair,
        adjudicator: "historical-adjudicator".into(),
        findings: vec![],
        residuals: vec![],
        adjudicated_at: ClockReading(1),
    };
    assert_eq!(
        store.record_campaign_adjudication(&archived_adjudication),
        Err(StoreError::LegacyCampaignRepairRouteRetired)
    );
    assert!(store
        .get_campaign_adjudication(&archived_adjudication.digest)
        .unwrap()
        .is_none());
    assert_eq!(
        campaign_svc::adjudicate(
            &mut store,
            "campaign",
            "stage",
            &Sha256Digest::of_bytes(b"review"),
            AdjudicationVerdict::ExactRepair,
            "adjudicator",
            vec![],
            vec![],
            ClockReading(1),
        ),
        Err(CampaignError::Refusal(
            CampaignRefusal::LegacyRepairRouteRetired
        ))
    );
    assert_eq!(
        campaign_svc::export_repair_authority(
            &mut store,
            &Sha256Digest::of_bytes(b"standing"),
            ClockReading(1),
            "verifier",
        ),
        Err(CampaignError::Refusal(
            CampaignRefusal::LegacyRepairRouteRetired
        ))
    );
    assert_eq!(
        campaign_svc::verify_repair_authority(
            &mut store,
            &archived_bundle(),
            ClockReading(1),
            "verifier",
        ),
        Err(CampaignError::Refusal(
            CampaignRefusal::LegacyRepairRouteRetired
        ))
    );
}

#[test]
fn historical_artifact_codec_checks_integrity_but_cannot_validate_authority() {
    let bundle = archived_bundle();
    let raw = campaign_export::render(&bundle);
    assert_eq!(campaign_export::parse(&raw).unwrap(), bundle);
    assert!(campaign_export::parse(&raw.replacen("docs/history.md", "docs/other.md", 1)).is_err());

    let mut store = SqliteStore::open_in_memory().unwrap();
    assert_eq!(
        campaign_svc::verify_repair_authority(
            &mut store,
            &campaign_export::parse(&raw).unwrap(),
            ClockReading(1),
            "verifier",
        ),
        Err(CampaignError::Refusal(
            CampaignRefusal::LegacyRepairRouteRetired
        ))
    );
}

#[test]
fn ordinary_operator_campaign_stage_remains_live() {
    let rejected = fixture(
        REJECTED,
        "sha256:6f72de0980d193daa01c420ff89e381aac81e53ed5605d3b51405620bf3fde45",
    );
    let before = fixture(
        PRE_SPEND,
        "sha256:c4071eb72f7c80b97c7eb7b9b1abafeaeea515241f5901df43e521806ada443f",
    );
    let proposal = operator_proposal(&rejected, AG_PRE_SPEND_IDENTITY, paths(&before));
    let mut store = SqliteStore::open_in_memory().unwrap();
    assert_eq!(
        campaign_svc::propose_stage(&mut store, &proposal).unwrap(),
        proposal.digest
    );
    let standing = campaign_svc::admit(&mut store, &proposal.digest, ClockReading(2_000)).unwrap();
    let context = ExecutionContext {
        campaign: standing.campaign().to_owned(),
        stage: standing.stage().to_owned(),
        role: standing.role(),
        proposal_digest: standing.proposal_digest(),
    };
    campaign_svc::consume(
        &mut store,
        &standing.digest(),
        &context,
        ClockReading(3_000),
    )
    .unwrap();
}
