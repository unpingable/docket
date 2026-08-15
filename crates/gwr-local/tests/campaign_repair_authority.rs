//! Structural retirement of the former campaign-stage repair-authority API.
//!
//! Historical artifact integrity is covered by `campaign_export` tests.
//! These executable boundaries prove that no current CLI verb recreates the
//! old proposal, adjudication, export, or verification office.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;

fn docket(args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_docket"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status,
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn retired(args: &[&str]) {
    let (status, stdout, stderr) = docket(args);
    assert!(
        !status.success(),
        "retired command unexpectedly succeeded: {stdout}"
    );
    assert!(
        stderr.contains("LegacyRepairRouteRetired"),
        "retirement refusal missing for {args:?}: {stderr}"
    );
}

#[test]
fn cli_cannot_propose_either_historical_repair_stage_class() {
    retired(&[
        "campaign",
        "propose-stage",
        "--class",
        "records_repair_stage",
    ]);
    retired(&[
        "campaign",
        "propose-stage",
        "--class",
        "existing_source_scope_repair_stage",
    ]);
}

#[test]
fn cli_cannot_adjudicate_a_new_exact_repair() {
    retired(&["campaign", "adjudicate", "--verdict", "exact-repair"]);
}

#[test]
fn cli_cannot_export_or_verify_historical_repair_authority() {
    retired(&["campaign", "export-repair-authority"]);
    retired(&["campaign", "verify-repair-authority"]);
}

#[test]
fn help_labels_historical_verbs_as_retired_and_does_not_offer_exact_repair() {
    let (status, stdout, stderr) = docket(&["--help"]);
    assert!(status.success(), "help failed: {stderr}");
    assert!(stdout.contains("export-repair-authority   Retired"));
    assert!(stdout.contains("verify-repair-authority   Retired"));
    assert!(stdout.contains("campaign adjudicate       Record a verdict (continue|refuse)"));
    assert!(!stdout.contains("continue|exact-repair|refuse"));
}

fn assert_source_census(source: &str, needle: &str, expected: usize) {
    assert_eq!(
        source.matches(needle).count(),
        expected,
        "load-bearing governed-repair source census changed for {needle:?}"
    );
}

#[test]
fn structural_census_keeps_only_the_two_governed_result_ingresses_and_retired_route_fences() {
    let loop_source = include_str!("../src/governed_loop.rs");
    let repair_source = include_str!("../src/governed_repair.rs");
    let retired_authority = include_str!("../../gwr-core/src/campaign/authority.rs");
    let campaign_service = include_str!("../../gwr-runtime/src/services/campaign.rs");

    // Exactly two executor-result ingresses perform the scope census: the
    // initial attempt result and completion of an already-durable reserved
    // reconciliation round. One governed branch delegates to the sole
    // Store-owned seal operation. A third ingress is an uncensused authority
    // surface and must fail this structural gate.
    assert_source_census(
        loop_source,
        "governed_repair::validate_effect_journal_for_issuance(",
        2,
    );
    assert_source_census(loop_source, "governed_repair::seal_requirement(", 1);
    assert_source_census(
        repair_source,
        "governed-repair-blocked-effect-was-performed",
        1,
    );
    assert_source_census(
        repair_source,
        "transaction_with_behavior(TransactionBehavior::Immediate)",
        1,
    );

    // Historical campaign-stage repair records remain decodable, but their
    // constructor and adjudication route remain structurally non-production.
    assert_source_census(
        retired_authority,
        "Err(CampaignRefusal::LegacyRepairRouteRetired)",
        3,
    );
    assert_source_census(
        campaign_service,
        "if verdict == AdjudicationVerdict::ExactRepair",
        1,
    );
    assert_source_census(
        campaign_service,
        "Err(CampaignRefusal::LegacyRepairRouteRetired.into())",
        7,
    );
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    fn visit(root: &Path, paths: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, paths);
            } else if path.extension().is_some_and(|value| value == "rs") {
                paths.push(path);
            }
        }
    }

    let mut paths = Vec::new();
    visit(root, &mut paths);
    paths.sort();
    paths
}

fn exact_symbol_files(roots: &[(&Path, &str)], symbol: &str, expected: &[&str]) {
    let actual = roots
        .iter()
        .flat_map(|(root, prefix)| {
            rust_sources(root).into_iter().filter_map(move |path| {
                fs::read_to_string(&path)
                    .unwrap()
                    .contains(symbol)
                    .then(|| format!("{prefix}/{}", path.strip_prefix(root).unwrap().display()))
            })
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<BTreeSet<_>>(),
        "consequence-bearing call-edge census changed for {symbol:?}"
    );
}

fn exact_symbol_occurrences(roots: &[(&Path, &str)], symbol: &str, expected: usize) {
    let actual = roots
        .iter()
        .flat_map(|(root, _)| rust_sources(root))
        .map(|path| fs::read_to_string(path).unwrap().matches(symbol).count())
        .sum::<usize>();
    assert_eq!(
        actual, expected,
        "consequence-bearing call-edge count changed for {symbol:?}"
    );
}

fn service_public_functions(root: &Path) -> BTreeSet<String> {
    rust_sources(root)
        .into_iter()
        .flat_map(|path| {
            let relative = path.strip_prefix(root).unwrap().display().to_string();
            fs::read_to_string(path)
                .unwrap()
                .lines()
                .filter_map(|line| line.strip_prefix("pub fn "))
                .map(move |line| {
                    let name = line.split(['(', '<']).next().unwrap();
                    format!("{relative}:{name}")
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn store_port_methods(source: &str) -> BTreeSet<String> {
    let body = source
        .split_once("pub trait Store {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    body.lines()
        .filter_map(|line| line.trim_start().strip_prefix("fn "))
        .map(|line| line.split(['(', '<']).next().unwrap().to_owned())
        .collect()
}

fn inherent_public_functions(source: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter_map(|line| line.strip_prefix("    pub fn "))
        .map(|line| line.split(['(', '<']).next().unwrap().to_owned())
        .collect()
}

fn metadata() -> serde_json::Value {
    let output = Command::new(env!("CARGO"))
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "metadata",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn cargo_targets_exports_and_intake_versions_match_the_closed_custody_surface() {
    let metadata = metadata();
    let packages = metadata["packages"].as_array().unwrap();
    let package = packages
        .iter()
        .find(|package| package["name"] == "gwr-local")
        .unwrap();
    let actual = package["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|target| {
            format!(
                "{}:{}",
                target["kind"][0].as_str().unwrap(),
                target["name"].as_str().unwrap()
            )
        })
        .collect::<BTreeSet<_>>();
    let expected = [
        "bin:docket",
        "bin:gwr-git-broker",
        "lib:gwr_local",
        "test:broker_path_authorization",
        "test:campaign_burn_concurrency",
        "test:campaign_repair_authority",
        "test:campaign_stage_standing",
        "test:cli_help",
        "test:dossier",
        "test:effect_class",
        "test:empty_observation_plan",
        "test:failure_injection",
        "test:git_broker",
        "test:governed_reconciliation_singleflight",
        "test:nq_c1_repair_specimens",
        "test:persistence",
        "test:provider_contract",
        "test:provider_contract_codex",
        "test:ratification",
        "test:read_surface",
        "test:ref_custody_boundary",
        "test:reservation",
        "test:token_canonicality",
        "test:vertical_slice",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert!(package["features"].as_object().unwrap().is_empty());

    // Inventory every workspace target, not only gwr-local. A newly added
    // binary/example/bench in another member must not become an unnoticed
    // consequence-bearing V1 intake.
    let workspace_targets = packages
        .iter()
        .map(|package| {
            let name = package["name"].as_str().unwrap().to_owned();
            let targets = package["targets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|target| {
                    format!(
                        "{}:{}",
                        target["kind"][0].as_str().unwrap(),
                        target["name"].as_str().unwrap()
                    )
                })
                .collect::<BTreeSet<_>>();
            (name, targets)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let expected_workspace_targets = [
        (
            "gwr-core".to_owned(),
            [
                "lib:gwr_core",
                "test:bridges",
                "test:observation_cannot_rewrite_outcome",
                "test:recovery_binding",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        ),
        ("gwr-local".to_owned(), expected),
        (
            "gwr-runtime".to_owned(),
            ["lib:gwr_runtime"].into_iter().map(str::to_owned).collect(),
        ),
    ]
    .into_iter()
    .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(workspace_targets, expected_workspace_targets);
    for package in packages {
        assert!(package["features"].as_object().unwrap().is_empty());
    }

    let local_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let local_lib = fs::read_to_string(local_root.join("src/lib.rs")).unwrap();
    let actual_exports = local_lib
        .lines()
        .filter_map(|line| line.strip_prefix("pub mod "))
        .map(|line| line.trim_end_matches(';').to_owned())
        .collect::<BTreeSet<_>>();
    let expected_exports = [
        "adapters",
        "broker",
        "campaign_export",
        "capabilities",
        "governed_loop",
        "governed_repair",
        "observe",
        "providers",
        "recover",
        "store",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(actual_exports, expected_exports);

    let runtime_services =
        fs::read_to_string(local_root.join("../gwr-runtime/src/services/mod.rs")).unwrap();
    assert!(!runtime_services.contains("authz_standing"));
    let store_port =
        fs::read_to_string(local_root.join("../gwr-runtime/src/ports/store.rs")).unwrap();
    assert!(!store_port.contains("fn record_authz_issuance("));
    assert!(!store_port.contains("fn create_upstream_standing_grant("));

    assert_eq!(
        service_public_functions(&local_root.join("../gwr-runtime/src/services")),
        [
            "authz_request.rs:assemble",
            "authz_request.rs:render_json",
            "authz_request.rs:render_text",
            "campaign.rs:adjudicate",
            "campaign.rs:admit",
            "campaign.rs:consume",
            "campaign.rs:export_repair_authority",
            "campaign.rs:propose_stage",
            "campaign.rs:record_effect_completed",
            "campaign.rs:record_receipt",
            "campaign.rs:verify_repair_authority",
            "dispatch.rs:dispatch",
            "dossier.rs:assemble",
            "dossier.rs:render_json",
            "dossier.rs:render_text",
            "dossier.rs:state_tag",
            "journal.rs:expectation",
            "journal.rs:inspect",
            "journal.rs:render_journal_json",
            "journal.rs:render_journal_text",
            "list.rs:assemble_list",
            "list.rs:assemble_summary",
            "list.rs:render_list_json",
            "list.rs:render_list_text",
            "preparation.rs:run_preparation",
            "ratification.rs:ratify",
            "reconcile.rs:reconcile",
            "recovery.rs:resolve",
            "reliance.rs:rely_review_queue",
            "reservation.rs:reserve",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        "the complete public runtime-service operation inventory changed"
    );
    assert_eq!(
        store_port_methods(&store_port),
        [
            "register_repository",
            "add_repository_alias",
            "get_repository",
            "find_repository_by_path",
            "bind_work_request_repository",
            "create_work_request",
            "get_work_request",
            "create_preparation_run",
            "get_preparation_run",
            "end_preparation_run",
            "ingest_candidate",
            "get_candidate",
            "admit_attempt",
            "get_attempt",
            "ensure_attempt_consequence_eligible",
            "find_attempt_dispatch",
            "find_dispatch_attempt",
            "get_dispatch_envelope",
            "create_standing_grant",
            "get_authz_issuance",
            "find_attempt_issuance",
            "get_grant_authorization",
            "get_standing_grant",
            "create_reservation",
            "get_reservation",
            "record_ratification",
            "record_reserved",
            "record_dispatch",
            "record_commitment",
            "record_dispatch_refusal",
            "record_indeterminate",
            "record_recovery_resolution",
            "record_recovery_fact",
            "get_recovery_fact",
            "record_observation",
            "get_observations",
            "get_commitment",
            "get_indeterminate",
            "find_commitment_owner",
            "record_reliance_admission",
            "record_reliance_refusal",
            "create_residual_obligation",
            "get_residual_obligations",
            "record_reconciliation",
            "timeline",
            "list_attempts",
            "get_ratification",
            "get_standing_use",
            "get_dispatch_refusal",
            "get_recovery_facts",
            "get_recovery_resolution",
            "get_reliance_admissions",
            "get_reliance_refusals",
            "get_reconciliation",
            "record_campaign_proposal",
            "get_campaign_proposal",
            "find_campaign_proposals",
            "record_campaign_standing",
            "get_campaign_standing",
            "latest_campaign_standing",
            "record_campaign_consumption",
            "burn_campaign_standing",
            "get_campaign_consumption",
            "mark_campaign_effect_completed",
            "record_campaign_receipt",
            "campaign_stage_receipts",
            "record_campaign_adjudication",
            "get_campaign_adjudications",
            "find_campaign_adjudication",
            "get_campaign_adjudication",
            "find_campaign_consumptions_by_receipt",
            "get_campaign_residuals",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        "the complete public persistence-port inventory changed"
    );

    let store_source = fs::read_to_string(local_root.join("src/store/mod.rs")).unwrap();
    assert_eq!(
        inherent_public_functions(&store_source),
        ["open", "open_in_memory"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "the concrete Store public constructor/test surface changed"
    );

    let local_src = local_root.join("src");
    let runtime_src = local_root.join("../gwr-runtime/src");
    let roots = [
        (local_src.as_path(), "gwr-local"),
        (runtime_src.as_path(), "gwr-runtime"),
    ];
    exact_symbol_files(
        &roots,
        "verify_signed_issuance(",
        &["gwr-local/governed_loop.rs"],
    );
    exact_symbol_files(
        &roots,
        "accept_with_checkpoint_verifier(",
        &["gwr-local/bin/docket.rs", "gwr-local/governed_loop.rs"],
    );
    exact_symbol_files(
        &roots,
        "create_standing_grant(",
        &[
            "gwr-local/bin/docket.rs",
            "gwr-local/store/mod.rs",
            "gwr-runtime/ports/store.rs",
        ],
    );
    exact_symbol_files(
        &roots,
        "ensure_attempt_consequence_eligible(",
        &[
            "gwr-local/store/mod.rs",
            "gwr-runtime/ports/store.rs",
            "gwr-runtime/services/dispatch.rs",
        ],
    );
    exact_symbol_files(
        &roots,
        "record_dispatch(",
        &[
            "gwr-local/store/mod.rs",
            "gwr-runtime/ports/store.rs",
            "gwr-runtime/services/dispatch.rs",
        ],
    );
    for (symbol, count) in [
        ("register_repository(", 3),
        ("add_repository_alias(", 4),
        ("bind_work_request_repository(", 3),
        ("create_work_request(", 3),
        ("create_preparation_run(", 3),
        ("end_preparation_run(", 8),
        ("ingest_candidate(", 3),
        ("admit_attempt(", 3),
        ("ensure_attempt_consequence_eligible(", 3),
        ("create_standing_grant(", 3),
        ("create_reservation(", 3),
        ("record_ratification(", 3),
        ("record_reserved(", 3),
        ("record_dispatch(", 3),
        ("record_commitment(", 3),
        ("record_dispatch_refusal(", 3),
        ("record_indeterminate(", 7),
        ("record_recovery_resolution(", 3),
        ("record_recovery_fact(", 3),
        ("record_observation(", 3),
        ("record_reliance_admission(", 3),
        ("record_reliance_refusal(", 3),
        ("create_residual_obligation(", 3),
        ("record_reconciliation(", 3),
        ("record_campaign_proposal(", 3),
        ("record_campaign_standing(", 3),
        ("record_campaign_consumption(", 2),
        ("burn_campaign_standing(", 3),
        ("mark_campaign_effect_completed(", 3),
        ("record_campaign_receipt(", 3),
        ("record_campaign_adjudication(", 3),
    ] {
        exact_symbol_occurrences(&roots, symbol, count);
    }
    let dispatch =
        fs::read_to_string(local_root.join("../gwr-runtime/src/services/dispatch.rs")).unwrap();
    let eligibility = dispatch
        .find("store.ensure_attempt_consequence_eligible(")
        .unwrap();
    assert!(eligibility < dispatch.find("store.find_attempt_dispatch(").unwrap());
    assert!(eligibility < dispatch.find("broker,").unwrap());
    assert_eq!(
        store_source
            .matches("refuse_retired_upstream_attempt(")
            .count(),
        10
    );

    for source_root in [
        local_root.join("src"),
        local_root.join("../gwr-core/src"),
        local_root.join("../gwr-runtime/src"),
    ] {
        for path in rust_sources(&source_root) {
            let source = fs::read_to_string(&path).unwrap();
            for retired in [
                "ag.docket-issuance:v1",
                "authz_intake",
                "authz_standing",
                "mint_from_issuance",
                "create_upstream_standing_grant",
                "record_authz_issuance",
            ] {
                assert!(
                    !source.contains(retired),
                    "retired V1 intake {retired:?} remains in {}",
                    path.display()
                );
            }
        }
    }

    let docket = fs::read_to_string(local_root.join("src/bin/docket.rs")).unwrap();
    assert!(!docket.contains("[\"authz\", \"accept\"]"));
    assert!(docket.contains("[\"governed-loop\", \"accept\"]"));
    let broker = fs::read_to_string(local_root.join("src/bin/gwr-git-broker.rs")).unwrap();
    assert!(!broker.contains("governed_loop"));
    let governed = fs::read_to_string(local_root.join("src/governed_loop.rs")).unwrap();
    assert!(governed.contains(
        "pub const SIGNED_ISSUANCE_SCHEMA_V2: &str = \"ag.governed-loop.signed-issuance/v2\""
    ));
    assert!(governed
        .contains("pub const AG_ISSUANCE_SCHEMA_V2: &str = \"ag.governed-loop.issuance/v2\""));
    let public_governed_functions = governed
        .lines()
        .filter_map(|line| line.strip_prefix("pub fn "))
        .map(|line| line.split_once('(').unwrap().0.to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        public_governed_functions,
        [
            "accept",
            "accept_with_checkpoint_verifier",
            "observe_issuance_with_checkpoint_verifier",
            "reconcile_signed_round_with_checkpoint_verifier",
            "strict_json<T: DeserializeOwned>",
            "verify_signed_issuance",
            "verify_signed_reconciliation_round_request",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}

#[test]
fn downstream_cannot_import_retired_v1_intake_or_standing_minter() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "docket-r3-retired-v1-boundary-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("src")).unwrap();
    let local = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname='docket-r3-retired-v1-boundary'\nversion='0.0.0'\nedition='2021'\n\n[dependencies]\ngwr-local={{path={:?}}}\ngwr-runtime={{path={:?}}}\n",
            local.display().to_string(),
            local.join("../gwr-runtime").display().to_string(),
        ),
    )
    .unwrap();
    fs::write(
        root.join("src/main.rs"),
        "use gwr_local::authz_intake::verify_issuance;\nuse gwr_runtime::services::authz_standing::mint_from_issuance;\nfn main() { let _ = verify_issuance; let _ = mint_from_issuance; }\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO"))
        .current_dir(&root)
        .env("CARGO_TARGET_DIR", root.join("target"))
        .args(["check", "--offline", "--quiet"])
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(&root);
    assert!(!output.status.success());
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostic.contains("could not find `authz_intake` in `gwr_local`"));
    assert!(diagnostic.contains("could not find `authz_standing` in `services`"));
}

#[test]
fn cli_refuses_retired_v1_accept_command_without_opening_state() {
    let (status, stdout, stderr) = docket(&["authz", "accept"]);
    assert!(!status.success(), "retired command succeeded: {stdout}");
    assert!(stderr.contains("unknown command"));
}

#[test]
fn historical_v1_row_remains_readable_but_has_no_write_or_mint_surface() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "docket-r3-historical-v1-row-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    drop(SqliteStore::open(&database).unwrap());
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute(
            "INSERT INTO authz_issuance
             (issuance_id, attempt, decision_id, issuer_principal, issuer_key_id,
              target_id, request_raw_sha256, request_upstream_digest, prepared_digest,
              requested_actor, issued_at, expires_at, premise_kinds, premise_statements,
              residual_status, residual_items, consumption_ledger, consumption_use_digest,
              body_b64, accepted_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
            rusqlite::params![
                "sha256:historical-v1",
                "00000000000000000000000000000001",
                "sha256:decision",
                "historical-principal",
                "historical-key",
                "historical-target",
                "sha256:request",
                "sha256:upstream-request",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "historical-actor",
                1_i64,
                2_i64,
                "",
                "",
                "none_recorded",
                "",
                "historical-ledger",
                "sha256:historical-use",
                "AA",
                1_i64,
            ],
        )
        .unwrap();
    drop(connection);

    let mut store = SqliteStore::open(&database).unwrap();
    let record = store
        .get_authz_issuance("sha256:historical-v1")
        .unwrap()
        .unwrap();
    assert_eq!(record.issuer_principal, "historical-principal");
    assert_eq!(record.body_b64, "AA");
    drop(store);
    let _ = fs::remove_dir_all(&root);
}
