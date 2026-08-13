//! Structural retirement of the former campaign-stage repair-authority API.
//!
//! Historical artifact integrity is covered by `campaign_export` tests.
//! These executable boundaries prove that no current CLI verb recreates the
//! old proposal, adjudication, export, or verification office.

use std::process::Command;

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
fn structural_census_keeps_one_governed_path_and_retired_route_fences() {
    let loop_source = include_str!("../src/governed_loop.rs");
    let repair_source = include_str!("../src/governed_repair.rs");
    let retired_authority = include_str!("../../gwr-core/src/campaign/authority.rs");
    let campaign_service = include_str!("../../gwr-runtime/src/services/campaign.rs");

    // Exactly one executor-result ingress performs the scope census and one
    // governed branch delegates to the sole Store-owned seal operation.
    assert_source_census(
        loop_source,
        "governed_repair::validate_effect_journal_for_issuance(",
        1,
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
