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
