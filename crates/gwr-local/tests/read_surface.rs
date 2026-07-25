//! Stage-2 acceptance (read-surface tranche): the canonical attempt list,
//! lookup by dispatch identity, and verified journal inspection.
//!
//! One canonical value sources each surface's human and JSON renderings; a
//! journal is rendered as evidence only after its bytes hash to the digest
//! the runtime persisted; and every identifier failure is a typed refusal,
//! never a silent selection.

use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::{StandingAct, StandingGrant, StandingScope};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::RecoveryVerdict;
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::preparation::CandidateArtifact;
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryIdentity, WorkRequest};
use gwr_local::adapters::{FixedClock, HashChainIds};
use gwr_local::broker::SubprocessGitBroker;
use gwr_local::capabilities::StandingTokenCodec;
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::dispatch::{dispatch, DispatchOutcome};
use gwr_runtime::services::journal::{inspect, JournalExpectation, JournalStatus};
use gwr_runtime::services::list::{assemble_list, render_list_json, render_list_text};
use gwr_runtime::services::ratification::ratify;
use gwr_runtime::services::recovery::resolve;
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

/// Run the docket CLI against a fixture's state dir; return (exit-zero, output).
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
    let root = std::env::temp_dir().join(format!("gwr-reads-{name}-{}", std::process::id()));
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
    let wr = WorkRequest {
        id: WorkRequestId::from_bytes([1; 16]),
        repository: RepositoryIdentity::new(repo.to_string_lossy()),
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
            allowed_paths: vec!["src/lib.rs".into(), "docs/notes.md".into()],
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

fn drive_committed(fx: &mut Fx) {
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
    gwr_runtime::services::reconcile::reconcile(
        &mut fx.store,
        fx.att.attempt_id,
        &FixedClock(ClockReading(50)),
        &mut fx.ids,
    )
    .unwrap();
}

fn drive_recovered(fx: &mut Fx) {
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
    let mut ids = HashChainIds::new();
    let fact = gwr_local::recover::produce_fact(
        &mut fx.store,
        fx.att.attempt_id,
        &fx.root.join("journals"),
        &FixedClock(ClockReading(60)),
        &mut ids,
    )
    .unwrap();
    let g = grant(fx, 2, StandingAct::ResolveRecovery);
    let mut ev = gwr_local::recover::GitRecoveryEvidence::new(fx.root.join("journals"));
    let r = resolve(
        &mut fx.store,
        fx.att.attempt_id,
        fact.id,
        g.id(),
        ACTOR,
        &mut ev,
        &FixedClock(ClockReading(60)),
        &mut ids,
    )
    .unwrap();
    assert_eq!(r.verdict, RecoveryVerdict::CommittedViaRecovery);
}

fn dispatch_hex(fx: &mut Fx) -> String {
    fx.store
        .find_attempt_dispatch(fx.att.attempt_id)
        .unwrap()
        .unwrap()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn journal_path(fx: &mut Fx) -> PathBuf {
    let hex = dispatch_hex(fx);
    fx.root.join("journals").join(format!("{hex}.journal"))
}

// --- A: the canonical list ---

#[test]
fn list_surfaces_derive_from_one_model_with_scope_and_timestamps() {
    let mut fx = fixture("list");
    drive_committed(&mut fx);

    let rows = assemble_list(&mut fx.store).unwrap();
    assert_eq!(rows.len(), 1);
    let s = &rows[0];
    assert!(s.admitted_at.0 > 0, "timestamp present");
    assert_eq!(s.allowed_paths.len(), 2, "complete scope in the model");
    assert_eq!(s.obligations_outstanding, 1);
    assert!(!s.premise_qualified, "normal settlement is not qualified");

    let text = render_list_text(&rows);
    let json = render_list_json(&rows);
    // Same canonical values on both surfaces.
    for fact in ["committed", "normal", TARGET_REF, "git-ref-update:v1"] {
        assert!(text.contains(fact), "human missing {fact}: {text}");
        assert!(json.contains(fact), "json missing {fact}: {json}");
    }
    assert!(json.contains("\"list_format\":\"gwr:attempt-list:v1\""));
    assert!(json.contains("\"admitted_at_ms\":3"));
    assert!(text.contains("admitted_at_ms 3"));
    // JSON carries complete values; the human table truncates long ones.
    assert!(
        json.contains(fx.att.repository.as_str()),
        "full repository path in JSON"
    );
    assert!(json.contains("docs/notes.md"), "every path in JSON");
    assert!(
        text.contains("src/lib.rs+1"),
        "human scope is concise: {text}"
    );
    assert!(
        !text.contains("docs/notes.md"),
        "human table does not dump every path"
    );
}

#[test]
fn premise_qualified_settlement_is_marked_in_the_list() {
    let mut fx = fixture("list-qualified");
    drive_recovered(&mut fx);

    let rows = assemble_list(&mut fx.store).unwrap();
    assert!(rows[0].premise_qualified);
    let text = render_list_text(&rows);
    let json = render_list_json(&rows);
    assert!(
        text.contains("settlement recovered (premise-qualified)"),
        "{text}"
    );
    assert!(json.contains("\"premise_qualified\":true"), "{json}");
    // And the show surface still carries the full qualification.
    let (ok, out) = docket(
        &fx.root,
        &["show", "--attempt", "09090909090909090909090909090909"],
    );
    assert!(ok, "{out}");
    assert!(out.contains("ExclusiveRefCustody"), "{out}");
}

// --- B: lookup by dispatch identity ---

#[test]
fn dispatch_identity_resolves_and_failures_are_typed() {
    let mut fx = fixture("lookup");
    drive_committed(&mut fx);
    let dsp = dispatch_hex(&mut fx);

    // The pointer in a governed commit subject now resolves.
    let (ok, by_dispatch) = docket(&fx.root, &["show", "--dispatch", &dsp]);
    assert!(ok, "{by_dispatch}");
    let (ok, by_attempt) = docket(
        &fx.root,
        &["show", "--attempt", "09090909090909090909090909090909"],
    );
    assert!(ok, "{by_attempt}");
    assert_eq!(by_dispatch, by_attempt, "one attempt, one dossier");

    // Unknown dispatch: typed refusal, no silent selection.
    let (ok, out) = docket(
        &fx.root,
        &["show", "--dispatch", "ffffffffffffffffffffffffffffffff"],
    );
    assert!(!ok);
    assert!(out.contains("unknown dispatch identity"), "{out}");

    // Malformed identifier.
    let (ok, out) = docket(&fx.root, &["show", "--dispatch", "zz"]);
    assert!(!ok);
    assert!(out.contains("bad id"), "{out}");

    // Ambiguous addressing is refused, not resolved by precedence.
    let (ok, out) = docket(
        &fx.root,
        &[
            "show",
            "--attempt",
            "09090909090909090909090909090909",
            "--dispatch",
            &dsp,
        ],
    );
    assert!(!ok);
    assert!(out.contains("exactly one of"), "{out}");

    // The journal surface resolves by dispatch too.
    let (ok, out) = docket(&fx.root, &["journal", "--dispatch", &dsp]);
    assert!(ok, "{out}");
    assert!(out.contains("status verified_complete"), "{out}");
}

// --- C: verified journal inspection ---

#[test]
fn intact_journals_verify_and_preserve_event_order() {
    let mut fx = fixture("journal-ok");
    drive_committed(&mut fx);

    let (ok, text) = docket(
        &fx.root,
        &["journal", "--attempt", "09090909090909090909090909090909"],
    );
    assert!(ok, "{text}");
    assert!(text.contains("status verified_complete"), "{text}");
    // Exact order preserved: the indexed event lines carry the phases in
    // journal order.
    let rendered: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("  "))
        .filter_map(|l| l.split_whitespace().nth(1))
        .collect();
    assert_eq!(
        rendered,
        vec![
            "received",
            "verified",
            "patch_applied",
            "paths_authorized",
            "tree_written",
            "commit_created",
            "ref_updating",
            "ref_updated",
            "acknowledged",
        ],
        "{text}"
    );
    let (ok, json) = docket(
        &fx.root,
        &[
            "journal",
            "--attempt",
            "09090909090909090909090909090909",
            "--json",
        ],
    );
    assert!(ok, "{json}");
    assert!(json.contains("\"journal_format\":\"gwr:journal-view:v1\""));
    assert!(json.contains("\"kind\":\"verified_complete\""));
    assert!(json.contains("\"verified\":true"));
    assert!(json.contains("\"phase\":\"ref_updated\""));
}

#[test]
fn crash_journals_verify_as_partial() {
    let mut fx = fixture("journal-partial");
    drive_recovered(&mut fx);

    let (ok, text) = docket(
        &fx.root,
        &["journal", "--attempt", "09090909090909090909090909090909"],
    );
    assert!(ok, "{text}");
    assert!(text.contains("status verified_partial"), "{text}");
    assert!(text.contains("does not reach a terminal phase"), "{text}");
    assert!(text.contains("ref_updated"), "{text}");
    assert!(!text.contains("acknowledged"), "{text}");
}

#[test]
fn altered_and_truncated_journals_refuse_visibly() {
    // Altered: one byte changed.
    let mut fx = fixture("journal-altered");
    drive_committed(&mut fx);
    let path = journal_path(&mut fx);
    let mut bytes = std::fs::read(&path).unwrap();
    let len = bytes.len();
    bytes[len - 2] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    let (ok, text) = docket(
        &fx.root,
        &["journal", "--attempt", "09090909090909090909090909090909"],
    );
    assert!(ok, "{text}");
    assert!(text.contains("status digest_mismatch"), "{text}");
    assert!(text.contains("content withheld"), "{text}");
    assert!(
        !text.contains("patch_applied"),
        "unverified content must not be rendered: {text}"
    );
    drop(fx);

    // Truncated: last line removed.
    let mut fx = fixture("journal-truncated");
    drive_committed(&mut fx);
    let path = journal_path(&mut fx);
    let content = std::fs::read_to_string(&path).unwrap();
    let truncated: Vec<&str> = content.lines().collect();
    std::fs::write(&path, truncated[..truncated.len() - 1].join("\n") + "\n").unwrap();
    let (ok, json) = docket(
        &fx.root,
        &[
            "journal",
            "--attempt",
            "09090909090909090909090909090909",
            "--json",
        ],
    );
    assert!(ok, "{json}");
    assert!(json.contains("\"kind\":\"digest_mismatch\""), "{json}");
    assert!(json.contains("\"verified\":false"), "{json}");
    assert!(json.contains("\"events\":[]"), "{json}");
    drop(fx);

    // Deleted: expected but missing.
    let mut fx = fixture("journal-missing");
    drive_committed(&mut fx);
    let path = journal_path(&mut fx);
    std::fs::remove_file(&path).unwrap();
    let (ok, text) = docket(
        &fx.root,
        &["journal", "--attempt", "09090909090909090909090909090909"],
    );
    assert!(ok, "{text}");
    assert!(text.contains("status missing"), "{text}");
}

#[test]
fn out_of_vocabulary_content_is_redacted_as_corrupt() {
    // Pure-level: a digest-matching journal containing a foreign line. (No
    // tamper path reaches this — tampering breaks the digest first — but a
    // recorded digest over malformed content must still refuse to render.)
    let bytes = b"received\nverified\nrm -rf / # provider output\nacknowledged\n";
    let view = inspect(
        AttemptId::from_bytes([9; 16]),
        Some(DispatchId::from_bytes([5; 16])),
        JournalExpectation::Digest(Sha256Digest::of_bytes(bytes)),
        Some(bytes),
    );
    match &view.status {
        JournalStatus::Corrupt { line_number, .. } => assert_eq!(*line_number, 3),
        other => panic!("expected corrupt, got {other:?}"),
    }
    assert!(view.events.is_empty(), "content withheld");
    let text = gwr_runtime::services::journal::render_journal_text(&view);
    assert!(text.contains("redacted"), "{text}");
    assert!(
        !text.contains("rm -rf"),
        "unvocabularied content must never be rendered: {text}"
    );
    let json = gwr_runtime::services::journal::render_journal_json(&view);
    assert!(!json.contains("rm -rf"), "{json}");

    // A journal with no recorded digest is unavailable, never evidence.
    let view = inspect(
        AttemptId::from_bytes([9; 16]),
        Some(DispatchId::from_bytes([5; 16])),
        JournalExpectation::NoRecordedDigest,
        Some(b"received\n"),
    );
    assert!(matches!(view.status, JournalStatus::Unavailable { .. }));
    assert!(view.events.is_empty());
}

// --- cross-cutting ---

#[test]
fn no_secret_authority_material_on_new_surfaces() {
    let mut fx = fixture("secrets");
    drive_committed(&mut fx);
    let key = [0x5a; 32];
    let codec = StandingTokenCodec::new(key);
    let g = grant(&mut fx, 7, StandingAct::Ratify);
    let token = codec.issue(&g);
    let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();

    let rows = assemble_list(&mut fx.store).unwrap();
    let (_, journal_text) = docket(
        &fx.root,
        &["journal", "--attempt", "09090909090909090909090909090909"],
    );
    let (_, journal_json) = docket(
        &fx.root,
        &[
            "journal",
            "--attempt",
            "09090909090909090909090909090909",
            "--json",
        ],
    );
    for surface in [
        render_list_text(&rows),
        render_list_json(&rows),
        journal_text,
        journal_json,
    ] {
        assert!(!surface.contains(&token), "token leaked");
        assert!(!surface.contains(&key_hex), "key leaked");
        let tag = token.rsplit('|').next().unwrap();
        assert!(!surface.contains(tag), "MAC tag leaked");
    }
}

#[test]
fn malformed_persisted_records_produce_typed_errors_on_new_surfaces() {
    let mut fx = fixture("corrupt");
    drive_committed(&mut fx);
    fx.store
        .execute_raw_for_test("UPDATE commitment SET journal_digest='zz'")
        .unwrap();
    let (ok, out) = docket(
        &fx.root,
        &["journal", "--attempt", "09090909090909090909090909090909"],
    );
    assert!(!ok, "corrupt digest column must refuse: {out}");
    assert!(out.contains("Corrupt"), "{out}");

    fx.store
        .execute_raw_for_test("UPDATE attempt_projection SET state='bogus'")
        .unwrap();
    let (ok, out) = docket(&fx.root, &["list"]);
    assert!(!ok, "corrupt projection must refuse: {out}");
    assert!(out.contains("Corrupt"), "{out}");
}
