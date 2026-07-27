//! Docket-side conformance for upstream authorization intake.
//!
//! The office boundary under test: an authenticated issuance is a *recorded
//! basis*, never authority. Docket verifies it against its own stored prepared
//! attempt — never against the record's own echoes — and only then mints its
//! own local, exact-attempt-bound, single-use standing. Upstream premises and
//! residuals survive as upstream facts, undischarged, and never merge into
//! settlement premises or Docket obligations.
//!
//! Signing here uses a throwaway keypair generated per test run; no private
//! key material is committed anywhere.

use gwr_core::authorization::{AuthorizationSource, UpstreamResidualStatus};
use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::{StandingAct, StandingGrant, StandingScope};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::preparation::CandidateArtifact;
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryLocator, WorkRequest};
use gwr_local::authz_intake::{
    confirm_request_bytes, request_digest, verify_issuance, IntakeRefusal, IssuerTrustConfig,
};
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::authz_standing::{mint_from_issuance, MintError};
use gwr_runtime::services::dossier;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

const ATTEMPT_BYTES: [u8; 16] = [9; 16];
const ACTOR: &str = "operator";
const REPO: &str = "/governed/repo";
const TARGET_REF: &str = "refs/gwr/target";
const BASIS: &str = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a";
const PREFIX: &[u8] = b"ag-ng\0docket-issuance-signature\0v1\0";

fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(A[((acc >> bits) & 63) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((acc << (6 - bits)) & 63) as usize] as char);
    }
    out
}

struct Signer {
    key_pair: Ed25519KeyPair,
    public_b64: String,
}

fn signer() -> Signer {
    let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
    let public_b64 = b64(key_pair.public_key().as_ref());
    Signer {
        key_pair,
        public_b64,
    }
}

fn trust(s: &Signer) -> IssuerTrustConfig {
    IssuerTrustConfig::parse(
        serde_json::json!({
            "issuers": [{
                "issuer_principal": "issuer",
                "key_id": "vertical-issuer-1",
                "public_key": s.public_b64,
            }]
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap()
}

fn attempt() -> PreparedAttempt {
    PreparedAttempt::admit(
        AttemptId::from_bytes(ATTEMPT_BYTES),
        WorkRequestId::from_bytes([1; 16]),
        CandidateArtifactId::from_bytes([2; 16]),
        RepositoryLocator::new(REPO),
        CommitHash::new(BASIS),
        Sha256Digest::of_bytes(b"patch"),
        GitRefEffect {
            target_ref: RefName::new(TARGET_REF),
            expected_basis: CommitHash::new(BASIS),
            patch_digest: Sha256Digest::of_bytes(b"patch"),
            allowed_paths: vec!["docs/vertical-01.md".into()],
        },
        ObservationPlan {
            argv: vec!["true".into()],
            environment_description: "fixture".into(),
        },
        ClockReading(1_100),
    )
}

fn body_json(att: &PreparedAttempt, mutate: impl Fn(&mut serde_json::Value)) -> serde_json::Value {
    let mut v = serde_json::json!({
        "issuance_id": "sha256:issuance-1",
        "decision_id": "sha256:decision-1",
        "issuer_principal": "issuer",
        "issuer_key_id": "vertical-issuer-1",
        "decision_context": {
            "authority_domain": "test.domain",
            "epoch": 1,
            "lifecycle_nonce": "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
            "catalog_identity": "sha256:catalog"
        },
        "principal_chain": ["root", "issuer"],
        "target_id": "docket-vertical",
        "request_source": {
            "schema": "gwr:authz-request:v1",
            "raw_sha256": "sha256:00",
            "ag_canonical_digest": "sha256:11"
        },
        "docket": {
            "attempt": hex(&ATTEMPT_BYTES),
            "prepared_attempt_digest": att.prepared_attempt_digest.to_hex(),
            "effect_class": "git-ref-update:v1",
            "repository": REPO,
            "target_ref": TARGET_REF,
            "basis": BASIS,
            "allowed_paths": ["docs/vertical-01.md"],
            "requested_actor": ACTOR
        },
        "issued_at_unix_ms": 2_000,
        "expires_at_unix_ms": 9_000,
        "premises": [{
            "kind": "principal_authentication",
            "statement": "the principal chain was authenticated by the local transport"
        }],
        "residual_obligations": {"status": "unrepresented", "items": []},
        "consumption": {
            "ledger": "ag-ng.docket-issuance.decision-ledger.v1",
            "use_digest": "sha256:use-1"
        },
        "decision": "admitted"
    });
    mutate(&mut v);
    v
}

fn hex(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn envelope(s: &Signer, body: &serde_json::Value) -> Vec<u8> {
    let body_bytes = serde_json::to_vec(body).unwrap();
    let mut msg = Vec::from(PREFIX);
    msg.extend_from_slice(&body_bytes);
    let sig = s.key_pair.sign(&msg);
    serde_json::to_vec(&serde_json::json!({
        "schema": "ag.docket-issuance:v1",
        "body_b64": b64(&body_bytes),
        "authentication": {
            "signer_key_id": "vertical-issuer-1",
            "signer_public_key": s.public_b64,
            "signature": b64(sig.as_ref()),
        }
    }))
    .unwrap()
}

fn now() -> ClockReading {
    ClockReading(3_000)
}

fn store_with_attempt(att: &PreparedAttempt) -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let wr = WorkRequest {
        id: att.work_request,
        repository_id: None,
        repository: att.repository.clone(),
        target_ref: att.effect.target_ref.clone(),
        goal: "fixture".into(),
        created_at: ClockReading(1_000),
    };
    store.create_work_request(&wr).unwrap();
    store
        .ingest_candidate(&CandidateArtifact {
            id: att.candidate,
            preparation_run: PreparationRunId::from_bytes([3; 16]),
            content_digest: att.artifact_digest,
            content_len: 1,
            ingested_at: ClockReading(1_050),
        })
        .unwrap();
    store.admit_attempt(att).unwrap();
    store
}

fn accept(
    store: &mut SqliteStore,
    bytes: &[u8],
    att: &PreparedAttempt,
    t: &IssuerTrustConfig,
    grant_byte: u8,
) -> Result<StandingGrant, MintError> {
    let verified = verify_issuance(bytes, att, att.attempt_id, t, now()).expect("verifies");
    mint_from_issuance(
        store,
        &verified.accepted,
        ActorId::from_bytes([4; 16]),
        StandingAct::Ratify,
        StandingGrantId::from_bytes([grant_byte; 16]),
        now(),
        3_600_000,
    )
}

// --- acceptance ---

#[test]
fn a_valid_issuance_mints_exactly_one_standing() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    let bytes = envelope(&s, &body_json(&att, |_| {}));
    let mut store = store_with_attempt(&att);
    let grant = accept(&mut store, &bytes, &att, &t, 7).expect("mints");
    assert_eq!(grant.scope().attempt_digest, att.prepared_attempt_digest);
    // The grant is an ordinary Docket grant, recorded as upstream-authorized.
    let (source, issuance) = store.get_grant_authorization(grant.id()).unwrap().unwrap();
    assert_eq!(source, AuthorizationSource::Upstream);
    assert_eq!(issuance.as_deref(), Some("sha256:issuance-1"));
    // Expiry never exceeds the issuance's own.
    assert!(grant.expires_at().0 <= 9_000);
}

#[test]
fn duplicate_intake_is_idempotent_and_mints_no_second_standing() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    let bytes = envelope(&s, &body_json(&att, |_| {}));
    let mut store = store_with_attempt(&att);
    accept(&mut store, &bytes, &att, &t, 7).expect("first mint");
    match accept(&mut store, &bytes, &att, &t, 8) {
        Err(MintError::AlreadyMinted { issuance_id }) => {
            assert_eq!(issuance_id, "sha256:issuance-1");
        }
        other => panic!("expected AlreadyMinted, got {other:?}"),
    }
}

#[test]
fn one_issuance_cannot_mint_standing_for_two_attempts() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    let bytes = envelope(&s, &body_json(&att, |_| {}));
    let mut store = store_with_attempt(&att);
    accept(&mut store, &bytes, &att, &t, 7).expect("first mint");

    // A second attempt, and an issuance naming it but reusing the identity.
    let mut other = attempt();
    other = PreparedAttempt::admit(
        AttemptId::from_bytes([10; 16]),
        other.work_request,
        other.candidate,
        other.repository.clone(),
        other.basis.clone(),
        other.artifact_digest,
        other.effect.clone(),
        other.observation_plan.clone(),
        ClockReading(1_200),
    );
    store.admit_attempt(&other).unwrap();
    let reused = envelope(
        &s,
        &body_json(&other, |v| {
            v["docket"]["attempt"] = serde_json::json!(hex(&[10; 16]));
            v["docket"]["prepared_attempt_digest"] = serde_json::json!(attempt_digest_of(&other));
        }),
    );
    let verified = verify_issuance(&reused, &other, other.attempt_id, &t, now()).unwrap();
    match mint_from_issuance(
        &mut store,
        &verified.accepted,
        ActorId::from_bytes([4; 16]),
        StandingAct::Ratify,
        StandingGrantId::from_bytes([9; 16]),
        now(),
        3_600_000,
    ) {
        Err(MintError::IssuanceSubstitution { .. } | MintError::AlreadyMinted { .. }) => {}
        other => panic!("expected refusal across attempts, got {other:?}"),
    }
}

fn attempt_digest_of(a: &PreparedAttempt) -> String {
    a.prepared_attempt_digest.to_hex()
}

// --- binding refusals: docket owns every comparison value ---

#[test]
fn binding_mismatches_refuse() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    type Mutation = Box<dyn Fn(&mut serde_json::Value)>;
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "attempt",
            Box::new(|v: &mut serde_json::Value| {
                v["docket"]["attempt"] = serde_json::json!(hex(&[99; 16]))
            }),
        ),
        (
            "prepared_attempt_digest",
            Box::new(|v: &mut serde_json::Value| {
                v["docket"]["prepared_attempt_digest"] = serde_json::json!("d9".repeat(32))
            }),
        ),
        (
            "effect_class",
            Box::new(|v: &mut serde_json::Value| {
                v["docket"]["effect_class"] = serde_json::json!("artifact-computation:v1")
            }),
        ),
        (
            "repository",
            Box::new(|v: &mut serde_json::Value| {
                v["docket"]["repository"] = serde_json::json!("/elsewhere")
            }),
        ),
        (
            "target_ref",
            Box::new(|v: &mut serde_json::Value| {
                v["docket"]["target_ref"] = serde_json::json!("refs/heads/main")
            }),
        ),
        (
            "basis",
            Box::new(|v: &mut serde_json::Value| {
                v["docket"]["basis"] = serde_json::json!("2b".repeat(20))
            }),
        ),
        (
            "allowed_paths",
            Box::new(|v: &mut serde_json::Value| {
                v["docket"]["allowed_paths"] = serde_json::json!(["src/lib.rs"])
            }),
        ),
    ];
    for (field, mutate) in cases {
        let bytes = envelope(&s, &body_json(&att, &mutate));
        match verify_issuance(&bytes, &att, att.attempt_id, &t, now()) {
            Err(IntakeRefusal::BindingMismatch { field: f, .. }) => assert_eq!(f, field),
            other => panic!("{field}: expected binding mismatch, got {other:?}"),
        }
    }
}

#[test]
fn wrong_actor_binding_is_visible_and_bound() {
    // The actor the issuance authorizes is signature-protected and becomes the
    // grant's actor; a different actor is a different authenticated record.
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    let bytes = envelope(
        &s,
        &body_json(&att, |v| {
            v["docket"]["requested_actor"] = serde_json::json!("stranger");
        }),
    );
    let verified = verify_issuance(&bytes, &att, att.attempt_id, &t, now()).unwrap();
    assert_eq!(verified.accepted.requested_actor, "stranger");
    // Tampering with the actor after signing breaks authentication.
    let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let body_b64 = tampered["body_b64"].as_str().unwrap().to_string();
    let mut body: serde_json::Value = serde_json::from_slice(&decode_b64(&body_b64)).unwrap();
    body["docket"]["requested_actor"] = serde_json::json!("operator");
    tampered["body_b64"] = serde_json::json!(b64(&serde_json::to_vec(&body).unwrap()));
    let bytes2 = serde_json::to_vec(&tampered).unwrap();
    assert!(matches!(
        verify_issuance(&bytes2, &att, att.attempt_id, &t, now()),
        Err(IntakeRefusal::AuthenticationFailed)
    ));
}

fn decode_b64(v: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut out = Vec::new();
    for ch in v.bytes() {
        let idx = A.iter().position(|c| *c == ch).unwrap() as u32;
        acc = (acc << 6) | idx;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

// --- authenticity, freshness, decision ---

#[test]
fn expired_issuance_refuses() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    let bytes = envelope(
        &s,
        &body_json(&att, |v| {
            v["expires_at_unix_ms"] = serde_json::json!(2_500);
        }),
    );
    match verify_issuance(&bytes, &att, att.attempt_id, &t, now()) {
        Err(IntakeRefusal::Expired { expires_at, now: n }) => {
            assert_eq!(expires_at, 2_500);
            assert_eq!(n, 3_000);
        }
        other => panic!("expected expiry refusal, got {other:?}"),
    }
}

#[test]
fn untrusted_issuer_refuses() {
    let att = attempt();
    let s = signer();
    let other = signer();
    // The record is validly signed by a key nobody trusts.
    let bytes = envelope(&other, &body_json(&att, |_| {}));
    match verify_issuance(&bytes, &att, att.attempt_id, &trust(&s), now()) {
        Err(IntakeRefusal::UntrustedIssuer { .. }) => {}
        other => panic!("expected untrusted issuer, got {other:?}"),
    }
    // And an unknown principal under a trusted key id refuses too.
    let bytes = envelope(
        &s,
        &body_json(&att, |v| {
            v["issuer_principal"] = serde_json::json!("someone-else");
        }),
    );
    assert!(matches!(
        verify_issuance(&bytes, &att, att.attempt_id, &trust(&s), now()),
        Err(IntakeRefusal::UntrustedIssuer { .. })
    ));
}

#[test]
fn a_record_cannot_nominate_its_own_verifier() {
    // Signed by a stranger, but presenting the stranger's public key as if it
    // were the trusted one. Verification uses the *trusted* key, so this fails.
    let att = attempt();
    let trusted = signer();
    let attacker = signer();
    let mut env: serde_json::Value =
        serde_json::from_slice(&envelope(&attacker, &body_json(&att, |_| {}))).unwrap();
    env["authentication"]["signer_public_key"] = serde_json::json!(attacker.public_b64);
    let bytes = serde_json::to_vec(&env).unwrap();
    match verify_issuance(&bytes, &att, att.attempt_id, &trust(&trusted), now()) {
        Err(IntakeRefusal::UntrustedIssuer { .. } | IntakeRefusal::AuthenticationFailed) => {}
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[test]
fn invalid_authentication_refuses() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    let mut env: serde_json::Value =
        serde_json::from_slice(&envelope(&s, &body_json(&att, |_| {}))).unwrap();
    // Flip one signature character to a different valid alphabet character.
    let sig = env["authentication"]["signature"].as_str().unwrap();
    let mut chars: Vec<char> = sig.chars().collect();
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    env["authentication"]["signature"] = serde_json::json!(chars.into_iter().collect::<String>());
    let bytes = serde_json::to_vec(&env).unwrap();
    assert!(matches!(
        verify_issuance(&bytes, &att, att.attempt_id, &t, now()),
        Err(IntakeRefusal::AuthenticationFailed)
    ));
}

#[test]
fn altered_premise_or_residual_breaks_verification() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    for pointer in [
        "/premises/0/statement",
        "/premises/0/kind",
        "/residual_obligations/status",
        "/consumption/use_digest",
        "/request_source/raw_sha256",
        "/request_source/ag_canonical_digest",
    ] {
        let bytes = envelope(&s, &body_json(&att, |_| {}));
        let mut env: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut body: serde_json::Value =
            serde_json::from_slice(&decode_b64(env["body_b64"].as_str().unwrap())).unwrap();
        *body.pointer_mut(pointer).unwrap() = serde_json::json!("tampered");
        env["body_b64"] = serde_json::json!(b64(&serde_json::to_vec(&body).unwrap()));
        let tampered = serde_json::to_vec(&env).unwrap();
        assert!(
            matches!(
                verify_issuance(&tampered, &att, att.attempt_id, &t, now()),
                Err(IntakeRefusal::AuthenticationFailed)
            ),
            "tampering with {pointer} must break authentication"
        );
    }
}

#[test]
fn a_non_admitted_result_cannot_mint_standing() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    let bytes = envelope(
        &s,
        &body_json(&att, |v| {
            v["decision"] = serde_json::json!("refused");
        }),
    );
    match verify_issuance(&bytes, &att, att.attempt_id, &t, now()) {
        Err(IntakeRefusal::NotAdmitted { decision }) => assert_eq!(decision, "refused"),
        other => panic!("expected NotAdmitted, got {other:?}"),
    }
}

#[test]
fn unsupported_schema_and_malformed_records_refuse() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    // A foreign document.
    let foreign = serde_json::to_vec(&serde_json::json!({"schema": "nq.witness.v1"})).unwrap();
    assert!(matches!(
        verify_issuance(&foreign, &att, att.attempt_id, &t, now()),
        Err(IntakeRefusal::UnsupportedSchema { .. })
    ));
    // Unknown field inside the body: not the supported record.
    let bytes = envelope(
        &s,
        &body_json(&att, |v| {
            v["surprise"] = serde_json::json!("x");
        }),
    );
    assert!(matches!(
        verify_issuance(&bytes, &att, att.attempt_id, &t, now()),
        Err(IntakeRefusal::Malformed { .. })
    ));
    // Unsupported request schema inside a well-formed record.
    let bytes = envelope(
        &s,
        &body_json(&att, |v| {
            v["request_source"]["schema"] = serde_json::json!("gwr:authz-request:v9");
        }),
    );
    assert!(matches!(
        verify_issuance(&bytes, &att, att.attempt_id, &t, now()),
        Err(IntakeRefusal::UnsupportedRequestSchema { .. })
    ));
}

#[test]
fn inconsistent_residual_sets_refuse() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    // Status claims presence with no items.
    let bytes = envelope(
        &s,
        &body_json(&att, |v| {
            v["residual_obligations"]["status"] = serde_json::json!("present");
        }),
    );
    assert!(matches!(
        verify_issuance(&bytes, &att, att.attempt_id, &t, now()),
        Err(IntakeRefusal::InconsistentResiduals { .. })
    ));
    // Status claims absence while carrying items.
    let bytes = envelope(
        &s,
        &body_json(&att, |v| {
            v["residual_obligations"]["items"] = serde_json::json!([{
                "source_system": "ag-ng", "obligation_id": "o1", "subject": "s",
                "kind": "k", "statement": "st"
            }]);
        }),
    );
    assert!(matches!(
        verify_issuance(&bytes, &att, att.attempt_id, &t, now()),
        Err(IntakeRefusal::InconsistentResiduals { .. })
    ));
}

// --- persistence, dossier, and office separation ---

#[test]
fn upstream_facts_survive_into_the_dossier_without_becoming_docket_facts() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    let bytes = envelope(
        &s,
        &body_json(&att, |v| {
            v["residual_obligations"] = serde_json::json!({
                "status": "present",
                "items": [{
                    "source_system": "ag-ng",
                    "obligation_id": "obl-1",
                    "subject": "docs/vertical-01.md",
                    "kind": "human_review_before_publication",
                    "statement": "a human must review the record before it is cited"
                }]
            });
        }),
    );
    let mut store = store_with_attempt(&att);
    accept(&mut store, &bytes, &att, &t, 7).expect("mints");

    let d = dossier::assemble(&mut store, att.attempt_id).unwrap();
    assert_eq!(d.authorization.source, Some(AuthorizationSource::Upstream));
    let i = d.authorization.issuance.as_ref().expect("issuance present");
    assert_eq!(i.residual_status, UpstreamResidualStatus::Present);
    assert_eq!(i.residuals.len(), 1);
    assert_eq!(i.premises.len(), 1);
    // Both digests survive, distinct from each other and from Docket's.
    assert_ne!(i.request_raw_sha256, i.request_upstream_digest);
    assert_eq!(i.prepared_digest, att.prepared_attempt_digest);

    let json = dossier::render_json(&d);
    let text = dossier::render_text(&d);
    for surface in [&json, &text] {
        assert!(surface.contains("upstream"), "authorization source shown");
        assert!(surface.contains("obl-1"), "upstream residual carried");
        assert!(
            surface.contains("human_review_before_publication"),
            "upstream residual kind kept in upstream vocabulary"
        );
    }
    // Upstream residuals are not discharged, and are not Docket obligations.
    assert!(json.contains("\"discharged\":false"));
    assert!(text.contains("outstanding: import and execution discharge nothing upstream"));
    assert!(d.observation.residual_obligations.is_empty());
    // Upstream premises are not settlement premises.
    assert!(json.contains("\"upstream_premises\""));
    assert!(json.contains("\"settlement_premises\""));
    assert!(text.contains("upstream_premise principal_authentication"));
    assert!(text.contains("are not this effect class's settlement premises"));
    // No secret, no authority object, no signature material in persistence.
    for forbidden in ["signature", "private", "pkcs8", "capability"] {
        assert!(!json.contains(forbidden), "{forbidden} must not appear");
    }
}

#[test]
fn local_standing_remains_functional_and_visibly_distinct() {
    let att = attempt();
    let mut store = store_with_attempt(&att);
    let grant = StandingGrant::issue(
        StandingGrantId::from_bytes([5; 16]),
        StandingScope {
            actor: ActorId::from_bytes([4; 16]),
            act: StandingAct::Ratify,
            repository: att.repository.clone(),
            attempt_digest: att.prepared_attempt_digest,
        },
        ClockReading(1_000_000),
    );
    store.create_standing_grant(&grant).unwrap();
    let (source, issuance) = store.get_grant_authorization(grant.id()).unwrap().unwrap();
    assert_eq!(source, AuthorizationSource::Local);
    assert!(issuance.is_none());

    let d = dossier::assemble(&mut store, att.attempt_id).unwrap();
    // No ratification yet, so no ratifying grant is projected; the local grant
    // is nonetheless recorded as locally authorized in the store.
    assert!(d.authorization.issuance.is_none());
    let text = dossier::render_text(&d);
    assert!(text.contains("authorization"));
}

#[test]
fn request_digest_loop_can_be_closed_and_mismatch_refuses() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    let request_bytes = br#"{"authz_request_format":"gwr:authz-request:v1"}"#;
    let expected = request_digest(request_bytes);
    let bytes = envelope(
        &s,
        &body_json(&att, |v| {
            v["request_source"]["raw_sha256"] = serde_json::json!(expected);
        }),
    );
    let verified = verify_issuance(&bytes, &att, att.attempt_id, &t, now()).unwrap();
    confirm_request_bytes(&verified, request_bytes).expect("loop closes");
    assert!(matches!(
        confirm_request_bytes(&verified, b"different bytes"),
        Err(IntakeRefusal::BindingMismatch { .. })
    ));
}

#[test]
fn malformed_persisted_issuance_data_produces_typed_errors() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    let bytes = envelope(&s, &body_json(&att, |_| {}));
    let mut store = store_with_attempt(&att);
    accept(&mut store, &bytes, &att, &t, 7).expect("mints");

    store
        .execute_raw_for_test("UPDATE authz_issuance SET residual_status='bogus'")
        .unwrap();
    match store.get_authz_issuance("sha256:issuance-1") {
        Err(gwr_runtime::ports::store::StoreError::Corrupt(msg)) => {
            assert!(msg.contains("bogus"), "{msg}");
        }
        other => panic!("expected typed corrupt error, got {other:?}"),
    }
    store
        .execute_raw_for_test("UPDATE authz_issuance SET residual_status='present'")
        .unwrap();
    store
        .execute_raw_for_test("UPDATE authz_issuance SET premise_statements=''")
        .unwrap();
    assert!(matches!(
        store.get_authz_issuance("sha256:issuance-1"),
        Err(gwr_runtime::ports::store::StoreError::Corrupt(_))
    ));
}

#[test]
fn substituted_bytes_under_the_same_issuance_identity_refuse() {
    let att = attempt();
    let s = signer();
    let t = trust(&s);
    let first = envelope(&s, &body_json(&att, |_| {}));
    let mut store = store_with_attempt(&att);
    accept(&mut store, &first, &att, &t, 7).expect("mints");

    // Same issuance_id, different signed content (a later expiry).
    let second = envelope(
        &s,
        &body_json(&att, |v| {
            v["expires_at_unix_ms"] = serde_json::json!(8_500);
        }),
    );
    let verified = verify_issuance(&second, &att, att.attempt_id, &t, now()).unwrap();
    match mint_from_issuance(
        &mut store,
        &verified.accepted,
        ActorId::from_bytes([4; 16]),
        StandingAct::Ratify,
        StandingGrantId::from_bytes([8; 16]),
        now(),
        3_600_000,
    ) {
        Err(MintError::IssuanceSubstitution { issuance_id }) => {
            assert_eq!(issuance_id, "sha256:issuance-1");
        }
        other => panic!("expected substitution refusal, got {other:?}"),
    }
}

// --- cross-repository conformance vectors ---
//
// These exercise the *shipped* vectors in `conformance/authz/`, which were
// produced by the upstream office's independent implementation. The consumer
// verifies the producer's artifacts; neither side shares code with the other.

fn vector(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/authz")
        .join(name);
    std::fs::read(path).unwrap()
}

fn vector_trust() -> IssuerTrustConfig {
    IssuerTrustConfig::parse(&vector("trust.json")).unwrap()
}

// The positive vector authenticates under the shipped trust configuration:
// schema, trusted issuer, and signature over the exact body bytes all hold.
#[test]
fn shipped_issuance_vector_authenticates() {
    let att = attempt();
    // Binding is checked against *this* store's attempt, which is not the
    // historical one the vector names — so the refusal must be a binding
    // mismatch, never an authentication failure.
    match verify_issuance(
        &vector("issuance.json"),
        &att,
        att.attempt_id,
        &vector_trust(),
        ClockReading(0),
    ) {
        Err(IntakeRefusal::BindingMismatch { field, .. }) => assert_eq!(field, "attempt"),
        other => panic!("expected binding mismatch after successful authentication, got {other:?}"),
    }
}

// Every tampered derivative fails authentication: the signature covers each
// protected field, including premises and residual status.
#[test]
fn tampered_issuance_vectors_fail_authentication() {
    let att = attempt();
    let t = vector_trust();
    for name in [
        "issuance-changed-prepared-digest.json",
        "issuance-changed-ag-digest.json",
        "issuance-changed-raw-digest.json",
        "issuance-changed-scope.json",
        "issuance-changed-actor.json",
        "issuance-changed-premise.json",
        "issuance-changed-residual.json",
        "issuance-expired.json",
        "issuance-not-admitted.json",
        "issuance-bad-authentication.json",
    ] {
        match verify_issuance(&vector(name), &att, att.attempt_id, &t, ClockReading(0)) {
            Err(IntakeRefusal::AuthenticationFailed) => {}
            other => panic!("{name}: expected authentication failure, got {other:?}"),
        }
    }
}

// Structural vectors refuse before authentication is even relevant.
#[test]
fn structural_issuance_vectors_refuse_typed() {
    let att = attempt();
    let t = vector_trust();
    assert!(matches!(
        verify_issuance(
            &vector("issuance-unknown-issuer.json"),
            &att,
            att.attempt_id,
            &t,
            ClockReading(0)
        ),
        Err(IntakeRefusal::UntrustedIssuer { .. })
    ));
    assert!(matches!(
        verify_issuance(
            &vector("issuance-unsupported-schema.json"),
            &att,
            att.attempt_id,
            &t,
            ClockReading(0)
        ),
        Err(IntakeRefusal::UnsupportedSchema { .. })
    ));
    assert!(matches!(
        verify_issuance(
            &vector("refusal-object.json"),
            &att,
            att.attempt_id,
            &t,
            ClockReading(0)
        ),
        Err(IntakeRefusal::Malformed { .. })
    ));
}

// The shipped request vector round-trips through the digest the consumer
// computes, and a changed request no longer matches the issuance's echo.
#[test]
fn shipped_request_vector_digests_match_the_issuance() {
    let att = attempt();
    let t = vector_trust();
    // Read the issuance's raw digest by authenticating it far enough to decode.
    let bytes = vector("issuance.json");
    let err = verify_issuance(&bytes, &att, att.attempt_id, &t, ClockReading(0)).unwrap_err();
    assert!(matches!(err, IntakeRefusal::BindingMismatch { .. }));
    // The consumer's own digest of the shipped request equals what the
    // issuance names; the altered request does not.
    let request = vector("request.json");
    let changed = vector("request-changed.json");
    let issuance_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let body_b64 = issuance_json["body_b64"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_slice(&decode_b64(body_b64)).unwrap();
    let named = body["request_source"]["raw_sha256"].as_str().unwrap();
    assert_eq!(request_digest(&request), named);
    assert_ne!(request_digest(&changed), named);
}
