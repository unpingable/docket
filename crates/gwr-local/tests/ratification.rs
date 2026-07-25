//! Task 7 ratification tests: exact authority, consumed once, refusals consume
//! nothing.

use gwr_core::bridge::standing_to_ratification as rat_bridge;
use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::{GrantState, StandingAct, StandingGrant, StandingScope};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::AttemptState;
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::refusal::StandingRefusal;
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryIdentity};
use gwr_local::adapters::{FixedClock, HashChainIds};
use gwr_local::capabilities::StandingTokenCodec;
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::ratification::{ratify, RatifyError};

fn attempt(byte: u8) -> PreparedAttempt {
    PreparedAttempt::admit(
        AttemptId::from_bytes([byte; 16]),
        WorkRequestId::from_bytes([1; 16]),
        CandidateArtifactId::from_bytes([2; 16]),
        RepositoryIdentity::new("/tmp/fixture"),
        CommitHash::new("basis-aaa"),
        Sha256Digest::of_bytes(b"candidate"),
        GitRefEffect {
            target_ref: RefName::new("refs/gwr/target"),
            expected_basis: CommitHash::new("basis-aaa"),
            patch_digest: Sha256Digest::of_bytes(b"patch"),
            allowed_paths: vec!["src/lib.rs".into()],
        },
        ObservationPlan {
            argv: vec!["cargo".into(), "test".into()],
            environment_description: "fixture".into(),
        },
        ClockReading(1),
    )
}

fn grant(att: &PreparedAttempt, act: StandingAct, actor: u8, expires: u64) -> StandingGrant {
    StandingGrant::issue(
        StandingGrantId::from_bytes([3; 16]),
        StandingScope {
            actor: ActorId::from_bytes([actor; 16]),
            act,
            repository: att.repository.clone(),
            attempt_digest: att.prepared_attempt_digest,
        },
        ClockReading(expires),
    )
}

struct Fx {
    store: SqliteStore,
    ids: HashChainIds,
    att: PreparedAttempt,
}

fn fx(expires: u64) -> Fx {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let att = attempt(9);
    store.admit_attempt(&att).unwrap();
    let g = grant(&att, StandingAct::Ratify, 4, expires);
    store.create_standing_grant(&g).unwrap();
    Fx {
        store,
        ids: HashChainIds::new(),
        att,
    }
}

const GRANT: StandingGrantId = StandingGrantId::from_bytes([3; 16]);
const ACTOR: ActorId = ActorId::from_bytes([4; 16]);

#[test]
fn happy_path_consumes_the_standing_use_exactly_once() {
    let mut f = fx(1000);
    let clock = FixedClock(ClockReading(50));
    let receipt = ratify(
        &mut f.store,
        f.att.attempt_id,
        GRANT,
        ACTOR,
        f.att.prepared_attempt_digest,
        f.att.basis.clone(),
        &clock,
        &mut f.ids,
    )
    .unwrap();
    assert_eq!(receipt.attempt, f.att.attempt_id);
    let g = f.store.get_standing_grant(GRANT).unwrap();
    assert!(matches!(g.state(), GrantState::Consumed { .. }));
    let projected = f.store.get_attempt(f.att.attempt_id).unwrap();
    assert!(matches!(projected.state, AttemptState::Ratified { .. }));
}

#[test]
fn wrong_attempt_digest_refuses_and_consumes_nothing() {
    let mut f = fx(1000);
    let clock = FixedClock(ClockReading(50));
    let err = ratify(
        &mut f.store,
        f.att.attempt_id,
        GRANT,
        ACTOR,
        Sha256Digest::of_bytes(b"a different artifact entirely"),
        f.att.basis.clone(),
        &clock,
        &mut f.ids,
    )
    .unwrap_err();
    assert_eq!(
        err,
        RatifyError::Bridge(rat_bridge::Refusal::DigestMismatch)
    );
    let g = f.store.get_standing_grant(GRANT).unwrap();
    assert_eq!(*g.state(), GrantState::Available);
}

#[test]
fn wrong_basis_refuses() {
    let mut f = fx(1000);
    let clock = FixedClock(ClockReading(50));
    let err = ratify(
        &mut f.store,
        f.att.attempt_id,
        GRANT,
        ACTOR,
        f.att.prepared_attempt_digest,
        CommitHash::new("basis-bbb"),
        &clock,
        &mut f.ids,
    )
    .unwrap_err();
    assert_eq!(err, RatifyError::Bridge(rat_bridge::Refusal::BasisMismatch));
}

#[test]
fn wrong_actor_refuses() {
    let mut f = fx(1000);
    let clock = FixedClock(ClockReading(50));
    let err = ratify(
        &mut f.store,
        f.att.attempt_id,
        GRANT,
        ActorId::from_bytes([99; 16]),
        f.att.prepared_attempt_digest,
        f.att.basis.clone(),
        &clock,
        &mut f.ids,
    )
    .unwrap_err();
    assert_eq!(
        err,
        RatifyError::Bridge(rat_bridge::Refusal::Standing(
            StandingRefusal::ScopeMismatch
        ))
    );
}

#[test]
fn grant_scoped_to_another_repository_or_effect_refuses() {
    // The grant is scoped to a different attempt digest (a different effect).
    let mut store = SqliteStore::open_in_memory().unwrap();
    let att = attempt(9);
    let other = attempt(10);
    store.admit_attempt(&att).unwrap();
    let g = grant(&other, StandingAct::Ratify, 4, 1000);
    store.create_standing_grant(&g).unwrap();
    let mut ids = HashChainIds::new();
    let clock = FixedClock(ClockReading(50));
    let err = ratify(
        &mut store,
        att.attempt_id,
        GRANT,
        ACTOR,
        att.prepared_attempt_digest,
        att.basis.clone(),
        &clock,
        &mut ids,
    )
    .unwrap_err();
    assert_eq!(
        err,
        RatifyError::Bridge(rat_bridge::Refusal::Standing(
            StandingRefusal::ScopeMismatch
        ))
    );
}

#[test]
fn expired_standing_refuses() {
    let mut f = fx(10);
    let clock = FixedClock(ClockReading(50)); // past expiry
    let err = ratify(
        &mut f.store,
        f.att.attempt_id,
        GRANT,
        ACTOR,
        f.att.prepared_attempt_digest,
        f.att.basis.clone(),
        &clock,
        &mut f.ids,
    )
    .unwrap_err();
    assert_eq!(
        err,
        RatifyError::Bridge(rat_bridge::Refusal::Standing(StandingRefusal::Expired))
    );
}

#[test]
fn exhausted_standing_refuses_on_replay() {
    let mut f = fx(1000);
    let clock = FixedClock(ClockReading(50));
    ratify(
        &mut f.store,
        f.att.attempt_id,
        GRANT,
        ACTOR,
        f.att.prepared_attempt_digest,
        f.att.basis.clone(),
        &clock,
        &mut f.ids,
    )
    .unwrap();
    let err = ratify(
        &mut f.store,
        f.att.attempt_id,
        GRANT,
        ACTOR,
        f.att.prepared_attempt_digest,
        f.att.basis.clone(),
        &clock,
        &mut f.ids,
    )
    .unwrap_err();
    assert_eq!(
        err,
        RatifyError::Bridge(rat_bridge::Refusal::Standing(StandingRefusal::AlreadyUsed))
    );
}

#[test]
fn tampered_token_fails_integrity() {
    let codec = StandingTokenCodec::new([7; 32]);
    let att = attempt(9);
    let g = grant(&att, StandingAct::Ratify, 4, 1000);
    let token = codec.issue(&g);
    // Round trip works.
    let verified = codec.verify(&token).unwrap();
    assert_eq!(verified.id(), g.id());
    assert_eq!(verified.scope(), g.scope());
    // Tamper with the expiry inside the payload. Fields are length-prefixed,
    // so a longer value carries its own new prefix.
    let tampered = token.replace("4:1000|", "6:999999|");
    assert_ne!(token, tampered, "the tamper must actually change the token");
    assert_eq!(
        codec.verify(&tampered).unwrap_err(),
        StandingRefusal::IntegrityFailure
    );
    // Tamper with the tag.
    let mut broken = token.clone();
    broken.pop();
    broken.push('0');
    assert!(codec.verify(&broken).is_err());
    // A different key refuses everything.
    let other = StandingTokenCodec::new([8; 32]);
    assert_eq!(
        other.verify(&token).unwrap_err(),
        StandingRefusal::IntegrityFailure
    );
}

/// V7: the serializer and the parser must agree about what was signed. A
/// repository containing the old `|` separator previously authenticated as a
/// different scope — attacker-chosen attempt digest and unbounded expiry —
/// with the HMAC fully intact.
#[test]
fn token_scope_survives_separator_injection() {
    let codec = StandingTokenCodec::new([7; 32]);
    let att = attempt(9);
    // The exact witness shape from the blind review, issued as a scope rather
    // than edited in afterwards.
    let g = StandingGrant::issue(
        StandingGrantId::from_bytes([3; 16]),
        StandingScope {
            actor: ActorId::from_bytes([4; 16]),
            act: StandingAct::Ratify,
            repository: RepositoryIdentity::new(format!(
                "/repo|{}|99999999999999",
                Sha256Digest::of_bytes(b"attacker digest").to_hex()
            )),
            attempt_digest: att.prepared_attempt_digest,
        },
        ClockReading(1000),
    );
    let token = codec.issue(&g);
    let verified = codec.verify(&token).unwrap();
    assert_eq!(
        verified.scope().repository,
        g.scope().repository,
        "repository was re-partitioned by the parser"
    );
    assert_eq!(verified.scope().attempt_digest, g.scope().attempt_digest);
    assert_eq!(verified.expires_at(), g.expires_at());
    assert_eq!(verified.scope(), g.scope());
}

/// Every field can carry the delimiter characters without changing the scope.
#[test]
fn token_round_trips_awkward_repository_paths() {
    let codec = StandingTokenCodec::new([9; 32]);
    let att = attempt(9);
    for repo in [
        "/plain/path",
        "/with|pipes",
        "/with:colons",
        "/with|pipes:and:colons|",
        "/with spaces and \"quotes\"",
        "",
        "/日本語",
    ] {
        let g = StandingGrant::issue(
            StandingGrantId::from_bytes([3; 16]),
            StandingScope {
                actor: ActorId::from_bytes([4; 16]),
                act: StandingAct::Ratify,
                repository: RepositoryIdentity::new(repo),
                attempt_digest: att.prepared_attempt_digest,
            },
            ClockReading(1000),
        );
        let verified = codec.verify(&codec.issue(&g)).unwrap();
        assert_eq!(
            verified.scope(),
            g.scope(),
            "scope changed for repo {repo:?}"
        );
        assert_eq!(verified.expires_at(), g.expires_at());
    }
}

/// Trailing bytes after the signed fields are refused rather than ignored.
#[test]
fn trailing_content_after_the_signed_fields_is_refused() {
    let codec = StandingTokenCodec::new([11; 32]);
    let att = attempt(9);
    let g = grant(&att, StandingAct::Ratify, 4, 1000);
    let token = codec.issue(&g);
    let (payload, tag) = token.rsplit_once('|').unwrap();
    let extended = format!("{payload}trailing|{tag}");
    assert!(codec.verify(&extended).is_err());
}
