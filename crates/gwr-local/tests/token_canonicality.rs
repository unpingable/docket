//! Regression for finding N-2: standing-token text must be canonical, and every
//! rejection must be a typed refusal in every build profile.
//!
//! `u8::from_str_radix(_, 16)` accepts uppercase, so an uppercase MAC tag used to
//! pass the constant-time verify and then hit a `debug_assert_eq!` on the hex
//! *string*: a panic in debug on operator-supplied input, and silent acceptance
//! in release. One grant had two valid token texts, and the two profiles
//! disagreed about it.
//!
//! These assertions are profile-independent by construction — they call `verify`
//! and inspect its `Result`, so `cargo test` and `cargo test --release` check the
//! same property.

use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::{StandingAct, StandingGrant, StandingScope};
use gwr_core::ids::{ActorId, StandingGrantId};
use gwr_core::refusal::StandingRefusal;
use gwr_core::work_request::{ClockReading, RepositoryLocator};
use gwr_local::capabilities::StandingTokenCodec;

fn codec() -> StandingTokenCodec {
    StandingTokenCodec::new([7u8; 32])
}

fn grant(repo: &str) -> StandingGrant {
    StandingGrant::issue(
        StandingGrantId::from_bytes([1; 16]),
        StandingScope {
            actor: ActorId::from_bytes([2; 16]),
            act: StandingAct::Ratify,
            repository: RepositoryLocator::new(repo),
            attempt_digest: Sha256Digest::of_bytes(b"attempt"),
        },
        ClockReading(5_000),
    )
}

/// The exact witness: same MAC bytes, different spelling.
#[test]
fn an_uppercase_mac_tag_is_refused_not_accepted_and_never_panics() {
    let g = grant("/repo");
    let token = codec().issue(&g);
    let (payload, tag) = token.rsplit_once('|').unwrap();
    let upper = format!("{payload}|{}", tag.to_uppercase());
    assert_ne!(upper, token, "the case change must produce different text");

    assert_eq!(
        codec().verify(&upper),
        Err(StandingRefusal::IntegrityFailure),
        "a non-canonical tag spelling must be an integrity failure"
    );
}

/// Mixed case, and case changes confined to the payload's hex fields.
#[test]
fn every_non_canonical_spelling_is_refused() {
    let g = grant("/repo");
    let token = codec().issue(&g);
    let (payload, tag) = token.rsplit_once('|').unwrap();

    let mut cases = vec![
        ("uppercase tag", format!("{payload}|{}", tag.to_uppercase())),
        (
            "one uppercase nibble",
            format!("{payload}|{}{}", tag[..1].to_uppercase(), &tag[1..]),
        ),
        (
            "uppercase payload hex",
            format!("{}|{tag}", payload.to_uppercase()),
        ),
    ];
    // A tag that is the right length but not hex at all.
    cases.push(("non-hex tag", format!("{payload}|{}", "z".repeat(64))));

    for (name, t) in cases {
        assert_eq!(
            codec().verify(&t),
            Err(StandingRefusal::IntegrityFailure),
            "`{name}` was not refused"
        );
    }
}

/// The canonical token still verifies, for every repository shape the domain
/// admits — including the `|` that once let the parser reconstruct a different
/// scope than the one signed (finding V7).
#[test]
fn the_canonical_token_round_trips_for_awkward_repositories() {
    for repo in [
        "/repo",
        "/repo|9999999999|deadbeef",
        "|",
        "/repo:with:colons",
        "12:fake",
        "/日本語/リポジトリ",
        "",
    ] {
        let g = grant(repo);
        let token = codec().issue(&g);
        let back = codec().verify(&token).unwrap_or_else(|e| {
            panic!("canonical token for {repo:?} was refused: {e:?}");
        });
        assert_eq!(back.scope().repository.as_str(), repo);
        assert_eq!(back.expires_at(), g.expires_at());
        assert_eq!(back.id(), g.id());
        // Canonicality: exactly one token text names this grant.
        assert_eq!(codec().issue(&back), token);
    }
}

/// Structural tampering stays refused, and never panics.
#[test]
fn tampered_tokens_are_refused() {
    let g = grant("/repo");
    let token = codec().issue(&g);
    let (payload, tag) = token.rsplit_once('|').unwrap();

    for (name, t) in [
        ("wrong key", token.clone()),
        ("trailing byte", format!("{payload}X|{tag}")),
        ("truncated tag", format!("{payload}|{}", &tag[..40])),
        ("empty tag", format!("{payload}|")),
        ("no separator", payload.to_string()),
        ("empty token", String::new()),
        (
            "length prefix lies",
            format!("{}|{tag}", payload.replacen("15:", "14:", 1)),
        ),
    ] {
        let result = if name == "wrong key" {
            StandingTokenCodec::new([8u8; 32]).verify(&t)
        } else {
            codec().verify(&t)
        };
        assert_eq!(
            result,
            Err(StandingRefusal::IntegrityFailure),
            "`{name}` was not refused"
        );
    }
}
