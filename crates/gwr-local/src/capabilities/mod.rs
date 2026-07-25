//! Local integrity-protected standing tokens.
//!
//! A token carries an exact standing scope under an HMAC-SHA256 tag. Integrity
//! verification establishes only that the runtime issued these exact bytes;
//! validity (expiry, consumption) is judged against the store's projection.
//! Tokens are never exposed to labor providers, and nothing a provider holds is
//! standing.

use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::{StandingAct, StandingGrant, StandingScope};
use gwr_core::ids::{ActorId, StandingGrantId};
use gwr_core::refusal::StandingRefusal;
use gwr_core::work_request::{ClockReading, RepositoryIdentity};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const TOKEN_PREFIX: &str = "gwr-standing-v1";

pub struct StandingTokenCodec {
    key: [u8; 32],
}

fn act_tag(act: StandingAct) -> &'static str {
    match act {
        StandingAct::Ratify => "ratify",
        StandingAct::ResolveRecovery => "resolve_recovery",
    }
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(hex: &str, out: &mut [u8]) -> Result<(), StandingRefusal> {
    if hex.len() != out.len() * 2 {
        return Err(StandingRefusal::IntegrityFailure);
    }
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| StandingRefusal::IntegrityFailure)?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| StandingRefusal::IntegrityFailure)?;
    }
    Ok(())
}

impl StandingTokenCodec {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// The one canonical transcript. Every field is length-prefixed, so no
    /// field's content can be read as structure — a repository path containing
    /// the old `|` separator previously authenticated as a *different* scope,
    /// because the parser and the serializer disagreed about what had been
    /// signed. Signing, serialization, parsing, and verification all go through
    /// this function.
    fn payload(grant: &StandingGrant) -> String {
        fn field(out: &mut String, value: &str) {
            out.push_str(&value.len().to_string());
            out.push(':');
            out.push_str(value);
        }
        let mut out = String::new();
        field(&mut out, TOKEN_PREFIX);
        field(&mut out, &hex16(grant.id().as_bytes()));
        field(&mut out, &hex16(grant.scope().actor.as_bytes()));
        field(&mut out, act_tag(grant.scope().act));
        field(&mut out, grant.scope().repository.as_str());
        field(&mut out, &grant.scope().attempt_digest.to_hex());
        field(&mut out, &grant.expires_at().0.to_string());
        out
    }

    /// Read one length-prefixed field, returning it and the rest.
    fn take_field(rest: &str) -> Result<(String, &str), StandingRefusal> {
        let colon = rest.find(':').ok_or(StandingRefusal::IntegrityFailure)?;
        let len: usize = rest[..colon]
            .parse()
            .map_err(|_| StandingRefusal::IntegrityFailure)?;
        let start = colon + 1;
        let end = start
            .checked_add(len)
            .ok_or(StandingRefusal::IntegrityFailure)?;
        if end > rest.len() || !rest.is_char_boundary(end) {
            return Err(StandingRefusal::IntegrityFailure);
        }
        Ok((rest[start..end].to_string(), &rest[end..]))
    }

    fn mac(&self, payload: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(payload.as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Issue a token for a grant. The grant itself is persisted separately; the
    /// token is the actor's handle to it.
    pub fn issue(&self, grant: &StandingGrant) -> String {
        let payload = Self::payload(grant);
        let tag = self.mac(&payload);
        format!("{payload}|{tag}")
    }

    /// Verify a token's integrity and reconstruct the scoped grant it names.
    /// The returned grant is `Available` by construction — actual consumption
    /// state comes from the store, never from the token.
    pub fn verify(&self, token: &str) -> Result<StandingGrant, StandingRefusal> {
        let (payload, tag) = token
            .rsplit_once('|')
            .ok_or(StandingRefusal::IntegrityFailure)?;
        let expected = self.mac(payload);
        // Constant-time comparison via the hmac crate's verify.
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(payload.as_bytes());
        let mut tag_bytes = [0u8; 32];
        unhex(tag, &mut tag_bytes)?;
        mac.verify_slice(&tag_bytes)
            .map_err(|_| StandingRefusal::IntegrityFailure)?;
        debug_assert_eq!(expected, tag);

        let (prefix, rest) = Self::take_field(payload)?;
        if prefix != TOKEN_PREFIX {
            return Err(StandingRefusal::IntegrityFailure);
        }
        let (grant_hex, rest) = Self::take_field(rest)?;
        let mut grant_id = [0u8; 16];
        unhex(&grant_hex, &mut grant_id)?;
        let (actor_hex, rest) = Self::take_field(rest)?;
        let mut actor = [0u8; 16];
        unhex(&actor_hex, &mut actor)?;
        let (act_str, rest) = Self::take_field(rest)?;
        let act = match act_str.as_str() {
            "ratify" => StandingAct::Ratify,
            "resolve_recovery" => StandingAct::ResolveRecovery,
            _ => return Err(StandingRefusal::IntegrityFailure),
        };
        let (repository, rest) = Self::take_field(rest)?;
        let (digest_hex, rest) = Self::take_field(rest)?;
        let mut digest = [0u8; 32];
        unhex(&digest_hex, &mut digest)?;
        let (expiry_str, rest) = Self::take_field(rest)?;
        let expires_at: u64 = expiry_str
            .parse()
            .map_err(|_| StandingRefusal::IntegrityFailure)?;
        // Nothing may trail the signed fields.
        if !rest.is_empty() {
            return Err(StandingRefusal::IntegrityFailure);
        }

        let grant = StandingGrant::issue(
            StandingGrantId::from_bytes(grant_id),
            StandingScope {
                actor: ActorId::from_bytes(actor),
                act,
                repository: RepositoryIdentity::new(repository),
                attempt_digest: Sha256Digest::from_bytes(digest),
            },
            ClockReading(expires_at),
        );
        // Every accepted parse must re-encode to exactly the bytes that were
        // signed. This is what makes "the scope this token names" and "the
        // scope whose bytes carry the MAC" the same object by construction.
        if Self::payload(&grant) != payload {
            return Err(StandingRefusal::IntegrityFailure);
        }
        Ok(grant)
    }
}
