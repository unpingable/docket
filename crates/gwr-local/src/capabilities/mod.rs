//! Local integrity-protected standing tokens.
//!
//! A token carries an exact standing scope under an HMAC-SHA256 tag. Integrity
//! verification establishes only that the runtime issued these exact bytes;
//! validity (expiry, consumption) is judged against the store's projection.
//! Tokens are never exposed to labor providers, and nothing a provider holds is
//! standing.

use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::{GrantState, StandingAct, StandingGrant, StandingScope};
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

    fn payload(grant: &StandingGrant) -> String {
        format!(
            "{TOKEN_PREFIX}|{}|{}|{}|{}|{}|{}",
            hex16(grant.id.as_bytes()),
            hex16(grant.scope.actor.as_bytes()),
            act_tag(grant.scope.act),
            grant.scope.repository.as_str(),
            grant.scope.attempt_digest.to_hex(),
            grant.expires_at.0
        )
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

        let mut parts = payload.split('|');
        let prefix = parts.next().ok_or(StandingRefusal::IntegrityFailure)?;
        if prefix != TOKEN_PREFIX {
            return Err(StandingRefusal::IntegrityFailure);
        }
        let mut grant_id = [0u8; 16];
        unhex(
            parts.next().ok_or(StandingRefusal::IntegrityFailure)?,
            &mut grant_id,
        )?;
        let mut actor = [0u8; 16];
        unhex(
            parts.next().ok_or(StandingRefusal::IntegrityFailure)?,
            &mut actor,
        )?;
        let act = match parts.next().ok_or(StandingRefusal::IntegrityFailure)? {
            "ratify" => StandingAct::Ratify,
            "resolve_recovery" => StandingAct::ResolveRecovery,
            _ => return Err(StandingRefusal::IntegrityFailure),
        };
        let repository = parts.next().ok_or(StandingRefusal::IntegrityFailure)?;
        let mut digest = [0u8; 32];
        unhex(
            parts.next().ok_or(StandingRefusal::IntegrityFailure)?,
            &mut digest,
        )?;
        let expires_at: u64 = parts
            .next()
            .ok_or(StandingRefusal::IntegrityFailure)?
            .parse()
            .map_err(|_| StandingRefusal::IntegrityFailure)?;
        Ok(StandingGrant {
            id: StandingGrantId::from_bytes(grant_id),
            scope: StandingScope {
                actor: ActorId::from_bytes(actor),
                act,
                repository: RepositoryIdentity::new(repository),
                attempt_digest: Sha256Digest::from_bytes(digest),
            },
            expires_at: ClockReading(expires_at),
            state: GrantState::Available,
        })
    }
}
