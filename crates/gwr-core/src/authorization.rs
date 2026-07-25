//! Upstream authorization records.
//!
//! An upstream authorization office decides whether exact proposed work may
//! receive authority. Docket does not re-decide that question: it verifies
//! that an authenticated issuance names *this exact prepared attempt*, records
//! the issuance as the basis, and then mints its own local standing.
//!
//! The types here are the shape of what Docket accepts and stores. None of
//! them is authority:
//!
//! - an issuance is an authenticated immutable fact about someone else's
//!   decision; presenting one to the broker is impossible, because the broker
//!   never sees one;
//! - upstream premises are recorded as *upstream* premises. They are not
//!   effect-class settlement premises, they are never merged with them, and
//!   Docket never claims to have verified them;
//! - upstream residual obligations are carried in their source vocabulary,
//!   undischarged. Docket's own `ObligationKind` is a different thing and the
//!   two are deliberately not interchangeable.

use crate::work_request::ClockReading;

/// Where a standing grant's authorization came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthorizationSource {
    /// Minted on local operator authority (the bootstrap path).
    Local,
    /// Minted after verifying an upstream authorization issuance.
    Upstream,
}

impl AuthorizationSource {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Upstream => "upstream",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "local" => Some(Self::Local),
            "upstream" => Some(Self::Upstream),
            _ => None,
        }
    }
}

/// One upstream authorization premise: something the upstream office assumed
/// rather than verified. Kept in its own type so it can never be confused with
/// [`crate::effect_spec::SettlementPremise`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UpstreamPremise {
    pub kind: String,
    pub statement: String,
}

/// Whether the upstream decision carried residual obligations — and, when it
/// did not, whether that is a finding or a limitation of the producer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpstreamResidualStatus {
    /// The upstream decision recorded no residual obligations.
    NoneRecorded,
    /// The upstream office cannot express residual obligations. Absence is a
    /// limitation of the producer, not evidence about the decision.
    Unrepresented,
    /// Residual obligations are present.
    Present,
}

impl UpstreamResidualStatus {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::NoneRecorded => "none_recorded",
            Self::Unrepresented => "unrepresented",
            Self::Present => "present",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "none_recorded" => Some(Self::NoneRecorded),
            "unrepresented" => Some(Self::Unrepresented),
            "present" => Some(Self::Present),
            _ => None,
        }
    }
}

/// One upstream residual obligation, in the source's own vocabulary. Docket
/// never discharges one and never rewrites it into a native obligation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UpstreamResidual {
    pub source_system: String,
    pub obligation_id: String,
    pub subject: String,
    pub kind: String,
    pub statement: String,
}

/// An accepted upstream issuance, exactly as Docket verified and stored it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AcceptedIssuance {
    pub issuance_id: String,
    pub attempt: crate::ids::AttemptId,
    pub decision_id: String,
    pub issuer_principal: String,
    pub issuer_key_id: String,
    pub target_id: String,
    /// Plain byte digest of the authorization request, in Docket's domain.
    pub request_raw_sha256: String,
    /// The upstream office's own canonical digest of the same request bytes.
    /// Distinct from `request_raw_sha256`; neither is derived from the other.
    pub request_upstream_digest: String,
    /// Docket's prepared-attempt transcript digest as the issuance echoed it,
    /// after Docket compared it against its own stored attempt.
    pub prepared_digest: crate::digest::Sha256Digest,
    pub requested_actor: String,
    pub issued_at: ClockReading,
    pub expires_at: ClockReading,
    pub premises: Vec<UpstreamPremise>,
    pub residual_status: UpstreamResidualStatus,
    pub residuals: Vec<UpstreamResidual>,
    /// The upstream office's own record that it burned its decision authority.
    /// A record of their burn, never a burn Docket can perform or reuse.
    pub consumption_ledger: String,
    pub consumption_use_digest: String,
    /// The exact signed body bytes, base64url-no-pad, retained so a later
    /// reader can re-verify the signature over precisely what was accepted.
    pub body_b64: String,
    pub accepted_at: ClockReading,
}
