//! Intake of an authenticated upstream authorization issuance.
//!
//! An upstream office decides whether exact proposed work may receive
//! authority and emits an authenticated immutable issuance record. This module
//! verifies such a record **against Docket's own stored prepared attempt** and,
//! only if every binding matches, records the issuance and lets the caller mint
//! local standing.
//!
//! The office boundary, enforced here rather than described:
//!
//! - **Docket never re-decides the upstream policy question.** Nothing in this
//!   module evaluates a catalog, a principal chain's authority, or whether the
//!   decision was wise. It checks authenticity, freshness, and exact binding —
//!   custody questions, not policy ones.
//! - **The issuance is not authority.** It cannot be presented to the broker;
//!   it mints nothing by itself. Verification lets Docket mint *its own*
//!   standing, bound to the exact attempt and digest, single-use, expiring no
//!   later than the issuance.
//! - **The issuance is never its own yardstick.** Every Docket-owned field it
//!   echoes is compared against the stored attempt. A record that disagrees is
//!   refused; a record that agrees adds no authority, only a recorded basis.
//! - **Upstream premises and residuals are carried, not adopted.** They are
//!   stored in upstream vocabulary, exposed as upstream facts, never merged
//!   into settlement premises or Docket obligations, and never discharged.

use gwr_core::authorization::{
    AcceptedIssuance, UpstreamPremise, UpstreamResidual, UpstreamResidualStatus,
};
use gwr_core::digest::Sha256Digest;
use gwr_core::ids::AttemptId;
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::work_request::ClockReading;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

/// The issuance envelope schema Docket accepts.
pub const ISSUANCE_SCHEMA: &str = "ag.docket-issuance:v1";

/// The request schema Docket produces and the issuance must name.
pub const REQUEST_SCHEMA: &str = "gwr:authz-request:v1";

/// Signature prefix, matching the producing office's statement domain. A
/// signature over another statement kind cannot be replayed as an issuance.
const SIGNATURE_PREFIX: &[u8] = b"ag-ng\0docket-issuance-signature\0v1\0";

/// One trusted upstream issuer. Trust is explicit configuration: an unlisted
/// issuer, or a listed issuer with a different key, is refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedIssuer {
    pub issuer_principal: String,
    pub key_id: String,
    /// Canonical base64url-no-pad Ed25519 public key.
    pub public_key: String,
}

/// The configured set of trusted upstream issuers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerTrustConfig {
    pub issuers: Vec<TrustedIssuer>,
}

impl IssuerTrustConfig {
    /// Parse a trust configuration. Unknown fields are refused: a
    /// misunderstood trust file must not silently trust more than intended.
    pub fn parse(bytes: &[u8]) -> Result<Self, IntakeRefusal> {
        serde_json::from_slice(bytes).map_err(|e| IntakeRefusal::Malformed {
            detail: format!("trust configuration: {e}"),
        })
    }

    fn find(&self, principal: &str, key_id: &str) -> Option<&TrustedIssuer> {
        self.issuers
            .iter()
            .find(|i| i.issuer_principal == principal && i.key_id == key_id)
    }
}

// ---------------------------------------------------------------------------
// Wire shapes. Strictly decoded: an unknown field means this is not the
// supported record.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    /// Checked by the schema probe before this struct is decoded; retained in
    /// the shape so `deny_unknown_fields` describes the whole envelope.
    #[allow(dead_code)]
    schema: String,
    body_b64: String,
    authentication: Authentication,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authentication {
    signer_key_id: String,
    /// The key the envelope nominates. Recorded for comparison against the
    /// trusted key; verification never uses this value.
    signer_public_key: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    issuance_id: String,
    decision_id: String,
    issuer_principal: String,
    issuer_key_id: String,
    decision_context: DecisionContext,
    principal_chain: Vec<String>,
    target_id: String,
    request_source: RequestSource,
    docket: DocketBinding,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    premises: Vec<Premise>,
    residual_obligations: Residuals,
    consumption: Consumption,
    decision: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionContext {
    authority_domain: String,
    epoch: u64,
    lifecycle_nonce: String,
    catalog_identity: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestSource {
    schema: String,
    raw_sha256: String,
    ag_canonical_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocketBinding {
    attempt: String,
    prepared_attempt_digest: String,
    effect_class: String,
    repository: String,
    target_ref: String,
    basis: String,
    allowed_paths: Vec<String>,
    requested_actor: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Premise {
    kind: String,
    statement: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Residuals {
    status: String,
    items: Vec<ResidualItem>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResidualItem {
    source_system: String,
    obligation_id: String,
    subject: String,
    kind: String,
    statement: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Consumption {
    ledger: String,
    use_digest: String,
}

// ---------------------------------------------------------------------------
// Typed refusals. Every one of them mints nothing and stores nothing.
// ---------------------------------------------------------------------------

/// Why an issuance was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntakeRefusal {
    /// Not the supported issuance schema.
    UnsupportedSchema { found: String },
    /// Structurally not a supported issuance (or trust configuration).
    Malformed { detail: String },
    /// The issuer is not in the trust configuration, or the presented key
    /// differs from the trusted one.
    UntrustedIssuer { principal: String, key_id: String },
    /// The signature does not verify over the exact body bytes.
    AuthenticationFailed,
    /// The record reports something other than an admitted decision.
    NotAdmitted { decision: String },
    /// The issuance has expired against the runtime clock.
    Expired { expires_at: u64, now: u64 },
    /// A field the issuance echoes disagrees with Docket's stored attempt.
    /// Docket owns the comparison value; the record never supplies both a
    /// claim and its yardstick.
    BindingMismatch {
        field: &'static str,
        expected: String,
        presented: String,
    },
    /// The request source is not the supported Docket request schema.
    UnsupportedRequestSchema { found: String },
    /// An upstream residual set is internally inconsistent.
    InconsistentResiduals { detail: String },
    /// This issuance identity was already accepted with different bytes.
    IssuanceSubstitution { issuance_id: String },
    /// This issuance already minted standing.
    AlreadyMinted { issuance_id: String },
    /// Persistence failure.
    Store { detail: String },
}

impl std::fmt::Display for IntakeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchema { found } => write!(
                f,
                "unsupported_schema: expected {ISSUANCE_SCHEMA:?}, found {found:?}"
            ),
            Self::Malformed { detail } => write!(f, "malformed_issuance: {detail}"),
            Self::UntrustedIssuer { principal, key_id } => write!(
                f,
                "untrusted_issuer: no trusted issuer {principal:?} with key {key_id:?}"
            ),
            Self::AuthenticationFailed => write!(f, "authentication_failed: signature invalid"),
            Self::NotAdmitted { decision } => {
                write!(f, "not_admitted: decision is {decision:?}, not \"admitted\"")
            }
            Self::Expired { expires_at, now } => {
                write!(f, "expired: expires_at {expires_at}, now {now}")
            }
            Self::BindingMismatch {
                field,
                expected,
                presented,
            } => write!(
                f,
                "binding_mismatch: {field} — docket holds {expected:?}, issuance names {presented:?}"
            ),
            Self::UnsupportedRequestSchema { found } => write!(
                f,
                "unsupported_request_schema: expected {REQUEST_SCHEMA:?}, found {found:?}"
            ),
            Self::InconsistentResiduals { detail } => {
                write!(f, "inconsistent_residuals: {detail}")
            }
            Self::IssuanceSubstitution { issuance_id } => write!(
                f,
                "issuance_substitution: {issuance_id} was accepted with different bytes"
            ),
            Self::AlreadyMinted { issuance_id } => {
                write!(f, "already_minted: {issuance_id} already minted standing")
            }
            Self::Store { detail } => write!(f, "store_error: {detail}"),
        }
    }
}

fn b64_decode(value: &str) -> Result<Vec<u8>, IntakeRefusal> {
    // Canonical base64url without padding, decoded by hand so a non-canonical
    // encoding cannot slip through a permissive decoder.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bad = || IntakeRefusal::Malformed {
        detail: "value is not canonical base64url-no-pad".to_string(),
    };
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(value.len() * 3 / 4);
    for ch in value.bytes() {
        let idx = ALPHABET.iter().position(|c| *c == ch).ok_or_else(bad)? as u32;
        acc = (acc << 6) | idx;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Leftover bits must be zero; otherwise the encoding is non-canonical.
    if bits >= 6 || (acc & ((1 << bits) - 1)) != 0 {
        return Err(bad());
    }
    Ok(out)
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let mut s = String::from("sha256:");
    for b in h.finalize() {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn mismatch(
    field: &'static str,
    expected: impl Into<String>,
    presented: impl Into<String>,
) -> IntakeRefusal {
    IntakeRefusal::BindingMismatch {
        field,
        expected: expected.into(),
        presented: presented.into(),
    }
}

/// The result of verifying an issuance: the accepted record, ready to be
/// persisted and to justify one local standing grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIssuance {
    pub accepted: AcceptedIssuance,
    /// The exact request-bytes digest the issuance names, in Docket's domain.
    /// Retained so a caller holding the request can confirm it independently.
    pub request_raw_sha256: String,
}

/// Verify an issuance against Docket's stored prepared attempt.
///
/// Pure over its inputs: no I/O, no persistence, no minting. Every
/// Docket-owned field is compared against `attempt`; the record's own echoes
/// are never used as the comparison baseline.
#[allow(clippy::too_many_lines)]
pub fn verify_issuance(
    bytes: &[u8],
    attempt: &PreparedAttempt,
    attempt_id: AttemptId,
    trust: &IssuerTrustConfig,
    now: ClockReading,
) -> Result<VerifiedIssuance, IntakeRefusal> {
    // Schema probe before strict parse, so a foreign document refuses as
    // unsupported rather than malformed.
    let probe: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| IntakeRefusal::Malformed {
            detail: format!("not JSON: {e}"),
        })?;
    let found = probe
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(absent)")
        .to_string();
    if found != ISSUANCE_SCHEMA {
        return Err(IntakeRefusal::UnsupportedSchema { found });
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|e| IntakeRefusal::Malformed {
            detail: e.to_string(),
        })?;

    // 1. Decode the exact body bytes. Trust and authentication are checked
    //    against the body's own issuer identity, which the signature covers.
    let body_bytes = b64_decode(&envelope.body_b64)?;
    let body: Body = serde_json::from_slice(&body_bytes).map_err(|e| IntakeRefusal::Malformed {
        detail: format!("issuance body: {e}"),
    })?;

    // 2. Trust: an explicitly configured issuer, with exactly its key. The
    //    key used for verification is the *trusted* one, never the key the
    //    envelope carries — a record cannot nominate its own verifier.
    let trusted = trust
        .find(&body.issuer_principal, &body.issuer_key_id)
        .ok_or_else(|| IntakeRefusal::UntrustedIssuer {
            principal: body.issuer_principal.clone(),
            key_id: body.issuer_key_id.clone(),
        })?;
    if trusted.public_key != envelope.authentication.signer_public_key
        || body.issuer_key_id != envelope.authentication.signer_key_id
    {
        return Err(IntakeRefusal::UntrustedIssuer {
            principal: body.issuer_principal.clone(),
            key_id: body.issuer_key_id.clone(),
        });
    }
    // 3. Authentication over the exact body bytes, under the trusted key.
    let public_key = b64_decode(&trusted.public_key)?;
    let signature = b64_decode(&envelope.authentication.signature)?;
    let mut message = Vec::with_capacity(SIGNATURE_PREFIX.len() + body_bytes.len());
    message.extend_from_slice(SIGNATURE_PREFIX);
    message.extend_from_slice(&body_bytes);
    UnparsedPublicKey::new(&ED25519, &public_key)
        .verify(&message, &signature)
        .map_err(|_| IntakeRefusal::AuthenticationFailed)?;

    // 4. Decision must be an admission. A refusal object never mints anything.
    if body.decision != "admitted" {
        return Err(IntakeRefusal::NotAdmitted {
            decision: body.decision,
        });
    }

    // 5. Freshness against the runtime clock.
    if now.0 >= body.expires_at_unix_ms {
        return Err(IntakeRefusal::Expired {
            expires_at: body.expires_at_unix_ms,
            now: now.0,
        });
    }

    // 6. Request schema.
    if body.request_source.schema != REQUEST_SCHEMA {
        return Err(IntakeRefusal::UnsupportedRequestSchema {
            found: body.request_source.schema,
        });
    }

    // 7. Exact binding against Docket's own stored attempt. Docket owns every
    //    comparison value here.
    let expected_attempt = hex16(attempt_id.as_bytes());
    if body.docket.attempt != expected_attempt {
        return Err(mismatch("attempt", expected_attempt, body.docket.attempt));
    }
    let expected_digest = attempt.prepared_attempt_digest.to_hex();
    if body.docket.prepared_attempt_digest != expected_digest {
        return Err(mismatch(
            "prepared_attempt_digest",
            expected_digest,
            body.docket.prepared_attempt_digest,
        ));
    }
    let expected_class = gwr_core::effect_spec::GitRefEffect::KIND;
    if body.docket.effect_class != expected_class {
        return Err(mismatch(
            "effect_class",
            expected_class,
            body.docket.effect_class,
        ));
    }
    if body.docket.repository != attempt.repository.as_str() {
        return Err(mismatch(
            "repository",
            attempt.repository.as_str(),
            body.docket.repository,
        ));
    }
    if body.docket.target_ref != attempt.effect.target_ref.as_str() {
        return Err(mismatch(
            "target_ref",
            attempt.effect.target_ref.as_str(),
            body.docket.target_ref,
        ));
    }
    if body.docket.basis != attempt.basis.as_str() {
        return Err(mismatch("basis", attempt.basis.as_str(), body.docket.basis));
    }
    if body.docket.allowed_paths != attempt.effect.allowed_paths {
        return Err(mismatch(
            "allowed_paths",
            attempt.effect.allowed_paths.join(","),
            body.docket.allowed_paths.join(","),
        ));
    }

    // 8. Residual consistency: a status claiming items must carry them, and a
    //    status claiming none must not.
    let residual_status = UpstreamResidualStatus::from_tag(&body.residual_obligations.status)
        .ok_or_else(|| IntakeRefusal::InconsistentResiduals {
            detail: format!("unknown status {:?}", body.residual_obligations.status),
        })?;
    let has_items = !body.residual_obligations.items.is_empty();
    match (residual_status, has_items) {
        (UpstreamResidualStatus::Present, false) => {
            return Err(IntakeRefusal::InconsistentResiduals {
                detail: "status is present but no residual items are carried".into(),
            })
        }
        (UpstreamResidualStatus::NoneRecorded | UpstreamResidualStatus::Unrepresented, true) => {
            return Err(IntakeRefusal::InconsistentResiduals {
                detail: format!(
                    "status is {} but residual items are carried",
                    residual_status.tag()
                ),
            })
        }
        _ => {}
    }

    let accepted = AcceptedIssuance {
        issuance_id: body.issuance_id,
        attempt: attempt_id,
        decision_id: body.decision_id,
        issuer_principal: body.issuer_principal,
        issuer_key_id: body.issuer_key_id,
        target_id: body.target_id,
        request_raw_sha256: body.request_source.raw_sha256.clone(),
        request_upstream_digest: body.request_source.ag_canonical_digest,
        prepared_digest: attempt.prepared_attempt_digest,
        requested_actor: body.docket.requested_actor,
        issued_at: ClockReading(body.issued_at_unix_ms),
        expires_at: ClockReading(body.expires_at_unix_ms),
        premises: body
            .premises
            .into_iter()
            .map(|p| UpstreamPremise {
                kind: p.kind,
                statement: p.statement,
            })
            .collect(),
        residual_status,
        residuals: body
            .residual_obligations
            .items
            .into_iter()
            .map(|r| UpstreamResidual {
                source_system: r.source_system,
                obligation_id: r.obligation_id,
                subject: r.subject,
                kind: r.kind,
                statement: r.statement,
            })
            .collect(),
        consumption_ledger: body.consumption.ledger,
        consumption_use_digest: body.consumption.use_digest,
        body_b64: envelope.body_b64,
        accepted_at: now,
    };
    // Fields decoded for completeness of the strict schema but not otherwise
    // used by Docket: the upstream decision context and principal chain are
    // upstream facts. They are authenticated, and they are exposed from the
    // retained body bytes rather than re-modelled here.
    let _ = (
        body.decision_context.authority_domain,
        body.decision_context.epoch,
        body.decision_context.lifecycle_nonce,
        body.decision_context.catalog_identity,
        body.principal_chain,
    );
    Ok(VerifiedIssuance {
        request_raw_sha256: body.request_source.raw_sha256,
        accepted,
    })
}

/// Confirm that the issuance names exactly these request bytes, in Docket's
/// own digest domain. Optional: a caller that still holds the request it
/// exported can close the loop rather than trusting the echo.
pub fn confirm_request_bytes(
    verified: &VerifiedIssuance,
    request_bytes: &[u8],
) -> Result<(), IntakeRefusal> {
    let actual = sha256_prefixed(request_bytes);
    if actual != verified.request_raw_sha256 {
        return Err(mismatch(
            "request_raw_sha256",
            actual,
            verified.request_raw_sha256.clone(),
        ));
    }
    Ok(())
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The digest Docket computes over an authorization request it exported.
#[must_use]
pub fn request_digest(request_bytes: &[u8]) -> String {
    sha256_prefixed(request_bytes)
}

/// Re-verify a stored issuance's signature over its retained body bytes.
/// Available so a reader can confirm that what was accepted is what is stored.
pub fn reverify_stored(
    accepted: &AcceptedIssuance,
    trust: &IssuerTrustConfig,
    signature_b64: &str,
) -> Result<(), IntakeRefusal> {
    let trusted = trust
        .find(&accepted.issuer_principal, &accepted.issuer_key_id)
        .ok_or_else(|| IntakeRefusal::UntrustedIssuer {
            principal: accepted.issuer_principal.clone(),
            key_id: accepted.issuer_key_id.clone(),
        })?;
    let body_bytes = b64_decode(&accepted.body_b64)?;
    let public_key = b64_decode(&trusted.public_key)?;
    let signature = b64_decode(signature_b64)?;
    let mut message = Vec::with_capacity(SIGNATURE_PREFIX.len() + body_bytes.len());
    message.extend_from_slice(SIGNATURE_PREFIX);
    message.extend_from_slice(&body_bytes);
    UnparsedPublicKey::new(&ED25519, &public_key)
        .verify(&message, &signature)
        .map_err(|_| IntakeRefusal::AuthenticationFailed)
}

/// A digest of the exact issuance bytes, used to detect substitution under an
/// identity already accepted.
#[must_use]
pub fn issuance_bytes_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::of_bytes(bytes)
}
