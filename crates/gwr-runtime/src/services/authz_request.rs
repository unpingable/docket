//! The canonical authorization-request projection, `gwr:authz-request:v1`.
//!
//! An upstream authorization office (AG) decides whether exact proposed work
//! may receive authority. To decide, it needs the exact proposal — and only
//! the proposal. This module projects the *stored prepared attempt* into one
//! versioned request value; both renderings are pure functions of it, so
//! there is no second source of truth and no prose for a machine to parse.
//!
//! What this projection is: **testimony about a prepared proposal**. It is
//! not authority, not a grant, and not a request for execution. Docket mints
//! nothing when it emits one, and an upstream office that receives one gains
//! nothing but the facts needed to decide.
//!
//! The `settlement_premises` it carries are Docket's own effect-class
//! premises, declared so the upstream office can see the terms Docket will
//! later settle under. They remain Docket's premises: an authorization
//! office does not adopt them, and its own authorization premises come back
//! separately in its issuance record.

use crate::ports::store::{Store, StoreError};
use crate::services::dossier::{js, js_str_arr, DossierError};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::{AttemptId, CandidateArtifactId, PreparationRunId, WorkRequestId};
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::work_request::ClockReading;

/// The request format identifier, carried in every rendering. Any change to
/// the field set or encodings is a version bump here, not an edit.
pub const AUTHZ_REQUEST_FORMAT: &str = "gwr:authz-request:v1";

/// One authorization request: the exact proposal, projected from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthzRequest {
    pub attempt: AttemptId,
    pub attempt_version: u64,
    pub work_request: WorkRequestId,
    pub preparation_run: PreparationRunId,
    pub candidate: CandidateArtifactId,
    pub goal: String,
    /// The actor the proposer asks to be authorized to ratify. Operator
    /// input at request time, echoed by the upstream office and re-checked
    /// by Docket at intake — never an assertion Docket takes on faith.
    pub requested_actor: String,
    pub attempt_record: PreparedAttempt,
    pub candidate_digest: gwr_core::digest::Sha256Digest,
    pub request_created_at: ClockReading,
}

/// Assemble the request for an attempt from the store alone.
pub fn assemble(
    store: &mut dyn Store,
    attempt_id: AttemptId,
    requested_actor: &str,
) -> Result<AuthzRequest, DossierError> {
    let projected = store.get_attempt(attempt_id)?;
    let wr = store.get_work_request(projected.attempt.work_request)?;
    let candidate = store.get_candidate(projected.attempt.candidate)?;
    Ok(AuthzRequest {
        attempt: attempt_id,
        attempt_version: projected.version,
        work_request: wr.id,
        preparation_run: candidate.preparation_run,
        candidate: candidate.id,
        goal: wr.goal,
        requested_actor: requested_actor.to_string(),
        candidate_digest: candidate.content_digest,
        request_created_at: wr.created_at,
        attempt_record: projected.attempt,
    })
}

/// A missing attempt is an ordinary read error here.
impl From<StoreError> for AuthzRequestError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthzRequestError {
    Store(StoreError),
}

fn hx(bytes: &[u8; 16]) -> String {
    bytes.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The versioned JSON rendering — the only form an upstream office consumes.
pub fn render_json(r: &AuthzRequest) -> String {
    let a = &r.attempt_record;
    let premises: Vec<String> = GitRefEffect::SETTLEMENT_PREMISES
        .iter()
        .map(|p| js(p.tag()))
        .collect();
    format!(
        "{{\"authz_request_format\":{},\"attempt\":{},\"attempt_version\":{},\
         \"effect_class\":{},\"prepared_attempt_digest\":{},\"repository\":{},\
         \"target_ref\":{},\"basis\":{},\"allowed_paths\":{},\
         \"settlement_premises\":[{}],\"requested_actor\":{},\"goal\":{},\
         \"work_request\":{},\"preparation_run\":{},\"candidate\":{},\
         \"candidate_digest\":{},\"request_created_at_ms\":{},\"admitted_at_ms\":{}}}",
        js(AUTHZ_REQUEST_FORMAT),
        js(&hx(r.attempt.as_bytes())),
        r.attempt_version,
        js(GitRefEffect::KIND),
        js(&a.prepared_attempt_digest.to_hex()),
        js(a.repository.as_str()),
        js(a.effect.target_ref.as_str()),
        js(a.basis.as_str()),
        js_str_arr(&a.effect.allowed_paths),
        premises.join(","),
        js(&r.requested_actor),
        js(&r.goal),
        js(&hx(r.work_request.as_bytes())),
        js(&hx(r.preparation_run.as_bytes())),
        js(&hx(r.candidate.as_bytes())),
        js(&r.candidate_digest.to_hex()),
        r.request_created_at.0,
        a.admitted_at.0,
    )
}

/// The human rendering. Same source value as the JSON rendering; an upstream
/// office never reads this.
pub fn render_text(r: &AuthzRequest) -> String {
    use std::fmt::Write as _;
    let a = &r.attempt_record;
    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(w, "authz_request_format {AUTHZ_REQUEST_FORMAT}");
    let _ = writeln!(w, "attempt {}", hx(r.attempt.as_bytes()));
    let _ = writeln!(w, "attempt_version {}", r.attempt_version);
    let _ = writeln!(w, "effect_class {}", GitRefEffect::KIND);
    let _ = writeln!(
        w,
        "prepared_attempt_digest {}",
        a.prepared_attempt_digest.to_hex()
    );
    let _ = writeln!(w, "repository {}", a.repository.as_str());
    let _ = writeln!(w, "target_ref {}", a.effect.target_ref.as_str());
    let _ = writeln!(w, "basis {}", a.basis.as_str());
    for p in &a.effect.allowed_paths {
        let _ = writeln!(w, "allowed_path {p}");
    }
    for p in GitRefEffect::SETTLEMENT_PREMISES {
        let _ = writeln!(w, "settlement_premise {}", p.tag());
    }
    let _ = writeln!(w, "requested_actor {}", r.requested_actor);
    let _ = writeln!(w, "goal {}", r.goal);
    let _ = writeln!(w, "work_request {}", hx(r.work_request.as_bytes()));
    let _ = writeln!(w, "preparation_run {}", hx(r.preparation_run.as_bytes()));
    let _ = writeln!(
        w,
        "candidate {} digest {}",
        hx(r.candidate.as_bytes()),
        r.candidate_digest.to_hex()
    );
    let _ = writeln!(
        w,
        "request_created_at_ms {} admitted_at_ms {}",
        r.request_created_at.0, a.admitted_at.0
    );
    let _ = writeln!(
        w,
        "note: this projection is testimony about a prepared proposal; it is \
         not authority, and emitting it mints nothing"
    );
    out
}
