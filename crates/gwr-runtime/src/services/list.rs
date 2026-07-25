//! The canonical attempt-list read model: enough to distinguish attempts
//! without opening each dossier.
//!
//! One assembled value sources both renderings. The summary holds complete
//! values; only the human renderer truncates (repository tails, path counts),
//! and the JSON rendering retains every value in full.

use crate::ports::store::{Store, StoreError};
use crate::services::dossier::{state_tag, Settlement};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::AttemptId;
use gwr_core::lifecycle::AttemptState;
use gwr_core::work_request::{ClockReading, RefName, RepositoryIdentity};

/// The versioned JSON format identifier for attempt lists.
pub const LIST_FORMAT: &str = "gwr:attempt-list:v1";

/// One attempt, summarized from records the runtime already owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptSummary {
    pub attempt: AttemptId,
    pub admitted_at: ClockReading,
    pub state: AttemptState,
    pub version: u64,
    pub effect_class: &'static str,
    pub repository: RepositoryIdentity,
    pub target_ref: RefName,
    pub allowed_paths: Vec<String>,
    pub settlement: Settlement,
    /// True when the terminal result is a recovery verdict — valid only
    /// relative to the asserted `ExclusiveRefCustody` premise.
    pub premise_qualified: bool,
    /// Residual obligations on file. No discharge mechanism exists in this
    /// runtime, so every recorded obligation is outstanding.
    pub obligations_outstanding: usize,
}

fn settlement_of(state: &AttemptState) -> Settlement {
    match state {
        AttemptState::Prepared | AttemptState::Ratified { .. } | AttemptState::Reserved { .. } => {
            Settlement::NotDispatched
        }
        AttemptState::Dispatching { .. } | AttemptState::Indeterminate { .. } => {
            Settlement::Unresolved
        }
        AttemptState::Committed { .. } => Settlement::Normal,
        AttemptState::DispatchRefused { .. } => Settlement::Refused,
        AttemptState::CommittedViaRecovery { .. } | AttemptState::ProvenNotCommitted { .. } => {
            Settlement::Recovered
        }
    }
}

/// Summarize one attempt from the store alone.
pub fn assemble_summary(
    store: &mut dyn Store,
    attempt_id: AttemptId,
) -> Result<AttemptSummary, StoreError> {
    let projected = store.get_attempt(attempt_id)?;
    let obligations = store.get_residual_obligations(attempt_id)?;
    let settlement = settlement_of(&projected.state);
    Ok(AttemptSummary {
        attempt: attempt_id,
        admitted_at: projected.attempt.admitted_at,
        effect_class: GitRefEffect::KIND,
        repository: projected.attempt.repository.clone(),
        target_ref: projected.attempt.effect.target_ref.clone(),
        allowed_paths: projected.attempt.effect.allowed_paths.clone(),
        premise_qualified: settlement == Settlement::Recovered,
        settlement,
        state: projected.state,
        version: projected.version,
        obligations_outstanding: obligations.len(),
    })
}

/// Summarize every attempt, in the store's listing order.
pub fn assemble_list(store: &mut dyn Store) -> Result<Vec<AttemptSummary>, StoreError> {
    let ids = store.list_attempts()?;
    ids.into_iter()
        .map(|id| assemble_summary(store, id))
        .collect()
}

fn hx(bytes: &[u8; 16]) -> String {
    bytes.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Truncate a long value for the human table, keeping the distinguishing
/// tail. Human rendering only; JSON always carries complete values.
fn tail(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        let kept: String = chars[chars.len() - (max - 1)..].iter().collect();
        format!("…{kept}")
    }
}

fn scope_summary(paths: &[String]) -> String {
    match paths.split_first() {
        None => "none".into(),
        Some((first, [])) => tail(first, 28),
        Some((first, rest)) => format!("{}+{}", tail(first, 24), rest.len()),
    }
}

/// Human rendering: one line per attempt, truncated where long.
pub fn render_list_text(list: &[AttemptSummary]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for s in list {
        let _ = writeln!(
            out,
            "attempt {} state {} settlement {}{} admitted_at_ms {} class {} repo {} ref {} \
             scope {} obligations {}",
            hx(s.attempt.as_bytes()),
            state_tag(&s.state),
            s.settlement.tag(),
            if s.premise_qualified {
                " (premise-qualified)"
            } else {
                ""
            },
            s.admitted_at.0,
            s.effect_class,
            tail(s.repository.as_str(), 28),
            s.target_ref.as_str(),
            scope_summary(&s.allowed_paths),
            s.obligations_outstanding,
        );
    }
    out
}

fn js(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Versioned JSON rendering with complete, untruncated values.
pub fn render_list_json(list: &[AttemptSummary]) -> String {
    let rows: Vec<String> = list
        .iter()
        .map(|s| {
            let paths: Vec<String> = s.allowed_paths.iter().map(|p| js(p)).collect();
            format!(
                "{{\"attempt\":{},\"state\":{},\"version\":{},\"settlement\":{},\
                 \"premise_qualified\":{},\"admitted_at_ms\":{},\"effect_class\":{},\
                 \"repository\":{},\"target_ref\":{},\"allowed_paths\":[{}],\
                 \"obligations_outstanding\":{}}}",
                js(&hx(s.attempt.as_bytes())),
                js(state_tag(&s.state)),
                s.version,
                js(s.settlement.tag()),
                s.premise_qualified,
                s.admitted_at.0,
                js(s.effect_class),
                js(s.repository.as_str()),
                js(s.target_ref.as_str()),
                paths.join(","),
                s.obligations_outstanding,
            )
        })
        .collect();
    format!(
        "{{\"list_format\":{},\"attempts\":[{}]}}",
        js(LIST_FORMAT),
        rows.join(",")
    )
}
