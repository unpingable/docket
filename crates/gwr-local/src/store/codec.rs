//! Exact, explicit encodings between core types and SQLite columns. No JSON,
//! no serde: every tag and list format here is part of the store's schema.

use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::StandingAct;
use gwr_core::ids::*;
use gwr_core::lifecycle::{
    AttemptState, DispatchRef, RatificationRef, RecoveryResolutionRef, RecoveryVerdict,
    ReservationRef,
};
use gwr_core::preparation::PreparationEnd;
use gwr_core::reconciliation::ObligationKind;
use gwr_core::recovery::FactSource;
use gwr_core::refusal::{DispatchRefusalGround, ObservationRefusal, RelianceRefusal};
use gwr_core::work_request::{CommitHash, RefName, RepositoryIdentity};
use gwr_runtime::ports::store::StoreError;

/// List encoding: length-prefixed, so `decode(encode(x)) == x` for every list
/// of strings the admitted domain can contain.
///
/// A delimiter-joined encoding was not injective: a path containing the
/// delimiter split into two on read, so an admitted attempt came back as a
/// different object with a different binding digest, and the digest handed to
/// the operator could never be ratified. Length prefixes cannot be forged by
/// content because the content is never scanned for structure.
///
/// Format: `<byte-len>:<utf8 bytes>` per element, concatenated.
pub fn join_list<S: AsRef<str>>(items: &[S]) -> String {
    let mut out = String::new();
    for item in items {
        let s = item.as_ref();
        out.push_str(&s.len().to_string());
        out.push(':');
        out.push_str(s);
    }
    out
}

pub fn split_list(encoded: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = encoded.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let Some(colon) = bytes[i..].iter().position(|b| *b == b':') else {
            break;
        };
        let colon = i + colon;
        let Ok(len) = std::str::from_utf8(&bytes[i..colon])
            .unwrap_or("")
            .parse::<usize>()
        else {
            break;
        };
        let start = colon + 1;
        let end = start + len;
        if end > bytes.len() {
            break;
        }
        out.push(String::from_utf8_lossy(&bytes[start..end]).into_owned());
        i = end;
    }
    out
}

pub fn id16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub trait FromBytes16 {
    fn from16(bytes: [u8; 16]) -> Self;
}

macro_rules! impl_from16 {
    ($($t:ty),+ $(,)?) => {
        $(impl FromBytes16 for $t {
            fn from16(bytes: [u8; 16]) -> Self {
                Self::from_bytes(bytes)
            }
        })+
    };
}

impl_from16!(
    WorkRequestId,
    PreparationRunId,
    CandidateArtifactId,
    AttemptId,
    RatificationId,
    StandingGrantId,
    StandingUseId,
    ReservationId,
    ReservationUseId,
    DispatchId,
    ObservationId,
    RecoveryFactId,
    RecoveryResolutionId,
    ObligationId,
    ActorId,
);

fn hex_bytes(hex: &str, out: &mut [u8]) {
    assert_eq!(hex.len(), out.len() * 2, "corrupt hex column: {hex}");
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).expect("corrupt hex column");
        out[i] = u8::from_str_radix(s, 16).expect("corrupt hex column");
    }
}

pub fn parse_id16<T: FromBytes16>(hex: &str) -> T {
    let mut bytes = [0u8; 16];
    hex_bytes(hex, &mut bytes);
    T::from16(bytes)
}

pub fn parse_digest(hex: &str) -> Sha256Digest {
    let mut bytes = [0u8; 32];
    hex_bytes(hex, &mut bytes);
    Sha256Digest::from_bytes(bytes)
}

pub fn repo(s: &str) -> RepositoryIdentity {
    RepositoryIdentity::new(s)
}

pub fn refname(s: &str) -> RefName {
    RefName::new(s)
}

pub fn commit(s: &str) -> CommitHash {
    CommitHash::new(s)
}

pub fn end_tag(end: PreparationEnd) -> &'static str {
    match end {
        PreparationEnd::CandidateProduced => "candidate_produced",
        PreparationEnd::ProviderRefused => "provider_refused",
        PreparationEnd::ProviderFailed => "provider_failed",
        PreparationEnd::Cancelled => "cancelled",
        PreparationEnd::Expired => "expired",
    }
}

pub fn parse_end_tag(tag: &str) -> Result<PreparationEnd, StoreError> {
    Ok(match tag {
        "candidate_produced" => PreparationEnd::CandidateProduced,
        "provider_refused" => PreparationEnd::ProviderRefused,
        "provider_failed" => PreparationEnd::ProviderFailed,
        "cancelled" => PreparationEnd::Cancelled,
        "expired" => PreparationEnd::Expired,
        other => return Err(StoreError::Backend(format!("unknown end tag {other}"))),
    })
}

pub fn act_tag(act: StandingAct) -> &'static str {
    match act {
        StandingAct::Ratify => "ratify",
        StandingAct::ResolveRecovery => "resolve_recovery",
    }
}

pub fn parse_act_tag(tag: &str) -> StandingAct {
    match tag {
        "ratify" => StandingAct::Ratify,
        "resolve_recovery" => StandingAct::ResolveRecovery,
        other => panic!("unknown act tag {other}"),
    }
}

pub fn ground_tag(ground: DispatchRefusalGround) -> &'static str {
    match ground {
        DispatchRefusalGround::BasisMoved => "basis_moved",
        DispatchRefusalGround::ForbiddenPath => "forbidden_path",
        DispatchRefusalGround::InvalidPatch => "invalid_patch",
        DispatchRefusalGround::EnvelopeMismatch => "envelope_mismatch",
    }
}

pub fn parse_ground_tag(tag: &str) -> Result<DispatchRefusalGround, StoreError> {
    Ok(match tag {
        "basis_moved" => DispatchRefusalGround::BasisMoved,
        "forbidden_path" => DispatchRefusalGround::ForbiddenPath,
        "invalid_patch" => DispatchRefusalGround::InvalidPatch,
        "envelope_mismatch" => DispatchRefusalGround::EnvelopeMismatch,
        other => return Err(StoreError::Backend(format!("unknown ground tag {other}"))),
    })
}

pub fn verdict_tag(verdict: RecoveryVerdict) -> &'static str {
    match verdict {
        RecoveryVerdict::CommittedViaRecovery => "committed_via_recovery",
        RecoveryVerdict::ProvenNotCommitted => "proven_not_committed",
    }
}

pub fn obligation_tag(kind: ObligationKind) -> &'static str {
    match kind {
        ObligationKind::HumanReviewBeforeMerge => "human_review_before_merge",
    }
}

pub fn parse_obligation_tag(tag: &str) -> ObligationKind {
    match tag {
        "human_review_before_merge" => ObligationKind::HumanReviewBeforeMerge,
        other => panic!("unknown obligation tag {other}"),
    }
}

pub fn source_tags(source: &FactSource) -> (&'static str, Option<String>) {
    match source {
        FactSource::BrokerJournal => ("broker_journal", None),
        FactSource::RefInspection => ("ref_inspection", None),
        FactSource::OperatorSupplied(detail) => ("operator_supplied", Some(detail.clone())),
    }
}

pub fn parse_source(kind: &str, detail: Option<String>) -> FactSource {
    match kind {
        "broker_journal" => FactSource::BrokerJournal,
        "ref_inspection" => FactSource::RefInspection,
        "operator_supplied" => FactSource::OperatorSupplied(detail.unwrap_or_default()),
        other => panic!("unknown fact source {other}"),
    }
}

pub fn reliance_refusal_tags(refusal: &RelianceRefusal) -> (&'static str, Option<String>) {
    match refusal {
        RelianceRefusal::NoBridge => ("no_bridge", None),
        RelianceRefusal::BridgeVersionUnsupported { presented } => {
            ("bridge_version_unsupported", Some(presented.to_string()))
        }
        RelianceRefusal::ClaimNotAdmissible => ("claim_not_admissible", None),
        RelianceRefusal::OutOfScope => ("out_of_scope", None),
        RelianceRefusal::Observation(ObservationRefusal::ScopeMismatch) => {
            ("observation_scope_mismatch", None)
        }
        RelianceRefusal::Observation(ObservationRefusal::ObservationFailed) => {
            ("observation_failed", None)
        }
    }
}

/// Nullable projection columns, as read.
pub struct ProjCols {
    pub rat_id: Option<String>,
    pub rat_use: Option<String>,
    pub rsv_id: Option<String>,
    pub rsv_use: Option<String>,
    pub dispatch: Option<String>,
    pub ground: Option<String>,
    pub resolution: Option<String>,
}

/// Rebuild the typed state from projection columns. Missing columns for a tag
/// are a corruption error, never a defaulted state.
pub fn reconstruct_state(
    tag: &str,
    cols: &ProjCols,
    prepared_digest: &Sha256Digest,
) -> Result<AttemptState, StoreError> {
    let corrupt = || StoreError::Backend(format!("projection columns incomplete for {tag}"));
    let rat = || -> Result<RatificationRef, StoreError> {
        Ok(RatificationRef {
            ratification: parse_id16(cols.rat_id.as_ref().ok_or_else(corrupt)?),
            prepared_attempt_digest: *prepared_digest,
            standing_use: parse_id16(cols.rat_use.as_ref().ok_or_else(corrupt)?),
        })
    };
    let rsv = || -> Result<ReservationRef, StoreError> {
        Ok(ReservationRef {
            reservation: parse_id16(cols.rsv_id.as_ref().ok_or_else(corrupt)?),
            reservation_use: parse_id16(cols.rsv_use.as_ref().ok_or_else(corrupt)?),
        })
    };
    let dsp = || -> Result<DispatchRef, StoreError> {
        Ok(DispatchRef {
            dispatch: parse_id16(cols.dispatch.as_ref().ok_or_else(corrupt)?),
        })
    };
    let res = || -> Result<RecoveryResolutionRef, StoreError> {
        Ok(RecoveryResolutionRef {
            resolution: parse_id16(cols.resolution.as_ref().ok_or_else(corrupt)?),
        })
    };
    Ok(match tag {
        "prepared" => AttemptState::Prepared,
        "ratified" => AttemptState::Ratified {
            ratification: rat()?,
        },
        "reserved" => AttemptState::Reserved {
            ratification: rat()?,
            reservation: parse_id16(cols.rsv_id.as_ref().ok_or_else(corrupt)?),
        },
        "dispatching" => AttemptState::Dispatching {
            ratification: rat()?,
            reservation: rsv()?,
            dispatch: dsp()?,
        },
        "committed" => AttemptState::Committed {
            ratification: rat()?,
            reservation: rsv()?,
            dispatch: dsp()?,
        },
        "dispatch_refused" => AttemptState::DispatchRefused {
            ratification: rat()?,
            reservation: rsv()?,
            dispatch: dsp()?,
            ground: parse_ground_tag(cols.ground.as_ref().ok_or_else(corrupt)?)?,
        },
        "indeterminate" => AttemptState::Indeterminate {
            ratification: rat()?,
            reservation: rsv()?,
            dispatch: dsp()?,
        },
        "committed_via_recovery" => AttemptState::CommittedViaRecovery {
            ratification: rat()?,
            reservation: rsv()?,
            dispatch: dsp()?,
            resolution: res()?,
        },
        "proven_not_committed" => AttemptState::ProvenNotCommitted {
            ratification: rat()?,
            reservation: rsv()?,
            dispatch: dsp()?,
            resolution: res()?,
        },
        other => return Err(StoreError::Backend(format!("unknown state tag {other}"))),
    })
}

#[cfg(test)]
mod tests {
    use super::{join_list, split_list};

    /// V5: `decode(encode(x)) = x` over the whole admitted domain, including
    /// the control characters a delimiter encoding silently re-partitioned.
    #[test]
    fn list_encoding_round_trips_arbitrary_content() {
        let cases: Vec<Vec<String>> = vec![
            vec![],
            vec!["".into()],
            vec!["src/lib.rs".into()],
            vec!["src/lib.rs".into(), "src/main.rs".into()],
            // The exact witness: the former delimiter, inside one element.
            vec!["src/lib.rs\u{1f}evil/pwned.rs".into()],
            vec!["a:b".into(), "12:not-a-length".into()],
            vec![
                "with space".into(),
                "with\nnewline".into(),
                "quote\"".into(),
            ],
            vec!["\u{1f}".into(), "".into(), "\u{1f}\u{1f}".into()],
            vec!["7:sneaky".into()],
            vec!["日本語のパス.rs".into()],
        ];
        for case in cases {
            let round = split_list(&join_list(&case));
            assert_eq!(round, case, "round trip failed for {case:?}");
        }
    }

    /// Distinct lists must not share an encoding — the injectivity the old
    /// delimiter format lacked.
    #[test]
    fn distinct_lists_encode_distinctly() {
        let one = vec!["src/lib.rs\u{1f}evil/pwned.rs".to_string()];
        let two = vec!["src/lib.rs".to_string(), "evil/pwned.rs".to_string()];
        assert_ne!(join_list(&one), join_list(&two));
        assert_eq!(split_list(&join_list(&one)), one);
        assert_eq!(split_list(&join_list(&two)), two);
    }
}
