//! The effect-broker port: one inspectable consequential effect with an exact
//! ambiguity boundary.
//!
//! The governed effect is the atomic target-ref transition — not patch
//! application, not tree writing, not object creation. The broker returns a
//! definite commitment, a definite refusal, or an uncertain acknowledgement
//! state. Uncertainty is an outcome, not an error: it is never guessed away and
//! never retried.

use gwr_core::digest::Sha256Digest;
use gwr_core::receipt::DispatchEnvelope;
use gwr_core::refusal::DispatchRefusalGround;
use gwr_core::work_request::CommitHash;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BrokerOutcome {
    /// The ref moved atomically from `previous` to `result_commit`, and the
    /// broker acknowledged it.
    Committed {
        previous: CommitHash,
        result_commit: CommitHash,
        journal_digest: Sha256Digest,
    },
    /// The broker definitively declined; no ref update occurred.
    Refused {
        ground: DispatchRefusalGround,
        journal_digest: Sha256Digest,
    },
    /// Acknowledgement was lost. Whether the effect landed is unknown and only
    /// exact recovery evidence plus recovery standing may decide it.
    Uncertain {
        last_journal_digest: Option<Sha256Digest>,
    },
}

pub trait EffectBroker {
    /// Execute the one persisted dispatch envelope. Presenting the same
    /// `DispatchId` again inspects the existing journal; the effect is never
    /// repeated.
    fn execute(&mut self, envelope: &DispatchEnvelope) -> BrokerOutcome;
}
