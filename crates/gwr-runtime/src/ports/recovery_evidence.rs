//! The recovery-evidence port: how the runtime establishes for itself what the
//! world currently says about an indeterminate dispatch.
//!
//! These readings are the runtime's own; they are never taken from a recovery
//! fact. A fact is testimony about them, and testimony that disagrees with the
//! reading is refused rather than believed.

use gwr_core::ids::DispatchId;
use gwr_core::work_request::{CommitHash, RefName, RepositoryIdentity};

pub trait RecoveryEvidenceSource {
    /// The value the governed target ref holds right now.
    fn read_target_ref(
        &mut self,
        repository: &RepositoryIdentity,
        target_ref: &RefName,
    ) -> Result<CommitHash, String>;

    /// The raw broker journal bytes for a dispatch, exactly as written. Empty
    /// when no journal exists.
    fn read_journal(&mut self, dispatch: DispatchId) -> Result<Vec<u8>, String>;
}

/// The result commit a broker journal records this dispatch as having created.
/// Parsed only from a journal whose digest already matched the one recorded at
/// indeterminacy — the digest answers "unaltered since we saw it", and this
/// answers "what did it say".
pub fn expected_result_from_journal(journal: &[u8]) -> Option<CommitHash> {
    String::from_utf8_lossy(journal)
        .lines()
        .find_map(|l| l.strip_prefix("commit_created ").map(str::trim))
        .filter(|c| !c.is_empty())
        .map(CommitHash::new)
}
