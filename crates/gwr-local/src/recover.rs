//! Recovery-fact production: exact Git evidence about an indeterminate
//! dispatch, from ref inspection and the broker journal.
//!
//! Producing a fact changes nothing. Authenticity is not authority; the fact
//! sits in the store until a separately authorized actor applies it.

use gwr_core::digest::Sha256Digest;
use gwr_core::ids::{AttemptId, RecoveryFactId};
use gwr_core::lifecycle::AttemptState;
use gwr_core::recovery::{FactSource, RecoveryFact};
use gwr_core::work_request::CommitHash;
use gwr_runtime::ports::adapters::{Clock, IdSource};
use gwr_runtime::ports::store::{Store, StoreError};
use std::path::Path;
use std::process::Command;

/// Reads the world for the recovery path: the current ref value from the
/// governed repository, and the broker journal for a dispatch. These are the
/// runtime's own readings — never a recovery fact's report of them.
pub struct GitRecoveryEvidence {
    pub journal_dir: std::path::PathBuf,
}

impl GitRecoveryEvidence {
    pub fn new(journal_dir: std::path::PathBuf) -> Self {
        Self { journal_dir }
    }
}

impl gwr_runtime::ports::recovery_evidence::RecoveryEvidenceSource for GitRecoveryEvidence {
    fn read_target_ref(
        &mut self,
        repository: &gwr_core::work_request::RepositoryIdentity,
        target_ref: &gwr_core::work_request::RefName,
    ) -> Result<CommitHash, String> {
        let out = Command::new("git")
            .args([
                "-C",
                repository.as_str(),
                "rev-parse",
                "--verify",
                target_ref.as_str(),
            ])
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("cannot read {}", target_ref.as_str()));
        }
        Ok(CommitHash::new(
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        ))
    }

    fn read_journal(&mut self, dispatch: gwr_core::ids::DispatchId) -> Result<Vec<u8>, String> {
        let hex: String = dispatch
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(std::fs::read(self.journal_dir.join(format!("{hex}.journal"))).unwrap_or_default())
    }
}

#[derive(Debug)]
pub enum RecoverError {
    Store(StoreError),
    NotIndeterminate,
    Io(String),
}

impl From<StoreError> for RecoverError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Inspect the world and record an exact recovery fact for an indeterminate
/// attempt: the observed target-ref value, the expected result commit where the
/// broker journal established one, and the journal digest.
pub fn produce_fact(
    store: &mut dyn Store,
    attempt_id: AttemptId,
    journal_dir: &Path,
    clock: &dyn Clock,
    ids: &mut dyn IdSource,
) -> Result<RecoveryFact, RecoverError> {
    let projected = store.get_attempt(attempt_id)?;
    let AttemptState::Indeterminate { dispatch, .. } = &projected.state else {
        return Err(RecoverError::NotIndeterminate);
    };
    let repo = projected.attempt.repository.as_str();
    let out = Command::new("git")
        .args([
            "-C",
            repo,
            "rev-parse",
            "--verify",
            projected.attempt.effect.target_ref.as_str(),
        ])
        .output()
        .map_err(|e| RecoverError::Io(e.to_string()))?;
    if !out.status.success() {
        return Err(RecoverError::Io("target ref unreadable".into()));
    }
    let observed_ref = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let dispatch_hex: String = dispatch
        .dispatch
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let journal_path = journal_dir.join(format!("{dispatch_hex}.journal"));
    let journal_bytes = std::fs::read(&journal_path).unwrap_or_default();
    let journal_digest = Sha256Digest::of_bytes(&journal_bytes);
    let expected_result_commit = String::from_utf8_lossy(&journal_bytes)
        .lines()
        .find_map(|l| l.strip_prefix("commit_created ").map(str::to_string))
        .map(CommitHash::new);

    let fact = RecoveryFact {
        id: RecoveryFactId::from_bytes(ids.fresh16()),
        attempt: attempt_id,
        dispatch: dispatch.dispatch,
        prepared_attempt_digest: projected.attempt.prepared_attempt_digest,
        repository: projected.attempt.repository.clone(),
        target_ref: projected.attempt.effect.target_ref.clone(),
        basis: projected.attempt.effect.expected_basis.clone(),
        observed_ref: CommitHash::new(observed_ref),
        expected_result_commit,
        journal_digest,
        source: FactSource::RefInspection,
        recorded_at: clock.now(),
    };
    store.record_recovery_fact(&fact)?;
    Ok(fact)
}
