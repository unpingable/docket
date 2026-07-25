//! Exact command observation: run the ratified command against the exact result
//! commit in a disposable worktree, and record precisely what happened.
//!
//! An observation proves nothing but itself. It cannot rewrite commitment, and
//! a failing observation against a committed effect means the effect committed
//! and the command failed.

use gwr_core::digest::Sha256Digest;
use gwr_core::ids::{AttemptId, ObservationId};
use gwr_core::observation_plan::ObservationRecord;
use gwr_runtime::ports::adapters::{Clock, IdSource};
use gwr_runtime::ports::store::{Store, StoreError};
use std::process::Command;

#[derive(Debug)]
pub enum ObserveError {
    Store(StoreError),
    Io(String),
}

impl From<StoreError> for ObserveError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Run the attempt's exact observation plan against the exact result commit of
/// its commitment, in a temporary detached worktree of the governed repository.
pub fn observe(
    store: &mut dyn Store,
    attempt_id: AttemptId,
    clock: &dyn Clock,
    ids: &mut dyn IdSource,
) -> Result<ObservationRecord, ObserveError> {
    let projected = store.get_attempt(attempt_id)?;
    let commitment = store.get_commitment(attempt_id)?;
    let repo = projected.attempt.repository.as_str().to_string();
    let result_commit = commitment.result_commit.clone();

    let worktree = std::env::temp_dir().join(format!(
        "gwr-observe-{}-{}",
        std::process::id(),
        result_commit.as_str()
    ));
    let _ = std::fs::remove_dir_all(&worktree);
    let add = Command::new("git")
        .args([
            "-C",
            &repo,
            "worktree",
            "add",
            "--detach",
            worktree.to_string_lossy().as_ref(),
            result_commit.as_str(),
        ])
        .output()
        .map_err(|e| ObserveError::Io(e.to_string()))?;
    if !add.status.success() {
        return Err(ObserveError::Io(format!(
            "worktree add failed: {}",
            String::from_utf8_lossy(&add.stderr)
        )));
    }

    let argv = projected.attempt.observation_plan.argv.clone();
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(&worktree)
        .output()
        .map_err(|e| ObserveError::Io(e.to_string()))?;

    let record = ObservationRecord {
        id: ObservationId::from_bytes(ids.fresh16()),
        attempt: attempt_id,
        argv,
        working_directory_identity: format!("detached-worktree@{}", result_commit.as_str()),
        result_commit,
        environment_description: projected
            .attempt
            .observation_plan
            .environment_description
            .clone(),
        exit_status: output.status.code().unwrap_or(-1),
        stdout_digest: Sha256Digest::of_bytes(&output.stdout),
        stderr_digest: Sha256Digest::of_bytes(&output.stderr),
        observed_at: clock.now(),
    };
    store.record_observation(&record)?;

    let _ = Command::new("git")
        .args([
            "-C",
            &repo,
            "worktree",
            "remove",
            "--force",
            worktree.to_string_lossy().as_ref(),
        ])
        .output();
    Ok(record)
}
