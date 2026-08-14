//! Integration-test-only staging of a commitment fixture without exposing a
//! raw or authority-bearing mutation on the production Store type.

use gwr_core::outcome::Commitment;
use std::path::Path;

fn id16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn record(db: &Path, commitment: &Commitment) -> rusqlite::Result<()> {
    let conn = rusqlite::Connection::open(db)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute(
        "INSERT OR IGNORE INTO commitment
         (attempt, dispatch, target_ref, previous_value, result_commit, journal_digest, at)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        rusqlite::params![
            id16(commitment.attempt.as_bytes()),
            id16(commitment.dispatch.as_bytes()),
            commitment.target_ref.as_str(),
            commitment.previous_value.as_str(),
            commitment.result_commit.as_str(),
            commitment.journal_digest.to_hex(),
            commitment.committed_at.0 as i64,
        ],
    )?;
    Ok(())
}
