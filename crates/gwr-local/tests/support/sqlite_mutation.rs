//! Integration-test-only access for deliberately corrupting a file-backed
//! SQLite fixture. This is deliberately outside the production Store API.

use std::path::Path;

pub fn execute_raw(db: &Path, sql: &str) -> rusqlite::Result<usize> {
    let conn = rusqlite::Connection::open(db)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute(sql, [])
}
