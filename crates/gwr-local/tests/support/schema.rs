//! Integration-test-only inspection of a file-backed fixture's physical
//! schema. Schema inspection is evidence, never a production Store operation.

use std::path::Path;

pub fn all_column_names(db: &Path) -> rusqlite::Result<Vec<String>> {
    let conn = rusqlite::Connection::open(db)?;
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    let mut names = Vec::new();
    for table in tables {
        let columns: Vec<String> = conn
            .prepare(&format!("PRAGMA table_info({table})"))?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<_, _>>()?;
        names.extend(
            columns
                .into_iter()
                .map(|column| format!("{table}.{column}")),
        );
    }
    Ok(names)
}
