//! Process-level first-open migration serialization.
//!
//! Every child crosses the public `docket list` entry point against the same
//! initially absent database. The parent releases them through one barrier so
//! the test exercises SQLite migration ownership rather than sequential open.

use rusqlite::Connection;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

struct FixtureRoot(PathBuf);

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn two_processes_share_one_atomic_first_open() {
    concurrent_first_open(2, 4);
}

#[test]
fn eight_processes_share_one_atomic_first_open_repeatedly() {
    concurrent_first_open(8, 8);
}

fn concurrent_first_open(fanout: usize, repetitions: usize) {
    for repetition in 0..repetitions {
        let fixture = FixtureRoot(std::env::temp_dir().join(format!(
            "docket-r5-first-open-{}-{}-{repetition}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        )));
        let state = fixture.0.join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let release = fixture.0.join("release");
        let wrapper = fixture.0.join("barrier");
        write_barrier(&wrapper);

        let children = (0..fanout)
            .map(|_| spawn_opener(&wrapper, &release, &state))
            .collect::<Vec<_>>();
        std::fs::write(&release, b"release").unwrap();

        for child in children {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "concurrent first open leaked a process failure: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                stdout,
                serde_json::json!({"attempts": [], "list_format": "gwr:attempt-list:v1"})
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!stderr.contains("duplicate column name"));
            assert!(!stderr.contains("already exists"));
        }

        verify_complete_empty_store(&state.join("state.sqlite"));
        // Ordinary clean reopen must observe the same exact schema.
        drop(gwr_local::store::SqliteStore::open(&state.join("state.sqlite")).unwrap());
        verify_complete_empty_store(&state.join("state.sqlite"));
    }
}

fn spawn_opener(wrapper: &Path, release: &Path, state: &Path) -> Child {
    Command::new(wrapper)
        .arg(release)
        .arg(env!("CARGO_BIN_EXE_docket"))
        .arg(state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn write_barrier(path: &Path) {
    std::fs::write(
        path,
        "#!/bin/sh\nset -eu\nrelease=$1\ndocket=$2\nstate=$3\nwhile [ ! -f \"$release\" ]; do sleep 0.001; done\nexec \"$docket\" list --json --state \"$state\"\n",
    )
    .unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn verify_complete_empty_store(database: &Path) {
    let connection = Connection::open(database).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('work_request')
                 WHERE name='repository_id'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE tbl_name='governed_reconciliation_round'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        11,
        "one table, seven automatic indexes, and three immutable/monotone triggers"
    );
    for table in [
        "governed_loop_attempt",
        "governed_reconciliation_round",
        "governed_loop_issuance_disposition",
        "governed_executor_result",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "first open must mint no custody in {table}");
    }
}
