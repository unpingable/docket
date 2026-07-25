//! The Git effect broker binary.
//!
//! Usage: gwr-git-broker <envelope-file> <patch-file> <journal-file>
//!
//! Reads one persisted dispatch envelope, applies the exact patch through a
//! temporary index, and performs the atomic target-ref transition, journaling
//! every phase. Prints exactly one final line on a definite outcome:
//! `COMMITTED <result> <previous>` or `REFUSED <ground>`. Anything else —
//! including death mid-run — is the caller's uncertainty to record.
//!
//! GWR_BROKER_CRASH_AFTER=<phase> aborts the process immediately after the
//! named journal phase is written (failure injection for tests).

use gwr_local::broker::{
    execute_envelope, inspect_journal, parse_envelope_file, BrokerRun, Journal,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: gwr-git-broker <envelope-file> <patch-file> <journal-file>");
        std::process::exit(2);
    }
    let envelope_content = std::fs::read_to_string(&args[1]).unwrap_or_else(|e| {
        eprintln!("cannot read envelope: {e}");
        std::process::exit(2);
    });
    let envelope = parse_envelope_file(&envelope_content).unwrap_or_else(|e| {
        eprintln!("bad envelope: {e}");
        std::process::exit(2);
    });
    let patch = std::fs::read(&args[2]).unwrap_or_else(|e| {
        eprintln!("cannot read patch: {e}");
        std::process::exit(2);
    });
    let mut journal = Journal::new(std::path::PathBuf::from(&args[3]));

    // Same dispatch: inspect the existing journal; never repeat the effect.
    if journal.exists() {
        let content = journal.read().unwrap_or_default();
        match inspect_journal(&content) {
            Some(BrokerRun::Committed { previous, result }) => {
                println!("COMMITTED {result} {previous}");
                std::process::exit(0);
            }
            Some(BrokerRun::Refused { ground }) => {
                println!("REFUSED {}", ground_tag(ground));
                std::process::exit(0);
            }
            None => {
                // An incomplete prior run: uncertainty, not a retry.
                eprintln!("journal exists without definite outcome; not repeating");
                std::process::exit(3);
            }
        }
    }

    let crash_after = std::env::var("GWR_BROKER_CRASH_AFTER").ok();
    match execute_envelope(&envelope, &patch, &mut journal, crash_after.as_deref()) {
        Ok(BrokerRun::Committed { previous, result }) => {
            println!("COMMITTED {result} {previous}");
        }
        Ok(BrokerRun::Refused { ground }) => {
            println!("REFUSED {}", ground_tag(ground));
        }
        Err(e) => {
            eprintln!("broker error: {e}");
            std::process::exit(3);
        }
    }
}

fn ground_tag(ground: gwr_core::refusal::DispatchRefusalGround) -> &'static str {
    use gwr_core::refusal::DispatchRefusalGround as G;
    match ground {
        G::BasisMoved => "basis_moved",
        G::ForbiddenPath => "forbidden_path",
        G::InvalidPatch => "invalid_patch",
        G::EnvelopeMismatch => "envelope_mismatch",
    }
}
