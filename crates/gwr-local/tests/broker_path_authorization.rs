//! Regression suite for V1, found by the blind adversarial review (2026-07-24):
//! the broker authorized a bag of strings scraped from `diff --git` headers,
//! taking only the `a/` side. Rename and copy patches carry no `+++ b/` line,
//! so a governed effect admitted for `src/lib.rs` committed `evil/pwned.rs`
//! with the journal recording the path check as passed.
//!
//! Authorization now runs against `git diff-index --raw -z` over the temporary
//! index — what the patch actually did — and authorizes the path *transition*,
//! both endpoints.

use gwr_local::broker::{parse_raw_transitions, transitions_authorized, PathTransition};

fn allowed() -> Vec<String> {
    vec!["src/lib.rs".to_string()]
}

/// Build a NUL-separated raw record the way git does.
fn raw(records: &[(&str, &[&str])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (meta, paths) in records {
        out.extend_from_slice(meta.as_bytes());
        out.push(0);
        for p in *paths {
            out.extend_from_slice(p.as_bytes());
            out.push(0);
        }
    }
    out
}

#[test]
fn rename_out_of_the_allowlist_is_refused() {
    // The exact shape of the review's witness: allowed source, unadmitted
    // destination. Previously the destination was never examined.
    let r = raw(&[(
        ":100644 100644 aaaaaaa bbbbbbb R100",
        &["src/lib.rs", "evil/pwned.rs"],
    )]);
    let t = parse_raw_transitions(&r).unwrap();
    assert_eq!(
        t,
        vec![PathTransition {
            status: 'R',
            source: "src/lib.rs".into(),
            destination: Some("evil/pwned.rs".into()),
        }]
    );
    assert!(!transitions_authorized(&t, &allowed()));
}

#[test]
fn rename_into_the_allowlist_is_also_refused() {
    // The reverse direction is a change to an unadmitted path too.
    let r = raw(&[(
        ":100644 100644 aaaaaaa bbbbbbb R100",
        &["other/thing.rs", "src/lib.rs"],
    )]);
    let t = parse_raw_transitions(&r).unwrap();
    assert!(!transitions_authorized(&t, &allowed()));
}

#[test]
fn copy_carries_both_endpoints() {
    let r = raw(&[(
        ":100644 100644 aaaaaaa bbbbbbb C100",
        &["src/lib.rs", "evil/copy.rs"],
    )]);
    let t = parse_raw_transitions(&r).unwrap();
    assert_eq!(t[0].status, 'C');
    assert_eq!(t[0].destination.as_deref(), Some("evil/copy.rs"));
    assert!(!transitions_authorized(&t, &allowed()));
}

#[test]
fn in_place_modification_of_an_admitted_path_is_authorized() {
    let r = raw(&[(":100644 100644 aaaaaaa bbbbbbb M", &["src/lib.rs"])]);
    let t = parse_raw_transitions(&r).unwrap();
    assert_eq!(t[0].source, "src/lib.rs");
    assert_eq!(t[0].destination.as_deref(), Some("src/lib.rs"));
    assert!(transitions_authorized(&t, &allowed()));
}

#[test]
fn addition_and_deletion_authorize_the_endpoint_that_exists() {
    let add_allowed = parse_raw_transitions(&raw(&[(
        ":000000 100644 0000000 bbbbbbb A",
        &["src/lib.rs"],
    )]))
    .unwrap();
    assert!(transitions_authorized(&add_allowed, &allowed()));

    let add_forbidden = parse_raw_transitions(&raw(&[(
        ":000000 100644 0000000 bbbbbbb A",
        &["evil/new.rs"],
    )]))
    .unwrap();
    assert!(!transitions_authorized(&add_forbidden, &allowed()));

    let delete_allowed = parse_raw_transitions(&raw(&[(
        ":100644 000000 aaaaaaa 0000000 D",
        &["src/lib.rs"],
    )]))
    .unwrap();
    assert_eq!(delete_allowed[0].destination, None);
    assert!(transitions_authorized(&delete_allowed, &allowed()));

    let delete_forbidden = parse_raw_transitions(&raw(&[(
        ":100644 000000 aaaaaaa 0000000 D",
        &["secrets.txt"],
    )]))
    .unwrap();
    assert!(!transitions_authorized(&delete_forbidden, &allowed()));
}

#[test]
fn paths_with_spaces_quotes_and_newlines_survive_nul_separation() {
    // These are exactly the paths porcelain parsing mangles or quotes.
    let weird = "src/a file \"with\" quotes\nand a newline.rs";
    let r = raw(&[(":100644 100644 aaaaaaa bbbbbbb M", &[weird])]);
    let t = parse_raw_transitions(&r).unwrap();
    assert_eq!(t[0].source, weird);
    assert!(!transitions_authorized(&t, &allowed()));
    assert!(transitions_authorized(&t, &[weird.to_string()]));
}

#[test]
fn multiple_records_all_must_be_authorized() {
    let r = raw(&[
        (":100644 100644 aaaaaaa bbbbbbb M", &["src/lib.rs"]),
        (":000000 100644 0000000 ccccccc A", &["evil/extra.rs"]),
    ]);
    let t = parse_raw_transitions(&r).unwrap();
    assert_eq!(t.len(), 2);
    assert!(!transitions_authorized(&t, &allowed()));
}

#[test]
fn an_empty_transition_set_is_not_authorized() {
    // A patch that changes nothing is not a governed effect.
    assert!(!transitions_authorized(&[], &allowed()));
}
