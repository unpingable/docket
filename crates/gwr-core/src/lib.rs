//! Pure deterministic types and transition rules for the governed work runtime.
//!
//! This crate owns typed identities, digest transcripts, immutable value objects,
//! lifecycle validation, reservation and standing-use rules, bridge admission,
//! receipt construction from established facts, recovery-resolution validation,
//! and reconciliation rules. It performs no I/O.

#![forbid(unsafe_code)]
