//! Local adapters: SQLite, filesystem artifacts, provider adapters, Git broker,
//! observations, CLI, clocks, and identity generation.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod capabilities;
pub mod providers;
pub mod store;

pub use gwr_runtime::services::preparation::REPORTED_DIGEST_LABEL;
