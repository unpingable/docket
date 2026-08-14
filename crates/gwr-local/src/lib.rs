//! Local adapters: SQLite, filesystem artifacts, provider adapters, Git broker,
//! observations, CLI, clocks, and identity generation.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod broker;
pub mod campaign_export;
pub mod capabilities;
pub mod governed_loop;
pub mod governed_repair;
pub mod observe;
pub mod providers;
pub mod recover;
pub mod store;

pub use gwr_runtime::services::preparation::REPORTED_DIGEST_LABEL;
