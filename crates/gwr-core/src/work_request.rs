//! The requested work. Vague by design: a work request never describes an exact
//! effect and is never the unit of dispatch.

use crate::ids::WorkRequestId;

/// Exact identity of a governed target repository, as a canonical locator string.
/// Value object: compared exactly, never normalized here.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RepositoryIdentity(String);

impl RepositoryIdentity {
    pub fn new(canonical: impl Into<String>) -> Self {
        Self(canonical.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A Git ref name, exact.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RefName(String);

impl RefName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An exact Git commit hash (hex, as printed by git).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CommitHash(String);

impl CommitHash {
    pub fn new(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A runtime clock reading in milliseconds since the Unix epoch. Readings are
/// established by the trusted runtime's clock adapter; core code only compares.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ClockReading(pub u64);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WorkRequest {
    pub id: WorkRequestId,
    pub repository: RepositoryIdentity,
    pub target_ref: RefName,
    pub goal: String,
    pub created_at: ClockReading,
}
