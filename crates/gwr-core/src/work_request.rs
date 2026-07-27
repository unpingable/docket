//! The requested work. Vague by design: a work request never describes an exact
//! effect and is never the unit of dispatch.

use crate::ids::{RepositoryId, WorkRequestId};

/// An operator-supplied operational repository locator.
///
/// This is deliberately not repository identity. It may be a host-local path
/// and may change when a working tree is moved or recloned. Logical identity is
/// the separately minted [`crate::ids::RepositoryId`].
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RepositoryLocator(String);

impl RepositoryLocator {
    pub fn new(locator: impl Into<String>) -> Self {
        Self(locator.into())
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
    /// Docket-owned logical identity. `None` exists only for records created
    /// before the explicit repository contract and is never filled from the
    /// path implicitly.
    pub repository_id: Option<RepositoryId>,
    /// Operational path/alias used for this request, never logical identity.
    pub repository: RepositoryLocator,
    pub target_ref: RefName,
    pub goal: String,
    pub created_at: ClockReading,
}
