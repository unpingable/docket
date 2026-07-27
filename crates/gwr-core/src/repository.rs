//! Docket-owned logical repository identity and operational aliases.
//!
//! Git deliberately provides no canonical repository identity. Docket therefore
//! mints or registers an opaque [`RepositoryId`] and keeps paths/remotes as
//! aliases only. An alias can move without changing the logical identity.

use crate::ids::RepositoryId;
use crate::work_request::{ClockReading, RepositoryLocator};

/// The closed alias vocabulary. A path is usable by the local runtime; a
/// remote is retained as an operator-declared alias and is never canonicalized.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RepositoryAliasKind {
    Path,
    Remote,
}

impl RepositoryAliasKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Remote => "remote",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "path" => Some(Self::Path),
            "remote" => Some(Self::Remote),
            _ => None,
        }
    }
}

/// One operator-registered operational alias. `current` selects the path the
/// local runtime should use now; historical aliases remain recorded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RepositoryAlias {
    pub kind: RepositoryAliasKind,
    pub locator: RepositoryLocator,
    pub registered_at: ClockReading,
    pub current: bool,
}

/// The persistent Docket-owned repository registration.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RepositoryRegistration {
    pub id: RepositoryId,
    pub registered_at: ClockReading,
    pub aliases: Vec<RepositoryAlias>,
}

impl RepositoryRegistration {
    /// The one current operational path, if one is registered.
    pub fn current_path(&self) -> Option<&RepositoryLocator> {
        self.aliases
            .iter()
            .find(|a| a.kind == RepositoryAliasKind::Path && a.current)
            .map(|a| &a.locator)
    }

    /// Whether this exact path is an explicitly registered alias. This is a
    /// registry lookup, not identity inference.
    pub fn has_path(&self, path: &RepositoryLocator) -> bool {
        self.aliases
            .iter()
            .any(|a| a.kind == RepositoryAliasKind::Path && &a.locator == path)
    }
}
