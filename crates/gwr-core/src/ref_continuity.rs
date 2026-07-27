//! The Git-specific Docket → Continuity subject contract.
//!
//! The subject names the standing of one working assumption: that an exact
//! result commit remains incorporated in an exact governed ref for one opaque,
//! Docket-owned repository identity. It says nothing about the checkout path,
//! historical settlement, present ancestry, or authority.

use crate::effect_spec::GitRefEffect;
use crate::ids::RepositoryId;
use crate::work_request::{CommitHash, RefName};

pub const REF_CONTINUITY_PREFIX: &str = "gwr:ref-continuity:v0:";

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RefContinuitySubject(String);

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RefContinuitySubjectError {
    TargetRefNotExact,
    ResultCommitNotFullHex,
}

impl RefContinuitySubject {
    /// Bind the exact supplied components. Repository identity is already a
    /// typed opaque value; this constructor never sees a path or remote.
    pub fn bind(
        repository_id: RepositoryId,
        target_ref: &RefName,
        result_commit: &CommitHash,
    ) -> Result<Self, RefContinuitySubjectError> {
        let target = target_ref.as_str();
        if GitRefEffect::validate_target_ref(target).is_err() {
            return Err(RefContinuitySubjectError::TargetRefNotExact);
        }
        let commit = result_commit.as_str();
        if !matches!(commit.len(), 40 | 64)
            || !commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(RefContinuitySubjectError::ResultCommitNotFullHex);
        }
        Ok(Self(format!(
            "{REF_CONTINUITY_PREFIX}{repository_id}#{target}@{commit}"
        )))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RefContinuitySubject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_contract_binds_typed_repo_ref_and_full_commit() {
        let subject = RefContinuitySubject::bind(
            RepositoryId::from_bytes([0x11; 16]),
            &RefName::new("refs/gwr/target"),
            &CommitHash::new("0123456789abcdef0123456789abcdef01234567"),
        )
        .unwrap();
        assert_eq!(
            subject.as_str(),
            "gwr:ref-continuity:v0:repo-11111111111111111111111111111111\
             #refs/gwr/target@0123456789abcdef0123456789abcdef01234567"
        );
    }

    #[test]
    fn abbreviated_or_non_hex_commit_refuses() {
        let commits = ["abc123".to_string(), "A".repeat(40), "g".repeat(40)];
        for commit in commits {
            assert_eq!(
                RefContinuitySubject::bind(
                    RepositoryId::from_bytes([1; 16]),
                    &RefName::new("refs/gwr/target"),
                    &CommitHash::new(&commit),
                ),
                Err(RefContinuitySubjectError::ResultCommitNotFullHex)
            );
        }
    }

    #[test]
    fn non_exact_or_invalid_ref_refuses() {
        for target in ["main", "refs/heads/topic..other", "refs/heads/open@{1}"] {
            assert_eq!(
                RefContinuitySubject::bind(
                    RepositoryId::from_bytes([1; 16]),
                    &RefName::new(target),
                    &CommitHash::new("0123456789abcdef0123456789abcdef01234567"),
                ),
                Err(RefContinuitySubjectError::TargetRefNotExact)
            );
        }
    }
}
