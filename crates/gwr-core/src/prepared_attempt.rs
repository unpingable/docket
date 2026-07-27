//! The exact attempt: an immutable description of one proposed effect.
//!
//! `AttemptId` is minted only here, at candidate admission, when five elements
//! are fixed exactly: repository identity, basis, artifact digest, effect
//! specification, and observation plan. Changing any of them is a different
//! attempt. A retry — even byte-identical — is a different attempt.

use crate::digest::{Sha256Digest, Transcript};
use crate::effect_spec::GitRefEffect;
use crate::ids::{AttemptId, CandidateArtifactId, WorkRequestId};
use crate::observation_plan::ObservationPlan;
use crate::work_request::{ClockReading, CommitHash, RepositoryLocator};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreparedAttempt {
    pub attempt_id: AttemptId,
    pub work_request: WorkRequestId,
    pub candidate: CandidateArtifactId,
    pub repository: RepositoryLocator,
    pub basis: CommitHash,
    pub artifact_digest: Sha256Digest,
    pub effect: GitRefEffect,
    pub observation_plan: ObservationPlan,
    pub admitted_at: ClockReading,
    /// Digest binding this exact attempt: identity plus all five fixed elements.
    /// Ratification binds this value.
    pub prepared_attempt_digest: Sha256Digest,
}

impl PreparedAttempt {
    /// Admit a candidate as an exact attempt. The caller supplies a freshly
    /// generated `AttemptId` (identity generation is an adapter concern); this
    /// constructor fixes the five elements and computes the binding digest.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        attempt_id: AttemptId,
        work_request: WorkRequestId,
        candidate: CandidateArtifactId,
        repository: RepositoryLocator,
        basis: CommitHash,
        artifact_digest: Sha256Digest,
        effect: GitRefEffect,
        observation_plan: ObservationPlan,
        admitted_at: ClockReading,
    ) -> Self {
        let mut t = Transcript::new("gwr:prepared-attempt:v1")
            .field("attempt_id", attempt_id.as_bytes())
            .text_field("repository", repository.as_str())
            .text_field("basis", basis.as_str())
            .field("artifact_digest", artifact_digest.as_bytes());
        t = effect.transcribe(t);
        t = observation_plan.transcribe(t);
        let prepared_attempt_digest = t.finalize();
        Self {
            attempt_id,
            work_request,
            candidate,
            repository,
            basis,
            artifact_digest,
            effect,
            observation_plan,
            admitted_at,
            prepared_attempt_digest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{AttemptId, CandidateArtifactId, WorkRequestId};

    fn base(attempt: [u8; 16], basis: &str, patch: [u8; 32], argv: &str) -> PreparedAttempt {
        PreparedAttempt::admit(
            AttemptId::from_bytes(attempt),
            WorkRequestId::from_bytes([9; 16]),
            CandidateArtifactId::from_bytes([8; 16]),
            RepositoryLocator::new("/tmp/fixture"),
            CommitHash::new(basis),
            Sha256Digest::of_bytes(b"candidate-bytes"),
            GitRefEffect {
                target_ref: crate::work_request::RefName::new("refs/gwr/target"),
                expected_basis: CommitHash::new(basis),
                patch_digest: Sha256Digest::from_bytes(patch),
                allowed_paths: vec!["src/lib.rs".into()],
            },
            ObservationPlan {
                argv: vec![argv.into()],
                environment_description: "fixture".into(),
            },
            ClockReading(1),
        )
    }

    #[test]
    fn identical_candidate_bytes_may_exist_under_different_attempts() {
        let a = base([1; 16], "aaa", [0; 32], "cargo");
        let b = base([2; 16], "aaa", [0; 32], "cargo");
        assert_eq!(a.artifact_digest, b.artifact_digest);
        assert_ne!(a.attempt_id, b.attempt_id);
        assert_ne!(a.prepared_attempt_digest, b.prepared_attempt_digest);
    }

    #[test]
    fn changed_basis_changes_the_digest() {
        let a = base([1; 16], "aaa", [0; 32], "cargo");
        let b = base([1; 16], "bbb", [0; 32], "cargo");
        assert_ne!(a.prepared_attempt_digest, b.prepared_attempt_digest);
    }

    #[test]
    fn changed_effect_changes_the_digest() {
        let a = base([1; 16], "aaa", [0; 32], "cargo");
        let b = base([1; 16], "aaa", [7; 32], "cargo");
        assert_ne!(a.prepared_attempt_digest, b.prepared_attempt_digest);
    }

    #[test]
    fn changed_observation_plan_changes_the_digest() {
        let a = base([1; 16], "aaa", [0; 32], "cargo");
        let b = base([1; 16], "aaa", [0; 32], "pytest");
        assert_ne!(a.prepared_attempt_digest, b.prepared_attempt_digest);
    }
}
