//! Exact effect specifications. v0 has exactly one effect class: an atomic Git
//! target-ref transition, tagged `git-ref-update:v1`. The governed effect is
//! the ref moving — not patch application, not tree writing, not object
//! creation.
//!
//! The class boundary is explicit: [`GitRefEffect::validate`] decides whether
//! a proposal is expressible in the one admitted class, and admission paths
//! refuse with a typed [`EffectClassRefusal`] before standing, reservation,
//! dispatch, provider execution, or Git are reached. The class tag is bound
//! into every prepared-attempt digest (see [`GitRefEffect::transcribe`]), so a
//! ratified Git effect cannot later be read as another kind of operation.

use crate::digest::{Sha256Digest, Transcript};
use crate::refusal::EffectClassRefusal;
use crate::work_request::{CommitHash, RefName};

/// Environmental premises the Git class's settlement and recovery model relies
/// on. These are properties of `git-ref-update:v1` — its endpoint can be
/// inspected, its ref update is an atomic compare-and-swap, its candidate and
/// result state are attributable, and its recovery verdicts assume exclusive
/// ref custody. They are **not** universal Docket guarantees, and nothing here
/// claims the model generalizes to email, calendar, shell, or arbitrary remote
/// APIs — an effect class that cannot state an equivalent model cannot reuse
/// this one's recovery story.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettlementPremise {
    /// The endpoint (the target ref) can be read back after a crash.
    InspectableEndpoint,
    /// The effect is an atomic compare-and-swap of the target ref.
    AtomicCompareAndSwap,
    /// Candidate and result state are content-addressed and attributable via
    /// the commitment ledger and the broker journal.
    AttributableResultState,
    /// `ExclusiveRefCustody`: recovery verdicts are valid only while the
    /// governed broker is the sole writer of the target ref (asserted by the
    /// deployment, never verified — `recovery::ExclusiveRefCustody`).
    ExclusiveRefCustody,
}

impl SettlementPremise {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::InspectableEndpoint => "inspectable_endpoint",
            Self::AtomicCompareAndSwap => "atomic_compare_and_swap",
            Self::AttributableResultState => "attributable_result_state",
            Self::ExclusiveRefCustody => "exclusive_ref_custody",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GitRefEffect {
    /// The dedicated target ref this effect may move. Nothing else is writable.
    pub target_ref: RefName,
    /// The exact basis the effect is specified against. If the ref no longer
    /// points here at dispatch, the specification no longer describes reality
    /// and dispatch refuses; the effect is not rebased.
    pub expected_basis: CommitHash,
    /// Digest of the exact unified diff to apply.
    pub patch_digest: Sha256Digest,
    /// Exact paths the patch may touch. Any other path is a broker refusal.
    pub allowed_paths: Vec<String>,
}

impl GitRefEffect {
    /// The effect-class tag, exactly as bound into every prepared-attempt
    /// digest transcript. There is one admitted effect class in v0.
    pub const KIND: &'static str = "git-ref-update:v1";

    /// The settlement model this class declares. Recovery for this class —
    /// and only this class — relies on exactly these premises.
    pub const SETTLEMENT_PREMISES: [SettlementPremise; 4] = [
        SettlementPremise::InspectableEndpoint,
        SettlementPremise::AtomicCompareAndSwap,
        SettlementPremise::AttributableResultState,
        SettlementPremise::ExclusiveRefCustody,
    ];

    /// Whether a proposed target is expressible as this class's target: a Git
    /// ref name under `refs/`. A conservative subset of
    /// `git-check-ref-format`; anything refused here is either not a ref name
    /// at all (`mailto:...`, a URL, free text) or a form Git itself rejects.
    /// Refusing means *no admitted effect class describes the proposal* —
    /// there is nothing else it could have been.
    pub fn validate_target_ref(name: &str) -> Result<(), EffectClassRefusal> {
        let refuse = || EffectClassRefusal::UnsupportedEffectClass {
            target: name.to_string(),
        };
        if !name.starts_with("refs/")
            || name.ends_with('/')
            || name.ends_with('.')
            || name.contains("//")
            || name.contains("..")
            || name.contains("@{")
        {
            return Err(refuse());
        }
        if name
            .chars()
            .any(|c| c.is_ascii_control() || " ~^:?*[\\".contains(c))
        {
            return Err(refuse());
        }
        for component in name.split('/') {
            if component.starts_with('.') || component.ends_with(".lock") {
                return Err(refuse());
            }
        }
        Ok(())
    }

    /// Whether a basis names an exact commit: a full lowercase-hex object id,
    /// as Git prints one. An empty or partial basis proposes no exact effect.
    pub fn validate_basis(basis: &str) -> Result<(), EffectClassRefusal> {
        let ok = matches!(basis.len(), 40 | 64)
            && basis
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
        if ok {
            Ok(())
        } else {
            Err(EffectClassRefusal::BasisNotACommitHash {
                basis: basis.to_string(),
            })
        }
    }

    /// Whether a path is expressible as a repository-relative authorization:
    /// non-empty, relative, non-traversing, no control characters.
    pub fn validate_path(path: &str) -> Result<(), EffectClassRefusal> {
        let refuse = || EffectClassRefusal::PathNotAdmissible {
            path: path.to_string(),
        };
        if path.is_empty() || path.starts_with('/') || path.ends_with('/') {
            return Err(refuse());
        }
        if path.chars().any(|c| c.is_ascii_control()) {
            return Err(refuse());
        }
        if path
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
        {
            return Err(refuse());
        }
        Ok(())
    }

    /// Full expressibility of this specification in the one admitted effect
    /// class. Admission paths call this before an attempt is minted; a refusal
    /// here spends nothing and creates nothing.
    pub fn validate(&self) -> Result<(), EffectClassRefusal> {
        Self::validate_target_ref(self.target_ref.as_str())?;
        Self::validate_basis(self.expected_basis.as_str())?;
        if self.allowed_paths.is_empty() {
            return Err(EffectClassRefusal::NoAdmittedPaths);
        }
        for p in &self.allowed_paths {
            Self::validate_path(p)?;
        }
        Ok(())
    }

    /// Contribution of this effect to a versioned digest transcript.
    pub fn transcribe(&self, t: Transcript) -> Transcript {
        let mut t = t
            .text_field("effect.kind", Self::KIND)
            .text_field("effect.target_ref", self.target_ref.as_str())
            .text_field("effect.expected_basis", self.expected_basis.as_str())
            .field("effect.patch_digest", self.patch_digest.as_bytes());
        for p in &self.allowed_paths {
            t = t.text_field("effect.allowed_path", p);
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refusal::EffectClassRefusal;

    fn effect(target: &str, basis: &str, paths: &[&str]) -> GitRefEffect {
        GitRefEffect {
            target_ref: RefName::new(target),
            expected_basis: CommitHash::new(basis),
            patch_digest: Sha256Digest::of_bytes(b"patch"),
            allowed_paths: paths.iter().map(|p| p.to_string()).collect(),
        }
    }

    const BASIS: &str = "72cb3b323fa286cd212378eadae4a42fe4dc093e";

    #[test]
    fn a_well_formed_git_effect_is_admissible() {
        assert_eq!(
            effect("refs/gwr/target", BASIS, &["src/lib.rs", "docs/x.md"]).validate(),
            Ok(())
        );
    }

    #[test]
    fn a_mailto_target_is_an_unsupported_effect_class() {
        // The pilot's run N: 'mailto:ops@example.com' was accepted as a ref
        // name and died eleven steps later as BasisMoved. It is refused here.
        assert_eq!(
            effect("mailto:ops@example.com", BASIS, &["x"]).validate(),
            Err(EffectClassRefusal::UnsupportedEffectClass {
                target: "mailto:ops@example.com".into()
            })
        );
    }

    #[test]
    fn non_ref_targets_are_unsupported() {
        for target in [
            "",
            "HEAD",
            "main",
            "https://example.com/hook",
            "refs/",
            "refs//x",
            "refs/gwr/target/",
            "refs/gwr/..",
            "refs/gwr/a b",
            "refs/gwr/a:b",
            "refs/gwr/a?b",
            "refs/gwr/a[b",
            "refs/gwr/a\\b",
            "refs/gwr/a^b",
            "refs/gwr/a~b",
            "refs/gwr/a*b",
            "refs/gwr/.hidden",
            "refs/gwr/x.lock",
            "refs/gwr/x.",
            "refs/gwr/a@{1}",
        ] {
            assert!(
                GitRefEffect::validate_target_ref(target).is_err(),
                "{target:?} must be refused"
            );
        }
    }

    #[test]
    fn an_empty_or_partial_basis_is_refused() {
        for basis in ["", "abc", "HEAD", &BASIS.to_uppercase(), "zz"] {
            assert_eq!(
                effect("refs/gwr/target", basis, &["x"]).validate(),
                Err(EffectClassRefusal::BasisNotACommitHash {
                    basis: basis.to_string()
                })
            );
        }
    }

    #[test]
    fn zero_paths_and_inadmissible_paths_are_refused() {
        assert_eq!(
            effect("refs/gwr/target", BASIS, &[]).validate(),
            Err(EffectClassRefusal::NoAdmittedPaths)
        );
        for path in ["", "/etc/passwd", "a/../b", "..", ".", "a//b", "a/"] {
            assert_eq!(
                effect("refs/gwr/target", BASIS, &[path]).validate(),
                Err(EffectClassRefusal::PathNotAdmissible {
                    path: path.to_string()
                }),
                "{path:?} must be refused"
            );
        }
        // '@' and dots inside a name are ordinary path bytes; the class does
        // not moralize about spelling, only about form.
        assert_eq!(
            effect("refs/gwr/target", BASIS, &["ops@example.com", "a.b/c.d"]).validate(),
            Ok(())
        );
    }

    #[test]
    fn the_class_tag_is_bound_into_the_digest() {
        // The transcript carries effect.kind; the frozen prepared-attempt
        // vectors in prepared_attempt.rs pin the full format. This asserts the
        // tag itself is stable — changing it is a class-identity change.
        assert_eq!(GitRefEffect::KIND, "git-ref-update:v1");
    }
}
