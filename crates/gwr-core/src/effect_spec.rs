//! Exact effect specifications. v0 has exactly one effect kind: an atomic Git
//! target-ref transition. The governed effect is the ref moving — not patch
//! application, not tree writing, not object creation.

use crate::digest::{Sha256Digest, Transcript};
use crate::work_request::{CommitHash, RefName};

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
    /// Contribution of this effect to a versioned digest transcript.
    pub fn transcribe(&self, t: Transcript) -> Transcript {
        let mut t = t
            .text_field("effect.kind", "git-ref-update:v1")
            .text_field("effect.target_ref", self.target_ref.as_str())
            .text_field("effect.expected_basis", self.expected_basis.as_str())
            .field("effect.patch_digest", self.patch_digest.as_bytes());
        for p in &self.allowed_paths {
            t = t.text_field("effect.allowed_path", p);
        }
        t
    }
}
