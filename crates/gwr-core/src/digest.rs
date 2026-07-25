//! Explicit versioned digest transcripts.
//!
//! Nothing in this runtime hashes incidental serialized JSON. Every digest is
//! computed over an explicit, versioned transcript: a domain tag followed by
//! length-prefixed labeled fields. Changing any field, field order, label, or the
//! domain tag changes the digest.

use sha2::{Digest as _, Sha256};
use std::fmt;

/// A SHA-256 digest of an explicit transcript or of exact artifact bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Digest of exact raw bytes (used for artifact content, command output).
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        Self(h.finalize().into())
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            use fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{self}")
    }
}

/// A versioned digest transcript. The domain tag names the record kind and its
/// input-format version, e.g. `gwr:prepared-attempt:v1`.
pub struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    pub fn new(domain_tag: &'static str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain_tag.len() as u64).to_be_bytes());
        hasher.update(domain_tag.as_bytes());
        Self { hasher }
    }

    pub fn field(mut self, label: &'static str, value: &[u8]) -> Self {
        self.hasher.update((label.len() as u64).to_be_bytes());
        self.hasher.update(label.as_bytes());
        self.hasher.update((value.len() as u64).to_be_bytes());
        self.hasher.update(value);
        self
    }

    pub fn text_field(self, label: &'static str, value: &str) -> Self {
        self.field(label, value.as_bytes())
    }

    pub fn finalize(self) -> Sha256Digest {
        Sha256Digest(self.hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_order_and_label_sensitive() {
        let a = Transcript::new("gwr:test:v1")
            .text_field("x", "1")
            .text_field("y", "2")
            .finalize();
        let b = Transcript::new("gwr:test:v1")
            .text_field("y", "2")
            .text_field("x", "1")
            .finalize();
        let c = Transcript::new("gwr:test:v2")
            .text_field("x", "1")
            .text_field("y", "2")
            .finalize();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn fixed_test_vectors() {
        // Frozen vectors: a change here means the digest input format changed,
        // which is a version bump, not an edit.
        assert_eq!(
            Sha256Digest::of_bytes(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let v = Transcript::new("gwr:test:v1")
            .text_field("field", "value")
            .finalize()
            .to_hex();
        assert_eq!(
            v,
            "9712eeb134c2fbdce3865d945920a373fe01394138e3e4b07e87da2ce49c4963"
        );
    }
}
