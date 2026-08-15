//! A signer that is not cryptography.
//!
//! Exists so the store conformance battery can check that a backend **keeps**
//! the attestation it was given. That is a persistence question, not a
//! cryptographic one, and pulling a real signature scheme into the battery would
//! make every backend author install a crypto dependency to prove their `INSERT`
//! has the right number of columns.
//!
//! Deliberately trivial and deliberately named. Nothing here is unforgeable —
//! the "signature" is the hash with a fixed byte prepended — and a deployment
//! that reached for this instead of a real [`Signer`](crate::core::Signer) would
//! have records that look attested and prove nothing. It lives in `testkit`,
//! which is off by default and documented as never belonging in a production
//! build, for exactly that reason.

use crate::core::{CheckpointSigner, Digest, KeyId, SignError, Signer, Verifier};

/// Produces a deterministic, forgeable "signature".
#[derive(Debug, Clone)]
pub struct StubSigner {
    key_id: KeyId,
}

impl StubSigner {
    #[must_use]
    pub fn new(key_id: impl Into<KeyId>) -> Self {
        Self {
            key_id: key_id.into(),
        }
    }
}

impl Default for StubSigner {
    fn default() -> Self {
        Self::new("testkit://stub")
    }
}

impl Signer for StubSigner {
    fn key_id(&self) -> KeyId {
        self.key_id.clone()
    }

    fn sign(&self, hash: &Digest) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(0xAB);
        out.extend_from_slice(hash.as_bytes());
        out
    }
}

/// Also a checkpoint signer, and equally forgeable.
///
/// Signs the message rather than a digest of it, matching what a real witness
/// key does, so a test reaching for this stub exercises production's shape.
#[async_trait::async_trait]
impl CheckpointSigner for StubSigner {
    fn key_id(&self) -> KeyId {
        self.key_id.clone()
    }

    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let mut out = Vec::with_capacity(33);
        out.push(0xAB);
        out.extend_from_slice(Digest::of(message).as_bytes());
        Ok(out)
    }
}

impl Verifier for StubSigner {
    fn verify(&self, key_id: &str, hash: &Digest, signature: &[u8]) -> bool {
        key_id == self.key_id && signature == Signer::sign(self, hash)
    }
}
