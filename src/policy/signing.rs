//! Ed25519 signing and verification, for deployments without their own.
//!
//! Behind the `signing` feature. The seam in [`core::attest`](crate::core) is
//! always available — this is one implementation of it, and a deployment with a
//! workload-identity system should plug that in instead. What is here exists so
//! that "sign the journal" is not blocked on procuring a PKI.
//!
//! # Why Ed25519 and not a choice
//!
//! Because there is nothing to configure. No curve, no padding mode, no hash
//! agility, no parameter that can be selected badly. The signature is 64 bytes,
//! signing is fast enough to sit on the journal's write path, and verification
//! needs only the public key.
//!
//! The [`Attestation`](crate::core::Attestation) deliberately carries no
//! algorithm field. Self-described algorithms are how a verifier gets talked
//! into checking a signature with something weaker than the one that made it;
//! here the verifier decides what it will accept, and a record it cannot check
//! is a record it rejects.
//!
//! # Keys come from outside
//!
//! [`Ed25519Signer`] is constructed from key bytes the deployment supplies. It
//! cannot generate one, and that is not an oversight: a plane that mints its own
//! identity produces records that look attested and prove nothing, because the
//! party being audited chose the key. `rand_core` is switched off in the
//! dependency for exactly this reason.

use std::fmt::Debug;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

use crate::core::{Digest, KeyId, Signer, Verifier};

/// Signs records with an Ed25519 key.
///
/// The secret never appears in `Debug` — same rule as a peer credential, and for
/// the same reason: a key that can be printed is a key in a log line, and this
/// one is held for the process's lifetime.
pub struct Ed25519Signer {
    key: SigningKey,
    key_id: KeyId,
}

impl Debug for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("key_id", &self.key_id)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Ed25519Signer {
    /// Build from a 32-byte seed the deployment supplies.
    ///
    /// `key_id` is what lands on every record. Give it the workload's real
    /// name — a SPIFFE ID if there is one — because "some key signed this" is a
    /// much weaker statement than "this workload signed this", and the second is
    /// what an audit is asking.
    #[must_use]
    pub fn new(key_id: impl Into<KeyId>, seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
            key_id: key_id.into(),
        }
    }

    /// The public half, for handing to a verifier.
    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn key_id(&self) -> KeyId {
        self.key_id.clone()
    }

    fn sign(&self, hash: &Digest) -> Vec<u8> {
        self.key.sign(hash.as_bytes()).to_bytes().to_vec()
    }
}

/// Verifies records against a set of known public keys.
///
/// A key the set does not contain fails verification rather than erroring: an
/// unknown signer and a bad signature are the same answer to the only question
/// being asked, which is *may I believe this record*. Distinguishing them would
/// tell a prober which key ids exist.
#[derive(Debug, Default)]
pub struct Ed25519Verifier {
    keys: std::collections::BTreeMap<KeyId, VerifyingKey>,
}

impl Ed25519Verifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust records signed by this key.
    ///
    /// # Errors
    ///
    /// If the bytes are not a valid Ed25519 public key.
    pub fn trust(
        mut self,
        key_id: impl Into<KeyId>,
        public: &[u8; 32],
    ) -> Result<Self, ed25519_dalek::SignatureError> {
        self.keys
            .insert(key_id.into(), VerifyingKey::from_bytes(public)?);
        Ok(self)
    }
}

impl Verifier for Ed25519Verifier {
    fn verify(&self, key_id: &str, hash: &Digest, signature: &[u8]) -> bool {
        let Some(key) = self.keys.get(key_id) else {
            return false;
        };
        let Ok(bytes) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        key.verify(hash.as_bytes(), &Signature::from_bytes(&bytes))
            .is_ok()
    }
}

/// Signing a card is signing **bytes**, not a digest.
///
/// The same key as the record signer, a different message shape: RFC 7515 says
/// the signature covers the JWS signing input itself. Signing its hash instead
/// would verify perfectly here and nowhere else.
#[cfg(feature = "manifest")]
impl crate::peers::CardSigner for Ed25519Signer {
    fn key_id(&self) -> KeyId {
        self.key_id.clone()
    }

    fn sign_bytes(&self, message: &[u8]) -> Vec<u8> {
        self.key.sign(message).to_bytes().to_vec()
    }
}

#[cfg(feature = "manifest")]
impl crate::peers::CardVerifier for Ed25519Verifier {
    fn verify_bytes(&self, key_id: &str, message: &[u8], signature: &[u8]) -> bool {
        let Some(key) = self.keys.get(key_id) else {
            return false;
        };
        let Ok(bytes) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        key.verify(message, &Signature::from_bytes(&bytes)).is_ok()
    }
}
