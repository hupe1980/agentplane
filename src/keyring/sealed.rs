//! A blob store that seals what it keeps.
//!
//! Wraps any [`BlobStore`] and encrypts payloads under a scope's data key. Two
//! details are what make it compose with the rest of the design rather than sit
//! beside it.
//!
//! **The address is over the plaintext.** A blob is addressed by the digest of
//! what was *put*, not of what was stored, so every digest already in a journal
//! keeps meaning what it meant. Encrypting under a content address computed from
//! ciphertext would have silently changed the identity of every payload, and the
//! chain commits to those.
//!
//! **A read verifies after opening.** The digest is checked against the
//! decrypted bytes, so the integrity claim is about the payload rather than
//! about the envelope somebody could have swapped.
//!
//! # The envelope carries its own key
//!
//! ```text
//! [u32 len][wrapped data key][24-byte nonce][ciphertext ‖ tag]
//! ```
//!
//! The wrapped key travels with the payload rather than being looked up, which
//! is what makes a **restore** work: a backup holds everything needed to bring
//! the bytes back and nothing needed to read them. The wrapping key never left
//! the key service, so restoring into a fresh store, a new region or a different
//! operator's hands yields ciphertext and a key nobody can open.
//!
//! It is also why each payload gets its **own** data key. A service mints a
//! fresh one per call — Vault's `transit/datakey`, KMS's `GenerateDataKey` —
//! and the erasure unit is the *wrapping* key: destroying a scope's wrapping key
//! makes every data key ever wrapped under it unopenable at once.

use async_trait::async_trait;

use crate::blob::{BlobError, BlobStore};
use crate::core::{Digest, Timestamp};

use super::{DataKey, KeyError, KeyRing, WrappedKey};

/// A [`BlobStore`] that seals payloads under a scope's data key.
///
/// One instance per erasure scope — a case, a tenant, whatever the deployment
/// destroys as a unit. The scope is fixed at construction on purpose: a store
/// that took it per call would let one payload land in the wrong erasure unit,
/// and the mistake would only surface when an erasure came back incomplete.
#[derive(Debug)]
pub struct EncryptedBlobs {
    inner: std::sync::Arc<dyn BlobStore>,
    keys: std::sync::Arc<dyn KeyRing>,
    scope: String,
}

impl EncryptedBlobs {
    /// Seal everything written through this store under `scope`'s data key.
    #[must_use]
    pub fn new(
        inner: std::sync::Arc<dyn BlobStore>,
        keys: std::sync::Arc<dyn KeyRing>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            keys,
            scope: scope.into(),
        }
    }

    fn cipher(key: &DataKey) -> chacha20poly1305::XChaCha20Poly1305 {
        use chacha20poly1305::KeyInit as _;
        chacha20poly1305::XChaCha20Poly1305::new(key.expose().into())
    }
}

/// A read that could not be trusted, with the reason in place of a hash.
fn corrupt(digest: Digest, why: &str) -> BlobError {
    BlobError::Corrupt {
        expected: digest.to_hex(),
        actual: why.to_owned(),
    }
}

/// An erased scope is not a missing blob and not a corrupt one.
///
/// Mapped here rather than at the call site so every backend reports a completed
/// erasure the same way. `NotFound` would send somebody looking for lost data,
/// and `Corrupt` would send them looking for a fault.
/// Split `[u32 len][wrapped][rest]`, refusing anything that does not fit.
///
/// Every length here is checked against the buffer rather than trusted: a
/// truncated or hostile envelope must be a refusal, not a panic in a slice.
fn split_envelope(digest: Digest, envelope: &[u8]) -> Result<(WrappedKey, &[u8]), BlobError> {
    let Some(head) = envelope.get(..4) else {
        return Err(corrupt(digest, "the envelope has no length prefix"));
    };
    let len = u32::from_be_bytes(head.try_into().expect("a four-byte slice")) as usize;
    let Some(bytes) = envelope.get(4..4 + len) else {
        return Err(corrupt(
            digest,
            "the envelope claims a wrapped key longer than itself",
        ));
    };
    let wrapped = serde_json::from_slice(bytes)
        .map_err(|_| corrupt(digest, "the envelope's wrapped key does not parse"))?;
    Ok((wrapped, &envelope[4 + len..]))
}

fn erased(e: KeyError) -> BlobError {
    match e {
        KeyError::Destroyed { scope, at, reason } => BlobError::Expired {
            digest: String::new(),
            at: at.unix_timestamp(),
            reason: format!("the data key for scope '{scope}' was destroyed: {reason}"),
        },
        other => BlobError::Backend(other.to_string()),
    }
}

#[async_trait]
impl BlobStore for EncryptedBlobs {
    async fn put(&self, bytes: &[u8]) -> Result<Digest, BlobError> {
        use chacha20poly1305::aead::{Aead, AeadCore, OsRng};

        // Addressed by the plaintext, so a digest already in a journal keeps
        // meaning what it meant.
        let digest = Digest::of(bytes);
        let (key, wrapped) = self.keys.data_key(&self.scope).await.map_err(erased)?;
        let cipher = Self::cipher(&key);
        let nonce = chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut OsRng);

        // The digest is the associated data: the envelope is bound to the
        // address it lives at, so ciphertext moved to another address fails to
        // authenticate rather than decrypting into somebody else's payload.
        let sealed = cipher
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: bytes,
                    aad: digest.to_hex().as_bytes(),
                },
            )
            .map_err(|e| BlobError::Backend(format!("sealing a payload failed: {e}")))?;

        // The wrapped key goes in front, length-prefixed, so the envelope is
        // self-describing and a restore needs nothing but itself.
        // Canonical bytes, not `serde_json::to_vec`: this crate enables
        // `preserve_order` transitively, so plain serialisation would order keys
        // by insertion. Nothing hashes this header today, and writing it in a
        // form that depends on field declaration order is how it would stop
        // being true quietly.
        let wrapped_bytes = crate::core::canon::to_bytes(&wrapped)
            .map_err(|e| BlobError::Backend(format!("a wrapped key would not serialise: {e}")))?;
        let len = u32::try_from(wrapped_bytes.len())
            .map_err(|_| BlobError::Backend("the wrapped key is implausibly large".to_owned()))?;

        let mut envelope = Vec::with_capacity(4 + wrapped_bytes.len() + 24 + sealed.len());
        envelope.extend_from_slice(&len.to_be_bytes());
        envelope.extend_from_slice(&wrapped_bytes);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&sealed);

        // The inner store addresses by *its* bytes, so the envelope would land
        // at its own digest. Written through `put_at` so the plaintext address
        // is the one that survives.
        self.inner.put_at(digest, &envelope).await?;
        Ok(digest)
    }

    async fn get(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        use chacha20poly1305::aead::Aead;

        let envelope = self.inner.get_raw(digest).await?;
        let (wrapped, rest) = split_envelope(digest, &envelope)?;
        if rest.len() < 24 {
            return Err(corrupt(digest, "the envelope is shorter than its nonce"));
        }
        let (nonce, sealed) = rest.split_at(24);

        // Opened through the service, which is where erasure is enforced: once
        // the scope's wrapping key is destroyed this fails for everyone holding
        // a copy, which is the whole guarantee.
        let key = self.keys.open(&wrapped).await.map_err(erased)?;
        let plain = Self::cipher(&key)
            .decrypt(
                nonce.into(),
                chacha20poly1305::aead::Payload {
                    msg: sealed,
                    aad: digest.to_hex().as_bytes(),
                },
            )
            .map_err(|_| corrupt(digest, "the sealed payload did not authenticate"))?;

        // Verified against the plaintext, so the claim is about the payload and
        // not about an envelope somebody could have swapped.
        let actual = Digest::of(&plain);
        if actual != digest {
            return Err(BlobError::Corrupt {
                expected: digest.to_hex(),
                actual: actual.to_hex(),
            });
        }
        Ok(plain)
    }

    async fn put_at(&self, digest: Digest, bytes: &[u8]) -> Result<(), BlobError> {
        self.inner.put_at(digest, bytes).await
    }

    async fn get_raw(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        self.inner.get_raw(digest).await
    }

    async fn expire(&self, digest: Digest, at: Timestamp, reason: &str) -> Result<(), BlobError> {
        self.inner.expire(digest, at, reason).await
    }

    async fn has(&self, digest: Digest) -> Result<bool, BlobError> {
        self.inner.has(digest).await
    }
}
