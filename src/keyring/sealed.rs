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
//! Stored bytes are the crate's one sealed envelope — the versioned
//! construction in [`envelope`](super::envelope) every other decorator writes
//! — bound to `blob:{scope}:{digest}` as associated data. The scope is in it
//! so an envelope copied to the same address under another erasure unit fails
//! to authenticate there rather than opening as that unit's data; the digest
//! is in it so ciphertext moved to another address fails the same way.
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

use super::{KeyError, KeyRing};

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

    /// The identity an envelope at `digest` is sealed to: this erasure unit
    /// and this address.
    fn aad(&self, digest: Digest) -> String {
        format!("blob:{}:{}", self.scope, digest.to_hex())
    }
}

/// A key failure, in the vocabulary a blob reader acts on.
///
/// Mapped here rather than at the call site so every backend reports each cause
/// the same way. A destroyed key is a completed erasure (`Expired`), never a
/// missing blob or a corrupt one; a retired key version, an envelope another
/// build wrote and a header this build cannot parse are intact bytes that did
/// not open (`Unopened`); an unreachable ring is an outage (`Backend`); and a
/// refusal — a payload that does not authenticate under this scope and
/// address, a truncated envelope, a wrapped key the ring will not open — is
/// bytes that are not what was written (`Corrupt`).
fn classify(digest: Digest, e: KeyError) -> BlobError {
    match e {
        KeyError::Destroyed { scope, at, reason } => BlobError::Expired {
            digest: digest.to_hex(),
            at: at.unix_timestamp(),
            reason: format!("the data key for scope '{scope}' was destroyed: {reason}"),
        },
        e @ (KeyError::Retired { .. }
        | KeyError::UnknownFormat { .. }
        | KeyError::UnreadableHeader { .. }) => BlobError::Unopened {
            digest: digest.to_hex(),
            detail: e.to_string(),
        },
        KeyError::Unavailable(e) => BlobError::Backend(format!("the key ring is unavailable: {e}")),
        KeyError::Refused(why) => BlobError::Corrupt {
            expected: digest.to_hex(),
            actual: why,
        },
    }
}

#[async_trait]
impl BlobStore for EncryptedBlobs {
    async fn put(&self, bytes: &[u8]) -> Result<Digest, BlobError> {
        // Addressed by the plaintext, so a digest already in a journal keeps
        // meaning what it meant.
        let digest = Digest::of(bytes);
        let envelope = super::envelope::seal(
            self.keys.as_ref(),
            &self.scope,
            self.aad(digest).as_bytes(),
            bytes,
        )
        .await
        .map_err(|e| match e {
            // Sealing is a write: a destroyed scope refuses it as erased, and
            // every other failure is the ring's, not the bytes'.
            e @ KeyError::Destroyed { .. } => classify(digest, e),
            other => BlobError::Backend(format!("sealing a payload failed: {other}")),
        })?;

        // The inner store addresses by *its* bytes, so the envelope would land
        // at its own digest. Written through `put_at` so the plaintext address
        // is the one that survives.
        self.inner.put_at(digest, &envelope).await?;
        Ok(digest)
    }

    async fn get(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        let envelope = self.inner.get_raw(digest).await?;

        // Opened through the service, which is where erasure is enforced: once
        // the scope's wrapping key is destroyed this fails for everyone holding
        // a copy, which is the whole guarantee.
        let plain =
            super::envelope::open(self.keys.as_ref(), self.aad(digest).as_bytes(), &envelope)
                .await
                .map_err(|e| classify(digest, e))?;

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

    async fn put_at(&self, digest: Digest, _bytes: &[u8]) -> Result<(), BlobError> {
        // Refused, not forwarded. `put_at`/`get_raw` are the envelope-layer
        // pair the *sealing* store uses against its inner store; exposed
        // through the decorator itself they were an unsealed side door — a
        // skill calling `put_at` on a deployment that asked for sealing stored
        // plaintext under a scope whose erasure could never reach it, and the
        // mistake only surfaced when an erasure came back incomplete. The
        // sealing write path still works: `put` above calls `put_at` on the
        // **inner** store this decorator holds, which is a different object.
        // What the refusal does not cover: a caller handed the inner store
        // directly is outside this decorator's reach — sealing is only as
        // whole as the wiring that routes every writer through it.
        Err(BlobError::Backend(format!(
            "put_at({}) refused: this blob store seals under scope '{}', and put_at would \
             store the bytes unsealed — use put, which seals and preserves the plaintext \
             address",
            digest.to_hex(),
            self.scope
        )))
    }

    async fn get_raw(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        // Symmetric with `put_at`: raw reads through the sealed handle would
        // hand out envelopes nobody can verify, and their only legitimate
        // reader is this decorator's own `get`.
        Err(BlobError::Backend(format!(
            "get_raw({}) refused: this blob store seals under scope '{}', and raw envelope \
             bytes are not a payload — use get, which opens and verifies",
            digest.to_hex(),
            self.scope
        )))
    }

    async fn expire(&self, digest: Digest, at: Timestamp, reason: &str) -> Result<(), BlobError> {
        self.inner.expire(digest, at, reason).await
    }

    async fn has(&self, digest: Digest) -> Result<bool, BlobError> {
        self.inner.has(digest).await
    }
}

#[cfg(all(test, feature = "testkit"))]
mod refusal_tests {
    use super::*;
    use crate::blob::MemoryBlobs;
    use crate::testkit::MemoryKeyRing;
    use std::sync::Arc;

    /// The sealed handle refuses the raw pair; the sealing pair still works.
    ///
    /// `put_at`/`get_raw` forwarded straight to the inner store, so a skill
    /// holding "the blob store" of a deployment that configured sealing could
    /// write plaintext with one call — under a scope whose erasure would then
    /// never reach it. The refusal is the enforcement; the `put`/`get`
    /// round-trip beside it is the proof the door that *should* be open still
    /// is.
    #[tokio::test]
    async fn the_sealed_handle_refuses_unsealed_io() {
        let store = EncryptedBlobs::new(
            Arc::new(MemoryBlobs::new()),
            Arc::new(MemoryKeyRing::new()),
            "acme/case-1",
        );
        let digest = store.put(b"the payload").await.expect("sealed put");
        assert_eq!(
            store.get(digest).await.expect("sealed get"),
            b"the payload",
            "the sealing pair must keep working"
        );

        let refused = store
            .put_at(digest, b"plaintext through the side door")
            .await
            .expect_err("put_at on a sealed handle stored plaintext");
        assert!(
            refused.to_string().contains("unsealed"),
            "the refusal must say why: {refused}"
        );
        assert!(
            store.get_raw(digest).await.is_err(),
            "get_raw on a sealed handle handed out raw envelopes"
        );
        // The refusal changed nothing: the sealed payload still opens.
        assert_eq!(
            store.get(digest).await.expect("still sealed"),
            b"the payload"
        );
    }

    /// **An envelope opens only where it was sealed.**
    ///
    /// Two erasure units over one backing store: the bytes one unit sealed,
    /// read through the other unit's handle at the same address, must not
    /// open — otherwise a blob outlives the erasure of the unit it belongs to
    /// by being read as another's.
    #[tokio::test]
    async fn an_envelope_read_under_another_scope_does_not_open() {
        let inner: Arc<dyn BlobStore> = Arc::new(MemoryBlobs::new());
        let ring: Arc<dyn KeyRing> = Arc::new(MemoryKeyRing::new());
        let sealed_in = EncryptedBlobs::new(Arc::clone(&inner), Arc::clone(&ring), "acme/case-1");
        let other = EncryptedBlobs::new(Arc::clone(&inner), Arc::clone(&ring), "acme/case-2");
        let digest = sealed_in.put(b"case one's bytes").await.expect("put");
        assert_eq!(
            inner.get_raw(digest).await.expect("raw")[0],
            super::super::envelope::FORMAT_VERSION,
            "a stored blob is not the crate's versioned envelope"
        );
        assert!(
            matches!(other.get(digest).await, Err(BlobError::Corrupt { .. })),
            "an envelope sealed for one erasure unit opened under another"
        );
        assert_eq!(
            sealed_in.get(digest).await.expect("get"),
            b"case one's bytes"
        );
    }

    /// **A retired key version is neither an erasure nor an outage.**
    #[tokio::test]
    async fn a_retired_key_version_reads_as_unopened() {
        let ring = Arc::new(MemoryKeyRing::new());
        let store = EncryptedBlobs::new(
            Arc::new(MemoryBlobs::new()),
            Arc::clone(&ring) as Arc<dyn KeyRing>,
            "acme/case-1",
        );
        let digest = store.put(b"the payload").await.expect("put");
        ring.rotate();
        ring.retire_below(1);
        let read = store.get(digest).await;
        assert!(
            matches!(read, Err(BlobError::Unopened { ref detail, .. }) if detail.contains("retired")),
            "a retired wrapping-key version read as {read:?}"
        );
    }
}
