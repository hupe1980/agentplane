//! Content-addressed bytes, kept out of the chain.
//!
//! The journal refuses a record over [`Record::MAX_RECORD_BYTES`], and this is
//! the other half of that refusal: somewhere for the bytes to go. The pattern is
//! the field's — Temporal calls it a claim check, offloading payloads above a
//! threshold and passing a reference through the event history instead — with
//! one difference that matters here.
//!
//! **The reference is the digest.** Temporal's token identifies a payload;
//! a digest *is* the payload's identity. So the hash chain still commits to the
//! exact bytes even though it does not contain them: an auditor who fetches a
//! blob can check it against the digest the chain already signed, and a swapped
//! blob is as detectable as a rewritten record. A reference that merely pointed
//! at mutable storage would move the tamper-evidence boundary without saying so.
//!
//! Three properties follow, and each is a rule rather than a nicety:
//!
//! * **The store computes the digest, never the caller.** A caller who supplied
//!   both bytes and digest could supply a pair that does not match, and every
//!   later verification would compare a blob against a claim rather than a fact.
//! * **Reads verify before returning.** Storage is the least trusted thing here
//!   — it is the part an operator can reach with a text editor.
//! * **Writes are idempotent by construction.** Same bytes, same address; there
//!   is nothing to race and no transaction to need. That is precisely why an
//!   object store is the right shape for this and the wrong shape for the
//!   journal, which needs ordered scans and multi-key atomicity.
//!
//! [`Record::MAX_RECORD_BYTES`]: crate::journal::Record::MAX_RECORD_BYTES

use std::fmt::Debug;

use async_trait::async_trait;

use crate::core::Digest;

#[cfg(feature = "opendal")]
mod opendal_store;
#[cfg(feature = "opendal")]
pub use opendal_store::OpenDalBlobs;

mod memory;
pub use memory::MemoryBlobs;

/// What can go wrong reaching content-addressed storage.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// The backing store failed.
    #[error("blob storage: {0}")]
    Backend(String),

    /// Nothing is stored at that address.
    ///
    /// Distinct from a corrupt read on purpose: a missing blob is a retention or
    /// configuration problem, a corrupt one is an integrity problem, and the
    /// second is the one somebody has to be paged about.
    #[error("no blob at {0}")]
    NotFound(String),

    /// The bytes do not hash to the address they were fetched from.
    ///
    /// Someone or something changed them after they were written. Reported
    /// rather than returned-with-a-warning for the same reason a broken hash
    /// chain is: content you cannot trust is worse than content you do not have,
    /// because it is used.
    #[error("blob at {expected} hashes to {actual} — the stored bytes were altered")]
    Corrupt { expected: String, actual: String },
}

/// Bytes addressed by their own hash.
#[async_trait]
pub trait BlobStore: Send + Sync + Debug {
    /// Store bytes and return the address they landed at.
    ///
    /// Writing the same bytes twice is the same write.
    ///
    /// # Errors
    ///
    /// If the backing store rejects the write.
    async fn put(&self, bytes: &[u8]) -> Result<Digest, BlobError>;

    /// Fetch bytes, verifying them against the address before returning.
    ///
    /// # Errors
    ///
    /// [`BlobError::NotFound`] if nothing is stored there,
    /// [`BlobError::Corrupt`] if what is stored does not hash to `digest`.
    async fn get(&self, digest: Digest) -> Result<Vec<u8>, BlobError>;

    /// Whether anything is stored at that address.
    ///
    /// Does not verify: this answers a retention question, and a caller who
    /// needs to trust the bytes must read them.
    ///
    /// # Errors
    ///
    /// If the backing store cannot be reached.
    async fn has(&self, digest: Digest) -> Result<bool, BlobError>;
}

/// Check fetched bytes against the address they came from.
///
/// Shared by every backend so the verification cannot be implemented slightly
/// differently — or omitted — by one of them.
pub(crate) fn verify(digest: Digest, bytes: Vec<u8>) -> Result<Vec<u8>, BlobError> {
    let actual = Digest::of(&bytes);
    if actual == digest {
        Ok(bytes)
    } else {
        Err(BlobError::Corrupt {
            expected: digest.to_hex(),
            actual: actual.to_hex(),
        })
    }
}
