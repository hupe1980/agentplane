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

use crate::core::{Digest, Timestamp};

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

    /// The bytes were deliberately expired, and a tombstone says so.
    ///
    /// The whole reason retention needs a distinct answer rather than reusing
    /// [`NotFound`](Self::NotFound). Three states an operator must be able to
    /// tell apart, and only one of them is an incident:
    ///
    /// | | means |
    /// |---|---|
    /// | `NotFound` | nothing was ever here, or it was lost. Investigate. |
    /// | `Expired` | retention did its job on a stated date, for a stated reason. |
    /// | `Corrupt` | the bytes were altered. Page someone. |
    ///
    /// Collapsing the middle case into the first is what makes an erasure
    /// request indistinguishable from data loss six months later — and the
    /// journal cannot settle it, because the journal deliberately never held
    /// the bytes.
    #[error("blob at {digest} was expired at {at}: {reason}")]
    Expired {
        digest: String,
        at: i64,
        reason: String,
    },
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

    /// Drop a blob's bytes, leaving a tombstone that says it was deliberate.
    ///
    /// This is the erasure half of retention, and it works *because* the chain
    /// only ever committed to a digest: the record still proves what happened
    /// and that it was not altered, while the bytes it described are gone. That
    /// is the property an Article 17 request needs and an Article 12 obligation
    /// must survive — they are only in tension if the payload lives in the
    /// chain, which is why it does not.
    ///
    /// Expiring twice is the same expiry; the first tombstone stands, so a
    /// retry cannot rewrite when or why the data went.
    ///
    /// # Errors
    ///
    /// If the backing store rejects the write.
    async fn expire(&self, digest: Digest, at: Timestamp, reason: &str) -> Result<(), BlobError>;

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

/// Expire every blob a case produced.
///
/// The erasure unit, because a case is what a request actually names — nobody
/// asks to forget a digest. Each blob is tombstoned with the same reason, so a
/// later read says *expired, on this date, for this reason* rather than
/// *missing*, and the journal still proves what happened.
///
/// Returns how many blobs were expired. Zero is an ordinary answer: a case that
/// stored nothing has nothing to forget, and reporting that as an error would
/// make the caller special-case the common path.
///
/// What this does **not** touch is the journal. Records are append-only by
/// design, so personal data written into one cannot be removed — keep it out of
/// records rather than expecting erasure to reach it.
///
/// # Errors
///
/// If the case's blob list cannot be read, or a blob cannot be expired.
pub async fn erase_case(
    blobs: &dyn BlobStore,
    cases: &dyn crate::case::CaseStore,
    case: crate::core::CaseId,
    at: crate::core::Timestamp,
    reason: &str,
) -> Result<usize, BlobError> {
    let digests = cases
        .blobs_of(case)
        .await
        .map_err(|e| BlobError::Backend(e.to_string()))?;
    let mut n = 0;
    for digest in digests {
        blobs.expire(digest, at, reason).await?;
        n += 1;
    }
    Ok(n)
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
