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

mod scoped;
pub use scoped::{ScopedBlobs, unit_address};

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
    /// Whose bytes this handle can reach.
    ///
    /// Content addressing makes two tenants writing identical bytes land on one
    /// object, which is a feature within a tenant and a defect across them. The
    /// severe half is not reading — payloads are sealed under a per-tenant data
    /// key — it is **erasure**: tombstoning a shared object destroys the other
    /// tenant's data while discharging one tenant's request, and reports success
    /// for both.
    ///
    /// Reported so a plane can refuse a blob store scoped to a different tenant
    /// than itself, the same way it refuses a mismatched journal.
    fn tenant(&self) -> &str {
        crate::core::TenantId::DEFAULT
    }

    /// Store bytes and return the address they landed at.
    ///
    /// The returned digest MUST be [`Digest::of`] of exactly the bytes given.
    /// That is a contract, not a description: callers that case-link before
    /// writing — governed media,
    /// [`store_blob`](crate::runtime::StepCtx::store_blob) — commit erasure
    /// traversal to the digest they computed, so a store answering with any
    /// other address would file the bytes *outside* that traversal, linked
    /// under one digest and stored under another where no erasure that follows
    /// the link can reach them. The media ingest treats a mismatch as a broken
    /// contract and fails the effect rather than prefer the store's answer.
    /// Envelope encryption keeps the contract true by addressing ciphertext at
    /// the **plaintext** digest through [`put_at`](Self::put_at).
    ///
    /// Writing the same bytes twice is the same write.
    ///
    /// # Errors
    ///
    /// If the backing store rejects the write.
    async fn put(&self, bytes: &[u8]) -> Result<Digest, BlobError>;

    /// Store bytes at an address that is **not** their own digest.
    ///
    /// The one legitimate reason to separate the two: envelope encryption, where
    /// a payload is addressed by the digest of the plaintext and stored as
    /// ciphertext. Every digest already written to a journal keeps meaning what
    /// it meant, and the encryption stays invisible to everything that only ever
    /// held an address.
    ///
    /// Callers other than [`EncryptedBlobs`](crate::keyring::EncryptedBlobs)
    /// almost certainly want [`put`](Self::put): an address that does not
    /// describe its contents is a content-addressed store with its defining
    /// property switched off, and [`get`](Self::get) can no longer verify.
    ///
    /// # Errors
    ///
    /// If the backing store rejects the write.
    async fn put_at(&self, digest: Digest, bytes: &[u8]) -> Result<(), BlobError>;

    /// Fetch exactly what is stored, without verifying it against the address.
    ///
    /// The counterpart to [`put_at`](Self::put_at): what is stored there is an
    /// envelope, so it does not hash to the address and the ordinary check would
    /// reject it. Verification does not disappear — it moves to after the
    /// envelope is opened, where it is a claim about the payload rather than
    /// about the envelope.
    ///
    /// # Errors
    ///
    /// [`BlobError::NotFound`] if nothing is stored there.
    async fn get_raw(&self, digest: Digest) -> Result<Vec<u8>, BlobError>;

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
/// `tenant` derives the addresses to tombstone: blobs live at
/// [`unit_address`]`(erasure_scope(tenant, case), digest)`, so this erasure
/// reaches exactly this case's copies — [`ScopedBlobs`] carries the argument
/// for why the erasure unit leads the address.
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
    #[cfg(feature = "keyring")] keyring: Option<&dyn crate::keyring::KeyRing>,
    tenant: &crate::core::TenantId,
    case: crate::core::CaseId,
    at: crate::core::Timestamp,
    reason: &str,
) -> Result<usize, BlobError> {
    let digests = cases
        .blobs_of(case)
        .await
        .map_err(|e| BlobError::Backend(e.to_string()))?;
    let scope = crate::core::erasure_scope(tenant, &case.to_string());
    let mut n = 0;
    for digest in digests {
        blobs
            .expire(unit_address(&scope, digest), at, reason)
            .await?;
        n += 1;
    }

    // The key last, and only once every tombstone is written.
    //
    // Order matters in one direction only. Tombstones first means a crash
    // between the two leaves bytes that are still there and still readable —
    // recoverable by running the erasure again. Key first would leave
    // tombstones unwritten over bytes nobody can read, so a later read reports
    // *corrupt* instead of *expired* and an operator is paged for an integrity
    // fault that is really a completed erasure.
    //
    // This is the step that makes the erasure reach backups: the tombstones
    // above only cover the live store.
    #[cfg(feature = "keyring")]
    if let Some(keys) = keyring {
        keys.destroy(&scope, at, reason)
            .await
            .map_err(|e| BlobError::Backend(e.to_string()))?;
    }
    Ok(n)
}

/// Destroy the erasure scope of a run that belongs to no case.
///
/// The counterpart of [`erase_case`], for the unit that call can never reach:
/// a record bound to no case seals its payloads under `tenant/<run>` (see
/// `SealedJournal`), and `erase_case` — which walks a case's blobs and
/// destroys the *case* scope — was the only erasure verb, so a case-less run's
/// sealed payloads had no erasure path at all. This is the missing verb: it
/// destroys exactly the `tenant/<run>` scope, and with it every payload sealed
/// under that run — in the live store, every replica, and every backup ever
/// taken, because what is destroyed was never in them.
///
/// **The erasure unit is the run.** There is no blob traversal here because
/// blob writes are scoped to a run's case; a run with no case links no blobs
/// through the case layer, and anything sealed for it lives in its journal
/// payloads. The journal's records — chain, routing fields, the fact the run
/// happened — remain readable and verifiable, which is the whole design: the
/// chain committed to ciphertext.
///
/// Idempotent as [`KeyRing::destroy`](crate::keyring::KeyRing::destroy) is:
/// the first destruction stands, so a retry cannot rewrite when or why the
/// data went.
///
/// # Errors
///
/// If the key ring cannot be reached.
#[cfg(feature = "keyring")]
pub async fn erase_run(
    keyring: &dyn crate::keyring::KeyRing,
    tenant: &crate::core::TenantId,
    run: crate::core::RunId,
    at: crate::core::Timestamp,
    reason: &str,
) -> Result<(), BlobError> {
    keyring
        .destroy(&crate::keyring::scope(tenant, &run.to_string()), at, reason)
        .await
        .map_err(|e| BlobError::Backend(e.to_string()))
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
