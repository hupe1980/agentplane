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

    /// The bytes are gone and the record of *why* cannot be read.
    ///
    /// A fourth state, and the one a lax reader hides. A tombstone is the only
    /// evidence an erasure happened that outlives the bytes it describes, so a
    /// reader that filled in a default — epoch zero, the reason "expired" —
    /// would answer [`Expired`](Self::Expired) with a date and a reason it made
    /// up, and a compliance drill would count a completed erasure it never saw.
    ///
    /// Reported as a finding rather than as a backend fault: the store *was*
    /// reached, and what came back was unreadable.
    #[error("blob at {digest}: the bytes are gone and their tombstone does not read ({detail})")]
    UnreadableTombstone { digest: String, detail: String },
}

/// Bytes addressed by their own hash.
///
/// # Two roles, and only one of them answers every method
///
/// Most of this trait is the contract every implementation carries: `put`,
/// `get`, `expire`, `has`, and the rule that an expired address stays expired.
///
/// [`put_at`](Self::put_at) and [`get_raw`](Self::get_raw) are the **envelope
/// pair**, and they belong to a *backing* store — one something may seal onto.
/// A sealing decorator refuses both on purpose
/// ([`EncryptedBlobs`](crate::keyring::EncryptedBlobs) does), because exposing
/// them through it is an unsealed side door: a caller reaching `put_at` on a
/// deployment that asked for sealing writes plaintext under a scope whose
/// erasure can never reach it. So a store that refuses the pair is not
/// incomplete, and a battery demanding it of everything would fail the one
/// implementation whose refusal is the guarantee — which is why
/// `testkit::conformance_blob` has two entry points rather than one.
///
/// Stated here rather than only at the decorator that refuses, because the
/// reader who needs it is writing the *next* implementation.
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
    /// **An expired address stays expired.** A store MUST refuse a write to an
    /// address it holds a tombstone for, with
    /// [`BlobError::Expired`](BlobError::Expired). Content addressing makes
    /// this the one rule that is not obvious: the address *is* the bytes, so a
    /// later write of the same bytes lands on the erased object and puts the
    /// data back — silently, under a tombstone that still says when and why it
    /// went. An erasure a subsequent write reverses is worse than one that
    /// never ran, because the first was reported as discharged. It is reachable
    /// through the ordinary API: a resumed run re-storing what it stored
    /// before, or a second run of the same matter doing the same work.
    ///
    /// A *different* erasure unit writing the same bytes is unaffected —
    /// [`ScopedBlobs`] gives it another address, which is what that type is
    /// for.
    ///
    /// # Errors
    ///
    /// [`BlobError::Expired`] if the address holds a tombstone, or
    /// [`BlobError::Backend`] if the backing store rejects the write.
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
    /// Carries [`put`](Self::put)'s tombstone rule, and needs it more: this is
    /// the write path a sealed deployment takes, so the refusal has to be here
    /// or sealing is the configuration that loses it.
    ///
    /// # Errors
    ///
    /// [`BlobError::Expired`] if the address holds a tombstone, or
    /// [`BlobError::Backend`] if the backing store rejects the write.
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
    /// [`BlobError::NotFound`] if nothing is stored there,
    /// [`BlobError::Expired`] if a tombstone says the bytes were erased, and
    /// [`BlobError::UnreadableTombstone`] if one is there and does not read.
    async fn get_raw(&self, digest: Digest) -> Result<Vec<u8>, BlobError>;

    /// Fetch bytes, verifying them against the address before returning.
    ///
    /// # Errors
    ///
    /// [`BlobError::NotFound`] if nothing is stored there,
    /// [`BlobError::Corrupt`] if what is stored does not hash to `digest`,
    /// [`BlobError::Expired`] if a tombstone says the bytes were erased, and
    /// [`BlobError::UnreadableTombstone`] if one is there and does not read.
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
/// `blobs` is optional because the erasure unit is the **key scope**, and a
/// plane that seals its journal with a key ring and stores no blobs at all is
/// an ordinary shape. Refusing to erase such a case for want of a store to
/// tombstone would leave the one act that reaches every copy undone because a
/// second, lesser act had nowhere to land. With no store the linked digests
/// are counted and left; on a sealed plane their bytes become unreadable by
/// the key destruction below, and a later drill reads them as *erased by
/// design* through the key rather than through a tombstone.
///
/// # Errors
///
/// If the case's blob list cannot be read, or a blob cannot be expired.
pub async fn erase_case(
    blobs: Option<&dyn BlobStore>,
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
    if let Some(blobs) = blobs {
        for digest in digests {
            blobs
                .expire(unit_address(&scope, digest), at, reason)
                .await?;
            n += 1;
        }
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

/// Re-state a blob failure in the vocabulary a step is refused in.
///
/// Only one variant changes shape, and it is the one that is not a fault:
/// [`BlobError::Expired`] on a *write* means the address was erased, which is a
/// rule rather than an outage and must not be classified as one. Everything
/// else keeps its own words inside a backend error, because to a caller holding
/// a step there is nothing else to do about them.
pub(crate) fn refusal(e: BlobError) -> crate::core::StoreError {
    match e {
        BlobError::Expired { digest, at, reason } => {
            crate::core::StoreError::BlobErased { digest, at, reason }
        }
        other => crate::core::StoreError::Backend(other.to_string()),
    }
}

/// [`refusal`] under a name a test may call.
///
/// The classification is the half of the rule a caller sees, and it is not
/// otherwise reachable: `StepCtx::store_blob` is the only in-crate caller and
/// its own error is wrapped twice by the time a test could read it.
#[doc(hidden)]
#[must_use]
pub fn refusal_for_test(e: BlobError) -> crate::core::StoreError {
    refusal(e)
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
