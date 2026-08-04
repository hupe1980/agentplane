//! The journal store contract.

use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;

use crate::core::{Digest, Epoch, RunId, Seq, StoreError};

use super::{Append, Record};

/// A run's current chain position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub seq: Seq,
    pub hash: Digest,
}

impl Head {
    /// Where an unwritten run starts.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            seq: 0,
            hash: Digest::ZERO,
        }
    }
}

/// Ownership of a run, held by one instance for a bounded time.
///
/// The epoch is the fencing token. Every append carries it, and the store
/// rejects a stale one *in the same transaction that writes* — so an instance
/// that was paused, partitioned, or GC-stalled and then wakes up cannot append
/// to a run someone else has taken over. Split-brain is prevented by the store's
/// arbitration, not by hoping the clocks agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub run: RunId,
    pub owner: String,
    pub epoch: Epoch,
}

/// A commitment to every run sealed so far.
///
/// Deliberately shaped like a [C2SP `tlog-checkpoint`](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md):
/// an origin naming the log, a size, and a root. Using the interoperable shape
/// rather than a bespoke one means existing verifiers and witness operators
/// work — and inventing a format here would buy nothing and cost every
/// integrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Which log. A deployment-chosen name, so two planes' checkpoints cannot
    /// be confused for one another.
    pub origin: String,
    /// How many runs are committed to.
    pub size: u64,
    /// The Merkle root over their sealed digests.
    pub root: Digest,
}

impl Checkpoint {
    /// The C2SP `tlog-checkpoint` note body: origin, size, base64 root.
    ///
    /// A text form matters more than it looks. A checkpoint is the one artifact
    /// that has to **leave the operator's control** — handed to an auditor,
    /// posted to a witness, pasted into a ticket — and an artifact that only
    /// exists as a Rust struct cannot do that. Using the interoperable encoding
    /// rather than a bespoke one means the thing they hold is checkable by tools
    /// this project did not write.
    #[must_use]
    pub fn to_note(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            b64(self.root.as_bytes())
        )
    }

    /// Read one back.
    ///
    /// # Errors
    ///
    /// If the note is malformed. Deliberately strict: a checkpoint that parses
    /// "close enough" is a checkpoint that compares against the wrong log.
    pub fn from_note(note: &str) -> Result<Self, StoreError> {
        let mut lines = note.lines();
        let bad = |what: &str| StoreError::Backend(format!("checkpoint note: {what}"));
        let origin = lines.next().ok_or_else(|| bad("no origin"))?.to_owned();
        let size = lines
            .next()
            .ok_or_else(|| bad("no size"))?
            .parse::<u64>()
            .map_err(|e| bad(&format!("size is not a number: {e}")))?;
        let root = lines.next().ok_or_else(|| bad("no root"))?;
        let root = unb64(root).ok_or_else(|| bad("root is not base64"))?;
        let root: [u8; 32] = root.try_into().map_err(|_| bad("root is not 32 bytes"))?;
        Ok(Self {
            origin,
            size,
            root: Digest::from_bytes(root),
        })
    }
}

/// Standard base64, without pulling in a dependency for sixty lines of use.
fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    let mut acc = 0u32;
    let mut bits = 0u8;
    let mut out = Vec::new();
    for c in s.trim().bytes() {
        if c == b'=' {
            break;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).ok()?);
        }
    }
    Some(out)
}

/// Evidence that one run is in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inclusion {
    /// Position in the log, in seal order.
    pub index: u64,
    /// The log size this proof is against.
    ///
    /// Carried because the tree's shape depends on it. The size is authenticated
    /// by the checkpoint, not by the proof — see [`crate::core::merkle`].
    pub size: u64,
    /// The run's terminal chain hash: the leaf value.
    pub seal: Digest,
    /// Sibling hashes, leaf-upwards.
    pub proof: Vec<Digest>,
}

/// A durable request that a run stop.
///
/// Carries the asker's name because an intervention with nobody attached to it
/// is an outage, not oversight — the same rule a human decision follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cancellation {
    pub actor: String,
    pub reason: String,
}

/// Append-only, hash-chained run history.
///
/// Implementations must guarantee, atomically:
///
/// 1. **Fencing** — reject appends whose epoch is below the current lease.
/// 2. **Exactly-once** — reject a second `EffectStarted` for an effect key that
///    already started in this run.
/// 3. **Chaining** — assign contiguous `seq` and link `prev_hash` to the run's
///    current head.
///
/// All three are storage invariants rather than application logic, because
/// application logic can be bypassed by the next caller and a constraint cannot.
#[async_trait]
pub trait JournalStore: Send + Sync + Debug {
    /// Append a batch, sealing each record into the chain.
    ///
    /// The whole batch commits or none of it does: a partially written step
    /// would leave a journal that describes something that never happened.
    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError>;

    /// Read a run's records from `from` (inclusive, 1-based) onward.
    async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError>;

    /// The run's current chain head.
    async fn head(&self, run: RunId) -> Result<Head, StoreError>;

    /// Take or renew ownership, returning the fencing epoch to write under.
    ///
    /// Claiming an expired lease bumps the epoch, which fences the previous
    /// owner. Renewing an owned lease keeps it.
    async fn acquire(&self, run: RunId, owner: &str, ttl: Duration) -> Result<Lease, StoreError>;

    /// Hand a lease back, so the next instance need not wait out the TTL.
    ///
    /// The counterpart to [`acquire`](Self::acquire), and the difference between
    /// a graceful shutdown and a crash. Without it every restart waits for
    /// expiry, and the temptation is to make the owner string constant so that
    /// the replacement "renews" instead — which quietly disables fencing,
    /// because two live instances then read each other's lease as their own.
    /// A release primitive is what lets the owner stay unique per process.
    ///
    /// Takes the caller's `epoch` and releases only if it is the one holding the
    /// lease. A fenced caller must not be able to free the lease of the instance
    /// that took over from it — that would hand the run to a third party while
    /// the rightful owner is mid-write.
    ///
    /// Releasing a lease you do not hold is **not an error**. A process shutting
    /// down after being fenced is in exactly that position, and making it fail
    /// would turn an orderly exit into a log full of alarms about a run that is
    /// already somebody else's problem.
    ///
    /// Idempotent: releasing twice is releasing once.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn release_lease(&self, run: RunId, epoch: Epoch) -> Result<(), StoreError>;

    /// Whose rows this handle can reach.
    ///
    /// The default is `default`, which is the tenant a store serves until told
    /// otherwise — a real tenant rather than an absence, so the single-tenant
    /// path is the same code as the multi-tenant one.
    ///
    /// This exists so a mismatch is a **startup refusal** rather than a silent
    /// leak. A plane's tenant scopes its data keys and reaches its policy
    /// requests, but the store handle is built separately and has to be scoped
    /// separately. Nothing about `RuntimeBuilder::tenant(acme)` over a store
    /// left on `default` looks wrong at runtime: it works, and it writes acme's
    /// runs into everybody's keyspace. Asking the store who it serves lets
    /// `build()` catch that before the first run.
    fn tenant(&self) -> &str {
        crate::core::TenantId::DEFAULT
    }

    /// Close the chain and return its terminal hash — what a signature covers.
    async fn seal(&self, run: RunId, epoch: Epoch, outcome: &str) -> Result<Digest, StoreError>;

    /// A commitment to the **set** of sealed runs.
    ///
    /// The per-run chain stops at the run boundary, so deleting an entire run
    /// leaves every remaining run verifying perfectly — see [`crate::core::merkle`].
    /// This closes that: a Merkle root over sealed-run digests, which moves if
    /// any of them is removed.
    ///
    /// On its own it is still only as trustworthy as the store. It becomes
    /// evidence when a checkpoint is **published somewhere the operator does not
    /// control** and compared later — which is the part deliberately left to the
    /// deployment, because a witness this crate chose would be a witness the
    /// crate's author picked for somebody else's audit.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn checkpoint(&self) -> Result<Checkpoint, StoreError>;

    /// Prove the log has only *grown* since a checkpoint of `old_size`.
    ///
    /// This is what makes a published checkpoint evidence, and without it the
    /// Merkle log is close to useless in practice: the root moves on **every**
    /// seal, so an auditor comparing two roots cannot tell legitimate growth
    /// from a deletion followed by growth. A consistency proof separates them —
    /// it shows every leaf committed to before is still committed to, in the
    /// same position.
    ///
    /// # Errors
    ///
    /// If the store is unreachable, or `old_size` exceeds the current log.
    async fn consistency_proof(&self, old_size: u64) -> Result<Vec<Digest>, StoreError>;

    /// Prove a sealed run is in the log this checkpoint commits to.
    ///
    /// Returns `None` for a run that was never sealed — which is an answer, not
    /// an error: an unsealed run is not in the log because it has not finished.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn inclusion_proof(&self, run: RunId) -> Result<Option<Inclusion>, StoreError>;

    /// Ask a run to stop, durably.
    ///
    /// **Deliberately not fenced, and that is the whole point.** Every other
    /// write here requires the lease, because two writers appending to one chain
    /// is the corruption fencing exists to prevent. A stop request is the
    /// opposite situation: the operator asking is *not* the run's owner, has no
    /// epoch, and is usually asking precisely because the owner is busy doing
    /// something they want stopped. Requiring the lease would mean the only
    /// party who can cancel a running agent is the process running it.
    ///
    /// So the request lands beside the chain rather than in it, exactly as a
    /// lease does, and the *owner* journals `RunCancelled` when it observes the
    /// request at its next step boundary. That keeps "who asked, and why" inside
    /// the hash chain without letting an unfenced writer append to it.
    ///
    /// Idempotent: returns `false` if a request was already recorded, so a
    /// retried or duplicated call does not overwrite the original asker.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn request_cancel(
        &self,
        run: RunId,
        actor: &str,
        reason: &str,
    ) -> Result<bool, StoreError>;

    /// The pending stop request for a run, if one was made.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn cancellation(&self, run: RunId) -> Result<Option<Cancellation>, StoreError>;

    /// Verify a run's chain end to end.
    async fn verify(&self, run: RunId) -> Result<Digest, StoreError> {
        let records = self.read(run, 1).await?;
        Record::verify_chain(&records, Digest::ZERO)
    }
}
