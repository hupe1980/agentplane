//! The embedded journal, on redb.
//!
//! Two of the runtime's three core guarantees are enforced *here*, by the shape
//! of the data rather than by application logic — because application logic can
//! be bypassed by the next caller:
//!
//! * **Exactly-once** — [`EFFECT_ONCE`] is keyed by `(run_id, effect_key)`, so a
//!   second start for one effect is not rejected, it is *inexpressible*. `insert`
//!   returns the prior value, and a prior value means the effect already began.
//!   This is stronger than the partial unique index it replaces: an index is a
//!   declaration a later migration can drop, a key is the table's identity.
//! * **Fencing** — the lease epoch is read and the records written in **one**
//!   write transaction. redb gives multi-table atomicity, so there is no window
//!   between the check and the append for a stale writer to slip into.
//!
//! redb is pure Rust and two crates deep. That is not tidiness: the previous
//! backend linked a cloud sync engine and a vector-search index that nothing
//! here uses, and every downstream consumer paid for them.
//!
//! It is also **synchronous**, so writes go through [`spawn_blocking`]. A commit
//! fsyncs, and an fsync on the async executor stalls every other task in the
//! process.
//!
//! [`spawn_blocking`]: tokio::task::spawn_blocking

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::core::{Digest, EffectKey, Epoch, RunId, Seq, StoreError};
use crate::journal::{Append, Cancellation, Head, JournalStore, Lease, Record};

/// `(run_id, seq) -> encoded record`. Ordered by construction, so a run's
/// history is a range scan and its head is the last entry of that range.
const JOURNAL: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("journal");

/// Every journaled record that belongs to a case, in case order.
///
/// `(tenant, case, run, seq) -> ()`. The primary row stays in [`JOURNAL`]; this
/// is only the ordering, so a record has exactly one home and the two cannot
/// disagree about its bytes.
///
/// Why an index rather than a filter: *show me everything about this matter* is
/// the question a regulated deployment asks, and answering it by listing a
/// case's runs and reading each one is a join whose cost grows with the case's
/// life. It also **misses** any record written by a run the case does not own —
/// which is exactly what a sweep is, since one tick may escalate several cases
/// and belongs to none of them.
///
/// Tenant-first, like every other key here, so a scan that forgets the
/// predicate returns nothing rather than somebody else's matter.
///
/// The write costs one B-tree insert inside the transaction that was already
/// open. Measured against uncased appends it is **below the noise floor**: two
/// runs of 2,000 appends disagreed about the sign, because a durable append is
/// dominated by the fsync and this is not. A number quoted from either run
/// would have been noise with a decimal point.
const JOURNAL_BY_CASE: TableDefinition<(&str, &str, &str, u64), ()> =
    TableDefinition::new("journal_by_case");

/// `(run_id, effect_key) -> seq`. Exactly-once. Only `EffectStarted` is written
/// here, which is the `WHERE` clause of the partial index this replaces.
const EFFECT_ONCE: TableDefinition<(&str, &str), u64> = TableDefinition::new("effect_once");

/// `run_id -> (owner, epoch, expires_at)`.
const RUN_LEASE: TableDefinition<&str, (&str, u64, u64)> = TableDefinition::new("run_lease");

/// `run_id -> (outcome, chain_head, sealed_at)`.
const RUN_SEAL: TableDefinition<&str, (&str, &[u8], u64)> = TableDefinition::new("run_seal");

/// `(tenant, outcome, ordinal) -> run_key`: concluded runs by how they ended.
///
/// A **derived** index. The outcome's home is the chain — the executor appends
/// `RunSealed` with the conclusion, so tamper detection covers how a run ended,
/// which it would not if a side table were authoritative. This is a convenience
/// for the one question the chain answers slowly: *what is quarantined right
/// now?*
///
/// Maintained by `append`, in the same transaction as the record it derives
/// from, and **the last conclusion wins**: a run that failed, was resumed and
/// then succeeded moves from `failed` to `succeeded`. Deriving it from the seal
/// instead would freeze the *first* conclusion forever — a resumed run would be
/// listed as failed for the rest of its life, which is worse than no index,
/// because a wrong answer reads exactly like a right one.
///
/// The ordinal is a per-tenant conclusion counter, so a scan is oldest-first
/// without a sort and a bounded reverse scan yields the newest conclusions.
const RUN_BY_OUTCOME: TableDefinition<(&str, &str, u64), &str> =
    TableDefinition::new("run_by_outcome");

/// `(tenant, run_key) -> (outcome, ordinal)`: the reverse of `RUN_BY_OUTCOME`.
///
/// What lets a re-conclusion *replace* its index row rather than accumulate a
/// second one — without it, a failed-then-succeeded run would appear under both
/// outcomes, and the failed listing would never drain.
const RUN_OUTCOME: TableDefinition<(&str, &str), (&str, u64)> = TableDefinition::new("run_outcome");

/// `(tenant, updated_at, run_id) -> ()`, every run by last durable append.
const RUN_ACTIVITY: TableDefinition<(&str, u64, &str), ()> = TableDefinition::new("run_activity");
/// `(tenant, run_id) -> updated_at`, for replacing the activity index row.
const RUN_LAST_ACTIVITY: TableDefinition<(&str, &str), u64> =
    TableDefinition::new("run_last_activity");

/// `log_index -> run_id`, the plane's Merkle log in seal order.
///
/// Positions are never reissued, so this table keeps gaps when a run is removed
/// — deliberately, so a freed position cannot be silently reused by a different
/// run. The *tree* is built by iterating in key order, which yields dense
/// positions; that is what makes the `ROW_NUMBER() OVER (ORDER BY log_index)`
/// the SQL backend needed unnecessary here, and with it the rank-vs-index bug
/// that cost an afternoon.
const SEAL_LOG: TableDefinition<(&str, u64), &str> = TableDefinition::new("seal_log");

/// `run_id -> (actor, reason, requested_at)`. An operator's stop request.
///
/// Keyed by run, so the request is idempotent and a retry cannot overwrite who
/// intervened. Deliberately not fenced: whoever wants a run stopped is not its
/// owner, holds no epoch, and is usually asking because the owner is busy.
const RUN_CANCEL: TableDefinition<&str, (&str, &str, u64)> = TableDefinition::new("run_cancel");

/// The next log position to hand out. `MAX + 1` over a table that keeps its gaps
/// would reuse a removed run's slot.
const COUNTERS: TableDefinition<&str, u64> = TableDefinition::new("counters");

const NEXT_LOG_INDEX: &str = "next_log_index";

/// The next conclusion ordinal to hand out, per tenant.
///
/// Separate from `NEXT_LOG_INDEX` because conclusions are not seals: a failed
/// run concludes without entering the Merkle log, and interleaving the two
/// sequences would leave the log with gaps that mean nothing.
const NEXT_CONCLUSION: &str = "next_conclusion";

/// An upper bound for a `&str` range end.
///
/// redb orders by encoded bytes, and `\u{10FFFF}` encodes to the highest
/// sequence UTF-8 admits, so no valid key can sort above it.
pub(super) const MAX_STR: &str = "\u{10FFFF}";

/// A single-node journal store on redb.
#[derive(Debug, Clone)]
pub struct RedbStore {
    db: Arc<Database>,
    /// Attached to the store rather than passed per append, because only the
    /// store knows a record's chain hash — it assigns `seq` and `prev_hash`
    /// inside the same transaction that writes. Signing anywhere else would be
    /// signing a guess about what the hash will be.
    signer: Option<Arc<dyn crate::core::Signer>>,
    /// Names this plane's Merkle log in every checkpoint.
    origin: String,
    /// Which tenant's keyspace this handle addresses.
    ///
    /// Part of the *key*, not a filter applied after reading. A store handle for
    /// tenant A cannot name tenant B's run: the key it builds does not exist, so
    /// a cross-tenant read is a miss rather than a row that some `WHERE` clause
    /// was supposed to remove. A filter that can be forgotten is not isolation,
    /// and the query that forgets it looks exactly like working software.
    tenant: crate::core::TenantId,
}

impl RedbStore {
    /// Open (or create) a database file.
    ///
    /// # Errors
    ///
    /// If the file cannot be opened or the tables cannot be created.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(|e| be(&e))?;
        Self::init(db)
    }

    /// An ephemeral database — for tests, for the simulator, and for the CLI's
    /// default journal.
    ///
    /// **Actually in memory.** It was not, and the reason is a comment that
    /// aged into a defect: it said *redb has no in-memory backend*, which was
    /// true of redb 1 and false since the dependency moved to 3. So the
    /// implementation created a file under [`std::env::temp_dir`] and unlinked
    /// it — an anonymous file, which behaves like memory right up until there is
    /// nowhere to put it.
    ///
    /// That is not a hypothetical. `agentplane run` journals here by default,
    /// and the container image runs on a **read-only root filesystem** with no
    /// writable temp directory, so the documented first command failed with
    /// `Read-only file system (os error 30)` — a message naming neither the
    /// journal nor the temp directory. The same failure waits in any hardened
    /// deployment, a scratch container, or a sandbox with no `/tmp`.
    ///
    /// A name that says *in memory* should not need a filesystem to be true.
    ///
    /// # Errors
    ///
    /// If the database cannot be initialised.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .map_err(|e| be(&e))?;
        Self::init(db)
    }

    /// Create every table, so a read on a fresh database is not a missing-table
    /// error the read paths would each have to special-case.
    fn init(db: Database) -> Result<Self, StoreError> {
        let w = begin_write(&db)?;
        {
            w.open_table(JOURNAL).map_err(|e| be(&e))?;
            w.open_table(JOURNAL_BY_CASE).map_err(|e| be(&e))?;
            w.open_table(EFFECT_ONCE).map_err(|e| be(&e))?;
            w.open_table(RUN_LEASE).map_err(|e| be(&e))?;
            w.open_table(RUN_SEAL).map_err(|e| be(&e))?;
            w.open_table(RUN_BY_OUTCOME).map_err(|e| be(&e))?;
            w.open_table(RUN_OUTCOME).map_err(|e| be(&e))?;
            w.open_table(SEAL_LOG).map_err(|e| be(&e))?;
            w.open_table(RUN_CANCEL).map_err(|e| be(&e))?;
            w.open_table(COUNTERS).map_err(|e| be(&e))?;
            super::redb_cases::create_tables(&w)?;
            super::redb_events::create_tables(&w)?;
            super::redb_tasks::create_tables(&w)?;
            super::redb_timers::create_tables(&w)?;
            super::redb_batches::create_tables(&w)?;
        }
        w.commit().map_err(|e| be(&e))?;
        Ok(Self {
            db: Arc::new(db),
            signer: None,
            origin: "agentplane".to_owned(),
            tenant: crate::core::TenantId::default(),
        })
    }

    /// A handle addressing one tenant's keyspace.
    ///
    /// Every key this store builds is prefixed, so two tenants may share one
    /// physical database and still not reach each other: a read for a run that
    /// belongs to another tenant finds nothing, because the key it looks under
    /// was never written.
    ///
    /// The checkpoint origin carries the tenant too — two tenants sharing a
    /// database would otherwise publish checkpoints under one origin name, and
    /// a witness could not tell whose history it was cosigning. Composed at
    /// read time from the base name and the tenant rather than baked into a
    /// field: baking it in made the builder order-sensitive, so `for_tenant`
    /// called twice double-qualified the origin and `origin()` after
    /// `for_tenant` silently dropped the tenant — either way a checkpoint
    /// under a name no verifier ever saw again.
    #[must_use]
    pub fn for_tenant(mut self, tenant: crate::core::TenantId) -> Self {
        self.tenant = tenant;
        self
    }

    /// The name this tenant's Merkle log publishes under.
    ///
    /// The default tenant keeps the bare base name, so a single-tenant plane's
    /// checkpoints read as they always have.
    fn log_origin(&self) -> String {
        if self.tenant.as_str() == crate::core::TenantId::DEFAULT {
            self.origin.clone()
        } else {
            format!("{}/{}", self.origin, self.tenant)
        }
    }

    /// The storage key for a run, and the only place one is derived.
    ///
    /// One derivation because the alternative is eleven, and eleven places
    /// building the same string is how one of them ends up building a slightly
    /// different one.
    pub(super) fn run_key(&self, run: RunId) -> String {
        format!("{}/{run}", self.tenant)
    }

    /// This handle's tenant, for a key or a range bound.
    ///
    /// Owned rather than borrowed because every caller moves it into a closure
    /// that outlives the borrow.
    pub(super) fn tenant_name(&self) -> String {
        self.tenant.to_string()
    }

    /// Name this plane's Merkle log.
    ///
    /// Goes into every checkpoint, so two planes' checkpoints cannot be
    /// confused for one another — which matters the moment they are published
    /// to a shared witness.
    #[must_use]
    pub fn origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = origin.into();
        self
    }

    /// Write records signed as this identity.
    ///
    /// Off unless asked, and the default is *unsigned rather than self-signed*:
    /// a plane that quietly minted its own key would produce records that look
    /// attested and prove nothing.
    #[must_use]
    pub fn signing_as(mut self, signer: Arc<dyn crate::core::Signer>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Run a closure against the database on the blocking pool.
    ///
    /// redb is synchronous and a commit fsyncs; doing that on the async
    /// executor stalls every other task in the process.
    pub(super) async fn with_db<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Database) -> Result<T, StoreError> + Send + 'static,
    {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || f(&db))
            .await
            .map_err(|e| StoreError::Backend(format!("blocking pool: {e}")))?
    }

    /// The log's leaves, in seal order — already leaf-hashed, which the type
    /// now says rather than the comment.
    async fn log_leaves(&self) -> Result<Vec<crate::core::merkle::LeafHash>, StoreError> {
        let tenant = self.tenant.clone();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let log = r.open_table(SEAL_LOG).map_err(|e| be(&e))?;
            let seals = r.open_table(RUN_SEAL).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            // This tenant's range only. Iterating the whole table would build a
            // Merkle log covering other tenants' runs, so a checkpoint would
            // commit to history its holder may not see.
            for entry in log
                .range((tenant.as_str(), 0)..=(tenant.as_str(), u64::MAX))
                .map_err(|e| be(&e))?
            {
                let (_, run) = entry.map_err(|e| be(&e))?;
                let Some(seal) = seals.get(run.value()).map_err(|e| be(&e))? else {
                    continue;
                };
                let (_, head, _) = seal.value();
                out.push(crate::core::merkle::leaf_hash(&digest(head)?));
            }
            Ok(out)
        })
        .await
    }

    /// Where a run sits in the log, and its leaf value.
    ///
    /// The position is the run's index in seal order, counted while iterating —
    /// dense by construction, because the tree is built from the same walk.
    async fn log_position(&self, run: RunId) -> Result<Option<(usize, Digest)>, StoreError> {
        let key = self.run_key(run);
        let tenant = self.tenant.clone();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let log = r.open_table(SEAL_LOG).map_err(|e| be(&e))?;
            let seals = r.open_table(RUN_SEAL).map_err(|e| be(&e))?;
            let mut rank = 0usize;
            for entry in log
                .range((tenant.as_str(), 0)..=(tenant.as_str(), u64::MAX))
                .map_err(|e| be(&e))?
            {
                let (_, run_id) = entry.map_err(|e| be(&e))?;
                let Some(seal) = seals.get(run_id.value()).map_err(|e| be(&e))? else {
                    continue;
                };
                if run_id.value() == key {
                    let (_, head, _) = seal.value();
                    return Ok(Some((rank, digest(head)?)));
                }
                rank += 1;
            }
            Ok(None)
        })
        .await
    }

    /// Overwrite a record's stored bytes while leaving its hash untouched,
    /// simulating an after-the-fact edit.
    ///
    /// Exists so the test suite can prove that tampering is *detected* rather
    /// than assumed impossible. Not part of the supported surface.
    ///
    /// # Errors
    ///
    /// If the write fails.
    #[doc(hidden)]
    pub async fn tamper_for_test(
        &self,
        run: RunId,
        seq: Seq,
        body: Vec<u8>,
    ) -> Result<(), StoreError> {
        let key = self.run_key(run);
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut t = w.open_table(JOURNAL).map_err(|e| be(&e))?;
                let existing = t
                    .get((key.as_str(), seq))
                    .map_err(|e| be(&e))?
                    .map(|v| v.value().to_vec());
                if let Some(bytes) = existing {
                    let row = Row::decode(&bytes)?;
                    let tampered = Row { body, ..row };
                    t.insert((key.as_str(), seq), tampered.encode().as_slice())
                        .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    /// Remove a run entirely — journal rows and seal alike.
    ///
    /// The one tampering the per-run chain structurally cannot see, so a suite
    /// that could not perform it could not test the mechanism that does. Not
    /// part of the supported surface.
    ///
    /// # Errors
    ///
    /// If the write fails.
    #[doc(hidden)]
    pub async fn delete_run_for_test(&self, run: RunId) -> Result<(), StoreError> {
        let key = self.run_key(run);
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut j = w.open_table(JOURNAL).map_err(|e| be(&e))?;
                let seqs: Vec<u64> = j
                    .range((key.as_str(), 0u64)..=(key.as_str(), u64::MAX))
                    .map_err(|e| be(&e))?
                    .filter_map(Result::ok)
                    .map(|(k, _)| k.value().1)
                    .collect();
                for s in seqs {
                    j.remove((key.as_str(), s)).map_err(|e| be(&e))?;
                }
                w.open_table(RUN_SEAL)
                    .map_err(|e| be(&e))?
                    .remove(key.as_str())
                    .map_err(|e| be(&e))?;
                // The log position is left in place, holding its gap: a freed
                // slot must never be reissued to a different run.
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }
}

/// One journal row.
///
/// Encoded by hand rather than through serde: the body is already bytes, and a
/// JSON envelope would base64 it on every append and every read.
struct Row {
    body: Vec<u8>,
    prev_hash: [u8; 32],
    hash: [u8; 32],
    key_id: Option<String>,
    signature: Option<Vec<u8>>,
}

impl Row {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 96);
        out.extend_from_slice(&self.prev_hash);
        out.extend_from_slice(&self.hash);
        // A key id without a signature (or the reverse) is a half-written row,
        // not an unsigned record. Written as one optional pair so the two
        // cannot drift apart.
        match (&self.key_id, &self.signature) {
            (Some(k), Some(s)) => {
                out.push(1);
                push_bytes(&mut out, k.as_bytes());
                push_bytes(&mut out, s);
            }
            _ => out.push(0),
        }
        push_bytes(&mut out, &self.body);
        out
    }

    fn decode(raw: &[u8]) -> Result<Self, StoreError> {
        let corrupt = |what: &str| StoreError::Corrupt {
            seq: 0,
            detail: format!("journal row truncated in {what}"),
        };
        if raw.len() < 65 {
            return Err(corrupt("header"));
        }
        let prev_hash: [u8; 32] = raw[0..32].try_into().map_err(|_| corrupt("prev_hash"))?;
        let hash: [u8; 32] = raw[32..64].try_into().map_err(|_| corrupt("hash"))?;
        let mut at = 64;
        let attested = raw[at] == 1;
        at += 1;
        let (key_id, signature) = if attested {
            let (k, n) = take_bytes(raw, at).ok_or_else(|| corrupt("key_id"))?;
            at = n;
            let (s, n) = take_bytes(raw, at).ok_or_else(|| corrupt("signature"))?;
            at = n;
            (
                Some(String::from_utf8(k).map_err(|_| corrupt("key_id utf-8"))?),
                Some(s),
            )
        } else {
            (None, None)
        };
        let (body, _) = take_bytes(raw, at).ok_or_else(|| corrupt("body"))?;
        Ok(Self {
            body,
            prev_hash,
            hash,
            key_id,
            signature,
        })
    }

    fn into_record(self) -> Result<Record, StoreError> {
        let attestation = self
            .key_id
            .zip(self.signature)
            .map(|(key_id, signature)| crate::core::Attestation { key_id, signature });
        Record::from_stored_attested(
            self.body,
            Digest::from_bytes(self.prev_hash),
            Digest::from_bytes(self.hash),
            attestation,
        )
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    // A record is refused above `MAX_RECORD_BYTES`, so no field can reach 4 GiB
    // — but the cast is checked anyway rather than assumed, because a silent
    // wrap here would write a length prefix that disagrees with the payload and
    // corrupt every record after it.
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

fn take_bytes(raw: &[u8], at: usize) -> Option<(Vec<u8>, usize)> {
    let end = at.checked_add(4)?;
    let len = u32::from_le_bytes(raw.get(at..end)?.try_into().ok()?) as usize;
    let stop = end.checked_add(len)?;
    Some((raw.get(end..stop)?.to_vec(), stop))
}

fn digest(bytes: &[u8]) -> Result<Digest, StoreError> {
    let b: [u8; 32] = bytes.try_into().map_err(|_| StoreError::Corrupt {
        seq: 0,
        detail: "a stored hash is not 32 bytes".into(),
    })?;
    Ok(Digest::from_bytes(b))
}

/// Begin a write transaction with its durability stated rather than inherited.
///
/// redb already defaults to [`Durability::Immediate`] — a commit is persistent
/// by the time it returns — which is exactly what the old backend spelled as
/// `PRAGMA synchronous = FULL`. Stating it anyway, in one place every write path
/// goes through, because "a committed record survives the process" is this
/// crate's central promise and a promise resting on a dependency's default can
/// be weakened by an upgrade with nothing here changing.
///
/// What this does *not* buy is a test: no suite here kills a process mid-commit,
/// so a regression would not be caught. It is a belt on a guarantee the tests
/// cannot reach, not a checked invariant.
pub(super) fn begin_write(db: &Database) -> Result<redb::WriteTransaction, StoreError> {
    let mut w = db.begin_write().map_err(|e| be(&e))?;
    w.set_durability(redb::Durability::Immediate)
        .map_err(|e| be(&e))?;
    Ok(w)
}

pub(super) fn be<E: std::fmt::Display>(e: &E) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// Wall-clock read for lease expiry.
///
/// Lease timing is infrastructure, not run logic: it never enters the journal's
/// content and therefore cannot affect replay. Run-visible time goes through
/// `StepCtx::now`, which journals the instant.
#[allow(clippy::disallowed_methods)]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A lease expiry instant from a TTL, refusing what whole seconds cannot hold.
///
/// Lease timing here has whole-second granularity, so a TTL below one second is
/// **refused rather than clamped**. The clamp this replaces turned "expire
/// immediately" into "hold for a second" without telling anyone — a contract
/// the runtime relies on, enforced only upstream. Nothing legitimate reaches
/// this refusal: the runtime builder already refuses any TTL below its own
/// two-second minimum at `build()` time. This is the *store's* boundary
/// enforcement, for every other embedder of the trait — they get the same
/// refusal instead of a silently longer lease. A TTL of 1.5s still truncates
/// to one second; the granularity is the contract, and only the value that
/// truncates to *zero* is a lie worth refusing.
///
/// The addition is checked, not assumed: `now + Duration::MAX` would wrap into
/// the past and produce a lease that is born expired — free for anyone to
/// claim while its owner believes it holds forever.
fn lease_expiry(now: u64, ttl: Duration) -> Result<u64, StoreError> {
    let secs = ttl.as_secs();
    if secs == 0 {
        return Err(StoreError::Backend(format!(
            "a lease TTL of {ttl:?} is below this store's whole-second \
             granularity and would round to zero — pass at least one second, \
             or use the runtime's lease_ttl which enforces its own minimum"
        )));
    }
    now.checked_add(secs).ok_or_else(|| {
        StoreError::Backend(format!(
            "a lease TTL of {ttl:?} overflows the expiry instant — the lease \
             would wrap into the past and read as already expired"
        ))
    })
}

/// The last record of a run, or genesis.
fn head_of(
    t: &impl ReadableTable<(&'static str, u64), &'static [u8]>,
    run: &str,
) -> Result<Head, StoreError>
where
{
    let last = t
        .range((run, 0u64)..=(run, u64::MAX))
        .map_err(|e| be(&e))?
        .next_back();
    match last {
        None => Ok(Head::genesis()),
        Some(entry) => {
            let (k, v) = entry.map_err(|e| be(&e))?;
            let row = Row::decode(v.value())?;
            Ok(Head {
                seq: k.value().1,
                hash: Digest::from_bytes(row.hash),
            })
        }
    }
}

#[allow(clippy::too_many_lines)]
#[async_trait]
impl JournalStore for RedbStore {
    /// One file, one writer. That single writer is what makes exactly-once a
    /// table key and fencing race-free here — and it is why a plane that needs
    /// two instances needs `PostgreSQL` instead.
    fn is_shared(&self) -> bool {
        false
    }

    fn tenant(&self) -> &str {
        self.tenant.as_str()
    }

    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError> {
        if batch.is_empty() {
            return Ok(Vec::new());
        }
        let run = batch[0].run;
        if let Some(a) = batch.iter().find(|a| a.run != run) {
            return Err(StoreError::Backend(format!(
                "batch spans runs {run} and {} — a batch is one run's atomic unit",
                a.run
            )));
        }
        let signer = self.signer.clone();
        let key = self.run_key(run);
        let tenant = self.tenant_name();

        self.with_db(move |db| {
            let w = begin_write(db)?;
            let sealed = {
                let mut journal = w.open_table(JOURNAL).map_err(|e| be(&e))?;
                let mut by_case = w.open_table(JOURNAL_BY_CASE).map_err(|e| be(&e))?;
                let mut once = w.open_table(EFFECT_ONCE).map_err(|e| be(&e))?;

                // Fence inside the write transaction: no window between the
                // check and the append for a stale writer to use.
                {
                    let leases = w.open_table(RUN_LEASE).map_err(|e| be(&e))?;
                    if let Some(l) = leases.get(key.as_str()).map_err(|e| be(&e))? {
                        let (_, current, _) = l.value();
                        if epoch != current {
                            return Err(StoreError::Fenced {
                                run: key.clone(),
                                held: epoch,
                                current,
                            });
                        }
                    }
                }

                // Sealed is frozen. The Merkle leaf is the chain head at seal
                // time, so an append past it — even by the epoch's rightful
                // holder — advances the true head past what every checkpoint
                // attests. Checked inside the write transaction like the fence,
                // because the executor's refusal to resume a closed run is
                // logic a future caller can bypass, and this is the constraint
                // that cannot be. The sealing appends themselves precede the
                // seal row, so they never meet this check.
                {
                    let seals = w.open_table(RUN_SEAL).map_err(|e| be(&e))?;
                    if let Some(seal) = seals.get(key.as_str()).map_err(|e| be(&e))? {
                        let (outcome, _, _) = seal.value();
                        return Err(StoreError::RunSealed {
                            run: key.clone(),
                            outcome: outcome.to_owned(),
                        });
                    }
                }

                let mut head = head_of(&journal, &key)?;
                let mut sealed = Vec::with_capacity(batch.len());

                for append in batch {
                    let effect_key = append.effect_key.map(EffectKey::to_hex);
                    let body = append.into_body(head.seq + 1, epoch);
                    let is_start =
                        matches!(body.kind, crate::journal::RecordKind::EffectStarted { .. });
                    let conclusion = match &body.kind {
                        crate::journal::RecordKind::RunSealed { outcome, .. } => {
                            Some(outcome.clone())
                        }
                        _ => None,
                    };
                    let record = Record::seal_signed(body, head.hash, signer.as_deref())?;
                    let seq = record.seq();

                    // Exactly-once. The key is the constraint: a prior value
                    // means this effect already started in this run.
                    if is_start && let Some(ek) = &effect_key {
                        let prior = once
                            .insert((key.as_str(), ek.as_str()), seq)
                            .map_err(|e| be(&e))?;
                        if prior.is_some() {
                            return Err(record.effect_key().map_or_else(
                                || StoreError::Backend("duplicate effect".into()),
                                StoreError::DuplicateEffect,
                            ));
                        }
                    }

                    let row = Row {
                        body: record.raw().to_vec(),
                        prev_hash: *record.prev_hash.as_bytes(),
                        hash: *record.hash.as_bytes(),
                        key_id: record.attestation.as_ref().map(|a| a.key_id.clone()),
                        signature: record.attestation.as_ref().map(|a| a.signature.clone()),
                    };
                    journal
                        .insert((key.as_str(), seq), row.encode().as_slice())
                        .map_err(|e| be(&e))?;
                    // Written in the same transaction as the row it points at,
                    // so the index cannot outlive or precede its record.
                    if let Some(case) = record.body.case {
                        by_case
                            .insert(
                                (
                                    tenant.as_str(),
                                    case.to_string().as_str(),
                                    key.as_str(),
                                    seq,
                                ),
                                (),
                            )
                            .map_err(|e| be(&e))?;
                    }

                    // The outcome index derives from the chain, here, in the
                    // same transaction as the record it derives from — and the
                    // last conclusion wins. A failed run that is resumed and
                    // succeeds moves between listings; an index fed by the seal
                    // would keep saying "failed" forever, and a wrong answer
                    // reads exactly like a right one.
                    if let Some(outcome) = conclusion {
                        let mut by_outcome = w.open_table(RUN_BY_OUTCOME).map_err(|e| be(&e))?;
                        let mut outcomes = w.open_table(RUN_OUTCOME).map_err(|e| be(&e))?;
                        let mut counters = w.open_table(COUNTERS).map_err(|e| be(&e))?;
                        if let Some(prior) = outcomes
                            .get((tenant.as_str(), key.as_str()))
                            .map_err(|e| be(&e))?
                            .map(|v| {
                                let (o, ord) = v.value();
                                (o.to_owned(), ord)
                            })
                        {
                            by_outcome
                                .remove((tenant.as_str(), prior.0.as_str(), prior.1))
                                .map_err(|e| be(&e))?;
                        }
                        let counter = format!("{NEXT_CONCLUSION}/{tenant}");
                        let next = counters
                            .get(counter.as_str())
                            .map_err(|e| be(&e))?
                            .map_or(0, |v| v.value());
                        by_outcome
                            .insert((tenant.as_str(), outcome.as_str(), next), key.as_str())
                            .map_err(|e| be(&e))?;
                        outcomes
                            .insert((tenant.as_str(), key.as_str()), (outcome.as_str(), next))
                            .map_err(|e| be(&e))?;
                        counters
                            .insert(counter.as_str(), next + 1)
                            .map_err(|e| be(&e))?;
                    }

                    head = Head {
                        seq,
                        hash: record.hash,
                    };
                    sealed.push(record);
                }
                let updated = now_secs();
                let mut activity = w.open_table(RUN_ACTIVITY).map_err(|e| be(&e))?;
                let mut last = w.open_table(RUN_LAST_ACTIVITY).map_err(|e| be(&e))?;
                if let Some(previous) = last
                    .get((tenant.as_str(), key.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|value| value.value())
                {
                    activity
                        .remove((tenant.as_str(), previous, key.as_str()))
                        .map_err(|e| be(&e))?;
                }
                activity
                    .insert((tenant.as_str(), updated, key.as_str()), ())
                    .map_err(|e| be(&e))?;
                last.insert((tenant.as_str(), key.as_str()), updated)
                    .map_err(|e| be(&e))?;
                sealed
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(sealed)
        })
        .await
    }

    async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError> {
        let key = self.run_key(run);
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(JOURNAL).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            for entry in t
                .range((key.as_str(), from)..=(key.as_str(), u64::MAX))
                .map_err(|e| be(&e))?
            {
                let (_, v) = entry.map_err(|e| be(&e))?;
                out.push(Row::decode(v.value())?.into_record()?);
            }
            Ok(out)
        })
        .await
    }

    async fn case_history(
        &self,
        case: crate::core::CaseId,
        limit: usize,
    ) -> Result<Vec<Record>, StoreError> {
        let tenant = self.tenant_name();
        let case = case.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let idx = r.open_table(JOURNAL_BY_CASE).map_err(|e| be(&e))?;
            let j = r.open_table(JOURNAL).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            for entry in idx
                .range(
                    (tenant.as_str(), case.as_str(), "", 0)
                        ..=(tenant.as_str(), case.as_str(), MAX_STR, u64::MAX),
                )
                .map_err(|e| be(&e))?
            {
                if out.len() >= limit {
                    break;
                }
                let (k, _) = entry.map_err(|e| be(&e))?;
                let (_, _, run, seq) = k.value();
                // The index carries the ordering; the row carries the bytes. A
                // record has one home, so the two cannot disagree about it.
                if let Some(v) = j.get((run, seq)).map_err(|e| be(&e))? {
                    out.push(Row::decode(v.value())?.into_record()?);
                }
            }
            Ok(out)
        })
        .await
    }

    async fn head(&self, run: RunId) -> Result<Head, StoreError> {
        let key = self.run_key(run);
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(JOURNAL).map_err(|e| be(&e))?;
            head_of(&t, &key)
        })
        .await
    }

    async fn acquire(&self, run: RunId, owner: &str, ttl: Duration) -> Result<Lease, StoreError> {
        let key = self.run_key(run);
        let owner = owner.to_owned();
        let owner_out = owner.clone();
        let epoch = self
            .with_db(move |db| {
                let w = begin_write(db)?;
                let epoch = {
                    let mut leases = w.open_table(RUN_LEASE).map_err(|e| be(&e))?;
                    let now = now_secs();
                    let expires = lease_expiry(now, ttl)?;

                    let existing = leases.get(key.as_str()).map_err(|e| be(&e))?.map(|v| {
                        let (o, e, x) = v.value();
                        (o.to_owned(), e, x)
                    });

                    let epoch = match existing {
                        // Fresh run.
                        None => 1,
                        // Expired or released: claim and fence whoever held
                        // it, **including this caller**. Checked before any
                        // ownership test on purpose — a lease that has lapsed
                        // is not yours to renew, because you cannot know
                        // whether somebody took over in the gap. Assuming you
                        // were fenced is the only safe reading.
                        Some((_, epoch, expires_at)) if expires_at <= now => epoch + 1,
                        // Still live — held by anyone, this caller included.
                        // `acquire` claims and never renews: a same-owner
                        // "renewal" here is a second entry point on one
                        // instance asking to drive a run the instance is
                        // already executing, and handing it the same epoch is
                        // two executors fencing cannot tell apart. Renewal is
                        // `renew`, which proves the caller still holds the
                        // exact `(owner, epoch)` it claims to.
                        Some((held_by, epoch, expires_at)) => {
                            return Err(StoreError::LeaseHeld {
                                run: key.clone(),
                                owner: held_by,
                                epoch,
                                remaining_secs: expires_at.saturating_sub(now),
                            });
                        }
                    };

                    leases
                        .insert(key.as_str(), (owner.as_str(), epoch, expires))
                        .map_err(|e| be(&e))?;
                    epoch
                };
                w.commit().map_err(|e| be(&e))?;
                Ok(epoch)
            })
            .await?;

        Ok(Lease {
            run,
            owner: owner_out,
            epoch,
        })
    }

    async fn renew(
        &self,
        run: RunId,
        owner: &str,
        epoch: Epoch,
        ttl: Duration,
    ) -> Result<Lease, StoreError> {
        let key = self.run_key(run);
        let owner = owner.to_owned();
        let owner_out = owner.clone();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut leases = w.open_table(RUN_LEASE).map_err(|e| be(&e))?;
                let now = now_secs();
                // Refused before the ownership check, so both backends answer
                // a bad TTL the same way whatever state the lease is in.
                let expires = lease_expiry(now, ttl)?;
                let existing = leases.get(key.as_str()).map_err(|e| be(&e))?.map(|v| {
                    let (o, e, x) = v.value();
                    (o.to_owned(), e, x)
                });
                // Held, unexpired, unreleased, by exactly `(owner, epoch)` —
                // anything else is a lease this caller has lost, and a renewal
                // never claims. A released row blanks the owner, so it fails
                // the ownership comparison; an expired row fails the expiry
                // one, because whoever claims it next takes epoch + 1 and a
                // renewal that got in first would resurrect the fenced past.
                match existing {
                    Some((held_by, held_epoch, expires_at))
                        if held_by == owner && held_epoch == epoch && expires_at > now =>
                    {
                        leases
                            .insert(key.as_str(), (owner.as_str(), epoch, expires))
                            .map_err(|e| be(&e))?;
                    }
                    _ => {
                        return Err(StoreError::LeaseNotHeld {
                            run: key.clone(),
                            epoch,
                        });
                    }
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await?;

        Ok(Lease {
            run,
            owner: owner_out,
            epoch,
        })
    }

    async fn release_lease(&self, run: RunId, epoch: Epoch) -> Result<(), StoreError> {
        let key = self.run_key(run);
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut leases = w.open_table(RUN_LEASE).map_err(|e| be(&e))?;
                let held = leases
                    .get(key.as_str())
                    .map_err(|e| be(&e))?
                    .map(|v| v.value().1);
                // Only the epoch that holds it may free it. A fenced caller
                // shutting down must not hand the run to a third party while
                // the instance that took over is mid-write.
                //
                // Marked expired rather than **removed**, and that distinction
                // is the whole safety of this operation. The epoch lives in
                // this row: delete it and `append` has nothing to fence
                // against, while the next `acquire` restarts at 1 — so a writer
                // already fenced at 2 outranks the new owner. Releasing must
                // free the lease without forgetting what has happened to it.
                if held == Some(epoch) {
                    leases
                        .insert(key.as_str(), ("", epoch, 0))
                        .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn abandoned_runs(&self, limit: usize) -> Result<Vec<RunId>, StoreError> {
        let prefix = format!("{}/", self.tenant);
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let leases = r.open_table(RUN_LEASE).map_err(|e| be(&e))?;
            let now = now_secs();
            // A full scan over this tenant's lease rows, released ones
            // included — they keep the epoch, so they cannot be deleted, and
            // an embedded store has no second index to range instead. That is
            // an accepted cost, not an oversight: the table holds one small
            // row per run ever admitted, the sweep reads it once per tick, and
            // redb walks it in memory-mapped pages. The shared-store backend
            // pays for an index because its table is shared by every instance;
            // this one is not.
            let mut expired: Vec<(u64, RunId)> = Vec::new();
            for entry in leases.range(prefix.as_str()..).map_err(|e| be(&e))? {
                let (k, v) = entry.map_err(|e| be(&e))?;
                let key = k.value();
                if !key.starts_with(prefix.as_str()) {
                    break;
                }
                let (owner, _, expires_at) = v.value();
                // Released rows blank the owner; live rows have not lapsed.
                // What remains is the set this method exists for: an owner
                // that stopped renewing without handing the run back.
                if owner.is_empty() || expires_at > now {
                    continue;
                }
                // Corruption, per the contract on `JournalStore::abandoned_runs`
                // and matching the shared-store backend: a stranded run
                // silently dropped from this listing is never recovered, so an
                // unparsable id is refused loudly rather than skipped.
                let id = &key[prefix.len()..];
                let run = RunId::parse(id).map_err(|e| StoreError::Corrupt {
                    seq: 0,
                    detail: format!("run_lease holds an unparsable run id '{id}': {e}"),
                })?;
                expired.push((expires_at, run));
            }
            // Oldest expiry first, so a bounded page cannot starve the run
            // that has been stranded longest behind fresher failures.
            expired.sort_unstable_by_key(|(at, _)| *at);
            Ok(expired.into_iter().take(limit).map(|(_, r)| r).collect())
        })
        .await
    }

    async fn seal(&self, run: RunId, epoch: Epoch, outcome: &str) -> Result<Digest, StoreError> {
        let key = self.run_key(run);
        let tenant = self.tenant.clone();
        let outcome = outcome.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let head_hash = {
                {
                    let leases = w.open_table(RUN_LEASE).map_err(|e| be(&e))?;
                    if let Some(l) = leases.get(key.as_str()).map_err(|e| be(&e))? {
                        let (_, current, _) = l.value();
                        if epoch != current {
                            return Err(StoreError::Fenced {
                                run: key.clone(),
                                held: epoch,
                                current,
                            });
                        }
                    }
                }

                let head = {
                    let journal = w.open_table(JOURNAL).map_err(|e| be(&e))?;
                    head_of(&journal, &key)?
                };

                let mut seals = w.open_table(RUN_SEAL).map_err(|e| be(&e))?;
                // First seal wins; a re-seal must not rewrite the outcome.
                if seals.get(key.as_str()).map_err(|e| be(&e))?.is_none() {
                    seals
                        .insert(
                            key.as_str(),
                            (
                                outcome.as_str(),
                                head.hash.as_bytes().as_slice(),
                                now_secs(),
                            ),
                        )
                        .map_err(|e| be(&e))?;

                    // Enter the log in the same transaction that seals: a seal
                    // the checkpoint does not commit to is the hole this closes.
                    // The counter is per tenant too. A shared counter would
                    // interleave two tenants' indices in one sequence, and the
                    // log would no longer be dense for either.
                    let counter = format!("{NEXT_LOG_INDEX}/{tenant}");
                    let mut counters = w.open_table(COUNTERS).map_err(|e| be(&e))?;
                    let next = counters
                        .get(counter.as_str())
                        .map_err(|e| be(&e))?
                        .map_or(0, |v| v.value());
                    w.open_table(SEAL_LOG)
                        .map_err(|e| be(&e))?
                        .insert((tenant.as_str(), next), key.as_str())
                        .map_err(|e| be(&e))?;
                    // The outcome index is *not* written here: it derives from
                    // the `RunSealed` record inside `append`, where the last
                    // conclusion wins. The seal freezes the journal and enters
                    // the log — it is not the outcome's home.
                    counters
                        .insert(counter.as_str(), next + 1)
                        .map_err(|e| be(&e))?;
                }
                head.hash
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(head_hash)
        })
        .await
    }

    async fn runs_by_outcome(&self, outcome: &str, limit: usize) -> Result<Vec<RunId>, StoreError> {
        let tenant = self.tenant_name();
        let outcome = outcome.to_owned();
        let prefix = format!("{tenant}/");
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let idx = r.open_table(RUN_BY_OUTCOME).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            // **Newest first**, which is what makes the bound survivable. See
            // `JournalStore::runs_by_outcome`: ascending order plus a page
            // limit means a plane whose backlog already exceeds one page
            // returns the *same* runs forever, and the quarantine that just
            // happened is the one that never appears.
            for entry in idx
                .range(
                    (tenant.as_str(), outcome.as_str(), 0)
                        ..=(tenant.as_str(), outcome.as_str(), u64::MAX),
                )
                .map_err(|e| be(&e))?
                .rev()
            {
                if out.len() >= limit {
                    break;
                }
                let (_, v) = entry.map_err(|e| be(&e))?;
                // Keys are `tenant/run`; the caller asked for runs. An entry
                // that does not carry this tenant's prefix, or whose id does
                // not parse, is corruption — reported rather than skipped,
                // matching the shared-store backend, because a quarantined run
                // silently thinned out of this page is the unreachable-signal
                // failure the method exists to remove.
                let key = v.value();
                let id = key
                    .strip_prefix(prefix.as_str())
                    .ok_or_else(|| StoreError::Corrupt {
                        seq: 0,
                        detail: format!(
                            "run_by_outcome points at '{key}', which is outside tenant '{tenant}'"
                        ),
                    })?;
                let run = RunId::parse(id).map_err(|e| StoreError::Corrupt {
                    seq: 0,
                    detail: format!("run_by_outcome holds an unparsable run id '{id}': {e}"),
                })?;
                out.push(run);
            }
            Ok(out)
        })
        .await
    }

    async fn recent_runs(
        &self,
        after: Option<(u64, RunId)>,
        limit: usize,
    ) -> Result<Vec<(RunId, u64)>, StoreError> {
        let tenant = self.tenant_name();
        let prefix = format!("{tenant}/");
        // The cursor's own key, so the range can end *below* it. Skipping in the
        // iterator instead would still walk every newer row, which is the cost
        // this page bound exists to remove.
        let end = after.map(|(updated, run)| (updated, format!("{prefix}{run}")));
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(activity) = r.open_table(RUN_ACTIVITY) else {
                return Ok(Vec::new());
            };
            // Exclusive upper bound at the cursor, so the row the caller last
            // saw is not served twice.
            let rows = match &end {
                Some((updated, key)) => activity
                    .range((tenant.as_str(), 0, "")..(tenant.as_str(), *updated, key.as_str()))
                    .map_err(|e| be(&e))?,
                None => activity
                    .range((tenant.as_str(), 0, "")..=(tenant.as_str(), u64::MAX, MAX_STR))
                    .map_err(|e| be(&e))?,
            };
            rows.rev()
                .filter_map(|entry| match entry {
                    Ok((key, _)) => {
                        let (_, updated, stored) = key.value();
                        stored
                            .strip_prefix(prefix.as_str())
                            .and_then(|id| RunId::parse(id).ok())
                            .map(|run| Ok((run, updated)))
                    }
                    Err(error) => Some(Err(be(&error))),
                })
                .take(limit)
                .collect()
        })
        .await
    }

    async fn checkpoint(&self) -> Result<crate::journal::Checkpoint, StoreError> {
        let leaves = self.log_leaves().await?;
        Ok(crate::journal::Checkpoint {
            origin: self.log_origin(),
            size: leaves.len() as u64,
            root: crate::core::merkle::root(&leaves),
        })
    }

    async fn consistency_proof(&self, old_size: u64) -> Result<Vec<Digest>, StoreError> {
        let leaves = self.log_leaves().await?;
        let old = usize::try_from(old_size).unwrap_or(usize::MAX);
        if old > leaves.len() {
            // Refused rather than answered with an empty proof: an empty proof
            // is what a *consistent* log of unchanged size returns, so handing
            // one back here would let "your checkpoint is from the future" read
            // as "everything is fine".
            return Err(StoreError::Backend(format!(
                "a checkpoint of size {old_size} is larger than this log ({}) — \
                 either it belongs to another plane, or runs were removed",
                leaves.len()
            )));
        }
        Ok(crate::core::merkle::consistency_proof(&leaves, old))
    }

    async fn inclusion_proof(
        &self,
        run: RunId,
    ) -> Result<Option<crate::journal::Inclusion>, StoreError> {
        let leaves = self.log_leaves().await?;
        let Some((index, seal)) = self.log_position(run).await? else {
            return Ok(None);
        };
        Ok(Some(crate::journal::Inclusion {
            index: index as u64,
            size: leaves.len() as u64,
            seal,
            proof: crate::core::merkle::inclusion_proof(&leaves, index),
        }))
    }

    async fn request_cancel(
        &self,
        run: RunId,
        actor: &str,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let key = self.run_key(run);
        let (actor, reason) = (actor.to_owned(), reason.to_owned());
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let first = {
                let mut t = w.open_table(RUN_CANCEL).map_err(|e| be(&e))?;
                // The first asker stays on the record; a retry must not rewrite
                // who intervened.
                if t.get(key.as_str()).map_err(|e| be(&e))?.is_some() {
                    false
                } else {
                    t.insert(key.as_str(), (actor.as_str(), reason.as_str(), now_secs()))
                        .map_err(|e| be(&e))?;
                    true
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(first)
        })
        .await
    }

    async fn cancellation(&self, run: RunId) -> Result<Option<Cancellation>, StoreError> {
        let key = self.run_key(run);
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(RUN_CANCEL).map_err(|e| be(&e))?;
            Ok(t.get(key.as_str()).map_err(|e| be(&e))?.map(|v| {
                let (actor, reason, _) = v.value();
                Cancellation {
                    actor: actor.to_owned(),
                    reason: reason.to_owned(),
                }
            }))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `origin` and `for_tenant` compose the same name whatever order they are
    /// called in, and calling either twice changes nothing.
    ///
    /// The origin used to be baked into a field at `for_tenant` time, so
    /// `for_tenant` twice double-qualified it and `origin` afterwards silently
    /// dropped the tenant — either way a checkpoint published under a name no
    /// verifier would ever see again.
    #[tokio::test]
    async fn checkpoint_origin_is_order_insensitive_and_idempotent() {
        let tenant = crate::core::TenantId::new("acme").expect("tenant");

        let tenant_then_origin = RedbStore::open_in_memory()
            .expect("store")
            .for_tenant(tenant.clone())
            .origin("plane-1");
        let origin_then_tenant = RedbStore::open_in_memory()
            .expect("store")
            .origin("plane-1")
            .for_tenant(tenant.clone());
        let twice = RedbStore::open_in_memory()
            .expect("store")
            .origin("plane-1")
            .for_tenant(tenant.clone())
            .for_tenant(tenant);

        let a = tenant_then_origin.checkpoint().await.expect("checkpoint");
        let b = origin_then_tenant.checkpoint().await.expect("checkpoint");
        let c = twice.checkpoint().await.expect("checkpoint");
        assert_eq!(a.origin, "plane-1/acme");
        assert_eq!(b.origin, a.origin, "builder order changed the log's name");
        assert_eq!(c.origin, a.origin, "for_tenant is not idempotent");
    }

    /// A stored run id that does not parse is reported as corruption, not
    /// silently thinned out of the listing.
    ///
    /// In here rather than in the integration suite because planting the
    /// corrupt row takes the private tables: no public write path produces
    /// one, which is exactly why a skip would hide it forever. The two
    /// listings this pins are the two whose silent thinning is worst — a
    /// stranded run dropped from `abandoned_runs` is never recovered, and a
    /// quarantined run dropped from `runs_by_outcome` is a detected failure
    /// whose signal reaches nobody.
    ///
    /// Each has a positive half first, so the error genuinely comes from the
    /// garbage row rather than from a scan that refuses everything.
    #[tokio::test]
    async fn an_unparsable_run_id_is_reported_as_corruption_not_skipped() {
        let store = RedbStore::open_in_memory().expect("store");
        let stranded = RunId::generate();
        let good_key = store.run_key(stranded);

        // A legitimate expired lease and a legitimate outcome row: the
        // positive halves.
        store
            .with_db({
                let good_key = good_key.clone();
                move |db| {
                    let w = begin_write(db)?;
                    {
                        w.open_table(RUN_LEASE)
                            .map_err(|e| be(&e))?
                            .insert(good_key.as_str(), ("worker", 1u64, 0u64))
                            .map_err(|e| be(&e))?;
                        w.open_table(RUN_BY_OUTCOME)
                            .map_err(|e| be(&e))?
                            .insert(("default", "failed", 0u64), good_key.as_str())
                            .map_err(|e| be(&e))?;
                    }
                    w.commit().map_err(|e| be(&e))?;
                    Ok(())
                }
            })
            .await
            .expect("plant the healthy rows");
        assert_eq!(
            store.abandoned_runs(10).await.expect("a clean scan"),
            vec![stranded]
        );
        assert_eq!(
            store
                .runs_by_outcome("failed", 10)
                .await
                .expect("a clean scan"),
            vec![stranded]
        );

        // The garbage no correct writer produces.
        store
            .with_db(|db| {
                let w = begin_write(db)?;
                {
                    w.open_table(RUN_LEASE)
                        .map_err(|e| be(&e))?
                        .insert("default/not-a-run-id", ("worker", 1u64, 0u64))
                        .map_err(|e| be(&e))?;
                    w.open_table(RUN_BY_OUTCOME)
                        .map_err(|e| be(&e))?
                        .insert(("default", "failed", 1u64), "default/not-a-run-id")
                        .map_err(|e| be(&e))?;
                }
                w.commit().map_err(|e| be(&e))?;
                Ok(())
            })
            .await
            .expect("plant the corrupt rows");

        let err = store
            .abandoned_runs(10)
            .await
            .expect_err("an unparsable lease row must refuse the sweep, not vanish from it");
        assert!(
            matches!(err, StoreError::Corrupt { .. }),
            "the refusal must be Corrupt, so it is promoted past retry logic: {err}"
        );
        let err = store
            .runs_by_outcome("failed", 10)
            .await
            .expect_err("an unparsable outcome row must refuse the listing, not vanish from it");
        assert!(
            matches!(err, StoreError::Corrupt { .. }),
            "the refusal must be Corrupt, so it is promoted past retry logic: {err}"
        );
    }
}
