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

/// `(run_id, effect_key) -> seq`. Exactly-once. Only `EffectStarted` is written
/// here, which is the `WHERE` clause of the partial index this replaces.
const EFFECT_ONCE: TableDefinition<(&str, &str), u64> = TableDefinition::new("effect_once");

/// `run_id -> (owner, epoch, expires_at)`.
const RUN_LEASE: TableDefinition<&str, (&str, u64, u64)> = TableDefinition::new("run_lease");

/// `run_id -> (outcome, chain_head, sealed_at)`.
const RUN_SEAL: TableDefinition<&str, (&str, &[u8], u64)> = TableDefinition::new("run_seal");

/// `log_index -> run_id`, the plane's Merkle log in seal order.
///
/// Positions are never reissued, so this table keeps gaps when a run is removed
/// — deliberately, so a freed position cannot be silently reused by a different
/// run. The *tree* is built by iterating in key order, which yields dense
/// positions; that is what makes the `ROW_NUMBER() OVER (ORDER BY log_index)`
/// the SQL backend needed unnecessary here, and with it the rank-vs-index bug
/// that cost an afternoon.
const SEAL_LOG: TableDefinition<u64, &str> = TableDefinition::new("seal_log");

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

    /// An ephemeral database — for tests and for the simulator.
    ///
    /// redb has no in-memory backend, so this is a file in a temporary
    /// directory that is removed when the process exits. Named with a counter
    /// rather than a random suffix because ambient randomness is denied
    /// crate-wide; two stores in one process must still not collide.
    ///
    /// # Errors
    ///
    /// If the temporary file cannot be created.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("agentplane-{pid}-{n}.redb"));
        let _ = std::fs::remove_file(&path);
        let db = Database::create(&path).map_err(|e| be(&e))?;
        // Unlinked immediately: the handle stays valid, so the file is reachable
        // by this process and by nothing else, and it cannot outlive a crash.
        let _ = std::fs::remove_file(&path);
        Self::init(db)
    }

    /// Create every table, so a read on a fresh database is not a missing-table
    /// error the read paths would each have to special-case.
    fn init(db: Database) -> Result<Self, StoreError> {
        let w = begin_write(&db)?;
        {
            w.open_table(JOURNAL).map_err(|e| be(&e))?;
            w.open_table(EFFECT_ONCE).map_err(|e| be(&e))?;
            w.open_table(RUN_LEASE).map_err(|e| be(&e))?;
            w.open_table(RUN_SEAL).map_err(|e| be(&e))?;
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
        })
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

    /// The log's leaves, in seal order.
    async fn log_leaves(&self) -> Result<Vec<Digest>, StoreError> {
        self.with_db(|db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let log = r.open_table(SEAL_LOG).map_err(|e| be(&e))?;
            let seals = r.open_table(RUN_SEAL).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            for entry in log.iter().map_err(|e| be(&e))? {
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
        let key = run.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let log = r.open_table(SEAL_LOG).map_err(|e| be(&e))?;
            let seals = r.open_table(RUN_SEAL).map_err(|e| be(&e))?;
            let mut rank = 0usize;
            for entry in log.iter().map_err(|e| be(&e))? {
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
        let key = run.to_string();
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
                    let tampered = Row {
                        body,
                        ..row.owned()
                    };
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
        let key = run.to_string();
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
    fn owned(self) -> Self {
        self
    }

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
        Ok(Record::from_stored_attested(
            self.body,
            Digest::from_bytes(self.prev_hash),
            Digest::from_bytes(self.hash),
            attestation,
        )?)
    }
}

fn push_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
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

#[async_trait]
impl JournalStore for RedbStore {
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
        let key = run.to_string();

        self.with_db(move |db| {
            let w = begin_write(db)?;
            let sealed = {
                let mut journal = w.open_table(JOURNAL).map_err(|e| be(&e))?;
                let mut once = w.open_table(EFFECT_ONCE).map_err(|e| be(&e))?;

                // Fence inside the write transaction: no window between the
                // check and the append for a stale writer to use.
                {
                    let leases = w.open_table(RUN_LEASE).map_err(|e| be(&e))?;
                    if let Some(l) = leases.get(key.as_str()).map_err(|e| be(&e))? {
                        let (_, current, _) = l.value();
                        if epoch < current {
                            return Err(StoreError::Fenced {
                                run: key.clone(),
                                held: epoch,
                                current,
                            });
                        }
                    }
                }

                let mut head = head_of(&journal, &key)?;
                let mut sealed = Vec::with_capacity(batch.len());

                for append in batch {
                    let effect_key = append.effect_key.map(EffectKey::to_hex);
                    let body = append.into_body(head.seq + 1, epoch);
                    let is_start =
                        matches!(body.kind, crate::journal::RecordKind::EffectStarted { .. });
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

                    head = Head {
                        seq,
                        hash: record.hash,
                    };
                    sealed.push(record);
                }
                sealed
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(sealed)
        })
        .await
    }

    async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError> {
        let key = run.to_string();
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

    async fn head(&self, run: RunId) -> Result<Head, StoreError> {
        let key = run.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(JOURNAL).map_err(|e| be(&e))?;
            head_of(&t, &key)
        })
        .await
    }

    async fn acquire(&self, run: RunId, owner: &str, ttl: Duration) -> Result<Lease, StoreError> {
        let key = run.to_string();
        let owner = owner.to_owned();
        let owner_out = owner.clone();
        let epoch = self
            .with_db(move |db| {
                let w = begin_write(db)?;
                let epoch = {
                    let mut leases = w.open_table(RUN_LEASE).map_err(|e| be(&e))?;
                    let now = now_secs();
                    let expires = now + ttl.as_secs().max(1);

                    let existing = leases.get(key.as_str()).map_err(|e| be(&e))?.map(|v| {
                        let (o, e, x) = v.value();
                        (o.to_owned(), e, x)
                    });

                    let epoch = match existing {
                        // Fresh run.
                        None => 1,
                        // Ours: renew without bumping — the epoch only moves on
                        // takeover.
                        Some((held_by, epoch, _)) if held_by == owner => epoch,
                        // Someone else's, still live. Not a fencing situation:
                        // this caller is not stale, it is simply not the owner.
                        Some((held_by, epoch, expires_at)) if expires_at > now => {
                            return Err(StoreError::LeaseHeld {
                                run: key.clone(),
                                owner: held_by,
                                epoch,
                                remaining_secs: expires_at.saturating_sub(now),
                            });
                        }
                        // Expired: take over and fence the previous owner.
                        Some((_, epoch, _)) => epoch + 1,
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

    async fn seal(&self, run: RunId, epoch: Epoch, outcome: &str) -> Result<Digest, StoreError> {
        let key = run.to_string();
        let outcome = outcome.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let head_hash = {
                {
                    let leases = w.open_table(RUN_LEASE).map_err(|e| be(&e))?;
                    if let Some(l) = leases.get(key.as_str()).map_err(|e| be(&e))? {
                        let (_, current, _) = l.value();
                        if epoch < current {
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
                    let mut counters = w.open_table(COUNTERS).map_err(|e| be(&e))?;
                    let next = counters
                        .get(NEXT_LOG_INDEX)
                        .map_err(|e| be(&e))?
                        .map_or(0, |v| v.value());
                    w.open_table(SEAL_LOG)
                        .map_err(|e| be(&e))?
                        .insert(next, key.as_str())
                        .map_err(|e| be(&e))?;
                    counters
                        .insert(NEXT_LOG_INDEX, next + 1)
                        .map_err(|e| be(&e))?;
                }
                head.hash
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(head_hash)
        })
        .await
    }

    async fn checkpoint(&self) -> Result<crate::journal::Checkpoint, StoreError> {
        let leaves = self.log_leaves().await?;
        Ok(crate::journal::Checkpoint {
            origin: self.origin.clone(),
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
        let key = run.to_string();
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
        let key = run.to_string();
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
