//! SQLite-backed journal.
//!
//! Two of the runtime's three core guarantees are enforced *here*, as database
//! constraints rather than application logic — because application logic can be
//! bypassed by the next caller and a constraint cannot:
//!
//! * **Exactly-once** — a partial unique index on `(run_id, effect_key)` where
//!   `kind = 'EffectStarted'`. A second start for one effect is rejected by the
//!   engine, not by a code path someone might forget to call.
//! * **Fencing** — the lease epoch is compared inside the same transaction that
//!   writes. A stale writer cannot interleave between the check and the append,
//!   because there is no gap to interleave into.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, params};

use crate::core::{Digest, EffectKey, Epoch, RunId, Seq, StoreError};
use crate::journal::{Append, Cancellation, Head, JournalStore, Lease, Record};

const SCHEMA: &str = r"
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = FULL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS journal (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     TEXT    NOT NULL,
    seq        INTEGER NOT NULL,
    case_id    TEXT,
    step       INTEGER,
    epoch      INTEGER NOT NULL,
    kind       TEXT    NOT NULL,
    version    INTEGER NOT NULL,
    effect_key TEXT,
    body       BLOB    NOT NULL,
    prev_hash  BLOB    NOT NULL,
    hash       BLOB    NOT NULL,
    -- Who wrote it. Null when the plane has no signer configured, which is an
    -- ordinary state: a hash chain still detects edits, it just cannot say who
    -- made them. Beside the hash rather than in `body`, because the signature
    -- covers the hash.
    key_id     TEXT,
    signature  BLOB,
    UNIQUE (run_id, seq)
);

CREATE INDEX IF NOT EXISTS journal_run_seq ON journal (run_id, seq);
CREATE INDEX IF NOT EXISTS journal_case    ON journal (case_id, id) WHERE case_id IS NOT NULL;

-- Exactly-once, as an invariant of the engine rather than of the caller.
CREATE UNIQUE INDEX IF NOT EXISTS journal_effect_once
    ON journal (run_id, effect_key) WHERE kind = 'EffectStarted';

-- Run ownership. `epoch` is the fencing token carried on every append.
CREATE TABLE IF NOT EXISTS run_lease (
    run_id     TEXT PRIMARY KEY,
    owner      TEXT    NOT NULL,
    epoch      INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS run_seal (
    run_id     TEXT PRIMARY KEY,
    outcome    TEXT NOT NULL,
    chain_head BLOB NOT NULL,
    sealed_at  INTEGER NOT NULL,
    -- Position in the plane's Merkle log, assigned at seal time.
    --
    -- `AUTOINCREMENT` semantics matter here: the order leaves enter the tree is
    -- part of what the root commits to, so a reused index after a delete would
    -- let a removed run be replaced by a different one at the same position.
    log_index  INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS run_seal_log ON run_seal (log_index)
    WHERE log_index IS NOT NULL;

-- An operator's stop request. Beside the chain rather than in it, and
-- deliberately not fenced: whoever wants a run stopped is not its owner, holds
-- no epoch, and is usually asking because the owner is busy. `PRIMARY KEY` on
-- the run makes the request idempotent, so a retry cannot overwrite the original
-- asker.
CREATE TABLE IF NOT EXISTS run_cancel (
    run_id       TEXT PRIMARY KEY,
    actor        TEXT    NOT NULL,
    reason       TEXT    NOT NULL,
    requested_at INTEGER NOT NULL
);
";

/// A single-node journal store.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
    /// Attached to the store rather than passed per append, because only the
    /// store knows a record's chain hash — it assigns `seq` and `prev_hash`
    /// inside the same transaction that writes. Signing anywhere else would be
    /// signing a guess about what the hash will be.
    signer: Option<Arc<dyn crate::core::Signer>>,
    /// Names this plane's Merkle log in every checkpoint.
    origin: String,
}

impl SqliteStore {
    /// Open (or create) a database file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path).map_err(|e| be(&e))?;
        Self::init(conn)
    }

    /// An ephemeral database — for tests and for the simulator.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(|e| be(&e))?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, StoreError> {
        conn.execute_batch(SCHEMA).map_err(|e| be(&e))?;
        conn.execute_batch(super::cases::CASE_SCHEMA)
            .map_err(|e| be(&e))?;
        conn.execute_batch(super::events::EVENT_SCHEMA)
            .map_err(|e| be(&e))?;
        conn.execute_batch(super::timers::SCHEMA)
            .map_err(|e| be(&e))?;
        conn.execute_batch(super::batches::SCHEMA)
            .map_err(|e| be(&e))?;
        conn.execute_batch(super::tasks::TASK_SCHEMA)
            .map_err(|e| be(&e))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
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

    /// The log's leaves, in seal order.
    async fn log_leaves(&self) -> Result<Vec<Digest>, StoreError> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT chain_head FROM run_seal
                      WHERE log_index IS NOT NULL ORDER BY log_index ASC",
                )
                .map_err(|e| be(&e))?;
            let rows = stmt
                .query_map([], |r| r.get::<_, Vec<u8>>(0))
                .map_err(|e| be(&e))?;
            let mut out = Vec::new();
            for row in rows {
                let bytes = row.map_err(|e| be(&e))?;
                let arr: [u8; 32] = bytes.try_into().map_err(|_| StoreError::Corrupt {
                    seq: 0,
                    detail: "a stored seal is not 32 bytes".into(),
                })?;
                out.push(crate::core::merkle::leaf_hash(&Digest::from_bytes(arr)));
            }
            Ok(out)
        })
        .await
    }

    /// Where a run sits in the log, and its leaf value.
    async fn log_position(&self, run: RunId) -> Result<Option<(usize, Digest)>, StoreError> {
        self.with_conn(move |conn| {
            // The *dense* rank, not the stored `log_index`. The two diverge the
            // moment a row is removed: indices keep their gaps — deliberately,
            // so a freed position is never reissued — while the tree is built
            // from the surviving leaves in order and cannot have holes. Handing
            // back the raw index makes every run after a deleted one fail to
            // prove an inclusion that is perfectly valid.
            let found = conn
                .query_row(
                    "SELECT rank, chain_head FROM (
                         SELECT run_id, chain_head,
                                ROW_NUMBER() OVER (ORDER BY log_index) - 1 AS rank
                           FROM run_seal WHERE log_index IS NOT NULL
                     ) ranked WHERE run_id = ?1",
                    params![run.to_string()],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
                )
                .optional()
                .map_err(|e| be(&e))?;
            let Some((index, bytes)) = found else {
                return Ok(None);
            };
            let arr: [u8; 32] = bytes.try_into().map_err(|_| StoreError::Corrupt {
                seq: 0,
                detail: "a stored seal is not 32 bytes".into(),
            })?;
            Ok(Some((
                usize::try_from(index).unwrap_or(0),
                Digest::from_bytes(arr),
            )))
        })
        .await
    }

    /// Write records signed as this identity.
    ///
    /// Off unless asked, and the default is *unsigned rather than
    /// self-signed*: a plane that quietly minted its own key would produce
    /// records that look attested and prove nothing, which is worse than
    /// records that admit they are only hashed.
    #[must_use]
    pub fn signing_as(mut self, signer: Arc<dyn crate::core::Signer>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Overwrite a record's stored bytes while leaving its hash untouched,
    /// simulating an after-the-fact edit.
    ///
    /// Exists so the test suite can prove that tampering is *detected* rather
    /// than assumed to be impossible. Not part of the supported surface.
    #[doc(hidden)]
    pub async fn tamper_for_test(
        &self,
        run: RunId,
        seq: Seq,
        body: Vec<u8>,
    ) -> Result<(), StoreError> {
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE journal SET body = ?1 WHERE run_id = ?2 AND seq = ?3",
                params![body, run.to_string(), seq.cast_signed()],
            )
            .map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    /// Remove a run entirely — journal rows and seal alike.
    ///
    /// Exists so the test suite can prove that a *whole-run deletion* is
    /// detected. It is the one tampering the per-run chain structurally cannot
    /// see, so a suite that could not perform it could not test the mechanism
    /// that does. Not part of the supported surface.
    #[doc(hidden)]
    pub async fn delete_run_for_test(&self, run: RunId) -> Result<(), StoreError> {
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(|e| be(&e))?;
            tx.execute(
                "DELETE FROM journal WHERE run_id = ?1",
                params![run.to_string()],
            )
            .map_err(|e| be(&e))?;
            tx.execute(
                "DELETE FROM run_seal WHERE run_id = ?1",
                params![run.to_string()],
            )
            .map_err(|e| be(&e))?;
            tx.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    /// Run a closure against the connection on the blocking pool.
    pub(super) async fn with_conn<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|_| {
                StoreError::Backend("journal mutex poisoned by a panicking writer".into())
            })?;
            f(&mut guard)
        })
        .await
        .map_err(|e| StoreError::Backend(format!("blocking pool: {e}")))?
    }
}

pub(super) fn be(e: &rusqlite::Error) -> StoreError {
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

fn head_of(tx: &rusqlite::Transaction<'_>, run: RunId) -> Result<Head, StoreError> {
    let row: Option<(i64, Vec<u8>)> = tx
        .query_row(
            "SELECT seq, hash FROM journal WHERE run_id = ?1 ORDER BY seq DESC LIMIT 1",
            params![run.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| be(&e))?;

    match row {
        None => Ok(Head::genesis()),
        Some((seq, hash)) => {
            let bytes: [u8; 32] = hash.try_into().map_err(|_| StoreError::Corrupt {
                seq: 0,
                detail: "stored hash is not 32 bytes".into(),
            })?;
            Ok(Head {
                seq: seq.cast_unsigned(),
                hash: Digest::from_bytes(bytes),
            })
        }
    }
}

/// Reject a writer whose epoch is below the current lease.
///
/// Called inside the append transaction so there is no window between the check
/// and the write.
fn check_fence(tx: &rusqlite::Transaction<'_>, run: RunId, epoch: Epoch) -> Result<(), StoreError> {
    let current: Option<i64> = tx
        .query_row(
            "SELECT epoch FROM run_lease WHERE run_id = ?1",
            params![run.to_string()],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| be(&e))?;

    if let Some(current) = current {
        let current = current.cast_unsigned();
        if epoch < current {
            return Err(StoreError::Fenced {
                run: run.to_string(),
                held: epoch,
                current,
            });
        }
    }
    Ok(())
}

#[async_trait]
impl JournalStore for SqliteStore {
    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError> {
        // Cloned out before the closure: `with_conn` moves its body onto a
        // blocking pool, so a borrow of `self` cannot travel with it.
        let signer = self.signer.clone();
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

        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(|e| be(&e))?;
            check_fence(&tx, run, epoch)?;

            let mut head = head_of(&tx, run)?;
            let mut sealed = Vec::with_capacity(batch.len());

            for append in batch {
                let effect_key = append.effect_key.map(EffectKey::to_hex);
                let body = append.into_body(head.seq + 1, epoch);
                let kind = body.kind.kind_str();
                let version = body.v;
                let case = body.case.map(|c| c.to_string());
                let step = body.step.map(|s| i64::from(s.0));
                let record = Record::seal_signed(body, head.hash, signer.as_deref())?;

                tx.execute(
                    "INSERT INTO journal
                       (run_id, seq, case_id, step, epoch, kind, version, effect_key,
                        body, prev_hash, hash, key_id, signature)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    params![
                        run.to_string(),
                        record.seq().cast_signed(),
                        case,
                        step,
                        epoch.cast_signed(),
                        kind,
                        version,
                        effect_key,
                        record.raw(),
                        record.prev_hash.as_bytes().as_slice(),
                        record.hash.as_bytes().as_slice(),
                        record.attestation.as_ref().map(|a| a.key_id.clone()),
                        record.attestation.as_ref().map(|a| a.signature.clone()),
                    ],
                )
                .map_err(|e| match e {
                    rusqlite::Error::SqliteFailure(f, _)
                        if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        // The exactly-once index fired: this effect already
                        // started in this run.
                        record.effect_key().map_or_else(
                            || StoreError::Backend(format!("constraint violation: {e}")),
                            StoreError::DuplicateEffect,
                        )
                    }
                    other => be(&other),
                })?;

                head = Head {
                    seq: record.seq(),
                    hash: record.hash,
                };
                sealed.push(record);
            }

            tx.commit().map_err(|e| be(&e))?;
            Ok(sealed)
        })
        .await
    }

    async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT body, prev_hash, hash, key_id, signature FROM journal
                     WHERE run_id = ?1 AND seq >= ?2 ORDER BY seq ASC",
                )
                .map_err(|e| be(&e))?;

            let rows = stmt
                .query_map(params![run.to_string(), from.cast_signed()], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<Vec<u8>>>(4)?,
                    ))
                })
                .map_err(|e| be(&e))?;

            let mut out = Vec::new();
            for row in rows {
                let (body, prev, hash, key_id, signature) = row.map_err(|e| be(&e))?;
                let to_digest = |v: Vec<u8>| -> Result<Digest, StoreError> {
                    let b: [u8; 32] = v.try_into().map_err(|_| StoreError::Corrupt {
                        seq: 0,
                        detail: "stored hash is not 32 bytes".into(),
                    })?;
                    Ok(Digest::from_bytes(b))
                };
                // A key id without a signature (or the reverse) is a half-written
                // row, not an unsigned record — zipped rather than defaulted so
                // it cannot be mistaken for the ordinary unsigned case.
                let attestation = key_id
                    .zip(signature)
                    .map(|(key_id, signature)| crate::core::Attestation { key_id, signature });
                out.push(Record::from_stored_attested(
                    body,
                    to_digest(prev)?,
                    to_digest(hash)?,
                    attestation,
                )?);
            }
            Ok(out)
        })
        .await
    }

    async fn head(&self, run: RunId) -> Result<Head, StoreError> {
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(|e| be(&e))?;
            let h = head_of(&tx, run)?;
            tx.commit().map_err(|e| be(&e))?;
            Ok(h)
        })
        .await
    }

    async fn acquire(&self, run: RunId, owner: &str, ttl: Duration) -> Result<Lease, StoreError> {
        let owner = owner.to_owned();
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(|e| be(&e))?;
            let now = now_secs();
            let expires = now + ttl.as_secs().max(1);
            let key = run.to_string();

            let existing: Option<(String, i64, i64)> = tx
                .query_row(
                    "SELECT owner, epoch, expires_at FROM run_lease WHERE run_id = ?1",
                    params![key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
                .map_err(|e| be(&e))?;

            let epoch = match existing {
                // Fresh run.
                None => 1,
                // Ours: renew without bumping — the epoch only moves on takeover.
                Some((held_by, epoch, _)) if held_by == owner => epoch.cast_unsigned(),
                // Someone else's, still live. Not a fencing situation: this
                // caller is not stale, it is simply not the owner. Waiting is
                // the correct response, so say so precisely.
                Some((held_by, epoch, expires_at)) if expires_at.cast_unsigned() > now => {
                    return Err(StoreError::LeaseHeld {
                        run: key,
                        owner: held_by,
                        epoch: epoch.cast_unsigned(),
                        remaining_secs: expires_at.cast_unsigned().saturating_sub(now),
                    });
                }
                // Expired: take over and fence the previous owner.
                Some((_, epoch, _)) => epoch.cast_unsigned() + 1,
            };

            tx.execute(
                "INSERT INTO run_lease (run_id, owner, epoch, expires_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(run_id) DO UPDATE SET
                   owner = excluded.owner,
                   epoch = excluded.epoch,
                   expires_at = excluded.expires_at",
                params![key, owner, epoch.cast_signed(), expires.cast_signed()],
            )
            .map_err(|e| be(&e))?;

            tx.commit().map_err(|e| be(&e))?;
            Ok(Lease { run, owner, epoch })
        })
        .await
    }

    async fn seal(&self, run: RunId, epoch: Epoch, outcome: &str) -> Result<Digest, StoreError> {
        let outcome = outcome.to_owned();
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(|e| be(&e))?;
            check_fence(&tx, run, epoch)?;
            let head = head_of(&tx, run)?;
            tx.execute(
                "INSERT INTO run_seal (run_id, outcome, chain_head, sealed_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(run_id) DO NOTHING",
                params![
                    run.to_string(),
                    outcome,
                    head.hash.as_bytes().as_slice(),
                    now_secs().cast_signed()
                ],
            )
            .map_err(|e| be(&e))?;
            // Assign the next log position, in the same transaction that
            // seals. A seal that is not in the log is a run the checkpoint does
            // not commit to — which is precisely the hole this closes.
            //
            // `MAX + 1` rather than `COUNT`: a count reuses an index after a
            // delete, which would let a removed run be silently replaced at the
            // same position by a different one.
            tx.execute(
                "UPDATE run_seal
                    SET log_index = (SELECT COALESCE(MAX(log_index), -1) + 1 FROM run_seal)
                  WHERE run_id = ?1 AND log_index IS NULL",
                params![run.to_string()],
            )
            .map_err(|e| be(&e))?;

            tx.commit().map_err(|e| be(&e))?;
            Ok(head.hash)
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
            // one back here would let "your checkpoint is from the future"
            // read as "everything is fine".
            return Err(StoreError::Backend(format!(
                "a checkpoint of size {old_size} is larger than this log ({}) —                  either it belongs to another plane, or runs were removed",
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
        let (actor, reason) = (actor.to_owned(), reason.to_owned());
        self.with_conn(move |conn| {
            // No fence check, on purpose — see `JournalStore::request_cancel`.
            // `DO NOTHING` rather than an upsert: the first asker is the one on
            // the record, and a retried request must not rewrite who intervened.
            let n = conn
                .execute(
                    "INSERT INTO run_cancel (run_id, actor, reason, requested_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(run_id) DO NOTHING",
                    params![run.to_string(), actor, reason, now_secs().cast_signed()],
                )
                .map_err(|e| be(&e))?;
            Ok(n == 1)
        })
        .await
    }

    async fn cancellation(&self, run: RunId) -> Result<Option<Cancellation>, StoreError> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT actor, reason FROM run_cancel WHERE run_id = ?1",
                params![run.to_string()],
                |row| {
                    Ok(Cancellation {
                        actor: row.get(0)?,
                        reason: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(|e| be(&e))
        })
        .await
    }
}
