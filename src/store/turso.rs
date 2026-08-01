//! The embedded journal, on Turso.
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
//!
//! Turso is a from-scratch SQLite-compatible engine written in Rust. It replaced
//! `rusqlite` outright, for two reasons that were each costing something real:
//!
//! * **No C dependency.** The bundled SQLite arrived through `libsqlite3-sys`,
//!   which raised its own toolchain floor without declaring `rust-version` — so
//!   cargo's resolver could not protect against it, and this crate's true
//!   minimum drifted above the one it advertised.
//! * **Natively async.** `rusqlite` blocks, so every journal read had to hop to
//!   the blocking pool through `spawn_blocking`. That hop is gone.
//!
//! Being SQLite-*compatible* is a claim, not a guarantee, so it is checked
//! rather than trusted: this store is held to [`crate::testkit::conformance`],
//! which states the [`JournalStore`] contract once and names the invariant that
//! fails. The partial index above is exactly the kind of thing a
//! reimplementation can accept and then quietly not enforce.
//!
//! The connection is held behind an async mutex rather than opened per call.
//! Appends serialise anyway — each one reads the chain head and writes the next
//! link, which is a read-modify-write over a single row — so a pool would buy
//! contention on the same lock the database would take, and would add a
//! `SQLITE_BUSY` failure mode that a single writer cannot have. Correctness does
//! not rest on the mutex: it rests on the transaction, the fence check inside
//! it, and the partial unique index.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::sync::Mutex;
use turso::{Connection, Row, Rows, params};

use crate::core::{Digest, EffectKey, Epoch, RunId, Seq, StoreError};
use crate::journal::{Append, Cancellation, Head, JournalStore, Lease, Record};

/// Connection tuning.
///
/// `journal_mode` is deliberately absent: it reports its result as a row, and a
/// statement that returns rows is not a batch statement — it is applied
/// separately in [`TursoStore::init`] so a silently ignored result cannot be
/// mistaken for a mode that was set.
const PRAGMAS: &str = "PRAGMA foreign_keys = ON;";

const JOURNAL: &str = r"
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

/// A single-node journal store on Turso.
#[derive(Debug, Clone)]
pub struct TursoStore {
    conn: Arc<Mutex<Connection>>,
    /// Attached to the store rather than passed per append, because only the
    /// store knows a record's chain hash — it assigns `seq` and `prev_hash`
    /// inside the same transaction that writes. Signing anywhere else would be
    /// signing a guess about what the hash will be.
    signer: Option<Arc<dyn crate::core::Signer>>,
    /// Names this plane's Merkle log in every checkpoint.
    origin: String,
}

impl TursoStore {
    /// Open (or create) a database file.
    ///
    /// # Errors
    ///
    /// If the file cannot be opened or the schema cannot be applied.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_string_lossy().into_owned();
        Self::open_at(&path).await
    }

    /// An ephemeral database — for tests and for the simulator.
    ///
    /// # Errors
    ///
    /// If the schema cannot be applied.
    pub async fn open_in_memory() -> Result<Self, StoreError> {
        Self::open_at(":memory:").await
    }

    async fn open_at(path: &str) -> Result<Self, StoreError> {
        let db = turso::Builder::new_local(path)
            .build()
            .await
            .map_err(|e| be(&e))?;
        let conn = db.connect().map_err(|e| be(&e))?;
        Self::init(conn).await
    }

    async fn init(conn: Connection) -> Result<Self, StoreError> {
        conn.execute_batch(PRAGMAS).await.map_err(|e| be(&e))?;
        // Returns the mode it settled on, so it is issued as a query and the
        // answer is read. A store that silently ran without WAL would still
        // pass every test in this crate and lose durability characteristics
        // nobody had agreed to give up.
        let mut rows = conn
            .query("PRAGMA journal_mode = WAL", ())
            .await
            .map_err(|e| be(&e))?;
        rows.next().await.map_err(|e| be(&e))?;
        drop(rows);

        for ddl in [
            JOURNAL,
            super::cases::CASE_SCHEMA,
            super::events::EVENT_SCHEMA,
            super::timers::SCHEMA,
            super::batches::SCHEMA,
            super::tasks::TASK_SCHEMA,
        ] {
            conn.execute_batch(ddl).await.map_err(|e| be(&e))?;
        }

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

    /// Exclusive access to the connection.
    ///
    /// The sibling modules that implement the case layer hold it for the length
    /// of one operation, exactly as the methods here do.
    pub(super) async fn conn(&self) -> tokio::sync::MutexGuard<'_, Connection> {
        self.conn.lock().await
    }

    /// The log's leaves, in seal order.
    async fn log_leaves(&self) -> Result<Vec<Digest>, StoreError> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT chain_head FROM run_seal
                  WHERE log_index IS NOT NULL ORDER BY log_index ASC",
                (),
            )
            .await
            .map_err(|e| be(&e))?;

        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| be(&e))? {
            out.push(crate::core::merkle::leaf_hash(&digest_at(&row, 0)?));
        }
        Ok(out)
    }

    /// Where a run sits in the log, and its leaf value.
    async fn log_position(&self, run: RunId) -> Result<Option<(usize, Digest)>, StoreError> {
        let conn = self.conn.lock().await;
        // The *dense* rank, not the stored `log_index`. The two diverge the
        // moment a row is removed: indices keep their gaps — deliberately, so a
        // freed position is never reissued — while the tree is built from the
        // surviving leaves in order and cannot have holes. Handing back the raw
        // index makes every run after a deleted one fail to prove an inclusion
        // that is perfectly valid.
        let rows = conn
            .query(
                "SELECT rank, chain_head FROM (
                     SELECT run_id, chain_head,
                            ROW_NUMBER() OVER (ORDER BY log_index) - 1 AS rank
                       FROM run_seal WHERE log_index IS NOT NULL
                 ) ranked WHERE run_id = ?1",
                params![run.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;

        let Some(row) = first(rows).await? else {
            return Ok(None);
        };
        let index: i64 = row.get(0).map_err(|e| be(&e))?;
        Ok(Some((
            usize::try_from(index).unwrap_or(0),
            digest_at(&row, 1)?,
        )))
    }

    /// Overwrite a record's stored bytes while leaving its hash untouched,
    /// simulating an after-the-fact edit.
    ///
    /// Exists so the test suite can prove that tampering is *detected* rather
    /// than assumed to be impossible. Not part of the supported surface.
    ///
    /// # Errors
    ///
    /// If the update cannot be applied.
    #[doc(hidden)]
    pub async fn tamper_for_test(
        &self,
        run: RunId,
        seq: Seq,
        body: Vec<u8>,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE journal SET body = ?1 WHERE run_id = ?2 AND seq = ?3",
            params![body, run.to_string(), seq.cast_signed()],
        )
        .await
        .map_err(|e| be(&e))?;
        Ok(())
    }

    /// Remove a run entirely — journal rows and seal alike.
    ///
    /// Exists so the test suite can prove that a *whole-run deletion* is
    /// detected. It is the one tampering the per-run chain structurally cannot
    /// see, so a suite that could not perform it could not test the mechanism
    /// that does. Not part of the supported surface.
    ///
    /// # Errors
    ///
    /// If the deletion cannot be applied.
    #[doc(hidden)]
    pub async fn delete_run_for_test(&self, run: RunId) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction().await.map_err(|e| be(&e))?;
        tx.execute(
            "DELETE FROM journal WHERE run_id = ?1",
            params![run.to_string()],
        )
        .await
        .map_err(|e| be(&e))?;
        tx.execute(
            "DELETE FROM run_seal WHERE run_id = ?1",
            params![run.to_string()],
        )
        .await
        .map_err(|e| be(&e))?;
        tx.commit().await.map_err(|e| be(&e))?;
        Ok(())
    }
}

pub(super) fn be(e: &turso::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// The first row of a result set, or `None`.
///
/// Turso has no `query_row`, and the shape it replaces — "at most one row, and
/// absence is ordinary" — appears in every lookup here.
pub(super) async fn first(mut rows: Rows) -> Result<Option<Row>, StoreError> {
    rows.next().await.map_err(|e| be(&e))
}

/// Read a 32-byte column as a digest.
fn digest_at(row: &Row, idx: usize) -> Result<Digest, StoreError> {
    let bytes: Vec<u8> = row.get(idx).map_err(|e| be(&e))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| StoreError::Corrupt {
        seq: 0,
        detail: "stored hash is not 32 bytes".into(),
    })?;
    Ok(Digest::from_bytes(arr))
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
///
/// Takes a plain `&Connection` because `Transaction` derefs to one — so the
/// same function serves the transactional callers (which need the read and the
/// write to be indivisible) and `head`.
async fn head_of(conn: &Connection, run: RunId) -> Result<Head, StoreError> {
    let rows = conn
        .query(
            "SELECT seq, hash FROM journal WHERE run_id = ?1 ORDER BY seq DESC LIMIT 1",
            params![run.to_string()],
        )
        .await
        .map_err(|e| be(&e))?;

    match first(rows).await? {
        None => Ok(Head::genesis()),
        Some(row) => {
            let seq: i64 = row.get(0).map_err(|e| be(&e))?;
            Ok(Head {
                seq: seq.cast_unsigned(),
                hash: digest_at(&row, 1)?,
            })
        }
    }
}

/// Reject a writer whose epoch is below the current lease.
///
/// Called inside the append transaction so there is no window between the check
/// and the write.
async fn check_fence(conn: &Connection, run: RunId, epoch: Epoch) -> Result<(), StoreError> {
    let rows = conn
        .query(
            "SELECT epoch FROM run_lease WHERE run_id = ?1",
            params![run.to_string()],
        )
        .await
        .map_err(|e| be(&e))?;

    if let Some(row) = first(rows).await? {
        let current: i64 = row.get(0).map_err(|e| be(&e))?;
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
impl JournalStore for TursoStore {
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

        let mut conn = self.conn.lock().await;
        let tx = conn.transaction().await.map_err(|e| be(&e))?;
        check_fence(&tx, run, epoch).await?;

        let mut head = head_of(&tx, run).await?;
        let mut sealed = Vec::with_capacity(batch.len());

        for append in batch {
            let effect_key = append.effect_key.map(EffectKey::to_hex);
            let body = append.into_body(head.seq + 1, epoch);
            let kind = body.kind.kind_str();
            let version = body.v;
            let case = body.case.map(|c| c.to_string());
            let step = body.step.map(|s| i64::from(s.0));
            let record = Record::seal_signed(body, head.hash, self.signer.as_deref())?;

            let written = tx
                .execute(
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
                        record.raw().to_vec(),
                        record.prev_hash.as_bytes().to_vec(),
                        record.hash.as_bytes().to_vec(),
                        record.attestation.as_ref().map(|a| a.key_id.clone()),
                        record.attestation.as_ref().map(|a| a.signature.clone()),
                    ],
                )
                .await;

            written.map_err(|e| match e {
                // The exactly-once index fired: this effect already started in
                // this run. Matched on the typed variant rather than on the
                // message text — a backend that reworded its diagnostic must not
                // be able to turn a duplicate into an opaque backend error.
                turso::Error::Constraint(_) => record.effect_key().map_or_else(
                    || StoreError::Backend(format!("constraint violation: {e}")),
                    StoreError::DuplicateEffect,
                ),
                other => be(&other),
            })?;

            head = Head {
                seq: record.seq(),
                hash: record.hash,
            };
            sealed.push(record);
        }

        tx.commit().await.map_err(|e| be(&e))?;
        Ok(sealed)
    }

    async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT body, prev_hash, hash, key_id, signature FROM journal
                 WHERE run_id = ?1 AND seq >= ?2 ORDER BY seq ASC",
                params![run.to_string(), from.cast_signed()],
            )
            .await
            .map_err(|e| be(&e))?;

        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| be(&e))? {
            let body: Vec<u8> = row.get(0).map_err(|e| be(&e))?;
            let prev = digest_at(&row, 1)?;
            let hash = digest_at(&row, 2)?;
            let key_id: Option<String> = row.get(3).map_err(|e| be(&e))?;
            let signature: Option<Vec<u8>> = row.get(4).map_err(|e| be(&e))?;
            // A key id without a signature (or the reverse) is a half-written
            // row, not an unsigned record — zipped rather than defaulted so it
            // cannot be mistaken for the ordinary unsigned case.
            let attestation = key_id
                .zip(signature)
                .map(|(key_id, signature)| crate::core::Attestation { key_id, signature });
            out.push(Record::from_stored_attested(body, prev, hash, attestation)?);
        }
        Ok(out)
    }

    async fn head(&self, run: RunId) -> Result<Head, StoreError> {
        let conn = self.conn.lock().await;
        head_of(&conn, run).await
    }

    async fn acquire(&self, run: RunId, owner: &str, ttl: Duration) -> Result<Lease, StoreError> {
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction().await.map_err(|e| be(&e))?;
        let now = now_secs();
        let expires = now + ttl.as_secs().max(1);
        let key = run.to_string();

        let rows = tx
            .query(
                "SELECT owner, epoch, expires_at FROM run_lease WHERE run_id = ?1",
                params![key.clone()],
            )
            .await
            .map_err(|e| be(&e))?;
        let existing = match first(rows).await? {
            None => None,
            Some(row) => {
                let held_by: String = row.get(0).map_err(|e| be(&e))?;
                let epoch: i64 = row.get(1).map_err(|e| be(&e))?;
                let expires_at: i64 = row.get(2).map_err(|e| be(&e))?;
                Some((held_by, epoch, expires_at))
            }
        };

        let epoch = match existing {
            // Fresh run.
            None => 1,
            // Ours: renew without bumping — the epoch only moves on takeover.
            Some((held_by, epoch, _)) if held_by == owner => epoch.cast_unsigned(),
            // Someone else's, still live. Not a fencing situation: this caller
            // is not stale, it is simply not the owner. Waiting is the correct
            // response, so say so precisely.
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
            params![
                key,
                owner.to_owned(),
                epoch.cast_signed(),
                expires.cast_signed()
            ],
        )
        .await
        .map_err(|e| be(&e))?;

        tx.commit().await.map_err(|e| be(&e))?;
        Ok(Lease {
            run,
            owner: owner.to_owned(),
            epoch,
        })
    }

    async fn seal(&self, run: RunId, epoch: Epoch, outcome: &str) -> Result<Digest, StoreError> {
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction().await.map_err(|e| be(&e))?;
        check_fence(&tx, run, epoch).await?;
        let head = head_of(&tx, run).await?;

        tx.execute(
            "INSERT INTO run_seal (run_id, outcome, chain_head, sealed_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(run_id) DO NOTHING",
            params![
                run.to_string(),
                outcome.to_owned(),
                head.hash.as_bytes().to_vec(),
                now_secs().cast_signed()
            ],
        )
        .await
        .map_err(|e| be(&e))?;

        // Assign the next log position, in the same transaction that seals. A
        // seal that is not in the log is a run the checkpoint does not commit
        // to — which is precisely the hole this closes.
        //
        // `MAX + 1` rather than `COUNT`: a count reuses an index after a delete,
        // which would let a removed run be silently replaced at the same
        // position by a different one.
        tx.execute(
            "UPDATE run_seal
                SET log_index = (SELECT COALESCE(MAX(log_index), -1) + 1 FROM run_seal)
              WHERE run_id = ?1 AND log_index IS NULL",
            params![run.to_string()],
        )
        .await
        .map_err(|e| be(&e))?;

        tx.commit().await.map_err(|e| be(&e))?;
        Ok(head.hash)
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
        let conn = self.conn.lock().await;
        // No fence check, on purpose — see `JournalStore::request_cancel`.
        // `DO NOTHING` rather than an upsert: the first asker is the one on the
        // record, and a retried request must not rewrite who intervened.
        let n = conn
            .execute(
                "INSERT INTO run_cancel (run_id, actor, reason, requested_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(run_id) DO NOTHING",
                params![
                    run.to_string(),
                    actor.to_owned(),
                    reason.to_owned(),
                    now_secs().cast_signed()
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(n == 1)
    }

    async fn cancellation(&self, run: RunId) -> Result<Option<Cancellation>, StoreError> {
        let conn = self.conn.lock().await;
        let rows = conn
            .query(
                "SELECT actor, reason FROM run_cancel WHERE run_id = ?1",
                params![run.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;

        match first(rows).await? {
            None => Ok(None),
            Some(row) => Ok(Some(Cancellation {
                actor: row.get(0).map_err(|e| be(&e))?,
                reason: row.get(1).map_err(|e| be(&e))?,
            })),
        }
    }
}
