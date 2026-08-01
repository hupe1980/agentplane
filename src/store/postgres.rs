//! PostgreSQL-backed journal.
//!
//! # What this backend is for
//!
//! `SQLite` serves a single process well and cannot serve several. The topology
//! that needs Postgres is the one where two plane instances share a store, and
//! there the interesting question is not throughput — it is who arbitrates.
//!
//! All three of [`JournalStore`]'s guarantees are storage invariants here, in
//! the same sense they are in `SQLite` and for the same reason: application logic
//! can be bypassed by the next caller, and a constraint cannot. That matters
//! more with two writers, not less.
//!
//! # Where a second backend goes wrong
//!
//! Reimplementing prose is how two backends drift. Every guarantee below is
//! checked by `testkit::conformance`, which is run against this store *and*
//! against `SQLite` — one battery, so a Postgres-shaped mistake cannot hide behind
//! a SQLite-shaped test suite.
//!
//! Three details are worth stating because each is a plausible way to get it
//! subtly wrong:
//!
//! * **Exactly-once is a partial unique index**, not a `SELECT` then `INSERT`.
//!   With two writers the read-then-write has a window, and the whole point of
//!   putting it in the database is that there is no window.
//!
//! * **Fencing is a predicate on the write**, evaluated inside the same
//!   statement that appends. Checking the epoch first and appending second
//!   re-introduces exactly the gap a paused instance wakes up into.
//!
//! * **`seq` comes from the run's own chain**, not from a sequence or an
//!   identity column. A global sequence would leave gaps — Postgres sequences
//!   are explicitly non-transactional — and a gap is indistinguishable from a
//!   deleted record when the chain is verified.

use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::{Config, Pool, Runtime as PoolRuntime};
use tokio_postgres::NoTls;
use tokio_postgres::error::SqlState;

use crate::core::{Digest, EffectKey, Epoch, RunId, Seq, StoreError};
use std::sync::Arc;

use crate::journal::{Append, Cancellation, Head, JournalStore, Lease, Record};

/// The schema, applied on connect.
///
/// Idempotent so that several instances starting at once do not race each other
/// into a failure — which is the normal case for this backend, not an edge one.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS journal (
    run_id     TEXT   NOT NULL,
    seq        BIGINT NOT NULL,
    epoch      BIGINT NOT NULL,
    kind       TEXT   NOT NULL,
    effect_key TEXT,
    prev_hash  BYTEA  NOT NULL,
    hash       BYTEA  NOT NULL,
    raw        BYTEA  NOT NULL,
    -- Who wrote it. Null when no signer is configured: a hash chain still
    -- detects edits, it just cannot say who made them.
    key_id     TEXT,
    signature  BYTEA,
    PRIMARY KEY (run_id, seq)
);

-- Exactly-once, as a constraint rather than a code path. A second
-- `EffectStarted` for one effect key in one run cannot be written, whichever
-- instance is writing and whatever it believes about the journal.
CREATE UNIQUE INDEX IF NOT EXISTS journal_effect_started
    ON journal (run_id, effect_key)
    WHERE kind = 'EffectStarted' AND effect_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS run_lease (
    run_id     TEXT   PRIMARY KEY,
    owner      TEXT   NOT NULL,
    epoch      BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

-- An operator's stop request. Beside the chain rather than in it, and
-- deliberately not fenced: whoever wants a run stopped is not its owner, holds
-- no epoch, and is usually asking because the owner is busy. The primary key
-- makes the request idempotent, so a retry cannot overwrite the original asker.
-- The plane's Merkle log: one row per sealed run, positioned by a sequence.
--
-- A sequence rather than `MAX + 1`, and that is what makes a log possible on
-- this backend at all. Several instances seal concurrently here — that is the
-- topology this backend exists for — and `MAX + 1` computed by two transactions
-- at once hands both the same position. A sequence is monotonic under
-- concurrency and never reissues a number after a delete: exactly the two
-- properties the log needs.
CREATE SEQUENCE IF NOT EXISTS run_log_position;

CREATE TABLE IF NOT EXISTS run_seal (
    run_id     TEXT   PRIMARY KEY,
    chain_head BYTEA  NOT NULL,
    log_index  BIGINT NOT NULL UNIQUE,
    sealed_at  BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS run_cancel (
    run_id       TEXT   PRIMARY KEY,
    actor        TEXT   NOT NULL,
    reason       TEXT   NOT NULL,
    requested_at BIGINT NOT NULL
);
";

/// A journal on `PostgreSQL`.
#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: Pool,
    /// See the `SQLite` backend: only the store knows a record's chain hash,
    /// because it assigns `seq` and `prev_hash` in the same transaction that
    /// writes.
    signer: Option<Arc<dyn crate::core::Signer>>,
    /// Names this plane's Merkle log in every checkpoint.
    origin: String,
}

impl PostgresStore {
    /// Write records signed as this identity.
    ///
    /// Off unless asked. The default is unsigned rather than self-signed: a
    /// plane that minted its own key would produce records that look attested
    /// and prove nothing.
    #[must_use]
    pub fn signing_as(mut self, signer: Arc<dyn crate::core::Signer>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Name this plane's Merkle log.
    #[must_use]
    pub fn origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = origin.into();
        self
    }

    /// The log's leaves, in seal order.
    async fn log_leaves(&self) -> Result<Vec<Digest>, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT chain_head FROM run_seal ORDER BY log_index ASC",
                &[],
            )
            .await
            .map_err(|e| be(&e))?;
        rows.iter()
            .map(|r| {
                digest_from(&r.get::<_, Vec<u8>>(0)).map(|d| crate::core::merkle::leaf_hash(&d))
            })
            .collect()
    }
}

fn be(e: &tokio_postgres::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn pool_err(e: &impl std::fmt::Display) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// Seconds since the epoch, for lease bookkeeping only.
///
/// Never enters the journal and never influences a replayed decision — it is
/// store metadata, exactly as the `SQLite` backend's is.
#[allow(clippy::disallowed_methods)]
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl PostgresStore {
    pub(super) fn pool_ref(&self) -> &Pool {
        &self.pool
    }

    /// Connect and apply the schema.
    ///
    /// # Errors
    ///
    /// If the URL does not parse, the pool cannot be built, or the schema cannot
    /// be applied.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let pg: tokio_postgres::Config = url
            .parse()
            .map_err(|e: tokio_postgres::Error| StoreError::Backend(e.to_string()))?;
        let mut cfg = Config::new();
        cfg.host = pg.get_hosts().first().map(|h| match h {
            tokio_postgres::config::Host::Tcp(s) => s.clone(),
            #[cfg(unix)]
            tokio_postgres::config::Host::Unix(p) => p.to_string_lossy().into_owned(),
        });
        cfg.port = pg.get_ports().first().copied();
        cfg.user = pg.get_user().map(ToOwned::to_owned);
        cfg.password = pg
            .get_password()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        cfg.dbname = pg.get_dbname().map(ToOwned::to_owned);

        let pool = cfg
            .create_pool(Some(PoolRuntime::Tokio1), NoTls)
            .map_err(|e| pool_err(&e))?;

        let client = pool.get().await.map_err(|e| pool_err(&e))?;
        client.batch_execute(SCHEMA).await.map_err(|e| be(&e))?;
        client
            .batch_execute(super::postgres_cases::CASE_SCHEMA)
            .await
            .map_err(|e| be(&e))?;
        Ok(Self {
            pool,
            signer: None,
            origin: "agentplane".to_owned(),
        })
    }
}

#[async_trait]
impl JournalStore for PostgresStore {
    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError> {
        if batch.is_empty() {
            return Ok(Vec::new());
        }
        let run = batch[0].run;
        let mut client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let tx = client.transaction().await.map_err(|e| be(&e))?;

        // Fencing and the chain head are read under the row lock the lease is
        // taken with, so a concurrent writer either waits or is refused. The
        // `FOR UPDATE` is what makes the epoch check and the append one
        // indivisible act — without it the check is advisory.
        let lease = tx
            .query_opt(
                "SELECT epoch FROM run_lease WHERE run_id = $1 FOR UPDATE",
                &[&run.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        if let Some(row) = lease {
            let current: i64 = row.get(0);
            let current = current.cast_unsigned();
            if epoch < current {
                return Err(StoreError::Fenced {
                    run: run.to_string(),
                    held: epoch,
                    current,
                });
            }
        }

        let head = tx
            .query_opt(
                "SELECT seq, hash FROM journal WHERE run_id = $1 ORDER BY seq DESC LIMIT 1",
                &[&run.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        let (mut seq, mut prev) = match head {
            Some(row) => {
                let s: i64 = row.get(0);
                let h: Vec<u8> = row.get(1);
                (s.cast_unsigned(), digest_from(&h)?)
            }
            None => (0, Digest::ZERO),
        };

        let mut sealed = Vec::with_capacity(batch.len());
        for append in batch {
            seq += 1;
            let body = append.into_body(seq, epoch);
            let record = Record::seal_signed(body, prev, self.signer.as_deref())?;
            prev = record.hash;

            let effect = record.effect_key().map(EffectKey::to_hex);
            let result = tx
                .execute(
                    "INSERT INTO journal
                       (run_id, seq, epoch, kind, effect_key, prev_hash, hash, raw,
                        key_id, signature)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                    &[
                        &run.to_string(),
                        &seq.cast_signed(),
                        &epoch.cast_signed(),
                        &record.kind().kind_str(),
                        &effect,
                        &record.prev_hash.as_bytes().to_vec(),
                        &record.hash.as_bytes().to_vec(),
                        &record.raw().to_vec(),
                        &record.attestation.as_ref().map(|a| a.key_id.clone()),
                        &record.attestation.as_ref().map(|a| a.signature.clone()),
                    ],
                )
                .await;

            if let Err(e) = result {
                // The partial unique index refusing a second start is not a
                // backend failure — it is exactly-once holding, and the caller
                // must be able to tell the two apart.
                if e.code() == Some(&SqlState::UNIQUE_VIOLATION)
                    && let Some(k) = record.effect_key()
                {
                    return Err(StoreError::DuplicateEffect(k));
                }
                return Err(be(&e));
            }
            sealed.push(record);
        }

        tx.commit().await.map_err(|e| be(&e))?;
        Ok(sealed)
    }

    async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT seq, prev_hash, hash, raw, key_id, signature FROM journal
                  WHERE run_id = $1 AND seq >= $2 ORDER BY seq ASC",
                &[&run.to_string(), &from.cast_signed()],
            )
            .await
            .map_err(|e| be(&e))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let seq: i64 = row.get(0);
            let prev: Vec<u8> = row.get(1);
            let hash: Vec<u8> = row.get(2);
            let raw: Vec<u8> = row.get(3);
            let key_id: Option<String> = row.get(4);
            let signature: Option<Vec<u8>> = row.get(5);
            // `from_stored_attested` recomputes the hash from the bytes and
            // refuses a mismatch, so tampering is caught at read time, per
            // record, before chain verification even runs.
            let _ = seq;
            // Zipped, not defaulted: half a signature is a half-written row
            // rather than an unsigned record.
            let attestation = key_id
                .zip(signature)
                .map(|(key_id, signature)| crate::core::Attestation { key_id, signature });
            out.push(Record::from_stored_attested(
                raw,
                digest_from(&prev)?,
                digest_from(&hash)?,
                attestation,
            )?);
        }
        Ok(out)
    }

    async fn head(&self, run: RunId) -> Result<Head, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let row = client
            .query_opt(
                "SELECT seq, hash FROM journal WHERE run_id = $1 ORDER BY seq DESC LIMIT 1",
                &[&run.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        match row {
            None => Ok(Head::genesis()),
            Some(row) => {
                let seq: i64 = row.get(0);
                let hash: Vec<u8> = row.get(1);
                Ok(Head {
                    seq: seq.cast_unsigned(),
                    hash: digest_from(&hash)?,
                })
            }
        }
    }

    async fn acquire(&self, run: RunId, owner: &str, ttl: Duration) -> Result<Lease, StoreError> {
        let mut client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let tx = client.transaction().await.map_err(|e| be(&e))?;
        let now = now_secs();
        let expires = now + ttl.as_secs().max(1);
        let key = run.to_string();

        // `FOR UPDATE` so two instances racing for an expired lease serialise:
        // exactly one takes it and bumps the epoch, and the other sees the
        // result of that rather than the state before it.
        let existing = tx
            .query_opt(
                "SELECT owner, epoch, expires_at FROM run_lease WHERE run_id = $1 FOR UPDATE",
                &[&key],
            )
            .await
            .map_err(|e| be(&e))?;

        let epoch = match existing {
            None => 1,
            Some(row) => {
                let held_by: String = row.get(0);
                let epoch: i64 = row.get(1);
                let expires_at: i64 = row.get(2);
                let epoch = epoch.cast_unsigned();
                if held_by == owner {
                    // Renewal keeps the epoch: bumping it would fence the owner
                    // against its own in-flight writes.
                    epoch
                } else if expires_at.cast_unsigned() > now {
                    return Err(StoreError::LeaseHeld {
                        run: key,
                        owner: held_by,
                        epoch,
                        remaining_secs: expires_at.cast_unsigned().saturating_sub(now),
                    });
                } else {
                    epoch + 1
                }
            }
        };

        tx.execute(
            "INSERT INTO run_lease (run_id, owner, epoch, expires_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (run_id) DO UPDATE SET
               owner = EXCLUDED.owner,
               epoch = EXCLUDED.epoch,
               expires_at = EXCLUDED.expires_at",
            &[
                &key,
                &owner.to_owned(),
                &epoch.cast_signed(),
                &expires.cast_signed(),
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

    async fn seal(&self, run: RunId, _epoch: Epoch, _outcome: &str) -> Result<Digest, StoreError> {
        // The conclusion is already *in* the chain — the executor appends
        // `RunSealed` before calling this — so sealing reports the terminal hash
        // rather than writing a second one. Tamper detection therefore covers
        // how the run ended, which it would not if the outcome lived in a side
        // table.
        let head = self.head(run).await?.hash;

        // Enter the log. `DO NOTHING` keeps a repeated seal idempotent — a run
        // that seals twice must not take two positions, or the log's size stops
        // matching the number of runs it commits to.
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "INSERT INTO run_seal (run_id, chain_head, log_index, sealed_at)
                 VALUES ($1, $2, nextval('run_log_position'), $3)
                 ON CONFLICT (run_id) DO NOTHING",
                &[
                    &run.to_string(),
                    &head.as_bytes().to_vec(),
                    &now_secs().cast_signed(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;

        Ok(head)
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
            // one back would let "your checkpoint is from the future" read as
            // "everything is fine".
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
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let Some(row) = client
            .query_opt(
                "SELECT rank, chain_head FROM (
                     SELECT run_id, chain_head,
                            ROW_NUMBER() OVER (ORDER BY log_index) - 1 AS rank
                       FROM run_seal
                 ) ranked WHERE run_id = $1",
                &[&run.to_string()],
            )
            .await
            .map_err(|e| be(&e))?
        else {
            return Ok(None);
        };
        // Position in the *tree* is the dense rank, not the sequence value: a
        // sequence skips numbers after a rollback and a tree cannot have holes.
        let index: i64 = row.get(0);
        let seal = digest_from(&row.get::<_, Vec<u8>>(1))?;
        let index = usize::try_from(index).unwrap_or(0);
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
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        // No fence check, on purpose — see `JournalStore::request_cancel`.
        // `DO NOTHING` rather than an upsert: the first asker stays on the
        // record, so a retried request cannot rewrite who intervened.
        let n = client
            .execute(
                "INSERT INTO run_cancel (run_id, actor, reason, requested_at)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (run_id) DO NOTHING",
                &[
                    &run.to_string(),
                    &actor.to_owned(),
                    &reason.to_owned(),
                    &now_secs().cast_signed(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(n == 1)
    }

    async fn cancellation(&self, run: RunId) -> Result<Option<Cancellation>, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let row = client
            .query_opt(
                "SELECT actor, reason FROM run_cancel WHERE run_id = $1",
                &[&run.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(row.map(|r| Cancellation {
            actor: r.get(0),
            reason: r.get(1),
        }))
    }
}

fn digest_from(bytes: &[u8]) -> Result<Digest, StoreError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| StoreError::Corrupt {
        seq: 0,
        detail: format!("a hash column holds {} bytes, not 32", bytes.len()),
    })?;
    Ok(Digest::from_bytes(arr))
}
