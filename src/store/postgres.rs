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

use serde_json::Value;

use crate::journal::{
    Append, AtomicJournal, AtomicTx, AtomicWork, Cancellation, Head, JournalStore, Lease, Record,
    SqlValue,
};

/// The schema, applied on connect.
///
/// Idempotent so that several instances starting at once do not race each other
/// into a failure — which is the normal case for this backend, not an edge one.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS journal (
    -- The tenant leads every key in this schema. A run id is unique, so a
    -- filter would do; a key component is what makes a query that forgets the
    -- predicate return nothing rather than another tenant's row, and what keeps
    -- every index physically clustered per tenant so a scan cannot walk into
    -- somebody else's traffic.
    tenant     TEXT   NOT NULL,
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
    -- Which matter this record belongs to, when it belongs to one.
    --
    -- A column and not only a field inside `raw`: *show me everything about
    -- this matter* is answerable by a range scan here, and by a join over the
    -- case's runs otherwise — a join that also **misses** every record written
    -- by a run the case does not own, which is exactly what a sweep is.
    case_id    TEXT,
    PRIMARY KEY (tenant, run_id, seq)
);

-- One matter's history, in order, without touching another tenant's.
CREATE INDEX IF NOT EXISTS journal_by_case
    ON journal (tenant, case_id, run_id, seq)
    WHERE case_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS run_activity (
    tenant     TEXT   NOT NULL,
    run_id     TEXT   NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, run_id)
);
CREATE INDEX IF NOT EXISTS run_activity_recent
    ON run_activity (tenant, updated_at DESC, run_id DESC);

-- Exactly-once, as a constraint rather than a code path. A second
-- `EffectStarted` for one effect key in one run cannot be written, whichever
-- instance is writing and whatever it believes about the journal.
CREATE UNIQUE INDEX IF NOT EXISTS journal_effect_started
    ON journal (tenant, run_id, effect_key)
    WHERE kind = 'EffectStarted' AND effect_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS run_lease (
    tenant     TEXT   NOT NULL,
    run_id     TEXT   NOT NULL,
    owner      TEXT   NOT NULL,
    epoch      BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, run_id)
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

-- One log per tenant, so a checkpoint commits to that tenant's runs and no
-- others. `log_index` is unique *within* a tenant: a shared sequence hands out
-- distinct numbers globally, and each tenant simply sees gaps, which the dense
-- rank in `inclusion_proof` removes before anything is proved.
CREATE TABLE IF NOT EXISTS run_seal (
    tenant     TEXT   NOT NULL,
    run_id     TEXT   NOT NULL,
    chain_head BYTEA  NOT NULL,
    log_index  BIGINT NOT NULL,
    sealed_at  BIGINT NOT NULL,
    -- How the run ended. **Derived**, not authoritative: the executor appends
    -- `RunSealed` before sealing, so tamper detection covers the outcome and
    -- this column can be rebuilt from the chain. It exists so *what is
    -- quarantined right now* is a query rather than a log search — a finding
    -- nobody can find is one that never reached a human.
    outcome    TEXT   NOT NULL,
    PRIMARY KEY (tenant, run_id),
    UNIQUE (tenant, log_index)
);

-- One outcome's backlog without touching another tenant's. Scanned **newest
-- first** — see `JournalStore::runs_by_outcome` for why the direction is part
-- of the contract rather than a detail of this index.
CREATE INDEX IF NOT EXISTS run_seal_by_outcome
    ON run_seal (tenant, outcome, log_index);

CREATE TABLE IF NOT EXISTS run_cancel (
    tenant       TEXT   NOT NULL,
    run_id       TEXT   NOT NULL,
    actor        TEXT   NOT NULL,
    reason       TEXT   NOT NULL,
    requested_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, run_id)
);

-- A2A push uses the journal itself as the outbox. `next_seq` is the first task
-- record this receiver has not acknowledged; advancing only after a 2xx makes a
-- crash produce a duplicate rather than a lost notification.
CREATE TABLE IF NOT EXISTS push_delivery (
    tenant          TEXT   NOT NULL,
    task_id         TEXT   NOT NULL,
    config_id       TEXT   NOT NULL,
    url             TEXT   NOT NULL,
    token           TEXT,
    auth_scheme     TEXT,
    auth_credentials TEXT,
    next_seq        BIGINT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at BIGINT NOT NULL DEFAULT 0,
    last_error      TEXT,
    PRIMARY KEY (tenant, task_id, config_id)
);
CREATE INDEX IF NOT EXISTS push_delivery_due
    ON push_delivery (tenant, next_attempt_at, task_id, config_id);
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
    /// Whose rows this handle can name. Every statement carries it.
    tenant: crate::core::TenantId,
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

    /// Serve one tenant.
    ///
    /// The handle is the boundary: a store built for `acme` cannot name a
    /// `globex` run even holding a valid id, because the tenant is part of every
    /// key rather than a predicate someone remembers to add. The origin moves
    /// with it, so two tenants' checkpoints are not mistaken for one plane's.
    #[must_use]
    pub fn for_tenant(mut self, tenant: crate::core::TenantId) -> Self {
        self.origin = format!("{}/{}", self.origin, tenant);
        self.tenant = tenant;
        self
    }

    /// This tenant's log leaves, in seal order.
    async fn log_leaves(&self) -> Result<Vec<Digest>, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT chain_head FROM run_seal WHERE tenant = $1 ORDER BY log_index ASC",
                &[&self.tenant_name()],
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

    pub(super) fn tenant_name(&self) -> String {
        self.tenant.to_string()
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
        client
            .batch_execute(super::postgres_authority::AUTHORITY_SCHEMA)
            .await
            .map_err(|e| be(&e))?;
        client
            .batch_execute(super::postgres_memory::MEMORY_SCHEMA)
            .await
            .map_err(|e| be(&e))?;
        Ok(Self {
            pool,
            signer: None,
            origin: "agentplane".to_owned(),
            tenant: crate::core::TenantId::default(),
        })
    }
}

impl PostgresStore {
    /// Refuse a displaced writer, under the row lock the lease is taken with.
    ///
    /// Split out so the ordinary append and the atomic one cannot drift: a
    /// second copy of a fence is a fence with a second chance to be wrong.
    async fn fence(
        &self,
        tx: &deadpool_postgres::tokio_postgres::Transaction<'_>,
        run: RunId,
        epoch: Epoch,
    ) -> Result<(), StoreError> {
        // Fencing and the chain head are read under the row lock the lease is
        // taken with, so a concurrent writer either waits or is refused. The
        // `FOR UPDATE` is what makes the epoch check and the append one
        // indivisible act — without it the check is advisory.
        let lease = tx
            .query_opt(
                "SELECT epoch FROM run_lease WHERE tenant = $1 AND run_id = $2 FOR UPDATE",
                &[&self.tenant_name(), &run.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        if let Some(row) = lease {
            let current: i64 = row.get(0);
            let current = current.cast_unsigned();
            if epoch != current {
                return Err(StoreError::Fenced {
                    run: run.to_string(),
                    held: epoch,
                    current,
                });
            }
        }

        Ok(())
    }

    /// Seal and insert a batch inside a transaction the caller owns.
    async fn append_within(
        &self,
        tx: &deadpool_postgres::tokio_postgres::Transaction<'_>,
        run: RunId,
        epoch: Epoch,
        batch: Vec<Append>,
    ) -> Result<Vec<Record>, StoreError> {
        let head = tx
            .query_opt(
                "SELECT seq, hash FROM journal
                  WHERE tenant = $1 AND run_id = $2 ORDER BY seq DESC LIMIT 1",
                &[&self.tenant_name(), &run.to_string()],
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
                       (tenant, run_id, seq, epoch, kind, effect_key, prev_hash, hash,
                        raw, key_id, signature, case_id)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                    &[
                        &self.tenant_name(),
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
                        &record.body.case.map(|c| c.to_string()),
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

        tx.execute(
            "INSERT INTO run_activity (tenant, run_id, updated_at) VALUES ($1, $2, $3)
             ON CONFLICT (tenant, run_id) DO UPDATE SET updated_at = EXCLUDED.updated_at",
            &[
                &self.tenant_name(),
                &run.to_string(),
                &now_secs().cast_signed(),
            ],
        )
        .await
        .map_err(|error| be(&error))?;

        Ok(sealed)
    }
}

#[async_trait]
impl JournalStore for PostgresStore {
    fn tenant(&self) -> &str {
        self.tenant.as_str()
    }

    /// This backend can. That is the whole reason the capability is a question
    /// rather than an assumption.
    fn atomic(&self) -> Option<&dyn AtomicJournal> {
        Some(self)
    }

    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError> {
        if batch.is_empty() {
            return Ok(Vec::new());
        }
        let run = batch[0].run;
        let mut client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let tx = client.transaction().await.map_err(|e| be(&e))?;
        self.fence(&tx, run, epoch).await?;
        let sealed = self.append_within(&tx, run, epoch, batch).await?;
        tx.commit().await.map_err(|e| be(&e))?;
        Ok(sealed)
    }

    async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT seq, prev_hash, hash, raw, key_id, signature FROM journal
                  WHERE tenant = $1 AND run_id = $2 AND seq >= $3 ORDER BY seq ASC",
                &[&self.tenant_name(), &run.to_string(), &from.cast_signed()],
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

    async fn runs_by_outcome(&self, outcome: &str, limit: usize) -> Result<Vec<RunId>, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                // **Newest first.** See `JournalStore::runs_by_outcome`:
                // ascending order plus a page limit means a plane whose backlog
                // already exceeds one page returns the same runs forever, and
                // the quarantine that just happened never appears.
                "SELECT run_id FROM run_seal
                  WHERE tenant = $1 AND outcome = $2
                  ORDER BY log_index DESC
                  LIMIT $3",
                &[
                    &self.tenant_name(),
                    &outcome,
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                ],
            )
            .await
            .map_err(|e| be(&e))?;

        Ok(rows
            .iter()
            .filter_map(|r| RunId::parse(r.get::<_, &str>(0)).ok())
            .collect())
    }

    async fn recent_runs(&self) -> Result<Vec<(RunId, u64)>, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT run_id, updated_at FROM run_activity
                 WHERE tenant = $1 ORDER BY updated_at DESC, run_id DESC",
                &[&self.tenant_name()],
            )
            .await
            .map_err(|error| be(&error))?;
        rows.into_iter()
            .map(|row| {
                let id: String = row.get(0);
                let updated: i64 = row.get(1);
                Ok((
                    RunId::parse(&id).map_err(|error| StoreError::Backend(error.to_string()))?,
                    updated.cast_unsigned(),
                ))
            })
            .collect()
    }

    async fn case_history(
        &self,
        case: crate::core::CaseId,
        limit: usize,
    ) -> Result<Vec<Record>, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT raw, prev_hash, hash, key_id, signature FROM journal
                  WHERE tenant = $1 AND case_id = $2
                  ORDER BY run_id, seq ASC
                  LIMIT $3",
                &[
                    &self.tenant_name(),
                    &case.to_string(),
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                ],
            )
            .await
            .map_err(|e| be(&e))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let raw: Vec<u8> = row.get(0);
            let prev: Vec<u8> = row.get(1);
            let hash: Vec<u8> = row.get(2);
            let key_id: Option<String> = row.get(3);
            let signature: Option<Vec<u8>> = row.get(4);
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
                "SELECT seq, hash FROM journal
                  WHERE tenant = $1 AND run_id = $2 ORDER BY seq DESC LIMIT 1",
                &[&self.tenant_name(), &run.to_string()],
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
                "SELECT owner, epoch, expires_at FROM run_lease
                  WHERE tenant = $1 AND run_id = $2 FOR UPDATE",
                &[&self.tenant_name(), &key],
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
                if expires_at.cast_unsigned() <= now {
                    // Expired or released: take over and fence whoever held it,
                    // **including this caller**. Checked before ownership on
                    // purpose — a lapsed lease is not yours to renew, because
                    // you cannot know whether somebody took over in the gap.
                    epoch + 1
                } else if held_by == owner {
                    // Ours and still live: renewal keeps the epoch, or the owner
                    // fences its own in-flight writes.
                    epoch
                } else {
                    return Err(StoreError::LeaseHeld {
                        run: key,
                        owner: held_by,
                        epoch,
                        remaining_secs: expires_at.cast_unsigned().saturating_sub(now),
                    });
                }
            }
        };

        tx.execute(
            "INSERT INTO run_lease (tenant, run_id, owner, epoch, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant, run_id) DO UPDATE SET
               owner = EXCLUDED.owner,
               epoch = EXCLUDED.epoch,
               expires_at = EXCLUDED.expires_at",
            &[
                &self.tenant_name(),
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

    async fn release_lease(&self, run: RunId, epoch: Epoch) -> Result<(), StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        // Two safety properties in one statement.
        //
        // The epoch predicate: a fenced caller shutting down must not free the
        // lease of the instance that took over from it. In the `WHERE` clause so
        // it is atomic rather than a read followed by a write somebody can race.
        //
        // And an **update, not a delete**. The epoch lives in this row: removing
        // it leaves `append` nothing to fence against and makes the next
        // `acquire` restart at 1, so a writer already fenced at 2 would outrank
        // the new owner. Expiring the row frees the lease while keeping the
        // history of what has happened to it.
        client
            .execute(
                "UPDATE run_lease SET owner = '', expires_at = 0 \
                 WHERE tenant = $1 AND run_id = $2 AND epoch = $3",
                &[&self.tenant_name(), &run.to_string(), &epoch.cast_signed()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn seal(&self, run: RunId, _epoch: Epoch, outcome: &str) -> Result<Digest, StoreError> {
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
                "INSERT INTO run_seal (tenant, run_id, chain_head, log_index, sealed_at, outcome)
                 VALUES ($1, $2, $3, nextval('run_log_position'), $4, $5)
                 ON CONFLICT (tenant, run_id) DO NOTHING",
                &[
                    &self.tenant_name(),
                    &run.to_string(),
                    &head.as_bytes().to_vec(),
                    &now_secs().cast_signed(),
                    &outcome,
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
                       FROM run_seal WHERE tenant = $1
                 ) ranked WHERE run_id = $2",
                &[&self.tenant_name(), &run.to_string()],
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
                "INSERT INTO run_cancel (tenant, run_id, actor, reason, requested_at)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (tenant, run_id) DO NOTHING",
                &[
                    &self.tenant_name(),
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
                "SELECT actor, reason FROM run_cancel WHERE tenant = $1 AND run_id = $2",
                &[&self.tenant_name(), &run.to_string()],
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

// ── Committing with the journal, rather than beside it ───────────────────────

/// The journal's own transaction, as much of it as a co-located resource may
/// use.
///
/// Holds a borrow rather than a pool handle on purpose: the resource cannot
/// outlive the transaction, cannot commit it, and cannot start another. What it
/// can do is exactly what makes this worth having — write to its own table in
/// the transaction that is about to record that it did.
struct PgAtomicTx<'a>(&'a deadpool_postgres::tokio_postgres::Transaction<'a>);

/// Bind a portable value to this driver's parameter type.
///
/// Owned first, then borrowed: `tokio_postgres` wants `&(dyn ToSql + Sync)`, and
/// the temporaries have to outlive the call.
fn bind(params: &[SqlValue]) -> Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> {
    params
        .iter()
        .map(|v| -> Box<dyn tokio_postgres::types::ToSql + Sync + Send> {
            match v {
                SqlValue::Null => Box::new(Option::<i64>::None),
                SqlValue::Bool(b) => Box::new(*b),
                SqlValue::Int(i) => Box::new(*i),
                SqlValue::Float(f) => Box::new(*f),
                SqlValue::Text(s) => Box::new(s.clone()),
                SqlValue::Bytes(b) => Box::new(b.clone()),
                SqlValue::Json(j) => Box::new(j.clone()),
            }
        })
        .collect()
}

fn as_refs(
    owned: &[Box<dyn tokio_postgres::types::ToSql + Sync + Send>],
) -> Vec<&(dyn tokio_postgres::types::ToSql + Sync)> {
    owned.iter().map(|b| &**b as _).collect()
}

#[async_trait]
impl AtomicTx for PgAtomicTx<'_> {
    async fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, StoreError> {
        let owned = bind(params);
        self.0
            .execute(sql, &as_refs(&owned))
            .await
            .map_err(|e| be(&e))
    }

    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Value>, StoreError> {
        let owned = bind(params);
        let rows = self
            .0
            .query(sql, &as_refs(&owned))
            .await
            .map_err(|e| be(&e))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let mut obj = serde_json::Map::new();
            for (i, col) in row.columns().iter().enumerate() {
                obj.insert(col.name().to_owned(), column_json(row, i, col.type_())?);
            }
            out.push(Value::Object(obj));
        }
        Ok(out)
    }
}

/// One column, as JSON.
///
/// Converted per Postgres type rather than by asking for a `Value` and taking
/// what comes: only `json`/`jsonb` answer that, so every other column would come
/// back **null** — a wrong answer wearing the shape of a missing one, which is
/// the worst of both. An unknown type is an error for the same reason: a
/// resource reading a column this does not understand should be told, not handed
/// a null it will treat as a zero.
fn column_json(
    row: &deadpool_postgres::tokio_postgres::Row,
    i: usize,
    ty: &tokio_postgres::types::Type,
) -> Result<Value, StoreError> {
    use tokio_postgres::types::Type;

    macro_rules! get {
        ($t:ty) => {
            row.try_get::<_, Option<$t>>(i)
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .map_or(Value::Null, Value::from)
        };
    }

    Ok(match *ty {
        Type::BOOL => get!(bool),
        Type::INT2 => get!(i16),
        Type::INT4 => get!(i32),
        Type::INT8 => get!(i64),
        Type::FLOAT4 => get!(f32),
        Type::FLOAT8 => get!(f64),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => get!(String),
        Type::JSON | Type::JSONB => row
            .try_get::<_, Option<Value>>(i)
            .map_err(|e| StoreError::Backend(e.to_string()))?
            .unwrap_or(Value::Null),
        Type::BYTEA => row
            .try_get::<_, Option<Vec<u8>>>(i)
            .map_err(|e| StoreError::Backend(e.to_string()))?
            .map_or(Value::Null, |b| Value::String(hex(&b))),
        ref other => {
            return Err(StoreError::Backend(format!(
                "column '{}' has type {other}, which this seam does not convert — \
                 select it as text or jsonb rather than being handed a null that \
                 reads as a zero",
                row.columns()[i].name()
            )));
        }
    })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[async_trait]
impl AtomicJournal for PostgresStore {
    async fn append_atomic(
        &self,
        run: RunId,
        epoch: Epoch,
        work: &dyn AtomicWork,
    ) -> Result<Vec<Record>, StoreError> {
        let mut client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let tx = client.transaction().await.map_err(|e| be(&e))?;

        // Before the work, not after. A displaced writer's statements should
        // never run at all, and the transaction rolling them back afterwards is
        // a weaker property that happens to look the same.
        self.fence(&tx, run, epoch).await?;

        let batch = work
            .run(&PgAtomicTx(&tx))
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        let sealed = self.append_within(&tx, run, epoch, batch).await?;
        tx.commit().await.map_err(|e| be(&e))?;
        Ok(sealed)
    }
}
