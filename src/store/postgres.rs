//! `PostgreSQL`-backed journal.
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
//!
//! # TLS: refused rather than half-wired
//!
//! This backend connects without a TLS connector, and [`connect`] refuses a URL
//! that *demands* one (`sslmode=require` or stricter) instead of silently
//! downgrading it to plaintext. That refusal is deliberate and so is the
//! absence of the connector: libpq's `sslmode` is a gradation, not a switch —
//! `require` encrypts **without verifying the certificate**, `verify-ca` checks
//! the chain but not the hostname, and only `verify-full` does what "TLS" is
//! usually taken to mean. A connector that verified under `require` would break
//! every self-signed deployment that asked for exactly what it configured; one
//! that skipped verification to match libpq would be a security feature that
//! does not verify certificates. Either mistake is silent, which is the worst
//! property a transport-security seam can have.
//!
//! The deployment shapes this backend serves need no connector, and they are
//! the ordinary ones:
//!
//! * **A co-located database** — a Unix socket or loopback TCP, where the bytes
//!   never cross a network. `sslmode=disable` says what is true.
//! * **A TLS-terminating proxy** — pgbouncer, a cloud SQL proxy, a service-mesh
//!   sidecar — that this store reaches in plaintext locally while the proxy
//!   speaks verified TLS outward. The proxy is administered by whoever
//!   administers the certificates, which is where that policy lives anyway.
//!
//! A deployment that must speak TLS end-to-end from this process should
//! terminate it in a sidecar until a connector with the full `sslmode`
//! gradation is wired; the refusal in [`connect`] is what keeps that gap
//! visible instead of silently unencrypted.
//!
//! [`connect`]: PostgresStore::connect

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
    -- Every counter and instant in this schema carries a CHECK for the reason
    -- `amount_of` gives: the types are unsigned, PostgreSQL has no unsigned
    -- integer, and a row edited around the application — negative by typo or
    -- by malice — must fail the edit rather than read back as a value that
    -- reverses an accumulation. Chain positions and epochs start at one, so
    -- their floor is 1, not 0.
    seq        BIGINT NOT NULL CHECK (seq >= 1),
    epoch      BIGINT NOT NULL CHECK (epoch >= 1),
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
    updated_at BIGINT NOT NULL CHECK (updated_at >= 0),
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
    epoch      BIGINT NOT NULL CHECK (epoch >= 1),
    expires_at BIGINT NOT NULL CHECK (expires_at >= 0),
    PRIMARY KEY (tenant, run_id)
);

-- The recovery sweep's read: leases that expired without being released. A
-- partial index over held rows only, because released rows blank the owner and
-- dominate the table — every run ever admitted leaves one, since the epoch
-- lives in the row and deleting it would un-fence the run. Without the WHERE
-- clause this index would be mostly rows the query filters out.
CREATE INDEX IF NOT EXISTS run_lease_abandoned
    ON run_lease (tenant, expires_at)
    WHERE owner <> '';

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
    log_index  BIGINT NOT NULL CHECK (log_index >= 1),
    sealed_at  BIGINT NOT NULL CHECK (sealed_at >= 0),
    -- How the run ended *when it sealed*. Descriptive: the outcome index that
    -- answers queries lives in run_outcome, fed by the chain's `RunSealed`
    -- records, where the last conclusion wins.
    outcome    TEXT   NOT NULL,
    PRIMARY KEY (tenant, run_id),
    UNIQUE (tenant, log_index)
);

-- Conclusion ordering under concurrency, for the same reason as
-- run_log_position: several instances conclude runs at once here.
CREATE SEQUENCE IF NOT EXISTS run_conclusion_ordinal;

-- Concluded runs by how they ended. **Derived**, not authoritative: fed by the
-- `RunSealed` record inside `append`, in the same transaction, so the outcome's
-- home stays the chain and this table can be rebuilt from it. The last
-- conclusion wins — a run that failed, was resumed and then succeeded moves
-- from `failed` to `succeeded`; an index fed by the seal would report the
-- first conclusion forever, and a wrong answer reads exactly like a right one.
CREATE TABLE IF NOT EXISTS run_outcome (
    tenant  TEXT   NOT NULL,
    run_id  TEXT   NOT NULL,
    outcome TEXT   NOT NULL,
    ordinal BIGINT NOT NULL CHECK (ordinal >= 1),
    PRIMARY KEY (tenant, run_id)
);

-- One outcome's backlog without touching another tenant's. Scanned **newest
-- first** — see `JournalStore::runs_by_outcome` for why the direction is part
-- of the contract rather than a detail of this index.
CREATE INDEX IF NOT EXISTS run_outcome_by_outcome
    ON run_outcome (tenant, outcome, ordinal);

-- The admission keys this tenant has issued. **Derived**, not authoritative:
-- fed by the `RunAdmitted` record inside `append`, in the same transaction, so
-- the key's home stays the chain and this table can be rebuilt from it.
--
-- The primary key is the mechanism, not a hint. Two instances admitting one
-- inbound message concurrently both find nothing and both insert; exactly one
-- commits, and the loser is told which run won.
--
-- Tenant-scoped for the reason `case_correlation` is: an admission key is a
-- business value, and two tenants using the same one is ordinary.
CREATE TABLE IF NOT EXISTS run_admission (
    tenant      TEXT   NOT NULL,
    key         TEXT   NOT NULL,
    run_id      TEXT   NOT NULL,
    admitted_at BIGINT NOT NULL CHECK (admitted_at >= 0),
    PRIMARY KEY (tenant, key)
);

CREATE TABLE IF NOT EXISTS run_cancel (
    tenant       TEXT   NOT NULL,
    run_id       TEXT   NOT NULL,
    actor        TEXT   NOT NULL,
    reason       TEXT   NOT NULL,
    requested_at BIGINT NOT NULL CHECK (requested_at >= 0),
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
    next_seq        BIGINT NOT NULL CHECK (next_seq >= 0),
    attempts        INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at BIGINT NOT NULL DEFAULT 0 CHECK (next_attempt_at >= 0),
    last_error      TEXT,
    -- Stopped, with the cursor kept: a receiver that answered permanently or
    -- outlasted the retry ceiling. Excluded from the due index so a parked row
    -- costs nothing per sweep, and still names how far its receiver got.
    parked          BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (tenant, task_id, config_id)
);
CREATE INDEX IF NOT EXISTS push_delivery_due
    ON push_delivery (tenant, next_attempt_at, task_id, config_id)
    WHERE NOT parked;
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
    /// key rather than a predicate someone remembers to add. The checkpoint
    /// origin carries the tenant too, so two tenants' checkpoints are not
    /// mistaken for one plane's — composed at read time from the base name and
    /// the tenant, never baked into a field. Baking it in made the builder
    /// order-sensitive: `for_tenant` called twice double-qualified the origin,
    /// and `origin()` after `for_tenant` silently dropped the tenant — either
    /// way a checkpoint under a name no verifier ever saw again.
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

    /// This tenant's log leaves, in seal order — already leaf-hashed, which
    /// the type now says rather than the comment.
    async fn log_leaves(&self) -> Result<Vec<crate::core::merkle::LeafHash>, StoreError> {
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
            .collect::<Result<Vec<_>, _>>()
    }
}

fn be(e: &tokio_postgres::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// Classify a failed `COMMIT`, for every journal write that commits one.
///
/// The one in-doubt window a native transaction keeps: the server *answering*
/// is what distinguishes "refused, rolled back" from "may have landed". A
/// database error is an answer — a serialization or constraint failure is a
/// clean rollback and stays an ordinary backend error. Anything else — the
/// connection dropping between sending `COMMIT` and receiving its
/// acknowledgement — means the commit may be standing, and the caller must not
/// treat it as taken back.
///
/// One function rather than a closure per call site, because a classification
/// that lives only on the atomic path lets a plain `append` or `seal` whose
/// commit acknowledgement was lost read as a retryable backend error — and the
/// retry double-appends every record that is not effect-keyed: exactly-once
/// guards only `EffectStarted` rows, so a retried `StepPlanned` or `RunSealed`
/// lands twice with nothing to refuse it.
fn commit_refused_or_in_doubt(e: &tokio_postgres::Error) -> StoreError {
    if e.as_db_error().is_some() {
        be(e)
    } else {
        StoreError::CommitUnknown {
            detail: e.to_string(),
        }
    }
}

fn pool_err(e: &impl std::fmt::Display) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// `BIGINT` out of the database, `u64` in the type.
///
/// Every counted quantity this crate stores — tokens, minor units, item counts,
/// draw ordinals — is unsigned, because a negative one reverses an accumulation
/// and un-spends whichever ceiling is comparing against it. `PostgreSQL` has no
/// unsigned integer, so the column is a `BIGINT` with a `CHECK` and this is the
/// boundary that reads it back.
///
/// Clamping rather than wrapping: a row edited around the `CHECK` should read as
/// *nothing left* rather than as billions, since only one of those two keeps a
/// ceiling closed. Here once rather than at each of the six call sites it had,
/// which were three spellings of the same conversion and would have stayed in
/// step only by luck.
pub(super) const fn amount_of(v: i64) -> u64 {
    if v < 0 { 0 } else { v.cast_unsigned() }
}

/// `u64` in the type, `BIGINT` into the database.
///
/// Saturating for the reason [`Spend::plus`](crate::core::Spend::plus) is: a
/// figure past `i64::MAX` minor units is not one any deployment holds, and
/// clamping at the ceiling keeps a ceiling closed where a wrap would open one.
#[expect(
    clippy::cast_possible_wrap,
    reason = "guarded above: values past i64::MAX clamp rather than wrapping"
)]
pub(super) const fn sql_amount(v: u64) -> i64 {
    if v > i64::MAX as u64 {
        i64::MAX
    } else {
        v as i64
    }
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

/// A lease expiry instant from a TTL, refusing what whole seconds cannot hold.
///
/// Lease timing here has whole-second granularity, so a TTL below one second is
/// **refused rather than clamped**. A clamp would turn "expire immediately"
/// into "hold for a second" without telling anyone — a contract
/// the runtime relies on (its epoch arithmetic assumes a TTL means what it
/// says), enforced only upstream. Nothing legitimate reaches this refusal: the
/// runtime builder already refuses any TTL below its own two-second minimum at
/// `build()` time. This is the *store's* boundary enforcement, for every other
/// embedder of the trait — they get the same refusal instead of a silently
/// longer lease. A TTL of 1.5s still truncates to one second; the granularity
/// is the contract, and only the value that truncates to *zero* is a lie worth
/// refusing.
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

impl PostgresStore {
    pub(super) fn pool_ref(&self) -> &Pool {
        &self.pool
    }

    /// A lifecycle lock for cryptographic memory erasure, in *this* database.
    ///
    /// The coordinator that makes [`EncryptedMemoryStore`] honest on an
    /// active-active plane. Deliberately taken from the store rather than
    /// constructed from a connection string: a lock in a different database
    /// would be a second system that can be up while this one is down, and a
    /// coordinator that is available when the data is not protects nothing.
    ///
    /// ```ignore
    /// let memory = EncryptedMemoryStore::new(inner, keys, tenant)
    ///     .coordinated_by(Arc::new(store.erasure_coordinator()));
    /// ```
    ///
    /// [`EncryptedMemoryStore`]: crate::keyring::EncryptedMemoryStore
    /// Whether somebody is holding a scope's erasure lock, without taking it.
    ///
    /// `pg_try_advisory_lock`, released immediately if it was free — so this
    /// answers the question and leaves the answer true. For tests and operator
    /// diagnostics; the erasure path itself blocks rather than probing, because
    /// a caller that failed to get the lock would have to choose between
    /// retrying and skipping, and skipping an erasure is the wrong answer to
    /// contention.
    ///
    /// # Errors
    ///
    /// If the database cannot be reached.
    #[cfg(feature = "keyring")]
    pub async fn erasure_probe(&self, scope: &str) -> Result<bool, crate::core::StoreError> {
        let key = crate::keyring::coordinator::PostgresCoordinator::scope_key(scope);
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::core::StoreError::Backend(e.to_string()))?;
        let row = client
            .query_one("SELECT pg_try_advisory_lock($1)", &[&key])
            .await
            .map_err(|e| crate::core::StoreError::Backend(e.to_string()))?;
        let got: bool = row.get(0);
        if got {
            client
                .execute("SELECT pg_advisory_unlock($1)", &[&key])
                .await
                .map_err(|e| crate::core::StoreError::Backend(e.to_string()))?;
        }
        Ok(!got)
    }

    #[cfg(feature = "keyring")]
    #[must_use]
    pub fn erasure_coordinator(&self) -> crate::keyring::coordinator::PostgresCoordinator {
        crate::keyring::coordinator::PostgresCoordinator::new(self.pool.clone())
    }

    pub(super) fn tenant_name(&self) -> String {
        self.tenant.to_string()
    }

    /// The tenant this handle is scoped to, for the store traits' accessors.
    ///
    /// Borrowed rather than owned: `tenant_name` exists because a query
    /// parameter needs a `String`, and a trait answering *who do you serve*
    /// should not allocate to say so.
    pub(super) fn tenant_str(&self) -> &str {
        self.tenant.as_str()
    }

    /// Connect and apply the schema.
    ///
    /// # Errors
    ///
    /// If the URL does not parse, the pool cannot be built, or the schema cannot
    /// be applied.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        Self::connect_sized(url, None).await
    }

    /// [`connect`](Self::connect), with an explicit connection ceiling.
    ///
    /// The default ceiling is the pool's own (CPU-derived), which is the right
    /// answer until it is not: a deployment sharing the database with other
    /// services sizes this deliberately, and a test proving behaviour *under
    /// pool exhaustion* needs a pool small enough to exhaust — the task-claim
    /// deadlock this crate shipped reproduced only where the pool was smaller
    /// than the racers, so every big development machine passed over it.
    ///
    /// # Errors
    ///
    /// As [`connect`](Self::connect).
    pub async fn connect_sized(
        url: &str,
        max_connections: Option<usize>,
    ) -> Result<Self, StoreError> {
        let pg: tokio_postgres::Config = url
            .parse()
            .map_err(|e: tokio_postgres::Error| StoreError::Backend(e.to_string()))?;

        // This pool is built with `NoTls`, so a URL *demanding* TLS would be
        // silently downgraded to plaintext — a journal of authorization
        // decisions and labelled payloads crossing the network in the clear,
        // under a connection string whose author explicitly asked otherwise.
        // Until a TLS connector is wired, the honest answer is a refusal that
        // names the gap, not a connection that ignores the word `require`.
        // `prefer` and `disable` are served as written: neither promises
        // encryption.
        match pg.get_ssl_mode() {
            tokio_postgres::config::SslMode::Disable | tokio_postgres::config::SslMode::Prefer => {}
            demanded => {
                return Err(StoreError::Backend(format!(
                    "the connection URL demands TLS (sslmode {demanded:?}) and this \
                     build connects without it — connecting anyway would silently \
                     send the journal in plaintext. Use sslmode=disable (or prefer) \
                     against a trusted network, or terminate TLS in a proxy this \
                     store connects to locally"
                )));
            }
        }

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

        if let Some(max) = max_connections {
            cfg.pool = Some(deadpool_postgres::PoolConfig::new(max));
        }
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
        // A batch is one run's atomic unit. Everything below — the fence the
        // caller took, the seal check, the head read, the chain each record
        // links into — is scoped to `run`, so a record naming another run
        // would be sealed into this run's chain under this run's fence.
        // Refused loudly, exactly as the embedded store refuses it: the two
        // backends must not disagree about what a batch is.
        if let Some(a) = batch.iter().find(|a| a.run != run) {
            return Err(StoreError::Backend(format!(
                "batch spans runs {run} and {} — a batch is one run's atomic unit",
                a.run
            )));
        }

        // Sealed is frozen. The Merkle leaf is the chain head at seal time, so
        // an append past it — even by the epoch's rightful holder — advances
        // the true head past what every checkpoint attests. Checked inside the
        // caller's transaction like the fence, and it covers `append_atomic`
        // too because both routes pass through here. The sealing appends
        // themselves precede the seal row, so they never meet this check.
        let sealed_row = tx
            .query_opt(
                "SELECT outcome FROM run_seal WHERE tenant = $1 AND run_id = $2",
                &[&self.tenant_name(), &run.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        if let Some(row) = sealed_row {
            return Err(StoreError::RunSealed {
                run: run.to_string(),
                outcome: row.get(0),
            });
        }

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
        let mut conclusion: Option<String> = None;
        let mut claimed: Option<String> = None;
        for append in batch {
            seq += 1;
            let body = append.into_body(seq, epoch);
            match &body.kind {
                crate::journal::RecordKind::RunConcluded { outcome, .. } => {
                    conclusion = Some(outcome.clone());
                }
                crate::journal::RecordKind::RunAdmitted {
                    idempotency_key: Some(key),
                    ..
                } => claimed = Some(key.clone()),
                _ => {}
            }
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
                return Err(refused_insert(&e, &record, run, seq));
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

        self.derive_indexes(tx, run, claimed, conclusion).await?;

        Ok(sealed)
    }

    /// The two indexes that derive from a record in this batch.
    ///
    /// Written inside the caller's transaction, which is the point: an index
    /// committing separately from the record it describes can outlive it,
    /// precede it, or — for the admission key — let a second run through.
    async fn derive_indexes(
        &self,
        tx: &deadpool_postgres::tokio_postgres::Transaction<'_>,
        run: RunId,
        claimed: Option<String>,
        conclusion: Option<String>,
    ) -> Result<(), StoreError> {
        // Claimed in the same transaction as the record that carries it, so
        // the claim and the run are one event. Never an upsert: the conflict
        // *is* the answer.
        if let Some(key) = claimed {
            // `DO NOTHING` rather than letting the unique violation raise: a
            // failed statement aborts the transaction, and the next thing needed
            // is a read of *which* run won. The constraint still arbitrates and
            // still blocks a concurrent inserter until that one commits.
            let taken = tx
                .execute(
                    "INSERT INTO run_admission (tenant, key, run_id, admitted_at)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (tenant, key) DO NOTHING",
                    &[
                        &self.tenant_name(),
                        &key,
                        &run.to_string(),
                        &now_secs().cast_signed(),
                    ],
                )
                .await
                .map_err(|error| be(&error))?;
            if taken == 0 {
                let holder = tx
                    .query_opt(
                        "SELECT run_id FROM run_admission WHERE tenant = $1 AND key = $2",
                        &[&self.tenant_name(), &key],
                    )
                    .await
                    .map_err(|error| be(&error))?
                    .map_or_else(String::new, |row| row.get(0));
                return Err(StoreError::DuplicateAdmission { key, run: holder });
            }
        }

        // The outcome index derives from the chain, here, in the same
        // transaction as the record it derives from — and the last conclusion
        // wins. See the schema comment on run_outcome.
        if let Some(outcome) = conclusion {
            tx.execute(
                "INSERT INTO run_outcome (tenant, run_id, outcome, ordinal)
                 VALUES ($1, $2, $3, nextval('run_conclusion_ordinal'))
                 ON CONFLICT (tenant, run_id) DO UPDATE
                    SET outcome = EXCLUDED.outcome, ordinal = EXCLUDED.ordinal",
                &[&self.tenant_name(), &run.to_string(), &outcome],
            )
            .await
            .map_err(|error| be(&error))?;
        }

        Ok(())
    }
}

/// Name what the database refused, in the caller's vocabulary.
///
/// A unique violation here is one of two very different facts, and the
/// **constraint name** is what tells them apart. The partial index
/// `journal_effect_started` refusing a second start is exactly-once holding —
/// not a backend failure, and the caller must be able to tell. The primary key
/// on `(tenant, run_id, seq)` refusing a row is a **race**: two writers
/// extended one chain concurrently, which the fence should have arbitrated.
/// Mapping that to `DuplicateEffect` sent operators hunting a repeated effect
/// that never was.
fn refused_insert(e: &tokio_postgres::Error, record: &Record, run: RunId, seq: u64) -> StoreError {
    if e.code() == Some(&SqlState::UNIQUE_VIOLATION) {
        let constraint = e
            .as_db_error()
            .and_then(|d| d.constraint())
            .unwrap_or_default();
        if constraint == "journal_effect_started"
            && let Some(k) = record.effect_key()
        {
            return StoreError::DuplicateEffect(k);
        }
        return StoreError::Backend(format!(
            "append raced another writer on run {run} at seq {seq} \
             (unique violation on '{constraint}') — two connections \
             extended one chain concurrently, which the lease fence \
             should have serialised"
        ));
    }
    be(e)
}

#[async_trait]
impl JournalStore for PostgresStore {
    /// The topology an embedded store cannot serve: several plane instances
    /// sharing one store, with fencing and exactly-once arbitrated by the
    /// database rather than by hoping the writers agree.
    fn is_shared(&self) -> bool {
        true
    }

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
        // In-doubt classification, not only on the atomic path: see
        // `commit_refused_or_in_doubt` for the double-append a retried
        // "failure" here would produce.
        tx.commit()
            .await
            .map_err(|e| commit_refused_or_in_doubt(&e))?;
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

    async fn admitted_as(&self, key: &str) -> Result<Option<RunId>, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let row = client
            .query_opt(
                "SELECT run_id FROM run_admission WHERE tenant = $1 AND key = $2",
                &[&self.tenant_name(), &key],
            )
            .await
            .map_err(|e| be(&e))?;
        row.map(|row| {
            let id: &str = row.get(0);
            RunId::parse(id).map_err(|e| StoreError::Corrupt {
                seq: 0,
                detail: format!("run_admission holds an unparseable run id '{id}': {e}"),
            })
        })
        .transpose()
    }

    async fn forget_admissions(
        &self,
        older_than: crate::core::Timestamp,
    ) -> Result<usize, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let removed = client
            .execute(
                "DELETE FROM run_admission WHERE tenant = $1 AND admitted_at < $2",
                &[&self.tenant_name(), &older_than.unix_timestamp()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(usize::try_from(removed).unwrap_or(usize::MAX))
    }

    async fn runs_by_outcome(&self, outcome: &str, limit: usize) -> Result<Vec<RunId>, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                // **Newest first.** See `JournalStore::runs_by_outcome`:
                // ascending order plus a page limit means a plane whose backlog
                // already exceeds one page returns the same runs forever, and
                // the quarantine that just happened never appears.
                "SELECT run_id FROM run_outcome
                  WHERE tenant = $1 AND outcome = $2
                  ORDER BY ordinal DESC
                  LIMIT $3",
                &[
                    &self.tenant_name(),
                    &outcome,
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                ],
            )
            .await
            .map_err(|e| be(&e))?;

        rows.iter()
            .map(|r| {
                let id: &str = r.get(0);
                // A stored run id that does not parse is corruption, and the
                // contract (see `JournalStore::runs_by_outcome`) is to say so
                // rather than silently thin the page: a quarantined run that
                // vanishes from the listing is the unreachable-signal failure
                // this method exists to remove.
                RunId::parse(id).map_err(|e| StoreError::Corrupt {
                    seq: 0,
                    detail: format!("run_outcome holds an unparsable run id '{id}': {e}"),
                })
            })
            .collect()
    }

    async fn recent_runs(
        &self,
        after: Option<(u64, RunId)>,
        limit: usize,
    ) -> Result<Vec<(RunId, u64)>, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let cap = i64::try_from(limit).unwrap_or(i64::MAX);
        // Row-value comparison, so the composite cursor is one predicate the
        // `(updated_at DESC, run_id DESC)` index can seek to rather than a
        // disjunction the planner has to unpick.
        let rows = match after {
            Some((updated, run)) => {
                client
                    .query(
                        "SELECT run_id, updated_at FROM run_activity
                         WHERE tenant = $1 AND (updated_at, run_id) < ($2, $3)
                         ORDER BY updated_at DESC, run_id DESC LIMIT $4",
                        &[
                            &self.tenant_name(),
                            &i64::try_from(updated).unwrap_or(i64::MAX),
                            &run.to_string(),
                            &cap,
                        ],
                    )
                    .await
            }
            None => {
                client
                    .query(
                        "SELECT run_id, updated_at FROM run_activity
                         WHERE tenant = $1
                         ORDER BY updated_at DESC, run_id DESC LIMIT $2",
                        &[&self.tenant_name(), &cap],
                    )
                    .await
            }
        }
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
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let now = now_secs();
        let expires = lease_expiry(now, ttl)?;
        let key = run.to_string();

        // **One guarded statement**, so a run's *first* lease is arbitrated by
        // the same constraint as every later one. The previous shape —
        // `SELECT … FOR UPDATE`, decide in Rust, upsert — locked nothing when
        // the row did not exist yet: `FOR UPDATE` on an absent row takes no
        // lock, so two instances first-acquiring one run concurrently both
        // read `None`, both computed epoch 1, and the loser's unguarded upsert
        // overwrote the winner's row. Both returned `Lease { epoch: 1 }` and
        // both passed the append fence — split-brain under a single fencing
        // token, on exactly the backend that exists to prevent it, and the
        // realistic trigger is mundane: two instances driving one batch
        // first-acquire the same reserved run id at the same instant.
        //
        // The `WHERE` clause admits exactly the leases `acquire` may claim:
        // expired ones, which includes released ones — release blanks the
        // owner and zeroes the expiry, so a released row *is* an expired row.
        // A live lease fails the predicate, the upsert updates zero rows, and
        // `RETURNING` hands back nothing: that is the `LeaseHeld` refusal. A
        // claim over a lapsed holder takes `run_lease.epoch + 1`, fencing them
        // — including this very caller, because a lapsed lease is not yours to
        // renew (renewal is `renew`, which proves the exact `(owner, epoch)`).
        // A fresh insert starts at epoch 1. `ON CONFLICT DO UPDATE` serialises
        // racing claimers on the row (or on the index entry being inserted),
        // so exactly one of them wins whichever state the row is in.
        let row = client
            .query_opt(
                "INSERT INTO run_lease (tenant, run_id, owner, epoch, expires_at)
                 VALUES ($1, $2, $3, 1, $4)
                 ON CONFLICT (tenant, run_id) DO UPDATE SET
                   owner = EXCLUDED.owner,
                   epoch = run_lease.epoch + 1,
                   expires_at = EXCLUDED.expires_at
                 WHERE run_lease.expires_at <= $5
                 RETURNING epoch",
                &[
                    &self.tenant_name(),
                    &key,
                    &owner.to_owned(),
                    &expires.cast_signed(),
                    &now.cast_signed(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;

        if let Some(row) = row {
            let epoch: i64 = row.get(0);
            return Ok(Lease {
                run,
                owner: owner.to_owned(),
                epoch: epoch.cast_unsigned(),
            });
        }

        // Zero rows means a live lease refused the claim. The holder is read
        // afterwards only to *name* them in the error; the refusal itself was
        // decided inside the guarded statement, so this read racing a
        // concurrent release can at worst describe a holder who has just let
        // go — the caller's next acquire will win.
        let held = client
            .query_opt(
                "SELECT owner, epoch, expires_at FROM run_lease
                  WHERE tenant = $1 AND run_id = $2",
                &[&self.tenant_name(), &key],
            )
            .await
            .map_err(|e| be(&e))?;
        match held {
            Some(row) => Err(StoreError::LeaseHeld {
                run: key,
                owner: row.get(0),
                epoch: row.get::<_, i64>(1).cast_unsigned(),
                remaining_secs: row.get::<_, i64>(2).cast_unsigned().saturating_sub(now),
            }),
            // Lease rows are never deleted (the epoch lives in them), so a
            // refused claim over a missing row is a store this code does not
            // understand.
            None => Err(StoreError::Backend(format!(
                "acquire for run {key} was refused but no lease row exists — \
                 lease rows are never deleted, so this store's state is not \
                 one this backend can have written"
            ))),
        }
    }

    async fn renew(
        &self,
        run: RunId,
        owner: &str,
        epoch: Epoch,
        ttl: Duration,
    ) -> Result<Lease, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let now = now_secs();
        let expires = lease_expiry(now, ttl)?;
        // One statement, so the check and the write cannot be raced: the row
        // is extended only where it is still held, unexpired and unreleased by
        // exactly `(owner, epoch)`. A released row blanks the owner and fails
        // the ownership predicate; an expired row fails the expiry one,
        // because whoever claims it next takes epoch + 1 and a renewal that
        // got in first would resurrect the fenced past. Zero rows updated
        // means the lease is lost, and a renewal never claims.
        let n = client
            .execute(
                "UPDATE run_lease SET expires_at = $5
                  WHERE tenant = $1 AND run_id = $2 AND owner = $3 AND epoch = $4
                    AND expires_at > $6",
                &[
                    &self.tenant_name(),
                    &run.to_string(),
                    &owner.to_owned(),
                    &epoch.cast_signed(),
                    &expires.cast_signed(),
                    &now.cast_signed(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        if n == 0 {
            return Err(StoreError::LeaseNotHeld {
                run: run.to_string(),
                epoch,
            });
        }
        Ok(Lease {
            run,
            owner: owner.to_owned(),
            epoch,
        })
    }

    async fn abandoned_runs(&self, limit: usize) -> Result<Vec<RunId>, StoreError> {
        let client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        // `owner <> ''` is the released/held distinction — release blanks the
        // owner rather than deleting the row, because the epoch lives in it.
        // The partial index `run_lease_abandoned` serves exactly this shape.
        //
        // Oldest expiry first, so a bounded page cannot starve the run that has
        // been stranded longest behind fresher failures.
        let rows = client
            .query(
                "SELECT run_id FROM run_lease
                  WHERE tenant = $1 AND owner <> '' AND expires_at <= $2
                  ORDER BY expires_at ASC
                  LIMIT $3",
                &[
                    &self.tenant_name(),
                    &now_secs().cast_signed(),
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        rows.iter()
            .map(|row| {
                let id: String = row.get(0);
                // Corruption, per the contract on `JournalStore::abandoned_runs`:
                // a stranded run silently dropped from this listing is never
                // recovered, so an unparsable id is refused loudly rather than
                // skipped.
                RunId::parse(&id).map_err(|e| StoreError::Corrupt {
                    seq: 0,
                    detail: format!("run_lease holds an unparsable run id '{id}': {e}"),
                })
            })
            .collect()
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

    async fn seal(&self, run: RunId, epoch: Epoch, outcome: &str) -> Result<Digest, StoreError> {
        // One transaction, fenced, mirroring the embedded store. This backend
        // exists for the topology where two instances race, and a seal is the
        // write that freezes a chain forever — so it must be arbitrated like
        // every other write. A seal that ignored its epoch and read the head
        // on a separate connection would let a fenced zombie seal a run its
        // replacement was still extending, freezing the Merkle leaf at a head
        // the true history had already moved past.
        let mut client = self.pool.get().await.map_err(|e| pool_err(&e))?;
        let tx = client.transaction().await.map_err(|e| be(&e))?;

        // The fence takes the lease row lock, so a concurrent append on the
        // same run either waits for this transaction or is fenced by it — the
        // head read below cannot go stale between the read and the insert.
        self.fence(&tx, run, epoch).await?;

        // The conclusion is already *in* the chain — the executor appends
        // `RunSealed` before calling this — so sealing reports the terminal
        // hash rather than writing a second one. Tamper detection therefore
        // covers how the run ended, which it would not if the outcome lived in
        // a side table.
        let head_row = tx
            .query_opt(
                "SELECT hash FROM journal
                  WHERE tenant = $1 AND run_id = $2 ORDER BY seq DESC LIMIT 1",
                &[&self.tenant_name(), &run.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        let head = match head_row {
            Some(row) => digest_from(&row.get::<_, Vec<u8>>(0))?,
            None => Digest::ZERO,
        };

        // Enter the log. `DO NOTHING` keeps a repeated seal idempotent — a run
        // that seals twice must not take two positions, or the log's size stops
        // matching the number of runs it commits to.
        tx.execute(
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
        // A seal is a write like any other: a lost commit acknowledgement is
        // in doubt, not retryable — see `commit_refused_or_in_doubt`.
        tx.commit()
            .await
            .map_err(|e| commit_refused_or_in_doubt(&e))?;

        Ok(head)
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

/// Refuse a statement that would end or control the journal's transaction.
///
/// The seam hands a co-located resource the journal's *own* transaction, and
/// the entire value of that is the shared fate: the resource's writes and the
/// records describing them commit together or not at all. A member that issues
/// `COMMIT` commits a half-written batch out from under `append_within`; a
/// `ROLLBACK` dissolves it and the seam then "commits" nothing while reporting
/// success; a `SAVEPOINT`/`RELEASE` pair lets the member carve out a region
/// whose fate diverges from the records'. None of those is a write a resource
/// may make, so they are refused before reaching the wire.
///
/// The check matches the statement's leading keyword (and, where one keyword
/// is ambiguous, the second): `COMMIT`, `END` and their prepared-transaction
/// forms; `ROLLBACK` and `ABORT`; `BEGIN` and `START`; `SAVEPOINT` and
/// `RELEASE`; `PREPARE TRANSACTION` (bare `PREPARE` — statement preparation —
/// stays allowed); `SET TRANSACTION` (other `SET`s stay allowed).
///
/// **What this does not cover**, stated so nobody mistakes it for a boundary:
/// a *function* with side effects on transaction state — a PL/pgSQL procedure
/// that `COMMIT`s, `dblink` opening its own autonomous connection, an
/// extension that manipulates the transaction from C — arrives here as an
/// innocent `SELECT`/`CALL` and passes. So does a control verb hidden behind a
/// leading comment (`/* */ COMMIT`), a `DO` block, or dynamic SQL built with
/// `EXECUTE` inside a function. This is a guard against the honest mistake —
/// a resource ported from code that managed its own transactions — not a
/// sandbox against a hostile one; a resource is trusted code the deployment
/// registered, and what this refusal protects is the atomicity *invariant*,
/// not the database from its own operators.
fn refuse_transaction_control(sql: &str) -> Result<(), StoreError> {
    let mut words = sql
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|w| !w.is_empty());
    let first = words.next().unwrap_or("").to_ascii_uppercase();
    let second = words.next().unwrap_or("").to_ascii_uppercase();
    let forbidden = match first.as_str() {
        // `END` is an alias for COMMIT, `ABORT` for ROLLBACK.
        "COMMIT" | "END" | "ROLLBACK" | "ABORT" | "BEGIN" | "START" | "SAVEPOINT" | "RELEASE" => {
            true
        }
        "PREPARE" | "SET" => second == "TRANSACTION",
        _ => false,
    };
    if forbidden {
        return Err(StoreError::Backend(format!(
            "the statement '{first}' would end or control the journal's \
             transaction — a co-located resource writes *inside* the \
             transaction that records it; it does not own that transaction, \
             and dissolving it from within would break the atomicity the \
             seam exists to provide"
        )));
    }
    Ok(())
}

#[async_trait]
impl AtomicTx for PgAtomicTx<'_> {
    async fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, StoreError> {
        refuse_transaction_control(sql)?;
        let owned = bind(params);
        self.0
            .execute(sql, &as_refs(&owned))
            .await
            .map_err(|e| be(&e))
    }

    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Value>, StoreError> {
        // Guarded on the query path too: the driver does not care which method
        // carries a statement, so `query("ROLLBACK", …)` would run it.
        refuse_transaction_control(sql)?;
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
        // The shared classification: a refusal is a clean rollback, a lost
        // acknowledgement is in doubt. See `commit_refused_or_in_doubt`.
        tx.commit()
            .await
            .map_err(|e| commit_refused_or_in_doubt(&e))?;
        Ok(sealed)
    }
}
