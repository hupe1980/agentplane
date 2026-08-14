//! The lifecycle lock cryptographic memory erasure needs, and who can hold it.
//!
//! Destroying a subject's wrapping key is not one operation. It reads the
//! subject's items, checks every legal hold, tombstones, and then asks a KMS to
//! destroy the scope — and between the hold check and the destroy, a write on
//! another instance can add an item, or an operator can place a hold on one.
//! Either makes the erasure wrong in a way nothing detects: the new item is
//! sealed under a scope that is about to stop existing, and the held item is
//! destroyed anyway.
//!
//! [`EncryptedMemoryStore`](super::EncryptedMemoryStore) closed that window with
//! a `tokio::sync::Mutex`, which is correct **and process-local** — so the
//! adapter held its contract on a single-writer deployment and silently did not
//! on an active-active one. That is worse than absent, because a configured key
//! ring reads as *this plane can erase*.
//!
//! So the lock is a seam. [`LocalCoordinator`] is the mutex, named for what it
//! is and refusing to pretend otherwise; [`PostgresCoordinator`] is a session
//! advisory lock in the database the plane already shares.
//!
//! # Why a session advisory lock, and not a row
//!
//! A row taken with `SELECT … FOR UPDATE` needs its transaction held open for
//! the whole erasure, and the erasure's own writes go through the store's other
//! connections — so the row lock would be held by a transaction that cannot see
//! the work it is protecting. A **session** advisory lock is held by the
//! connection rather than the transaction, and `PostgreSQL` releases it when the
//! session ends. That last property is the one that matters: an instance that
//! dies mid-erasure releases the lock by dying, where a lease with a TTL would
//! either strand the subject or hand it over while the KMS call is still in
//! flight.

use async_trait::async_trait;

use crate::core::StoreError;

/// Permission to run one subject's lifecycle operation, held until released.
///
/// Deliberately not an RAII guard. Releasing a distributed lock is `async` and
/// fallible, and `Drop` is neither — a guard would have to either block a
/// runtime thread or drop the failure, and dropping *that* failure strands the
/// subject for every other instance. Callers use
/// [`under_lock`], which releases on both paths.
#[derive(Debug)]
pub struct Lease {
    scope: String,
    token: u64,
}

impl Lease {
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }
}

/// Who serialises a scope's lifecycle operations.
#[async_trait]
pub trait ErasureCoordinator: Send + Sync + std::fmt::Debug {
    /// Block until this scope's lifecycle lock is held.
    ///
    /// **Not cancel-safe.** Dropping this future mid-flight can leave the lock
    /// taken with no [`Lease`] to release it — the `PostgresCoordinator` has a
    /// query outstanding on a pooled connection at that moment, and returning
    /// that connection to the pool deadlocks its next user. Found by a test
    /// that wrapped this in a `timeout` and hung the suite. Call it through
    /// [`under_lock`], never inside a `select!` or a `timeout`; to ask *whether*
    /// a scope is locked without taking it, use a probe
    /// (`PostgresStore::erasure_probe`).
    async fn acquire(&self, scope: &str) -> Result<Lease, StoreError>;

    /// Release it. Called on the success *and* the failure path.
    async fn release(&self, lease: Lease) -> Result<(), StoreError>;

    /// Whether this coordinator spans instances.
    ///
    /// Read at `build` so a plane can refuse a single-node coordinator beside a
    /// shared store rather than discovering it during an erasure that reported
    /// success. A coordinator that answers wrongly here is the one failure this
    /// seam cannot catch, which is why the answer is a constant per
    /// implementation and not a configuration value.
    fn is_distributed(&self) -> bool;
}

/// Run `work` with the scope's lifecycle lock held.
///
/// A free function rather than a default method, so the release-on-both-paths
/// rule has exactly one implementation. Two copies of one rule agree everywhere
/// except the boundary nobody probed, and here that boundary is a lock nobody
/// released — a subject stranded for every other instance.
///
/// # Errors
///
/// The acquire failure, the work's own failure, or — only when the work
/// succeeded and the release did not — the release failure.
pub async fn under_lock<T, F, Fut>(
    coordinator: &dyn ErasureCoordinator,
    scope: &str,
    work: F,
) -> Result<T, StoreError>
where
    F: FnOnce() -> Fut + Send,
    Fut: std::future::Future<Output = Result<T, StoreError>> + Send,
{
    let lease = coordinator.acquire(scope).await?;
    let outcome = work().await;
    let released = coordinator.release(lease).await;
    match (outcome, released) {
        // The work's failure wins: it is the one the caller asked about, and a
        // release failure on top of it is noise about a lock the database will
        // free when the session ends.
        (Err(work), _) => Err(work),
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(release)) => Err(release),
    }
}

/// The process-local lock, named for what it is.
///
/// Correct for redb or any other single-writer deployment, and honest about
/// being nothing else: [`is_distributed`](ErasureCoordinator::is_distributed)
/// answers `false`, so a plane sharing a store can refuse it at build.
///
/// Per **scope**, not one lock for everything: two independent scopes never
/// contend, so the granularity is whatever the caller's scopes encode. That
/// is a capability, not a promise about any particular caller —
/// [`EncryptedMemoryStore`](super::EncryptedMemoryStore) deliberately passes
/// **one scope per tenant** (its id-addressed operations cannot know their
/// subject without a racy lookup), so for that wrapper this coordinator
/// behaves as a per-tenant lock and the finer granularity sits unused. A
/// caller with genuinely finer scopes — per case, per subject — gets the
/// finer lock for free.
#[derive(Debug, Default)]
pub struct LocalCoordinator {
    scopes:
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    held: std::sync::Mutex<std::collections::HashMap<u64, tokio::sync::OwnedMutexGuard<()>>>,
    next: std::sync::atomic::AtomicU64,
}

impl LocalCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ErasureCoordinator for LocalCoordinator {
    async fn acquire(&self, scope: &str) -> Result<Lease, StoreError> {
        let lock = {
            let mut scopes = self.scopes.lock().expect("lifecycle scopes");
            std::sync::Arc::clone(
                scopes
                    .entry(scope.to_owned())
                    .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        let guard = lock.lock_owned().await;
        let token = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.held
            .lock()
            .expect("lifecycle leases")
            .insert(token, guard);
        Ok(Lease {
            scope: scope.to_owned(),
            token,
        })
    }

    async fn release(&self, lease: Lease) -> Result<(), StoreError> {
        self.held
            .lock()
            .expect("lifecycle leases")
            .remove(&lease.token);
        Ok(())
    }

    fn is_distributed(&self) -> bool {
        false
    }
}

/// A lifecycle lock held in the `PostgreSQL` the plane already shares.
///
/// `pg_advisory_lock` on a **session**, so it is held by the connection rather
/// than by a transaction — which is what this needs, because the erasure's own
/// writes go through the store's other connections and a transaction-scoped
/// lock would be held by something that cannot see the work it protects.
///
/// The property that made this the right primitive rather than a lease table:
/// `PostgreSQL` releases a session's advisory locks **when the session ends**. An
/// instance that dies mid-erasure therefore releases by dying. A lease with a
/// TTL has to choose between stranding the subject until the TTL expires and
/// handing it to another instance while the first one's KMS call may still be
/// in flight, and neither is a choice worth making when the database already
/// knows whether the holder is alive.
#[cfg(feature = "postgres")]
#[derive(Debug)]
pub struct PostgresCoordinator {
    pool: deadpool_postgres::Pool,
    held: tokio::sync::Mutex<std::collections::HashMap<u64, deadpool_postgres::Object>>,
    next: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "postgres")]
impl PostgresCoordinator {
    /// Take the lock in this pool's database.
    ///
    /// The same database as the journal, deliberately: a lock in a *different*
    /// one would be a second system that can be up while the store is down, and
    /// an erasure coordinator that is available when the data is not protects
    /// nothing.
    #[must_use]
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self {
            pool,
            held: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            next: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// A scope name as the 64-bit key `pg_advisory_lock` takes.
    ///
    /// SHA-256 truncated rather than a `DefaultHasher`: the key has to be the
    /// same number in every process that ever locks this scope, and
    /// `DefaultHasher` is explicitly not stable across releases — a hash that
    /// changed between two instances' binaries would give each its own lock and
    /// silently stop excluding anything.
    pub(crate) fn scope_key(scope: &str) -> i64 {
        Self::key(scope)
    }

    fn key(scope: &str) -> i64 {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(scope.as_bytes());
        i64::from_be_bytes(digest[..8].try_into().expect("8 bytes"))
    }
}

#[cfg(feature = "postgres")]
#[async_trait]
impl ErasureCoordinator for PostgresCoordinator {
    async fn acquire(&self, scope: &str) -> Result<Lease, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        // Blocking form, not `try_`: a caller that failed to get the lock would
        // have to decide between retrying and skipping, and skipping an erasure
        // is the wrong answer to contention.
        client
            .execute("SELECT pg_advisory_lock($1)", &[&Self::key(scope)])
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let token = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.held.lock().await.insert(token, client);
        Ok(Lease {
            scope: scope.to_owned(),
            token,
        })
    }

    async fn release(&self, lease: Lease) -> Result<(), StoreError> {
        let Some(client) = self.held.lock().await.remove(&lease.token) else {
            return Ok(());
        };
        // Unlock explicitly and only then return the connection to the pool. A
        // pooled session that goes back still holding the lock keeps it until
        // that session is recycled, which is a lock leak with no error anywhere
        // — the failure this whole seam exists to prevent, arriving from inside.
        let unlocked = client
            .execute(
                "SELECT pg_advisory_unlock($1)",
                &[&Self::key(lease.scope())],
            )
            .await;
        match unlocked {
            Ok(_) => {
                drop(client);
                Ok(())
            }
            Err(error) => {
                // The unlock failed but the session may still be healthy —
                // a statement timeout, a cancelled query — and a healthy
                // session recycled into the pool **still holds the lock**:
                // its next user runs unrelated queries on a connection that
                // silently serialises every erasure on this scope, until the
                // pool happens to retire it. Taking the connection out of the
                // pool and dropping it closes the session, and PostgreSQL
                // frees a dead session's advisory locks — so the failure path
                // costs one connection instead of an invisible lock leak.
                // What this does not cover: a network partition where the
                // server never notices the client is gone keeps the lock until
                // the server-side timeout reaps the session.
                drop(deadpool_postgres::Object::take(client));
                Err(StoreError::Backend(error.to_string()))
            }
        }
    }

    fn is_distributed(&self) -> bool {
        true
    }
}
