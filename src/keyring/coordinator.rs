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
//! A `tokio::sync::Mutex` closes that window and is **process-local**, so on its
//! own it holds the contract on a single-writer deployment and silently does not
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
/// **Dropping it releases the lock**, and that is what makes every path through
/// this seam safe rather than only the ones that remember to call
/// [`release`](ErasureCoordinator::release). The argument against an RAII guard
/// — that releasing a distributed lock is `async` and fallible while `Drop` is
/// neither — is true of a lease *table* and false of the two primitives here: a
/// process-local mutex releases by dropping its guard, and a `PostgreSQL`
/// session advisory lock releases when the session ends, so dropping the
/// connection is a complete release. Both are synchronous and cannot fail.
///
/// `release` still exists and is still what callers use through
/// [`under_lock`], because it does the *tidy* thing: it unlocks explicitly, so
/// the scope is free immediately rather than whenever a connection finishes
/// closing, and it can report a failure. Correctness does not depend on it
/// being reached.
///
/// An implementation whose release genuinely needs a round trip — a lease row,
/// a lock service with no session semantics — builds a lease with
/// [`new`](Self::new) and carries no guard. It is then back to needing
/// `release`, and its cancellation story is its own.
pub struct Lease {
    scope: String,
    token: u64,
    /// Whatever holds the lock, if holding it is a value. Dropped on release
    /// and on cancellation alike.
    guard: Option<Box<dyn std::any::Any + Send + Sync>>,
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("scope", &self.scope)
            .field("token", &self.token)
            .field("guarded", &self.guard.is_some())
            .finish()
    }
}

impl Lease {
    /// Mint a lease for a scope, keyed by whatever the implementation uses to
    /// find the lock again in [`release`](ErasureCoordinator::release).
    ///
    /// Public because the trait is a seam: an implementation living in another
    /// crate — etcd, Redis, a vendor's lock service — has to be able to return
    /// one of these, and without a constructor the trait is `pub` and
    /// implementable by nobody.
    #[must_use]
    pub fn new(scope: impl Into<String>, token: u64) -> Self {
        Self {
            scope: scope.into(),
            token,
            guard: None,
        }
    }

    /// A lease whose lock is released by dropping `guard`.
    ///
    /// Prefer this wherever it is expressible: it is what makes a cancelled
    /// future release the scope instead of stranding it. `release` can take the
    /// guard back with [`take_guard`](Self::take_guard) to unlock explicitly
    /// first.
    #[must_use]
    pub fn holding<G: Send + Sync + 'static>(
        scope: impl Into<String>,
        token: u64,
        guard: G,
    ) -> Self {
        Self {
            scope: scope.into(),
            token,
            guard: Some(Box::new(guard)),
        }
    }

    /// Take the guard back, to release it deliberately rather than by dropping.
    pub fn take_guard<G: 'static>(&mut self) -> Option<Box<G>> {
        self.guard.take().and_then(|g| g.downcast::<G>().ok())
    }

    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The implementation's own handle on the held lock.
    #[must_use]
    pub const fn token(&self) -> u64 {
        self.token
    }
}

/// Proof that an acquire is happening inside [`under_lock`].
///
/// Its only field is private to this module, so a value of it cannot be
/// constructed anywhere else — which makes calling
/// [`acquire`](ErasureCoordinator::acquire) outside `under_lock` a compile
/// error rather than a rule in a doc comment. What that buys is the explicit
/// unlock and the reported failure: a dropped lease frees the scope on its own,
/// and a lease nobody ever drops is a scope held for as long as the caller
/// holds it.
///
/// The rule is the compiler's now, and this is what says so — widen the field
/// back to public and this stops failing:
///
/// ```compile_fail
/// use agentplane::keyring::{ErasureCoordinator, LocalCoordinator, UnderLock};
/// # async fn f() {
/// let coordinator = LocalCoordinator::default();
/// // No way to make an `UnderLock` from out here, so no way to take a lock
/// // this caller has not promised to release.
/// let _ = coordinator.acquire("scope", UnderLock(())).await;
/// # }
/// ```
#[derive(Debug)]
pub struct UnderLock(());

#[cfg(feature = "testkit")]
impl UnderLock {
    /// Take a lifecycle lock without the wrapper, to test the lock itself.
    ///
    /// A distributed lock is only testable by holding it: one instance takes a
    /// scope, a second must block, the release must grant it, and a different
    /// scope must not contend. None of that fits inside
    /// [`under_lock`]'s closure, which releases before it returns.
    ///
    /// Gated on `testkit` for the reason every escape in that feature is: it
    /// exists so a seam can be *checked*, and it must not ship. Using it to
    /// skip `under_lock` in ordinary code reinstates the bug the token exists
    /// to prevent — an acquire whose release never runs strands the scope for
    /// every other instance — and no test will tell you, because the strand
    /// only appears on the next erasure.
    #[must_use]
    pub const fn for_test() -> Self {
        Self(())
    }
}

/// Who serialises a scope's lifecycle operations.
#[async_trait]
pub trait ErasureCoordinator: Send + Sync + std::fmt::Debug {
    /// Block until this scope's lifecycle lock is held.
    ///
    /// Reachable only from [`under_lock`], which is what the [`UnderLock`]
    /// argument is for. The lease releases itself when dropped, so this is
    /// about the *tidy* release rather than about correctness: `under_lock`
    /// unlocks explicitly on both paths, so the scope frees immediately and a
    /// release failure reaches somebody.
    ///
    /// # Errors
    ///
    /// Whatever the underlying lock service answers.
    async fn acquire(&self, scope: &str, _: UnderLock) -> Result<Lease, StoreError>;

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
/// **Dropping this future releases the scope**, for both shipped coordinators,
/// because the lock travels in the [`Lease`] and dropping a lease is a complete
/// release: a process-local mutex gives up its guard, and a `PostgreSQL`
/// session advisory lock ends with the session. So an ordinary `timeout` around
/// something that reaches here — a `timeout` on an `EncryptedMemoryStore`
/// write, say — abandons the work without stranding the subject.
///
/// What is lost on that path is only the tidy half: the explicit unlock, so the
/// scope frees when the connection finishes closing rather than immediately,
/// and the release failure, which nobody is left to report. A coordinator whose
/// release genuinely needs a round trip carries no guard and has neither
/// property — see [`Lease`].
///
/// To ask *whether* a scope is locked without taking it, use a probe
/// (`PostgresStore::erasure_probe`).
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
    let lease = coordinator.acquire(scope, UnderLock(())).await?;
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
    async fn acquire(&self, scope: &str, _: UnderLock) -> Result<Lease, StoreError> {
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
        Ok(Lease::holding(scope, token, guard))
    }

    async fn release(&self, lease: Lease) -> Result<(), StoreError> {
        // The guard travels in the lease, so releasing is dropping it — which
        // is also what a cancelled future does.
        drop(lease);
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
    async fn acquire(&self, scope: &str, _: UnderLock) -> Result<Lease, StoreError> {
        let pooled = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        // **Detached from the pool before the lock is taken**, and that is what
        // makes this future safe to drop. A session advisory lock belongs to
        // the connection, so a pooled connection handed back while it holds one
        // — or while a `pg_advisory_lock` is still outstanding on it — keeps the
        // lock and wedges whoever gets that connection next. Owned by the lease
        // instead, a dropped future drops the client, the client closes the
        // session, and `PostgreSQL` frees the session's locks. That is the same
        // property this primitive was chosen for: an instance that dies
        // mid-erasure releases by dying, and a cancelled future is a small
        // death.
        //
        // The cost is one connection per erasure rather than one borrow, paid
        // on an operation a deployment performs when somebody asks to be
        // forgotten.
        let client = deadpool_postgres::Object::take(pooled);
        // Blocking form, not `try_`: a caller that failed to get the lock would
        // have to decide between retrying and skipping, and skipping an erasure
        // is the wrong answer to contention.
        client
            .execute("SELECT pg_advisory_lock($1)", &[&Self::key(scope)])
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let token = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Lease::holding(scope, token, client))
    }

    async fn release(&self, mut lease: Lease) -> Result<(), StoreError> {
        let Some(client) = lease.take_guard::<deadpool_postgres::ClientWrapper>() else {
            return Ok(());
        };
        // Unlock explicitly rather than relying on the session ending, so the
        // scope is free the instant the work is done rather than whenever the
        // connection finishes closing. Dropping the client is what actually
        // guarantees it either way.
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
                // The unlock failed but the session may still be healthy — a
                // statement timeout, a cancelled query — and a healthy session
                // that stayed open **still holds the lock**. Dropping the
                // client closes it, and `PostgreSQL` frees a dead session's
                // advisory locks, so the failure path costs one connection
                // instead of an invisible lock leak.
                //
                // What this does not cover: a network partition where the
                // server never notices the client is gone keeps the lock until
                // the server-side timeout reaps the session.
                drop(client);
                Err(StoreError::Backend(error.to_string()))
            }
        }
    }

    fn is_distributed(&self) -> bool {
        true
    }
}
