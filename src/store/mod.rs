//! Persistence backends.
//!
//! Single node runs on Turso — a SQLite-compatible engine written in Rust; the
//! active-active topology (run-ownership leases plus fencing epochs, arbitrated
//! by the store) is designed for `PostgreSQL`. The
//! [`JournalStore`](crate::journal::JournalStore) contract is identical for
//! both, and the invariants it demands — fencing, exactly-once, chaining — are
//! expressed as constraints so a backend cannot quietly omit one.

#[cfg(feature = "turso")]
mod batches;
#[cfg(feature = "turso")]
mod cases;
#[cfg(feature = "turso")]
mod events;
#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "postgres")]
mod postgres_cases;
#[cfg(feature = "turso")]
mod tasks;
#[cfg(feature = "turso")]
mod timers;
#[cfg(feature = "turso")]
mod turso;

#[cfg(feature = "postgres")]
pub use postgres::PostgresStore;
#[cfg(feature = "turso")]
pub use turso::TursoStore;
