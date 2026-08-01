//! Persistence backends.
//!
//! Single node runs on `SQLite`; the active-active topology (run-ownership leases
//! plus fencing epochs, arbitrated by the store) is designed for `PostgreSQL`. The
//! [`JournalStore`](crate::journal::JournalStore) contract is identical for
//! both, and the invariants it demands — fencing, exactly-once, chaining — are
//! expressed as constraints so a backend cannot quietly omit one.

#[cfg(feature = "sqlite")]
mod batches;
#[cfg(feature = "sqlite")]
mod cases;
#[cfg(feature = "sqlite")]
mod events;
#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "postgres")]
mod postgres_cases;
#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "sqlite")]
mod tasks;
#[cfg(feature = "sqlite")]
mod timers;

#[cfg(feature = "postgres")]
pub use postgres::PostgresStore;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;
