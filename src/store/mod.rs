//! Persistence backends.
//!
//! Single node runs on [redb](https://github.com/cberner/redb) — pure Rust, two
//! crates deep, with a stable on-disk format. The active-active topology
//! (run-ownership leases plus fencing epochs, arbitrated by the store) is
//! designed for `PostgreSQL`. The
//! [`JournalStore`](crate::journal::JournalStore) contract is identical for
//! both, and the invariants it demands — fencing, exactly-once, chaining — are
//! expressed as constraints so a backend cannot quietly omit one.

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "postgres")]
mod postgres_cases;
#[cfg(feature = "redb")]
mod redb;
#[cfg(feature = "redb")]
mod redb_batches;
#[cfg(feature = "redb")]
mod redb_cases;
#[cfg(feature = "redb")]
mod redb_events;
#[cfg(feature = "redb")]
mod redb_tasks;
#[cfg(feature = "redb")]
mod redb_timers;

#[cfg(feature = "postgres")]
pub use postgres::PostgresStore;
#[cfg(feature = "redb")]
pub use redb::RedbStore;
