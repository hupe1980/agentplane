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
mod postgres_authority;
#[cfg(feature = "postgres")]
mod postgres_cases;
#[cfg(feature = "postgres")]
mod postgres_memory;
#[cfg(all(feature = "postgres", feature = "push"))]
mod postgres_push;
#[cfg(feature = "postgres")]
mod postgres_quota;
#[cfg(all(feature = "postgres", feature = "manifest"))]
mod postgres_registry;
#[cfg(feature = "redb")]
mod redb;
#[cfg(feature = "redb")]
mod redb_authority;
#[cfg(feature = "redb")]
mod redb_batches;
#[cfg(feature = "redb")]
mod redb_cases;
#[cfg(feature = "redb")]
mod redb_events;
#[cfg(feature = "redb")]
mod redb_memory;
#[cfg(all(feature = "redb", feature = "push"))]
mod redb_push;
#[cfg(feature = "redb")]
mod redb_quota;
#[cfg(all(feature = "redb", feature = "manifest"))]
mod redb_registry;
#[cfg(feature = "redb")]
mod redb_tasks;
#[cfg(feature = "redb")]
mod redb_timers;

#[cfg(feature = "postgres")]
pub use postgres::PostgresStore;
#[cfg(feature = "redb")]
pub use redb::RedbStore;

/// A stored `(actor, basis)` pair, or corruption naming the table it came from.
///
/// Every backend keeps operator attribution as two columns, and an act this
/// build cannot attribute is one it must refuse rather than serve under a
/// guessed name: the whole evidentiary weight of an operator act is who asked.
pub(crate) fn decode_operator(
    actor: &str,
    basis: &str,
    table: &str,
) -> Result<crate::core::Operator, crate::core::StoreError> {
    crate::core::Operator::from_parts(actor, basis).map_err(|e| crate::core::StoreError::Corrupt {
        seq: 0,
        detail: format!("{table} holds an act this build cannot attribute: {e}"),
    })
}

/// What a store keeps beside the keys, for the two rows that carry an operator.
///
/// These live here rather than beside `Halt` and `LegalHold` because they are
/// **encodings**, not domain types: `core` is held to having no I/O and no
/// knowledge of which backends exist, and a row shape gated on a backend
/// feature is exactly that knowledge. One spelling each, because two encoders
/// of one row agree until the day a field is added to one of them.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct HaltRow {
    pub reason: String,
    pub by: crate::core::Operator,
    #[serde(with = "time::serde::rfc3339")]
    pub at: crate::core::Timestamp,
}

/// The same, for a preservation order.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct HoldRow {
    pub reason: String,
    pub by: crate::core::Operator,
}

/// Rebuild a halt from its key and its row.
pub(crate) fn halt_from_row(scope: crate::quota::HaltScope, row: HaltRow) -> crate::quota::Halt {
    crate::quota::Halt {
        scope,
        reason: row.reason,
        by: row.by,
        at: row.at,
    }
}

/// The part of a hold a store writes under its keys.
///
/// Only the embedded backend serializes the row whole; PostgreSQL writes the
/// same fields as columns, so this is gated on the backend that uses it rather
/// than allowed as dead code in the builds that do not.
#[cfg(feature = "redb")]
pub(crate) fn hold_row(h: &crate::core::LegalHold) -> HoldRow {
    HoldRow {
        reason: h.reason.clone(),
        by: h.by.clone(),
    }
}

/// Rebuild a hold from its instant and its row.
pub(crate) fn hold_from_row(
    placed_at: crate::core::Timestamp,
    row: HoldRow,
) -> crate::core::LegalHold {
    crate::core::LegalHold {
        placed_at,
        reason: row.reason,
        by: row.by,
    }
}
