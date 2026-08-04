//! Committing with the journal, rather than beside it.
//!
//! # The one case where a saga is not the best available answer
//!
//! An [`EffectGroup`](crate::runtime::EffectGroup) is the saga form: members are
//! performed, and taken back if the group aborts. That is the right answer when
//! the members live in systems that cannot share a transaction — a payment
//! provider and a warehouse — because there is nothing else on offer.
//!
//! It is *not* the best answer when the resource lives in the **same database as
//! the journal**. There the member's write and the record that it happened can
//! commit together, and then:
//!
//! * nothing is externalised and later reversed, so no reversal can fail;
//! * there is no `InDoubt` state, because a transaction either committed or did
//!   not — the undecidable window the effect protocol exists to survive is not
//!   merely handled, it is absent;
//! * an abort is a `ROLLBACK`, which is free and cannot itself fail halfway.
//!
//! Compensation that never has to run beats compensation that runs correctly.
//!
//! # Why this seam is SQL-shaped, and only Postgres has it
//!
//! The premise is that the resource is *already there* — a ledger table, a
//! reservation table, whatever the deployment keeps beside its journal. So the
//! seam speaks the language that resource is written in. A key-value seam that
//! every backend could implement would only be able to touch a table this crate
//! defined, which is not the table anybody wants to be atomic with.
//!
//! Embedded backends return `None` from
//! [`JournalStore::atomic`](crate::journal::JournalStore::atomic). That is a
//! capability being absent rather than a failure: a group with an atomic member
//! on a store that cannot enlist is refused when the member is registered, which
//! is the only time refusing is free.
//!
//! # The work returns the records
//!
//! [`AtomicWork::run`] both applies the members and hands back the records to
//! append. This is not a convenience: the records carry the members' *outputs*,
//! so anything that built them outside the transaction would be describing work
//! whose result it could not yet know. One call, one transaction, no ordering
//! for a caller to get wrong.

use std::fmt::Debug;

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{EffectDescriptor, EffectError, Epoch, StoreError};
use crate::journal::{Append, Record};

/// A value a co-located resource binds into a statement.
///
/// Deliberately a closed set rather than the driver's own parameter trait. A
/// resource written against `tokio_postgres::ToSql` would be a resource that
/// cannot be tested without a database and cannot move to another backend, and
/// this crate would have a driver in its public API.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    /// Bound as `jsonb`.
    Json(Value),
}

impl From<i64> for SqlValue {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}
impl From<&str> for SqlValue {
    fn from(v: &str) -> Self {
        Self::Text(v.to_owned())
    }
}
impl From<String> for SqlValue {
    fn from(v: String) -> Self {
        Self::Text(v)
    }
}
impl From<bool> for SqlValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}
impl From<Value> for SqlValue {
    fn from(v: Value) -> Self {
        Self::Json(v)
    }
}

/// As much of the journal's own transaction as a co-located resource may use.
///
/// Statements are parameterised because the alternative is a resource building
/// SQL by concatenation, and a resource is handed values that came from a model
/// often enough that this is not a style preference.
#[async_trait]
pub trait AtomicTx: Send + Sync {
    /// Run a statement, returning the number of rows it changed.
    ///
    /// # Errors
    ///
    /// If the statement is rejected. The transaction is then poisoned and the
    /// whole group rolls back — which is the point.
    async fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, StoreError>;

    /// Run a query, returning each row as a JSON object.
    ///
    /// # Errors
    ///
    /// If the query is rejected.
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Value>, StoreError>;
}

/// One member that commits with the journal or not at all.
#[async_trait]
pub trait AtomicResource: Send + Sync + Debug {
    /// What this does, for the journal record and the effect key.
    fn descriptor(&self) -> EffectDescriptor;

    /// Apply it, inside the journal's transaction.
    ///
    /// Returning `Err` rolls the whole transaction back, including every other
    /// member and the group's own records. There is no partial outcome to
    /// report and nothing to compensate.
    ///
    /// # Errors
    ///
    /// If the resource refuses the work.
    async fn apply(&self, tx: &dyn AtomicTx) -> Result<Value, EffectError>;
}

/// What runs inside the journal's transaction.
///
/// Implemented by the runtime, not by users: it is how an
/// [`EffectGroup`](crate::runtime::EffectGroup) hands its atomic members and the
/// records describing them to the store as one unit.
#[async_trait]
pub trait AtomicWork: Send + Sync {
    /// Apply the members and return the records to append in the same
    /// transaction.
    ///
    /// # Errors
    ///
    /// If any member refuses. Nothing is committed.
    async fn run(&self, tx: &dyn AtomicTx) -> Result<Vec<Append>, EffectError>;
}

/// A store whose own transaction a co-located resource can join.
///
/// Reached through [`JournalStore::atomic`](crate::journal::JournalStore::atomic),
/// which answers `None` for a backend that cannot offer this. Absence is the
/// honest answer and it is checked where it is cheap — at registration, not at
/// commit.
#[async_trait]
pub trait AtomicJournal: Send + Sync {
    /// Run `work` and append what it returns, in one transaction, fenced by
    /// `epoch` exactly as an ordinary append is.
    ///
    /// The run is named rather than read from the records, because the fence is
    /// taken **before** the work runs. Deriving it afterwards would execute a
    /// displaced writer's statements and only then discover it had no right to
    /// — harmless for a transaction, and a bad habit to build a fence on.
    ///
    /// The fence is not optional here and not weaker: a displaced writer that
    /// could commit a resource change because it arrived wrapped in a
    /// transaction would be a fence with a hole in it shaped like this feature.
    ///
    /// # Errors
    ///
    /// [`StoreError::Fenced`] if the epoch has moved on, or whatever the work
    /// or the append reports. Any error means **nothing** was committed.
    async fn append_atomic(
        &self,
        run: crate::core::RunId,
        epoch: Epoch,
        work: &dyn AtomicWork,
    ) -> Result<Vec<Record>, StoreError>;
}
