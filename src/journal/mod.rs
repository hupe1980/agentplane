//! The journal: append-only, hash-chained run history.
//!
//! This is the product. Recovery, audit, cost accounting, regression testing,
//! and regulatory record-keeping are all views over one log — and because the
//! audit trail *is* the recovery mechanism, it cannot silently stop working.
//! The system would stop working with it. Logging that exists only for
//! compliance always rots; this cannot.

mod record;
mod replay;
mod store;
mod upcast;

pub use record::{Append, Record, RecordBody, RecordKind};
pub use replay::{EffectReplay, ReplayCursor, StepCursor};
pub use store::{Cancellation, Checkpoint, Head, Inclusion, JournalStore, Lease};
pub use upcast::{Identity, Upcaster};
