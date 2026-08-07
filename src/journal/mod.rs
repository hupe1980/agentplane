//! The journal: append-only, hash-chained run history.
//!
//! This is the product. Recovery, audit, cost accounting, regression testing,
//! and regulatory record-keeping are all views over one log — and because the
//! audit trail *is* the recovery mechanism, it cannot silently stop working.
//! The system would stop working with it. Logging that exists only for
//! compliance always rots; this cannot.

mod atomic;
mod note;
mod record;
mod replay;
mod store;
mod upcast;
mod witness;
#[cfg(feature = "witness-http")]
mod witness_http;

pub use atomic::{AtomicJournal, AtomicResource, AtomicTx, AtomicWork, SqlValue};
pub use note::{NoteSignature, SignedNote, key_id};
pub use record::{AgentIdentity, Append, Record, RecordBody, RecordKind};
pub use replay::{EffectReplay, ReplayCursor, StepCursor};
pub use store::{Cancellation, Checkpoint, Head, Inclusion, JournalStore, Lease};
pub use upcast::{Identity, Upcaster};
pub use witness::{
    Cosignature, MemoryWitness, QuorumOutcome, Witness, WitnessError, WitnessQuorum, cosign_quorum,
};
#[cfg(feature = "witness-http")]
pub use witness_http::HttpWitness;
