//! The journal: append-only, hash-chained run history.
//!
//! This is the product. Recovery, audit, cost accounting, regression testing,
//! and regulatory record-keeping are all views over one log — and because the
//! audit trail *is* the recovery mechanism, it cannot silently stop working.
//! The system would stop working with it. Logging that exists only for
//! compliance always rots; this cannot.

mod atomic;
mod failure;
mod note;
// Unconditional: a build with no key ring still reads an export a sealed
// plane wrote, and must tell a sealed payload from a readable one.
pub mod payload;

mod record;
mod replay;
mod signal;
mod store;
mod upcast;
pub mod view;
mod witness;
#[cfg(feature = "witness-http")]
mod witness_http;

pub use atomic::{AtomicJournal, AtomicResource, AtomicTx, AtomicWork, SqlValue};
pub use failure::{FailedEffect, failed_effect, refuses_the_account};
pub use note::{NoteSignature, SignedNote, key_id};
pub use record::{
    AgentIdentity, Append, BoundSubject, Record, RecordBody, RecordKind, SubjectBinding,
};
pub use replay::{
    Divergence, EffectReplay, ReplayCursor, StepCursor, Unconsumed, undecided_effects,
};
pub use signal::{AppendSignals, AppendWatch};
pub use store::{
    Cancellation, Checkpoint, FeedCursor, FeedPage, Head, Inclusion, JournalStore, Lease,
    WaitingRun,
};
pub use upcast::{Identity, Upcaster, current_upcaster};
pub use witness::{
    Anchor, Cosignature, CosignedCheckpoint, MemoryWitness, QuorumOutcome, SplitView, Witness,
    WitnessError, WitnessQuorum, WitnessTime, cosign_quorum, split_views,
};
#[cfg(feature = "witness-http")]
pub use witness_http::{HttpWitness, LogKey, TrustedWitness, WitnessReader, cosignatures_in};
