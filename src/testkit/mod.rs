//! Test facilities for embedders, and for this crate's own assurance layers.
//!
//! Shipped rather than confined to `tests/` because an embedder's own store
//! implementation and own skills need the same treatment this crate's do, and
//! rebuilding a fault injector per project is how each one ends up testing a
//! slightly different, slightly weaker thing.
//!
//! Behind the `testkit` feature, off by default: nothing here should be
//! reachable from a production build.

pub mod backstop;
pub mod conformance;
// The case-layer battery is backend-agnostic — it names no `redb` type — so the
// gate has to be "a backend exists", not "the embedded one does". Read as `redb`
// it made the *shared-store* backend's own contract untestable without linking
// the embedded one, which is the configuration a Postgres deployment ships.
#[cfg(any(feature = "redb", feature = "postgres"))]
pub mod conformance_case;
#[cfg(feature = "keyring")]
pub mod conformance_keyring;
pub mod conformance_quota;
mod fake_model;
pub mod faults;
#[cfg(feature = "keyring")]
pub mod memory_keyring;
mod shared_journal;
pub use shared_journal::SharedJournal;
mod staged_atomic;
mod stub_signer;
#[cfg(feature = "keyring")]
pub use memory_keyring::MemoryKeyRing;
pub use staged_atomic::{StagedAtomic, Statement};
pub use stub_signer::StubSigner;

pub use backstop::assert_replay_was_not_backstopped;
pub use conformance::{Report, Violation, check as check_journal_store};
pub use fake_model::{Ask, FakeProvider};
pub use faults::{Fault, Faulty, Schedule};
