//! Test facilities for embedders, and for this crate's own assurance layers.
//!
//! Shipped rather than confined to `tests/` because an embedder's own store
//! implementation and own skills need the same treatment this crate's do, and
//! rebuilding a fault injector per project is how each one ends up testing a
//! slightly different, slightly weaker thing.
//!
//! Behind the `testkit` feature, off by default, and **no feature a release
//! enables pulls it in** — `no_shipped_feature_enables_testkit` in
//! `tests/guards/docs.rs` is what makes that a fact rather than an intention.
//!
//! The deterministic *model* is deliberately not here but in
//! [`model::fake`](crate::model::fake), behind `fake-model`, which ships: a
//! stand-in model is a driver, while everything in this module stands in for a
//! control.

pub mod backstop;
pub mod conformance;
// Ungated: `BlobStore` is in `core`'s own layer, every implementation of it
// ships in the default build, and the contract this checks is the one an
// erasure request lands on.
pub mod conformance_blob;
// Ungated for the reason the blob battery is: `Calendar` is a `core` seam, and
// it is the one this crate is most likely to be *replaced* at — the built-in
// calendar understands hours, days and minutes, and a real regulatory deadline
// does not.
pub mod conformance_calendar;
// The case-layer battery is backend-agnostic — it names no `redb` type — so the
// gate has to be "a backend exists", not "the embedded one does". Read as `redb`
// it made the *shared-store* backend's own contract untestable without linking
// the embedded one, which is the configuration a Postgres deployment ships.
// Gated on `http`, which is where `Authenticator` lives: the seam only exists
// for a deployment serving the operator surface.
#[cfg(feature = "http")]
pub mod conformance_auth;
#[cfg(any(feature = "redb", feature = "postgres"))]
pub mod conformance_case;
#[cfg(feature = "keyring")]
pub mod conformance_keyring;
// Ungated: `PolicyEngine` is a `core` seam with no feature of its own, and the
// deployment most likely to replace it is the one that wrote its rules in Rust
// rather than taking the shipped evaluator.
pub mod conformance_policy;
#[cfg(feature = "push")]
pub mod conformance_push;
pub mod conformance_quota;
#[cfg(feature = "manifest")]
pub mod conformance_registry;
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

/// The deterministic provider, which lives beside the real drivers.
///
/// Named here too, because a test author looking for a double looks in
/// `testkit`. It is *not* gated on `testkit` at its definition — see
/// [`model::fake`](crate::model::fake).
pub use crate::model::fake::{Ask, FakeProvider};
pub use backstop::assert_replay_was_not_backstopped;
pub use conformance::{Report, Violation, check as check_journal_store};
pub use faults::{Fault, Faulty, Schedule};
