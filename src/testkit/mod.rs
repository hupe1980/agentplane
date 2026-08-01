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
#[cfg(feature = "sqlite")]
pub mod conformance_case;
mod fake_model;
pub mod faults;
mod stub_signer;
pub use stub_signer::StubSigner;

pub use backstop::assert_replay_was_not_backstopped;
pub use conformance::{Report, Violation, check as check_journal_store};
pub use fake_model::{Ask, FakeProvider};
pub use faults::{Fault, Faulty, Schedule};
