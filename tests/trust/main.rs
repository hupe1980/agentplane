//! Authority, provenance, and what may cross a boundary.
//!
//! One of a handful of integration targets rather than one per file. Cargo
//! compiles and links every integration test as its own crate, so thirty-three
//! files meant thirty-three links of the same dependency graph — ~56s to
//! rebuild after touching one line of the library.
//!
//! Collapsing them into a handful of grouped targets links five times instead
//! of thirty-three: measured at **56.3s down to ~24s** to rebuild after
//! touching one line of the library, which is the cost paid on every edit.
//!
//! A *single* target was measured too, at 17.8s. It is faster here and worse
//! where it is less visible: the mutation sweep rebuilds a test binary per
//! mutant, and one binary holding every module relinks all of it ninety-six
//! times. Five groups keep both costs reasonable rather than optimising one
//! into the other.

mod attestation;
mod boundary;
mod budgets;
mod cedar;
mod identity;
#[cfg(feature = "keyring")]
mod keyring;
mod manifest;
mod peers;
mod policy;
mod witness;
