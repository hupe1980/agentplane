//! Authorization engines, the requests the runtime asks them, and the offline
//! re-derivation of those requests from an export.
//!
//! The seam itself is `core::policy`; this module holds the adapters, each
//! behind its own feature. The crate ships none by default — see
//! `core::policy` on why a permissive engine and no engine must not be two
//! different things. [`requests`] and [`check`] are engine-agnostic and
//! unconditional.

pub mod check;
pub mod requests;

#[cfg(feature = "cedar")]
mod cedar;

#[cfg(feature = "cedar")]
pub use cedar::{
    CEDAR_LANGUAGE, CONTEXT_NULLS_STRIPPED, CedarEngine, CedarError, evaluator_semantics,
};

#[cfg(feature = "signing")]
mod signing;

#[cfg(feature = "signing")]
pub use signing::{Ed25519Signer, Ed25519Verifier};
