//! Authorization engines.
//!
//! The seam itself is `core::policy`; this module holds the adapters, each
//! behind its own feature. The crate ships none by default — see
//! `core::policy` on why a permissive engine and no engine must not be two
//! different things.

#[cfg(feature = "cedar")]
mod cedar;

#[cfg(feature = "cedar")]
pub use cedar::{CONTEXT_NULLS_STRIPPED, CedarEngine, CedarError};

#[cfg(feature = "signing")]
mod signing;

#[cfg(feature = "signing")]
pub use signing::{Ed25519Signer, Ed25519Verifier};
