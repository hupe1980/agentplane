//! The isolation unit a deployment shares nothing across.
//!
//! Multi-tenancy is an end-to-end property, not a column added to runs. Every
//! key, index, lease, correlation, blob path and authorization request needs
//! defined tenant semantics, or isolation holds everywhere except the one place
//! nobody checked — which is where it will be found.
//!
//! This type is the *name*. What it buys depends on what consults it, and this
//! crate is explicit about that rather than implying more: see the status page
//! for exactly which surfaces are tenant-scoped today and which are not.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Which tenant a run, key, or decision belongs to.
///
/// Deliberately a validated newtype rather than a bare `String`. A tenant name
/// reaches storage keys and key-ring scopes, so a name containing a separator
/// could make two different tenants produce one scope — the failure that looks
/// like nothing at all until one of them erases the other's data.
///
/// # Deserialization is a constructor, and it takes the same door
///
/// `#[serde(try_from)]` rather than a derived `Deserialize`, because a derive
/// would reach the private field directly and hand out exactly the names
/// [`new`](Self::new) exists to refuse. That is not a hypothetical door: a
/// tenant arrives from a credential claim an [`Authenticator`] parsed, a store
/// row, or a journal record, and every one of those is `serde` rather than a
/// call to `new`. A `TenantId` holding `acme/prod` makes
/// [`keyring::scope`](crate::keyring::scope) derive one key scope for two
/// distinct tenants, so either tenant's erasure destroys the other's key and
/// reports success.
///
/// A stored name that no longer parses is therefore a **read error**, which is
/// the honest outcome: silently accepting it is what lets the collision exist.
///
/// [`Authenticator`]: crate::api::Authenticator
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct TenantId(String);

impl TryFrom<String> for TenantId {
    type Error = TenantError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

/// Why a tenant name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TenantError {
    /// Nothing, or only whitespace. A tenant that cannot be named cannot be
    /// isolated from, and an empty name silently collides with every other
    /// deployment that also forgot to set one.
    #[error("a tenant id must not be empty")]
    Empty,

    /// A character that would change how a composite key parses.
    ///
    /// `/` and `:` separate scopes and identifiers elsewhere in this crate, so
    /// `acme/prod` as a tenant name is `acme` plus a path segment to anything
    /// that splits on it — and the two tenants that result are indistinguishable
    /// afterwards.
    #[error(
        "a tenant id may not contain '{0}': it becomes part of composite keys and key-ring \
         scopes, where a separator makes two distinct tenants collide into one"
    )]
    Separator(char),

    /// Long enough to be a mistake rather than a name.
    #[error("a tenant id is limited to {max} characters, and this one is {len}")]
    TooLong { len: usize, max: usize },
}

impl TenantId {
    /// The longest a tenant name may be.
    ///
    /// Bounded because the name reaches metric labels and storage keys. An
    /// unbounded label is an unbounded cardinality problem, which is how a
    /// metrics backend falls over for a reason nobody connects to a tenant name.
    pub const MAX_LEN: usize = 64;

    /// The tenant a deployment that never named one is running as.
    ///
    /// Single-tenant is the ordinary case and must not require ceremony. It is
    /// a *real* tenant rather than an absence, so the single- and multi-tenant
    /// paths are the same code — a special "no tenant" case is a second path,
    /// and the second path is the one that does not get tested.
    pub const DEFAULT: &'static str = "default";

    /// Name a tenant.
    ///
    /// # Errors
    ///
    /// If the name is empty, over [`MAX_LEN`](Self::MAX_LEN), or contains a
    /// character that composite keys use as a separator.
    pub fn new(name: impl Into<String>) -> Result<Self, TenantError> {
        let name = name.into();
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(TenantError::Empty);
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(TenantError::TooLong {
                len: trimmed.len(),
                max: Self::MAX_LEN,
            });
        }
        // Refused rather than escaped. Escaping means every reader has to
        // unescape identically, and the one that does not is the collision.
        if let Some(bad) = trimmed
            .chars()
            .find(|c| matches!(c, '/' | ':' | '\0' | '\n') || c.is_control())
        {
            return Err(TenantError::Separator(bad));
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The name, for building a composite key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self(Self::DEFAULT.to_owned())
    }
}

/// The name of one erasure unit: a case, a run, a memory subject, a named
/// retention policy — always under its tenant.
///
/// One implementation, consumed by the key ring (as the scope a data key is
/// wrapped under) and by the blob layer (as the unit that leads a storage
/// address), because the two must agree byte for byte: the whole guarantee is
/// that destroying a scope's key and expiring a scope's blobs reach exactly
/// the same unit, and two spellings of the joiner would make them reach two.
///
/// The `/` cannot be forged into a tenant name — [`TenantId`] refuses it — so
/// `acme` + `prod/case-1` and a tenant named `acme/prod` cannot collide.
#[must_use]
pub fn erasure_scope(tenant: &TenantId, unit: &str) -> String {
    format!("{tenant}/{unit}")
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
