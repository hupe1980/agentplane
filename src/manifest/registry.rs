//! Where a manifest is found by name, and why that is a security decision.
//!
//! A manifest makes a grant reviewable. A registry is what makes the reviewed
//! version the one that *runs* — and it is exactly where the ecosystem has been
//! attacked. The npm and `PyPI` incidents were not parser bugs; they were a name
//! resolving to content nobody reviewed. So this registry is built around two
//! refusals rather than around lookup:
//!
//! * **A published version is immutable.** Re-publishing `agent:1.2.0` with
//!   different content is refused, not overwritten. Go's module proxy and
//!   crates.io both learned this the hard way: if a version can change, then
//!   "we reviewed 1.2.0" is a statement about a moment, not about an artifact.
//!   Publishing *identical* content again succeeds, because a retried deploy is
//!   not an attack and making it look like one trains people to force.
//! * **A resolve can be pinned.** [`Registry::resolve_pinned`] takes the digest
//!   the caller expects and refuses anything else. Immutability is a promise the
//!   registry makes about itself; a pin is the caller declining to need it —
//!   which is the only form that survives the registry being the compromised
//!   party.
//!
//! The two are deliberately not redundant. Immutability catches the honest
//! mistake at write time and names who to talk to; the pin catches the
//! dishonest one at read time and does not have to trust the writer.
//!
//! Publisher evidence follows the same no-rewrite rule. An identical unsigned
//! artifact may later adopt its first attestation, but an existing publisher
//! cannot be silently replaced by another identity. Supporting several
//! publishers would require an explicit attestation set rather than mutable
//! metadata.
//!
//! What this is *not* is a network service or key-management system. Resolution
//! is a trait so a remote registry, a signed index, or a file tree can implement
//! it; [`MemoryRegistry`] proves the logic for tests and single-process use.
//! Signing and verification use [`crate::core::Signer`] and
//! [`crate::core::Verifier`]; this crate never mints or decides to trust a key.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::core::{Attestation, DOMAIN_MANIFEST, Digest, KeyId, Signer, Verifier, signing_hash};

use super::{Manifest, ManifestError};

/// Why a registry would not answer, or would not accept.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// No such name at that version.
    #[error("no manifest '{name}' at version '{version}'")]
    NotFound { name: String, version: String },

    /// That version already exists with different content.
    ///
    /// The refusal that makes a version number mean something. Reported with
    /// both digests so the answer to "what changed" does not require guessing
    /// which copy is which.
    #[error(
        "manifest '{name}' version '{version}' is already published as {existing} \
         and cannot be replaced by {offered} — publish a new version"
    )]
    Immutable {
        name: String,
        version: String,
        existing: String,
        offered: String,
    },

    /// The resolved manifest is not the one the caller pinned.
    ///
    /// Distinct from [`Immutable`](Self::Immutable) because the two accuse
    /// different parties: `Immutable` says a publisher tried to change history,
    /// `PinBroken` says the registry served content that does not match what the
    /// caller reviewed — which includes the case where the registry itself is
    /// the problem.
    #[error(
        "manifest '{name}' version '{version}' resolved to {actual}, not the \
         pinned {expected} — the registry served content this caller did not review"
    )]
    PinBroken {
        name: String,
        version: String,
        expected: String,
        actual: String,
    },

    /// The stored bytes are not a manifest this crate accepts.
    #[error("stored manifest '{name}' at '{version}' is unusable: {source}")]
    Corrupt {
        name: String,
        version: String,
        #[source]
        source: ManifestError,
    },

    /// The manifest carries no signature and one was required.
    ///
    /// Distinct from a bad signature for the same reason a record's is: the two
    /// call for opposite responses. A missing signature usually means this was
    /// published before signing was configured — an operational fact. A bad one
    /// means somebody tampered, or a key rotated wrongly.
    #[error(
        "manifest '{name}' version '{version}' is unsigned, and this resolve required a signature"
    )]
    Unsigned { name: String, version: String },

    /// The signature is not one that key made.
    #[error(
        "manifest '{name}' version '{version}' carries a signature that '{key_id}' did not \
         make — the content is intact, so it was republished by somebody who could compute \
         a digest but not sign it"
    )]
    BadSignature {
        name: String,
        version: String,
        key_id: String,
    },

    /// Identical content is already attributed to another publisher.
    ///
    /// Artifact bytes are immutable, and publisher identity is evidence about
    /// those bytes rather than replaceable metadata. Supporting several
    /// publishers would require an explicit attestation set; silently replacing
    /// the one stored identity would rewrite who approved an artifact.
    #[error(
        "manifest '{name}' version '{version}' is already attributed to '{existing}', not \
         '{offered}' — publisher evidence is immutable; publish a new version"
    )]
    PublisherChanged {
        name: String,
        version: String,
        existing: String,
        offered: String,
    },

    /// The backing store failed.
    #[error("registry storage: {0}")]
    Backend(String),
}

/// A place manifests are published to and resolved from.
#[async_trait]
pub trait Registry: Send + Sync + Debug {
    /// Publish a manifest under its own name and version.
    ///
    /// Returns the digest it is addressable by. Publishing the same content
    /// twice is the same publish.
    ///
    /// # Errors
    ///
    /// [`RegistryError::Immutable`] if that version already holds different
    /// content.
    async fn publish(&self, manifest: &Manifest) -> Result<Digest, RegistryError>;

    /// Publish, and record who says so.
    ///
    /// The half a digest cannot supply. Immutability and pinning both answer
    /// *what* was published; neither answers *who*, and "the registry accepted
    /// it" is not an answer when the registry is the thing you are worried
    /// about.
    ///
    /// Signed over [`crate::core::signing_hash`] with
    /// [`DOMAIN_MANIFEST`](crate::core::DOMAIN_MANIFEST), not over the bare
    /// digest — so a manifest signature can never be presented as a record
    /// attestation, and a record attestation can never be presented as an
    /// approval of a manifest.
    ///
    /// # Errors
    ///
    /// Everything [`publish`](Self::publish) can return, plus
    /// [`RegistryError::PublisherChanged`] if this version is already attributed
    /// to a different signer.
    async fn publish_signed(
        &self,
        manifest: &Manifest,
        signer: &dyn Signer,
    ) -> Result<Digest, RegistryError>;

    /// Resolve, and refuse anything this verifier will not vouch for.
    ///
    /// Returns the manifest and the key that signed it, because "it verified"
    /// is not the whole answer — *which* identity signed it is what a caller
    /// decides to trust, and this crate never makes that decision for them.
    ///
    /// # Errors
    ///
    /// [`RegistryError::Unsigned`] if nothing signed it,
    /// [`RegistryError::BadSignature`] if the signature does not check out, plus
    /// everything [`resolve`](Self::resolve) can return.
    async fn resolve_verified(
        &self,
        name: &str,
        version: &str,
        verifier: &dyn Verifier,
    ) -> Result<(Manifest, KeyId), RegistryError>;

    /// Resolve a name and version to whatever the registry currently holds.
    ///
    /// Trusts the registry. Prefer [`Registry::resolve_pinned`] anywhere the
    /// answer decides what an agent is allowed to do.
    ///
    /// # Errors
    ///
    /// [`RegistryError::NotFound`] if nothing is published there.
    async fn resolve(&self, name: &str, version: &str) -> Result<Manifest, RegistryError>;

    /// Resolve, and refuse anything but the digest the caller expects.
    ///
    /// # Errors
    ///
    /// [`RegistryError::PinBroken`] if the content differs from `expected`, plus
    /// everything [`Registry::resolve`] can return.
    async fn resolve_pinned(
        &self,
        name: &str,
        version: &str,
        expected: Digest,
    ) -> Result<Manifest, RegistryError> {
        let m = self.resolve(name, version).await?;
        let actual = m.digest().map_err(|e| RegistryError::Corrupt {
            name: name.to_owned(),
            version: version.to_owned(),
            source: e,
        })?;
        if actual == expected {
            Ok(m)
        } else {
            Err(RegistryError::PinBroken {
                name: name.to_owned(),
                version: version.to_owned(),
                expected: expected.to_hex(),
                actual: actual.to_hex(),
            })
        }
    }

    /// Every published version of a name, in the registry's order.
    ///
    /// Not sorted by the crate: [`super::Metadata::version`] is free-form, and a
    /// registry that imposed an ordering it does not understand would answer
    /// "which is latest" wrongly and confidently.
    ///
    /// # Errors
    ///
    /// If the backing store cannot be read.
    async fn versions(&self, name: &str) -> Result<Vec<String>, RegistryError>;
}

/// A registry that lives in this process.
///
/// For tests and single-process deployments. Named to make the volatility
/// obvious at the call site, the same way [`crate::journal::MemoryWitness`] is.
/// One published version.
#[derive(Debug, Clone)]
struct Entry {
    digest: Digest,
    yaml: String,
    /// `None` when it was published before anybody signed. An operational fact,
    /// not a defect — and `resolve_verified` says so precisely.
    attestation: Option<Attestation>,
}

#[derive(Debug, Default)]
pub struct MemoryRegistry {
    entries: Mutex<BTreeMap<(String, String), Entry>>,
}

impl MemoryRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The immutability rule, shared by the signed and unsigned paths.
    ///
    /// One implementation on purpose: two would be two chances to get "may this
    /// replace what is there" subtly different, and the signed path is exactly
    /// where a weaker rule would matter most.
    fn insert(
        &self,
        manifest: &Manifest,
        attestation: Option<Attestation>,
    ) -> Result<Digest, RegistryError> {
        let (name, version) = (
            manifest.metadata.name.clone(),
            manifest.metadata.version.clone(),
        );
        let digest = manifest.digest().map_err(|e| RegistryError::Corrupt {
            name: name.clone(),
            version: version.clone(),
            source: e,
        })?;
        let yaml = serde_yaml_ng::to_string(manifest)
            .map_err(|e| RegistryError::Backend(e.to_string()))?;

        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RegistryError::Backend("registry mutex poisoned".into()))?;
        match entries.get_mut(&(name.clone(), version.clone())) {
            // Same content is the same publish — a retried deploy must not look
            // like an attack. Signing may be adopted later without deleting an
            // immutable artifact, but an existing publisher may not be silently
            // replaced by another identity.
            Some(existing) if existing.digest == digest => {
                match (&existing.attestation, attestation) {
                    (None, Some(signed)) => existing.attestation = Some(signed),
                    (Some(recorded), Some(offered)) if recorded.key_id != offered.key_id => {
                        return Err(RegistryError::PublisherChanged {
                            name,
                            version,
                            existing: recorded.key_id.clone(),
                            offered: offered.key_id,
                        });
                    }
                    _ => {}
                }
                Ok(digest)
            }
            Some(existing) => Err(RegistryError::Immutable {
                name,
                version,
                existing: existing.digest.to_hex(),
                offered: digest.to_hex(),
            }),
            None => {
                entries.insert(
                    (name, version),
                    Entry {
                        digest,
                        yaml,
                        attestation,
                    },
                );
                Ok(digest)
            }
        }
    }
}

#[async_trait]
impl Registry for MemoryRegistry {
    async fn publish(&self, manifest: &Manifest) -> Result<Digest, RegistryError> {
        self.insert(manifest, None)
    }

    async fn publish_signed(
        &self,
        manifest: &Manifest,
        signer: &dyn Signer,
    ) -> Result<Digest, RegistryError> {
        let digest = manifest.digest().map_err(|e| RegistryError::Corrupt {
            name: manifest.metadata.name.clone(),
            version: manifest.metadata.version.clone(),
            source: e,
        })?;
        // Domain-separated, so this signature cannot be replayed as a record
        // attestation and a record attestation cannot be replayed as approval
        // of a manifest.
        let attestation = signer.attest(&signing_hash(DOMAIN_MANIFEST, &digest));
        self.insert(manifest, Some(attestation))
    }

    async fn resolve_verified(
        &self,
        name: &str,
        version: &str,
        verifier: &dyn Verifier,
    ) -> Result<(Manifest, KeyId), RegistryError> {
        let manifest = self.resolve(name, version).await?;
        let attestation = {
            let entries = self
                .entries
                .lock()
                .map_err(|_| RegistryError::Backend("registry mutex poisoned".into()))?;
            entries
                .get(&(name.to_owned(), version.to_owned()))
                .and_then(|e| e.attestation.clone())
        };
        let Some(a) = attestation else {
            return Err(RegistryError::Unsigned {
                name: name.to_owned(),
                version: version.to_owned(),
            });
        };

        // Recomputed from the manifest that was just re-parsed, never read back
        // from the row. Verifying a stored digest against a stored signature
        // would confirm only that the registry is consistent with itself.
        let digest = manifest.digest().map_err(|e| RegistryError::Corrupt {
            name: name.to_owned(),
            version: version.to_owned(),
            source: e,
        })?;
        if verifier.verify(
            &a.key_id,
            &signing_hash(DOMAIN_MANIFEST, &digest),
            &a.signature,
        ) {
            Ok((manifest, a.key_id))
        } else {
            Err(RegistryError::BadSignature {
                name: name.to_owned(),
                version: version.to_owned(),
                key_id: a.key_id.clone(),
            })
        }
    }

    async fn resolve(&self, name: &str, version: &str) -> Result<Manifest, RegistryError> {
        let yaml = {
            let entries = self
                .entries
                .lock()
                .map_err(|_| RegistryError::Backend("registry mutex poisoned".into()))?;
            entries
                .get(&(name.to_owned(), version.to_owned()))
                .map(|e| e.yaml.clone())
                .ok_or_else(|| RegistryError::NotFound {
                    name: name.to_owned(),
                    version: version.to_owned(),
                })?
        };
        // Re-parsed rather than handed back from a cache, so a stored manifest
        // that this version of the crate would refuse is refused on the way out
        // too. A registry that only validates on write enforces the rules of
        // whatever version happened to publish.
        Manifest::parse(&yaml).map_err(|e| RegistryError::Corrupt {
            name: name.to_owned(),
            version: version.to_owned(),
            source: e,
        })
    }

    async fn versions(&self, name: &str) -> Result<Vec<String>, RegistryError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| RegistryError::Backend("registry mutex poisoned".into()))?;
        Ok(entries
            .range((name.to_owned(), String::new())..)
            .take_while(|((n, _), _)| n == name)
            .map(|((_, v), _)| v.clone())
            .collect())
    }
}
