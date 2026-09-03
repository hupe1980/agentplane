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
    /// [`DOMAIN_MANIFEST`], not over the bare
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

    /// Every name this registry holds, sorted.
    ///
    /// *Which agents does this organisation run?* is the question a governance
    /// function asks first, and `versions` cannot answer it — it needs the name
    /// you were already going to ask about. An inventory nobody can enumerate
    /// is one that gets maintained somewhere else, and then the two drift.
    ///
    /// Sorted, unlike `versions`, and the difference is not an inconsistency: a
    /// name is an ordinary string with an obvious ordering, where a version is
    /// free-form and this crate has no opinion about whether `1.10` follows
    /// `1.9`.
    ///
    /// # Errors
    ///
    /// If the backing store cannot be read.
    async fn names(&self) -> Result<Vec<String>, RegistryError>;
}

/// What a publish must do to whatever is already stored.
///
/// # Why this is a value rather than three implementations
///
/// The rule — *the same content is the same publish, a different content is a
/// refusal, and an unsigned artifact may adopt its first attestation but never
/// change publisher* — is the whole security argument for having a registry.
/// Every backend has to apply it inside its own read-modify-write, and three
/// hand-written copies would be three chances to get "may this replace what is
/// there" subtly different. The one that is wrong is whichever nobody tested,
/// and the signed path is exactly where a weaker rule would matter most.
///
/// So the decision is computed once, here, and each backend only *performs* it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishVerdict {
    /// Nothing is stored under this name and version. Write the row.
    Insert,
    /// The same content is stored, and this publish carries the first
    /// attestation for it. Record the attestation, leave the content.
    AdoptAttestation,
    /// The same content, and nothing to change. A retried deploy.
    Unchanged,
}

/// Apply the immutability and publisher rules to one publish.
///
/// `stored` is what the backend found under `(name, version)`, if anything.
///
/// # Errors
///
/// [`RegistryError::Immutable`] when the version holds different content, and
/// [`RegistryError::PublisherChanged`] when identical content is already
/// attributed to a different signer.
pub fn decide_publish(
    name: &str,
    version: &str,
    offered: Digest,
    offered_attestation: Option<&Attestation>,
    stored: Option<(Digest, Option<&Attestation>)>,
) -> Result<PublishVerdict, RegistryError> {
    let Some((existing, recorded)) = stored else {
        return Ok(PublishVerdict::Insert);
    };
    if existing != offered {
        // The refusal that makes a version number mean something. Publishing
        // identical content again succeeds, because a retried deploy is not an
        // attack and making it look like one trains people to force.
        return Err(RegistryError::Immutable {
            name: name.to_owned(),
            version: version.to_owned(),
            existing: existing.to_hex(),
            offered: offered.to_hex(),
        });
    }
    match (recorded, offered_attestation) {
        (None, Some(_)) => Ok(PublishVerdict::AdoptAttestation),
        (Some(recorded), Some(offered)) if recorded.key_id != offered.key_id => {
            Err(RegistryError::PublisherChanged {
                name: name.to_owned(),
                version: version.to_owned(),
                existing: recorded.key_id.clone(),
                offered: offered.key_id.clone(),
            })
        }
        _ => Ok(PublishVerdict::Unchanged),
    }
}

/// The signature a publisher makes over a manifest.
///
/// Domain-separated with [`DOMAIN_MANIFEST`], so this signature cannot be
/// replayed as a record attestation and a record attestation cannot be replayed
/// as approval of a manifest. Shared by every backend for the same reason
/// [`decide_publish`] is: one spelling of what is signed, or two backends
/// produce attestations that do not verify against each other.
///
/// # Errors
///
/// If the manifest cannot be digested.
pub fn attest_manifest(
    manifest: &Manifest,
    signer: &dyn Signer,
) -> Result<(Digest, Attestation), RegistryError> {
    let digest = manifest.digest().map_err(|e| RegistryError::Corrupt {
        name: manifest.metadata.name.clone(),
        version: manifest.metadata.version.clone(),
        source: e,
    })?;
    Ok((
        digest,
        signer.attest(&signing_hash(DOMAIN_MANIFEST, &digest)),
    ))
}

/// Check a resolved manifest against the attestation a registry stored for it.
///
/// The digest is **recomputed from the manifest that was just re-parsed**,
/// never read back from the row. Verifying a stored digest against a stored
/// signature would confirm only that the registry is consistent with itself,
/// which is precisely the assurance a caller worried about the registry does
/// not want.
///
/// # Errors
///
/// [`RegistryError::Unsigned`] when nothing signed it, and
/// [`RegistryError::BadSignature`] when the signature is not one that key made.
pub fn check_attestation(
    name: &str,
    version: &str,
    manifest: &Manifest,
    attestation: Option<&Attestation>,
    verifier: &dyn Verifier,
) -> Result<KeyId, RegistryError> {
    let Some(a) = attestation else {
        return Err(RegistryError::Unsigned {
            name: name.to_owned(),
            version: version.to_owned(),
        });
    };
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
        Ok(a.key_id.clone())
    } else {
        Err(RegistryError::BadSignature {
            name: name.to_owned(),
            version: version.to_owned(),
            key_id: a.key_id.clone(),
        })
    }
}

/// Re-parse stored YAML, so a registry cannot serve what this crate refuses.
///
/// A registry that only validates on write enforces the rules of whatever
/// version happened to publish, which is the version nobody is running any
/// more.
///
/// # Errors
///
/// [`RegistryError::Corrupt`] when the stored bytes are not a manifest this
/// crate accepts.
pub fn reparse(name: &str, version: &str, yaml: &str) -> Result<Manifest, RegistryError> {
    Manifest::parse(yaml).map_err(|source| RegistryError::Corrupt {
        name: name.to_owned(),
        version: version.to_owned(),
        source,
    })
}

/// The canonical stored form of a manifest.
///
/// # Errors
///
/// If the manifest cannot be serialized.
pub fn to_yaml(manifest: &Manifest) -> Result<String, RegistryError> {
    serde_yaml_ng::to_string(manifest).map_err(|e| RegistryError::Backend(e.to_string()))
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

    /// Apply one publish under the map lock.
    ///
    /// The *decision* is [`decide_publish`]'s, shared with every durable
    /// backend; what is here is only the performing of it.
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
        let yaml = to_yaml(manifest)?;

        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RegistryError::Backend("registry mutex poisoned".into()))?;
        let key = (name.clone(), version.clone());
        let stored = entries
            .get(&key)
            .map(|e| (e.digest, e.attestation.as_ref()));
        match decide_publish(&name, &version, digest, attestation.as_ref(), stored)? {
            PublishVerdict::Insert => {
                entries.insert(
                    key,
                    Entry {
                        digest,
                        yaml,
                        attestation,
                    },
                );
            }
            PublishVerdict::AdoptAttestation => {
                if let Some(entry) = entries.get_mut(&key) {
                    entry.attestation = attestation;
                }
            }
            PublishVerdict::Unchanged => {}
        }
        Ok(digest)
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
        let (_, attestation) = attest_manifest(manifest, signer)?;
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
        let key = check_attestation(name, version, &manifest, attestation.as_ref(), verifier)?;
        Ok((manifest, key))
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
        reparse(name, version, &yaml)
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

    async fn names(&self) -> Result<Vec<String>, RegistryError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| RegistryError::Backend("registry mutex poisoned".into()))?;
        let mut names: Vec<String> = entries.keys().map(|(n, _)| n.clone()).collect();
        names.dedup();
        Ok(names)
    }
}
