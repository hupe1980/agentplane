//! A durable manifest registry on redb.
//!
//! [`MemoryRegistry`](crate::manifest::MemoryRegistry) proves the immutability,
//! pinning and publisher rules and is the right thing for a test; an inventory
//! that disappears with its process answers *which agents does this
//! organisation run* for nobody, and a second registry kept beside it drifts.
//! This is the same registry with its state on disk — not a network service
//! (a remote registry is still a [`Registry`] somebody writes), but two planes
//! opening one file see one inventory.
//!
//! # One transaction per publish, and why that is the whole point
//!
//! Immutability is a claim about a race as much as about a rule. Reading the
//! stored digest, comparing it, then writing leaves a window in which two
//! publishes of *different* content both see "nothing there" and both insert —
//! and the second silently wins, which is exactly the outcome the rule exists
//! to prevent. redb has a single writer, so the read, the decision and the
//! write below are one write transaction and the race is unspellable. It is
//! the same reason exactly-once is a unique index rather than a `SELECT`
//! before an `INSERT`.
//!
//! The *decision* is
//! [`decide_publish`](crate::manifest::registry::decide_publish), shared with
//! every other backend: three hand-written copies of "may this replace what is
//! there" are three chances to get it subtly different, and the one that is
//! wrong is whichever nobody tested.
//!
//! # Tenant-scoped, like every other table here
//!
//! A manifest is published by an organisation, and the rest of this store is
//! keyed by tenant. A registry that was not would let one tenant's publish
//! collide with another's over a name they both happened to choose — and
//! `metadata.name` is whatever an author typed, so the collision is ordinary
//! rather than exotic.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::core::{Attestation, Digest, KeyId, Signer, StoreError, Verifier};
use crate::manifest::registry::{
    PublishVerdict, attest_manifest, check_attestation, decide_publish, reparse, to_yaml,
};
use crate::manifest::{Manifest, Registry, RegistryError};

use super::redb::{MAX_STR, RedbStore, be, begin_write};

/// `(tenant, name, version) -> (digest hex, manifest YAML, key id, signature hex)`.
///
/// The attestation is two columns rather than one serialized struct because the
/// halves are read separately: the key id answers *who published this* for an
/// operator, and the signature is only ever handed to a verifier.
///
/// An **empty key id** is the absence. That is not a sentinel overlapping a
/// real value the way `revoked_at == 0` was in the authority table: a signature
/// cannot exist without a key id, so there is nothing an empty one could be
/// confused with. Unsigned is an operational fact about a publish that happened
/// before anybody signed — not a defect, and `resolve_verified` says which of
/// the two it is.
type RegistryRow<'a> = (&'a str, &'a str, &'a str, &'a str);
const MANIFESTS: TableDefinition<(&str, &str, &str), RegistryRow<'static>> =
    TableDefinition::new("registry_manifests");

/// The stored attestation, if the row carries one.
fn stored_attestation(key_id: &str, signature: &str) -> Option<Attestation> {
    if key_id.is_empty() {
        return None;
    }
    Some(Attestation {
        key_id: key_id.to_owned(),
        // A signature that does not decode cannot verify, and an empty one
        // fails exactly as a wrong one does. Reporting corruption here would
        // put a second failure mode in front of the answer the caller needs,
        // which is `BadSignature` either way.
        signature: hex::decode(signature).unwrap_or_default(),
    })
}

/// What the store found under one key.
type Stored = Option<(Digest, Option<Attestation>)>;

fn backend(e: &StoreError) -> RegistryError {
    RegistryError::Backend(e.to_string())
}

impl RedbStore {
    /// Apply one publish: read, decide and write in a single transaction.
    ///
    /// A refusal travels back as a **value** rather than as a `StoreError`.
    /// Packing "this version already holds different content" into a backend
    /// error string would mean the caller decides behaviour by matching on
    /// prose, and the first person to reword it turns every refusal into an
    /// outage — the same reasoning the quota store's ceiling refusal follows.
    async fn publish_row(
        &self,
        manifest: &Manifest,
        attestation: Option<Attestation>,
    ) -> Result<Digest, RegistryError> {
        let tenant = self.tenant_name();
        let name = manifest.metadata.name.clone();
        let version = manifest.metadata.version.clone();
        let digest = manifest.digest().map_err(|source| RegistryError::Corrupt {
            name: name.clone(),
            version: version.clone(),
            source,
        })?;
        let yaml = to_yaml(manifest)?;
        let signed = attestation
            .as_ref()
            .map_or((String::new(), String::new()), |a| {
                (a.key_id.clone(), hex::encode(&a.signature))
            });

        let outcome: Result<(), RegistryError> = self
            .with_db(move |db| {
                let w = begin_write(db)?;
                let key = (tenant.as_str(), name.as_str(), version.as_str());
                let decided = {
                    let mut table = w.open_table(MANIFESTS).map_err(|e| be(&e))?;
                    let stored: Stored = match table.get(key).map_err(|e| be(&e))? {
                        Some(row) => {
                            let (hex, _, key_id, signature) = row.value();
                            let digest =
                                Digest::from_hex(hex).map_err(|_| StoreError::Corrupt {
                                    seq: 0,
                                    detail: format!(
                                        "registry row '{name}' '{version}' holds '{hex}', \
                                         which is not a digest"
                                    ),
                                })?;
                            Some((digest, stored_attestation(key_id, signature)))
                        }
                        None => None,
                    };
                    let verdict = decide_publish(
                        &name,
                        &version,
                        digest,
                        attestation.as_ref(),
                        stored.as_ref().map(|(d, a)| (*d, a.as_ref())),
                    );
                    match verdict {
                        // One `insert` covers both writes: in the adopt case the
                        // content is identical by construction — that is what
                        // `decide_publish` established — so rewriting the row is
                        // rewriting it with itself plus a signature.
                        Ok(PublishVerdict::Insert | PublishVerdict::AdoptAttestation) => {
                            table
                                .insert(
                                    key,
                                    (
                                        digest.to_hex().as_str(),
                                        yaml.as_str(),
                                        signed.0.as_str(),
                                        signed.1.as_str(),
                                    ),
                                )
                                .map_err(|e| be(&e))?;
                            Ok(())
                        }
                        Ok(PublishVerdict::Unchanged) => Ok(()),
                        Err(refusal) => Err(refusal),
                    }
                };
                // Committed either way, so a refusal leaves no transaction
                // open. A refused publish wrote nothing, so committing it
                // commits nothing.
                w.commit().map_err(|e| be(&e))?;
                Ok(decided)
            })
            .await
            .map_err(|e| backend(&e))?;
        outcome.map(|()| digest)
    }

    /// One row, or [`RegistryError::NotFound`].
    async fn row(
        &self,
        name: &str,
        version: &str,
    ) -> Result<(String, Option<Attestation>), RegistryError> {
        let tenant = self.tenant_name();
        let (name, version) = (name.to_owned(), version.to_owned());
        let (asked_name, asked_version) = (name.clone(), version.clone());
        let found = self
            .with_db(move |db| {
                let r = db.begin_read().map_err(|e| be(&e))?;
                // An absent table is an empty registry, not an error: nothing
                // has ever been published, so there is nothing to read.
                let Ok(table) = r.open_table(MANIFESTS) else {
                    return Ok(None);
                };
                let Some(row) = table
                    .get((tenant.as_str(), name.as_str(), version.as_str()))
                    .map_err(|e| be(&e))?
                else {
                    return Ok(None);
                };
                let (_, yaml, key_id, signature) = row.value();
                Ok(Some((
                    yaml.to_owned(),
                    stored_attestation(key_id, signature),
                )))
            })
            .await
            .map_err(|e| backend(&e))?;
        found.ok_or(RegistryError::NotFound {
            name: asked_name,
            version: asked_version,
        })
    }
}

#[async_trait]
impl Registry for RedbStore {
    async fn publish(&self, manifest: &Manifest) -> Result<Digest, RegistryError> {
        self.publish_row(manifest, None).await
    }

    async fn publish_signed(
        &self,
        manifest: &Manifest,
        signer: &dyn Signer,
    ) -> Result<Digest, RegistryError> {
        let (_, attestation) = attest_manifest(manifest, signer)?;
        self.publish_row(manifest, Some(attestation)).await
    }

    async fn resolve(&self, name: &str, version: &str) -> Result<Manifest, RegistryError> {
        let (yaml, _) = self.row(name, version).await?;
        reparse(name, version, &yaml)
    }

    async fn resolve_verified(
        &self,
        name: &str,
        version: &str,
        verifier: &dyn Verifier,
    ) -> Result<(Manifest, KeyId), RegistryError> {
        let (yaml, attestation) = self.row(name, version).await?;
        let manifest = reparse(name, version, &yaml)?;
        let key = check_attestation(name, version, &manifest, attestation.as_ref(), verifier)?;
        Ok((manifest, key))
    }

    async fn versions(&self, name: &str) -> Result<Vec<String>, RegistryError> {
        let tenant = self.tenant_name();
        let name = name.to_owned();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(table) = r.open_table(MANIFESTS) else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for entry in table
                .range(
                    (tenant.as_str(), name.as_str(), "")
                        ..=(tenant.as_str(), name.as_str(), MAX_STR),
                )
                .map_err(|e| be(&e))?
            {
                let (key, _) = entry.map_err(|e| be(&e))?;
                out.push(key.value().2.to_owned());
            }
            Ok(out)
        })
        .await
        .map_err(|e| backend(&e))
    }

    async fn names(&self) -> Result<Vec<String>, RegistryError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(table) = r.open_table(MANIFESTS) else {
                return Ok(Vec::new());
            };
            let mut out: Vec<String> = Vec::new();
            for entry in table
                .range((tenant.as_str(), "", "")..=(tenant.as_str(), MAX_STR, MAX_STR))
                .map_err(|e| be(&e))?
            {
                let (key, _) = entry.map_err(|e| be(&e))?;
                let name = key.value().1.to_owned();
                // The range is already in key order, so every version of one
                // name is a contiguous run and comparing with the last is
                // enough to collapse it.
                if out.last() != Some(&name) {
                    out.push(name);
                }
            }
            Ok(out)
        })
        .await
        .map_err(|e| backend(&e))
    }
}
