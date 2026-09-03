//! A durable manifest registry on `PostgreSQL`.
//!
//! The backend the immutability rule is actually about. On one node almost
//! anything holds it up; the moment two instances publish concurrently, only
//! the database can arbitrate — so the rule is enforced by a **unique primary
//! key plus one transaction that reads and writes**, not by a `SELECT` this
//! process makes a decision from and then hopes about.
//!
//! The decision itself is
//! [`decide_publish`](crate::manifest::registry::decide_publish), shared with
//! the embedded backend and with `MemoryRegistry`. Three hand-written copies of
//! "may this replace what is there" are three chances to get it subtly
//! different, and the one that is wrong is whichever nobody tested.
//!
//! The lock is a **transaction-scoped advisory lock on the key**, taken before
//! the read. `SELECT … FOR UPDATE` cannot do this job: it locks a row that
//! exists, and the race that matters is two publishes of different content
//! both finding *no* row — both decide to insert, and whichever lands second
//! either fails on the primary key with an error that reads like a backend
//! fault, or (under an upsert) silently wins. The advisory lock serialises on
//! the key whether or not the row is there yet, so the second publisher reads
//! the first one's row and is refused as the immutability rule intends.

use async_trait::async_trait;

use crate::core::{Attestation, Digest, KeyId, Signer, StoreError, Verifier};
use crate::manifest::registry::{
    PublishVerdict, attest_manifest, check_attestation, decide_publish, reparse, to_yaml,
};
use crate::manifest::{Manifest, Registry, RegistryError};

use super::postgres::PostgresStore;

fn be(e: &tokio_postgres::Error) -> RegistryError {
    RegistryError::Backend(e.to_string())
}

fn pool_err(e: &impl std::fmt::Display) -> RegistryError {
    RegistryError::Backend(e.to_string())
}

/// The stored attestation, if the row carries one.
///
/// An empty key id is the absence: a signature cannot exist without one, so
/// there is no sentinel here overlapping a value it might be confused with.
fn stored_attestation(key_id: &str, signature: &str) -> Option<Attestation> {
    if key_id.is_empty() {
        return None;
    }
    Some(Attestation {
        key_id: key_id.to_owned(),
        // A signature that does not decode cannot verify, and an empty one
        // fails exactly as a wrong one does — `BadSignature` either way.
        signature: hex::decode(signature).unwrap_or_default(),
    })
}

impl PostgresStore {
    /// Apply one publish: lock, decide and write in one transaction.
    async fn publish_row(
        &self,
        manifest: &Manifest,
        attestation: Option<Attestation>,
    ) -> Result<Digest, RegistryError> {
        let name = manifest.metadata.name.clone();
        let version = manifest.metadata.version.clone();
        let digest = manifest.digest().map_err(|source| RegistryError::Corrupt {
            name: name.clone(),
            version: version.clone(),
            source,
        })?;
        let yaml = to_yaml(manifest)?;
        let (key_id, signature) = attestation
            .as_ref()
            .map_or((String::new(), String::new()), |a| {
                (a.key_id.clone(), hex::encode(&a.signature))
            });

        let mut client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let tx = client.transaction().await.map_err(|e| be(&e))?;
        let tenant = self.tenant_name();

        // Serialise on the key before reading, whether or not a row exists.
        // `hashtext` of the joined key is a 32-bit lock id; a collision between
        // two unrelated keys only serialises two publishes that did not need
        // it, never admits one that should have waited.
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1 || E'\\x1f' || $2 || E'\\x1f' || $3))",
            &[&tenant, &name, &version],
        )
        .await
        .map_err(|e| be(&e))?;

        let existing = tx
            .query_opt(
                "SELECT digest, key_id, signature FROM registry_manifests
                 WHERE tenant = $1 AND name = $2 AND version = $3",
                &[&tenant, &name, &version],
            )
            .await
            .map_err(|e| be(&e))?;

        let stored = match &existing {
            Some(row) => {
                let hex: String = row.get(0);
                let stored_digest = Digest::from_hex(&hex).map_err(|_| {
                    RegistryError::Backend(format!(
                        "registry row '{name}' '{version}' holds '{hex}', which is not a digest"
                    ))
                })?;
                Some((
                    stored_digest,
                    stored_attestation(&row.get::<_, String>(1), &row.get::<_, String>(2)),
                ))
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
        // The refusal rolls back rather than committing nothing: an open
        // transaction returned to the pool is a lock held by whoever gets the
        // connection next.
        let verdict = match verdict {
            Ok(verdict) => verdict,
            Err(refusal) => {
                let _ = tx.rollback().await;
                return Err(refusal);
            }
        };

        match verdict {
            // A plain insert, never an upsert: the advisory lock makes a
            // conflict here impossible, and an `ON CONFLICT DO UPDATE` would
            // turn any future hole in that reasoning into a silent overwrite —
            // the exact outcome the primary key exists to refuse.
            PublishVerdict::Insert => {
                tx.execute(
                    "INSERT INTO registry_manifests (tenant, name, version, digest, yaml, key_id, signature)
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    &[
                        &tenant,
                        &name,
                        &version,
                        &digest.to_hex(),
                        &yaml,
                        &key_id,
                        &signature,
                    ],
                )
                .await
                .map_err(|e| be(&e))?;
            }
            // Only the attestation columns move; the content is identical by
            // construction, which is what `decide_publish` established.
            PublishVerdict::AdoptAttestation => {
                tx.execute(
                    "UPDATE registry_manifests SET key_id = $4, signature = $5
                     WHERE tenant = $1 AND name = $2 AND version = $3",
                    &[&tenant, &name, &version, &key_id, &signature],
                )
                .await
                .map_err(|e| be(&e))?;
            }
            PublishVerdict::Unchanged => {}
        }
        tx.commit().await.map_err(|e| be(&e))?;
        Ok(digest)
    }

    /// One row, or [`RegistryError::NotFound`].
    async fn row(
        &self,
        name: &str,
        version: &str,
    ) -> Result<(String, Option<Attestation>), RegistryError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let row = client
            .query_opt(
                "SELECT yaml, key_id, signature FROM registry_manifests
                 WHERE tenant = $1 AND name = $2 AND version = $3",
                &[&self.tenant_name(), &name, &version],
            )
            .await
            .map_err(|e| be(&e))?
            .ok_or_else(|| RegistryError::NotFound {
                name: name.to_owned(),
                version: version.to_owned(),
            })?;
        Ok((
            row.get(0),
            stored_attestation(&row.get::<_, String>(1), &row.get::<_, String>(2)),
        ))
    }
}

#[async_trait]
impl Registry for PostgresStore {
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
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT version FROM registry_manifests
                 WHERE tenant = $1 AND name = $2
                 ORDER BY version",
                &[&self.tenant_name(), &name],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    async fn names(&self) -> Result<Vec<String>, RegistryError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT DISTINCT name FROM registry_manifests
                 WHERE tenant = $1
                 ORDER BY name",
                &[&self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }
}

/// Not a `StoreError`, and the conversion is here so a caller that has one can
/// still say what it means.
impl From<StoreError> for RegistryError {
    fn from(e: StoreError) -> Self {
        Self::Backend(e.to_string())
    }
}
