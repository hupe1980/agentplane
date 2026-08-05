//! Governed memory on `PostgreSQL`.
//!
//! This is the memory backend for the topology `PostgreSQL` exists to serve:
//! several plane instances sharing one store. Version allocation, current-row
//! replacement, and derivation-edge replacement therefore happen under one
//! row lock and one transaction rather than through process-local arbitration.

use async_trait::async_trait;
use tokio_postgres::Row;

use crate::core::StoreError;
use crate::memory::{MemoryItem, MemoryStore, Recall};

use super::postgres::PostgresStore;

pub(super) const MEMORY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS memory_items (
    tenant      TEXT   NOT NULL,
    id          TEXT   NOT NULL,
    version     BIGINT NOT NULL CHECK (version > 0),
    subject     TEXT   NOT NULL,
    purpose     TEXT   NOT NULL,
    created_at  BIGINT NOT NULL,
    current     BOOLEAN NOT NULL,
    item        JSONB  NOT NULL,
    PRIMARY KEY (tenant, id, version)
);

-- The arbiter for concurrent revisions: one current version per tenant/id.
CREATE UNIQUE INDEX IF NOT EXISTS memory_one_current
    ON memory_items (tenant, id) WHERE current;

-- Current memories for one governed scope, newest first.
CREATE INDEX IF NOT EXISTS memory_by_subject
    ON memory_items (tenant, subject, purpose, created_at DESC, id)
    WHERE current;

CREATE TABLE IF NOT EXISTS memory_derived (
    tenant     TEXT NOT NULL,
    source_id  TEXT NOT NULL,
    derived_id TEXT NOT NULL,
    PRIMARY KEY (tenant, source_id, derived_id)
);

CREATE INDEX IF NOT EXISTS memory_derived_by_target
    ON memory_derived (tenant, derived_id, source_id);

CREATE TABLE IF NOT EXISTS memory_forgotten (
    tenant TEXT NOT NULL,
    id     TEXT NOT NULL,
    PRIMARY KEY (tenant, id)
);
";

fn be(error: &tokio_postgres::Error) -> StoreError {
    if let Some(db) = error.as_db_error() {
        let detail = db
            .detail()
            .map_or(String::new(), |detail| format!(": {detail}"));
        StoreError::Backend(format!("{} ({}{})", db.message(), db.code().code(), detail))
    } else {
        StoreError::Backend(error.to_string())
    }
}

fn decode(row: &Row) -> Result<MemoryItem, StoreError> {
    serde_json::from_value(row.get("item")).map_err(|error| StoreError::Backend(error.to_string()))
}

fn version_u64(version: i64) -> Result<u64, StoreError> {
    u64::try_from(version)
        .map_err(|_| StoreError::Backend(format!("invalid memory version {version}")))
}

fn version_i64(version: u64) -> Result<i64, StoreError> {
    i64::try_from(version).map_err(|_| {
        StoreError::Backend(format!(
            "memory version {version} exceeds PostgreSQL BIGINT"
        ))
    })
}

#[async_trait]
impl MemoryStore for PostgresStore {
    #[allow(clippy::too_many_lines)]
    async fn remember(&self, item: &MemoryItem) -> Result<u64, StoreError> {
        let mut client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tx = client.transaction().await.map_err(|error| be(&error))?;
        let tenant = self.tenant_name();

        // A shared subject lock lets unrelated ids in the subject proceed while
        // excluding `forget_subject`. ID locks cover the first write, where no
        // current row exists for `FOR UPDATE`, and every derivation source is
        // locked too so it cannot disappear between validation and commit.
        tx.query_one(
            "SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))",
            &[&format!(
                "memory-subject:{}:{tenant}{}",
                tenant.len(),
                item.subject
            )],
        )
        .await
        .map_err(|error| be(&error))?;
        let mut locked_ids = std::collections::BTreeSet::from([item.id.as_str()]);
        locked_ids.extend(item.derived_from.iter().map(|source| source.id.as_str()));
        for id in locked_ids {
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&format!("memory-id:{}:{tenant}{id}", tenant.len())],
            )
            .await
            .map_err(|error| be(&error))?;
        }

        let previous = tx
            .query_opt(
                "SELECT version, item FROM memory_items
                 WHERE tenant = $1 AND id = $2 AND current
                 FOR UPDATE",
                &[&tenant, &item.id],
            )
            .await
            .map_err(|error| be(&error))?;

        if previous.is_none()
            && tx
                .query_opt(
                    "SELECT 1 FROM memory_forgotten WHERE tenant = $1 AND id = $2",
                    &[&tenant, &item.id],
                )
                .await
                .map_err(|error| be(&error))?
                .is_some()
        {
            return Err(StoreError::Backend(format!(
                "memory id '{}' was forgotten and cannot be reused",
                item.id
            )));
        }

        if let Some(row) = previous.as_ref() {
            let prior = decode(row)?;
            if prior.subject != item.subject || prior.purpose != item.purpose {
                return Err(StoreError::Backend(format!(
                    "memory id '{}' is scoped to subject '{}' and purpose '{}'; use a new id \
                     instead of moving it to subject '{}' and purpose '{}'",
                    item.id, prior.subject, prior.purpose, item.subject, item.purpose
                )));
            }
        }

        for source in &item.derived_from {
            let source_version = version_i64(source.version)?;
            let row = tx
                .query_opt(
                    "SELECT item FROM memory_items
                     WHERE tenant = $1 AND id = $2 AND version = $3",
                    &[&tenant, &source.id, &source_version],
                )
                .await
                .map_err(|error| be(&error))?
                .ok_or_else(|| {
                    StoreError::Backend(format!(
                        "derived memory '{}' names missing source '{}' version {}",
                        item.id, source.id, source.version
                    ))
                })?;
            let source_item = decode(&row)?;
            if source_item.selection_digest() != source.digest {
                return Err(StoreError::Backend(format!(
                    "derived memory '{}' names a changed source '{}' version {}",
                    item.id, source.id, source.version
                )));
            }
            if source_item.subject != item.subject {
                return Err(StoreError::Backend(format!(
                    "derived memory '{}' must stay in source subject '{}' rather than '{}'",
                    item.id, source_item.subject, item.subject
                )));
            }
        }

        let version = match &previous {
            Some(row) => version_u64(row.get::<_, i64>("version"))?
                .checked_add(1)
                .ok_or_else(|| StoreError::Backend("memory version overflow".to_owned()))?,
            None => 1,
        };

        if let Some(row) = previous {
            let previous_version = row.get::<_, i64>("version");
            let mut previous_item = decode(&row)?;
            previous_item.superseded_at = Some(item.created_at);
            let previous_json = serde_json::to_value(previous_item)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            tx.execute(
                "UPDATE memory_items SET current = FALSE, item = $4
                 WHERE tenant = $1 AND id = $2 AND version = $3",
                &[&tenant, &item.id, &previous_version, &previous_json],
            )
            .await
            .map_err(|error| be(&error))?;
        }

        let mut stored = item.clone();
        stored.version = version;
        stored.superseded_at = None;
        let json = serde_json::to_value(&stored)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        tx.execute(
            "INSERT INTO memory_items
                (tenant, id, version, subject, purpose, created_at, current, item)
             VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7)",
            &[
                &tenant,
                &stored.id,
                &version_i64(version)?,
                &stored.subject,
                &stored.purpose,
                &stored.created_at.unix_timestamp(),
                &json,
            ],
        )
        .await
        .map_err(|error| be(&error))?;

        tx.execute(
            "DELETE FROM memory_derived WHERE tenant = $1 AND derived_id = $2",
            &[&tenant, &stored.id],
        )
        .await
        .map_err(|error| be(&error))?;
        for source in &stored.derived_from {
            tx.execute(
                "INSERT INTO memory_derived (tenant, source_id, derived_id)
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                &[&tenant, &source.id, &stored.id],
            )
            .await
            .map_err(|error| be(&error))?;
        }

        tx.commit().await.map_err(|error| be(&error))?;
        Ok(version)
    }

    async fn recall(&self, query: &Recall) -> Result<Vec<MemoryItem>, StoreError> {
        let client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tenant = self.tenant_name();
        let limit = i64::try_from(query.limit)
            .map_err(|_| StoreError::Backend("memory recall limit exceeds BIGINT".to_owned()))?;
        let rows = client
            .query(
                "SELECT item FROM memory_items
                 WHERE tenant = $1 AND subject = $2 AND current
                   AND ($3::TEXT IS NULL OR purpose = $3)
                 ORDER BY created_at DESC, id ASC LIMIT $4",
                &[&tenant, &query.subject, &query.purpose, &limit],
            )
            .await
            .map_err(|error| be(&error))?;
        rows.iter().map(decode).collect()
    }

    async fn version(&self, id: &str, version: u64) -> Result<Option<MemoryItem>, StoreError> {
        let client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tenant = self.tenant_name();
        client
            .query_opt(
                "SELECT item FROM memory_items WHERE tenant = $1 AND id = $2 AND version = $3",
                &[&tenant, &id, &version_i64(version)?],
            )
            .await
            .map_err(|error| be(&error))?
            .as_ref()
            .map(decode)
            .transpose()
    }

    async fn forget(&self, id: &str) -> Result<(), StoreError> {
        let mut client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tx = client.transaction().await.map_err(|error| be(&error))?;
        let tenant = self.tenant_name();
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("memory-id:{}:{tenant}{id}", tenant.len())],
        )
        .await
        .map_err(|error| be(&error))?;
        tx.execute(
            "DELETE FROM memory_derived WHERE tenant = $1 AND derived_id = $2",
            &[&tenant, &id],
        )
        .await
        .map_err(|error| be(&error))?;
        let removed = tx
            .execute(
                "DELETE FROM memory_items WHERE tenant = $1 AND id = $2",
                &[&tenant, &id],
            )
            .await
            .map_err(|error| be(&error))?;
        if removed > 0 {
            tx.execute(
                "INSERT INTO memory_forgotten (tenant, id) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
                &[&tenant, &id],
            )
            .await
            .map_err(|error| be(&error))?;
        }
        tx.commit().await.map_err(|error| be(&error))
    }

    async fn forget_subject(&self, subject: &str) -> Result<usize, StoreError> {
        let mut client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tx = client.transaction().await.map_err(|error| be(&error))?;
        let tenant = self.tenant_name();
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!(
                "memory-subject:{}:{tenant}{subject}",
                tenant.len()
            )],
        )
        .await
        .map_err(|error| be(&error))?;
        let rows = tx
            .query(
                "SELECT id FROM memory_items
                 WHERE tenant = $1 AND subject = $2 AND current FOR UPDATE",
                &[&tenant, &subject],
            )
            .await
            .map_err(|error| be(&error))?;
        let ids: Vec<String> = rows.iter().map(|row| row.get("id")).collect();
        for id in &ids {
            tx.execute(
                "DELETE FROM memory_derived WHERE tenant = $1 AND derived_id = $2",
                &[&tenant, id],
            )
            .await
            .map_err(|error| be(&error))?;
            tx.execute(
                "INSERT INTO memory_forgotten (tenant, id) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
                &[&tenant, id],
            )
            .await
            .map_err(|error| be(&error))?;
        }
        tx.execute(
            "DELETE FROM memory_items WHERE tenant = $1 AND subject = $2",
            &[&tenant, &subject],
        )
        .await
        .map_err(|error| be(&error))?;
        tx.commit().await.map_err(|error| be(&error))?;
        Ok(ids.len())
    }

    async fn derivatives(&self, id: &str) -> Result<Vec<MemoryItem>, StoreError> {
        let client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tenant = self.tenant_name();
        let rows = client
            .query(
                "SELECT item.item
                 FROM memory_derived edge
                 JOIN memory_items item
                   ON item.tenant = edge.tenant
                  AND item.id = edge.derived_id
                  AND item.current
                 WHERE edge.tenant = $1 AND edge.source_id = $2
                 ORDER BY item.created_at DESC, item.id ASC",
                &[&tenant, &id],
            )
            .await
            .map_err(|error| be(&error))?;
        rows.iter().map(decode).collect()
    }
}
