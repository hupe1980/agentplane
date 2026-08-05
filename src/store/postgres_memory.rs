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
    expires_at  BIGINT,
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

CREATE TABLE IF NOT EXISTS memory_legal_holds (
    tenant TEXT NOT NULL,
    id     TEXT NOT NULL,
    PRIMARY KEY (tenant, id)
);

CREATE TABLE IF NOT EXISTS memory_access_expiry (
    tenant     TEXT   NOT NULL,
    id         TEXT   NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, id)
);

CREATE INDEX IF NOT EXISTS memory_expiry
    ON memory_items (tenant, expires_at, id)
    WHERE current AND expires_at IS NOT NULL;
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

        // A shared graph lock excludes cascading erasure while allowing normal
        // memory writes to proceed concurrently. The shared subject lock lets
        // unrelated ids in the subject proceed while excluding
        // `forget_subject`. ID locks cover the first write, where no current row
        // exists for `FOR UPDATE`, and every derivation source is locked too so
        // it cannot disappear between validation and commit.
        tx.query_one(
            "SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))",
            &[&format!("memory-graph:{}:{tenant}", tenant.len())],
        )
        .await
        .map_err(|error| be(&error))?;
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
                (tenant, id, version, subject, purpose, created_at, expires_at, current, item)
             VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8)",
            &[
                &tenant,
                &stored.id,
                &version_i64(version)?,
                &stored.subject,
                &stored.purpose,
                &stored.created_at.unix_timestamp(),
                &stored
                    .expires_at
                    .map(crate::core::Timestamp::unix_timestamp),
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
                                "SELECT item.item FROM memory_items item
                                 LEFT JOIN memory_access_expiry access
                                     ON access.tenant = item.tenant AND access.id = item.id
                                 WHERE item.tenant = $1 AND item.subject = $2 AND item.current
                                     AND ($3::TEXT IS NULL OR item.purpose = $3)
                                     AND ($4::BIGINT IS NULL
                                                OR (item.expires_at IS NULL AND access.expires_at IS NULL)
                                                OR GREATEST(
                                                        COALESCE(item.expires_at, -9223372036854775808),
                                                        COALESCE(access.expires_at, -9223372036854775808)
                                                ) > $4)
                                 ORDER BY item.created_at DESC, item.id ASC LIMIT $5",
                                &[
                                        &tenant,
                                        &query.subject,
                                        &query.purpose,
                                        &query.as_of.map(crate::core::Timestamp::unix_timestamp),
                                        &limit,
                                ],
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
            &[&format!("memory-lifecycle:{}:{tenant}", tenant.len())],
        )
        .await
        .map_err(|error| be(&error))?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("memory-id:{}:{tenant}{id}", tenant.len())],
        )
        .await
        .map_err(|error| be(&error))?;
        if tx
            .query_opt(
                "SELECT 1 FROM memory_legal_holds WHERE tenant = $1 AND id = $2",
                &[&tenant, &id],
            )
            .await
            .map_err(|error| be(&error))?
            .is_some()
        {
            return Err(StoreError::Backend(format!(
                "memory '{id}' is under legal hold"
            )));
        }
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

    async fn forget_cascading(&self, id: &str) -> Result<usize, StoreError> {
        let mut client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tx = client.transaction().await.map_err(|error| be(&error))?;
        let tenant = self.tenant_name();
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("memory-lifecycle:{}:{tenant}", tenant.len())],
        )
        .await
        .map_err(|error| be(&error))?;

        // Exclusive against the shared lock every memory write takes. The
        // derivation graph is therefore stable for the complete traversal and
        // deletion, not merely for each query in it.
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("memory-graph:{}:{tenant}", tenant.len())],
        )
        .await
        .map_err(|error| be(&error))?;

        let mut queue = vec![id.to_owned()];
        let mut doomed = std::collections::BTreeSet::new();
        while let Some(source) = queue.pop() {
            if !doomed.insert(source.clone()) {
                continue;
            }
            let rows = tx
                .query(
                    "SELECT edge.derived_id
                     FROM memory_derived edge
                     JOIN memory_items item
                       ON item.tenant = edge.tenant
                      AND item.id = edge.derived_id
                      AND item.current
                     WHERE edge.tenant = $1 AND edge.source_id = $2",
                    &[&tenant, &source],
                )
                .await
                .map_err(|error| be(&error))?;
            queue.extend(rows.iter().map(|row| row.get::<_, String>("derived_id")));
        }

        for memory_id in &doomed {
            if tx
                .query_opt(
                    "SELECT 1 FROM memory_legal_holds WHERE tenant = $1 AND id = $2",
                    &[&tenant, memory_id],
                )
                .await
                .map_err(|error| be(&error))?
                .is_some()
            {
                return Err(StoreError::Backend(format!(
                    "memory '{memory_id}' is under legal hold"
                )));
            }
        }

        for memory_id in &doomed {
            tx.execute(
                "DELETE FROM memory_derived
                 WHERE tenant = $1 AND (source_id = $2 OR derived_id = $2)",
                &[&tenant, memory_id],
            )
            .await
            .map_err(|error| be(&error))?;
            tx.execute(
                "DELETE FROM memory_items WHERE tenant = $1 AND id = $2",
                &[&tenant, memory_id],
            )
            .await
            .map_err(|error| be(&error))?;
            tx.execute(
                "INSERT INTO memory_forgotten (tenant, id) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
                &[&tenant, memory_id],
            )
            .await
            .map_err(|error| be(&error))?;
        }

        tx.commit().await.map_err(|error| be(&error))?;
        Ok(doomed.len())
    }

    async fn forget_subject(&self, subject: &str) -> Result<usize, StoreError> {
        let mut client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tx = client.transaction().await.map_err(|error| be(&error))?;
        let tenant = self.tenant_name();
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("memory-lifecycle:{}:{tenant}", tenant.len())],
        )
        .await
        .map_err(|error| be(&error))?;
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
            if tx
                .query_opt(
                    "SELECT 1 FROM memory_legal_holds WHERE tenant = $1 AND id = $2",
                    &[&tenant, id],
                )
                .await
                .map_err(|error| be(&error))?
                .is_some()
            {
                return Err(StoreError::Backend(format!(
                    "memory '{id}' is under legal hold"
                )));
            }
        }
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

    async fn set_legal_hold(&self, id: &str, held: bool) -> Result<(), StoreError> {
        let mut client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tx = client.transaction().await.map_err(|error| be(&error))?;
        let tenant = self.tenant_name();
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("memory-lifecycle:{}:{tenant}", tenant.len())],
        )
        .await
        .map_err(|error| be(&error))?;
        let exists = tx
            .query_opt(
                "SELECT 1 FROM memory_items
                 WHERE tenant = $1 AND id = $2 AND current FOR UPDATE",
                &[&tenant, &id],
            )
            .await
            .map_err(|error| be(&error))?
            .is_some();
        if held && !exists {
            return Err(StoreError::Backend(format!(
                "cannot hold missing memory '{id}'"
            )));
        }
        if held {
            tx.execute(
                "INSERT INTO memory_legal_holds (tenant, id) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
                &[&tenant, &id],
            )
            .await
            .map_err(|error| be(&error))?;
        } else {
            tx.execute(
                "DELETE FROM memory_legal_holds WHERE tenant = $1 AND id = $2",
                &[&tenant, &id],
            )
            .await
            .map_err(|error| be(&error))?;
        }
        tx.commit().await.map_err(|error| be(&error))
    }

    async fn legal_hold(&self, id: &str) -> Result<bool, StoreError> {
        let client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tenant = self.tenant_name();
        client
            .query_opt(
                "SELECT 1 FROM memory_legal_holds WHERE tenant = $1 AND id = $2",
                &[&tenant, &id],
            )
            .await
            .map(|row| row.is_some())
            .map_err(|error| be(&error))
    }

    async fn sweep_expired(&self, at: crate::core::Timestamp) -> Result<usize, StoreError> {
        let mut client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tx = client.transaction().await.map_err(|error| be(&error))?;
        let tenant = self.tenant_name();
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("memory-lifecycle:{}:{tenant}", tenant.len())],
        )
        .await
        .map_err(|error| be(&error))?;
        let rows = tx
            .query(
                "SELECT item.id
                 FROM memory_items item
                                 LEFT JOIN memory_access_expiry access
                                     ON access.tenant = item.tenant AND access.id = item.id
                 LEFT JOIN memory_legal_holds hold
                   ON hold.tenant = item.tenant AND hold.id = item.id
                 WHERE item.tenant = $1 AND item.current
                                     AND (item.expires_at IS NOT NULL OR access.expires_at IS NOT NULL)
                                     AND GREATEST(
                                             COALESCE(item.expires_at, -9223372036854775808),
                                             COALESCE(access.expires_at, -9223372036854775808)
                                     ) <= $2
                   AND hold.id IS NULL
                 FOR UPDATE OF item",
                &[&tenant, &at.unix_timestamp()],
            )
            .await
            .map_err(|error| be(&error))?;
        let ids: Vec<String> = rows.iter().map(|row| row.get("id")).collect();
        for id in &ids {
            tx.execute(
                "DELETE FROM memory_access_expiry WHERE tenant = $1 AND id = $2",
                &[&tenant, id],
            )
            .await
            .map_err(|error| be(&error))?;
            tx.execute(
                "DELETE FROM memory_derived WHERE tenant = $1 AND derived_id = $2",
                &[&tenant, id],
            )
            .await
            .map_err(|error| be(&error))?;
            tx.execute(
                "DELETE FROM memory_items WHERE tenant = $1 AND id = $2",
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
        tx.commit().await.map_err(|error| be(&error))?;
        Ok(ids.len())
    }

    async fn touch(&self, ids: &[String], at: crate::core::Timestamp) -> Result<(), StoreError> {
        let mut client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tx = client.transaction().await.map_err(|error| be(&error))?;
        let tenant = self.tenant_name();
        for id in ids {
            let Some(row) = tx
                .query_opt(
                    "SELECT item FROM memory_items
                     WHERE tenant = $1 AND id = $2 AND current FOR UPDATE",
                    &[&tenant, id],
                )
                .await
                .map_err(|error| be(&error))?
            else {
                continue;
            };
            let item = decode(&row)?;
            let Some(window) = item.access_retention_seconds else {
                continue;
            };
            let expiry = at
                .unix_timestamp()
                .saturating_add(i64::try_from(window).unwrap_or(i64::MAX));
            tx.execute(
                "INSERT INTO memory_access_expiry (tenant, id, expires_at)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (tenant, id) DO UPDATE
                 SET expires_at = GREATEST(memory_access_expiry.expires_at, EXCLUDED.expires_at)",
                &[&tenant, id, &expiry],
            )
            .await
            .map_err(|error| be(&error))?;
        }
        tx.commit().await.map_err(|error| be(&error))
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
