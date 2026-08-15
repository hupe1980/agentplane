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
    -- Lower sorts first: 0 trusted, 1 untrusted. A ranking key belongs in the
    -- index rather than in a sort, for the same reason the tenant does.
    trust_rank  SMALLINT NOT NULL,
    item        JSONB  NOT NULL,
    PRIMARY KEY (tenant, id, version)
);

-- The arbiter for concurrent revisions: one current version per tenant/id.
CREATE UNIQUE INDEX IF NOT EXISTS memory_one_current
    ON memory_items (tenant, id) WHERE current;

-- Current memories for one governed scope: most trusted first, then newest.
--
-- `trust_rank` leads `created_at` because recall truncates, and truncating by
-- recency alone is an eviction an attacker steers — anything able to write an
-- untrusted memory writes `limit` of them and the trusted ones silently lose.
CREATE INDEX IF NOT EXISTS memory_by_subject
    ON memory_items (tenant, subject, purpose, trust_rank, created_at DESC, id)
    WHERE current;

-- Derivation edges, **per version on both ends**. Supersession does not
-- un-absorb anything: a summary re-derived from other sources still contains
-- what its superseded version read, and that version stays readable through
-- version(). Id-level edges were replaced on every revision, so a cascade from
-- the original source no longer found the superseded summary that had absorbed
-- it. Per-version edges make the traversal see the union of what was ever
-- derived, and let it erase exactly the superseded versions that named a
-- doomed source while sparing a current version that did not.
CREATE TABLE IF NOT EXISTS memory_derived (
    tenant          TEXT   NOT NULL,
    source_id       TEXT   NOT NULL,
    source_version  BIGINT NOT NULL,
    derived_id      TEXT   NOT NULL,
    derived_version BIGINT NOT NULL,
    PRIMARY KEY (tenant, source_id, source_version, derived_id, derived_version)
);

-- The reverse lookup erasure needs: finding the edges pointing at a memory
-- without scanning the tenant's whole edge table inside the erasure
-- transaction.
CREATE INDEX IF NOT EXISTS memory_derived_by_target
    ON memory_derived (tenant, derived_id, derived_version);

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

/// Lower sorts first. Explicit rather than relying on the enum's own order, so
/// a new level has to be given a rank rather than inheriting one.
const fn trust_rank(trust: crate::core::Trust) -> i16 {
    match trust {
        crate::core::Trust::Trusted => 0,
        crate::core::Trust::Untrusted => 1,
    }
}

#[async_trait]
impl MemoryStore for PostgresStore {
    fn tenant(&self) -> &str {
        self.tenant_str()
    }

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
                (tenant, id, version, subject, purpose, created_at, expires_at, current,
                 trust_rank, item)
             VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8, $9)",
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
                &trust_rank(stored.trust),
                &json,
            ],
        )
        .await
        .map_err(|error| be(&error))?;

        // Sliding retention starts at the write, not at the first touch.
        // Initialized lazily, an item with a window and no fixed expiry was
        // *immortal* until somebody touched it — opt-in garbage that never
        // collects. The write is itself an access, so the window opens here
        // and each journaled touch slides it; a version written without the
        // window drops the row, because retention is a property of what is
        // currently believed.
        match stored.access_retention_seconds {
            Some(window) => {
                let expiry = stored
                    .created_at
                    .unix_timestamp()
                    .saturating_add(i64::try_from(window).unwrap_or(i64::MAX));
                tx.execute(
                    "INSERT INTO memory_access_expiry (tenant, id, expires_at)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (tenant, id) DO UPDATE
                     SET expires_at =
                         GREATEST(memory_access_expiry.expires_at, EXCLUDED.expires_at)",
                    &[&tenant, &stored.id, &expiry],
                )
                .await
                .map_err(|error| be(&error))?;
            }
            None => {
                tx.execute(
                    "DELETE FROM memory_access_expiry WHERE tenant = $1 AND id = $2",
                    &[&tenant, &stored.id],
                )
                .await
                .map_err(|error| be(&error))?;
            }
        }

        // One edge per source, keyed by this version on the derived end and
        // the exact version read on the source end. Earlier versions' edges
        // deliberately stay: a superseded summary still contains what it
        // absorbed and remains readable through version(), so its lineage must
        // stay traversable for as long as the version itself exists. Erasure —
        // not supersession — is what removes edges.
        for source in &stored.derived_from {
            tx.execute(
                "INSERT INTO memory_derived
                    (tenant, source_id, source_version, derived_id, derived_version)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                &[
                    &tenant,
                    &source.id,
                    &version_i64(source.version)?,
                    &stored.id,
                    &version_i64(version)?,
                ],
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
        // `expires_at` is a hard ceiling: sliding access retention may shorten
        // a life below it, never extend one past it — so the effective expiry
        // is the *earlier* of the two (`LEAST`, with absent sides coalesced to
        // +infinity so they never win).
        let rows = client
            .query(
                                "SELECT item.item FROM memory_items item
                                 LEFT JOIN memory_access_expiry access
                                     ON access.tenant = item.tenant AND access.id = item.id
                                 WHERE item.tenant = $1 AND item.subject = $2 AND item.current
                                     AND ($3::TEXT IS NULL OR item.purpose = $3)
                                     AND ($4::BIGINT IS NULL
                                                OR (item.expires_at IS NULL AND access.expires_at IS NULL)
                                                OR LEAST(
                                                        COALESCE(item.expires_at, 9223372036854775807),
                                                        COALESCE(access.expires_at, 9223372036854775807)
                                                ) > $4)
                                 ORDER BY item.trust_rank ASC, item.created_at DESC, item.id ASC LIMIT $5",
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

    async fn subject_ids(&self, subject: &str) -> Result<Vec<String>, StoreError> {
        let client = self.pool_ref().get().await.map_err(|error| {
            StoreError::Backend(format!("PostgreSQL pool unavailable: {error}"))
        })?;
        let tenant = self.tenant_name();
        // No LIMIT, deliberately: this is the erasure path's enumeration, and
        // a page size here would be a page size on how much of a subject an
        // erasure reaches. The recall limit's BIGINT ceiling does not apply
        // because there is no limit to convert.
        let rows = client
            .query(
                "SELECT DISTINCT id FROM memory_items
                 WHERE tenant = $1 AND subject = $2 AND current
                 ORDER BY id",
                &[&tenant, &subject],
            )
            .await
            .map_err(|error| be(&error))?;
        Ok(rows.iter().map(|row| row.get("id")).collect())
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
        // Edges deliberately stay — both directions. Outgoing, so a correction
        // that later becomes an erasure request can still find this memory's
        // derivatives; incoming, so a cascade from further *upstream* routes
        // through this tombstone to reach them — A → B → C with B forgotten
        // here must still let a cascade from poisoned A find C. The read path
        // keeps a kept edge harmless (`derivatives` joins on a current item),
        // and the tombstone prevents id reuse from attaching this lineage to
        // unrelated future content.
        let removed = tx
            .execute(
                "DELETE FROM memory_items WHERE tenant = $1 AND id = $2",
                &[&tenant, &id],
            )
            .await
            .map_err(|error| be(&error))?;
        // The sliding-retention row goes with the memory it describes. Left
        // behind it is residue about an erased id; every erasure path removes
        // it, where this backend used to leave it to the expiry sweep alone.
        tx.execute(
            "DELETE FROM memory_access_expiry WHERE tenant = $1 AND id = $2",
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

    #[allow(clippy::too_many_lines)]
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

        // The traversal is **version-granular**. Edges are kept per derivative
        // version, and a doomed source propagates to exactly the derivative
        // versions that read it:
        //
        //   * a derivative whose *current* version absorbed a doomed node is
        //     doomed as a whole id — its content is believed now, so the id,
        //     every version, and everything derived onward all go;
        //   * a derivative whose only absorbing versions are **superseded**
        //     loses those versions and keeps its current one — a summary
        //     honestly re-derived from clean sources is not destroyed by its
        //     own history, but the history that named the doomed source stops
        //     being readable through version().
        //
        // Every edge target is enqueued, **including tombstoned ones**:
        // `forget` deliberately keeps a forgotten memory's edges so a cascade
        // from further upstream can route through the tombstone. A tombstoned
        // node has nothing to remove, but its descendants do.
        let mut id_queue = vec![id.to_owned()];
        let mut version_queue: Vec<(String, i64)> = Vec::new();
        let mut doomed = std::collections::BTreeSet::new();
        let mut doomed_versions: std::collections::BTreeSet<(String, i64)> =
            std::collections::BTreeSet::new();
        loop {
            if let Some(source) = id_queue.pop() {
                if !doomed.insert(source.clone()) {
                    continue;
                }
                // Every outgoing edge, from every version of a fully doomed
                // id.
                let rows = tx
                    .query(
                        "SELECT derived_id, derived_version FROM memory_derived
                         WHERE tenant = $1 AND source_id = $2",
                        &[&tenant, &source],
                    )
                    .await
                    .map_err(|error| be(&error))?;
                version_queue.extend(
                    rows.iter()
                        .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1))),
                );
            } else if let Some((derived_id, derived_version)) = version_queue.pop() {
                if doomed.contains(&derived_id) {
                    continue;
                }
                let current_version: Option<i64> = tx
                    .query_opt(
                        "SELECT version FROM memory_items
                         WHERE tenant = $1 AND id = $2 AND current",
                        &[&tenant, &derived_id],
                    )
                    .await
                    .map_err(|error| be(&error))?
                    .map(|row| row.get(0));
                if current_version == Some(derived_version) {
                    id_queue.push(derived_id);
                } else {
                    if !doomed_versions.insert((derived_id.clone(), derived_version)) {
                        continue;
                    }
                    // Only this version's own onward lineage: what a
                    // superseded summary was itself read into.
                    let rows = tx
                        .query(
                            "SELECT derived_id, derived_version FROM memory_derived
                             WHERE tenant = $1 AND source_id = $2 AND source_version = $3",
                            &[&tenant, &derived_id, &derived_version],
                        )
                        .await
                        .map_err(|error| be(&error))?;
                    version_queue.extend(
                        rows.iter()
                            .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1))),
                    );
                }
            } else {
                break;
            }
        }

        // A hold blocks every erasure path, version-level included: an id
        // under hold must not lose even a superseded version.
        let held_candidates = doomed
            .iter()
            .chain(doomed_versions.iter().map(|(memory_id, _)| memory_id));
        for memory_id in held_candidates {
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

        // Counted per node that actually held rows, so a tombstoned
        // intermediate the traversal passed through is not reported as an
        // erasure it did not perform.
        let mut erased = 0usize;
        for memory_id in &doomed {
            tx.execute(
                "DELETE FROM memory_derived
                 WHERE tenant = $1 AND (source_id = $2 OR derived_id = $2)",
                &[&tenant, memory_id],
            )
            .await
            .map_err(|error| be(&error))?;
            let rows = tx
                .execute(
                    "DELETE FROM memory_items WHERE tenant = $1 AND id = $2",
                    &[&tenant, memory_id],
                )
                .await
                .map_err(|error| be(&error))?;
            if rows > 0 {
                erased += 1;
            }
            // Sliding-retention residue goes with the id — every erasure path
            // removes it.
            tx.execute(
                "DELETE FROM memory_access_expiry WHERE tenant = $1 AND id = $2",
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

        // Superseded versions that absorbed a doomed source, on ids that stay
        // alive. Only the version row goes: the id keeps its current entry and
        // — no tombstone — its future. `AND NOT current` is belt on top of the
        // traversal's own check; the graph lock makes the two agree.
        let mut partly: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (memory_id, version) in &doomed_versions {
            if doomed.contains(memory_id) {
                continue;
            }
            tx.execute(
                "DELETE FROM memory_derived
                 WHERE tenant = $1
                   AND ((source_id = $2 AND source_version = $3)
                     OR (derived_id = $2 AND derived_version = $3))",
                &[&tenant, memory_id, version],
            )
            .await
            .map_err(|error| be(&error))?;
            let rows = tx
                .execute(
                    "DELETE FROM memory_items
                     WHERE tenant = $1 AND id = $2 AND version = $3 AND NOT current",
                    &[&tenant, memory_id, version],
                )
                .await
                .map_err(|error| be(&error))?;
            if rows > 0 {
                partly.insert(memory_id.as_str());
            }
        }
        erased += partly.len();

        tx.commit().await.map_err(|error| be(&error))?;
        Ok(erased)
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
            // Incoming edges only, through the by-target index: a derivative
            // must stay in its source's subject, so every source of this id is
            // in this same erasure and the edge is intra-subject cleanup, not
            // lineage a later cascade could still need.
            tx.execute(
                "DELETE FROM memory_derived WHERE tenant = $1 AND derived_id = $2",
                &[&tenant, id],
            )
            .await
            .map_err(|error| be(&error))?;
            // Sliding-retention residue goes with the id — every erasure path
            // removes it.
            tx.execute(
                "DELETE FROM memory_access_expiry WHERE tenant = $1 AND id = $2",
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
        // Exclusive against the shared graph lock every memory write takes,
        // exactly as `forget_cascading` is — the sweep is an erasure, and an
        // erasure that held only the lifecycle lock raced `remember`: a new
        // derivative could be created under a source mid-expiry, committing a
        // summary whose source this transaction was already erasing.
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("memory-graph:{}:{tenant}", tenant.len())],
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
                                     -- The recall rule, applied to erasure: the
                                     -- ceiling wins, so a touched-up window never
                                     -- carries an item past its immutable expires_at.
                                     AND LEAST(
                                             COALESCE(item.expires_at, 9223372036854775807),
                                             COALESCE(access.expires_at, 9223372036854775807)
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
            // Derivation edges deliberately stay — both directions, exactly as
            // `forget` keeps them. An expired memory becomes a tombstone, not a
            // hole in the graph: with U → E → D and E expired here, a later
            // `forget_cascading(U)` must still route *through* E to reach D,
            // and this sweep once deleted E's incoming edges — severing exactly
            // that path, so the poisoned source's summary-of-a-summary outlived
            // the erasure. The read path keeps a kept edge harmless
            // (`derivatives` joins on a current row), and the tombstone
            // prevents id reuse from attaching this lineage to unrelated
            // future content.
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
        // Edges are per-version, so only an edge written by the *current*
        // version of the derivative counts here: a summary re-derived from
        // other sources is no longer a live derivative of this one, even
        // though its superseded versions keep their lineage for erasure.
        // EXISTS rather than JOIN because one current version may hold several
        // edges to different versions of the same source, and a join would
        // return it once per edge.
        let rows = client
            .query(
                "SELECT item.item
                 FROM memory_items item
                 WHERE item.tenant = $1 AND item.current
                   AND EXISTS (
                       SELECT 1 FROM memory_derived edge
                       WHERE edge.tenant = item.tenant
                         AND edge.source_id = $2
                         AND edge.derived_id = item.id
                         AND edge.derived_version = item.version)
                 ORDER BY item.created_at DESC, item.id ASC",
                &[&tenant, &id],
            )
            .await
            .map_err(|error| be(&error))?;
        rows.iter().map(decode).collect()
    }
}
