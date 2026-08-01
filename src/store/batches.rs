//! SQLite-backed batch state.

use async_trait::async_trait;
use rusqlite::{OptionalExtension, params};

use crate::batch::{BatchCensus, BatchStore, ItemOutcome, ItemRecord};
use crate::core::{BatchId, RunId, Spend, StoreError};

use super::sqlite::{SqliteStore, be};

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS batches (
    batch_id    TEXT PRIMARY KEY,
    plan_digest TEXT NOT NULL,
    -- Set when the source returns an empty page. A batch with no unfinished
    -- item is not finished unless this is true; see BatchStore::mark_exhausted.
    exhausted   INTEGER NOT NULL DEFAULT 0
);

-- One row per item. The row exists from the moment the item is reserved, which
-- is what makes an interrupted item findable: a crash leaves `outcome` NULL
-- beside a run id that can be replayed.
CREATE TABLE IF NOT EXISTS batch_items (
    batch_id TEXT    NOT NULL REFERENCES batches (batch_id) ON DELETE CASCADE,
    item_key TEXT    NOT NULL,
    run_id   TEXT    NOT NULL,
    -- NULL while reserved-but-unfinished.
    outcome  TEXT,
    detail   TEXT,
    tokens   INTEGER NOT NULL DEFAULT 0,
    minor    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (batch_id, item_key)
);

-- The cursor scan and the census both walk items in key order.
CREATE INDEX IF NOT EXISTS batch_items_key
    ON batch_items (batch_id, item_key);
";

fn outcome_to_row(o: &ItemOutcome) -> (&'static str, Option<String>) {
    match o {
        ItemOutcome::Succeeded => ("succeeded", None),
        ItemOutcome::Failed(d) => ("failed", Some(d.clone())),
        ItemOutcome::Quarantined(d) => ("quarantined", Some(d.clone())),
        ItemOutcome::Suspended(d) => ("suspended", Some(d.clone())),
    }
}

fn outcome_from_row(s: Option<String>, detail: Option<String>) -> Option<ItemOutcome> {
    let d = detail.unwrap_or_default();
    match s?.as_str() {
        "succeeded" => Some(ItemOutcome::Succeeded),
        "failed" => Some(ItemOutcome::Failed(d)),
        "quarantined" => Some(ItemOutcome::Quarantined(d)),
        "suspended" => Some(ItemOutcome::Suspended(d)),
        _ => None,
    }
}

#[async_trait]
impl BatchStore for SqliteStore {
    async fn open(&self, id: BatchId, plan_digest: &str) -> Result<(), StoreError> {
        let digest = plan_digest.to_owned();
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO batches (batch_id, plan_digest) VALUES (?1, ?2)
                 ON CONFLICT (batch_id) DO NOTHING",
                params![id.to_string(), digest],
            )
            .map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn mark_exhausted(&self, id: BatchId) -> Result<(), StoreError> {
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE batches SET exhausted = 1 WHERE batch_id = ?1",
                params![id.to_string()],
            )
            .map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn is_exhausted(&self, id: BatchId) -> Result<bool, StoreError> {
        self.with_conn(move |conn| {
            let v: Option<i64> = conn
                .query_row(
                    "SELECT exhausted FROM batches WHERE batch_id = ?1",
                    params![id.to_string()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| be(&e))?;
            Ok(v.unwrap_or(0) != 0)
        })
        .await
    }

    async fn reserve(
        &self,
        batch: BatchId,
        key: &str,
        run: RunId,
    ) -> Result<ItemRecord, StoreError> {
        let k = key.to_owned();
        self.with_conn(move |conn| {
            // `DO NOTHING` then read back, rather than an upsert: if this item
            // was already reserved, the caller must get the *original* run id.
            // Overwriting it would orphan the first run's journal and re-perform
            // its effects, which is the one thing this row exists to prevent.
            conn.execute(
                "INSERT INTO batch_items (batch_id, item_key, run_id)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (batch_id, item_key) DO NOTHING",
                params![batch.to_string(), k, run.to_string()],
            )
            .map_err(|e| be(&e))?;

            let (run_s, outcome, detail, tokens, minor): (
                String,
                Option<String>,
                Option<String>,
                i64,
                i64,
            ) = conn
                .query_row(
                    "SELECT run_id, outcome, detail, tokens, minor FROM batch_items
                      WHERE batch_id = ?1 AND item_key = ?2",
                    params![batch.to_string(), k],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .map_err(|e| be(&e))?;

            Ok(ItemRecord {
                key: k,
                run: RunId::parse(&run_s).map_err(|e| StoreError::Corrupt {
                    seq: 0,
                    detail: format!("bad run id '{run_s}': {e}"),
                })?,
                outcome: outcome_from_row(outcome, detail),
                spend: Spend {
                    tokens: u64::try_from(tokens).unwrap_or(0),
                    minor_units: minor,
                },
            })
        })
        .await
    }

    async fn record(
        &self,
        batch: BatchId,
        key: &str,
        outcome: &ItemOutcome,
        spend: Spend,
    ) -> Result<(), StoreError> {
        let k = key.to_owned();
        let (state, detail) = outcome_to_row(outcome);
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE batch_items
                    SET outcome = ?3, detail = ?4, tokens = ?5, minor = ?6
                  WHERE batch_id = ?1 AND item_key = ?2",
                params![
                    batch.to_string(),
                    k,
                    state,
                    detail,
                    i64::try_from(spend.tokens).unwrap_or(i64::MAX),
                    spend.minor_units,
                ],
            )
            .map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn cursor(&self, batch: BatchId) -> Result<Option<String>, StoreError> {
        self.with_conn(move |conn| {
            // The contiguous terminal prefix: the highest key such that every
            // item up to and including it is terminal.
            //
            // Expressed as "the last key before the first non-terminal one",
            // because taking MAX over terminal items would step over a suspended
            // item sitting behind finished ones — and a resume that skips a
            // waiting item reports the batch complete while it is not.
            let first_open: Option<String> = conn
                .query_row(
                    "SELECT MIN(item_key) FROM batch_items
                      WHERE batch_id = ?1
                        AND (outcome IS NULL OR outcome = 'suspended')",
                    params![batch.to_string()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| be(&e))?
                .flatten();

            let cursor: Option<String> = match first_open {
                Some(open) => conn
                    .query_row(
                        "SELECT MAX(item_key) FROM batch_items
                          WHERE batch_id = ?1 AND item_key < ?2",
                        params![batch.to_string(), open],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| be(&e))?
                    .flatten(),
                None => conn
                    .query_row(
                        "SELECT MAX(item_key) FROM batch_items WHERE batch_id = ?1",
                        params![batch.to_string()],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| be(&e))?
                    .flatten(),
            };
            Ok(cursor)
        })
        .await
    }

    async fn census(&self, batch: BatchId) -> Result<BatchCensus, StoreError> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT outcome, COUNT(*), SUM(tokens), SUM(minor)
                       FROM batch_items WHERE batch_id = ?1
                      GROUP BY outcome",
                )
                .map_err(|e| be(&e))?;
            let rows = stmt
                .query_map(params![batch.to_string()], |r| {
                    Ok((
                        r.get::<_, Option<String>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                    ))
                })
                .map_err(|e| be(&e))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| be(&e))?;

            let mut c = BatchCensus::default();
            for (outcome, n, tokens, minor) in rows {
                let n = u64::try_from(n).unwrap_or(0);
                match outcome.as_deref() {
                    Some("succeeded") => c.succeeded = n,
                    Some("failed") => c.failed = n,
                    Some("quarantined") => c.quarantined = n,
                    Some("suspended") => c.suspended = n,
                    // NULL: reserved, no outcome recorded.
                    _ => c.in_flight = n,
                }
                c.spend.tokens += u64::try_from(tokens.unwrap_or(0)).unwrap_or(0);
                c.spend.minor_units += minor.unwrap_or(0);
            }
            Ok(c)
        })
        .await
    }

    async fn items(&self, batch: BatchId, limit: usize) -> Result<Vec<ItemRecord>, StoreError> {
        let lim = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT item_key, run_id, outcome, detail, tokens, minor
                       FROM batch_items WHERE batch_id = ?1
                      ORDER BY item_key ASC LIMIT ?2",
                )
                .map_err(|e| be(&e))?;
            let rows = stmt
                .query_map(params![batch.to_string(), lim], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                })
                .map_err(|e| be(&e))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| be(&e))?;

            let mut out = Vec::with_capacity(rows.len());
            for (key, run_s, outcome, detail, tokens, minor) in rows {
                out.push(ItemRecord {
                    key,
                    run: RunId::parse(&run_s).map_err(|e| StoreError::Corrupt {
                        seq: 0,
                        detail: format!("bad run id '{run_s}': {e}"),
                    })?,
                    outcome: outcome_from_row(outcome, detail),
                    spend: Spend {
                        tokens: u64::try_from(tokens).unwrap_or(0),
                        minor_units: minor,
                    },
                });
            }
            Ok(out)
        })
        .await
    }
}
