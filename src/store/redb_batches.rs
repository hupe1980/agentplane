//! Batch state on redb.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::batch::{BatchCensus, BatchStore, ItemOutcome, ItemRecord};
use crate::core::{BatchId, RunId, Spend, StoreError};

use super::redb::{MAX_STR, RedbStore, be, begin_write};

/// `batch_id -> (plan_digest, exhausted)`.
const BATCHES: TableDefinition<&str, (&str, u8)> = TableDefinition::new("batches");

/// `(batch_id, item_key) -> (run_id, outcome, has_outcome, detail, tokens, minor)`.
///
/// The row exists from the moment the item is reserved, which is what makes an
/// interrupted item findable: a crash leaves no outcome beside a run id that can
/// be replayed.
const ITEMS: TableDefinition<(&str, &str), (&str, &str, u8, &str, i64, i64)> =
    TableDefinition::new("batch_items");

pub(super) fn create_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(BATCHES).map_err(|e| be(&e))?;
    w.open_table(ITEMS).map_err(|e| be(&e))?;
    Ok(())
}

fn outcome_to_row(o: &ItemOutcome) -> (&'static str, String) {
    match o {
        ItemOutcome::Succeeded => ("succeeded", String::new()),
        ItemOutcome::Failed(d) => ("failed", d.clone()),
        ItemOutcome::Quarantined(d) => ("quarantined", d.clone()),
        ItemOutcome::Suspended(d) => ("suspended", d.clone()),
    }
}

fn outcome_from_row(has: u8, s: &str, detail: &str) -> Option<ItemOutcome> {
    if has != 1 {
        return None;
    }
    let d = detail.to_owned();
    match s {
        "succeeded" => Some(ItemOutcome::Succeeded),
        "failed" => Some(ItemOutcome::Failed(d)),
        "quarantined" => Some(ItemOutcome::Quarantined(d)),
        "suspended" => Some(ItemOutcome::Suspended(d)),
        _ => None,
    }
}

/// Whether an item still needs work. A suspended item is *not* terminal — it is
/// waiting, and a resume that steps over it reports the batch complete while it
/// is not.
fn is_open(has_outcome: u8, outcome: &str) -> bool {
    has_outcome != 1 || outcome == "suspended"
}

#[async_trait]
impl BatchStore for RedbStore {
    async fn open(&self, id: BatchId, plan_digest: &str) -> Result<(), StoreError> {
        let (key, digest) = (id.to_string(), plan_digest.to_owned());
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut t = w.open_table(BATCHES).map_err(|e| be(&e))?;
                if t.get(key.as_str()).map_err(|e| be(&e))?.is_none() {
                    t.insert(key.as_str(), (digest.as_str(), 0u8))
                        .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn mark_exhausted(&self, id: BatchId) -> Result<(), StoreError> {
        let key = id.to_string();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut t = w.open_table(BATCHES).map_err(|e| be(&e))?;
                let digest = t
                    .get(key.as_str())
                    .map_err(|e| be(&e))?
                    .map(|v| v.value().0.to_owned());
                if let Some(digest) = digest {
                    t.insert(key.as_str(), (digest.as_str(), 1u8))
                        .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn is_exhausted(&self, id: BatchId) -> Result<bool, StoreError> {
        let key = id.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(BATCHES).map_err(|e| be(&e))?;
            Ok(t.get(key.as_str())
                .map_err(|e| be(&e))?
                .is_some_and(|v| v.value().1 == 1))
        })
        .await
    }

    async fn reserve(
        &self,
        batch: BatchId,
        key: &str,
        run: RunId,
    ) -> Result<ItemRecord, StoreError> {
        let (b, k, r) = (batch.to_string(), key.to_owned(), run.to_string());
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let out = {
                let mut t = w.open_table(ITEMS).map_err(|e| be(&e))?;
                // Reserve then read back, rather than overwrite: if this item was
                // already reserved the caller must get the *original* run id.
                // Overwriting would orphan the first run's journal and re-perform
                // its effects, which is the one thing this row exists to prevent.
                if t.get((b.as_str(), k.as_str()))
                    .map_err(|e| be(&e))?
                    .is_none()
                {
                    t.insert(
                        (b.as_str(), k.as_str()),
                        (r.as_str(), "", 0u8, "", 0i64, 0i64),
                    )
                    .map_err(|e| be(&e))?;
                }
                let row = t
                    .get((b.as_str(), k.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|v| {
                        let (run, oc, has, detail, tokens, minor) = v.value();
                        (
                            run.to_owned(),
                            oc.to_owned(),
                            has,
                            detail.to_owned(),
                            tokens,
                            minor,
                        )
                    });
                let Some((run_s, outcome, has, detail, tokens, minor)) = row else {
                    return Err(StoreError::NotFound(format!("{b}/{k}")));
                };
                ItemRecord {
                    key: k.clone(),
                    run: RunId::parse(&run_s).map_err(|e| StoreError::Corrupt {
                        seq: 0,
                        detail: format!("bad run id '{run_s}': {e}"),
                    })?,
                    outcome: outcome_from_row(has, &outcome, &detail),
                    spend: Spend {
                        tokens: u64::try_from(tokens).unwrap_or(0),
                        minor_units: minor,
                    },
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(out)
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
        let (b, k) = (batch.to_string(), key.to_owned());
        let (state, detail) = outcome_to_row(outcome);
        let tokens = i64::try_from(spend.tokens).unwrap_or(i64::MAX);
        let minor = spend.minor_units;
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut t = w.open_table(ITEMS).map_err(|e| be(&e))?;
                let run = t
                    .get((b.as_str(), k.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|v| v.value().0.to_owned());
                if let Some(run) = run {
                    t.insert(
                        (b.as_str(), k.as_str()),
                        (run.as_str(), state, 1u8, detail.as_str(), tokens, minor),
                    )
                    .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn cursor(&self, batch: BatchId) -> Result<Option<String>, StoreError> {
        let b = batch.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(ITEMS).map_err(|e| be(&e))?;
            // The contiguous terminal prefix: the last key before the first
            // item still needing work. Taking the greatest *terminal* key
            // instead would step over a suspended item sitting behind finished
            // ones, and a resume that skips a waiting item reports the batch
            // complete while it is not.
            let mut last_terminal: Option<String> = None;
            for e in t
                .range((b.as_str(), "")..=(b.as_str(), MAX_STR))
                .map_err(|e| be(&e))?
            {
                let (k, v) = e.map_err(|e| be(&e))?;
                let (_, outcome, has, _, _, _) = v.value();
                if is_open(has, outcome) {
                    break;
                }
                last_terminal = Some(k.value().1.to_owned());
            }
            Ok(last_terminal)
        })
        .await
    }

    async fn census(&self, batch: BatchId) -> Result<BatchCensus, StoreError> {
        let b = batch.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(ITEMS).map_err(|e| be(&e))?;
            let mut c = BatchCensus::default();
            for e in t
                .range((b.as_str(), "")..=(b.as_str(), MAX_STR))
                .map_err(|e| be(&e))?
            {
                let (_, v) = e.map_err(|e| be(&e))?;
                let (_, outcome, has, _, tokens, minor) = v.value();
                if has == 1 {
                    match outcome {
                        "succeeded" => c.succeeded += 1,
                        "failed" => c.failed += 1,
                        "quarantined" => c.quarantined += 1,
                        "suspended" => c.suspended += 1,
                        _ => c.in_flight += 1,
                    }
                } else {
                    // Reserved, no outcome recorded.
                    c.in_flight += 1;
                }
                c.spend.tokens += u64::try_from(tokens).unwrap_or(0);
                c.spend.minor_units += minor;
            }
            Ok(c)
        })
        .await
    }

    async fn items(&self, batch: BatchId, limit: usize) -> Result<Vec<ItemRecord>, StoreError> {
        let b = batch.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(ITEMS).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            for e in t
                .range((b.as_str(), "")..=(b.as_str(), MAX_STR))
                .map_err(|e| be(&e))?
            {
                if out.len() >= limit {
                    break;
                }
                let (k, v) = e.map_err(|e| be(&e))?;
                let (run_s, outcome, has, detail, tokens, minor) = v.value();
                out.push(ItemRecord {
                    key: k.value().1.to_owned(),
                    run: RunId::parse(run_s).map_err(|e| StoreError::Corrupt {
                        seq: 0,
                        detail: format!("bad run id '{run_s}': {e}"),
                    })?,
                    outcome: outcome_from_row(has, outcome, detail),
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
