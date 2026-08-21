//! Batch state on redb.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::batch::{BatchCensus, BatchStore, ItemOutcome, ItemRecord};
use crate::core::{BatchId, RunId, Spend, StoreError};

use super::redb::{MAX_STR, RedbStore, be, begin_write};

/// `batch_id -> (plan_digest, exhausted)`.
const BATCHES: TableDefinition<(&str, &str), (&str, u8)> = TableDefinition::new("batches");

/// `(batch_id, item_key) -> (run_id, outcome, has_outcome, detail, tokens, minor)`.
///
/// The row exists from the moment the item is reserved, which is what makes an
/// interrupted item findable: a crash leaves no outcome beside a run id that can
/// be replayed.
/// `(run_id, outcome, has_outcome, detail, tokens, minor)`.
type ItemRow<'a> = (&'a str, &'a str, u8, &'a str, u64, u64);

const ITEMS: TableDefinition<(&str, &str, &str), ItemRow<'static>> =
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
        ItemOutcome::Exhausted(d) => ("exhausted", d.clone()),
    }
}

/// `None` means *no outcome yet* — and only that. An outcome string this
/// store cannot read is damage, not absence: decoded to `None` it would say
/// the item never ran, the census would carry it as in-flight forever, and
/// the batch would report `Running` over a row nobody can explain.
fn outcome_from_row(has: u8, s: &str, detail: &str) -> Result<Option<ItemOutcome>, StoreError> {
    if has != 1 {
        return Ok(None);
    }
    let d = detail.to_owned();
    Ok(Some(match s {
        "succeeded" => ItemOutcome::Succeeded,
        "failed" => ItemOutcome::Failed(d),
        "quarantined" => ItemOutcome::Quarantined(d),
        "suspended" => ItemOutcome::Suspended(d),
        "exhausted" => ItemOutcome::Exhausted(d),
        other => {
            return Err(StoreError::Corrupt {
                seq: 0,
                detail: format!("unknown item outcome '{other}'"),
            });
        }
    }))
}

/// Whether an item still needs work. A suspended item is *not* terminal — it is
/// waiting, and a resume that steps over it reports the batch complete while it
/// is not.
fn is_open(has_outcome: u8, outcome: &str) -> bool {
    has_outcome != 1 || outcome == "suspended" || outcome == "exhausted"
}

#[async_trait]
impl BatchStore for RedbStore {
    async fn open(&self, id: BatchId, plan_digest: &str) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let (key, digest) = (id.to_string(), plan_digest.to_owned());
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut t = w.open_table(BATCHES).map_err(|e| be(&e))?;
                let stored = t
                    .get((tenant.as_str(), key.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|v| v.value().0.to_owned());
                match stored {
                    None => {
                        t.insert((tenant.as_str(), key.as_str()), (digest.as_str(), 0u8))
                            .map_err(|e| be(&e))?;
                    }
                    Some(stored) if stored == digest => {}
                    // One batch runs one frozen plan; a resume offering an
                    // edited one is a second act wearing this batch's name.
                    Some(stored) => {
                        return Err(StoreError::BatchPlanChanged {
                            batch: key.clone(),
                            stored,
                            offered: digest.clone(),
                        });
                    }
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn plan_digest(&self, id: BatchId) -> Result<Option<String>, StoreError> {
        let tenant = self.tenant_name();
        let key = id.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(t) = r.open_table(BATCHES) else {
                return Ok(None);
            };
            Ok(t.get((tenant.as_str(), key.as_str()))
                .map_err(|e| be(&e))?
                .map(|v| v.value().0.to_owned()))
        })
        .await
    }

    async fn mark_exhausted(&self, id: BatchId) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let key = id.to_string();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut t = w.open_table(BATCHES).map_err(|e| be(&e))?;
                let digest = t
                    .get((tenant.as_str(), key.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|v| v.value().0.to_owned());
                // A mark on an unknown batch is a refusal, not a no-op: this
                // is the one bit that lets a census read as *finished*, and
                // `Ok` over nothing is the quietest way to lose it.
                let Some(digest) = digest else {
                    return Err(StoreError::NotFound(key.clone()));
                };
                t.insert((tenant.as_str(), key.as_str()), (digest.as_str(), 1u8))
                    .map_err(|e| be(&e))?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn is_exhausted(&self, id: BatchId) -> Result<bool, StoreError> {
        let tenant = self.tenant_name();
        let key = id.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(BATCHES).map_err(|e| be(&e))?;
            Ok(t.get((tenant.as_str(), key.as_str()))
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
        let tenant = self.tenant_name();
        let (batch_key, item, run_id) = (batch.to_string(), key.to_owned(), run.to_string());
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let out = {
                let mut t = w.open_table(ITEMS).map_err(|e| be(&e))?;
                // Reserve then read back, rather than overwrite: if this item was
                // already reserved the caller must get the *original* run id.
                // Overwriting would orphan the first run's journal and re-perform
                // its effects, which is the one thing this row exists to prevent.
                if t.get((tenant.as_str(), batch_key.as_str(), item.as_str()))
                    .map_err(|e| be(&e))?
                    .is_none()
                {
                    t.insert(
                        (tenant.as_str(), batch_key.as_str(), item.as_str()),
                        (run_id.as_str(), "", 0u8, "", 0u64, 0u64),
                    )
                    .map_err(|e| be(&e))?;
                }
                let row = t
                    .get((tenant.as_str(), batch_key.as_str(), item.as_str()))
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
                    return Err(StoreError::NotFound(format!("{batch_key}/{item}")));
                };
                ItemRecord {
                    key: item.clone(),
                    run: RunId::parse(&run_s).map_err(|e| StoreError::Corrupt {
                        seq: 0,
                        detail: format!("bad run id '{run_s}': {e}"),
                    })?,
                    outcome: outcome_from_row(has, &outcome, &detail)?,
                    spend: Spend {
                        tokens,
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
        let tenant = self.tenant_name();
        let (batch_key, item) = (batch.to_string(), key.to_owned());
        let (state, detail) = outcome_to_row(outcome);
        let tokens = spend.tokens;
        let minor = spend.minor_units;
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut t = w.open_table(ITEMS).map_err(|e| be(&e))?;
                let run = t
                    .get((tenant.as_str(), batch_key.as_str(), item.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|v| v.value().0.to_owned());
                // An unreserved item is a refusal, not a no-op: returning `Ok`
                // while writing nothing tells the caller *recorded* over an
                // outcome that vanished.
                let Some(run) = run else {
                    return Err(StoreError::NotFound(format!("{batch_key}/{item}")));
                };
                t.insert(
                    (tenant.as_str(), batch_key.as_str(), item.as_str()),
                    (run.as_str(), state, 1u8, detail.as_str(), tokens, minor),
                )
                .map_err(|e| be(&e))?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn cursor(&self, batch: BatchId) -> Result<Option<String>, StoreError> {
        let tenant = self.tenant_name();
        let batch_key = batch.to_string();
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
                .range(
                    (tenant.as_str(), batch_key.as_str(), "")
                        ..=(tenant.as_str(), batch_key.as_str(), MAX_STR),
                )
                .map_err(|e| be(&e))?
            {
                let (k, v) = e.map_err(|e| be(&e))?;
                let (_, outcome, has, _, _, _) = v.value();
                if is_open(has, outcome) {
                    break;
                }
                last_terminal = Some(k.value().2.to_owned());
            }
            Ok(last_terminal)
        })
        .await
    }

    async fn census(&self, batch: BatchId) -> Result<BatchCensus, StoreError> {
        let tenant = self.tenant_name();
        let batch_key = batch.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(ITEMS).map_err(|e| be(&e))?;
            let mut c = BatchCensus::default();
            for e in t
                .range(
                    (tenant.as_str(), batch_key.as_str(), "")
                        ..=(tenant.as_str(), batch_key.as_str(), MAX_STR),
                )
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
                        "exhausted" => c.exhausted += 1,
                        // Damage, not a bucket: filed as in-flight this row
                        // would keep the batch `Running` forever, silently.
                        other => {
                            return Err(StoreError::Corrupt {
                                seq: 0,
                                detail: format!("unknown item outcome '{other}'"),
                            });
                        }
                    }
                } else {
                    // Reserved, no outcome recorded.
                    c.in_flight += 1;
                }
                c.spend.tokens += tokens;
                c.spend.minor_units += minor;
            }
            Ok(c)
        })
        .await
    }

    async fn items(&self, batch: BatchId, limit: usize) -> Result<Vec<ItemRecord>, StoreError> {
        let tenant = self.tenant_name();
        let batch_key = batch.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(ITEMS).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            for e in t
                .range(
                    (tenant.as_str(), batch_key.as_str(), "")
                        ..=(tenant.as_str(), batch_key.as_str(), MAX_STR),
                )
                .map_err(|e| be(&e))?
            {
                if out.len() >= limit {
                    break;
                }
                let (k, v) = e.map_err(|e| be(&e))?;
                let (run_s, outcome, has, detail, tokens, minor) = v.value();
                out.push(ItemRecord {
                    key: k.value().2.to_owned(),
                    run: RunId::parse(run_s).map_err(|e| StoreError::Corrupt {
                        seq: 0,
                        detail: format!("bad run id '{run_s}': {e}"),
                    })?,
                    outcome: outcome_from_row(has, outcome, detail)?,
                    spend: Spend {
                        tokens,
                        minor_units: minor,
                    },
                });
            }
            Ok(out)
        })
        .await
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    /// Every outcome this store writes is one it reads back as the same value.
    #[test]
    fn every_written_outcome_decodes_to_the_value_that_wrote_it() {
        for outcome in [
            ItemOutcome::Succeeded,
            ItemOutcome::Failed("x".into()),
            ItemOutcome::Quarantined("x".into()),
            ItemOutcome::Suspended("x".into()),
            ItemOutcome::Exhausted("x".into()),
        ] {
            let (state, detail) = outcome_to_row(&outcome);
            assert_eq!(
                outcome_from_row(1, state, &detail).expect("round trip"),
                Some(outcome)
            );
        }
        assert_eq!(
            outcome_from_row(0, "", "").expect("absence is not damage"),
            None
        );
    }

    /// **An outcome this store cannot read is damage, not absence.**
    ///
    /// Decoded to `None` it says the item never ran; the census then carries
    /// the row as in-flight forever and the batch reports `Running` over a
    /// row nobody can explain — a corrupt store wearing a healthy status.
    #[test]
    fn an_unreadable_item_outcome_is_refused_rather_than_defaulted() {
        for bad in ["", "Succeeded", "done", "succeeded "] {
            assert!(
                matches!(
                    outcome_from_row(1, bad, "").err(),
                    Some(StoreError::Corrupt { .. })
                ),
                "outcome '{bad}' decoded instead of refusing"
            );
        }
    }
}
