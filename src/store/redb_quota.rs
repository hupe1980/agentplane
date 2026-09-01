//! Per-tenant quota accounting on redb.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::core::{RunId, Spend, StoreError, Timestamp};
use crate::quota::{QuotaError, QuotaSettlement, QuotaStore};

use super::redb::{MAX_STR, RedbStore, be, begin_write};

/// `(tenant, run_id) -> admitted_at`. The set of runs currently executing.
///
/// A **set**, not a counter, and the difference is recovery. A bare counter that
/// is incremented on admission and decremented at the end leaks a slot every
/// time a process dies in between, and nothing can ever tell which increments
/// were real — the ceiling silently tightens until somebody restarts everything.
/// A set names its members, so a stranded slot is attributable to a run an
/// operator can look up, and releasing it is idempotent by construction.
///
/// The timestamp is what makes that attribution useful: a slot held far longer
/// than any run should take is visible as a slot held far longer than any run
/// should take.
const RUNNING: TableDefinition<(&str, &str), i64> = TableDefinition::new("quota_running");

/// `(tenant, period) -> (tokens, minor_units)`.
const SPENT: TableDefinition<(&str, &str), (u64, u64)> = TableDefinition::new("quota_spent");

/// `(tenant, run, epoch) -> (period, tokens, minor_units, release_slot)`.
///
/// The receipt makes a lost acknowledgement retryable without charging twice.
/// Empty `period` means this pass had no spend ceiling; period keys themselves
/// are never empty.
type SettlementKey<'a> = (&'a str, &'a str, u64);
type SettlementReceipt<'a> = (&'a str, u64, u64, u8);
const SETTLED: TableDefinition<SettlementKey<'static>, SettlementReceipt<'static>> =
    TableDefinition::new("quota_settled");

/// `tenant -> reason`. The emergency stop.
///
/// One row per halted tenant and nothing for the rest, so the check is a point
/// lookup and an unhalted plane pays one miss. In the store rather than in the
/// process, because a switch that stops only the instance it was thrown on is
/// not a switch — it is the in-process-counter failure arriving during an
/// incident.
const HALTED: TableDefinition<&str, &str> = TableDefinition::new("quota_halted");

#[async_trait]
impl QuotaStore for RedbStore {
    fn tenant(&self) -> &str {
        crate::journal::JournalStore::tenant(self)
    }

    async fn reserve(
        &self,
        run: RunId,
        limit: Option<u32>,
        at: Timestamp,
    ) -> Result<(), QuotaError> {
        let tenant = self.tenant_name();
        let run = run.to_string();
        let at = at.unix_timestamp();

        // The refusal comes back as a **value**, not an error message. Packing
        // "at the ceiling" into a `StoreError` string would mean the caller
        // decides behaviour by matching on prose, and the first person to
        // reword that prose silently turns every refusal into an outage.
        let taken: Result<(), u32> = self
            .with_db(move |db| {
                // One write transaction for the count *and* the insert. redb
                // has a single writer, so this is atomic against every other
                // admission on this store — the whole guarantee: a read followed
                // by a write lets two admissions through one remaining slot.
                let w = begin_write(db)?;
                let outcome = {
                    let mut running = w.open_table(RUNNING).map_err(|e| be(&e))?;

                    // Idempotent per run: a retried admission must not consume a
                    // second slot, nor fail against a ceiling it is already
                    // counted in.
                    let held = running
                        .get((tenant.as_str(), run.as_str()))
                        .map_err(|e| be(&e))?
                        .is_some();

                    let mut refused = None;
                    if !held && let Some(limit) = limit {
                        // Ranged over this tenant, never `len()`: that counts
                        // every tenant's runs, so one busy tenant would throttle
                        // everybody else — a shared ceiling wearing a per-tenant
                        // name.
                        //
                        // Walked only as far as the answer needs, then compared
                        // **once, outside the loop**. Comparing inside it looks
                        // equivalent and is not: with a ceiling of zero the body
                        // never runs, so nothing is ever compared and every run
                        // is admitted. A ceiling of zero is the one an operator
                        // sets to stop a tenant dead.
                        let mut n = 0u32;
                        for e in running
                            .range((tenant.as_str(), "")..=(tenant.as_str(), MAX_STR))
                            .map_err(|e| be(&e))?
                            .take(limit as usize)
                        {
                            e.map_err(|e| be(&e))?;
                            n += 1;
                        }
                        if n >= limit {
                            refused = Some(n);
                        }
                    }
                    if let Some(n) = refused {
                        Err(n)
                    } else {
                        running
                            .insert((tenant.as_str(), run.as_str()), at)
                            .map_err(|e| be(&e))?;
                        Ok(())
                    }
                };
                w.commit().map_err(|e| be(&e))?;
                Ok(outcome)
            })
            .await?;

        taken.map_err(|running| QuotaError::TooManyRuns {
            tenant: self.tenant_name(),
            running,
        })
    }

    async fn set_halt(&self, reason: Option<&str>) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let reason = reason.map(ToOwned::to_owned);
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut halted = w.open_table(HALTED).map_err(|e| be(&e))?;
                match &reason {
                    Some(reason) => {
                        halted
                            .insert(tenant.as_str(), reason.as_str())
                            .map_err(|e| be(&e))?;
                    }
                    None => {
                        halted.remove(tenant.as_str()).map_err(|e| be(&e))?;
                    }
                }
            }
            w.commit().map_err(|e| be(&e))
        })
        .await
    }

    async fn halted(&self) -> Result<Option<String>, StoreError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            // An absent table is an unhalted plane, not an error: nothing has
            // ever been halted, so there is nothing to read.
            let Ok(halted) = r.open_table(HALTED) else {
                return Ok(None);
            };
            Ok(halted
                .get(tenant.as_str())
                .map_err(|e| be(&e))?
                .map(|v| v.value().to_owned()))
        })
        .await
    }

    async fn release(&self, run: RunId) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let run = run.to_string();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut running = w.open_table(RUNNING).map_err(|e| be(&e))?;
                running
                    .remove((tenant.as_str(), run.as_str()))
                    .map_err(|e| be(&e))?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn settle(&self, settlement: &QuotaSettlement) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let settlement = settlement.clone();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let run = settlement.run.to_string();
            let period = settlement.period.as_deref().unwrap_or("");
            let receipt = (
                period,
                settlement.spend.tokens,
                settlement.spend.minor_units,
                u8::from(settlement.release_slot),
            );
            let fresh = {
                let mut settled = w.open_table(SETTLED).map_err(|e| be(&e))?;
                let stored = settled
                    .get((tenant.as_str(), run.as_str(), settlement.epoch))
                    .map_err(|e| be(&e))?
                    .map(|value| {
                        let (period, tokens, minor_units, release_slot) = value.value();
                        (period.to_owned(), tokens, minor_units, release_slot)
                    });
                match stored {
                    Some(stored)
                        if stored != (period.to_owned(), receipt.1, receipt.2, receipt.3) =>
                    {
                        return Err(StoreError::Corrupt {
                            seq: 0,
                            detail: format!(
                                "quota pass {run}/{} was settled twice with different payloads",
                                settlement.epoch
                            ),
                        });
                    }
                    Some(_) => false,
                    None => {
                        settled
                            .insert((tenant.as_str(), run.as_str(), settlement.epoch), receipt)
                            .map_err(|e| be(&e))?;
                        true
                    }
                }
            };
            if !fresh {
                w.commit().map_err(|e| be(&e))?;
                return Ok(());
            }
            if let Some(period) = settlement.period.as_deref() {
                let mut totals = w.open_table(SPENT).map_err(|e| be(&e))?;
                let (tokens, minor) = totals
                    .get((tenant.as_str(), period))
                    .map_err(|e| be(&e))?
                    .map_or((0, 0), |v| v.value());
                totals
                    .insert(
                        (tenant.as_str(), period),
                        (
                            tokens.saturating_add(settlement.spend.tokens),
                            minor.saturating_add(settlement.spend.minor_units),
                        ),
                    )
                    .map_err(|e| be(&e))?;
            }
            if settlement.release_slot {
                w.open_table(RUNNING)
                    .map_err(|e| be(&e))?
                    .remove((tenant.as_str(), run.as_str()))
                    .map_err(|e| be(&e))?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn spent(&self, period: &str) -> Result<Spend, StoreError> {
        let tenant = self.tenant_name();
        let period = period.to_owned();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            // Nothing has been spent because nothing has ever been written.
            let Ok(t) = r.open_table(SPENT) else {
                return Ok(Spend::default());
            };
            let (tokens, minor_units) = t
                .get((tenant.as_str(), period.as_str()))
                .map_err(|e| be(&e))?
                .map_or((0, 0), |v| v.value());
            Ok(Spend {
                tokens,
                minor_units,
            })
        })
        .await
    }

    async fn running(&self) -> Result<u32, StoreError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(t) = r.open_table(RUNNING) else {
                return Ok(0);
            };
            let mut n = 0u32;
            for e in t
                .range((tenant.as_str(), "")..=(tenant.as_str(), MAX_STR))
                .map_err(|e| be(&e))?
            {
                e.map_err(|e| be(&e))?;
                n += 1;
            }
            Ok(n)
        })
        .await
    }
}
