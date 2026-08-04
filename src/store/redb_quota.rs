//! Per-tenant quota accounting on redb.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::core::{RunId, Spend, StoreError, Timestamp};
use crate::quota::{QuotaError, QuotaStore};

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
const SPENT: TableDefinition<(&str, &str), (u64, i64)> = TableDefinition::new("quota_spent");

#[async_trait]
impl QuotaStore for RedbStore {
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

    async fn accrue(&self, period: &str, spend: Spend) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let period = period.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut totals = w.open_table(SPENT).map_err(|e| be(&e))?;
                let (tokens, minor) = totals
                    .get((tenant.as_str(), period.as_str()))
                    .map_err(|e| be(&e))?
                    .map_or((0, 0), |v| v.value());
                totals
                    .insert(
                        (tenant.as_str(), period.as_str()),
                        // Saturating: a spend total that wraps would report a
                        // tenant at zero after enough usage, which is a ceiling
                        // that disappears once it matters most.
                        (
                            tokens.saturating_add(spend.tokens),
                            minor.saturating_add(spend.minor_units),
                        ),
                    )
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
