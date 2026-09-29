//! Per-tenant quota accounting on redb.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::core::{RunId, Spend, StoreError, Timestamp};
use crate::quota::{
    Halt, HaltScope, Held, QuotaError, QuotaSettlement, QuotaStore, RateCeiling, RateReservation,
    SpendHold, TenantQuota,
};

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

/// `(tenant, run) -> (period, tokens, minor_units)`: what an open run still
/// holds against a period.
///
/// Written beside the slot at admission, reduced by every pass settlement and
/// removed by the one that concludes the run — each in the transaction that
/// writes the receipt. A run holds one row whatever it spends in, so a resume
/// in a later period moves the row rather than adding a second.
type HoldRow<'a> = (&'a str, u64, u64);
const RESERVED: TableDefinition<(&str, &str), HoldRow<'static>> =
    TableDefinition::new("quota_reserved");

/// `(tenant, run, epoch) -> (period, tokens, minor_units, release_slot, concludes)`.
///
/// The receipt makes a lost acknowledgement retryable without charging twice.
/// Empty `period` means this pass had no spend ceiling; period keys themselves
/// are never empty.
type SettlementKey<'a> = (&'a str, &'a str, u64);
type SettlementReceipt<'a> = (&'a str, u64, u64, u8, u8);
const SETTLED: TableDefinition<SettlementKey<'static>, SettlementReceipt<'static>> =
    TableDefinition::new("quota_settled");

/// `(tenant, scope) -> reason`. The emergency stop.
///
/// One row per standing halt and nothing for the rest, so an unhalted plane
/// pays one empty range scan. In the store rather than in the process, because
/// a switch that stops only the instance it was thrown on is not a switch — it
/// is the in-process-counter failure arriving during an incident.
///
/// Keyed on the scope as well as the tenant, so a halt on one agent and a halt
/// on the whole tenant are two rows rather than one flag the last writer wins.
/// An incident that widens and then partly resolves is the ordinary shape, and
/// a single overwritable flag gets it wrong in the direction that lets work
/// through.
const HALTED: TableDefinition<(&str, &str), &str> = TableDefinition::new("quota_halted");

/// `(tenant, grant, run, dispatch) -> reserved_at`: one row per dispatch of a
/// rate-ceilinged tool.
///
/// The key is the idempotency: a retry and a recovered re-dispatch derive the
/// same `(run, dispatch)` and find their own row. The count is the rows for
/// `(tenant, grant)` inside the window.
type RateKey<'a> = (&'a str, &'a str, &'a str, &'a str);
const RATE: TableDefinition<RateKey<'static>, i64> = TableDefinition::new("quota_rate");

// `reserve` is one write transaction deciding a slot and a spend hold
// together, and splitting it would split the decision it exists to keep whole.
#[allow(clippy::too_many_lines)]
#[async_trait]
impl QuotaStore for RedbStore {
    fn tenant(&self) -> &str {
        crate::journal::JournalStore::tenant(self)
    }

    async fn reserve(
        &self,
        run: RunId,
        quota: &TenantQuota,
        hold: Option<&SpendHold>,
        at: Timestamp,
    ) -> Result<(), QuotaError> {
        let tenant = self.tenant_name();
        let run = run.to_string();
        let at = at.unix_timestamp();
        let limit = quota.max_concurrent_runs;
        let quota = *quota;
        let hold = hold.cloned();

        // The refusal comes back as a **value**, not an error message. Packing
        // "at the ceiling" into a `StoreError` string would mean the caller
        // decides behaviour by matching on prose, and the first person to
        // reword that prose silently turns every refusal into an outage.
        let taken: Result<(), QuotaError> = self
            .with_db(move |db| {
                // One write transaction for the counts *and* the inserts. redb
                // has a single writer, so this is atomic against every other
                // admission on this store — the whole guarantee: a read followed
                // by a write lets two admissions through one remaining slot, or
                // one remaining unit of the period.
                let w = begin_write(db)?;
                let outcome = {
                    let mut running = w.open_table(RUNNING).map_err(|e| be(&e))?;
                    let mut reserved = w.open_table(RESERVED).map_err(|e| be(&e))?;

                    // Idempotent per run: a retried admission must not consume a
                    // second slot, nor fail against a ceiling it is already
                    // counted in.
                    let slot_held = running
                        .get((tenant.as_str(), run.as_str()))
                        .map_err(|e| be(&e))?
                        .is_some();

                    let mut refused = None;
                    if !slot_held && let Some(limit) = limit {
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
                            refused = Some(QuotaError::TooManyRuns {
                                tenant: tenant.clone(),
                                running: n,
                            });
                        }
                    }

                    // The spend hold, decided in the same transaction as the
                    // slot: settled plus everything already held in the period
                    // plus this. A run already holding spend is a retried
                    // admission and takes nothing more.
                    let fresh_hold = match &hold {
                        Some(hold)
                            if reserved
                                .get((tenant.as_str(), run.as_str()))
                                .map_err(|e| be(&e))?
                                .is_none() =>
                        {
                            Some(hold)
                        }
                        _ => None,
                    };
                    if refused.is_none()
                        && let Some(hold) = fresh_hold
                    {
                        let settled = w
                            .open_table(SPENT)
                            .map_err(|e| be(&e))?
                            .get((tenant.as_str(), hold.period.as_str()))
                            .map_err(|e| be(&e))?
                            .map_or((0, 0), |v| v.value());
                        let outstanding = held_in(&reserved, &tenant, &hold.period)?;
                        if let Err(e) = crate::quota::check_spend(
                            &tenant,
                            &hold.period,
                            &quota,
                            Spend {
                                tokens: settled.0,
                                minor_units: settled.1,
                            },
                            outstanding,
                            hold.amount,
                        ) {
                            refused = Some(e);
                        }
                    }

                    if let Some(refusal) = refused {
                        Err(refusal)
                    } else {
                        running
                            .insert((tenant.as_str(), run.as_str()), at)
                            .map_err(|e| be(&e))?;
                        if let Some(hold) = fresh_hold {
                            reserved
                                .insert(
                                    (tenant.as_str(), run.as_str()),
                                    (
                                        hold.period.as_str(),
                                        hold.amount.tokens,
                                        hold.amount.minor_units,
                                    ),
                                )
                                .map_err(|e| be(&e))?;
                        }
                        Ok(())
                    }
                };
                w.commit().map_err(|e| be(&e))?;
                Ok(outcome)
            })
            .await?;

        taken
    }

    async fn reserve_rate(&self, reservation: &RateReservation) -> Result<(), QuotaError> {
        let tenant = self.tenant_name();
        let reservation = reservation.clone();
        let taken: Result<(), QuotaError> = self
            .with_db(move |db| {
                // One write transaction for the count and the insert: redb's
                // single writer is the serialisation the ceiling needs.
                let w = begin_write(db)?;
                let outcome = {
                    let mut rate = w.open_table(RATE).map_err(|e| be(&e))?;
                    let grant = reservation.grant.as_str();
                    let run = reservation.run.to_string();
                    let dispatch = reservation.dispatch.to_hex();
                    let held = rate
                        .get((tenant.as_str(), grant, run.as_str(), dispatch.as_str()))
                        .map_err(|e| be(&e))?
                        .is_some();
                    if held {
                        Ok(())
                    } else {
                        let floor =
                            crate::quota::rate_prune_floor(reservation.at, &reservation.ceilings);
                        let (instants, stale) = rate_rows(&rate, &tenant, grant, floor)?;
                        for key in &stale {
                            rate.remove((tenant.as_str(), grant, key.0.as_str(), key.1.as_str()))
                                .map_err(|e| be(&e))?;
                        }
                        let verdict = if reservation.exempt {
                            Ok(())
                        } else {
                            crate::quota::check_rate(
                                &tenant,
                                grant,
                                &reservation.ceilings,
                                &instants,
                                reservation.at,
                            )
                        };
                        if verdict.is_ok() {
                            rate.insert(
                                (tenant.as_str(), grant, run.as_str(), dispatch.as_str()),
                                reservation.at.unix_timestamp(),
                            )
                            .map_err(|e| be(&e))?;
                        }
                        verdict
                    }
                };
                w.commit().map_err(|e| be(&e))?;
                Ok(outcome)
            })
            .await?;
        taken
    }

    async fn rate_room(
        &self,
        grant: &str,
        ceilings: &[RateCeiling],
        at: Timestamp,
    ) -> Result<(), QuotaError> {
        let tenant = self.tenant_name();
        let grant = grant.to_owned();
        let ceilings = ceilings.to_vec();
        let answer: Result<(), QuotaError> = self
            .with_db(move |db| {
                let r = db.begin_read().map_err(|e| be(&e))?;
                // Nothing has ever been reserved, so every window has room.
                let Ok(rate) = r.open_table(RATE) else {
                    return Ok(Ok(()));
                };
                let (instants, _) = rate_rows(&rate, &tenant, &grant, i64::MIN)?;
                Ok(crate::quota::check_rate(
                    &tenant, &grant, &ceilings, &instants, at,
                ))
            })
            .await?;
        answer
    }

    async fn set_halt(
        &self,
        scope: &HaltScope,
        by: &crate::core::Operator,
        at: crate::core::Timestamp,
        reason: &str,
    ) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let scope = scope.key();
        // Encoded through the one row type both backends share, so a field
        // added to a halt cannot reach one store and miss the other.
        let row = serde_json::to_string(&super::HaltRow {
            reason: reason.to_owned(),
            by: by.clone(),
            at,
        })
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut halted = w.open_table(HALTED).map_err(|e| be(&e))?;
                halted
                    .insert((tenant.as_str(), scope.as_str()), row.as_str())
                    .map_err(|e| be(&e))?;
            }
            w.commit().map_err(|e| be(&e))
        })
        .await
    }

    async fn lift_halt(&self, scope: &HaltScope) -> Result<bool, StoreError> {
        let tenant = self.tenant_name();
        let scope = scope.key();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let standing = {
                let mut halted = w.open_table(HALTED).map_err(|e| be(&e))?;
                halted
                    .remove((tenant.as_str(), scope.as_str()))
                    .map_err(|e| be(&e))?
                    .is_some()
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(standing)
        })
        .await
    }

    async fn halts(&self) -> Result<Vec<Halt>, StoreError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            // An absent table is an unhalted plane, not an error: nothing has
            // ever been halted, so there is nothing to read.
            let Ok(halted) = r.open_table(HALTED) else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for entry in halted
                .range((tenant.as_str(), "")..=(tenant.as_str(), MAX_STR))
                .map_err(|e| be(&e))?
            {
                let (key, row) = entry.map_err(|e| be(&e))?;
                let stored = key.value().1.to_owned();
                // Corruption, not a row to skip. A halt this build cannot read
                // is one it would otherwise run straight through, and from the
                // outside that is indistinguishable from a halt that was lifted.
                let scope = HaltScope::parse(&stored).ok_or_else(|| StoreError::Corrupt {
                    seq: 0,
                    detail: format!(
                        "quota_halted holds the scope '{stored}', which this build cannot \
                         read — refusing rather than admitting work an operator stopped"
                    ),
                })?;
                // The row is held to the same standard as the scope: a halt
                // whose operator this build cannot read is still a halt, and
                // guessing at who threw it is worse than refusing.
                let row: super::HaltRow =
                    serde_json::from_str(row.value()).map_err(|e| StoreError::Corrupt {
                        seq: 0,
                        detail: format!(
                            "quota_halted holds a row for '{stored}' this build cannot read \
                             ({e}) — refusing rather than admitting work an operator stopped"
                        ),
                    })?;
                out.push(super::halt_from_row(scope, row));
            }
            Ok(out)
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
                let mut reserved = w.open_table(RESERVED).map_err(|e| be(&e))?;
                reserved
                    .remove((tenant.as_str(), run.as_str()))
                    .map_err(|e| be(&e))?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn carry(&self, run: RunId, period: &str) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let run = run.to_string();
        let period = period.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut reserved = w.open_table(RESERVED).map_err(|e| be(&e))?;
                let row = reserved
                    .get((tenant.as_str(), run.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|v| {
                        let (p, tokens, minor) = v.value();
                        (p.to_owned(), tokens, minor)
                    });
                if let Some((held_in, tokens, minor)) = row
                    && held_in != period
                {
                    reserved
                        .insert(
                            (tenant.as_str(), run.as_str()),
                            (period.as_str(), tokens, minor),
                        )
                        .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))
        })
        .await
    }

    async fn reservations(&self, limit: usize) -> Result<Vec<Held>, StoreError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(t) = r.open_table(RESERVED) else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for e in t
                .range((tenant.as_str(), "")..=(tenant.as_str(), MAX_STR))
                .map_err(|e| be(&e))?
            {
                if out.len() >= limit {
                    break;
                }
                let (k, v) = e.map_err(|e| be(&e))?;
                let raw = k.value().1;
                let (period, tokens, minor_units) = v.value();
                // Damage, not absence, for the reason the slot listing gives:
                // a skipped row is a hold nobody can find.
                out.push(Held {
                    run: RunId::parse(raw).map_err(|e| StoreError::Corrupt {
                        seq: 0,
                        detail: format!("bad run id '{raw}' in the quota hold table: {e}"),
                    })?,
                    period: period.to_owned(),
                    remaining: Spend {
                        tokens,
                        minor_units,
                    },
                });
            }
            Ok(out)
        })
        .await
    }

    async fn reserved(&self, period: &str) -> Result<Spend, StoreError> {
        let tenant = self.tenant_name();
        let period = period.to_owned();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(t) = r.open_table(RESERVED) else {
                return Ok(Spend::default());
            };
            held_in(&t, &tenant, &period)
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
                u8::from(settlement.concludes),
            );
            let fresh = {
                let mut settled = w.open_table(SETTLED).map_err(|e| be(&e))?;
                let stored = settled
                    .get((tenant.as_str(), run.as_str(), settlement.epoch))
                    .map_err(|e| be(&e))?
                    .map(|value| {
                        let (period, tokens, minor_units, release_slot, concludes) = value.value();
                        (
                            period.to_owned(),
                            tokens,
                            minor_units,
                            release_slot,
                            concludes,
                        )
                    });
                match stored {
                    Some(stored)
                        if stored
                            != (
                                period.to_owned(),
                                receipt.1,
                                receipt.2,
                                receipt.3,
                                receipt.4,
                            ) =>
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
            // The pass's spend leaves the run's hold as it enters the settled
            // total, so the period counts it once; the concluding pass gives
            // back what the run never spent.
            {
                let mut reserved = w.open_table(RESERVED).map_err(|e| be(&e))?;
                let row = reserved
                    .get((tenant.as_str(), run.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|v| {
                        let (p, tokens, minor) = v.value();
                        (p.to_owned(), tokens, minor)
                    });
                if settlement.concludes {
                    reserved
                        .remove((tenant.as_str(), run.as_str()))
                        .map_err(|e| be(&e))?;
                } else if let Some((held_in, tokens, minor)) = row {
                    reserved
                        .insert(
                            (tenant.as_str(), run.as_str()),
                            (
                                held_in.as_str(),
                                tokens.saturating_sub(settlement.spend.tokens),
                                minor.saturating_sub(settlement.spend.minor_units),
                            ),
                        )
                        .map_err(|e| be(&e))?;
                }
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

    async fn running_runs(&self, limit: usize) -> Result<Vec<RunId>, StoreError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(t) = r.open_table(RUNNING) else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for e in t
                .range((tenant.as_str(), "")..=(tenant.as_str(), MAX_STR))
                .map_err(|e| be(&e))?
            {
                if out.len() >= limit {
                    break;
                }
                let (k, _) = e.map_err(|e| be(&e))?;
                let raw = k.value().1;
                // A key this store cannot read is damage, not absence: skipping
                // it would hide exactly the stranded slot this listing exists to
                // name, and hide it as a shorter list nobody can tell from a
                // shorter queue.
                out.push(RunId::parse(raw).map_err(|e| StoreError::Corrupt {
                    seq: 0,
                    detail: format!("bad run id '{raw}' in the quota slot table: {e}"),
                })?);
            }
            Ok(out)
        })
        .await
    }
}

/// What this tenant's open runs hold against `period`.
fn held_in<T: ReadableTable<(&'static str, &'static str), HoldRow<'static>>>(
    table: &T,
    tenant: &str,
    period: &str,
) -> Result<Spend, StoreError> {
    let mut total = Spend::default();
    for e in table
        .range((tenant, "")..=(tenant, MAX_STR))
        .map_err(|e| be(&e))?
    {
        let (_, v) = e.map_err(|e| be(&e))?;
        let (held_in, tokens, minor_units) = v.value();
        if held_in == period {
            total += Spend {
                tokens,
                minor_units,
            };
        }
    }
    Ok(total)
}

/// The reservation instants held for `(tenant, grant)`, and the `(run,
/// dispatch)` of each row at or before `floor`, which no ceiling counts.
type StaleRow = (String, String);
fn rate_rows<T: ReadableTable<RateKey<'static>, i64>>(
    table: &T,
    tenant: &str,
    grant: &str,
    floor: i64,
) -> Result<(Vec<i64>, Vec<StaleRow>), StoreError> {
    let mut instants = Vec::new();
    let mut stale = Vec::new();
    for e in table
        .range((tenant, grant, "", "")..=(tenant, grant, MAX_STR, MAX_STR))
        .map_err(|e| be(&e))?
    {
        let (k, v) = e.map_err(|e| be(&e))?;
        let at = v.value();
        if at <= floor {
            let (_, _, run, dispatch) = k.value();
            stale.push((run.to_owned(), dispatch.to_owned()));
        } else {
            instants.push(at);
        }
    }
    Ok((instants, stale))
}
