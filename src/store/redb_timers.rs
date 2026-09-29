//! Durable timers on redb.

use std::ops::Bound;

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::case::TimerStore;
use crate::core::{CaseId, EffectKey, Phase, RunId, StoreError, Timer, Timestamp};

use super::redb::{MAX_STR, RedbStore, be, begin_write, decoded, is_sealed};

fn phase_from(s: &str) -> Result<Phase, StoreError> {
    decoded("step phase", s, Phase::parse(s))
}

/// `(tenant, run_id, effect_key) -> (case_id, has_case, step, phase, fire_at,
/// claimed_at, has_claim)`.
///
/// The tenant is its own key component rather than a prefix glued onto the run
/// id: the run comes back out of the key already bare, so nothing has to parse
/// a separator back off to rebuild a `RunId`.
/// `(case_id, has_case, step, phase, fire_at, claimed_at, has_claim)`.
type TimerRow<'a> = (&'a str, u8, u32, &'a str, i64, i64, u8);

const TIMERS: TableDefinition<(&str, &str, &str), TimerRow<'static>> =
    TableDefinition::new("timers");

/// `(tenant, fire_at, run_id, effect_key) -> ()`. The sweep's only access path.
///
/// The tenant leads, so a sweep ranges over one tenant's timers rather than
/// filtering another's out afterwards. Ordering by time first would make every
/// plane walk every tenant's due set and try to claim what it found — the
/// isolation hole a `WHERE` clause is supposed to close and eventually does not.
const TIMERS_DUE: TableDefinition<(&str, i64, &str, &str), ()> = TableDefinition::new("timers_due");

/// How long a claim holds before another sweep may take the timer.
///
/// A claim is a lease, not a permanent mark. A sweeper that dies between
/// claiming a timer and journaling its wake-up would otherwise strand the
/// sleeping run forever — the row stays claimed, no sweep touches it again, and
/// the run waits for an instant that already passed. Re-firing is safe: the
/// wake-up is recorded under a fixed effect key, so a second write is the same
/// write.
const CLAIM_LEASE: i64 = 60;

pub(super) fn create_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(TIMERS).map_err(|e| be(&e))?;
    w.open_table(TIMERS_DUE).map_err(|e| be(&e))?;
    Ok(())
}

fn build(
    run: &str,
    effect: &str,
    case: &str,
    has_case: u8,
    step: u32,
    phase: &str,
    fire_at: i64,
) -> Result<Timer, StoreError> {
    Ok(Timer {
        run: RunId::parse(run).map_err(|e| StoreError::Corrupt {
            seq: 0,
            detail: format!("bad run id '{run}': {e}"),
        })?,
        case: if has_case == 1 {
            Some(CaseId::parse(case).map_err(|e| StoreError::Corrupt {
                seq: 0,
                detail: format!("bad case id '{case}': {e}"),
            })?)
        } else {
            None
        },
        effect: EffectKey::from_hex(effect).map_err(|e| StoreError::Corrupt {
            seq: 0,
            detail: format!("bad effect key '{effect}': {e}"),
        })?,
        step: crate::core::StepId(step),
        phase: phase_from(phase)?,
        fire_at: Timestamp::from_unix_timestamp(fire_at).map_err(|e| StoreError::Corrupt {
            seq: 0,
            detail: format!("unrepresentable timestamp {fire_at}: {e}"),
        })?,
    })
}

/// Remove one timer and its due-index entry, in the caller's transaction, so a
/// retired timer cannot be left findable by the sweep.
fn retire(
    w: &redb::WriteTransaction,
    tenant: &str,
    run: &str,
    effect: &str,
) -> Result<(), StoreError> {
    let mut t = w.open_table(TIMERS).map_err(|e| be(&e))?;
    if let Some(v) = t.remove((tenant, run, effect)).map_err(|e| be(&e))? {
        let fire_at = v.value().4;
        drop(v);
        w.open_table(TIMERS_DUE)
            .map_err(|e| be(&e))?
            .remove((tenant, fire_at, run, effect))
            .map_err(|e| be(&e))?;
    }
    Ok(())
}

#[async_trait]
impl TimerStore for RedbStore {
    fn tenant(&self) -> &str {
        crate::journal::JournalStore::tenant(self)
    }

    async fn arm(&self, timer: &Timer) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let (run, effect) = (timer.run.to_string(), timer.effect.to_hex());
        let case = timer.case.map(|c| c.to_string()).unwrap_or_default();
        let has_case = u8::from(timer.case.is_some());
        let step = timer.step.0;
        let phase = timer.phase.as_str();
        let fire_at = timer.fire_at.unix_timestamp();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut t = w.open_table(TIMERS).map_err(|e| be(&e))?;
                // First arming wins: re-arming must not move a timer somebody
                // may already have claimed.
                if t.get((tenant.as_str(), run.as_str(), effect.as_str()))
                    .map_err(|e| be(&e))?
                    .is_none()
                {
                    t.insert(
                        (tenant.as_str(), run.as_str(), effect.as_str()),
                        (case.as_str(), has_case, step, phase, fire_at, 0, 0),
                    )
                    .map_err(|e| be(&e))?;
                    w.open_table(TIMERS_DUE)
                        .map_err(|e| be(&e))?
                        .insert(
                            (tenant.as_str(), fire_at, run.as_str(), effect.as_str()),
                            (),
                        )
                        .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn claim_due(&self, now: Timestamp, limit: usize) -> Result<Vec<Timer>, StoreError> {
        let cutoff = now.unix_timestamp();
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let out = {
                // `limit` bounds the claims, not the candidates. Capping the
                // candidates would let a page of timers held under another
                // sweeper's live claim fill the page, and the due timers
                // behind them would never be looked at. Read in chunks, so a
                // backlog is walked only as far as it takes to fill the page.
                //
                // Selected and claimed in one transaction: a second sweeper
                // reading concurrently finds nothing rather than a second copy
                // of the same wake-up.
                let chunk = limit.max(64);
                let mut after: Option<(i64, String, String)> = None;
                let mut out = Vec::new();
                'scan: loop {
                    let candidates: Vec<(i64, String, String)> = {
                        let due = w.open_table(TIMERS_DUE).map_err(|e| be(&e))?;
                        let end = Bound::Included((tenant.as_str(), cutoff, MAX_STR, MAX_STR));
                        let start = match &after {
                            Some((at, run, effect)) => Bound::Excluded((
                                tenant.as_str(),
                                *at,
                                run.as_str(),
                                effect.as_str(),
                            )),
                            None => Bound::Included((tenant.as_str(), i64::MIN, "", "")),
                        };
                        due.range::<(&str, i64, &str, &str)>((start, end))
                            .map_err(|e| be(&e))?
                            .take(chunk)
                            .map(|e| {
                                e.map(|(k, _)| {
                                    let (_, at, run, effect) = k.value();
                                    (at, run.to_owned(), effect.to_owned())
                                })
                                .map_err(|e| be(&e))
                            })
                            .collect::<Result<_, _>>()?
                    };
                    let Some(last) = candidates.last().cloned() else {
                        break;
                    };
                    after = Some(last);
                    for (_, run, effect) in candidates {
                        if out.len() >= limit {
                            break 'scan;
                        }
                        // A sealed run can record no wake. Its timer is
                        // retired here rather than returned, or it is claimed
                        // and fails once per lease period for ever.
                        if is_sealed(&w, &tenant, &run)? {
                            retire(&w, &tenant, &run, &effect)?;
                            continue;
                        }
                        let mut timers = w.open_table(TIMERS).map_err(|e| be(&e))?;
                        let Some(row) = timers
                            .get((tenant.as_str(), run.as_str(), effect.as_str()))
                            .map_err(|e| be(&e))?
                            .map(|v| {
                                let (c, hc, st, ph, fa, ca, hca) = v.value();
                                (c.to_owned(), hc, st, ph.to_owned(), fa, ca, hca)
                            })
                        else {
                            continue;
                        };
                        let (case, has_case, step, phase, fire_at, claimed_at, has_claim) = row;
                        // An unexpired claim belongs to another sweeper.
                        if has_claim == 1 && claimed_at > cutoff - CLAIM_LEASE {
                            continue;
                        }
                        timers
                            .insert(
                                (tenant.as_str(), run.as_str(), effect.as_str()),
                                (
                                    case.as_str(),
                                    has_case,
                                    step,
                                    phase.as_str(),
                                    fire_at,
                                    cutoff,
                                    1,
                                ),
                            )
                            .map_err(|e| be(&e))?;
                        out.push(build(
                            &run, &effect, &case, has_case, step, &phase, fire_at,
                        )?);
                    }
                }
                out
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(out)
        })
        .await
    }

    async fn pending_count(&self) -> Result<u64, StoreError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(TIMERS).map_err(|e| be(&e))?;
            // Counted over this tenant's range rather than `len()` on the
            // table, like every sibling read here: a whole-table count reports
            // every tenant's timers as this one's — a gauge that reads
            // plausibly and is wrong, on the store whose keys exist precisely
            // so one tenant cannot see another's rows.
            let mut n = 0u64;
            for e in t
                .range((tenant.as_str(), "", "")..=(tenant.as_str(), MAX_STR, MAX_STR))
                .map_err(|e| be(&e))?
            {
                e.map_err(|e| be(&e))?;
                n += 1;
            }
            Ok(n)
        })
        .await
    }

    async fn disarm(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let (run, effect) = (run.to_string(), effect.to_hex());
        self.with_db(move |db| {
            let w = begin_write(db)?;
            retire(&w, &tenant, &run, &effect)?;
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn disarm_run(&self, run: RunId) -> Result<usize, StoreError> {
        let tenant = self.tenant_name();
        let run = run.to_string();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let effects: Vec<String> = {
                let t = w.open_table(TIMERS).map_err(|e| be(&e))?;
                t.range(
                    (tenant.as_str(), run.as_str(), "")..=(tenant.as_str(), run.as_str(), MAX_STR),
                )
                .map_err(|e| be(&e))?
                .map(|e| e.map(|(k, _)| k.value().2.to_owned()).map_err(|e| be(&e)))
                .collect::<Result<_, _>>()?
            };
            for effect in &effects {
                retire(&w, &tenant, &run, effect)?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(effects.len())
        })
        .await
    }
}

impl RedbStore {
    /// How many armed timers a run still has.
    ///
    /// For tests; the sweep uses `claim_due`, and an operator asking what a
    /// run waits for reads `waiting_runs`.
    ///
    /// # Errors
    ///
    /// If the count cannot be read.
    pub async fn armed_timers(&self, run: RunId) -> Result<usize, StoreError> {
        Ok(self.armed_timer_rows(run).await?.len())
    }

    /// The timers a run still has armed, as the rows the sweep would claim.
    ///
    /// For tests, like [`armed_timers`](Self::armed_timers).
    ///
    /// # Errors
    ///
    /// If the rows cannot be read or decoded.
    pub async fn armed_timer_rows(&self, run: RunId) -> Result<Vec<Timer>, StoreError> {
        let tenant = self.tenant_name();
        let run = run.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(TIMERS).map_err(|e| be(&e))?;
            t.range((tenant.as_str(), run.as_str(), "")..=(tenant.as_str(), run.as_str(), MAX_STR))
                .map_err(|e| be(&e))?
                .map(|e| {
                    let (k, v) = e.map_err(|e| be(&e))?;
                    let (_, run, effect) = k.value();
                    let (case, has_case, step, phase, fire_at, _, _) = v.value();
                    build(run, effect, case, has_case, step, phase, fire_at)
                })
                .collect()
        })
        .await
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    /// Both phases round-trip; the pair cannot drift while this passes.
    #[test]
    fn every_written_phase_decodes_to_the_value_that_wrote_it() {
        for phase in [Phase::Forward, Phase::Compensating] {
            assert_eq!(phase_from(phase.as_str()).expect("round trip"), phase);
        }
    }

    /// **A phase this store cannot read is damage, not `Forward`.**
    ///
    /// The phase tells a step's forward pass from its compensating one, so a
    /// damaged column answered `Forward` hands the unwind logic a compensating
    /// record wearing the wrong half of the saga — the same refusal the
    /// shared-store backend makes, held here so the two cannot disagree at
    /// the boundary nobody probed.
    #[test]
    fn an_unreadable_timer_phase_is_refused_rather_than_defaulted() {
        for bad in ["", "Forward", "compensating "] {
            assert!(
                matches!(phase_from(bad).err(), Some(StoreError::Corrupt { .. })),
                "phase '{bad}' decoded instead of refusing"
            );
        }
    }
}
