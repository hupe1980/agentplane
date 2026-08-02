//! Durable timers on redb.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::case::TimerStore;
use crate::core::{CaseId, EffectKey, Phase, RunId, StoreError, Timer, Timestamp};

use super::redb::{MAX_STR, RedbStore, be};

/// `(run_id, effect_key) -> (case_id, has_case, step, phase, fire_at, claimed_at, has_claim)`.
const TIMERS: TableDefinition<(&str, &str), (&str, u8, u32, &str, i64, i64, u8)> =
    TableDefinition::new("timers");

/// `(fire_at, run_id, effect_key) -> ()`. The sweep's only access path.
const TIMERS_DUE: TableDefinition<(i64, &str, &str), ()> = TableDefinition::new("timers_due");

/// How long a claim holds before another sweep may take the timer.
///
/// A claim is a lease, not a permanent mark. A sweeper that dies between
/// claiming a timer and journaling its wake-up would otherwise strand the
/// sleeping run forever — the row stays claimed, no sweep touches it again, and
/// the run waits for an instant that already passed. Re-firing is safe: the
/// wake-up is recorded under a fixed effect key, so a second write is the same
/// write.
const CLAIM_LEASE: i64 = 60;

fn phase_str(p: Phase) -> &'static str {
    match p {
        Phase::Forward => "forward",
        Phase::Compensating => "compensating",
    }
}

fn phase_from(s: &str) -> Phase {
    match s {
        "compensating" => Phase::Compensating,
        // An unknown value can only come from a future version. Treating it as
        // forward keeps the read total rather than failing a wake-up on a
        // column it does not recognise.
        _ => Phase::Forward,
    }
}

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
        phase: phase_from(phase),
        fire_at: Timestamp::from_unix_timestamp(fire_at).map_err(|e| StoreError::Corrupt {
            seq: 0,
            detail: format!("unrepresentable timestamp {fire_at}: {e}"),
        })?,
    })
}

#[async_trait]
impl TimerStore for RedbStore {
    async fn arm(&self, timer: &Timer) -> Result<(), StoreError> {
        let (run, effect) = (timer.run.to_string(), timer.effect.to_hex());
        let case = timer.case.map(|c| c.to_string()).unwrap_or_default();
        let has_case = u8::from(timer.case.is_some());
        let step = timer.step.0;
        let phase = phase_str(timer.phase);
        let fire_at = timer.fire_at.unix_timestamp();
        self.with_db(move |db| {
            let w = db.begin_write().map_err(|e| be(&e))?;
            {
                let mut t = w.open_table(TIMERS).map_err(|e| be(&e))?;
                // First arming wins: re-arming must not move a timer somebody
                // may already have claimed.
                if t.get((run.as_str(), effect.as_str()))
                    .map_err(|e| be(&e))?
                    .is_none()
                {
                    t.insert(
                        (run.as_str(), effect.as_str()),
                        (case.as_str(), has_case, step, phase, fire_at, 0, 0),
                    )
                    .map_err(|e| be(&e))?;
                    w.open_table(TIMERS_DUE)
                        .map_err(|e| be(&e))?
                        .insert((fire_at, run.as_str(), effect.as_str()), ())
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
        self.with_db(move |db| {
            let w = db.begin_write().map_err(|e| be(&e))?;
            let out = {
                // Selected and claimed in one transaction: a second sweeper
                // reading concurrently finds nothing rather than a second copy
                // of the same wake-up.
                let due = w.open_table(TIMERS_DUE).map_err(|e| be(&e))?;
                let mut candidates = Vec::new();
                for e in due
                    .range((i64::MIN, "", "")..=(cutoff, MAX_STR, MAX_STR))
                    .map_err(|e| be(&e))?
                {
                    if candidates.len() >= limit {
                        break;
                    }
                    let (k, _) = e.map_err(|e| be(&e))?;
                    let (_, run, effect) = k.value();
                    candidates.push((run.to_owned(), effect.to_owned()));
                }
                drop(due);

                let mut timers = w.open_table(TIMERS).map_err(|e| be(&e))?;
                let mut out = Vec::new();
                for (run, effect) in candidates {
                    let Some(row) = timers
                        .get((run.as_str(), effect.as_str()))
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
                            (run.as_str(), effect.as_str()),
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
                out
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(out)
        })
        .await
    }

    async fn pending_count(&self) -> Result<u64, StoreError> {
        self.with_db(|db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            r.open_table(TIMERS)
                .map_err(|e| be(&e))?
                .len()
                .map_err(|e| be(&e))
        })
        .await
    }

    async fn disarm(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError> {
        let (run, effect) = (run.to_string(), effect.to_hex());
        self.with_db(move |db| {
            let w = db.begin_write().map_err(|e| be(&e))?;
            {
                let mut t = w.open_table(TIMERS).map_err(|e| be(&e))?;
                if let Some(v) = t
                    .remove((run.as_str(), effect.as_str()))
                    .map_err(|e| be(&e))?
                {
                    let fire_at = v.value().4;
                    drop(v);
                    // The index entry goes in the same transaction, so a
                    // disarmed timer cannot be left findable by the sweep.
                    w.open_table(TIMERS_DUE)
                        .map_err(|e| be(&e))?
                        .remove((fire_at, run.as_str(), effect.as_str()))
                        .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn pending(&self, limit: usize) -> Result<Vec<Timer>, StoreError> {
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let due = r.open_table(TIMERS_DUE).map_err(|e| be(&e))?;
            let timers = r.open_table(TIMERS).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            for e in due.iter().map_err(|e| be(&e))? {
                if out.len() >= limit {
                    break;
                }
                let (k, _) = e.map_err(|e| be(&e))?;
                let (_, run, effect) = k.value();
                if let Some(v) = timers.get((run, effect)).map_err(|e| be(&e))? {
                    let (c, hc, st, ph, fa, _, _) = v.value();
                    out.push(build(run, effect, c, hc, st, ph, fa)?);
                }
            }
            Ok(out)
        })
        .await
    }
}

/// Whether a run still has an armed timer.
///
/// Used by tests and by operator tooling; the sweep uses `claim_due`.
impl RedbStore {
    /// # Errors
    ///
    /// If the count cannot be read.
    pub async fn armed_timers(&self, run: RunId) -> Result<usize, StoreError> {
        let run = run.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(TIMERS).map_err(|e| be(&e))?;
            let n = t
                .range((run.as_str(), "")..=(run.as_str(), MAX_STR))
                .map_err(|e| be(&e))?
                .count();
            Ok(n)
        })
        .await
    }
}
