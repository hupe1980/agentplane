//! Durable timers.

use async_trait::async_trait;
use turso::params;

use crate::case::TimerStore;
use crate::core::{CaseId, EffectKey, Phase, RunId, StoreError, Timer, Timestamp};

use super::turso::{TursoStore, be, first};

pub(super) const SCHEMA: &str = "
-- Durable wake-ups. One row per (run, effect).
CREATE TABLE IF NOT EXISTS timers (
    run_id     TEXT    NOT NULL,
    effect_key TEXT    NOT NULL,
    case_id    TEXT,
    -- Where the sleeping step is. The fired wake-up is journaled under this
    -- position, and replay verifies effects per step.
    step       INTEGER NOT NULL,
    phase      TEXT    NOT NULL,
    fire_at    INTEGER NOT NULL,
    -- Set when a sweep takes ownership. Two sweepers against one store must not
    -- both resume the same run.
    claimed_at INTEGER,
    PRIMARY KEY (run_id, effect_key)
);

-- The sweep's only query: unclaimed and due, soonest first.
CREATE INDEX IF NOT EXISTS timers_due
    ON timers (claimed_at, fire_at);
";

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

fn row_to_timer(
    run: &str,
    effect: &str,
    case: Option<String>,
    step: i64,
    phase: &str,
    fire_at: i64,
) -> Result<Timer, StoreError> {
    Ok(Timer {
        run: RunId::parse(run).map_err(|e| StoreError::Corrupt {
            seq: 0,
            detail: format!("bad run id '{run}': {e}"),
        })?,
        case: case
            .map(|c| {
                CaseId::parse(&c).map_err(|e| StoreError::Corrupt {
                    seq: 0,
                    detail: format!("bad case id '{c}': {e}"),
                })
            })
            .transpose()?,
        effect: EffectKey::from_hex(effect).map_err(|e| StoreError::Corrupt {
            seq: 0,
            detail: format!("bad effect key '{effect}': {e}"),
        })?,
        step: crate::core::StepId(u32::try_from(step).unwrap_or(0)),
        phase: phase_from(phase),
        fire_at: Timestamp::from_unix_timestamp(fire_at).map_err(|e| StoreError::Corrupt {
            seq: 0,
            detail: format!("unrepresentable timestamp {fire_at}: {e}"),
        })?,
    })
}

#[async_trait]
impl TimerStore for TursoStore {
    async fn arm(&self, timer: &Timer) -> Result<(), StoreError> {
        let conn = self.conn().await;
        conn.execute(
            "INSERT INTO timers
               (run_id, effect_key, case_id, step, phase, fire_at, claimed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
             ON CONFLICT (run_id, effect_key) DO NOTHING",
            params![
                timer.run.to_string(),
                timer.effect.to_hex(),
                timer.case.map(|c| c.to_string()),
                i64::from(timer.step.0),
                phase_str(timer.phase),
                timer.fire_at.unix_timestamp(),
            ],
        )
        .await
        .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn claim_due(&self, now: Timestamp, limit: usize) -> Result<Vec<Timer>, StoreError> {
        let cutoff = now.unix_timestamp();
        let lim = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut conn = self.conn().await;
        let tx = conn.transaction().await.map_err(|e| be(&e))?;

        // Selected and claimed in one transaction: a second sweeper reading
        // concurrently finds nothing rather than a second copy of the same
        // wake-up.
        let mut rows = tx
            .query(
                "SELECT run_id, effect_key, case_id, step, phase, fire_at
                   FROM timers
                  WHERE fire_at <= ?1
                    AND (claimed_at IS NULL OR claimed_at <= ?3)
               ORDER BY fire_at ASC
                  LIMIT ?2",
                params![cutoff, lim, cutoff - CLAIM_LEASE],
            )
            .await
            .map_err(|e| be(&e))?;

        let mut raw = Vec::new();
        while let Some(r) = rows.next().await.map_err(|e| be(&e))? {
            raw.push((
                r.get::<String>(0).map_err(|e| be(&e))?,
                r.get::<String>(1).map_err(|e| be(&e))?,
                r.get::<Option<String>>(2).map_err(|e| be(&e))?,
                r.get::<i64>(3).map_err(|e| be(&e))?,
                r.get::<String>(4).map_err(|e| be(&e))?,
                r.get::<i64>(5).map_err(|e| be(&e))?,
            ));
        }
        drop(rows);

        let mut out = Vec::with_capacity(raw.len());
        for (run, effect, case, step, phase, fire_at) in raw {
            tx.execute(
                "UPDATE timers SET claimed_at = ?3
                  WHERE run_id = ?1 AND effect_key = ?2",
                params![run.clone(), effect.clone(), cutoff],
            )
            .await
            .map_err(|e| be(&e))?;
            out.push(row_to_timer(&run, &effect, case, step, &phase, fire_at)?);
        }

        tx.commit().await.map_err(|e| be(&e))?;
        Ok(out)
    }

    async fn pending_count(&self) -> Result<u64, StoreError> {
        let conn = self.conn().await;
        let rows = conn
            .query("SELECT COUNT(*) FROM timers", ())
            .await
            .map_err(|e| be(&e))?;
        let n: i64 = match first(rows).await? {
            Some(r) => r.get(0).map_err(|e| be(&e))?,
            None => 0,
        };
        Ok(u64::try_from(n).unwrap_or(0))
    }

    async fn disarm(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError> {
        let conn = self.conn().await;
        conn.execute(
            "DELETE FROM timers WHERE run_id = ?1 AND effect_key = ?2",
            params![run.to_string(), effect.to_hex()],
        )
        .await
        .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn pending(&self, limit: usize) -> Result<Vec<Timer>, StoreError> {
        let lim = i64::try_from(limit).unwrap_or(i64::MAX);
        let conn = self.conn().await;
        let mut rows = conn
            .query(
                "SELECT run_id, effect_key, case_id, step, phase, fire_at
                   FROM timers
               ORDER BY fire_at ASC
                  LIMIT ?1",
                params![lim],
            )
            .await
            .map_err(|e| be(&e))?;

        let mut out = Vec::new();
        while let Some(r) = rows.next().await.map_err(|e| be(&e))? {
            let run: String = r.get(0).map_err(|e| be(&e))?;
            let effect: String = r.get(1).map_err(|e| be(&e))?;
            let case: Option<String> = r.get(2).map_err(|e| be(&e))?;
            let step: i64 = r.get(3).map_err(|e| be(&e))?;
            let phase: String = r.get(4).map_err(|e| be(&e))?;
            let fire_at: i64 = r.get(5).map_err(|e| be(&e))?;
            out.push(row_to_timer(&run, &effect, case, step, &phase, fire_at)?);
        }
        Ok(out)
    }
}

/// Whether a run still has an armed timer.
///
/// Used by tests and by operator tooling; the sweep uses `claim_due`.
impl TursoStore {
    /// # Errors
    ///
    /// If the count cannot be read.
    pub async fn armed_timers(&self, run: RunId) -> Result<usize, StoreError> {
        let conn = self.conn().await;
        let rows = conn
            .query(
                "SELECT COUNT(*) FROM timers WHERE run_id = ?1",
                params![run.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        let n: i64 = match first(rows).await? {
            Some(r) => r.get(0).map_err(|e| be(&e))?,
            None => 0,
        };
        Ok(usize::try_from(n).unwrap_or(0))
    }
}
