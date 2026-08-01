//! Case storage.
//!
//! Two constraints carry the correctness here, both expressed in the schema
//! rather than in application code:
//!
//! * A **unique index on `(namespace, value)` for open cases** makes
//!   "concurrent messages for one new case produce one case" a database
//!   invariant. Without it, two inbound messages racing at admission fragment a
//!   process across two cases, and its obligations are tracked in neither.
//! * An index on `(state, resolved_at)` keeps the deadline sweep a range scan
//!   at a hundred thousand open obligations, rather than a table scan that
//!   quietly stops running on time.

use async_trait::async_trait;
use serde_json::Value;
use turso::{Row, params};

use crate::case::{CaseCensus, CaseStore, Correlation};
use crate::core::{
    Case, CaseId, CaseStatus, CaseVersion, CorrelationKey, Deadline, DeadlineState, Digest, RunId,
    StoreError, Timestamp,
};

use super::turso::{TursoStore, be, first};

pub(super) const CASE_SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS cases (
    case_id   TEXT PRIMARY KEY,
    kind      TEXT    NOT NULL,
    status    TEXT    NOT NULL,
    state     TEXT    NOT NULL,
    -- Bumped by every state write, which must name the version it read. The
    -- read-to-write window on a case contains a model call, so two runs on one
    -- case overlap as a matter of course; without this a blind UPDATE silently
    -- discards whichever write lost the race.
    version   INTEGER NOT NULL DEFAULT 0,
    opened_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS cases_status ON cases (status, opened_at DESC);

CREATE TABLE IF NOT EXISTS case_correlation (
    case_id   TEXT NOT NULL REFERENCES cases (case_id) ON DELETE CASCADE,
    namespace TEXT NOT NULL,
    value     TEXT NOT NULL,
    open      INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (case_id, namespace, value)
);

-- One open case per business key. This is what stops two concurrent inbound
-- messages from fragmenting a process across two cases.
CREATE UNIQUE INDEX IF NOT EXISTS case_correlation_open
    ON case_correlation (namespace, value) WHERE open = 1;

CREATE TABLE IF NOT EXISTS case_runs (
    case_id TEXT NOT NULL REFERENCES cases (case_id) ON DELETE CASCADE,
    run_id  TEXT NOT NULL,
    seq     INTEGER NOT NULL,
    PRIMARY KEY (case_id, run_id)
);

CREATE TABLE IF NOT EXISTS case_deadlines (
    case_id         TEXT    NOT NULL REFERENCES cases (case_id) ON DELETE CASCADE,
    name            TEXT    NOT NULL,
    resolved_at     INTEGER NOT NULL,
    calendar_digest BLOB    NOT NULL,
    warn_at         INTEGER,
    state           TEXT    NOT NULL,
    PRIMARY KEY (case_id, name)
);

-- The sweep's access path: due and approaching obligations, in time order.
CREATE INDEX IF NOT EXISTS case_deadlines_due
    ON case_deadlines (state, resolved_at);
";

fn ts(t: Timestamp) -> i64 {
    t.unix_timestamp()
}

fn from_ts(v: i64) -> Result<Timestamp, StoreError> {
    Timestamp::from_unix_timestamp(v).map_err(|e| StoreError::Corrupt {
        seq: 0,
        detail: format!("unrepresentable timestamp {v}: {e}"),
    })
}

fn status_from(s: &str) -> Result<CaseStatus, StoreError> {
    Ok(match s {
        "open" => CaseStatus::Open,
        "awaiting_external" => CaseStatus::AwaitingExternal,
        "awaiting_human" => CaseStatus::AwaitingHuman,
        "escalated" => CaseStatus::Escalated,
        "closed" => CaseStatus::Closed,
        other => {
            return Err(StoreError::Corrupt {
                seq: 0,
                detail: format!("unknown case status '{other}'"),
            });
        }
    })
}

fn deadline_state_from(s: &str) -> Result<DeadlineState, StoreError> {
    Ok(match s {
        "pending" => DeadlineState::Pending,
        "warned" => DeadlineState::Warned,
        "breached" => DeadlineState::Breached,
        "met" => DeadlineState::Met,
        "cancelled" => DeadlineState::Cancelled,
        other => {
            return Err(StoreError::Corrupt {
                seq: 0,
                detail: format!("unknown deadline state '{other}'"),
            });
        }
    })
}

/// One `case_deadlines` row, before validation.
///
/// Kept as a named struct rather than a tuple so the mapping from column order
/// to meaning is stated once, where a mis-ordered `row.get` would otherwise be
/// invisible.
struct DeadlineRow {
    case: String,
    name: String,
    resolved_at: i64,
    calendar_digest: Vec<u8>,
    warn_at: Option<i64>,
    state: String,
}

fn deadline_from_row(row: &Row) -> Result<DeadlineRow, StoreError> {
    Ok(DeadlineRow {
        case: row.get(0).map_err(|e| be(&e))?,
        name: row.get(1).map_err(|e| be(&e))?,
        resolved_at: row.get(2).map_err(|e| be(&e))?,
        calendar_digest: row.get(3).map_err(|e| be(&e))?,
        warn_at: row.get(4).map_err(|e| be(&e))?,
        state: row.get(5).map_err(|e| be(&e))?,
    })
}

/// Every deadline a query returns, validated.
async fn deadlines_from(mut rows: turso::Rows) -> Result<Vec<Deadline>, StoreError> {
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(|e| be(&e))? {
        out.push(build_deadline(deadline_from_row(&row)?)?);
    }
    Ok(out)
}

fn build_deadline(r: DeadlineRow) -> Result<Deadline, StoreError> {
    let bytes: [u8; 32] = r
        .calendar_digest
        .try_into()
        .map_err(|_| StoreError::Corrupt {
            seq: 0,
            detail: "stored calendar digest is not 32 bytes".into(),
        })?;
    Ok(Deadline {
        case: CaseId::parse(&r.case).map_err(|e| StoreError::Corrupt {
            seq: 0,
            detail: format!("bad case id '{}': {e}", r.case),
        })?,
        name: r.name,
        resolved_at: from_ts(r.resolved_at)?,
        calendar_digest: Digest::from_bytes(bytes),
        warn_at: r.warn_at.map(from_ts).transpose()?,
        state: deadline_state_from(&r.state)?,
    })
}

#[async_trait]
impl CaseStore for TursoStore {
    async fn correlate(&self, keys: &[CorrelationKey]) -> Result<Option<CaseId>, StoreError> {
        if keys.is_empty() {
            return Ok(None);
        }
        let conn = self.conn().await;
        for k in keys {
            let rows = conn
                .query(
                    "SELECT case_id FROM case_correlation
                     WHERE namespace = ?1 AND value = ?2 AND open = 1",
                    params![k.namespace.clone(), k.value.clone()],
                )
                .await
                .map_err(|e| be(&e))?;
            if let Some(row) = first(rows).await? {
                let id: String = row.get(0).map_err(|e| be(&e))?;
                return CaseId::parse(&id)
                    .map(Some)
                    .map_err(|e| StoreError::Corrupt {
                        seq: 0,
                        detail: format!("bad case id '{id}': {e}"),
                    });
            }
        }
        Ok(None)
    }

    async fn correlate_or_open(
        &self,
        kind: &str,
        keys: &[CorrelationKey],
        at: Timestamp,
    ) -> Result<Correlation, StoreError> {
        let mut conn = self.conn().await;
        let tx = conn.transaction().await.map_err(|e| be(&e))?;

        // Look inside the transaction so a concurrent opener cannot slip
        // between the check and the insert.
        for k in keys {
            let rows = tx
                .query(
                    "SELECT case_id FROM case_correlation
                     WHERE namespace = ?1 AND value = ?2 AND open = 1",
                    params![k.namespace.clone(), k.value.clone()],
                )
                .await
                .map_err(|e| be(&e))?;
            if let Some(row) = first(rows).await? {
                let id: String = row.get(0).map_err(|e| be(&e))?;
                tx.commit().await.map_err(|e| be(&e))?;
                let id = CaseId::parse(&id).map_err(|e| StoreError::Corrupt {
                    seq: 0,
                    detail: format!("bad case id '{id}': {e}"),
                })?;
                return Ok(Correlation::Attached(id));
            }
        }

        let id = CaseId::generate();
        tx.execute(
            "INSERT INTO cases (case_id, kind, status, state, opened_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id.to_string(),
                kind.to_owned(),
                CaseStatus::Open.as_str(),
                "null",
                ts(at)
            ],
        )
        .await
        .map_err(|e| be(&e))?;

        for k in keys {
            tx.execute(
                "INSERT INTO case_correlation (case_id, namespace, value, open)
                 VALUES (?1, ?2, ?3, 1)",
                params![id.to_string(), k.namespace.clone(), k.value.clone()],
            )
            .await
            .map_err(|e| match e {
                // Lost the race: someone opened a case for this key between our
                // read and our write.
                turso::Error::Constraint(_) => StoreError::Backend(format!(
                    "correlation key {k} was claimed concurrently — retry"
                )),
                other => be(&other),
            })?;
        }

        tx.commit().await.map_err(|e| be(&e))?;
        Ok(Correlation::Opened(id))
    }

    async fn case(&self, id: CaseId) -> Result<Option<Case>, StoreError> {
        let conn = self.conn().await;
        let rows = conn
            .query(
                "SELECT kind, status, state, opened_at, version FROM cases WHERE case_id = ?1",
                params![id.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        let Some(row) = first(rows).await? else {
            return Ok(None);
        };
        let kind: String = row.get(0).map_err(|e| be(&e))?;
        let status: String = row.get(1).map_err(|e| be(&e))?;
        let state: String = row.get(2).map_err(|e| be(&e))?;
        let opened: i64 = row.get(3).map_err(|e| be(&e))?;
        let version: i64 = row.get(4).map_err(|e| be(&e))?;

        let mut corr_rows = conn
            .query(
                "SELECT namespace, value FROM case_correlation
                 WHERE case_id = ?1 ORDER BY namespace, value",
                params![id.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        let mut correlation = Vec::new();
        while let Some(r) = corr_rows.next().await.map_err(|e| be(&e))? {
            correlation.push(CorrelationKey::new(
                r.get::<String>(0).map_err(|e| be(&e))?,
                r.get::<String>(1).map_err(|e| be(&e))?,
            ));
        }

        let mut run_rows = conn
            .query(
                "SELECT run_id FROM case_runs WHERE case_id = ?1 ORDER BY seq",
                params![id.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        let mut runs = Vec::new();
        while let Some(r) = run_rows.next().await.map_err(|e| be(&e))? {
            let s: String = r.get(0).map_err(|e| be(&e))?;
            runs.push(RunId::parse(&s).map_err(|e| StoreError::Corrupt {
                seq: 0,
                detail: format!("bad run id '{s}': {e}"),
            })?);
        }

        Ok(Some(Case {
            id,
            kind,
            status: status_from(&status)?,
            correlation,
            state: serde_json::from_str(&state).unwrap_or(Value::Null),
            version: CaseVersion(u64::try_from(version).unwrap_or(0)),
            opened_at: from_ts(opened)?,
            runs,
        }))
    }

    async fn attach_run(&self, case: CaseId, run: RunId) -> Result<(), StoreError> {
        let conn = self.conn().await;
        conn.execute(
            "INSERT INTO case_runs (case_id, run_id, seq)
             VALUES (?1, ?2, (SELECT COALESCE(MAX(seq), 0) + 1 FROM case_runs WHERE case_id = ?1))
             ON CONFLICT (case_id, run_id) DO NOTHING",
            params![case.to_string(), run.to_string()],
        )
        .await
        .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn put_state(
        &self,
        case: CaseId,
        expected: CaseVersion,
        state: Value,
    ) -> Result<CaseVersion, StoreError> {
        let conn = self.conn().await;
        let encoded = serde_json::to_string(&state)?;
        let next = expected.next();
        // One statement. A read followed by a write would leave a window the
        // next caller can race, which is the whole thing being prevented — so
        // the version check is a predicate on the UPDATE.
        let n = conn
            .execute(
                "UPDATE cases SET state = ?2, version = ?3 \
                 WHERE case_id = ?1 AND version = ?4",
                params![
                    case.to_string(),
                    encoded,
                    i64::try_from(next.0).unwrap_or(i64::MAX),
                    i64::try_from(expected.0).unwrap_or(i64::MAX),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        if n == 1 {
            return Ok(next);
        }
        // Nothing matched: either the case is gone or it has moved on. The
        // caller needs to know which — a missing case reported as a conflict
        // sends them into a re-read loop against nothing.
        let rows = conn
            .query(
                "SELECT version FROM cases WHERE case_id = ?1",
                params![case.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        match first(rows).await? {
            Some(row) => {
                let current: i64 = row.get(0).map_err(|e| be(&e))?;
                Err(StoreError::CaseConflict {
                    case: case.to_string(),
                    expected: expected.0,
                    current: u64::try_from(current).unwrap_or(0),
                })
            }
            None => Err(StoreError::NotFound(case.to_string())),
        }
    }

    async fn set_status(&self, case: CaseId, status: CaseStatus) -> Result<(), StoreError> {
        let conn = self.conn().await;
        let n = conn
            .execute(
                "UPDATE cases SET status = ?2 WHERE case_id = ?1",
                params![case.to_string(), status.as_str()],
            )
            .await
            .map_err(|e| be(&e))?;
        if n == 0 {
            return Err(StoreError::NotFound(case.to_string()));
        }
        Ok(())
    }

    async fn close(&self, case: CaseId) -> Result<(), StoreError> {
        let mut conn = self.conn().await;
        let tx = conn.transaction().await.map_err(|e| be(&e))?;

        // A case with an unmet obligation may not be closed. This is the check
        // that stops a missed regulatory window from disappearing behind a tidy
        // "closed" status.
        let rows = tx
            .query(
                "SELECT COUNT(*) FROM case_deadlines
                 WHERE case_id = ?1 AND state IN ('pending', 'warned')",
                params![case.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        let open_obligations: i64 = match first(rows).await? {
            Some(row) => row.get(0).map_err(|e| be(&e))?,
            None => 0,
        };

        if open_obligations > 0 {
            return Err(StoreError::Backend(format!(
                "case {case} has {open_obligations} open deadline(s); \
                 resolve or cancel them before closing"
            )));
        }

        let n = tx
            .execute(
                "UPDATE cases SET status = 'closed' WHERE case_id = ?1",
                params![case.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        if n == 0 {
            return Err(StoreError::NotFound(case.to_string()));
        }

        // Release the correlation keys so a genuinely new matter about the same
        // entity opens a fresh case rather than reanimating this one.
        tx.execute(
            "UPDATE case_correlation SET open = 0 WHERE case_id = ?1",
            params![case.to_string()],
        )
        .await
        .map_err(|e| be(&e))?;

        tx.commit().await.map_err(|e| be(&e))?;
        Ok(())
    }

    async fn register_deadline(&self, deadline: &Deadline) -> Result<(), StoreError> {
        let conn = self.conn().await;
        conn.execute(
            "INSERT INTO case_deadlines
               (case_id, name, resolved_at, calendar_digest, warn_at, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (case_id, name) DO NOTHING",
            params![
                deadline.case.to_string(),
                deadline.name.clone(),
                ts(deadline.resolved_at),
                deadline.calendar_digest.as_bytes().to_vec(),
                deadline.warn_at.map(ts),
                deadline.state.as_str(),
            ],
        )
        .await
        .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn deadlines(&self, case: CaseId) -> Result<Vec<Deadline>, StoreError> {
        let conn = self.conn().await;
        let rows = conn
            .query(
                "SELECT case_id, name, resolved_at, calendar_digest, warn_at, state
                 FROM case_deadlines WHERE case_id = ?1 ORDER BY resolved_at",
                params![case.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        deadlines_from(rows).await
    }

    async fn set_deadline_state(
        &self,
        case: CaseId,
        name: &str,
        state: DeadlineState,
    ) -> Result<(), StoreError> {
        let conn = self.conn().await;
        let n = conn
            .execute(
                "UPDATE case_deadlines SET state = ?3 WHERE case_id = ?1 AND name = ?2",
                params![case.to_string(), name.to_owned(), state.as_str()],
            )
            .await
            .map_err(|e| be(&e))?;
        if n == 0 {
            return Err(StoreError::NotFound(format!("{case}/{name}")));
        }
        Ok(())
    }

    async fn census(&self, now: Timestamp) -> Result<CaseCensus, StoreError> {
        let conn = self.conn().await;
        // One statement, so the count and the oldest stamp cannot disagree
        // about which cases were open. MIN over `opened_at` is the whole reason
        // that column exists.
        let rows = conn
            .query(
                "SELECT COUNT(*), MIN(opened_at) FROM cases WHERE status != 'closed'",
                (),
            )
            .await
            .map_err(|e| be(&e))?;
        let (open, oldest): (i64, Option<i64>) = match first(rows).await? {
            Some(row) => (
                row.get(0).map_err(|e| be(&e))?,
                row.get(1).map_err(|e| be(&e))?,
            ),
            None => (0, None),
        };

        let rows = conn
            .query(
                "SELECT COUNT(*) FROM case_deadlines
                  WHERE state IN ('pending', 'warned') AND resolved_at <= ?1",
                params![ts(now)],
            )
            .await
            .map_err(|e| be(&e))?;
        let due: i64 = match first(rows).await? {
            Some(row) => row.get(0).map_err(|e| be(&e))?,
            None => 0,
        };

        Ok(CaseCensus {
            open: u64::try_from(open).unwrap_or(0),
            oldest_age_secs: oldest.map(|o| {
                crate::runtime::metrics::age_secs(
                    Timestamp::from_unix_timestamp(o).unwrap_or(now),
                    now,
                )
            }),
            due: u64::try_from(due).unwrap_or(0),
        })
    }

    async fn due(&self, now: Timestamp, limit: usize) -> Result<Vec<Deadline>, StoreError> {
        let conn = self.conn().await;
        let rows = conn
            .query(
                "SELECT case_id, name, resolved_at, calendar_digest, warn_at, state
                 FROM case_deadlines
                 WHERE state IN ('pending', 'warned')
                   AND (resolved_at <= ?1 OR (warn_at IS NOT NULL AND warn_at <= ?1))
                 ORDER BY resolved_at ASC LIMIT ?2",
                params![ts(now), i64::try_from(limit).unwrap_or(i64::MAX)],
            )
            .await
            .map_err(|e| be(&e))?;
        deadlines_from(rows).await
    }

    async fn by_status(&self, status: CaseStatus, limit: usize) -> Result<Vec<Case>, StoreError> {
        let ids = {
            let conn = self.conn().await;
            let mut rows = conn
                .query(
                    "SELECT case_id FROM cases WHERE status = ?1
                     ORDER BY opened_at DESC LIMIT ?2",
                    params![status.as_str(), i64::try_from(limit).unwrap_or(i64::MAX)],
                )
                .await
                .map_err(|e| be(&e))?;
            let mut out: Vec<String> = Vec::new();
            while let Some(r) = rows.next().await.map_err(|e| be(&e))? {
                out.push(r.get(0).map_err(|e| be(&e))?);
            }
            out
            // Guard released here: `case()` below takes it again, and the mutex
            // is not reentrant.
        };

        let mut cases = Vec::with_capacity(ids.len());
        for id in ids {
            let id = CaseId::parse(&id).map_err(|e| StoreError::Corrupt {
                seq: 0,
                detail: format!("bad case id '{id}': {e}"),
            })?;
            if let Some(c) = self.case(id).await? {
                cases.push(c);
            }
        }
        Ok(cases)
    }
}
