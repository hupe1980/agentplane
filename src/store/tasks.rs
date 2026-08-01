//! SQLite-backed worklist.
//!
//! Claiming happens inside a transaction that checks eligibility and writes the
//! holder in one step. Two reviewers opening the same queue at the same moment
//! must not both believe they hold a task — and a check followed by a separate
//! write has exactly that window.

use async_trait::async_trait;
use rusqlite::{OptionalExtension, params};

use crate::case::{ClaimError, TaskStore};
use crate::core::{
    CaseId, Justification, OnExpiry, Priority, RunId, StoreError, Task, TaskId, TaskState,
    Timestamp,
};

use super::sqlite::{SqliteStore, be};

pub(super) const TASK_SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS tasks (
    task_id         TEXT PRIMARY KEY,
    run_id          TEXT    NOT NULL,
    case_id         TEXT,
    kind            TEXT    NOT NULL,
    justification   TEXT    NOT NULL,
    candidate_roles TEXT    NOT NULL,
    excluded_actors TEXT    NOT NULL,
    assignee        TEXT,
    priority        TEXT    NOT NULL,
    state           TEXT    NOT NULL,
    on_expiry       TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    due_at          INTEGER
);

-- The operator's view: open work, most urgent and oldest first.
CREATE INDEX IF NOT EXISTS tasks_queue
    ON tasks (state, priority DESC, created_at ASC);

-- The sweep's access path: pending work whose window has closed.
CREATE INDEX IF NOT EXISTS tasks_overdue
    ON tasks (due_at) WHERE state IN ('open', 'claimed', 'escalated');

CREATE INDEX IF NOT EXISTS tasks_case ON tasks (case_id, created_at);
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

fn state_from(s: &str) -> Result<TaskState, StoreError> {
    Ok(match s {
        "open" => TaskState::Open,
        "claimed" => TaskState::Claimed,
        "completed" => TaskState::Completed,
        "expired" => TaskState::Expired,
        "escalated" => TaskState::Escalated,
        other => {
            return Err(StoreError::Corrupt {
                seq: 0,
                detail: format!("unknown task state '{other}'"),
            });
        }
    })
}

fn priority_from(s: &str) -> Priority {
    match s {
        "low" => Priority::Low,
        "high" => Priority::High,
        "urgent" => Priority::Urgent,
        _ => Priority::Normal,
    }
}

fn expiry_from(s: &str) -> OnExpiry {
    match s {
        "escalate" => OnExpiry::Escalate,
        "proceed" => OnExpiry::Proceed,
        _ => OnExpiry::Deny,
    }
}

fn expiry_str(e: OnExpiry) -> &'static str {
    match e {
        OnExpiry::Deny => "deny",
        OnExpiry::Escalate => "escalate",
        OnExpiry::Proceed => "proceed",
    }
}

/// One `tasks` row, before validation. Named rather than a tuple so the
/// column-order-to-meaning mapping is stated once.
struct TaskRow {
    task_id: String,
    run_id: String,
    case_id: Option<String>,
    kind: String,
    justification: String,
    candidate_roles: String,
    excluded_actors: String,
    assignee: Option<String>,
    priority: String,
    state: String,
    on_expiry: String,
    created_at: i64,
    due_at: Option<i64>,
}

const COLUMNS: &str = "task_id, run_id, case_id, kind, justification, candidate_roles, \
                       excluded_actors, assignee, priority, state, on_expiry, created_at, due_at";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TaskRow> {
    Ok(TaskRow {
        task_id: r.get(0)?,
        run_id: r.get(1)?,
        case_id: r.get(2)?,
        kind: r.get(3)?,
        justification: r.get(4)?,
        candidate_roles: r.get(5)?,
        excluded_actors: r.get(6)?,
        assignee: r.get(7)?,
        priority: r.get(8)?,
        state: r.get(9)?,
        on_expiry: r.get(10)?,
        created_at: r.get(11)?,
        due_at: r.get(12)?,
    })
}

fn build(r: TaskRow) -> Result<Task, StoreError> {
    let bad = |what: &str, v: &str, e: &dyn std::fmt::Display| StoreError::Corrupt {
        seq: 0,
        detail: format!("bad {what} '{v}': {e}"),
    };
    Ok(Task {
        id: TaskId::parse(&r.task_id).map_err(|e| bad("task id", &r.task_id, &e))?,
        run: RunId::parse(&r.run_id).map_err(|e| bad("run id", &r.run_id, &e))?,
        case: r
            .case_id
            .map(|c| CaseId::parse(&c).map_err(|e| bad("case id", &c, &e)))
            .transpose()?,
        kind: r.kind,
        justification: serde_json::from_str::<Justification>(&r.justification)?,
        candidate_roles: serde_json::from_str(&r.candidate_roles)?,
        excluded_actors: serde_json::from_str(&r.excluded_actors)?,
        assignee: r.assignee,
        priority: priority_from(&r.priority),
        state: state_from(&r.state)?,
        on_expiry: expiry_from(&r.on_expiry),
        created_at: from_ts(r.created_at)?,
        due_at: r.due_at.map(from_ts).transpose()?,
    })
}

#[async_trait]
impl TaskStore for SqliteStore {
    async fn open(&self, task: &Task) -> Result<Task, StoreError> {
        let t = task.clone();
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO tasks
                   (task_id, run_id, case_id, kind, justification, candidate_roles,
                    excluded_actors, assignee, priority, state, on_expiry, created_at, due_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT (task_id) DO NOTHING",
                params![
                    t.id.to_hex(),
                    t.run.to_string(),
                    t.case.map(|c| c.to_string()),
                    t.kind,
                    serde_json::to_string(&t.justification)?,
                    serde_json::to_string(&t.candidate_roles)?,
                    serde_json::to_string(&t.excluded_actors)?,
                    t.assignee,
                    t.priority.as_str(),
                    t.state.as_str(),
                    expiry_str(t.on_expiry),
                    ts(t.created_at),
                    t.due_at.map(ts),
                ],
            )
            .map_err(|e| be(&e))?;

            let found = conn
                .query_row(
                    &format!("SELECT {COLUMNS} FROM tasks WHERE task_id = ?1"),
                    params![t.id.to_hex()],
                    row,
                )
                .map_err(|e| be(&e))?;
            build(found)
        })
        .await
    }

    async fn task(&self, id: TaskId) -> Result<Option<Task>, StoreError> {
        self.with_conn(move |conn| {
            let found = conn
                .query_row(
                    &format!("SELECT {COLUMNS} FROM tasks WHERE task_id = ?1"),
                    params![id.to_hex()],
                    row,
                )
                .optional()
                .map_err(|e| be(&e))?;
            found.map(build).transpose()
        })
        .await
    }

    async fn claim(&self, id: TaskId, actor: &str, roles: &[String]) -> Result<Task, ClaimError> {
        let actor = actor.to_owned();
        let roles = roles.to_vec();
        let result: Result<Result<Task, ClaimError>, StoreError> = self
            .with_conn(move |conn| {
                let tx = conn.transaction().map_err(|e| be(&e))?;

                let found = tx
                    .query_row(
                        &format!("SELECT {COLUMNS} FROM tasks WHERE task_id = ?1"),
                        params![id.to_hex()],
                        row,
                    )
                    .optional()
                    .map_err(|e| be(&e))?;

                let Some(found) = found else {
                    return Ok(Err(ClaimError::NotFound(id)));
                };
                let task = build(found)?;

                // Eligibility before availability, and the order is load-bearing
                // — see `TaskStore::claim`.
                //
                // Four eyes: whoever proposed the action does not approve it.
                if task.excluded_actors.iter().any(|a| a == &actor) {
                    return Ok(Err(ClaimError::Excluded { actor }));
                }
                if !task.candidate_roles.is_empty()
                    && !task.candidate_roles.iter().any(|r| roles.contains(r))
                {
                    return Ok(Err(ClaimError::WrongRole { actor }));
                }
                if !task.state.is_pending() {
                    return Ok(Err(ClaimError::NotPending {
                        task: id,
                        state: task.state,
                    }));
                }
                if let Some(holder) = &task.assignee
                    && holder != &actor
                {
                    return Ok(Err(ClaimError::AlreadyClaimed {
                        task: id,
                        holder: holder.clone(),
                    }));
                }

                tx.execute(
                    "UPDATE tasks SET assignee = ?2, state = 'claimed' WHERE task_id = ?1",
                    params![id.to_hex(), actor],
                )
                .map_err(|e| be(&e))?;

                let updated = tx
                    .query_row(
                        &format!("SELECT {COLUMNS} FROM tasks WHERE task_id = ?1"),
                        params![id.to_hex()],
                        row,
                    )
                    .map_err(|e| be(&e))?;
                let updated = build(updated)?;

                tx.commit().map_err(|e| be(&e))?;
                Ok(Ok(updated))
            })
            .await;

        result?
    }

    async fn release(&self, id: TaskId, actor: &str) -> Result<(), ClaimError> {
        let actor = actor.to_owned();
        let result: Result<Result<(), ClaimError>, StoreError> = self
            .with_conn(move |conn| {
                let n = conn
                    .execute(
                        "UPDATE tasks SET assignee = NULL, state = 'open'
                         WHERE task_id = ?1 AND assignee = ?2 AND state = 'claimed'",
                        params![id.to_hex(), actor],
                    )
                    .map_err(|e| be(&e))?;
                if n == 0 {
                    // Not "no such task": the row may exist and be held by
                    // somebody else. Reporting success here would tell a caller
                    // they released work they never held.
                    return Ok(Err(ClaimError::NotHeld { task: id, actor }));
                }
                Ok(Ok(()))
            })
            .await;
        result?
    }

    async fn set_state(&self, id: TaskId, state: TaskState) -> Result<(), StoreError> {
        self.with_conn(move |conn| {
            let n = conn
                .execute(
                    "UPDATE tasks SET state = ?2 WHERE task_id = ?1",
                    params![id.to_hex(), state.as_str()],
                )
                .map_err(|e| be(&e))?;
            if n == 0 {
                return Err(StoreError::NotFound(id.to_string()));
            }
            Ok(())
        })
        .await
    }

    async fn queue(&self, roles: &[String], limit: usize) -> Result<Vec<Task>, StoreError> {
        let roles = roles.to_vec();
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {COLUMNS} FROM tasks
                     WHERE state IN ('open', 'escalated')
                     ORDER BY CASE priority
                                WHEN 'urgent' THEN 0 WHEN 'high' THEN 1
                                WHEN 'normal' THEN 2 ELSE 3 END,
                              created_at ASC
                     LIMIT ?1"
                ))
                .map_err(|e| be(&e))?;
            let rows = stmt
                .query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], row)
                .map_err(|e| be(&e))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| be(&e))?;

            let mut out = Vec::new();
            for r in rows {
                let t = build(r)?;
                // Filtering here rather than in SQL keeps role semantics in one
                // place: `may_decide` is what the claim path uses too, so the
                // queue can never show work the claim would refuse.
                if t.candidate_roles.is_empty()
                    || t.candidate_roles.iter().any(|r| roles.contains(r))
                {
                    out.push(t);
                }
            }
            Ok(out)
        })
        .await
    }

    async fn for_case(&self, case: CaseId) -> Result<Vec<Task>, StoreError> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {COLUMNS} FROM tasks WHERE case_id = ?1 ORDER BY created_at"
                ))
                .map_err(|e| be(&e))?;
            let rows = stmt
                .query_map(params![case.to_string()], row)
                .map_err(|e| be(&e))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| be(&e))?;
            rows.into_iter().map(build).collect()
        })
        .await
    }

    async fn open_count(&self) -> Result<u64, StoreError> {
        self.with_conn(move |conn| {
            // `claimed` counts: a task someone reserved and has not answered is
            // still a decision the plane is waiting on. Excluding it would make
            // the backlog shrink the moment a reviewer opened it.
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM tasks
                      WHERE state IN ('open', 'claimed', 'escalated')",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| super::sqlite::be(&e))?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
        .await
    }

    async fn overdue(&self, now: Timestamp, limit: usize) -> Result<Vec<Task>, StoreError> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {COLUMNS} FROM tasks
                     WHERE state IN ('open', 'claimed', 'escalated')
                       AND due_at IS NOT NULL AND due_at <= ?1
                     ORDER BY due_at ASC LIMIT ?2"
                ))
                .map_err(|e| be(&e))?;
            let rows = stmt
                .query_map(
                    params![ts(now), i64::try_from(limit).unwrap_or(i64::MAX)],
                    row,
                )
                .map_err(|e| be(&e))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| be(&e))?;
            rows.into_iter().map(build).collect()
        })
        .await
    }
}
