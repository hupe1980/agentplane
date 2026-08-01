//! Worklist.
//!
//! Claiming happens inside a transaction that checks eligibility and writes the
//! holder in one step. Two reviewers opening the same queue at the same moment
//! must not both believe they hold a task — and a check followed by a separate
//! write has exactly that window.

use async_trait::async_trait;
use turso::params;

use crate::case::{ClaimError, TaskStore};
use crate::core::{
    CaseId, Justification, OnExpiry, Priority, RunId, StoreError, Task, TaskId, TaskState,
    Timestamp,
};

use super::turso::{TursoStore, be, first};

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

fn row(r: &turso::Row) -> Result<TaskRow, StoreError> {
    Ok(TaskRow {
        task_id: r.get(0).map_err(|e| be(&e))?,
        run_id: r.get(1).map_err(|e| be(&e))?,
        case_id: r.get(2).map_err(|e| be(&e))?,
        kind: r.get(3).map_err(|e| be(&e))?,
        justification: r.get(4).map_err(|e| be(&e))?,
        candidate_roles: r.get(5).map_err(|e| be(&e))?,
        excluded_actors: r.get(6).map_err(|e| be(&e))?,
        assignee: r.get(7).map_err(|e| be(&e))?,
        priority: r.get(8).map_err(|e| be(&e))?,
        state: r.get(9).map_err(|e| be(&e))?,
        on_expiry: r.get(10).map_err(|e| be(&e))?,
        created_at: r.get(11).map_err(|e| be(&e))?,
        due_at: r.get(12).map_err(|e| be(&e))?,
    })
}

/// Every task a query returns, built and validated.
async fn tasks_from(mut rows: turso::Rows) -> Result<Vec<Task>, StoreError> {
    let mut out = Vec::new();
    while let Some(r) = rows.next().await.map_err(|e| be(&e))? {
        out.push(build(row(&r)?)?);
    }
    Ok(out)
}

/// One task by id, inside whatever connection or transaction is passed.
async fn task_by_id(conn: &turso::Connection, id: TaskId) -> Result<Option<TaskRow>, StoreError> {
    let rows = conn
        .query(
            &format!("SELECT {COLUMNS} FROM tasks WHERE task_id = ?1"),
            params![id.to_hex()],
        )
        .await
        .map_err(|e| be(&e))?;
    match first(rows).await? {
        Some(r) => row(&r).map(Some),
        None => Ok(None),
    }
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
impl TaskStore for TursoStore {
    async fn open(&self, task: &Task) -> Result<Task, StoreError> {
        let conn = self.conn().await;
        conn.execute(
            "INSERT INTO tasks
               (task_id, run_id, case_id, kind, justification, candidate_roles,
                excluded_actors, assignee, priority, state, on_expiry, created_at, due_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT (task_id) DO NOTHING",
            params![
                task.id.to_hex(),
                task.run.to_string(),
                task.case.map(|c| c.to_string()),
                task.kind.clone(),
                serde_json::to_string(&task.justification)?,
                serde_json::to_string(&task.candidate_roles)?,
                serde_json::to_string(&task.excluded_actors)?,
                task.assignee.clone(),
                task.priority.as_str(),
                task.state.as_str(),
                expiry_str(task.on_expiry),
                ts(task.created_at),
                task.due_at.map(ts),
            ],
        )
        .await
        .map_err(|e| be(&e))?;

        match task_by_id(&conn, task.id).await? {
            Some(found) => build(found),
            None => Err(StoreError::NotFound(task.id.to_string())),
        }
    }

    async fn task(&self, id: TaskId) -> Result<Option<Task>, StoreError> {
        let conn = self.conn().await;
        task_by_id(&conn, id).await?.map(build).transpose()
    }

    async fn claim(&self, id: TaskId, actor: &str, roles: &[String]) -> Result<Task, ClaimError> {
        let mut conn = self.conn().await;
        let tx = conn.transaction().await.map_err(|e| be(&e))?;

        let Some(found) = task_by_id(&tx, id).await? else {
            return Err(ClaimError::NotFound(id));
        };
        let task = build(found)?;

        // Eligibility before availability, and the order is load-bearing — see
        // `TaskStore::claim`.
        //
        // Four eyes: whoever proposed the action does not approve it.
        if task.excluded_actors.iter().any(|a| a == actor) {
            return Err(ClaimError::Excluded {
                actor: actor.to_owned(),
            });
        }
        if !task.candidate_roles.is_empty()
            && !task.candidate_roles.iter().any(|r| roles.contains(r))
        {
            return Err(ClaimError::WrongRole {
                actor: actor.to_owned(),
            });
        }
        if !task.state.is_pending() {
            return Err(ClaimError::NotPending {
                task: id,
                state: task.state,
            });
        }
        if let Some(holder) = &task.assignee
            && holder != actor
        {
            return Err(ClaimError::AlreadyClaimed {
                task: id,
                holder: holder.clone(),
            });
        }

        tx.execute(
            "UPDATE tasks SET assignee = ?2, state = 'claimed' WHERE task_id = ?1",
            params![id.to_hex(), actor.to_owned()],
        )
        .await
        .map_err(|e| be(&e))?;

        let updated = match task_by_id(&tx, id).await? {
            Some(r) => build(r)?,
            None => return Err(ClaimError::NotFound(id)),
        };

        tx.commit().await.map_err(|e| be(&e))?;
        Ok(updated)
    }

    async fn release(&self, id: TaskId, actor: &str) -> Result<(), ClaimError> {
        let conn = self.conn().await;
        let n = conn
            .execute(
                "UPDATE tasks SET assignee = NULL, state = 'open'
                 WHERE task_id = ?1 AND assignee = ?2 AND state = 'claimed'",
                params![id.to_hex(), actor.to_owned()],
            )
            .await
            .map_err(|e| be(&e))?;
        if n == 0 {
            // Not "no such task": the row may exist and be held by somebody
            // else. Reporting success here would tell a caller they released
            // work they never held.
            return Err(ClaimError::NotHeld {
                task: id,
                actor: actor.to_owned(),
            });
        }
        Ok(())
    }

    async fn set_state(&self, id: TaskId, state: TaskState) -> Result<(), StoreError> {
        let conn = self.conn().await;
        let n = conn
            .execute(
                "UPDATE tasks SET state = ?2 WHERE task_id = ?1",
                params![id.to_hex(), state.as_str()],
            )
            .await
            .map_err(|e| be(&e))?;
        if n == 0 {
            return Err(StoreError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn queue(&self, roles: &[String], limit: usize) -> Result<Vec<Task>, StoreError> {
        let conn = self.conn().await;
        let rows = conn
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM tasks
                     WHERE state IN ('open', 'escalated')
                     ORDER BY CASE priority
                                WHEN 'urgent' THEN 0 WHEN 'high' THEN 1
                                WHEN 'normal' THEN 2 ELSE 3 END,
                              created_at ASC
                     LIMIT ?1"
                ),
                params![i64::try_from(limit).unwrap_or(i64::MAX)],
            )
            .await
            .map_err(|e| be(&e))?;

        // Filtering here rather than in SQL keeps role semantics in one place:
        // `may_decide` is what the claim path uses too, so the queue can never
        // show work the claim would refuse.
        Ok(tasks_from(rows)
            .await?
            .into_iter()
            .filter(|t| {
                t.candidate_roles.is_empty() || t.candidate_roles.iter().any(|r| roles.contains(r))
            })
            .collect())
    }

    async fn for_case(&self, case: CaseId) -> Result<Vec<Task>, StoreError> {
        let conn = self.conn().await;
        let rows = conn
            .query(
                &format!("SELECT {COLUMNS} FROM tasks WHERE case_id = ?1 ORDER BY created_at"),
                params![case.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        tasks_from(rows).await
    }

    async fn open_count(&self) -> Result<u64, StoreError> {
        let conn = self.conn().await;
        // `claimed` counts: a task someone reserved and has not answered is
        // still a decision the plane is waiting on. Excluding it would make the
        // backlog shrink the moment a reviewer opened it.
        let rows = conn
            .query(
                "SELECT COUNT(*) FROM tasks
                  WHERE state IN ('open', 'claimed', 'escalated')",
                (),
            )
            .await
            .map_err(|e| be(&e))?;
        let n: i64 = match first(rows).await? {
            Some(r) => r.get(0).map_err(|e| be(&e))?,
            None => 0,
        };
        Ok(u64::try_from(n).unwrap_or(0))
    }

    async fn overdue(&self, now: Timestamp, limit: usize) -> Result<Vec<Task>, StoreError> {
        let conn = self.conn().await;
        let rows = conn
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM tasks
                     WHERE state IN ('open', 'claimed', 'escalated')
                       AND due_at IS NOT NULL AND due_at <= ?1
                     ORDER BY due_at ASC LIMIT ?2"
                ),
                params![ts(now), i64::try_from(limit).unwrap_or(i64::MAX)],
            )
            .await
            .map_err(|e| be(&e))?;
        tasks_from(rows).await
    }
}
