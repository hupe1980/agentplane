//! The worklist on redb.
//!
//! Claiming happens inside one write transaction that checks eligibility and
//! writes the holder together. Two reviewers opening the same queue at the same
//! moment must not both believe they hold a task — and a check followed by a
//! separate write has exactly that window.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::case::{ClaimError, TaskStore};
use crate::core::{CaseId, StoreError, Task, TaskId, TaskState, Timestamp};

use super::redb::{MAX_STR, RedbStore, be, begin_write};

/// `task_id -> the task as JSON`.
///
/// Stored whole rather than split into columns: `Task` already round-trips
/// through serde, and redb has no column concept to gain from splitting it.
/// Everything the indexes below need is derived from the parsed task, so the row
/// and its indexes cannot disagree about a field that exists in only one of them.
const TASKS: TableDefinition<(&str, &str), &str> = TableDefinition::new("tasks");

const QUEUE: TableDefinition<(&str, u8, i64, &str), ()> = TableDefinition::new("tasks_queue");

/// `(due_at, task_id) -> ()`, pending work with a window that can close.
const OVERDUE: TableDefinition<(&str, i64, &str), ()> = TableDefinition::new("tasks_overdue");

/// `(case_id, created_at, task_id) -> ()`.
const BY_CASE: TableDefinition<(&str, &str, i64, &str), ()> = TableDefinition::new("tasks_by_case");

/// `task_id -> ()`, every task still waiting on somebody.
///
/// Its length *is* the backlog. Counting by walking `TASKS` would parse a task
/// from JSON per row to read one field, which turns an operator's dashboard
/// refresh into a full deserialization of the worklist.
///
/// Wider than [`QUEUE`], deliberately: a claimed task has left the queue but is
/// still a decision the plane is waiting on, and a backlog that shrank the
/// moment a reviewer opened something would report progress that had not
/// happened.
const PENDING: TableDefinition<(&str, &str), ()> = TableDefinition::new("tasks_pending");

pub(super) fn create_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(TASKS).map_err(|e| be(&e))?;
    w.open_table(QUEUE).map_err(|e| be(&e))?;
    w.open_table(OVERDUE).map_err(|e| be(&e))?;
    w.open_table(BY_CASE).map_err(|e| be(&e))?;
    w.open_table(PENDING).map_err(|e| be(&e))?;
    Ok(())
}

fn ts(t: Timestamp) -> i64 {
    t.unix_timestamp()
}

/// Queue order, most urgent first.
fn priority_rank(s: &str) -> u8 {
    match s {
        "urgent" => 0,
        "high" => 1,
        "normal" => 2,
        _ => 3,
    }
}

/// Whether a task is still waiting on somebody.
fn is_queued(state: &str) -> bool {
    matches!(state, "open" | "escalated")
}

fn is_pending(state: &str) -> bool {
    matches!(state, "open" | "claimed" | "escalated")
}

/// Move a task between the derived indexes, in the transaction that writes it.
fn reindex(
    w: &redb::WriteTransaction,
    tenant: &str,
    id: &str,
    was: &Task,
    now_state: TaskState,
) -> Result<(), StoreError> {
    let (before, after) = (was.state.as_str(), now_state.as_str());
    if before == after {
        return Ok(());
    }
    let rank = priority_rank(was.priority.as_str());
    let created = ts(was.created_at);
    let mut queue = w.open_table(QUEUE).map_err(|e| be(&e))?;
    match (is_queued(before), is_queued(after)) {
        (true, false) => {
            queue
                .remove((tenant, rank, created, id))
                .map_err(|e| be(&e))?;
        }
        (false, true) => {
            queue
                .insert((tenant, rank, created, id), ())
                .map_err(|e| be(&e))?;
        }
        _ => {}
    }
    drop(queue);

    let mut pending = w.open_table(PENDING).map_err(|e| be(&e))?;
    match (is_pending(before), is_pending(after)) {
        (true, false) => {
            pending.remove((tenant, id)).map_err(|e| be(&e))?;
        }
        (false, true) => {
            pending.insert((tenant, id), ()).map_err(|e| be(&e))?;
        }
        _ => {}
    }
    drop(pending);

    if let Some(due) = was.due_at {
        let mut overdue = w.open_table(OVERDUE).map_err(|e| be(&e))?;
        match (is_pending(before), is_pending(after)) {
            (true, false) => {
                overdue.remove((tenant, ts(due), id)).map_err(|e| be(&e))?;
            }
            (false, true) => {
                overdue
                    .insert((tenant, ts(due), id), ())
                    .map_err(|e| be(&e))?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Read a task back out of the store.
fn load(
    t: &impl ReadableTable<(&'static str, &'static str), &'static str>,
    tenant: &str,
    id: &str,
) -> Result<Option<Task>, StoreError> {
    match t.get((tenant, id)).map_err(|e| be(&e))? {
        None => Ok(None),
        Some(v) => Ok(Some(serde_json::from_str(v.value())?)),
    }
}

/// Claim's eligibility ladder, in its load-bearing order — see
/// `TaskStore::claim` for why eligibility outranks availability.
///
/// One implementation serving both acquisition verbs, so `take_over` cannot
/// drift a rung: two copies of an ordered ladder agree everywhere except the
/// rung nobody probed.
fn eligible(task: &Task, id: TaskId, actor: &str, roles: &[String]) -> Result<(), ClaimError> {
    if task.excluded_actors.iter().any(|a| a == actor) {
        return Err(ClaimError::Excluded {
            actor: actor.to_owned(),
        });
    }
    if !task.candidate_roles.is_empty() && !task.candidate_roles.iter().any(|r| roles.contains(r)) {
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
    Ok(())
}

#[async_trait]
impl TaskStore for RedbStore {
    fn tenant(&self) -> &str {
        self.tenant_str()
    }

    async fn open(&self, task: &Task) -> Result<Task, StoreError> {
        let tenant = self.tenant_name();
        let id = task.id.to_hex();
        let encoded = serde_json::to_string(task)?;
        let (rank, created) = (priority_rank(task.priority.as_str()), ts(task.created_at));
        let (queued, pending) = (
            is_queued(task.state.as_str()),
            is_pending(task.state.as_str()),
        );
        let due = task.due_at.map(ts);
        let case = task.case.map(|c| c.to_string());
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let out = {
                let mut tasks = w.open_table(TASKS).map_err(|e| be(&e))?;
                // First open wins, by id: reopening must not rewrite a task
                // somebody may already hold.
                if let Some(found) = load(&tasks, &tenant, &id)? {
                    found
                } else {
                    {
                        tasks
                            .insert((tenant.as_str(), id.as_str()), encoded.as_str())
                            .map_err(|e| be(&e))?;
                        drop(tasks);
                        if queued {
                            w.open_table(QUEUE)
                                .map_err(|e| be(&e))?
                                .insert((tenant.as_str(), rank, created, id.as_str()), ())
                                .map_err(|e| be(&e))?;
                        }
                        if let Some(d) = due
                            && pending
                        {
                            w.open_table(OVERDUE)
                                .map_err(|e| be(&e))?
                                .insert((tenant.as_str(), d, id.as_str()), ())
                                .map_err(|e| be(&e))?;
                        }
                        if pending {
                            w.open_table(PENDING)
                                .map_err(|e| be(&e))?
                                .insert((tenant.as_str(), id.as_str()), ())
                                .map_err(|e| be(&e))?;
                        }
                        if let Some(c) = &case {
                            w.open_table(BY_CASE)
                                .map_err(|e| be(&e))?
                                .insert((tenant.as_str(), c.as_str(), created, id.as_str()), ())
                                .map_err(|e| be(&e))?;
                        }
                        serde_json::from_str(&encoded)?
                    }
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(out)
        })
        .await
    }

    async fn task(&self, id: TaskId) -> Result<Option<Task>, StoreError> {
        let tenant = self.tenant_name();
        let key = id.to_hex();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(TASKS).map_err(|e| be(&e))?;
            load(&t, &tenant, &key)
        })
        .await
    }

    async fn claim(&self, id: TaskId, actor: &str, roles: &[String]) -> Result<Task, ClaimError> {
        let tenant = self.tenant_name();
        let key = id.to_hex();
        let actor = actor.to_owned();
        let roles = roles.to_vec();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let out = {
                let mut tasks = w.open_table(TASKS).map_err(|e| be(&e))?;
                match load(&tasks, &tenant, &key)? {
                    None => Err(ClaimError::NotFound(id)),
                    Some(task) => {
                        if let Err(refused) = eligible(&task, id, &actor, &roles) {
                            Err(refused)
                        } else if let Some(holder) = task.assignee.as_ref().filter(|h| *h != &actor)
                        {
                            Err(ClaimError::AlreadyClaimed {
                                task: id,
                                holder: holder.clone(),
                            })
                        } else {
                            let mut updated = task.clone();
                            updated.assignee = Some(actor);
                            updated.state = TaskState::Claimed;
                            tasks
                                .insert(
                                    (tenant.as_str(), key.as_str()),
                                    serde_json::to_string(&updated)?.as_str(),
                                )
                                .map_err(|e| be(&e))?;
                            drop(tasks);
                            reindex(&w, &tenant, &key, &task, TaskState::Claimed)?;
                            Ok(updated)
                        }
                    }
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(out)
        })
        .await?
    }

    async fn take_over(
        &self,
        id: TaskId,
        from: &str,
        actor: &str,
        roles: &[String],
    ) -> Result<Task, ClaimError> {
        let tenant = self.tenant_name();
        let key = id.to_hex();
        let from = from.to_owned();
        let actor = actor.to_owned();
        let roles = roles.to_vec();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let out = {
                let mut tasks = w.open_table(TASKS).map_err(|e| be(&e))?;
                match load(&tasks, &tenant, &key)? {
                    None => Err(ClaimError::NotFound(id)),
                    Some(task) => {
                        // A take-over is a claim: the ladder does not thin
                        // because the previous reviewer left.
                        if let Err(refused) = eligible(&task, id, &actor, &roles) {
                            Err(refused)
                        } else if task.assignee.as_deref() != Some(from.as_str()) {
                            // The compare-and-swap guard. A take-over decided
                            // from a stale view must not displace whoever
                            // holds the task *now* — and an unheld task takes
                            // the ordinary claim verb, not this one.
                            Err(ClaimError::NotHeld {
                                task: id,
                                actor: from,
                            })
                        } else {
                            let mut updated = task.clone();
                            updated.assignee = Some(actor);
                            updated.state = TaskState::Claimed;
                            tasks
                                .insert(
                                    (tenant.as_str(), key.as_str()),
                                    serde_json::to_string(&updated)?.as_str(),
                                )
                                .map_err(|e| be(&e))?;
                            drop(tasks);
                            reindex(&w, &tenant, &key, &task, TaskState::Claimed)?;
                            Ok(updated)
                        }
                    }
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(out)
        })
        .await?
    }

    async fn release(&self, id: TaskId, actor: &str) -> Result<(), ClaimError> {
        let tenant = self.tenant_name();
        let key = id.to_hex();
        let actor = actor.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let out = {
                let mut tasks = w.open_table(TASKS).map_err(|e| be(&e))?;
                let found = load(&tasks, &tenant, &key)?;
                // Not "no such task": the row may exist and be held by somebody
                // else. Reporting success here would tell a caller they released
                // work they never held.
                let held = found.as_ref().is_some_and(|t| {
                    t.state == TaskState::Claimed && t.assignee.as_deref() == Some(actor.as_str())
                });
                if held {
                    let task = found.expect("held implies present");
                    let mut updated = task.clone();
                    updated.assignee = None;
                    updated.state = TaskState::Open;
                    tasks
                        .insert(
                            (tenant.as_str(), key.as_str()),
                            serde_json::to_string(&updated)?.as_str(),
                        )
                        .map_err(|e| be(&e))?;
                    drop(tasks);
                    reindex(&w, &tenant, &key, &task, TaskState::Open)?;
                    Ok(())
                } else {
                    Err(ClaimError::NotHeld { task: id, actor })
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(out)
        })
        .await?
    }

    async fn set_state(&self, id: TaskId, state: TaskState) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let key = id.to_hex();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut tasks = w.open_table(TASKS).map_err(|e| be(&e))?;
                let Some(task) = load(&tasks, &tenant, &key)? else {
                    return Err(StoreError::NotFound(id.to_string()));
                };
                let mut updated = task.clone();
                updated.state = state;
                tasks
                    .insert(
                        (tenant.as_str(), key.as_str()),
                        serde_json::to_string(&updated)?.as_str(),
                    )
                    .map_err(|e| be(&e))?;
                drop(tasks);
                reindex(&w, &tenant, &key, &task, state)?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn queue(&self, roles: &[String], limit: usize) -> Result<Vec<Task>, StoreError> {
        let tenant = self.tenant_name();
        let roles = roles.to_vec();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let q = r.open_table(QUEUE).map_err(|e| be(&e))?;
            let tasks = r.open_table(TASKS).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            // The index is keyed by priority rank then age, so redb's ascending
            // order is already the queue order — ranged to this tenant, like
            // every sibling read, so the walk's cost is this tenant's queue
            // rather than everybody's.
            for e in q
                .range(
                    (tenant.as_str(), 0u8, i64::MIN, "")
                        ..=(tenant.as_str(), u8::MAX, i64::MAX, MAX_STR),
                )
                .map_err(|e| be(&e))?
            {
                if out.len() >= limit {
                    break;
                }
                let (k, _) = e.map_err(|e| be(&e))?;
                if let Some(t) = load(&tasks, &tenant, k.value().3)? {
                    // Filtered here rather than in the index, so role semantics
                    // live in one place: the queue can never show work the claim
                    // path would refuse.
                    if t.candidate_roles.is_empty()
                        || t.candidate_roles.iter().any(|r| roles.contains(r))
                    {
                        out.push(t);
                    }
                }
            }
            Ok(out)
        })
        .await
    }

    async fn for_case(&self, case: CaseId) -> Result<Vec<Task>, StoreError> {
        let tenant = self.tenant_name();
        let key = case.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let by_case = r.open_table(BY_CASE).map_err(|e| be(&e))?;
            let tasks = r.open_table(TASKS).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            for e in by_case
                .range(
                    (tenant.as_str(), key.as_str(), i64::MIN, "")
                        ..=(tenant.as_str(), key.as_str(), i64::MAX, MAX_STR),
                )
                .map_err(|e| be(&e))?
            {
                let (k, _) = e.map_err(|e| be(&e))?;
                if let Some(t) = load(&tasks, &tenant, k.value().3)? {
                    out.push(t);
                }
            }
            Ok(out)
        })
        .await
    }

    async fn open_count(&self) -> Result<u64, StoreError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            // Counted over this tenant's range rather than `len()` on the
            // table: a whole-table count reports every tenant's open tasks as
            // this one's, which is a metric that reads plausibly and is wrong.
            let pending = r.open_table(PENDING).map_err(|e| be(&e))?;
            let mut n = 0u64;
            for e in pending
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

    async fn overdue(&self, now: Timestamp, limit: usize) -> Result<Vec<Task>, StoreError> {
        let tenant = self.tenant_name();
        let cutoff = ts(now);
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let od = r.open_table(OVERDUE).map_err(|e| be(&e))?;
            let tasks = r.open_table(TASKS).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            for e in od
                .range((tenant.as_str(), i64::MIN, "")..=(tenant.as_str(), cutoff, MAX_STR))
                .map_err(|e| be(&e))?
            {
                if out.len() >= limit {
                    break;
                }
                let (k, _) = e.map_err(|e| be(&e))?;
                if let Some(t) = load(&tasks, &tenant, k.value().2)? {
                    out.push(t);
                }
            }
            Ok(out)
        })
        .await
    }
}
