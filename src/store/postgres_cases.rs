//! The case layer on `PostgreSQL`.
//!
//! Every store here exists to settle one race, and the races are the reason this
//! file is not a mechanical translation of the `SQLite` one:
//!
//! | Store | Race | How Postgres settles it |
//! |---|---|---|
//! | cases | two messages, one new matter | partial unique index on open keys |
//! | events | one message, two waiters | `UPDATE … RETURNING` claims in one statement |
//! | timers | one wake-up, two sweeps | same |
//! | tasks | one decision, two reviewers | same |
//! | batches | one item, two reservations | `ON CONFLICT DO NOTHING`, then read back |
//!
//! `UPDATE … RETURNING` is the reason several of these are *simpler* here than
//! in `SQLite` rather than merely different. The read-then-write that `SQLite` has
//! to wrap in a transaction becomes a single statement whose result tells you
//! whether you won — there is no window to reason about because there is no
//! second statement.
//!
//! Whether that reasoning is right is not left to the reader:
//! `testkit::conformance_case` runs the same battery against this and against
//! `SQLite`.

use async_trait::async_trait;
use deadpool_postgres::Pool;
use tokio_postgres::error::SqlState;

use crate::batch::{BatchCensus, BatchStore, ItemOutcome, ItemRecord};
use crate::case::{BufferedEvent, ClaimError, TargetedDelivery};
use crate::case::{CaseCensus, CaseStore, Correlation, EventStore, TaskStore, TimerStore};
use crate::core::{
    BatchId, Case, CaseId, CaseStatus, CaseVersion, CorrelationKey, DeadLetter, Deadline,
    DeadlineState, Digest, EffectKey, InboundEvent, OnExpiry, Priority, RunId, Spend, StoreError,
    Subscription, Task, TaskId, TaskState, Timer, Timestamp,
};

use super::postgres::{PostgresStore, amount_of, sql_amount};

pub(super) const CASE_SCHEMA: &str = "
-- Every table here leads with the tenant, for the reason the journal schema
-- gives: a key component turns a forgotten predicate into an empty result
-- instead of another tenant's row. The foreign keys carry it too, so a child
-- row cannot reference a parent in a different tenant.
CREATE TABLE IF NOT EXISTS cases (
    tenant    TEXT   NOT NULL,
    case_id   TEXT   NOT NULL,
    kind      TEXT   NOT NULL,
    status    TEXT   NOT NULL,
    state     TEXT   NOT NULL,
    -- Bumped by every state write, which must name the version it read. This
    -- backend is the one that exists for several plane instances sharing a
    -- store, so the overlapping read-modify-write is not a corner case here —
    -- it is the normal operating condition.
    version   BIGINT NOT NULL DEFAULT 0,
    opened_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, case_id)
);

CREATE TABLE IF NOT EXISTS case_correlation (
    tenant    TEXT    NOT NULL,
    case_id   TEXT    NOT NULL,
    namespace TEXT    NOT NULL,
    value     TEXT    NOT NULL,
    open      BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (tenant, case_id, namespace, value),
    FOREIGN KEY (tenant, case_id) REFERENCES cases (tenant, case_id) ON DELETE CASCADE
);

-- One open case per business key. This is the arbiter, not a hint: two inbound
-- messages racing to open the same matter both attempt the insert, and exactly
-- one succeeds. The loser re-reads and attaches.
-- Scoped to the tenant, because a correlation key is a *business* value:
-- `document`/`DOC-1` means something different to every tenant, and two of them
-- using it is ordinary rather than a collision. Globally unique, one tenant's
-- run would attach to another's case and the two would share a history, a
-- deadline set and an erasure unit.
CREATE UNIQUE INDEX IF NOT EXISTS case_correlation_open
    ON case_correlation (tenant, namespace, value) WHERE open;

CREATE TABLE IF NOT EXISTS case_runs (
    tenant  TEXT   NOT NULL,
    case_id TEXT   NOT NULL,
    run_id  TEXT   NOT NULL,
    seq     BIGINT NOT NULL,
    PRIMARY KEY (tenant, case_id, run_id),
    FOREIGN KEY (tenant, case_id) REFERENCES cases (tenant, case_id) ON DELETE CASCADE
);

-- The blobs a case produced. The case is what an erasure request names, and a
-- digest cannot be reversed to find its case, so the link has to be recorded
-- when the bytes are written or it cannot be recovered at all.
CREATE TABLE IF NOT EXISTS case_blobs (
    tenant     TEXT   NOT NULL,
    case_id    TEXT   NOT NULL,
    digest     BYTEA  NOT NULL,
    written_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, case_id, digest),
    FOREIGN KEY (tenant, case_id) REFERENCES cases (tenant, case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS case_blobs_time
    ON case_blobs (tenant, case_id, written_at);

CREATE TABLE IF NOT EXISTS case_deadlines (
    tenant          TEXT   NOT NULL,
    case_id         TEXT   NOT NULL,
    name            TEXT   NOT NULL,
    resolved_at     BIGINT NOT NULL,
    calendar_digest BYTEA  NOT NULL,
    warn_at         BIGINT,
    state           TEXT   NOT NULL,
    PRIMARY KEY (tenant, case_id, name),
    FOREIGN KEY (tenant, case_id) REFERENCES cases (tenant, case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS inbound_events (
    -- The dedup identity is (source, id), CloudEvents' uniqueness pair. Keying
    -- on id alone deduplicates two producers into each other: id is unique
    -- within a producer, and the collision is silent because the second message
    -- looks exactly like a retry of the first.
    tenant      TEXT    NOT NULL,
    event_id    TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    -- The producer's own id, stored rather than split back out of the key: a
    -- reconstructed event must be the event that arrived, and parsing the key
    -- apart would be a second place that has to agree about the separator.
    bare_id     TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    received_at BIGINT  NOT NULL,
    claimed_by  TEXT,
    claimed_at  BIGINT,
    dead        BOOLEAN NOT NULL DEFAULT FALSE,
    dead_reason TEXT,
    PRIMARY KEY (tenant, event_id)
);

CREATE TABLE IF NOT EXISTS inbound_correlation (
    tenant    TEXT NOT NULL,
    event_id  TEXT NOT NULL,
    namespace TEXT NOT NULL,
    value     TEXT NOT NULL,
    PRIMARY KEY (tenant, event_id, namespace, value),
    FOREIGN KEY (tenant, event_id)
        REFERENCES inbound_events (tenant, event_id) ON DELETE CASCADE
);

-- The match path: an arriving event finds the runs waiting for it here. The
-- tenant leads for the same reason it leads `case_correlation_open`, and this
-- is the worse of the two failures — one tenant's message resuming another
-- tenant's run hands it a payload it was never sent.
CREATE TABLE IF NOT EXISTS subscriptions (
    tenant     TEXT   NOT NULL,
    run_id     TEXT   NOT NULL,
    effect_key TEXT   NOT NULL,
    case_id    TEXT,
    step       BIGINT NOT NULL,
    phase      TEXT   NOT NULL,
    event_kind TEXT   NOT NULL,
    namespace  TEXT   NOT NULL,
    value      TEXT   NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, run_id, effect_key, namespace, value)
);

CREATE TABLE IF NOT EXISTS timers (
    tenant     TEXT   NOT NULL,
    run_id     TEXT   NOT NULL,
    effect_key TEXT   NOT NULL,
    case_id    TEXT,
    step       BIGINT NOT NULL,
    phase      TEXT   NOT NULL,
    fire_at    BIGINT NOT NULL,
    claimed_at BIGINT,
    PRIMARY KEY (tenant, run_id, effect_key)
);

CREATE TABLE IF NOT EXISTS tasks (
    tenant          TEXT   NOT NULL,
    task_id         TEXT   NOT NULL,
    run_id          TEXT   NOT NULL,
    case_id         TEXT,
    kind            TEXT   NOT NULL,
    justification   TEXT   NOT NULL,
    candidate_roles TEXT   NOT NULL,
    excluded_actors TEXT   NOT NULL,
    assignee        TEXT,
    priority        TEXT   NOT NULL,
    state           TEXT   NOT NULL,
    on_expiry       TEXT   NOT NULL,
    created_at      BIGINT NOT NULL,
    due_at          BIGINT,
    PRIMARY KEY (tenant, task_id)
);

CREATE TABLE IF NOT EXISTS batches (
    tenant      TEXT    NOT NULL,
    batch_id    TEXT    NOT NULL,
    plan_digest TEXT    NOT NULL,
    exhausted   BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (tenant, batch_id)
);

CREATE TABLE IF NOT EXISTS batch_items (
    tenant   TEXT   NOT NULL,
    batch_id TEXT   NOT NULL,
    item_key TEXT   NOT NULL,
    run_id   TEXT   NOT NULL,
    outcome  TEXT,
    detail   TEXT,
    tokens   BIGINT NOT NULL DEFAULT 0,
    minor    BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant, batch_id, item_key),
    FOREIGN KEY (tenant, batch_id) REFERENCES batches (tenant, batch_id) ON DELETE CASCADE
);

-- The runs a tenant currently has executing.
--
-- A set rather than a counter, and the difference is recovery: a counter that is
-- incremented on admission leaks a slot every time a process dies before the
-- decrement, and nothing can say which increments were real. A set names its
-- members, so a stranded slot is attributable to a run an operator can look up,
-- and releasing it is idempotent by construction.
CREATE TABLE IF NOT EXISTS quota_running (
    tenant      TEXT   NOT NULL,
    run_id      TEXT   NOT NULL,
    admitted_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, run_id)
);

-- The emergency stop: one row per halted tenant, none for the rest.
--
-- In the database rather than in a process, because a switch that stops only
-- the instance it was thrown on is not a switch — it is the in-process-counter
-- failure arriving during an incident.
CREATE TABLE IF NOT EXISTS quota_halted (
    tenant      TEXT   NOT NULL,
    reason      TEXT   NOT NULL,
    PRIMARY KEY (tenant)
);

CREATE TABLE IF NOT EXISTS quota_spent (
    tenant      TEXT   NOT NULL,
    period      TEXT   NOT NULL,
    tokens      BIGINT NOT NULL DEFAULT 0,
    minor_units BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant, period)
);
";

fn be(e: &tokio_postgres::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn pool_err(e: &impl std::fmt::Display) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn corrupt(what: &str, e: impl std::fmt::Display) -> StoreError {
    StoreError::Corrupt {
        seq: 0,
        detail: format!("{what}: {e}"),
    }
}

fn status_from(s: &str) -> Result<CaseStatus, StoreError> {
    Ok(match s {
        "open" => CaseStatus::Open,
        "awaiting_external" => CaseStatus::AwaitingExternal,
        "awaiting_human" => CaseStatus::AwaitingHuman,
        "escalated" => CaseStatus::Escalated,
        "closed" => CaseStatus::Closed,
        other => return Err(corrupt("unknown case status", other)),
    })
}

fn deadline_state_from(s: &str) -> Result<DeadlineState, StoreError> {
    Ok(match s {
        "pending" => DeadlineState::Pending,
        "warned" => DeadlineState::Warned,
        "breached" => DeadlineState::Breached,
        "met" => DeadlineState::Met,
        "cancelled" => DeadlineState::Cancelled,
        other => return Err(corrupt("unknown deadline state", other)),
    })
}

fn task_state_from(s: &str) -> Result<TaskState, StoreError> {
    Ok(match s {
        "open" => TaskState::Open,
        "claimed" => TaskState::Claimed,
        "completed" => TaskState::Completed,
        "expired" => TaskState::Expired,
        "escalated" => TaskState::Escalated,
        other => return Err(corrupt("unknown task state", other)),
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

fn phase_str(p: crate::core::Phase) -> &'static str {
    match p {
        crate::core::Phase::Forward => "forward",
        crate::core::Phase::Compensating => "compensating",
    }
}

fn phase_from(s: &str) -> crate::core::Phase {
    match s {
        "compensating" => crate::core::Phase::Compensating,
        _ => crate::core::Phase::Forward,
    }
}

impl PostgresStore {
    fn pool(&self) -> &Pool {
        self.pool_ref()
    }
}

#[async_trait]
impl CaseStore for PostgresStore {
    async fn correlate(&self, keys: &[CorrelationKey]) -> Result<Option<CaseId>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        for k in keys {
            let row = client
                .query_opt(
                    "SELECT case_id FROM case_correlation
                      WHERE tenant = $3 AND namespace = $1 AND value = $2 AND open",
                    &[&k.namespace, &k.value, &self.tenant_name()],
                )
                .await
                .map_err(|e| be(&e))?;
            if let Some(row) = row {
                let id: String = row.get(0);
                return Ok(Some(
                    CaseId::parse(&id).map_err(|e| corrupt("bad case id", e))?,
                ));
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
        // Two attempts, and the second is not a retry loop for flakiness — it is
        // how the constraint arbitrates. Both messages read no open case, both
        // try to insert, and the unique index picks a winner. The loser comes
        // back here and *finds* the winner's row, which is exactly the answer it
        // should have had.
        for attempt in 0..2 {
            if let Some(existing) = self.correlate(keys).await? {
                return Ok(Correlation::Attached(existing));
            }

            let mut client = self.pool().get().await.map_err(|e| pool_err(&e))?;
            let tx = client.transaction().await.map_err(|e| be(&e))?;
            let id = CaseId::generate();
            tx.execute(
                "INSERT INTO cases (case_id, kind, status, state, opened_at, tenant)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &id.to_string(),
                    &kind.to_owned(),
                    &CaseStatus::Open.as_str(),
                    &"null".to_owned(),
                    &at.unix_timestamp(),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;

            let mut lost = false;
            for k in keys {
                let r = tx
                    .execute(
                        "INSERT INTO case_correlation (case_id, namespace, value, open, tenant)
                         VALUES ($1, $2, $3, TRUE, $4)",
                        &[&id.to_string(), &k.namespace, &k.value, &self.tenant_name()],
                    )
                    .await;
                if let Err(e) = r {
                    if e.code() == Some(&SqlState::UNIQUE_VIOLATION) {
                        lost = true;
                        break;
                    }
                    return Err(be(&e));
                }
            }
            if lost {
                // Someone else opened this matter first. Discard ours entirely —
                // a half-opened case with no keys is a case nothing can reach.
                drop(tx);
                continue;
            }
            tx.commit().await.map_err(|e| be(&e))?;
            let _ = attempt;
            return Ok(Correlation::Opened(id));
        }

        // Two losses means a third party is opening and closing this key in a
        // tight loop; say so rather than looping forever.
        self.correlate(keys)
            .await?
            .map(Correlation::Attached)
            .ok_or_else(|| {
                StoreError::Backend(
                    "could not open or attach a case: the correlation key is being opened \
                     and closed concurrently"
                        .into(),
                )
            })
    }

    async fn case(&self, id: CaseId) -> Result<Option<Case>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let Some(row) = client
            .query_opt(
                "SELECT kind, status, state, opened_at, version FROM cases
                  WHERE case_id = $1 AND tenant = $2",
                &[&id.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?
        else {
            return Ok(None);
        };
        let kind: String = row.get(0);
        let status: String = row.get(1);
        let state: String = row.get(2);
        let opened: i64 = row.get(3);
        let version: i64 = row.get(4);

        let corr = client
            .query(
                "SELECT namespace, value FROM case_correlation
                  WHERE case_id = $1 AND tenant = $2",
                &[&id.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        let runs = client
            .query(
                "SELECT run_id FROM case_runs
                  WHERE case_id = $1 AND tenant = $2 ORDER BY seq ASC",
                &[&id.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;

        Ok(Some(Case {
            id,
            kind,
            status: status_from(&status)?,
            correlation: corr
                .iter()
                .map(|r| CorrelationKey::new(r.get::<_, String>(0), r.get::<_, String>(1)))
                .collect(),
            state: serde_json::from_str(&state)?,
            version: CaseVersion(u64::try_from(version).unwrap_or(0)),
            opened_at: Timestamp::from_unix_timestamp(opened)
                .map_err(|e| corrupt("unrepresentable opened_at", e))?,
            runs: runs
                .iter()
                .map(|r| RunId::parse(&r.get::<_, String>(0)))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| corrupt("bad run id", e))?,
        }))
    }

    async fn attach_run(&self, case: CaseId, run: RunId) -> Result<(), StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "INSERT INTO case_runs (case_id, run_id, seq, tenant)
                 VALUES ($1, $2,
                         (SELECT COALESCE(MAX(seq), 0) + 1 FROM case_runs
                           WHERE case_id = $1 AND tenant = $3),
                         $3)
                 ON CONFLICT (tenant, case_id, run_id) DO NOTHING",
                &[&case.to_string(), &run.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn link_blob(
        &self,
        case: CaseId,
        digest: Digest,
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        // The primary key makes re-linking the same bytes the same record:
        // two runs on one case writing identical content land on one digest by
        // construction, and that is one artifact.
        client
            .execute(
                "INSERT INTO case_blobs (case_id, digest, written_at, tenant)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (tenant, case_id, digest) DO NOTHING",
                &[
                    &case.to_string(),
                    &digest.as_bytes().as_slice(),
                    &at.unix_timestamp(),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn blobs_of(&self, case: CaseId) -> Result<Vec<Digest>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT digest FROM case_blobs
                  WHERE case_id = $1 AND tenant = $2 ORDER BY written_at, digest",
                &[&case.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let raw: Vec<u8> = row.get(0);
            let bytes: [u8; 32] = raw.try_into().map_err(|_| StoreError::Corrupt {
                seq: 0,
                detail: "a linked blob digest is not 32 bytes".into(),
            })?;
            out.push(Digest::from_bytes(bytes));
        }
        Ok(out)
    }

    async fn put_state(
        &self,
        case: CaseId,
        expected: CaseVersion,
        state: serde_json::Value,
    ) -> Result<CaseVersion, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let next = expected.next();
        // The row count is read, and that is the point. The previous version of
        // this method discarded it and returned `Ok(())` for a case that does
        // not exist — the same defect already found once in `release` on this
        // backend. A guard whose result nobody reads is not a guard.
        let n = client
            .execute(
                "UPDATE cases SET state = $2, version = $3
                  WHERE case_id = $1 AND version = $4 AND tenant = $5",
                &[
                    &case.to_string(),
                    &state.to_string(),
                    &i64::try_from(next.0).unwrap_or(i64::MAX),
                    &i64::try_from(expected.0).unwrap_or(i64::MAX),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        if n == 1 {
            return Ok(next);
        }
        // Tell "gone" apart from "moved on": a missing case reported as a
        // conflict sends the caller into a re-read loop against nothing.
        let current = client
            .query_opt(
                "SELECT version FROM cases WHERE case_id = $1 AND tenant = $2",
                &[&case.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        match current {
            Some(row) => Err(StoreError::CaseConflict {
                case: case.to_string(),
                expected: expected.0,
                current: u64::try_from(row.get::<_, i64>(0)).unwrap_or(0),
            }),
            None => Err(StoreError::NotFound(case.to_string())),
        }
    }

    async fn set_status(&self, case: CaseId, status: CaseStatus) -> Result<(), StoreError> {
        // Closing releases the correlation keys and refuses an open obligation;
        // an ordinary status write does neither. Keeping `set_status(Closed)` a
        // bare column write let the `status` column and correlation-open
        // membership disagree — a closed case stayed correlatable and a new
        // matter attached to it. Route it through `close`.
        if status == CaseStatus::Closed {
            return self.close(case).await;
        }
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let n = client
            .execute(
                "UPDATE cases SET status = $2 WHERE case_id = $1 AND tenant = $3",
                &[&case.to_string(), &status.as_str(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        if n == 0 {
            return Err(StoreError::NotFound(case.to_string()));
        }
        Ok(())
    }

    async fn close(&self, case: CaseId) -> Result<(), StoreError> {
        let mut client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let tx = client.transaction().await.map_err(|e| be(&e))?;

        // An unmet obligation survives closure, because closure is the moment
        // people stop looking.
        let open: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM case_deadlines
                  WHERE case_id = $1 AND tenant = $2 AND state IN ('pending', 'warned')",
                &[&case.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?
            .get(0);
        if open > 0 {
            return Err(StoreError::Backend(format!(
                "case {case} has {open} unmet obligation(s) and cannot be closed"
            )));
        }

        tx.execute(
            "UPDATE cases SET status = $2 WHERE case_id = $1 AND tenant = $3",
            &[
                &case.to_string(),
                &CaseStatus::Closed.as_str(),
                &self.tenant_name(),
            ],
        )
        .await
        .map_err(|e| be(&e))?;
        // Releasing the keys is what lets a later message open a *new* matter
        // rather than reanimating an audited one.
        tx.execute(
            "UPDATE case_correlation SET open = FALSE WHERE case_id = $1 AND tenant = $2",
            &[&case.to_string(), &self.tenant_name()],
        )
        .await
        .map_err(|e| be(&e))?;
        tx.commit().await.map_err(|e| be(&e))?;
        Ok(())
    }

    async fn register_deadline(&self, d: &Deadline) -> Result<(), StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "INSERT INTO case_deadlines
                   (case_id, name, resolved_at, calendar_digest, warn_at, state, tenant)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (tenant, case_id, name) DO NOTHING",
                &[
                    &d.case.to_string(),
                    &d.name,
                    &d.resolved_at.unix_timestamp(),
                    &d.calendar_digest.as_bytes().to_vec(),
                    &d.warn_at.map(Timestamp::unix_timestamp),
                    &d.state.as_str(),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn deadlines(&self, case: CaseId) -> Result<Vec<Deadline>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT case_id, name, resolved_at, calendar_digest, warn_at, state
                   FROM case_deadlines
                  WHERE case_id = $1 AND tenant = $2 ORDER BY resolved_at ASC",
                &[&case.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        rows.iter().map(deadline_from).collect()
    }

    async fn set_deadline_state(
        &self,
        case: CaseId,
        name: &str,
        state: DeadlineState,
    ) -> Result<(), StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "UPDATE case_deadlines SET state = $3
                  WHERE case_id = $1 AND name = $2 AND tenant = $4",
                &[
                    &case.to_string(),
                    &name.to_owned(),
                    &state.as_str(),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn due(&self, now: Timestamp, limit: usize) -> Result<Vec<Deadline>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT case_id, name, resolved_at, calendar_digest, warn_at, state
                   FROM case_deadlines
                  WHERE tenant = $3 AND state IN ('pending', 'warned')
                    AND (resolved_at <= $1 OR (warn_at IS NOT NULL AND warn_at <= $1))
                  ORDER BY resolved_at ASC LIMIT $2",
                &[
                    &now.unix_timestamp(),
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        rows.iter().map(deadline_from).collect()
    }

    async fn by_status(&self, status: CaseStatus, limit: usize) -> Result<Vec<Case>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT case_id FROM cases
                  WHERE status = $1 AND tenant = $3 ORDER BY opened_at DESC LIMIT $2",
                &[
                    &status.as_str(),
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.get(0);
            let id = CaseId::parse(&id).map_err(|e| corrupt("bad case id", e))?;
            if let Some(c) = self.case(id).await? {
                out.push(c);
            }
        }
        Ok(out)
    }

    async fn census(&self, now: Timestamp) -> Result<CaseCensus, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let row = client
            .query_one(
                "SELECT COUNT(*), MIN(opened_at) FROM cases
                  WHERE tenant = $1 AND status <> 'closed'",
                &[&self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        let open: i64 = row.get(0);
        let oldest: Option<i64> = row.get(1);
        let due: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM case_deadlines
                  WHERE tenant = $2 AND state IN ('pending', 'warned') AND resolved_at <= $1",
                &[&now.unix_timestamp(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?
            .get(0);

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
}

fn deadline_from(row: &tokio_postgres::Row) -> Result<Deadline, StoreError> {
    let case: String = row.get(0);
    let digest: Vec<u8> = row.get(3);
    let warn: Option<i64> = row.get(4);
    let state: String = row.get(5);
    let arr: [u8; 32] = digest
        .try_into()
        .map_err(|_| corrupt("calendar digest", "not 32 bytes"))?;
    Ok(Deadline {
        case: CaseId::parse(&case).map_err(|e| corrupt("bad case id", e))?,
        name: row.get(1),
        resolved_at: Timestamp::from_unix_timestamp(row.get::<_, i64>(2))
            .map_err(|e| corrupt("unrepresentable deadline", e))?,
        calendar_digest: Digest::from_bytes(arr),
        warn_at: warn
            .map(Timestamp::from_unix_timestamp)
            .transpose()
            .map_err(|e| corrupt("unrepresentable warn_at", e))?,
        state: deadline_state_from(&state)?,
    })
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl EventStore for PostgresStore {
    async fn buffer(&self, event: &InboundEvent, at: Timestamp) -> Result<bool, StoreError> {
        let mut client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let tx = client.transaction().await.map_err(|e| be(&e))?;
        let inserted = tx
            .execute(
                "INSERT INTO inbound_events
                   (event_id, source, bare_id, kind, payload, received_at, tenant)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (tenant, event_id) DO NOTHING",
                &[
                    &event.dedup_key(),
                    &event.source,
                    &event.id,
                    &event.kind,
                    &event.payload.to_string(),
                    &at.unix_timestamp(),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        if inserted == 0 {
            tx.commit().await.map_err(|e| be(&e))?;
            return Ok(false);
        }
        for k in &event.correlation {
            tx.execute(
                "INSERT INTO inbound_correlation (event_id, namespace, value, tenant)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                // The dedup key throughout: correlation rows reference the row
                // `buffer` wrote, and that is keyed by `(source, id)`.
                &[
                    &event.dedup_key(),
                    &k.namespace,
                    &k.value,
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        }
        tx.commit().await.map_err(|e| be(&e))?;
        Ok(true)
    }

    async fn subscribe(&self, sub: &Subscription, at: Timestamp) -> Result<(), StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        for k in &sub.correlation {
            client
                .execute(
                    "INSERT INTO subscriptions
                       (run_id, effect_key, case_id, step, phase, event_kind,
                        namespace, value, created_at, tenant)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                     ON CONFLICT DO NOTHING",
                    &[
                        &sub.run.to_string(),
                        &sub.effect.to_hex(),
                        &sub.case.map(|c| c.to_string()),
                        &i64::from(sub.step.0),
                        &phase_str(sub.phase),
                        &sub.kind,
                        &k.namespace,
                        &k.value,
                        &at.unix_timestamp(),
                        &self.tenant_name(),
                    ],
                )
                .await
                .map_err(|e| be(&e))?;
        }
        Ok(())
    }

    async fn claim_for(
        &self,
        sub: &Subscription,
        at: Timestamp,
    ) -> Result<Option<BufferedEvent>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        for k in &sub.correlation {
            // One statement. The claim predicate and the write are evaluated
            // together, so two waiters cannot both come away with the row —
            // there is no window because there is no second statement.
            //
            // `claimed_by IS NULL` — or already claimed **by this very run**.
            // The second arm is crash recovery, the same idempotence
            // `deliver_to` grants a retried targeted delivery: `match_waiter`
            // claims durably and the run resumes in a separate step, so a
            // crash between the two leaves an event claimed for a run that
            // never saw it. Without the arm the resumed wait re-subscribes,
            // finds nothing — its own event filtered out by its own claim —
            // and sleeps until its deadline breaches. Single delivery is
            // untouched: only the claiming run can re-claim.
            let row = client
                .query_opt(
                    "UPDATE inbound_events SET claimed_by = $1, claimed_at = $2
                      WHERE tenant = $6 AND event_id = (
                          SELECT e.event_id FROM inbound_events e
                            JOIN inbound_correlation c
                              ON c.tenant = e.tenant AND c.event_id = e.event_id
                           WHERE e.tenant = $6 AND e.kind = $3
                             AND c.namespace = $4 AND c.value = $5
                             AND (e.claimed_by IS NULL OR e.claimed_by = $1)
                             AND NOT e.dead
                           ORDER BY e.received_at ASC
                           FOR UPDATE SKIP LOCKED
                           LIMIT 1)
                  RETURNING bare_id, kind, payload, received_at, source, event_id",
                    &[
                        &sub.run.to_string(),
                        &at.unix_timestamp(),
                        &sub.kind,
                        &k.namespace,
                        &k.value,
                        &self.tenant_name(),
                    ],
                )
                .await
                .map_err(|e| be(&e))?;
            if let Some(row) = row {
                return Ok(Some(
                    buffered_from(&row, &client, &self.tenant_name()).await?,
                ));
            }
        }
        Ok(None)
    }

    async fn match_waiter(
        &self,
        event: &InboundEvent,
        at: Timestamp,
    ) -> Result<Option<Subscription>, StoreError> {
        let mut client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let tx = client.transaction().await.map_err(|e| be(&e))?;

        for k in &event.correlation {
            let Some(row) = tx
                .query_opt(
                    "SELECT run_id, effect_key, case_id, step, phase FROM subscriptions
                      WHERE tenant = $4 AND event_kind = $1
                        AND namespace = $2 AND value = $3
                      ORDER BY created_at ASC LIMIT 1",
                    &[&event.kind, &k.namespace, &k.value, &self.tenant_name()],
                )
                .await
                .map_err(|e| be(&e))?
            else {
                continue;
            };
            let run: String = row.get(0);

            // Claiming the event in the same transaction is what stops one
            // message resuming two runs.
            let claimed = tx
                .execute(
                    "UPDATE inbound_events SET claimed_by = $2, claimed_at = $3
                      WHERE tenant = $4 AND event_id = $1
                        AND claimed_by IS NULL AND NOT dead",
                    &[
                        &event.dedup_key(),
                        &run,
                        &at.unix_timestamp(),
                        &self.tenant_name(),
                    ],
                )
                .await
                .map_err(|e| be(&e))?;
            if claimed == 0 {
                tx.commit().await.map_err(|e| be(&e))?;
                return Ok(None);
            }

            let effect: String = row.get(1);
            let case: Option<String> = row.get(2);
            let step: i64 = row.get(3);
            let phase: String = row.get(4);
            // The claim retires the subscription, in the same transaction —
            // the same rule the redb backend holds and for the same reason:
            // left registered until the run's own unsubscribe, it matched a
            // *second* event, sequentially, which was then claimed for a run
            // whose wait the first already satisfied — parked under a claim
            // nobody consumes, invisible to dead-lettering. The resumed wait
            // re-subscribes idempotently and recovers its own claimed event
            // through the crash-recovery arm. `deliver_to` deliberately does
            // not retire, because its retry path rebuilds `Matched` from
            // these rows.
            tx.execute(
                "DELETE FROM subscriptions
                  WHERE tenant = $1 AND run_id = $2 AND effect_key = $3",
                &[&self.tenant_name(), &run, &effect],
            )
            .await
            .map_err(|e| be(&e))?;
            tx.commit().await.map_err(|e| be(&e))?;

            return Ok(Some(Subscription {
                run: RunId::parse(&run).map_err(|e| corrupt("bad run id", e))?,
                case: case
                    .map(|c| CaseId::parse(&c))
                    .transpose()
                    .map_err(|e| corrupt("bad case id", e))?,
                effect: EffectKey::from_hex(&effect).map_err(|e| corrupt("bad effect key", e))?,
                step: crate::core::StepId(u32::try_from(step).unwrap_or(0)),
                phase: phase_from(&phase),
                kind: event.kind.clone(),
                correlation: event.correlation.clone(),
            }));
        }
        tx.commit().await.map_err(|e| be(&e))?;
        Ok(None)
    }

    async fn deliver_to(
        &self,
        target: RunId,
        event: &InboundEvent,
        at: Timestamp,
    ) -> Result<TargetedDelivery, StoreError> {
        let mut client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let tx = client.transaction().await.map_err(|e| be(&e))?;
        let tenant = self.tenant_name();
        let event_id = event.dedup_key();

        let existing_claim: Option<Option<String>> = tx
            .query_opt(
                "SELECT claimed_by FROM inbound_events
                  WHERE tenant = $1 AND event_id = $2 FOR UPDATE",
                &[&tenant, &event_id],
            )
            .await
            .map_err(|e| be(&e))?
            .map(|row| row.get(0));

        // Lock this run's candidate subscription rows. Two continuations for
        // one task then serialize before either can insert its event.
        let rows = tx
            .query(
                "SELECT effect_key, case_id, step, phase, namespace, value
                   FROM subscriptions
                  WHERE tenant = $1 AND run_id = $2 AND event_kind = $3
                  ORDER BY created_at ASC
                  FOR UPDATE",
                &[&tenant, &target.to_string(), &event.kind],
            )
            .await
            .map_err(|e| be(&e))?;
        let Some(selected) = rows.iter().find(|row| {
            let namespace: String = row.get(4);
            let value: String = row.get(5);
            event
                .correlation
                .iter()
                .any(|key| key.namespace == namespace && key.value == value)
        }) else {
            tx.commit().await.map_err(|e| be(&e))?;
            return Ok(TargetedDelivery::NotWaiting);
        };

        let effect: String = selected.get(0);
        let case: Option<String> = selected.get(1);
        let step: i64 = selected.get(2);
        let phase: String = selected.get(3);
        let subscription = Subscription {
            run: target,
            case: case
                .map(|value| CaseId::parse(&value))
                .transpose()
                .map_err(|e| corrupt("bad case id", e))?,
            effect: EffectKey::from_hex(&effect).map_err(|e| corrupt("bad effect key", e))?,
            step: crate::core::StepId(u32::try_from(step).unwrap_or(0)),
            phase: phase_from(&phase),
            kind: event.kind.clone(),
            correlation: rows
                .iter()
                .filter(|row| row.get::<_, String>(0) == effect)
                .map(|row| CorrelationKey::new(row.get::<_, String>(4), row.get::<_, String>(5)))
                .collect(),
        };

        if let Some(claimed_by) = existing_claim {
            tx.commit().await.map_err(|e| be(&e))?;
            return Ok(
                if claimed_by.as_deref() == Some(target.to_string().as_str()) {
                    TargetedDelivery::Matched(subscription)
                } else {
                    TargetedDelivery::Duplicate
                },
            );
        }

        let inserted = tx
            .execute(
                "INSERT INTO inbound_events
                   (event_id, source, bare_id, kind, payload, received_at,
                    claimed_by, claimed_at, tenant)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $6, $8)
                 ON CONFLICT (tenant, event_id) DO NOTHING",
                &[
                    &event_id,
                    &event.source,
                    &event.id,
                    &event.kind,
                    &event.payload.to_string(),
                    &at.unix_timestamp(),
                    &target.to_string(),
                    &tenant,
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        if inserted == 0 {
            let claimed_by: Option<String> = tx
                .query_one(
                    "SELECT claimed_by FROM inbound_events
                      WHERE tenant = $1 AND event_id = $2",
                    &[&tenant, &event_id],
                )
                .await
                .map_err(|e| be(&e))?
                .get(0);
            tx.commit().await.map_err(|e| be(&e))?;
            return Ok(
                if claimed_by.as_deref() == Some(target.to_string().as_str()) {
                    TargetedDelivery::Matched(subscription)
                } else {
                    TargetedDelivery::Duplicate
                },
            );
        }
        for key in &event.correlation {
            tx.execute(
                "INSERT INTO inbound_correlation (event_id, namespace, value, tenant)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                &[&event_id, &key.namespace, &key.value, &tenant],
            )
            .await
            .map_err(|e| be(&e))?;
        }

        tx.commit().await.map_err(|e| be(&e))?;
        Ok(TargetedDelivery::Matched(subscription))
    }

    async fn unsubscribe(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "DELETE FROM subscriptions
                  WHERE tenant = $3 AND run_id = $1 AND effect_key = $2",
                &[&run.to_string(), &effect.to_hex(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn sweep_unclaimed(
        &self,
        older_than: Timestamp,
        reason: &str,
    ) -> Result<usize, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let n = client
            .execute(
                "UPDATE inbound_events SET dead = TRUE, dead_reason = $2
                  WHERE tenant = $3 AND claimed_by IS NULL AND NOT dead
                    AND received_at < $1",
                &[
                    &older_than.unix_timestamp(),
                    &reason.to_owned(),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    async fn dead_letters(&self, limit: usize) -> Result<Vec<DeadLetter>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT bare_id, kind, payload, received_at, dead_reason, source
                   FROM inbound_events WHERE tenant = $2 AND dead
                  ORDER BY received_at DESC LIMIT $1",
                &[
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let payload: String = row.get(2);
            out.push(DeadLetter {
                event: InboundEvent {
                    source: row.get(5),
                    id: row.get(0),
                    kind: row.get(1),
                    correlation: Vec::new(),
                    payload: serde_json::from_str(&payload)?,
                },
                received_at: Timestamp::from_unix_timestamp(row.get::<_, i64>(3))
                    .map_err(|e| corrupt("unrepresentable received_at", e))?,
                reason: row.get::<_, Option<String>>(4).unwrap_or_default(),
            });
        }
        Ok(out)
    }

    async fn waiting(&self, limit: usize) -> Result<Vec<Subscription>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT run_id, effect_key, case_id, step, phase, event_kind, namespace, value
                   FROM subscriptions WHERE tenant = $2
                  ORDER BY created_at ASC LIMIT $1",
                &[
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let run: String = row.get(0);
            let effect: String = row.get(1);
            let case: Option<String> = row.get(2);
            let step: i64 = row.get(3);
            let phase: String = row.get(4);
            out.push(Subscription {
                run: RunId::parse(&run).map_err(|e| corrupt("bad run id", e))?,
                case: case
                    .map(|c| CaseId::parse(&c))
                    .transpose()
                    .map_err(|e| corrupt("bad case id", e))?,
                effect: EffectKey::from_hex(&effect).map_err(|e| corrupt("bad effect key", e))?,
                step: crate::core::StepId(u32::try_from(step).unwrap_or(0)),
                phase: phase_from(&phase),
                kind: row.get(5),
                correlation: vec![CorrelationKey::new(
                    row.get::<_, String>(6),
                    row.get::<_, String>(7),
                )],
            });
        }
        Ok(out)
    }
}

async fn buffered_from(
    row: &tokio_postgres::Row,
    client: &deadpool_postgres::Client,
    tenant: &str,
) -> Result<BufferedEvent, StoreError> {
    let id: String = row.get(0);
    let payload: String = row.get(2);
    // Correlation is keyed by the dedup key, which is what `buffer` wrote — not
    // by `bare_id`, the producer's own id. Reading it back under the wrong one
    // returns nothing, and a claimed event would arrive with no keys at all:
    // valid-looking, silently stripped of what it was routed on.
    let event_id: String = row.get(5);
    let corr = client
        .query(
            "SELECT namespace, value FROM inbound_correlation
              WHERE tenant = $2 AND event_id = $1",
            &[&event_id, &tenant],
        )
        .await
        .map_err(|e| be(&e))?;
    Ok(BufferedEvent {
        event: InboundEvent {
            source: row.get(4),
            id: id.clone(),
            kind: row.get(1),
            correlation: corr
                .iter()
                .map(|r| CorrelationKey::new(r.get::<_, String>(0), r.get::<_, String>(1)))
                .collect(),
            payload: serde_json::from_str(&payload)?,
        },
        received_at: Timestamp::from_unix_timestamp(row.get::<_, i64>(3))
            .map_err(|e| corrupt("unrepresentable received_at", e))?,
    })
}

/// How long a timer claim holds before another sweep may take it.
const CLAIM_LEASE: i64 = 60;

#[async_trait]
impl TimerStore for PostgresStore {
    async fn arm(&self, timer: &Timer) -> Result<(), StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "INSERT INTO timers
                   (run_id, effect_key, case_id, step, phase, fire_at, tenant)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (tenant, run_id, effect_key) DO NOTHING",
                &[
                    &timer.run.to_string(),
                    &timer.effect.to_hex(),
                    &timer.case.map(|c| c.to_string()),
                    &i64::from(timer.step.0),
                    &phase_str(timer.phase),
                    &timer.fire_at.unix_timestamp(),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn claim_due(&self, now: Timestamp, limit: usize) -> Result<Vec<Timer>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        // Claimed and selected in one statement, with `SKIP LOCKED` so a second
        // sweeper takes different rows rather than blocking on the first's.
        let rows = client
            .query(
                "UPDATE timers SET claimed_at = $1
                  WHERE tenant = $4 AND (run_id, effect_key) IN (
                      SELECT run_id, effect_key FROM timers
                       WHERE tenant = $4 AND fire_at <= $1
                         AND (claimed_at IS NULL OR claimed_at <= $2)
                       ORDER BY fire_at ASC
                       FOR UPDATE SKIP LOCKED
                       LIMIT $3)
              RETURNING run_id, effect_key, case_id, step, phase, fire_at",
                &[
                    &now.unix_timestamp(),
                    &(now.unix_timestamp() - CLAIM_LEASE),
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        rows.iter().map(timer_from).collect()
    }

    async fn pending_count(&self) -> Result<u64, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let n: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM timers WHERE tenant = $1",
                &[&self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?
            .get(0);
        Ok(u64::try_from(n).unwrap_or(0))
    }

    async fn disarm(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "DELETE FROM timers WHERE tenant = $3 AND run_id = $1 AND effect_key = $2",
                &[&run.to_string(), &effect.to_hex(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn pending(&self, limit: usize) -> Result<Vec<Timer>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT run_id, effect_key, case_id, step, phase, fire_at
                   FROM timers WHERE tenant = $2 ORDER BY fire_at ASC LIMIT $1",
                &[
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        rows.iter().map(timer_from).collect()
    }
}

fn timer_from(row: &tokio_postgres::Row) -> Result<Timer, StoreError> {
    let run: String = row.get(0);
    let effect: String = row.get(1);
    let case: Option<String> = row.get(2);
    let step: i64 = row.get(3);
    let phase: String = row.get(4);
    Ok(Timer {
        run: RunId::parse(&run).map_err(|e| corrupt("bad run id", e))?,
        case: case
            .map(|c| CaseId::parse(&c))
            .transpose()
            .map_err(|e| corrupt("bad case id", e))?,
        effect: EffectKey::from_hex(&effect).map_err(|e| corrupt("bad effect key", e))?,
        step: crate::core::StepId(u32::try_from(step).unwrap_or(0)),
        phase: phase_from(&phase),
        fire_at: Timestamp::from_unix_timestamp(row.get::<_, i64>(5))
            .map_err(|e| corrupt("unrepresentable fire_at", e))?,
    })
}

#[async_trait]
impl TaskStore for PostgresStore {
    async fn open(&self, task: &Task) -> Result<Task, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "INSERT INTO tasks (task_id, run_id, case_id, kind, justification,
                                    candidate_roles, excluded_actors, assignee, priority,
                                    state, on_expiry, created_at, due_at, tenant)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                 ON CONFLICT (tenant, task_id) DO NOTHING",
                &[
                    &task.id.to_hex(),
                    &task.run.to_string(),
                    &task.case.map(|c| c.to_string()),
                    &task.kind,
                    &serde_json::to_string(&task.justification)?,
                    &task.candidate_roles.join(","),
                    &task.excluded_actors.join(","),
                    &task.assignee,
                    &task.priority.as_str(),
                    &task.state.as_str(),
                    &expiry_str(task.on_expiry),
                    &task.created_at.unix_timestamp(),
                    &task.due_at.map(Timestamp::unix_timestamp),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(self.task(task.id).await?.unwrap_or_else(|| task.clone()))
    }

    async fn task(&self, id: TaskId) -> Result<Option<Task>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let row = client
            .query_opt(
                &format!("SELECT {TASK_COLS} FROM tasks WHERE task_id = $1 AND tenant = $2"),
                &[&id.to_hex(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        row.as_ref().map(task_from).transpose()
    }

    async fn claim(&self, id: TaskId, actor: &str, roles: &[String]) -> Result<Task, ClaimError> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| ClaimError::Store(pool_err(&e)))?;
        let Some(task) = self.task(id).await.map_err(ClaimError::Store)? else {
            return Err(ClaimError::NotFound(id));
        };
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

        // The reservation itself is one statement, guarded on the row still
        // being unheld. Checking above and writing here would leave a window two
        // reviewers both pass through.
        let updated = client
            .execute(
                "UPDATE tasks SET assignee = $2, state = 'claimed'
                  WHERE task_id = $1 AND tenant = $3
                    AND (assignee IS NULL OR assignee = $2)",
                &[&id.to_hex(), &actor.to_owned(), &self.tenant_name()],
            )
            .await
            .map_err(|e| ClaimError::Store(be(&e)))?;
        if updated == 0 {
            let holder = self
                .task(id)
                .await
                .map_err(ClaimError::Store)?
                .and_then(|t| t.assignee)
                .unwrap_or_default();
            return Err(ClaimError::AlreadyClaimed { task: id, holder });
        }
        self.task(id)
            .await
            .map_err(ClaimError::Store)?
            .ok_or(ClaimError::NotFound(id))
    }

    async fn take_over(
        &self,
        id: TaskId,
        from: &str,
        actor: &str,
        roles: &[String],
    ) -> Result<Task, ClaimError> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| ClaimError::Store(pool_err(&e)))?;
        let Some(task) = self.task(id).await.map_err(ClaimError::Store)? else {
            return Err(ClaimError::NotFound(id));
        };
        // Claim's eligibility-first order, unchanged: a take-over is a claim,
        // and four-eyes exclusion does not thin because the previous reviewer
        // left.
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

        // The displacement is one statement, guarded on the holder still being
        // the one the caller named — the compare-and-swap that keeps a
        // take-over decided from a stale view from displacing whoever holds
        // the task *now*.
        let updated = client
            .execute(
                "UPDATE tasks SET assignee = $2, state = 'claimed'
                  WHERE task_id = $1 AND tenant = $4
                    AND assignee = $3 AND state = 'claimed'",
                &[
                    &id.to_hex(),
                    &actor.to_owned(),
                    &from.to_owned(),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| ClaimError::Store(be(&e)))?;
        if updated == 0 {
            return Err(ClaimError::NotHeld {
                task: id,
                actor: from.to_owned(),
            });
        }
        self.task(id)
            .await
            .map_err(ClaimError::Store)?
            .ok_or(ClaimError::NotFound(id))
    }

    async fn release(&self, id: TaskId, actor: &str) -> Result<(), ClaimError> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| ClaimError::Store(pool_err(&e)))?;
        let freed = client
            .execute(
                "UPDATE tasks SET assignee = NULL, state = 'open'
                  WHERE task_id = $1 AND tenant = $3
                    AND assignee = $2 AND state = 'claimed'",
                &[&id.to_hex(), &actor.to_owned(), &self.tenant_name()],
            )
            .await
            .map_err(|e| ClaimError::Store(be(&e)))?;
        // The predicate did the work; the row count is what says whether it
        // matched. Discarding it reported success for a release that freed
        // nothing — caught by the conformance battery, not by this backend's
        // own tests.
        if freed == 0 {
            return Err(ClaimError::NotHeld {
                task: id,
                actor: actor.to_owned(),
            });
        }
        Ok(())
    }

    async fn set_state(&self, id: TaskId, state: TaskState) -> Result<(), StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "UPDATE tasks SET state = $2 WHERE task_id = $1 AND tenant = $3",
                &[&id.to_hex(), &state.as_str(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn queue(&self, roles: &[String], limit: usize) -> Result<Vec<Task>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                &format!(
                    "SELECT {TASK_COLS} FROM tasks
                      WHERE tenant = $2 AND state IN ('open', 'escalated')
                      ORDER BY created_at ASC LIMIT $1"
                ),
                &[
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        let all: Result<Vec<Task>, StoreError> = rows.iter().map(task_from).collect();
        Ok(all?
            .into_iter()
            .filter(|t| {
                t.candidate_roles.is_empty() || t.candidate_roles.iter().any(|r| roles.contains(r))
            })
            .collect())
    }

    async fn for_case(&self, case: CaseId) -> Result<Vec<Task>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                &format!(
                    "SELECT {TASK_COLS} FROM tasks
                      WHERE case_id = $1 AND tenant = $2 ORDER BY created_at ASC"
                ),
                &[&case.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        rows.iter().map(task_from).collect()
    }

    async fn open_count(&self) -> Result<u64, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let n: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM tasks
                  WHERE tenant = $1 AND state IN ('open','claimed','escalated')",
                &[&self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?
            .get(0);
        Ok(u64::try_from(n).unwrap_or(0))
    }

    async fn overdue(&self, now: Timestamp, limit: usize) -> Result<Vec<Task>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                &format!(
                    "SELECT {TASK_COLS} FROM tasks
                      WHERE tenant = $3 AND state IN ('open','claimed','escalated')
                        AND due_at IS NOT NULL AND due_at <= $1
                      ORDER BY due_at ASC LIMIT $2"
                ),
                &[
                    &now.unix_timestamp(),
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        rows.iter().map(task_from).collect()
    }
}

const TASK_COLS: &str = "task_id, run_id, case_id, kind, justification, candidate_roles, \
                         excluded_actors, assignee, priority, state, on_expiry, created_at, due_at";

fn split(s: &str) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split(',').map(ToOwned::to_owned).collect()
    }
}

fn task_from(row: &tokio_postgres::Row) -> Result<Task, StoreError> {
    let id: String = row.get(0);
    let run: String = row.get(1);
    let case: Option<String> = row.get(2);
    let justification: String = row.get(4);
    let roles: String = row.get(5);
    let excluded: String = row.get(6);
    let priority: String = row.get(8);
    let state: String = row.get(9);
    let on_expiry: String = row.get(10);
    let due: Option<i64> = row.get(12);

    Ok(Task {
        id: TaskId::parse(&id).map_err(|e| corrupt("bad task id", e))?,
        run: RunId::parse(&run).map_err(|e| corrupt("bad run id", e))?,
        case: case
            .map(|c| CaseId::parse(&c))
            .transpose()
            .map_err(|e| corrupt("bad case id", e))?,
        kind: row.get(3),
        justification: serde_json::from_str(&justification)?,
        candidate_roles: split(&roles),
        excluded_actors: split(&excluded),
        assignee: row.get(7),
        priority: priority_from(&priority),
        state: task_state_from(&state)?,
        on_expiry: expiry_from(&on_expiry),
        created_at: Timestamp::from_unix_timestamp(row.get::<_, i64>(11))
            .map_err(|e| corrupt("unrepresentable created_at", e))?,
        due_at: due
            .map(Timestamp::from_unix_timestamp)
            .transpose()
            .map_err(|e| corrupt("unrepresentable due_at", e))?,
    })
}

#[async_trait]
impl BatchStore for PostgresStore {
    async fn open(&self, id: BatchId, plan_digest: &str) -> Result<(), StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "INSERT INTO batches (batch_id, plan_digest, tenant) VALUES ($1, $2, $3)
                 ON CONFLICT (tenant, batch_id) DO NOTHING",
                &[
                    &id.to_string(),
                    &plan_digest.to_owned(),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn mark_exhausted(&self, id: BatchId) -> Result<(), StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "UPDATE batches SET exhausted = TRUE WHERE batch_id = $1 AND tenant = $2",
                &[&id.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn is_exhausted(&self, id: BatchId) -> Result<bool, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        Ok(client
            .query_opt(
                "SELECT exhausted FROM batches WHERE batch_id = $1 AND tenant = $2",
                &[&id.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?
            .is_some_and(|r| r.get::<_, bool>(0)))
    }

    async fn reserve(
        &self,
        batch: BatchId,
        key: &str,
        run: RunId,
    ) -> Result<ItemRecord, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        // `DO NOTHING` then read back: an item already reserved must hand back
        // the *original* run id, or the journal holding its effects is orphaned
        // and they are performed again.
        client
            .execute(
                "INSERT INTO batch_items (batch_id, item_key, run_id, tenant)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (tenant, batch_id, item_key) DO NOTHING",
                &[
                    &batch.to_string(),
                    &key.to_owned(),
                    &run.to_string(),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        let row = client
            .query_one(
                "SELECT run_id, outcome, detail, tokens, minor FROM batch_items
                  WHERE batch_id = $1 AND item_key = $2 AND tenant = $3",
                &[&batch.to_string(), &key.to_owned(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        item_from(&row, key)
    }

    async fn record(
        &self,
        batch: BatchId,
        key: &str,
        outcome: &ItemOutcome,
        spend: Spend,
    ) -> Result<(), StoreError> {
        let (state, detail) = match outcome {
            ItemOutcome::Succeeded => ("succeeded", None),
            ItemOutcome::Failed(d) => ("failed", Some(d.clone())),
            ItemOutcome::Quarantined(d) => ("quarantined", Some(d.clone())),
            ItemOutcome::Suspended(d) => ("suspended", Some(d.clone())),
        };
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let updated = client
            .execute(
                "UPDATE batch_items SET outcome = $3, detail = $4, tokens = $5, minor = $6
                  WHERE batch_id = $1 AND item_key = $2 AND tenant = $7",
                &[
                    &batch.to_string(),
                    &key.to_owned(),
                    &state,
                    &detail,
                    &sql_amount(spend.tokens),
                    &sql_amount(spend.minor_units),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        // The predicate did the work; the row count says whether it matched.
        // Discarding it reported success for a record that wrote nothing —
        // the same lie a release that freed nothing tells.
        if updated == 0 {
            return Err(StoreError::NotFound(format!("{batch}/{key}")));
        }
        Ok(())
    }

    async fn cursor(&self, batch: BatchId) -> Result<Option<String>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        // The contiguous terminal prefix: an item still running or suspended
        // holds the cursor behind it, or a resume steps over work outstanding.
        let first_open: Option<String> = client
            .query_one(
                "SELECT MIN(item_key) FROM batch_items
                  WHERE batch_id = $1 AND tenant = $2
                    AND (outcome IS NULL OR outcome = 'suspended')",
                &[&batch.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?
            .get(0);

        let row = match first_open {
            Some(open) => client
                .query_one(
                    "SELECT MAX(item_key) FROM batch_items
                      WHERE batch_id = $1 AND item_key < $2 AND tenant = $3",
                    &[&batch.to_string(), &open, &self.tenant_name()],
                )
                .await
                .map_err(|e| be(&e))?,
            None => client
                .query_one(
                    "SELECT MAX(item_key) FROM batch_items
                      WHERE batch_id = $1 AND tenant = $2",
                    &[&batch.to_string(), &self.tenant_name()],
                )
                .await
                .map_err(|e| be(&e))?,
        };
        Ok(row.get(0))
    }

    async fn census(&self, batch: BatchId) -> Result<BatchCensus, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT outcome, COUNT(*), COALESCE(SUM(tokens),0), COALESCE(SUM(minor),0)
                   FROM batch_items WHERE batch_id = $1 AND tenant = $2
                  GROUP BY outcome",
                &[&batch.to_string(), &self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;

        let mut c = BatchCensus::default();
        for row in rows {
            let outcome: Option<String> = row.get(0);
            let n: i64 = row.get(1);
            let tokens: i64 = row.get(2);
            let minor: i64 = row.get(3);
            let n = amount_of(n);
            match outcome.as_deref() {
                Some("succeeded") => c.succeeded = n,
                Some("failed") => c.failed = n,
                Some("quarantined") => c.quarantined = n,
                Some("suspended") => c.suspended = n,
                _ => c.in_flight = n,
            }
            c.spend.tokens += amount_of(tokens);
            c.spend.minor_units += amount_of(minor);
        }
        Ok(c)
    }

    async fn items(&self, batch: BatchId, limit: usize) -> Result<Vec<ItemRecord>, StoreError> {
        let client = self.pool().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT item_key, run_id, outcome, detail, tokens, minor FROM batch_items
                  WHERE batch_id = $1 AND tenant = $3 ORDER BY item_key ASC LIMIT $2",
                &[
                    &batch.to_string(),
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                    &self.tenant_name(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let key: String = row.get(0);
            out.push(ItemRecord {
                key: key.clone(),
                run: RunId::parse(&row.get::<_, String>(1))
                    .map_err(|e| corrupt("bad run id", e))?,
                outcome: outcome_from(row.get::<_, Option<String>>(2), row.get(3)),
                spend: Spend {
                    tokens: amount_of(row.get::<_, i64>(4)),
                    minor_units: amount_of(row.get::<_, i64>(5)),
                },
            });
        }
        Ok(out)
    }
}

fn outcome_from(state: Option<String>, detail: Option<String>) -> Option<ItemOutcome> {
    let d = detail.unwrap_or_default();
    match state?.as_str() {
        "succeeded" => Some(ItemOutcome::Succeeded),
        "failed" => Some(ItemOutcome::Failed(d)),
        "quarantined" => Some(ItemOutcome::Quarantined(d)),
        "suspended" => Some(ItemOutcome::Suspended(d)),
        _ => None,
    }
}

fn item_from(row: &tokio_postgres::Row, key: &str) -> Result<ItemRecord, StoreError> {
    let run: String = row.get(0);
    Ok(ItemRecord {
        key: key.to_owned(),
        run: RunId::parse(&run).map_err(|e| corrupt("bad run id", e))?,
        outcome: outcome_from(row.get::<_, Option<String>>(1), row.get(2)),
        spend: Spend {
            tokens: amount_of(row.get::<_, i64>(3)),
            minor_units: amount_of(row.get::<_, i64>(4)),
        },
    })
}
