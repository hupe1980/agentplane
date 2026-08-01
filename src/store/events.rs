//! SQLite-backed inbound events.
//!
//! Claiming is the delicate part. Both directions — a wait looking for a
//! buffered event, and an event looking for a waiter — run inside a transaction
//! that marks the winner in the same statement it selects it. Without that, two
//! runs waiting on one key could both consume a single message, or one message
//! could resume two runs.

use async_trait::async_trait;
use rusqlite::{OptionalExtension, params};

use crate::case::{BufferedEvent, EventStore};
use crate::core::{
    CaseId, CorrelationKey, DeadLetter, EffectKey, InboundEvent, RunId, StoreError, Subscription,
    Timestamp,
};

use super::sqlite::{SqliteStore, be};

pub(super) const EVENT_SCHEMA: &str = r"
-- Every inbound event, stored on arrival whether or not anyone is waiting.
-- `claimed_by` is what makes delivery single-consumer.
CREATE TABLE IF NOT EXISTS inbound_events (
    event_id    TEXT PRIMARY KEY,
    kind        TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    received_at INTEGER NOT NULL,
    claimed_by  TEXT,
    claimed_at  INTEGER,
    dead        INTEGER NOT NULL DEFAULT 0,
    dead_reason TEXT
);

-- The sweep's access path: unclaimed, live, oldest first.
CREATE INDEX IF NOT EXISTS inbound_unclaimed
    ON inbound_events (received_at) WHERE claimed_by IS NULL AND dead = 0;

CREATE TABLE IF NOT EXISTS inbound_correlation (
    event_id  TEXT NOT NULL REFERENCES inbound_events (event_id) ON DELETE CASCADE,
    namespace TEXT NOT NULL,
    value     TEXT NOT NULL,
    PRIMARY KEY (event_id, namespace, value)
);

CREATE INDEX IF NOT EXISTS inbound_correlation_match
    ON inbound_correlation (namespace, value);

-- Durable registrations of interest. One row per (run, effect, key).
CREATE TABLE IF NOT EXISTS subscriptions (
    run_id     TEXT    NOT NULL,
    effect_key TEXT    NOT NULL,
    case_id    TEXT,
    -- Where the wait lives. Delivery journals the awaited result under this
    -- position, and replay verifies effects per step: a wait recorded against
    -- the wrong step is a wait the resumed run never finds.
    step       INTEGER NOT NULL,
    phase      TEXT    NOT NULL,
    event_kind TEXT    NOT NULL,
    namespace  TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (run_id, effect_key, namespace, value)
);

CREATE INDEX IF NOT EXISTS subscriptions_match
    ON subscriptions (event_kind, namespace, value);
";

/// Stored as text so a human reading the table sees which pass is waiting.
fn phase_str(p: crate::core::Phase) -> &'static str {
    match p {
        crate::core::Phase::Forward => "forward",
        crate::core::Phase::Compensating => "compensating",
    }
}

fn phase_from(s: &str) -> crate::core::Phase {
    match s {
        "compensating" => crate::core::Phase::Compensating,
        // Anything else is the forward pass. An unknown value can only come
        // from a future version, and treating it as forward keeps the read
        // total rather than failing a delivery on a column it does not know.
        _ => crate::core::Phase::Forward,
    }
}

fn ts(t: Timestamp) -> i64 {
    t.unix_timestamp()
}

fn from_ts(v: i64) -> Result<Timestamp, StoreError> {
    Timestamp::from_unix_timestamp(v).map_err(|e| StoreError::Corrupt {
        seq: 0,
        detail: format!("unrepresentable timestamp {v}: {e}"),
    })
}

fn load_correlation(
    conn: &rusqlite::Connection,
    event_id: &str,
) -> Result<Vec<CorrelationKey>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT namespace, value FROM inbound_correlation
             WHERE event_id = ?1 ORDER BY namespace, value",
        )
        .map_err(|e| be(&e))?;
    let rows = stmt
        .query_map(params![event_id], |r| {
            Ok(CorrelationKey::new(
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
            ))
        })
        .map_err(|e| be(&e))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| be(&e))?);
    }
    Ok(out)
}

#[async_trait]
impl EventStore for SqliteStore {
    async fn buffer(&self, event: &InboundEvent, at: Timestamp) -> Result<bool, StoreError> {
        let e = event.clone();
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(|err| be(&err))?;

            let seen: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM inbound_events WHERE event_id = ?1",
                    params![e.id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|err| be(&err))?;
            if seen.is_some() {
                tx.commit().map_err(|err| be(&err))?;
                return Ok(false);
            }

            tx.execute(
                "INSERT INTO inbound_events (event_id, kind, payload, received_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![e.id, e.kind, serde_json::to_string(&e.payload)?, ts(at)],
            )
            .map_err(|err| be(&err))?;

            for k in &e.correlation {
                tx.execute(
                    "INSERT INTO inbound_correlation (event_id, namespace, value)
                     VALUES (?1, ?2, ?3)",
                    params![e.id, k.namespace, k.value],
                )
                .map_err(|err| be(&err))?;
            }

            tx.commit().map_err(|err| be(&err))?;
            Ok(true)
        })
        .await
    }

    async fn subscribe(&self, sub: &Subscription, at: Timestamp) -> Result<(), StoreError> {
        let s = sub.clone();
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(|e| be(&e))?;
            for k in &s.correlation {
                tx.execute(
                    "INSERT INTO subscriptions
                       (run_id, effect_key, case_id, step, phase,
                        event_kind, namespace, value, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                     ON CONFLICT (run_id, effect_key, namespace, value) DO NOTHING",
                    params![
                        s.run.to_string(),
                        s.effect.to_hex(),
                        s.case.map(|c| c.to_string()),
                        i64::from(s.step.0),
                        phase_str(s.phase),
                        s.kind,
                        k.namespace,
                        k.value,
                        ts(at)
                    ],
                )
                .map_err(|e| be(&e))?;
            }
            tx.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn claim_for(
        &self,
        sub: &Subscription,
        at: Timestamp,
    ) -> Result<Option<BufferedEvent>, StoreError> {
        let s = sub.clone();
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(|e| be(&e))?;

            let mut found: Option<(String, String, i64)> = None;
            for k in &s.correlation {
                found = tx
                    .query_row(
                        "SELECT e.event_id, e.payload, e.received_at
                         FROM inbound_events e
                         JOIN inbound_correlation c ON c.event_id = e.event_id
                         WHERE e.kind = ?1 AND c.namespace = ?2 AND c.value = ?3
                           AND e.claimed_by IS NULL AND e.dead = 0
                         ORDER BY e.received_at ASC LIMIT 1",
                        params![s.kind, k.namespace, k.value],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()
                    .map_err(|e| be(&e))?;
                if found.is_some() {
                    break;
                }
            }

            let Some((event_id, payload, received)) = found else {
                tx.commit().map_err(|e| be(&e))?;
                return Ok(None);
            };

            // Claim in the same transaction that selected it: two runs waiting
            // on one key must not both consume a single message.
            tx.execute(
                "UPDATE inbound_events SET claimed_by = ?2, claimed_at = ?3
                 WHERE event_id = ?1 AND claimed_by IS NULL",
                params![event_id, s.run.to_string(), ts(at)],
            )
            .map_err(|e| be(&e))?;

            let correlation = load_correlation(&tx, &event_id)?;
            let kind: String = tx
                .query_row(
                    "SELECT kind FROM inbound_events WHERE event_id = ?1",
                    params![event_id],
                    |r| r.get(0),
                )
                .map_err(|e| be(&e))?;

            tx.commit().map_err(|e| be(&e))?;

            Ok(Some(BufferedEvent {
                event: InboundEvent {
                    id: event_id,
                    kind,
                    correlation,
                    payload: serde_json::from_str(&payload)?,
                },
                received_at: from_ts(received)?,
            }))
        })
        .await
    }

    async fn match_waiter(
        &self,
        event: &InboundEvent,
        at: Timestamp,
    ) -> Result<Option<Subscription>, StoreError> {
        let e = event.clone();
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(|err| be(&err))?;

            let mut found: Option<(String, String, Option<String>, i64, String)> = None;
            for k in &e.correlation {
                found = tx
                    .query_row(
                        "SELECT run_id, effect_key, case_id, step, phase FROM subscriptions
                         WHERE event_kind = ?1 AND namespace = ?2 AND value = ?3
                         ORDER BY created_at ASC LIMIT 1",
                        params![e.kind, k.namespace, k.value],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                    )
                    .optional()
                    .map_err(|err| be(&err))?;
                if found.is_some() {
                    break;
                }
            }

            let Some((run, effect, case, step, phase)) = found else {
                tx.commit().map_err(|err| be(&err))?;
                return Ok(None);
            };

            // Claim the event for this run in the same transaction, so one
            // message cannot resume two runs.
            let claimed = tx
                .execute(
                    "UPDATE inbound_events SET claimed_by = ?2, claimed_at = ?3
                     WHERE event_id = ?1 AND claimed_by IS NULL AND dead = 0",
                    params![e.id, run, ts(at)],
                )
                .map_err(|err| be(&err))?;
            if claimed == 0 {
                // Someone else took it between the select and here.
                tx.commit().map_err(|err| be(&err))?;
                return Ok(None);
            }

            let correlation: Vec<CorrelationKey> = tx
                .prepare(
                    "SELECT namespace, value FROM subscriptions
                     WHERE run_id = ?1 AND effect_key = ?2 ORDER BY namespace, value",
                )
                .and_then(|mut st| {
                    st.query_map(params![run, effect], |r| {
                        Ok(CorrelationKey::new(
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                        ))
                    })
                    .and_then(std::iter::Iterator::collect)
                })
                .map_err(|err| be(&err))?;

            tx.commit().map_err(|err| be(&err))?;

            let case = case
                .map(|c| {
                    CaseId::parse(&c).map_err(|err| StoreError::Corrupt {
                        seq: 0,
                        detail: format!("bad case id '{c}': {err}"),
                    })
                })
                .transpose()?;

            Ok(Some(Subscription {
                run: RunId::parse(&run).map_err(|err| StoreError::Corrupt {
                    seq: 0,
                    detail: format!("bad run id '{run}': {err}"),
                })?,
                case,
                effect: EffectKey::from_hex(&effect).map_err(|err| StoreError::Corrupt {
                    seq: 0,
                    detail: format!("bad effect key '{effect}': {err}"),
                })?,
                step: crate::core::StepId(u32::try_from(step).unwrap_or(0)),
                phase: phase_from(&phase),
                kind: e.kind.clone(),
                correlation,
            }))
        })
        .await
    }

    async fn unsubscribe(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError> {
        self.with_conn(move |conn| {
            conn.execute(
                "DELETE FROM subscriptions WHERE run_id = ?1 AND effect_key = ?2",
                params![run.to_string(), effect.to_hex()],
            )
            .map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn sweep_unclaimed(
        &self,
        older_than: Timestamp,
        reason: &str,
    ) -> Result<usize, StoreError> {
        let reason = reason.to_owned();
        self.with_conn(move |conn| {
            let n = conn
                .execute(
                    // `<=`, not `<`: a zero grace window must retire everything
                    // already buffered. With second-granularity timestamps, `<`
                    // silently spares anything received in the current second.
                    "UPDATE inbound_events SET dead = 1, dead_reason = ?2
                     WHERE claimed_by IS NULL AND dead = 0 AND received_at <= ?1",
                    params![ts(older_than), reason],
                )
                .map_err(|e| be(&e))?;
            Ok(n)
        })
        .await
    }

    async fn dead_letters(&self, limit: usize) -> Result<Vec<DeadLetter>, StoreError> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT event_id, kind, payload, received_at, dead_reason
                     FROM inbound_events WHERE dead = 1
                     ORDER BY received_at DESC LIMIT ?1",
                )
                .map_err(|e| be(&e))?;
            let rows = stmt
                .query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                })
                .map_err(|e| be(&e))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| be(&e))?;

            let mut out = Vec::new();
            for (id, kind, payload, received, reason) in rows {
                let correlation = load_correlation(conn, &id)?;
                out.push(DeadLetter {
                    event: InboundEvent {
                        id,
                        kind,
                        correlation,
                        payload: serde_json::from_str(&payload)?,
                    },
                    received_at: from_ts(received)?,
                    reason: reason.unwrap_or_else(|| "unclaimed".into()),
                });
            }
            Ok(out)
        })
        .await
    }

    async fn waiting(&self, limit: usize) -> Result<Vec<Subscription>, StoreError> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT run_id, effect_key, event_kind, namespace, value, case_id, step, phase
                     FROM subscriptions ORDER BY created_at ASC LIMIT ?1",
                )
                .map_err(|e| be(&e))?;
            let rows = stmt
                .query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, i64>(6)?,
                        r.get::<_, String>(7)?,
                    ))
                })
                .map_err(|e| be(&e))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| be(&e))?;

            let mut out = Vec::new();
            for (run, effect, kind, ns, v, case, step, phase) in rows {
                out.push(Subscription {
                    run: RunId::parse(&run).map_err(|e| StoreError::Corrupt {
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
                    effect: EffectKey::from_hex(&effect).map_err(|e| StoreError::Corrupt {
                        seq: 0,
                        detail: format!("bad effect key '{effect}': {e}"),
                    })?,
                    step: crate::core::StepId(u32::try_from(step).unwrap_or(0)),
                    phase: phase_from(&phase),
                    kind,
                    correlation: vec![CorrelationKey::new(ns, v)],
                });
            }
            Ok(out)
        })
        .await
    }
}
