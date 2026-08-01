//! Inbound events.
//!
//! Claiming is the delicate part. Both directions — a wait looking for a
//! buffered event, and an event looking for a waiter — run inside a transaction
//! that marks the winner in the same statement it selects it. Without that, two
//! runs waiting on one key could both consume a single message, or one message
//! could resume two runs.

use async_trait::async_trait;
use turso::params;

use crate::case::{BufferedEvent, EventStore};
use crate::core::{
    CaseId, CorrelationKey, DeadLetter, EffectKey, InboundEvent, RunId, StoreError, Subscription,
    Timestamp,
};

use super::turso::{TursoStore, be, first};

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

async fn load_correlation(
    conn: &turso::Connection,
    event_id: &str,
) -> Result<Vec<CorrelationKey>, StoreError> {
    let mut rows = conn
        .query(
            "SELECT namespace, value FROM inbound_correlation
             WHERE event_id = ?1 ORDER BY namespace, value",
            params![event_id.to_owned()],
        )
        .await
        .map_err(|e| be(&e))?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().await.map_err(|e| be(&e))? {
        out.push(CorrelationKey::new(
            r.get::<String>(0).map_err(|e| be(&e))?,
            r.get::<String>(1).map_err(|e| be(&e))?,
        ));
    }
    Ok(out)
}

#[async_trait]
impl EventStore for TursoStore {
    async fn buffer(&self, event: &InboundEvent, at: Timestamp) -> Result<bool, StoreError> {
        let mut conn = self.conn().await;
        let tx = conn.transaction().await.map_err(|err| be(&err))?;

        let seen = tx
            .query(
                "SELECT 1 FROM inbound_events WHERE event_id = ?1",
                params![event.id.clone()],
            )
            .await
            .map_err(|err| be(&err))?;
        if first(seen).await?.is_some() {
            tx.commit().await.map_err(|err| be(&err))?;
            return Ok(false);
        }

        tx.execute(
            "INSERT INTO inbound_events (event_id, kind, payload, received_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                event.id.clone(),
                event.kind.clone(),
                serde_json::to_string(&event.payload)?,
                ts(at)
            ],
        )
        .await
        .map_err(|err| be(&err))?;

        for k in &event.correlation {
            tx.execute(
                "INSERT INTO inbound_correlation (event_id, namespace, value)
                 VALUES (?1, ?2, ?3)",
                params![event.id.clone(), k.namespace.clone(), k.value.clone()],
            )
            .await
            .map_err(|err| be(&err))?;
        }

        tx.commit().await.map_err(|err| be(&err))?;
        Ok(true)
    }

    async fn subscribe(&self, sub: &Subscription, at: Timestamp) -> Result<(), StoreError> {
        let mut conn = self.conn().await;
        let tx = conn.transaction().await.map_err(|e| be(&e))?;
        for k in &sub.correlation {
            tx.execute(
                "INSERT INTO subscriptions
                   (run_id, effect_key, case_id, step, phase,
                    event_kind, namespace, value, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT (run_id, effect_key, namespace, value) DO NOTHING",
                params![
                    sub.run.to_string(),
                    sub.effect.to_hex(),
                    sub.case.map(|c| c.to_string()),
                    i64::from(sub.step.0),
                    phase_str(sub.phase),
                    sub.kind.clone(),
                    k.namespace.clone(),
                    k.value.clone(),
                    ts(at)
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        }
        tx.commit().await.map_err(|e| be(&e))?;
        Ok(())
    }

    async fn claim_for(
        &self,
        sub: &Subscription,
        at: Timestamp,
    ) -> Result<Option<BufferedEvent>, StoreError> {
        let mut conn = self.conn().await;
        let tx = conn.transaction().await.map_err(|e| be(&e))?;

        let mut found: Option<(String, String, i64)> = None;
        for k in &sub.correlation {
            let rows = tx
                .query(
                    "SELECT e.event_id, e.payload, e.received_at
                     FROM inbound_events e
                     JOIN inbound_correlation c ON c.event_id = e.event_id
                     WHERE e.kind = ?1 AND c.namespace = ?2 AND c.value = ?3
                       AND e.claimed_by IS NULL AND e.dead = 0
                     ORDER BY e.received_at ASC LIMIT 1",
                    params![sub.kind.clone(), k.namespace.clone(), k.value.clone()],
                )
                .await
                .map_err(|e| be(&e))?;
            if let Some(r) = first(rows).await? {
                found = Some((
                    r.get(0).map_err(|e| be(&e))?,
                    r.get(1).map_err(|e| be(&e))?,
                    r.get(2).map_err(|e| be(&e))?,
                ));
                break;
            }
        }

        let Some((event_id, payload, received)) = found else {
            tx.commit().await.map_err(|e| be(&e))?;
            return Ok(None);
        };

        // Claim in the same transaction that selected it: two runs waiting on
        // one key must not both consume a single message.
        tx.execute(
            "UPDATE inbound_events SET claimed_by = ?2, claimed_at = ?3
             WHERE event_id = ?1 AND claimed_by IS NULL",
            params![event_id.clone(), sub.run.to_string(), ts(at)],
        )
        .await
        .map_err(|e| be(&e))?;

        let correlation = load_correlation(&tx, &event_id).await?;
        let rows = tx
            .query(
                "SELECT kind FROM inbound_events WHERE event_id = ?1",
                params![event_id.clone()],
            )
            .await
            .map_err(|e| be(&e))?;
        let kind: String = match first(rows).await? {
            Some(r) => r.get(0).map_err(|e| be(&e))?,
            None => {
                return Err(StoreError::Corrupt {
                    seq: 0,
                    detail: format!("event {event_id} vanished mid-claim"),
                });
            }
        };

        tx.commit().await.map_err(|e| be(&e))?;

        Ok(Some(BufferedEvent {
            event: InboundEvent {
                id: event_id,
                kind,
                correlation,
                payload: serde_json::from_str(&payload)?,
            },
            received_at: from_ts(received)?,
        }))
    }

    async fn match_waiter(
        &self,
        event: &InboundEvent,
        at: Timestamp,
    ) -> Result<Option<Subscription>, StoreError> {
        let mut conn = self.conn().await;
        let tx = conn.transaction().await.map_err(|err| be(&err))?;

        let mut found: Option<(String, String, Option<String>, i64, String)> = None;
        for k in &event.correlation {
            let rows = tx
                .query(
                    "SELECT run_id, effect_key, case_id, step, phase FROM subscriptions
                     WHERE event_kind = ?1 AND namespace = ?2 AND value = ?3
                     ORDER BY created_at ASC LIMIT 1",
                    params![event.kind.clone(), k.namespace.clone(), k.value.clone()],
                )
                .await
                .map_err(|err| be(&err))?;
            if let Some(r) = first(rows).await? {
                found = Some((
                    r.get(0).map_err(|e| be(&e))?,
                    r.get(1).map_err(|e| be(&e))?,
                    r.get(2).map_err(|e| be(&e))?,
                    r.get(3).map_err(|e| be(&e))?,
                    r.get(4).map_err(|e| be(&e))?,
                ));
                break;
            }
        }

        let Some((run, effect, case, step, phase)) = found else {
            tx.commit().await.map_err(|err| be(&err))?;
            return Ok(None);
        };

        // Claim the event for this run in the same transaction, so one message
        // cannot resume two runs.
        let claimed = tx
            .execute(
                "UPDATE inbound_events SET claimed_by = ?2, claimed_at = ?3
                 WHERE event_id = ?1 AND claimed_by IS NULL AND dead = 0",
                params![event.id.clone(), run.clone(), ts(at)],
            )
            .await
            .map_err(|err| be(&err))?;
        if claimed == 0 {
            // Someone else took it between the select and here.
            tx.commit().await.map_err(|err| be(&err))?;
            return Ok(None);
        }

        let mut rows = tx
            .query(
                "SELECT namespace, value FROM subscriptions
                 WHERE run_id = ?1 AND effect_key = ?2 ORDER BY namespace, value",
                params![run.clone(), effect.clone()],
            )
            .await
            .map_err(|err| be(&err))?;
        let mut correlation: Vec<CorrelationKey> = Vec::new();
        while let Some(r) = rows.next().await.map_err(|err| be(&err))? {
            correlation.push(CorrelationKey::new(
                r.get::<String>(0).map_err(|e| be(&e))?,
                r.get::<String>(1).map_err(|e| be(&e))?,
            ));
        }
        drop(rows);

        tx.commit().await.map_err(|err| be(&err))?;

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
            kind: event.kind.clone(),
            correlation,
        }))
    }

    async fn unsubscribe(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError> {
        let conn = self.conn().await;
        conn.execute(
            "DELETE FROM subscriptions WHERE run_id = ?1 AND effect_key = ?2",
            params![run.to_string(), effect.to_hex()],
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
        let conn = self.conn().await;
        let n = conn
            .execute(
                // `<=`, not `<`: a zero grace window must retire everything
                // already buffered. With second-granularity timestamps, `<`
                // silently spares anything received in the current second.
                "UPDATE inbound_events SET dead = 1, dead_reason = ?2
                 WHERE claimed_by IS NULL AND dead = 0 AND received_at <= ?1",
                params![ts(older_than), reason.to_owned()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(usize::try_from(n).unwrap_or(usize::MAX))
    }

    async fn dead_letters(&self, limit: usize) -> Result<Vec<DeadLetter>, StoreError> {
        let conn = self.conn().await;
        let mut rows = conn
            .query(
                "SELECT event_id, kind, payload, received_at, dead_reason
                 FROM inbound_events WHERE dead = 1
                 ORDER BY received_at DESC LIMIT ?1",
                params![i64::try_from(limit).unwrap_or(i64::MAX)],
            )
            .await
            .map_err(|e| be(&e))?;

        let mut raw = Vec::new();
        while let Some(r) = rows.next().await.map_err(|e| be(&e))? {
            raw.push((
                r.get::<String>(0).map_err(|e| be(&e))?,
                r.get::<String>(1).map_err(|e| be(&e))?,
                r.get::<String>(2).map_err(|e| be(&e))?,
                r.get::<i64>(3).map_err(|e| be(&e))?,
                r.get::<Option<String>>(4).map_err(|e| be(&e))?,
            ));
        }
        drop(rows);

        let mut out = Vec::new();
        for (id, kind, payload, received, reason) in raw {
            let correlation = load_correlation(&conn, &id).await?;
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
    }

    async fn waiting(&self, limit: usize) -> Result<Vec<Subscription>, StoreError> {
        let conn = self.conn().await;
        let mut rows = conn
            .query(
                "SELECT run_id, effect_key, event_kind, namespace, value, case_id, step, phase
                 FROM subscriptions ORDER BY created_at ASC LIMIT ?1",
                params![i64::try_from(limit).unwrap_or(i64::MAX)],
            )
            .await
            .map_err(|e| be(&e))?;

        let mut out = Vec::new();
        while let Some(r) = rows.next().await.map_err(|e| be(&e))? {
            let run: String = r.get(0).map_err(|e| be(&e))?;
            let effect: String = r.get(1).map_err(|e| be(&e))?;
            let kind: String = r.get(2).map_err(|e| be(&e))?;
            let ns: String = r.get(3).map_err(|e| be(&e))?;
            let v: String = r.get(4).map_err(|e| be(&e))?;
            let case: Option<String> = r.get(5).map_err(|e| be(&e))?;
            let step: i64 = r.get(6).map_err(|e| be(&e))?;
            let phase: String = r.get(7).map_err(|e| be(&e))?;

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
    }
}
