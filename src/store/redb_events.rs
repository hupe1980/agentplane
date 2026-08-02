//! Inbound events on redb.
//!
//! Claiming is the delicate part. Both directions — a wait looking for a
//! buffered event, and an event looking for a waiter — select and mark the
//! winner inside one write transaction. Without that, two runs waiting on one
//! key could both consume a single message, or one message could resume two
//! runs.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::case::{BufferedEvent, EventStore};
use crate::core::{
    CaseId, CorrelationKey, DeadLetter, EffectKey, InboundEvent, RunId, StoreError, Subscription,
    Timestamp,
};

use super::redb::{MAX_STR, RedbStore, be};

/// `event_id -> (kind, payload, received_at, claimed_by, claimed_at, has_claim,
/// dead, dead_reason)`.
const EVENTS: TableDefinition<&str, (&str, &str, i64, &str, i64, u8, u8, &str)> =
    TableDefinition::new("inbound_events");

/// `(event_id, namespace, value) -> ()`, an event's own keys.
const EVENT_CORR: TableDefinition<(&str, &str, &str), ()> =
    TableDefinition::new("inbound_correlation");

/// `(namespace, value, received_at, event_id) -> ()`, the match path.
///
/// Ordered by arrival within a key, so the oldest unclaimed message for a key is
/// the first entry rather than the result of a scan.
const EVENT_BY_KEY: TableDefinition<(&str, &str, i64, &str), ()> =
    TableDefinition::new("inbound_by_key");

/// `(run_id, effect_key, namespace, value) -> (case_id, has_case, step, phase, kind, created_at)`.
const SUBS: TableDefinition<(&str, &str, &str, &str), (&str, u8, u32, &str, &str, i64)> =
    TableDefinition::new("subscriptions");

/// `(event_kind, namespace, value, created_at, run_id, effect_key) -> ()`.
const SUBS_BY_KEY: TableDefinition<(&str, &str, &str, i64, &str, &str), ()> =
    TableDefinition::new("subscriptions_by_key");

/// `(received_at, event_id) -> ()`, unclaimed and live — the sweep's access
/// path, oldest first.
///
/// Without it the sweep reads every event ever received to find the few that
/// have expired, which is a scan that quietly stops finishing on time exactly
/// when the backlog matters most.
const EVENTS_LIVE: TableDefinition<(i64, &str), ()> = TableDefinition::new("inbound_live");

/// `(received_at, event_id) -> ()`, retired events, for the dead-letter view.
const EVENTS_DEAD: TableDefinition<(i64, &str), ()> = TableDefinition::new("inbound_dead");

/// `(created_at, run_id, effect_key, namespace, value) -> ()`, waits in
/// registration order.
const SUBS_BY_TIME: TableDefinition<(i64, &str, &str, &str, &str), ()> =
    TableDefinition::new("subscriptions_by_time");

pub(super) fn create_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(EVENTS).map_err(|e| be(&e))?;
    w.open_table(EVENT_CORR).map_err(|e| be(&e))?;
    w.open_table(EVENT_BY_KEY).map_err(|e| be(&e))?;
    w.open_table(SUBS).map_err(|e| be(&e))?;
    w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
    w.open_table(EVENTS_LIVE).map_err(|e| be(&e))?;
    w.open_table(EVENTS_DEAD).map_err(|e| be(&e))?;
    w.open_table(SUBS_BY_TIME).map_err(|e| be(&e))?;
    Ok(())
}

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
        // Anything else is the forward pass. An unknown value can only come from
        // a future version, and treating it as forward keeps the read total
        // rather than failing a delivery on a column it does not know.
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
    t: &impl ReadableTable<(&'static str, &'static str, &'static str), ()>,
    event_id: &str,
) -> Result<Vec<CorrelationKey>, StoreError> {
    let mut out = Vec::new();
    for e in t
        .range((event_id, "", "")..=(event_id, MAX_STR, MAX_STR))
        .map_err(|e| be(&e))?
    {
        let (k, _) = e.map_err(|e| be(&e))?;
        let (_, ns, v) = k.value();
        out.push(CorrelationKey::new(ns.to_owned(), v.to_owned()));
    }
    Ok(out)
}

#[async_trait]
impl EventStore for RedbStore {
    async fn buffer(&self, event: &InboundEvent, at: Timestamp) -> Result<bool, StoreError> {
        let id = event.id.clone();
        let kind = event.kind.clone();
        let payload = serde_json::to_string(&event.payload)?;
        let keys = event.correlation.clone();
        self.with_db(move |db| {
            let w = db.begin_write().map_err(|e| be(&e))?;
            let fresh = {
                let mut ev = w.open_table(EVENTS).map_err(|e| be(&e))?;
                if ev.get(id.as_str()).map_err(|e| be(&e))?.is_some() {
                    false
                } else {
                    ev.insert(
                        id.as_str(),
                        (
                            kind.as_str(),
                            payload.as_str(),
                            ts(at),
                            "",
                            0i64,
                            0u8,
                            0u8,
                            "",
                        ),
                    )
                    .map_err(|e| be(&e))?;
                    w.open_table(EVENTS_LIVE)
                        .map_err(|e| be(&e))?
                        .insert((ts(at), id.as_str()), ())
                        .map_err(|e| be(&e))?;
                    let mut corr = w.open_table(EVENT_CORR).map_err(|e| be(&e))?;
                    let mut by_key = w.open_table(EVENT_BY_KEY).map_err(|e| be(&e))?;
                    for k in &keys {
                        corr.insert((id.as_str(), k.namespace.as_str(), k.value.as_str()), ())
                            .map_err(|e| be(&e))?;
                        by_key
                            .insert(
                                (k.namespace.as_str(), k.value.as_str(), ts(at), id.as_str()),
                                (),
                            )
                            .map_err(|e| be(&e))?;
                    }
                    true
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(fresh)
        })
        .await
    }

    async fn subscribe(&self, sub: &Subscription, at: Timestamp) -> Result<(), StoreError> {
        let run = sub.run.to_string();
        let effect = sub.effect.to_hex();
        let case = sub.case.map(|c| c.to_string()).unwrap_or_default();
        let has_case = u8::from(sub.case.is_some());
        let step = sub.step.0;
        let phase = phase_str(sub.phase);
        let kind = sub.kind.clone();
        let keys = sub.correlation.clone();
        self.with_db(move |db| {
            let w = db.begin_write().map_err(|e| be(&e))?;
            {
                let mut subs = w.open_table(SUBS).map_err(|e| be(&e))?;
                let mut by_key = w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
                let mut by_time = w.open_table(SUBS_BY_TIME).map_err(|e| be(&e))?;
                for k in &keys {
                    let key = (
                        run.as_str(),
                        effect.as_str(),
                        k.namespace.as_str(),
                        k.value.as_str(),
                    );
                    if subs.get(key).map_err(|e| be(&e))?.is_none() {
                        subs.insert(
                            key,
                            (case.as_str(), has_case, step, phase, kind.as_str(), ts(at)),
                        )
                        .map_err(|e| be(&e))?;
                        by_key
                            .insert(
                                (
                                    kind.as_str(),
                                    k.namespace.as_str(),
                                    k.value.as_str(),
                                    ts(at),
                                    run.as_str(),
                                    effect.as_str(),
                                ),
                                (),
                            )
                            .map_err(|e| be(&e))?;
                        by_time
                            .insert(
                                (
                                    ts(at),
                                    run.as_str(),
                                    effect.as_str(),
                                    k.namespace.as_str(),
                                    k.value.as_str(),
                                ),
                                (),
                            )
                            .map_err(|e| be(&e))?;
                    }
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn claim_for(
        &self,
        sub: &Subscription,
        at: Timestamp,
    ) -> Result<Option<BufferedEvent>, StoreError> {
        let run = sub.run.to_string();
        let kind = sub.kind.clone();
        let keys = sub.correlation.clone();
        self.with_db(move |db| {
            let w = db.begin_write().map_err(|e| be(&e))?;
            let found = {
                let by_key = w.open_table(EVENT_BY_KEY).map_err(|e| be(&e))?;
                let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;

                let mut hit = None;
                'outer: for k in &keys {
                    for e in by_key
                        .range(
                            (k.namespace.as_str(), k.value.as_str(), i64::MIN, "")
                                ..=(k.namespace.as_str(), k.value.as_str(), i64::MAX, MAX_STR),
                        )
                        .map_err(|e| be(&e))?
                    {
                        let (ek, _) = e.map_err(|e| be(&e))?;
                        let id = ek.value().3.to_owned();
                        let Some(row) = events.get(id.as_str()).map_err(|e| be(&e))?.map(|v| {
                            let (kd, pl, ra, _, _, hc, dead, _) = v.value();
                            (kd.to_owned(), pl.to_owned(), ra, hc, dead)
                        }) else {
                            continue;
                        };
                        if row.0 == kind && row.3 == 0 && row.4 == 0 {
                            hit = Some((id, row));
                            break 'outer;
                        }
                    }
                }

                match hit {
                    None => None,
                    Some((id, (kd, payload, received, _, _))) => {
                        // Claimed in the same transaction that selected it: two
                        // runs waiting on one key must not both consume a single
                        // message.
                        events
                            .insert(
                                id.as_str(),
                                (
                                    kd.as_str(),
                                    payload.as_str(),
                                    received,
                                    run.as_str(),
                                    ts(at),
                                    1u8,
                                    0u8,
                                    "",
                                ),
                            )
                            .map_err(|e| be(&e))?;
                        drop(events);
                        // No longer sweepable: the index moves with the row it
                        // describes, in the row's transaction.
                        w.open_table(EVENTS_LIVE)
                            .map_err(|e| be(&e))?
                            .remove((received, id.as_str()))
                            .map_err(|e| be(&e))?;
                        let corr_t = w.open_table(EVENT_CORR).map_err(|e| be(&e))?;
                        let correlation = load_correlation(&corr_t, &id)?;
                        Some(BufferedEvent {
                            event: InboundEvent {
                                id,
                                kind: kd,
                                correlation,
                                payload: serde_json::from_str(&payload)?,
                            },
                            received_at: from_ts(received)?,
                        })
                    }
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(found)
        })
        .await
    }

    async fn match_waiter(
        &self,
        event: &InboundEvent,
        at: Timestamp,
    ) -> Result<Option<Subscription>, StoreError> {
        let id = event.id.clone();
        let kind = event.kind.clone();
        let keys = event.correlation.clone();
        self.with_db(move |db| {
            let w = db.begin_write().map_err(|e| be(&e))?;
            // One expression, no early returns: the tables below borrow `w`, and
            // redb's commit consumes it.
            let found = {
                let by_key = w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
                let subs = w.open_table(SUBS).map_err(|e| be(&e))?;

                let mut hit = None;
                'outer: for k in &keys {
                    for e in by_key
                        .range(
                            (
                                kind.as_str(),
                                k.namespace.as_str(),
                                k.value.as_str(),
                                i64::MIN,
                                "",
                                "",
                            )
                                ..=(
                                    kind.as_str(),
                                    k.namespace.as_str(),
                                    k.value.as_str(),
                                    i64::MAX,
                                    MAX_STR,
                                    MAX_STR,
                                ),
                        )
                        .map_err(|e| be(&e))?
                    {
                        let (sk, _) = e.map_err(|e| be(&e))?;
                        let (_, ns, val, _, run, effect) = sk.value();
                        if let Some(v) = subs.get((run, effect, ns, val)).map_err(|e| be(&e))? {
                            let (c, hc, st, ph, _, _) = v.value();
                            hit = Some((
                                run.to_owned(),
                                effect.to_owned(),
                                c.to_owned(),
                                hc,
                                st,
                                ph.to_owned(),
                            ));
                            break 'outer;
                        }
                    }
                }
                drop(by_key);

                match hit {
                    None => None,
                    Some((run, effect, case, has_case, step, phase)) => {
                        // Claim the event for this run in the same transaction,
                        // so one message cannot resume two runs.
                        let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;
                        let row = events.get(id.as_str()).map_err(|e| be(&e))?.map(|v| {
                            let (kd, pl, ra, _, _, hc, dead, _) = v.value();
                            (kd.to_owned(), pl.to_owned(), ra, hc, dead)
                        });
                        // Absent, already claimed, or dead: somebody else took it
                        // between the select and here.
                        let claimable = row
                            .as_ref()
                            .is_some_and(|(_, _, _, hc, dead)| *hc == 0 && *dead == 0);
                        if !claimable {
                            None
                        } else {
                            let (kd, pl, ra, _, _) = row.expect("claimable implies present");
                            events
                                .insert(
                                    id.as_str(),
                                    (
                                        kd.as_str(),
                                        pl.as_str(),
                                        ra,
                                        run.as_str(),
                                        ts(at),
                                        1u8,
                                        0u8,
                                        "",
                                    ),
                                )
                                .map_err(|e| be(&e))?;
                            drop(events);
                            w.open_table(EVENTS_LIVE)
                                .map_err(|e| be(&e))?
                                .remove((ra, id.as_str()))
                                .map_err(|e| be(&e))?;

                            let mut correlation = Vec::new();
                            for e in subs
                                .range(
                                    (run.as_str(), effect.as_str(), "", "")
                                        ..=(run.as_str(), effect.as_str(), MAX_STR, MAX_STR),
                                )
                                .map_err(|e| be(&e))?
                            {
                                let (k, _) = e.map_err(|e| be(&e))?;
                                let (_, _, ns, v) = k.value();
                                correlation.push(CorrelationKey::new(ns.to_owned(), v.to_owned()));
                            }

                            Some(Subscription {
                                run: RunId::parse(&run).map_err(|e| StoreError::Corrupt {
                                    seq: 0,
                                    detail: format!("bad run id '{run}': {e}"),
                                })?,
                                case: if has_case == 1 {
                                    Some(CaseId::parse(&case).map_err(|e| StoreError::Corrupt {
                                        seq: 0,
                                        detail: format!("bad case id '{case}': {e}"),
                                    })?)
                                } else {
                                    None
                                },
                                effect: EffectKey::from_hex(&effect).map_err(|e| {
                                    StoreError::Corrupt {
                                        seq: 0,
                                        detail: format!("bad effect key '{effect}': {e}"),
                                    }
                                })?,
                                step: crate::core::StepId(step),
                                phase: phase_from(&phase),
                                kind: kind.clone(),
                                correlation,
                            })
                        }
                    }
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(found)
        })
        .await
    }

    async fn unsubscribe(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError> {
        let (run, effect) = (run.to_string(), effect.to_hex());
        self.with_db(move |db| {
            let w = db.begin_write().map_err(|e| be(&e))?;
            {
                let mut subs = w.open_table(SUBS).map_err(|e| be(&e))?;
                let mut doomed = Vec::new();
                for e in subs
                    .range(
                        (run.as_str(), effect.as_str(), "", "")
                            ..=(run.as_str(), effect.as_str(), MAX_STR, MAX_STR),
                    )
                    .map_err(|e| be(&e))?
                {
                    let (k, v) = e.map_err(|e| be(&e))?;
                    let (_, _, ns, val) = k.value();
                    let (_, _, _, _, kind, created) = v.value();
                    doomed.push((ns.to_owned(), val.to_owned(), kind.to_owned(), created));
                }
                let mut by_key = w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
                let mut by_time = w.open_table(SUBS_BY_TIME).map_err(|e| be(&e))?;
                for (ns, val, kind, created) in doomed {
                    subs.remove((run.as_str(), effect.as_str(), ns.as_str(), val.as_str()))
                        .map_err(|e| be(&e))?;
                    // The index goes with it, in the same transaction: a stale
                    // index entry would hand a message to a run that stopped
                    // waiting.
                    by_key
                        .remove((
                            kind.as_str(),
                            ns.as_str(),
                            val.as_str(),
                            created,
                            run.as_str(),
                            effect.as_str(),
                        ))
                        .map_err(|e| be(&e))?;
                    by_time
                        .remove((
                            created,
                            run.as_str(),
                            effect.as_str(),
                            ns.as_str(),
                            val.as_str(),
                        ))
                        .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn sweep_unclaimed(
        &self,
        older_than: Timestamp,
        reason: &str,
    ) -> Result<usize, StoreError> {
        let cutoff = ts(older_than);
        let reason = reason.to_owned();
        self.with_db(move |db| {
            let w = db.begin_write().map_err(|e| be(&e))?;
            let n = {
                // A range over the live index, not a scan of every event ever
                // received. `<=`, not `<`: a zero grace window must retire
                // everything already buffered, and with second-granularity
                // stamps `<` silently spares anything received this second.
                let live = w.open_table(EVENTS_LIVE).map_err(|e| be(&e))?;
                let mut doomed = Vec::new();
                for e in live
                    .range((i64::MIN, "")..=(cutoff, MAX_STR))
                    .map_err(|e| be(&e))?
                {
                    let (k, _) = e.map_err(|e| be(&e))?;
                    let (at, id) = k.value();
                    doomed.push((at, id.to_owned()));
                }
                drop(live);

                let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;
                let mut live = w.open_table(EVENTS_LIVE).map_err(|e| be(&e))?;
                let mut dead = w.open_table(EVENTS_DEAD).map_err(|e| be(&e))?;
                let mut n = 0usize;
                for (at, id) in doomed {
                    let Some(row) = events.get(id.as_str()).map_err(|e| be(&e))?.map(|v| {
                        let (kd, pl, ra, _, _, hc, d, _) = v.value();
                        (kd.to_owned(), pl.to_owned(), ra, hc, d)
                    }) else {
                        continue;
                    };
                    // The index decides, with no second opinion on top of it.
                    // Both are written in this one transaction, so they cannot
                    // drift; re-checking the row here would mask a maintenance
                    // bug instead of preventing one, leaving the guarantee held
                    // by two mechanisms and falsifiable by neither. If the
                    // index is ever wrong, the store conformance battery sees a
                    // delivered message in the dead-letter queue.
                    events
                        .insert(
                            id.as_str(),
                            (
                                row.0.as_str(),
                                row.1.as_str(),
                                row.2,
                                "",
                                0i64,
                                0u8,
                                1u8,
                                reason.as_str(),
                            ),
                        )
                        .map_err(|e| be(&e))?;
                    live.remove((at, id.as_str())).map_err(|e| be(&e))?;
                    dead.insert((row.2, id.as_str()), ()).map_err(|e| be(&e))?;
                    n += 1;
                }
                n
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(n)
        })
        .await
    }

    async fn dead_letters(&self, limit: usize) -> Result<Vec<DeadLetter>, StoreError> {
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let dead = r.open_table(EVENTS_DEAD).map_err(|e| be(&e))?;
            let events = r.open_table(EVENTS).map_err(|e| be(&e))?;
            let corr = r.open_table(EVENT_CORR).map_err(|e| be(&e))?;

            let mut out = Vec::new();
            // Newest first, taken from the index in reverse rather than by
            // sorting every retired event.
            for e in dead.iter().map_err(|e| be(&e))?.rev() {
                if out.len() >= limit {
                    break;
                }
                let (k, _) = e.map_err(|e| be(&e))?;
                let id = k.value().1;
                let Some(v) = events.get(id).map_err(|e| be(&e))? else {
                    continue;
                };
                let (kind, payload, received, _, _, _, _, reason) = v.value();
                out.push(DeadLetter {
                    event: InboundEvent {
                        id: id.to_owned(),
                        kind: kind.to_owned(),
                        correlation: load_correlation(&corr, id)?,
                        payload: serde_json::from_str(payload)?,
                    },
                    received_at: from_ts(received)?,
                    reason: if reason.is_empty() {
                        "unclaimed".to_owned()
                    } else {
                        reason.to_owned()
                    },
                });
            }
            Ok(out)
        })
        .await
    }

    async fn waiting(&self, limit: usize) -> Result<Vec<Subscription>, StoreError> {
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let by_time = r.open_table(SUBS_BY_TIME).map_err(|e| be(&e))?;
            let subs = r.open_table(SUBS).map_err(|e| be(&e))?;

            let mut out = Vec::new();
            // Registration order is the index's own order, so this is a bounded
            // walk rather than reading every wait and sorting them.
            for e in by_time.iter().map_err(|e| be(&e))? {
                if out.len() >= limit {
                    break;
                }
                let (k, _) = e.map_err(|e| be(&e))?;
                let (_, run, effect, ns, val) = k.value();
                let Some(v) = subs.get((run, effect, ns, val)).map_err(|e| be(&e))? else {
                    continue;
                };
                let (case, has_case, step, phase, kind, _) = v.value();
                out.push(Subscription {
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
                    kind: kind.to_owned(),
                    correlation: vec![CorrelationKey::new(ns.to_owned(), val.to_owned())],
                });
            }
            Ok(out)
        })
        .await
    }
}
