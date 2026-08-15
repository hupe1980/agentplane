//! Inbound events on redb.
//!
//! Claiming is the delicate part. Both directions — a wait looking for a
//! buffered event, and an event looking for a waiter — select and mark the
//! winner inside one write transaction. Without that, two runs waiting on one
//! key could both consume a single message, or one message could resume two
//! runs.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::case::{BufferedEvent, EventStore, TargetedDelivery};
use crate::core::{
    CaseId, CorrelationKey, DeadLetter, EffectKey, InboundEvent, RunId, StoreError, Subscription,
    Timestamp,
};

use super::redb::{MAX_STR, RedbStore, be, begin_write};

/// `(source, id) -> (source, id, kind, payload, received_at, claimed_by,
/// claimed_at, has_claim, dead, dead_reason)`.
///
/// Keyed by the pair, not by `id`: `id` is unique only within one producer, so
/// two counterparties numbering their messages from one would silently
/// deduplicate into each other. `source` is stored as well as keyed because a
/// reconstructed event must be the event that arrived — provenance included,
/// and with the *bare* id rather than the composite key it is filed under.
/// Splitting the key back apart on read would be a second place that has to
/// agree about the separator.
type EventRow<'a> = (
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    i64,
    &'a str,
    i64,
    u8,
    u8,
    &'a str,
);

const EVENTS: TableDefinition<(&str, &str), EventRow<'static>> =
    TableDefinition::new("inbound_events");

/// `(tenant, event_id, namespace, value) -> ()`, an event's own keys.
const EVENT_CORR: TableDefinition<(&str, &str, &str, &str), ()> =
    TableDefinition::new("inbound_correlation");

/// `(tenant, namespace, value, received_at, event_id) -> ()`, the match path.
///
/// Ordered by arrival within a key, so the oldest unclaimed message for a key is
/// the first entry rather than the result of a scan.
///
/// The tenant leads for the same reason it leads the subscription index: a
/// correlation key is a business value, and two tenants using `order`/`A-1` is
/// ordinary. The event body is fetched under the tenant afterwards, so a
/// cross-tenant hit here is discarded rather than delivered — but that leaves
/// isolation resting on one lookup, and a range that cannot see another
/// tenant's rows is a constraint rather than a check somebody must remember.
const EVENT_BY_KEY: TableDefinition<(&str, &str, &str, i64, &str), ()> =
    TableDefinition::new("inbound_by_key");

/// `(run_id, effect_key, namespace, value) -> (case_id, has_case, step, phase, kind, created_at)`.
/// `(case_id, has_case, step, phase, kind, created_at)`.
type SubRow<'a> = (&'a str, u8, u32, &'a str, &'a str, i64);

const SUBS: TableDefinition<(&str, &str, &str, &str, &str), SubRow<'static>> =
    TableDefinition::new("subscriptions");

/// `(tenant, event_kind, namespace, value, created_at, run_id, effect_key)`.
///
/// The tenant leads because this is the *match* path: a range that did not
/// bound it could hand one tenant's event to another tenant's waiting run,
/// which is the worst thing an event store can do.
type SubKey<'a> = (&'a str, &'a str, &'a str, &'a str, i64, &'a str, &'a str);

/// `(event_kind, namespace, value, created_at, run_id, effect_key) -> ()`.
const SUBS_BY_KEY: TableDefinition<SubKey<'static>, ()> =
    TableDefinition::new("subscriptions_by_key");

/// `(received_at, event_id) -> ()`, unclaimed and live — the sweep's access
/// path, oldest first.
///
/// Without it the sweep reads every event ever received to find the few that
/// have expired, which is a scan that quietly stops finishing on time exactly
/// when the backlog matters most.
const EVENTS_LIVE: TableDefinition<(&str, i64, &str), ()> = TableDefinition::new("inbound_live");

/// `(received_at, event_id) -> ()`, retired events, for the dead-letter view.
const EVENTS_DEAD: TableDefinition<(&str, i64, &str), ()> = TableDefinition::new("inbound_dead");

/// `(tenant, run_id, event_id) -> ()`, events a run currently holds claimed.
///
/// The index `unsubscribe` strips delivered payloads through. Written in the
/// same transaction as every claim, removed when the run's unsubscribe sheds
/// the payload — without it, finding "the events this run claimed" is a scan
/// of every event the tenant ever received, on the hot path of every wait.
const EVENTS_CLAIMED: TableDefinition<(&str, &str, &str), ()> =
    TableDefinition::new("inbound_claimed");

/// `(created_at, run_id, effect_key, namespace, value) -> ()`, waits in
/// registration order.
const SUBS_BY_TIME: TableDefinition<(&str, i64, &str, &str, &str, &str), ()> =
    TableDefinition::new("subscriptions_by_time");

pub(super) fn create_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(EVENTS).map_err(|e| be(&e))?;
    w.open_table(EVENT_CORR).map_err(|e| be(&e))?;
    w.open_table(EVENT_BY_KEY).map_err(|e| be(&e))?;
    w.open_table(SUBS).map_err(|e| be(&e))?;
    w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
    w.open_table(EVENTS_LIVE).map_err(|e| be(&e))?;
    w.open_table(EVENTS_DEAD).map_err(|e| be(&e))?;
    w.open_table(EVENTS_CLAIMED).map_err(|e| be(&e))?;
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
    t: &impl ReadableTable<(&'static str, &'static str, &'static str, &'static str), ()>,
    tenant: &str,
    event_id: &str,
) -> Result<Vec<CorrelationKey>, StoreError> {
    let mut out = Vec::new();
    for e in t
        .range((tenant, event_id, "", "")..=(tenant, event_id, MAX_STR, MAX_STR))
        .map_err(|e| be(&e))?
    {
        let (k, _) = e.map_err(|e| be(&e))?;
        let (_, _, ns, v) = k.value();
        out.push(CorrelationKey::new(ns.to_owned(), v.to_owned()));
    }
    Ok(out)
}

/// A waiting subscription's identity and the fields needed to rebuild it:
/// `(run_id, effect_key, case_id, has_case, step, phase)`.
type Waiter = (String, String, String, u8, u32, String);

/// Stamp an event row as claimed by one run.
///
/// Extracted because `match_waiter` was over the line limit, and because this is
/// the one write that decides a message belongs to a run — worth being able to
/// find on its own.
fn claim_row(
    events: &mut redb::Table<'_, (&'static str, &'static str), EventRow<'static>>,
    key: (&str, &str),
    row: (&str, &str, &str, &str, i64),
    claim: (&str, i64),
) -> Result<(), StoreError> {
    let (tenant, id) = key;
    let (src, bare, kind, payload, received) = row;
    let (run, at) = claim;
    events
        .insert(
            (tenant, id),
            (src, bare, kind, payload, received, run, at, 1u8, 0u8, ""),
        )
        .map_err(|e| be(&e))?;
    Ok(())
}

/// Replace an event row's payload with JSON `null`, keeping everything else.
///
/// The erasure primitive shared by `unsubscribe` (delivered rows) and
/// `erase_payload` (unclaimed and dead-lettered rows). The row's identity,
/// claim state and dead-letter accounting all survive: dedup needs the
/// `(source, id)` key so a replay of the erased message is still refused, and
/// the dead-letter list stays countable and attributable — only the
/// counterparty's content goes.
fn strip_payload(
    events: &mut redb::Table<'_, (&'static str, &'static str), EventRow<'static>>,
    tenant: &str,
    key: &str,
) -> Result<bool, StoreError> {
    let Some(row) = events.get((tenant, key)).map_err(|e| be(&e))?.map(|v| {
        let (src, bid, kd, _, ra, cb, ca, hc, dead, reason) = v.value();
        (
            src.to_owned(),
            bid.to_owned(),
            kd.to_owned(),
            ra,
            cb.to_owned(),
            ca,
            hc,
            dead,
            reason.to_owned(),
        )
    }) else {
        return Ok(false);
    };
    events
        .insert(
            (tenant, key),
            (
                row.0.as_str(),
                row.1.as_str(),
                row.2.as_str(),
                "null",
                row.3,
                row.4.as_str(),
                row.5,
                row.6,
                row.7,
                row.8.as_str(),
            ),
        )
        .map_err(|e| be(&e))?;
    Ok(true)
}

/// Write an event's correlation rows and its match-path index.
///
/// Its own function because `buffer` was over the line limit with it inline, and
/// because "file the event" and "make it findable" are separate jobs that fail
/// separately.
///
/// No tenant here: these rows point at an event, and the event row they point at
/// is tenant-keyed — so a lookup that crosses tenants finds a correlation entry
/// and then no event. The isolation is in `EVENTS`, and adding a second copy of
/// it here would be a second thing to keep in agreement.
fn index_correlation(
    w: &redb::WriteTransaction,
    tenant: &str,
    id: &str,
    keys: &[CorrelationKey],
    at: i64,
) -> Result<(), StoreError> {
    let mut corr = w.open_table(EVENT_CORR).map_err(|e| be(&e))?;
    let mut by_key = w.open_table(EVENT_BY_KEY).map_err(|e| be(&e))?;
    for k in keys {
        corr.insert((tenant, id, k.namespace.as_str(), k.value.as_str()), ())
            .map_err(|e| be(&e))?;
        by_key
            .insert((tenant, k.namespace.as_str(), k.value.as_str(), at, id), ())
            .map_err(|e| be(&e))?;
    }
    Ok(())
}

/// The oldest subscription waiting on any of `keys` for this event kind.
///
/// Separate from [`EventStore::match_waiter`] because it answers a different
/// question — *who is waiting* — from the one the caller acts on, which is
/// *may I claim this for them*. Returns the wait's identity and the fields the
/// caller needs to rebuild it.
fn oldest_waiter(
    tenant: &str,
    by_key: &impl ReadableTable<SubKey<'static>, ()>,
    subs: &impl ReadableTable<
        (
            &'static str,
            &'static str,
            &'static str,
            &'static str,
            &'static str,
        ),
        SubRow<'static>,
    >,
    kind: &str,
    keys: &[CorrelationKey],
) -> Result<Option<Waiter>, StoreError> {
    for k in keys {
        for e in by_key
            .range(
                (
                    tenant,
                    kind,
                    k.namespace.as_str(),
                    k.value.as_str(),
                    i64::MIN,
                    "",
                    "",
                )
                    ..=(
                        tenant,
                        kind,
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
            let (_, _, ns, val, _, run, effect) = sk.value();
            if let Some(v) = subs
                .get((tenant, run, effect, ns, val))
                .map_err(|e| be(&e))?
            {
                let (case, has_case, step, phase, _, _) = v.value();
                return Ok(Some((
                    run.to_owned(),
                    effect.to_owned(),
                    case.to_owned(),
                    has_case,
                    step,
                    phase.to_owned(),
                )));
            }
        }
    }
    Ok(None)
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl EventStore for RedbStore {
    fn tenant(&self) -> &str {
        self.tenant_str()
    }

    async fn buffer(&self, event: &InboundEvent, at: Timestamp) -> Result<bool, StoreError> {
        let tenant = self.tenant_name();
        let id = event.dedup_key();
        let bare_id = event.id.clone();
        let source = event.source.clone();
        let kind = event.kind.clone();
        let payload = serde_json::to_string(&event.payload)?;
        let keys = event.correlation.clone();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let fresh = {
                let mut ev = w.open_table(EVENTS).map_err(|e| be(&e))?;
                if ev
                    .get((tenant.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?
                    .is_some()
                {
                    false
                } else {
                    ev.insert(
                        (tenant.as_str(), id.as_str()),
                        (
                            source.as_str(),
                            bare_id.as_str(),
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
                        .insert((tenant.as_str(), ts(at), id.as_str()), ())
                        .map_err(|e| be(&e))?;
                    index_correlation(&w, &tenant, &id, &keys, ts(at))?;
                    true
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(fresh)
        })
        .await
    }

    async fn subscribe(&self, sub: &Subscription, at: Timestamp) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let run = sub.run.to_string();
        let effect = sub.effect.to_hex();
        let case = sub.case.map(|c| c.to_string()).unwrap_or_default();
        let has_case = u8::from(sub.case.is_some());
        let step = sub.step.0;
        let phase = phase_str(sub.phase);
        let kind = sub.kind.clone();
        let keys = sub.correlation.clone();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut subs = w.open_table(SUBS).map_err(|e| be(&e))?;
                let mut by_key = w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
                let mut by_time = w.open_table(SUBS_BY_TIME).map_err(|e| be(&e))?;
                for k in &keys {
                    let key = (
                        tenant.as_str(),
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
                                    tenant.as_str(),
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
                                    tenant.as_str(),
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
        let tenant = self.tenant_name();
        let run = sub.run.to_string();
        let kind = sub.kind.clone();
        let keys = sub.correlation.clone();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let found = {
                let by_key = w.open_table(EVENT_BY_KEY).map_err(|e| be(&e))?;
                let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;

                let mut hit = None;
                'outer: for k in &keys {
                    for e in by_key
                        .range(
                            (
                                tenant.as_str(),
                                k.namespace.as_str(),
                                k.value.as_str(),
                                i64::MIN,
                                "",
                            )
                                ..=(
                                    tenant.as_str(),
                                    k.namespace.as_str(),
                                    k.value.as_str(),
                                    i64::MAX,
                                    MAX_STR,
                                ),
                        )
                        .map_err(|e| be(&e))?
                    {
                        let (ek, _) = e.map_err(|e| be(&e))?;
                        let id = ek.value().4.to_owned();
                        let Some(row) = events
                            .get((tenant.as_str(), id.as_str()))
                            .map_err(|e| be(&e))?
                            .map(|v| {
                                let (src, bid, kd, pl, ra, claimed_by, _, hc, dead, _) = v.value();
                                (
                                    kd.to_owned(),
                                    pl.to_owned(),
                                    ra,
                                    hc,
                                    dead,
                                    src.to_owned(),
                                    bid.to_owned(),
                                    claimed_by.to_owned(),
                                )
                            })
                        else {
                            continue;
                        };
                        // Unclaimed — or already claimed **by this very run**.
                        // The second arm is crash recovery, and it is the same
                        // idempotence `deliver_to` grants a retried targeted
                        // delivery: `match_waiter` claims durably and the run
                        // resumes in a separate step, so a crash between the
                        // two leaves an event claimed for a run that never saw
                        // it. Without this arm the resumed wait re-subscribes,
                        // finds nothing — its own event filtered out by its own
                        // claim — and sleeps until the deadline breaches: the
                        // message arrived in time and was lost anyway. Single
                        // delivery is untouched, because only the claiming run
                        // can re-claim.
                        if row.0 == kind && (row.3 == 0 || row.7 == run) && row.4 == 0 {
                            hit = Some((id, row));
                            break 'outer;
                        }
                    }
                }

                match hit {
                    None => None,
                    Some((id, (kd, payload, received, _, _, src, bid, _))) => {
                        // Claimed in the same transaction that selected it: two
                        // runs waiting on one key must not both consume a single
                        // message.
                        events
                            .insert(
                                (tenant.as_str(), id.as_str()),
                                (
                                    src.as_str(),
                                    bid.as_str(),
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
                            .remove((tenant.as_str(), received, id.as_str()))
                            .map_err(|e| be(&e))?;
                        // Findable by the claiming run, so its unsubscribe can
                        // shed the delivered payload without a scan.
                        w.open_table(EVENTS_CLAIMED)
                            .map_err(|e| be(&e))?
                            .insert((tenant.as_str(), run.as_str(), id.as_str()), ())
                            .map_err(|e| be(&e))?;
                        let corr_t = w.open_table(EVENT_CORR).map_err(|e| be(&e))?;
                        let correlation = load_correlation(&corr_t, &tenant, &id)?;
                        Some(BufferedEvent {
                            event: InboundEvent {
                                source: src,
                                id: bid,
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
        let tenant = self.tenant_name();
        // The dedup key, not the bare id: `buffer` stored the row under
        // `(source, id)`, and looking it up by `id` alone finds nothing — the
        // event is durable and no waiter ever matches it.
        let id = event.dedup_key();
        let kind = event.kind.clone();
        let keys = event.correlation.clone();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            // One expression, no early returns: the tables below borrow `w`, and
            // redb's commit consumes it.
            let found = {
                let by_key = w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
                let mut subs = w.open_table(SUBS).map_err(|e| be(&e))?;
                let hit = oldest_waiter(&tenant, &by_key, &subs, &kind, &keys)?;
                drop(by_key);

                match hit {
                    None => None,
                    Some((run, effect, case, has_case, step, phase)) => {
                        // Claim the event for this run in the same transaction,
                        // so one message cannot resume two runs.
                        let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;
                        let row = events
                            .get((tenant.as_str(), id.as_str()))
                            .map_err(|e| be(&e))?
                            .map(|v| {
                                let (src, bid, kd, pl, ra, _, _, hc, dead, _) = v.value();
                                (
                                    kd.to_owned(),
                                    pl.to_owned(),
                                    ra,
                                    hc,
                                    dead,
                                    src.to_owned(),
                                    bid.to_owned(),
                                )
                            });
                        // Absent, already claimed, or dead: somebody else took it
                        // between the select and here.
                        let claimable = row
                            .as_ref()
                            .is_some_and(|(_, _, _, hc, dead, _, _)| *hc == 0 && *dead == 0);
                        if claimable {
                            let (kd, pl, ra, _, _, src, bid) =
                                row.expect("claimable implies present");
                            claim_row(
                                &mut events,
                                (&tenant, &id),
                                (&src, &bid, &kd, &pl, ra),
                                (&run, ts(at)),
                            )?;
                            drop(events);
                            w.open_table(EVENTS_LIVE)
                                .map_err(|e| be(&e))?
                                .remove((tenant.as_str(), ra, id.as_str()))
                                .map_err(|e| be(&e))?;
                            // Findable by the claiming run, so its unsubscribe
                            // can shed the delivered payload without a scan.
                            w.open_table(EVENTS_CLAIMED)
                                .map_err(|e| be(&e))?
                                .insert((tenant.as_str(), run.as_str(), id.as_str()), ())
                                .map_err(|e| be(&e))?;

                            let mut correlation = Vec::new();
                            let mut retired = Vec::new();
                            for e in subs
                                .range(
                                    (tenant.as_str(), run.as_str(), effect.as_str(), "", "")
                                        ..=(
                                            tenant.as_str(),
                                            run.as_str(),
                                            effect.as_str(),
                                            MAX_STR,
                                            MAX_STR,
                                        ),
                                )
                                .map_err(|e| be(&e))?
                            {
                                let (k, v) = e.map_err(|e| be(&e))?;
                                let (_, _, _, ns, val) = k.value();
                                let (_, _, _, _, sub_kind, created) = v.value();
                                correlation
                                    .push(CorrelationKey::new(ns.to_owned(), val.to_owned()));
                                retired.push((
                                    ns.to_owned(),
                                    val.to_owned(),
                                    sub_kind.to_owned(),
                                    created,
                                ));
                            }
                            // The claim retires the subscription, in the same
                            // transaction. Left registered until the run's own
                            // unsubscribe, it matched a *second* event —
                            // sequentially, no race required — which was then
                            // claimed for a run whose wait the first event
                            // already satisfied: parked under a claim nobody
                            // consumes, and claimed events never dead-letter.
                            // The resumed wait re-subscribes idempotently and
                            // recovers its own claimed event through the
                            // crash-recovery arm, so nothing legitimate needs
                            // the stale registration.
                            for (ns, val, sub_kind, created) in retired {
                                subs.remove((
                                    tenant.as_str(),
                                    run.as_str(),
                                    effect.as_str(),
                                    ns.as_str(),
                                    val.as_str(),
                                ))
                                .map_err(|e| be(&e))?;
                                let mut by_key = w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
                                by_key
                                    .remove((
                                        tenant.as_str(),
                                        sub_kind.as_str(),
                                        ns.as_str(),
                                        val.as_str(),
                                        created,
                                        run.as_str(),
                                        effect.as_str(),
                                    ))
                                    .map_err(|e| be(&e))?;
                                let mut by_time = w.open_table(SUBS_BY_TIME).map_err(|e| be(&e))?;
                                by_time
                                    .remove((
                                        tenant.as_str(),
                                        created,
                                        run.as_str(),
                                        effect.as_str(),
                                        ns.as_str(),
                                        val.as_str(),
                                    ))
                                    .map_err(|e| be(&e))?;
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
                        } else {
                            None
                        }
                    }
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(found)
        })
        .await
    }

    async fn deliver_to(
        &self,
        target: RunId,
        event: &InboundEvent,
        at: Timestamp,
    ) -> Result<TargetedDelivery, StoreError> {
        let tenant = self.tenant_name();
        let run = target.to_string();
        let id = event.dedup_key();
        let bare_id = event.id.clone();
        let source = event.source.clone();
        let kind = event.kind.clone();
        let payload = serde_json::to_string(&event.payload)?;
        let keys = event.correlation.clone();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let outcome = {
                let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;
                let existing_claim = events
                    .get((tenant.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|row| {
                        let (_, _, _, _, _, claimed_by, _, has_claim, _, _) = row.value();
                        (claimed_by.to_owned(), has_claim)
                    });
                let subs = w.open_table(SUBS).map_err(|e| be(&e))?;
                let mut selected: Option<(String, String, u8, u32, String)> = None;
                for row in subs
                    .range(
                        (tenant.as_str(), run.as_str(), "", "", "")
                            ..=(tenant.as_str(), run.as_str(), MAX_STR, MAX_STR, MAX_STR),
                    )
                    .map_err(|e| be(&e))?
                {
                    let (key, value) = row.map_err(|e| be(&e))?;
                    let (_, _, effect, namespace, value_key) = key.value();
                    let (case, has_case, step, phase, event_kind, _) = value.value();
                    if event_kind == kind
                        && keys.iter().any(|candidate| {
                            candidate.namespace == namespace && candidate.value == value_key
                        })
                    {
                        selected = Some((
                            effect.to_owned(),
                            case.to_owned(),
                            has_case,
                            step,
                            phase.to_owned(),
                        ));
                        break;
                    }
                }

                let Some((effect, case, has_case, step, phase)) = selected else {
                    drop(subs);
                    drop(events);
                    w.commit().map_err(|e| be(&e))?;
                    return Ok(if existing_claim.is_some() {
                        TargetedDelivery::Duplicate
                    } else {
                        TargetedDelivery::NotWaiting
                    });
                };

                let mut correlation = Vec::new();
                for row in subs
                    .range(
                        (tenant.as_str(), run.as_str(), effect.as_str(), "", "")
                            ..=(
                                tenant.as_str(),
                                run.as_str(),
                                effect.as_str(),
                                MAX_STR,
                                MAX_STR,
                            ),
                    )
                    .map_err(|e| be(&e))?
                {
                    let (key, _) = row.map_err(|e| be(&e))?;
                    let (_, _, _, namespace, value) = key.value();
                    correlation.push(CorrelationKey::new(namespace.to_owned(), value.to_owned()));
                }
                drop(subs);

                let subscription = Subscription {
                    run: target,
                    case: if has_case == 1 {
                        Some(CaseId::parse(&case).map_err(|e| StoreError::Corrupt {
                            seq: 0,
                            detail: format!("bad case id '{case}': {e}"),
                        })?)
                    } else {
                        None
                    },
                    effect: EffectKey::from_hex(&effect).map_err(|e| StoreError::Corrupt {
                        seq: 0,
                        detail: format!("bad effect key '{effect}': {e}"),
                    })?,
                    step: crate::core::StepId(step),
                    phase: phase_from(&phase),
                    kind: kind.clone(),
                    correlation,
                };

                if let Some((claimed_by, has_claim)) = existing_claim {
                    drop(events);
                    if has_claim == 1 && claimed_by == run {
                        TargetedDelivery::Matched(subscription)
                    } else {
                        TargetedDelivery::Duplicate
                    }
                } else {
                    events
                        .insert(
                            (tenant.as_str(), id.as_str()),
                            (
                                source.as_str(),
                                bare_id.as_str(),
                                kind.as_str(),
                                payload.as_str(),
                                ts(at),
                                run.as_str(),
                                ts(at),
                                1u8,
                                0u8,
                                "",
                            ),
                        )
                        .map_err(|e| be(&e))?;
                    drop(events);
                    index_correlation(&w, &tenant, &id, &keys, ts(at))?;
                    // Findable by the claiming run, so its unsubscribe can
                    // shed the delivered payload without a scan.
                    w.open_table(EVENTS_CLAIMED)
                        .map_err(|e| be(&e))?
                        .insert((tenant.as_str(), run.as_str(), id.as_str()), ())
                        .map_err(|e| be(&e))?;
                    // The subscription is deliberately **not** retired here,
                    // unlike `match_waiter` — the asymmetry is the two paths'
                    // retry semantics. A retried targeted delivery rebuilds
                    // its `Matched` from these rows to resume a run that
                    // crashed between claim and resume; and a second distinct
                    // message claimed through a satisfied wait is recovered by
                    // the protocol itself, because the task's next
                    // continuation re-matches the claimed event for the same
                    // run. The broadcast path has no such retry loop, which
                    // is why `match_waiter` retires and this does not.
                    TargetedDelivery::Matched(subscription)
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(outcome)
        })
        .await
    }

    async fn unsubscribe(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let (run, effect) = (run.to_string(), effect.to_hex());
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut subs = w.open_table(SUBS).map_err(|e| be(&e))?;
                let mut doomed = Vec::new();
                for e in subs
                    .range(
                        (tenant.as_str(), run.as_str(), effect.as_str(), "", "")
                            ..=(
                                tenant.as_str(),
                                run.as_str(),
                                effect.as_str(),
                                MAX_STR,
                                MAX_STR,
                            ),
                    )
                    .map_err(|e| be(&e))?
                {
                    let (k, v) = e.map_err(|e| be(&e))?;
                    let (_, _, _, ns, val) = k.value();
                    let (_, _, _, _, kind, created) = v.value();
                    doomed.push((ns.to_owned(), val.to_owned(), kind.to_owned(), created));
                }
                let mut by_key = w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
                let mut by_time = w.open_table(SUBS_BY_TIME).map_err(|e| be(&e))?;
                for (ns, val, kind, created) in doomed {
                    subs.remove((
                        tenant.as_str(),
                        run.as_str(),
                        effect.as_str(),
                        ns.as_str(),
                        val.as_str(),
                    ))
                    .map_err(|e| be(&e))?;
                    // The index goes with it, in the same transaction: a stale
                    // index entry would hand a message to a run that stopped
                    // waiting.
                    by_key
                        .remove((
                            tenant.as_str(),
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
                            tenant.as_str(),
                            created,
                            run.as_str(),
                            effect.as_str(),
                            ns.as_str(),
                            val.as_str(),
                        ))
                        .map_err(|e| be(&e))?;
                }
            }
            {
                // The run's unsubscribe is the store's signal that delivery
                // was journaled, so the buffer's copy of every payload this
                // run claimed is shed here — the row keeps its `(source, id)`
                // identity, claim and dead-letter fields, because dedup and
                // accounting need those and only the content was ever the
                // erasure concern. Stripping at the *claim* instead would lose
                // the payload for a run that crashed between claim and
                // resume, whose recovery re-reads it from the buffer.
                let mut claimed = w.open_table(EVENTS_CLAIMED).map_err(|e| be(&e))?;
                let held: Vec<String> = claimed
                    .range(
                        (tenant.as_str(), run.as_str(), "")
                            ..=(tenant.as_str(), run.as_str(), MAX_STR),
                    )
                    .map_err(|e| be(&e))?
                    .map(|entry| {
                        entry
                            .map(|(key, _)| key.value().2.to_owned())
                            .map_err(|error| be(&error))
                    })
                    .collect::<Result<_, _>>()?;
                let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;
                for id in held {
                    strip_payload(&mut events, &tenant, &id)?;
                    claimed
                        .remove((tenant.as_str(), run.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn erase_payload(&self, source: &str, id: &str) -> Result<bool, StoreError> {
        let tenant = self.tenant_name();
        // Through the one implementation of the dedup identity, not a second
        // spelling of its separator.
        let key = InboundEvent {
            source: source.to_owned(),
            id: id.to_owned(),
            kind: String::new(),
            correlation: Vec::new(),
            payload: serde_json::Value::Null,
        }
        .dedup_key();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let existed = {
                let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;
                strip_payload(&mut events, &tenant, &key)?
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(existed)
        })
        .await
    }

    async fn sweep_unclaimed(
        &self,
        older_than: Timestamp,
        reason: &str,
    ) -> Result<usize, StoreError> {
        let tenant = self.tenant_name();
        let cutoff = ts(older_than);
        let reason = reason.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let n = {
                // A range over the live index, not a scan of every event ever
                // received. `<=`, not `<`: a zero grace window must retire
                // everything already buffered, and with second-granularity
                // stamps `<` silently spares anything received this second.
                let live = w.open_table(EVENTS_LIVE).map_err(|e| be(&e))?;
                let mut doomed = Vec::new();
                for e in live
                    .range((tenant.as_str(), i64::MIN, "")..=(tenant.as_str(), cutoff, MAX_STR))
                    .map_err(|e| be(&e))?
                {
                    let (k, _) = e.map_err(|e| be(&e))?;
                    let (_, at, id) = k.value();
                    doomed.push((at, id.to_owned()));
                }
                drop(live);

                let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;
                let mut live = w.open_table(EVENTS_LIVE).map_err(|e| be(&e))?;
                let mut dead = w.open_table(EVENTS_DEAD).map_err(|e| be(&e))?;
                let mut n = 0usize;
                for (at, id) in doomed {
                    let Some(row) = events
                        .get((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?
                        .map(|v| {
                            let (src, bid, kd, pl, ra, _, _, hc, d, _) = v.value();
                            (
                                kd.to_owned(),
                                pl.to_owned(),
                                ra,
                                hc,
                                d,
                                src.to_owned(),
                                bid.to_owned(),
                            )
                        })
                    else {
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
                            (tenant.as_str(), id.as_str()),
                            (
                                row.5.as_str(),
                                row.6.as_str(),
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
                    live.remove((tenant.as_str(), at, id.as_str()))
                        .map_err(|e| be(&e))?;
                    dead.insert((tenant.as_str(), row.2, id.as_str()), ())
                        .map_err(|e| be(&e))?;
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
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let dead = r.open_table(EVENTS_DEAD).map_err(|e| be(&e))?;
            let events = r.open_table(EVENTS).map_err(|e| be(&e))?;
            let corr = r.open_table(EVENT_CORR).map_err(|e| be(&e))?;

            let mut out = Vec::new();
            // Newest first, taken from the index in reverse rather than by
            // sorting every retired event — and over this tenant's range, since
            // a dead-letter view is read by an operator deciding what went
            // wrong and must not show them another tenant's traffic.
            for e in dead
                .range((tenant.as_str(), i64::MIN, "")..=(tenant.as_str(), i64::MAX, MAX_STR))
                .map_err(|e| be(&e))?
                .rev()
            {
                if out.len() >= limit {
                    break;
                }
                let (k, _) = e.map_err(|e| be(&e))?;
                let id = k.value().2;
                let Some(v) = events.get((tenant.as_str(), id)).map_err(|e| be(&e))? else {
                    continue;
                };
                let (source, bare, kind, payload, received, _, _, _, _, reason) = v.value();
                out.push(DeadLetter {
                    event: InboundEvent {
                        source: source.to_owned(),
                        id: bare.to_owned(),
                        kind: kind.to_owned(),
                        correlation: load_correlation(&corr, &tenant, id)?,
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
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let by_time = r.open_table(SUBS_BY_TIME).map_err(|e| be(&e))?;
            let subs = r.open_table(SUBS).map_err(|e| be(&e))?;

            let mut out = Vec::new();
            // Registration order is the index's own order, so this is a bounded
            // walk rather than reading every wait and sorting them — and it is
            // ranged to this tenant, like every sibling read. The whole-table
            // walk this replaces leaned on the row lookup below being
            // tenant-keyed, which held for *leaking* but not for *counting*:
            // another tenant registering the same `(run, effect, key)` tuple —
            // all attacker-suppliable strings — made this tenant's row match
            // twice, and one wait listed as two is an operator paging over
            // phantom backlog another tenant controls the size of.
            for e in by_time
                .range(
                    (tenant.as_str(), i64::MIN, "", "", "", "")
                        ..=(
                            tenant.as_str(),
                            i64::MAX,
                            MAX_STR,
                            MAX_STR,
                            MAX_STR,
                            MAX_STR,
                        ),
                )
                .map_err(|e| be(&e))?
            {
                if out.len() >= limit {
                    break;
                }
                let (k, _) = e.map_err(|e| be(&e))?;
                let (_, _, run, effect, ns, val) = k.value();
                let Some(v) = subs
                    .get((tenant.as_str(), run, effect, ns, val))
                    .map_err(|e| be(&e))?
                else {
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
