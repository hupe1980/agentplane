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

use super::redb::{MAX_STR, RedbStore, be, begin_write, decoded, is_sealed};

fn phase_from(s: &str) -> Result<crate::core::Phase, StoreError> {
    decoded("step phase", s, crate::core::Phase::parse(s))
}

/// `(source, id) -> (source, id, kind, payload, received_at, claimed_by,
/// claimed_at, has_claim, dead, dead_reason, by_actor, by_basis)`.
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
    // The operator this plane minted the message for, and what established
    // the name — empty for everything that arrived over a wire. Two slots
    // rather than a rendered string, as every other operator row here is.
    &'a str,
    &'a str,
);

/// The two slots an operator occupies in a row, or empty for a wire message.
///
/// One encoder, because two would agree until the day a basis is added.
fn encode_minter(by: Option<&crate::core::Operator>) -> (String, String) {
    by.map_or_else(
        || (String::new(), String::new()),
        |o| (o.actor().to_owned(), o.basis().as_str().to_owned()),
    )
}

/// The inverse. Empty means nobody minted it; half-filled is corruption.
fn decode_minter(actor: &str, basis: &str) -> Result<Option<crate::core::Operator>, StoreError> {
    match (actor.is_empty(), basis.is_empty()) {
        (true, true) => Ok(None),
        (false, false) => super::decode_operator(actor, basis, "inbound_events").map(Some),
        _ => Err(StoreError::Corrupt {
            seq: 0,
            detail: "inbound_events holds half an operator: a minted event carries a \
                     name and what established it, or neither"
                .to_owned(),
        }),
    }
}

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

/// `(run_id, effect_key, namespace, value) -> (case_id, has_case, step, phase, kind, created_at, from)`.
type SubRow<'a> = (&'a str, u8, u32, &'a str, &'a str, i64, Option<&'a str>);

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

/// `(tenant, run_id, event_id) -> effect_key`, events a run holds claimed and
/// has not yet consumed, with the wait each was claimed for.
///
/// The wait is what makes a claim recoverable without being re-consumable: a
/// wait recovers only a claim made for it, and only while the entry stands.
/// Written in the same transaction as every claim, removed when that wait's
/// unsubscribe sheds the payload — so retiring one wait never strips another
/// wait's undelivered message, and a consumed message is never handed to the
/// run's next wait on the same key.
const EVENTS_CLAIMED: TableDefinition<(&str, &str, &str), &str> =
    TableDefinition::new("inbound_claimed");

/// `(tenant, event_id) -> ()`, messages delivered to one run by name.
///
/// A message addressed to a run is that run's alone: one its run never
/// consumed is dead-lettered when the run's waits retire, never offered to
/// another run waiting on the same key.
const EVENTS_TARGETED: TableDefinition<(&str, &str), ()> = TableDefinition::new("inbound_targeted");

/// `(created_at, run_id, effect_key, namespace, value) -> ()`, waits in
/// registration order.
const SUBS_BY_TIME: TableDefinition<(&str, i64, &str, &str, &str, &str), ()> =
    TableDefinition::new("subscriptions_by_time");

/// `(tenant, run_id, effect_key) -> parked_at`, waits holding a claimed event
/// nothing has delivered yet.
///
/// The redelivery pass's access path. It walks this rather than
/// [`SUBS_BY_TIME`], which holds every registered wait: a plane holds far more
/// long, legitimate waits than one redelivery page, and a parked pair behind
/// them would never be reached. Cleared with the subscription it marks.
const PARKED: TableDefinition<(&str, &str, &str), i64> =
    TableDefinition::new("subscriptions_parked");

/// `(tenant, event_id) -> ()`, rows whose payload `erase_payload` removed.
///
/// Its own table rather than a thirteenth column: set once and never cleared,
/// and read only by the claim that must never hand an erased row to a run as
/// a value, whatever its claim says.
const EVENTS_ERASED: TableDefinition<(&str, &str), ()> = TableDefinition::new("inbound_erased");

pub(super) fn create_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(EVENTS_ERASED).map_err(|e| be(&e))?;
    w.open_table(EVENTS).map_err(|e| be(&e))?;
    w.open_table(EVENT_CORR).map_err(|e| be(&e))?;
    w.open_table(EVENT_BY_KEY).map_err(|e| be(&e))?;
    w.open_table(SUBS).map_err(|e| be(&e))?;
    w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
    w.open_table(EVENTS_LIVE).map_err(|e| be(&e))?;
    w.open_table(EVENTS_DEAD).map_err(|e| be(&e))?;
    w.open_table(EVENTS_CLAIMED).map_err(|e| be(&e))?;
    w.open_table(EVENTS_TARGETED).map_err(|e| be(&e))?;
    w.open_table(SUBS_BY_TIME).map_err(|e| be(&e))?;
    w.open_table(PARKED).map_err(|e| be(&e))?;
    Ok(())
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
type Waiter = (String, String, String, u8, u32, String, Option<String>);

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
    by: (&str, &str),
) -> Result<(), StoreError> {
    let (tenant, id) = key;
    let (src, bare, kind, payload, received) = row;
    let (run, at) = claim;
    events
        .insert(
            (tenant, id),
            (
                src, bare, kind, payload, received, run, at, 1u8, 0u8, "", by.0, by.1,
            ),
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
        let (src, bid, kd, _, ra, cb, ca, hc, dead, reason, ba, bb) = v.value();
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
            // Kept, like the claim state and the dead-letter accounting: an
            // erasure destroys the counterparty's content, and *who on this
            // plane minted the message* is not that. It is the same rule the
            // journal holds for an operator's name.
            ba.to_owned(),
            bb.to_owned(),
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
                row.9.as_str(),
                row.10.as_str(),
            ),
        )
        .map_err(|e| be(&e))?;
    Ok(true)
}

/// Retire an erased event nobody had claimed, with the reason `erased`.
///
/// Its payload is already `null`; left live, the next matching waiter would
/// claim that `null` as the counterparty's message. Dead-lettered instead, it
/// keeps its identity for dedup and names itself in the operator's list.
fn dead_letter_as_erased(
    w: &redb::WriteTransaction,
    events: &mut redb::Table<'_, (&'static str, &'static str), EventRow<'static>>,
    tenant: &str,
    key: &str,
    received: i64,
) -> Result<(), StoreError> {
    let Some(row) = events.get((tenant, key)).map_err(|e| be(&e))?.map(|v| {
        let (src, bid, kd, pl, ra, _, _, _, _, _, ba, bb) = v.value();
        (
            src.to_owned(),
            bid.to_owned(),
            kd.to_owned(),
            pl.to_owned(),
            ra,
            ba.to_owned(),
            bb.to_owned(),
        )
    }) else {
        return Ok(());
    };
    events
        .insert(
            (tenant, key),
            (
                row.0.as_str(),
                row.1.as_str(),
                row.2.as_str(),
                row.3.as_str(),
                row.4,
                "",
                0i64,
                0u8,
                1u8,
                crate::case::ERASED_REASON,
                row.5.as_str(),
                row.6.as_str(),
            ),
        )
        .map_err(|e| be(&e))?;
    w.open_table(EVENTS_LIVE)
        .map_err(|e| be(&e))?
        .remove((tenant, received, key))
        .map_err(|e| be(&e))?;
    w.open_table(EVENTS_DEAD)
        .map_err(|e| be(&e))?
        .insert((tenant, received, key), ())
        .map_err(|e| be(&e))?;
    Ok(())
}

/// Unpark the waits of `run` that `event_id`'s correlation keys match.
///
/// The erasure of a claimed, undelivered event releases its claim; the wait
/// that was parked holding it is a wait again, matchable by the next event,
/// rather than a pair the redelivery pass tries for ever.
fn unpark_for(
    w: &redb::WriteTransaction,
    tenant: &str,
    run: &str,
    event_id: &str,
) -> Result<(), StoreError> {
    let keys = load_correlation(
        &w.open_table(EVENT_CORR).map_err(|e| be(&e))?,
        tenant,
        event_id,
    )?;
    let effects: Vec<String> = w
        .open_table(PARKED)
        .map_err(|e| be(&e))?
        .range((tenant, run, "")..=(tenant, run, MAX_STR))
        .map_err(|e| be(&e))?
        .map(|e| e.map(|(k, _)| k.value().2.to_owned()).map_err(|e| be(&e)))
        .collect::<Result<_, _>>()?;
    let subs = w.open_table(SUBS).map_err(|e| be(&e))?;
    let mut matching = Vec::new();
    for effect in effects {
        for k in &keys {
            if subs
                .get((
                    tenant,
                    run,
                    effect.as_str(),
                    k.namespace.as_str(),
                    k.value.as_str(),
                ))
                .map_err(|e| be(&e))?
                .is_some()
            {
                matching.push(effect.clone());
                break;
            }
        }
    }
    drop(subs);
    let mut parked = w.open_table(PARKED).map_err(|e| be(&e))?;
    for effect in matching {
        parked
            .remove((tenant, run, effect.as_str()))
            .map_err(|e| be(&e))?;
    }
    Ok(())
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
    w: &redb::WriteTransaction,
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
    source: &str,
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
            // A sealed run consumes nothing. Passed over, so the event goes
            // to the next live waiter rather than to a claim nobody reads.
            if is_sealed(w, tenant, run)? {
                continue;
            }
            // A parked wait already holds its claimed event and is waiting
            // only for redelivery. It is not a waiter: a second event elected
            // for it would be claimed for a satisfied wait and never consumed.
            if is_parked(w, tenant, run, effect)? {
                continue;
            }
            if let Some(v) = subs
                .get((tenant, run, effect, ns, val))
                .map_err(|e| be(&e))?
            {
                let (case, has_case, step, phase, _, _, from) = v.value();
                // A wait naming its sender is not a waiter for anyone else.
                if from.is_some_and(|from| from != source) {
                    continue;
                }
                return Ok(Some((
                    run.to_owned(),
                    effect.to_owned(),
                    case.to_owned(),
                    has_case,
                    step,
                    phase.to_owned(),
                    from.map(str::to_owned),
                )));
            }
        }
    }
    Ok(None)
}

/// Whether a wait is parked: it holds a claimed event nothing delivered yet.
fn is_parked(
    w: &redb::WriteTransaction,
    tenant: &str,
    run: &str,
    effect: &str,
) -> Result<bool, StoreError> {
    Ok(w.open_table(PARKED)
        .map_err(|e| be(&e))?
        .get((tenant, run, effect))
        .map_err(|e| be(&e))?
        .is_some())
}

/// Register a wait under each of its correlation keys, in the caller's
/// transaction. Idempotent per key: a resumed run re-registering the same wait
/// keeps its original registration instant.
fn register_wait(
    w: &redb::WriteTransaction,
    tenant: &str,
    sub: &Subscription,
    at: i64,
) -> Result<(), StoreError> {
    let run = sub.run.to_string();
    let effect = sub.effect.to_hex();
    let case = sub.case.map(|c| c.to_string()).unwrap_or_default();
    let has_case = u8::from(sub.case.is_some());
    let phase = sub.phase.as_str();
    let mut subs = w.open_table(SUBS).map_err(|e| be(&e))?;
    let mut by_key = w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
    let mut by_time = w.open_table(SUBS_BY_TIME).map_err(|e| be(&e))?;
    for k in &sub.correlation {
        let key = (
            tenant,
            run.as_str(),
            effect.as_str(),
            k.namespace.as_str(),
            k.value.as_str(),
        );
        if subs.get(key).map_err(|e| be(&e))?.is_none() {
            subs.insert(
                key,
                (
                    case.as_str(),
                    has_case,
                    sub.step.0,
                    phase,
                    sub.kind.as_str(),
                    at,
                    sub.from.as_deref(),
                ),
            )
            .map_err(|e| be(&e))?;
            by_key
                .insert(
                    (
                        tenant,
                        sub.kind.as_str(),
                        k.namespace.as_str(),
                        k.value.as_str(),
                        at,
                        run.as_str(),
                        effect.as_str(),
                    ),
                    (),
                )
                .map_err(|e| be(&e))?;
            by_time
                .insert(
                    (
                        tenant,
                        at,
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
    Ok(())
}

/// Retire one wait — its rows, both indexes and its parked mark — in the
/// caller's transaction. A stale index entry would hand a message to a run
/// that stopped waiting.
fn drop_wait(
    w: &redb::WriteTransaction,
    tenant: &str,
    run: &str,
    effect: &str,
) -> Result<(), StoreError> {
    let mut subs = w.open_table(SUBS).map_err(|e| be(&e))?;
    let mut doomed = Vec::new();
    for e in subs
        .range((tenant, run, effect, "", "")..=(tenant, run, effect, MAX_STR, MAX_STR))
        .map_err(|e| be(&e))?
    {
        let (k, v) = e.map_err(|e| be(&e))?;
        let (_, _, _, ns, val) = k.value();
        let (_, _, _, _, kind, created, _) = v.value();
        doomed.push((ns.to_owned(), val.to_owned(), kind.to_owned(), created));
    }
    let mut by_key = w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
    let mut by_time = w.open_table(SUBS_BY_TIME).map_err(|e| be(&e))?;
    for (ns, val, kind, created) in doomed {
        subs.remove((tenant, run, effect, ns.as_str(), val.as_str()))
            .map_err(|e| be(&e))?;
        by_key
            .remove((
                tenant,
                kind.as_str(),
                ns.as_str(),
                val.as_str(),
                created,
                run,
                effect,
            ))
            .map_err(|e| be(&e))?;
        by_time
            .remove((tenant, created, run, effect, ns.as_str(), val.as_str()))
            .map_err(|e| be(&e))?;
    }
    w.open_table(PARKED)
        .map_err(|e| be(&e))?
        .remove((tenant, run, effect))
        .map_err(|e| be(&e))?;
    Ok(())
}

/// Shed the buffer's copy of the payloads `run` holds claimed for `effect`,
/// or for every wait when `effect` is `None`.
///
/// A wait's unsubscribe is the store's signal that its delivery was journaled,
/// so the row keeps its `(source, id)` identity, claim and dead-letter fields —
/// dedup and accounting need those, and only the content was ever the erasure
/// concern. Stripping at the *claim* instead would lose the payload for a run
/// that crashed between claim and resume, whose recovery re-reads it from the
/// buffer.
fn shed_claimed(
    w: &redb::WriteTransaction,
    tenant: &str,
    run: &str,
    effect: Option<&str>,
) -> Result<(), StoreError> {
    let mut claimed = w.open_table(EVENTS_CLAIMED).map_err(|e| be(&e))?;
    let held: Vec<String> = claimed
        .range((tenant, run, "")..=(tenant, run, MAX_STR))
        .map_err(|e| be(&e))?
        .filter_map(|entry| match entry {
            Ok((key, value)) => effect
                .is_none_or(|effect| value.value() == effect)
                .then(|| Ok(key.value().2.to_owned())),
            Err(error) => Some(Err(be(&error))),
        })
        .collect::<Result<_, _>>()?;
    let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;
    for id in held {
        strip_payload(&mut events, tenant, &id)?;
        claimed
            .remove((tenant, run, id.as_str()))
            .map_err(|e| be(&e))?;
    }
    Ok(())
}

/// Hand back to the buffer, unclaimed and live, what `run` holds claimed for
/// a wait in `unanswered`, and return those messages.
fn release_claimed(
    w: &redb::WriteTransaction,
    tenant: &str,
    run: &str,
    unanswered: &std::collections::BTreeSet<String>,
) -> Result<Vec<InboundEvent>, StoreError> {
    let mut claimed = w.open_table(EVENTS_CLAIMED).map_err(|e| be(&e))?;
    let held: Vec<String> = claimed
        .range((tenant, run, "")..=(tenant, run, MAX_STR))
        .map_err(|e| be(&e))?
        .filter_map(|entry| match entry {
            Ok((key, effect)) => unanswered
                .contains(effect.value())
                .then(|| Ok(key.value().2.to_owned())),
            Err(error) => Some(Err(be(&error))),
        })
        .collect::<Result<_, _>>()?;
    let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;
    let mut live = w.open_table(EVENTS_LIVE).map_err(|e| be(&e))?;
    let corr = w.open_table(EVENT_CORR).map_err(|e| be(&e))?;
    let mut released = Vec::with_capacity(held.len());
    for id in held {
        claimed
            .remove((tenant, run, id.as_str()))
            .map_err(|e| be(&e))?;
        let Some((src, bid, kind, payload, received, dead, ba, bb)) = events
            .get((tenant, id.as_str()))
            .map_err(|e| be(&e))?
            .map(|v| {
                let (src, bid, kd, pl, ra, _, _, _, dead, _, ba, bb) = v.value();
                (
                    src.to_owned(),
                    bid.to_owned(),
                    kd.to_owned(),
                    pl.to_owned(),
                    ra,
                    dead,
                    ba.to_owned(),
                    bb.to_owned(),
                )
            })
        else {
            continue;
        };
        if dead == 1 {
            continue;
        }
        let addressed = w
            .open_table(EVENTS_TARGETED)
            .map_err(|e| be(&e))?
            .get((tenant, id.as_str()))
            .map_err(|e| be(&e))?
            .is_some();
        events
            .insert(
                (tenant, id.as_str()),
                (
                    src.as_str(),
                    bid.as_str(),
                    kind.as_str(),
                    payload.as_str(),
                    received,
                    "",
                    0i64,
                    0u8,
                    u8::from(addressed),
                    if addressed {
                        crate::case::ADDRESSEE_CONCLUDED_REASON
                    } else {
                        ""
                    },
                    ba.as_str(),
                    bb.as_str(),
                ),
            )
            .map_err(|e| be(&e))?;
        if addressed {
            // Its run's alone: dead-lettered, never offered to another run.
            w.open_table(EVENTS_DEAD)
                .map_err(|e| be(&e))?
                .insert((tenant, received, id.as_str()), ())
                .map_err(|e| be(&e))?;
            continue;
        }
        live.insert((tenant, received, id.as_str()), ())
            .map_err(|e| be(&e))?;
        released.push(InboundEvent {
            correlation: load_correlation(&corr, tenant, &id)?,
            source: src,
            id: bid,
            kind,
            payload: serde_json::from_str(&payload)?,
            by: decode_minter(&ba, &bb)?,
        });
    }
    Ok(released)
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
        let (by_actor, by_basis) = encode_minter(event.by.as_ref());
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
                            by_actor.as_str(),
                            by_basis.as_str(),
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
        let sub = sub.clone();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            register_wait(&w, &tenant, &sub, ts(at))?;
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
        let effect = sub.effect.to_hex();
        let kind = sub.kind.clone();
        let keys = sub.correlation.clone();
        let wait = sub.clone();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let found = {
                // A wait already parked holds a claim — made by a delivery
                // that reached it between its registration and this call, or
                // before a crash — and recovers that one alone. Taking a second
                // message too would leave one of the two to be shed unread.
                let parked_here = w
                    .open_table(PARKED)
                    .map_err(|e| be(&e))?
                    .get((tenant.as_str(), run.as_str(), effect.as_str()))
                    .map_err(|e| be(&e))?
                    .is_some();
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
                                let (src, bid, kd, pl, ra, claimed_by, _, hc, dead, _, ba, bb) =
                                    v.value();
                                (
                                    kd.to_owned(),
                                    pl.to_owned(),
                                    ra,
                                    hc,
                                    dead,
                                    src.to_owned(),
                                    bid.to_owned(),
                                    claimed_by.to_owned(),
                                    ba.to_owned(),
                                    bb.to_owned(),
                                )
                            })
                        else {
                            continue;
                        };
                        // Unclaimed — or already claimed **for this very wait**
                        // and not yet consumed. The second arm is crash
                        // recovery: `match_waiter` claims durably and the run
                        // resumes in a separate step, so a crash between the
                        // two leaves an event claimed for a wait that never saw
                        // it. Scoped to the wait, not the run, and to a claim
                        // its unsubscribe has not consumed: a message the run
                        // already journaled is never handed to its next wait
                        // on the same key.
                        let own_claim = row.3 == 1
                            && row.7 == run
                            && w.open_table(EVENTS_CLAIMED)
                                .map_err(|e| be(&e))?
                                .get((tenant.as_str(), run.as_str(), id.as_str()))
                                .map_err(|e| be(&e))?
                                .is_some_and(|claimed| claimed.value() == effect);
                        let erased = w
                            .open_table(EVENTS_ERASED)
                            .map_err(|e| be(&e))?
                            .get((tenant.as_str(), id.as_str()))
                            .map_err(|e| be(&e))?
                            .is_some();
                        if row.0 == kind
                            && wait.accepts_source(&row.5)
                            && ((row.3 == 0 && !parked_here) || own_claim)
                            && row.4 == 0
                            && !erased
                        {
                            hit = Some((id, row));
                            break 'outer;
                        }
                    }
                }

                match hit {
                    None => None,
                    Some((id, (kd, payload, received, _, _, src, bid, _, ba, bb))) => {
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
                                    ba.as_str(),
                                    bb.as_str(),
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
                        // Findable by the claiming wait, so its unsubscribe can
                        // shed the delivered payload without a scan.
                        w.open_table(EVENTS_CLAIMED)
                            .map_err(|e| be(&e))?
                            .insert(
                                (tenant.as_str(), run.as_str(), id.as_str()),
                                effect.as_str(),
                            )
                            .map_err(|e| be(&e))?;
                        // Parked in the claim's transaction: a wait holding an
                        // undelivered message takes no second one, and a crash
                        // before it is journaled leaves a pair the redelivery
                        // pass finds.
                        w.open_table(PARKED)
                            .map_err(|e| be(&e))?
                            .insert((tenant.as_str(), run.as_str(), effect.as_str()), ts(at))
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
                                by: decode_minter(&ba, &bb)?,
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
        let source = event.source.clone();
        let keys = event.correlation.clone();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            // One expression, no early returns: the tables below borrow `w`, and
            // redb's commit consumes it.
            let found = {
                let by_key = w.open_table(SUBS_BY_KEY).map_err(|e| be(&e))?;
                let subs = w.open_table(SUBS).map_err(|e| be(&e))?;
                let hit = oldest_waiter(&w, &tenant, &by_key, &subs, &kind, &source, &keys)?;
                drop(by_key);

                match hit {
                    None => None,
                    Some((run, effect, case, has_case, step, phase, from)) => {
                        // Claim the event for this run in the same transaction,
                        // so one message cannot resume two runs.
                        let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;
                        let row = events
                            .get((tenant.as_str(), id.as_str()))
                            .map_err(|e| be(&e))?
                            .map(|v| {
                                let (src, bid, kd, pl, ra, _, _, hc, dead, _, ba, bb) = v.value();
                                (
                                    kd.to_owned(),
                                    pl.to_owned(),
                                    ra,
                                    hc,
                                    dead,
                                    src.to_owned(),
                                    bid.to_owned(),
                                    ba.to_owned(),
                                    bb.to_owned(),
                                )
                            });
                        // Absent, already claimed, or dead: somebody else took it
                        // between the select and here.
                        let claimable = row
                            .as_ref()
                            .is_some_and(|(_, _, _, hc, dead, ..)| *hc == 0 && *dead == 0);
                        if claimable {
                            let (kd, pl, ra, _, _, src, bid, ba, bb) =
                                row.expect("claimable implies present");
                            claim_row(
                                &mut events,
                                (&tenant, &id),
                                (&src, &bid, &kd, &pl, ra),
                                (&run, ts(at)),
                                (&ba, &bb),
                            )?;
                            drop(events);
                            w.open_table(EVENTS_LIVE)
                                .map_err(|e| be(&e))?
                                .remove((tenant.as_str(), ra, id.as_str()))
                                .map_err(|e| be(&e))?;
                            // Findable by the claiming wait, so its unsubscribe
                            // can shed the delivered payload without a scan.
                            w.open_table(EVENTS_CLAIMED)
                                .map_err(|e| be(&e))?
                                .insert(
                                    (tenant.as_str(), run.as_str(), id.as_str()),
                                    effect.as_str(),
                                )
                                .map_err(|e| be(&e))?;

                            let mut correlation = Vec::new();
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
                                let (k, _) = e.map_err(|e| be(&e))?;
                                let (_, _, _, ns, val) = k.value();
                                correlation
                                    .push(CorrelationKey::new(ns.to_owned(), val.to_owned()));
                            }
                            // The claim parks the subscription, in the same
                            // transaction: a parked wait is matched no second
                            // event, and a crash before the resume leaves a
                            // pair the redelivery pass finds and finishes. The
                            // wait's own unsubscribe, after its delivery is
                            // journaled, retires it.
                            w.open_table(PARKED)
                                .map_err(|e| be(&e))?
                                .insert((tenant.as_str(), run.as_str(), effect.as_str()), ts(at))
                                .map_err(|e| be(&e))?;

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
                                phase: phase_from(&phase)?,
                                kind: kind.clone(),
                                correlation,
                                from,
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
        let (by_actor, by_basis) = encode_minter(event.by.as_ref());
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let outcome = {
                let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;
                let existing_claim = events
                    .get((tenant.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|row| {
                        let (_, _, _, _, _, claimed_by, _, has_claim, _, _, _, _) = row.value();
                        (claimed_by.to_owned(), has_claim)
                    });
                // A message this run already holds claimed resumes the wait it
                // was claimed for, while that claim stands — a retry after a
                // crash between claim and resume. Consumed, or claimed by
                // another run, it is a duplicate. A new message goes to a wait
                // holding no undelivered message.
                let claimed_for: Option<String> = match &existing_claim {
                    Some((claimed_by, 1)) if *claimed_by == run => w
                        .open_table(EVENTS_CLAIMED)
                        .map_err(|e| be(&e))?
                        .get((tenant.as_str(), run.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?
                        .map(|effect| effect.value().to_owned()),
                    _ => None,
                };
                let parked = w.open_table(PARKED).map_err(|e| be(&e))?;
                let subs = w.open_table(SUBS).map_err(|e| be(&e))?;
                let mut selected: Option<(String, String, u8, u32, String, Option<String>)> = None;
                for row in subs
                    .range(
                        (tenant.as_str(), run.as_str(), "", "", "")
                            ..=(tenant.as_str(), run.as_str(), MAX_STR, MAX_STR, MAX_STR),
                    )
                    .map_err(|e| be(&e))?
                {
                    let (key, value) = row.map_err(|e| be(&e))?;
                    let (_, _, effect, namespace, value_key) = key.value();
                    let (case, has_case, step, phase, event_kind, _, from) = value.value();
                    let eligible = match (&existing_claim, &claimed_for) {
                        (Some(_), Some(claimed)) => claimed == effect,
                        (Some(_), None) => false,
                        (None, _) => parked
                            .get((tenant.as_str(), run.as_str(), effect))
                            .map_err(|e| be(&e))?
                            .is_none(),
                    };
                    if eligible
                        && event_kind == kind
                        && from.is_none_or(|from| from == source)
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
                            from.map(str::to_owned),
                        ));
                        break;
                    }
                }

                drop(parked);
                let Some((effect, case, has_case, step, phase, from)) = selected else {
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
                let subscription_effect = effect.clone();

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
                    phase: phase_from(&phase)?,
                    kind: kind.clone(),
                    correlation,
                    from,
                };

                if existing_claim.is_some() {
                    // Selected only as the wait its standing claim was made for.
                    drop(events);
                    TargetedDelivery::Matched(subscription)
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
                                by_actor.as_str(),
                                by_basis.as_str(),
                            ),
                        )
                        .map_err(|e| be(&e))?;
                    drop(events);
                    index_correlation(&w, &tenant, &id, &keys, ts(at))?;
                    w.open_table(EVENTS_TARGETED)
                        .map_err(|e| be(&e))?
                        .insert((tenant.as_str(), id.as_str()), ())
                        .map_err(|e| be(&e))?;
                    // Findable by the claiming wait, so its unsubscribe can
                    // shed the delivered payload without a scan.
                    w.open_table(EVENTS_CLAIMED)
                        .map_err(|e| be(&e))?
                        .insert(
                            (tenant.as_str(), run.as_str(), id.as_str()),
                            subscription_effect.as_str(),
                        )
                        .map_err(|e| be(&e))?;
                    // Parked until the run's unsubscribe: a crash between this
                    // claim and the resume leaves a pair the redelivery pass
                    // finds.
                    w.open_table(PARKED)
                        .map_err(|e| be(&e))?
                        .insert(
                            (tenant.as_str(), run.as_str(), subscription_effect.as_str()),
                            ts(at),
                        )
                        .map_err(|e| be(&e))?;
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
            drop_wait(&w, &tenant, &run, &effect)?;
            shed_claimed(&w, &tenant, &run, Some(&effect))?;
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn unsubscribe_run(
        &self,
        run: RunId,
        unanswered: &[EffectKey],
    ) -> Result<crate::case::Retired, StoreError> {
        let tenant = self.tenant_name();
        let run = run.to_string();
        let unanswered: std::collections::BTreeSet<String> =
            unanswered.iter().map(|effect| effect.to_hex()).collect();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let effects: std::collections::BTreeSet<String> = {
                let subs = w.open_table(SUBS).map_err(|e| be(&e))?;
                subs.range(
                    (tenant.as_str(), run.as_str(), "", "", "")
                        ..=(tenant.as_str(), run.as_str(), MAX_STR, MAX_STR, MAX_STR),
                )
                .map_err(|e| be(&e))?
                .map(|e| e.map(|(k, _)| k.value().2.to_owned()).map_err(|e| be(&e)))
                .collect::<Result<_, _>>()?
            };
            for effect in &effects {
                drop_wait(&w, &tenant, &run, effect)?;
            }
            let released = release_claimed(&w, &tenant, &run, &unanswered)?;
            shed_claimed(&w, &tenant, &run, None)?;
            w.commit().map_err(|e| be(&e))?;
            Ok(crate::case::Retired {
                waits: effects.len(),
                released,
            })
        })
        .await
    }

    async fn park_wait(&self, sub: &Subscription, at: Timestamp) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let sub = sub.clone();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            register_wait(&w, &tenant, &sub, ts(at))?;
            w.open_table(PARKED)
                .map_err(|e| be(&e))?
                .insert(
                    (
                        tenant.as_str(),
                        sub.run.to_string().as_str(),
                        sub.effect.to_hex().as_str(),
                    ),
                    ts(at),
                )
                .map_err(|e| be(&e))?;
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn parked_waits(&self, limit: usize) -> Result<Vec<Subscription>, StoreError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            // A sealed run can record no delivery. Its parked pairs are
            // retired here rather than listed, or the redelivery pass tries
            // each, fails, and finds it again every tick.
            let listed: Vec<(String, String)> = {
                let parked = w.open_table(PARKED).map_err(|e| be(&e))?;
                parked
                    .range((tenant.as_str(), "", "")..=(tenant.as_str(), MAX_STR, MAX_STR))
                    .map_err(|e| be(&e))?
                    .map(|e| {
                        e.map(|(k, _)| {
                            let (_, run, effect) = k.value();
                            (run.to_owned(), effect.to_owned())
                        })
                        .map_err(|e| be(&e))
                    })
                    .collect::<Result<_, _>>()?
            };
            let mut live = Vec::new();
            for (run, effect) in listed {
                if is_sealed(&w, &tenant, &run)? {
                    drop_wait(&w, &tenant, &run, &effect)?;
                    shed_claimed(&w, &tenant, &run, None)?;
                } else {
                    live.push((run, effect));
                }
            }
            let subs = w.open_table(SUBS).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            for (run, effect) in &live {
                if out.len() >= limit {
                    break;
                }
                let (run, effect) = (run.as_str(), effect.as_str());
                let mut found: Option<(String, u8, u32, String, String, Option<String>)> = None;
                let mut correlation = Vec::new();
                for row in subs
                    .range(
                        (tenant.as_str(), run, effect, "", "")
                            ..=(tenant.as_str(), run, effect, MAX_STR, MAX_STR),
                    )
                    .map_err(|e| be(&e))?
                {
                    let (key, value) = row.map_err(|e| be(&e))?;
                    let (_, _, _, ns, val) = key.value();
                    let (case, has_case, step, phase, kind, _, from) = value.value();
                    correlation.push(CorrelationKey::new(ns.to_owned(), val.to_owned()));
                    found.get_or_insert_with(|| {
                        (
                            case.to_owned(),
                            has_case,
                            step,
                            phase.to_owned(),
                            kind.to_owned(),
                            from.map(str::to_owned),
                        )
                    });
                }
                let Some((case, has_case, step, phase, kind, from)) = found else {
                    continue;
                };
                out.push(Subscription {
                    run: RunId::parse(run).map_err(|e| StoreError::Corrupt {
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
                    effect: EffectKey::from_hex(effect).map_err(|e| StoreError::Corrupt {
                        seq: 0,
                        detail: format!("bad effect key '{effect}': {e}"),
                    })?,
                    step: crate::core::StepId(step),
                    phase: phase_from(&phase)?,
                    kind,
                    correlation,
                    from,
                });
            }
            drop(subs);
            w.commit().map_err(|e| be(&e))?;
            Ok(out)
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
            by: None,
        }
        .dedup_key();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let existed = {
                let mut events = w.open_table(EVENTS).map_err(|e| be(&e))?;
                // Read before the strip: whether the row was still undelivered
                // decides whether it leaves the claimable set.
                let row = events
                    .get((tenant.as_str(), key.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|v| {
                        let (_, _, _, _, received, by, _, claimed, dead, _, _, _) = v.value();
                        (received, by.to_owned(), claimed == 1, dead == 1)
                    });
                let existed = strip_payload(&mut events, &tenant, &key)?;
                if existed {
                    w.open_table(EVENTS_ERASED)
                        .map_err(|e| be(&e))?
                        .insert((tenant.as_str(), key.as_str()), ())
                        .map_err(|e| be(&e))?;
                }
                if let Some((received, claimant, claimed, dead)) = row {
                    // Claimed and not yet journaled: the claimant's
                    // unsubscribe removes this index entry when it sheds the
                    // delivered payload, so an entry here is a claim no run
                    // has consumed.
                    let undelivered_claim = claimed
                        && w.open_table(EVENTS_CLAIMED)
                            .map_err(|e| be(&e))?
                            .remove((tenant.as_str(), claimant.as_str(), key.as_str()))
                            .map_err(|e| be(&e))?
                            .is_some();
                    if (!claimed && !dead) || undelivered_claim {
                        dead_letter_as_erased(&w, &mut events, &tenant, &key, received)?;
                    }
                    if undelivered_claim {
                        drop(events);
                        unpark_for(&w, &tenant, &claimant, &key)?;
                    }
                }
                existed
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(existed)
        })
        .await
    }

    async fn minter(
        &self,
        source: &str,
        id: &str,
    ) -> Result<Option<crate::case::Minter>, StoreError> {
        let tenant = self.tenant_name();
        let key = crate::core::origin_key(source, id);
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(events) = r.open_table(EVENTS) else {
                return Ok(None);
            };
            let Some(row) = events
                .get((tenant.as_str(), key.as_str()))
                .map_err(|e| be(&e))?
                .map(|v| {
                    let (.., ba, bb) = v.value();
                    (ba.to_owned(), bb.to_owned())
                })
            else {
                return Ok(None);
            };
            Ok(Some(decode_minter(&row.0, &row.1)?.map_or(
                crate::case::Minter::Nobody,
                crate::case::Minter::Operator,
            )))
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
                            let (src, bid, kd, pl, ra, _, _, hc, d, _, ba, bb) = v.value();
                            (
                                kd.to_owned(),
                                pl.to_owned(),
                                ra,
                                hc,
                                d,
                                src.to_owned(),
                                bid.to_owned(),
                                ba.to_owned(),
                                bb.to_owned(),
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
                                // A dead letter keeps its minter, exactly as
                                // it keeps its identity: the queue is read by
                                // an operator diagnosing where a message came
                                // from.
                                row.7.as_str(),
                                row.8.as_str(),
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
                let (source, bare, kind, payload, received, _, _, _, _, reason, ba, bb) = v.value();
                out.push(DeadLetter {
                    event: InboundEvent {
                        source: source.to_owned(),
                        id: bare.to_owned(),
                        kind: kind.to_owned(),
                        correlation: load_correlation(&corr, &tenant, id)?,
                        payload: serde_json::from_str(payload)?,
                        by: decode_minter(ba, bb)?,
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
            // ranged to this tenant, like every sibling read. A whole-table
            // walk would lean on the row lookup below being tenant-keyed,
            // which holds for *leaking* but not for *counting*:
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
                let (case, has_case, step, phase, kind, _, from) = v.value();
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
                    phase: phase_from(phase)?,
                    kind: kind.to_owned(),
                    correlation: vec![CorrelationKey::new(ns.to_owned(), val.to_owned())],
                    from: from.map(str::to_owned),
                });
            }
            Ok(out)
        })
        .await
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    /// Both phases round-trip; the pair cannot drift while this passes.
    #[test]
    fn every_written_phase_decodes_to_the_value_that_wrote_it() {
        for phase in [
            crate::core::Phase::Forward,
            crate::core::Phase::Compensating,
        ] {
            assert_eq!(phase_from(phase.as_str()).expect("round trip"), phase);
        }
    }

    /// **A subscription phase this store cannot read is damage, not `Forward`.**
    ///
    /// What a default would cost is specific: the phase selects the replay cursor
    /// the delivery is journaled under, and forward and compensating effects
    /// must never share one. A compensating wait whose phase is misread has its
    /// answer filed on the forward cursor — so that wait is never satisfied and
    /// the run waits forever, while a strict replay meets a record on the
    /// forward cursor nothing requested and quarantines.
    #[test]
    fn an_unreadable_subscription_phase_is_refused_rather_than_defaulted() {
        for bad in ["", "Forward", "compensating ", "backward"] {
            assert!(
                matches!(phase_from(bad).err(), Some(StoreError::Corrupt { .. })),
                "phase '{bad}' decoded instead of refusing"
            );
        }
    }
}
