//! What every journal store must do, checked against any implementation.
//!
//! # Why this exists rather than a second set of tests
//!
//! [`JournalStore`] states three guarantees and says they must hold
//! *atomically*: fencing, exactly-once, and chaining. They are not application
//! logic — they are storage invariants, deliberately, because application logic
//! can be bypassed by the next caller and a constraint cannot.
//!
//! A second backend is exactly where that stops being true. The embedded store
//! encodes all three; a Postgres store written from the same prose will encode
//! two of them and something *nearly* the third, and nothing will notice,
//! because the suite that proves the runtime correct runs against the embedded
//! store. The
//! new backend gets whatever tests its author remembered to write, and those
//! will be the ones they were already thinking about.
//!
//! So the invariants are written once, here, and every implementation is run
//! against the same battery. An embedder bringing their own store gets the same
//! benefit, which is why this ships rather than living in `tests/`.
//!
//! # It reports every failure, not the first
//!
//! Bringing up a backend is iterative. A battery that stops at the first
//! problem turns that into a sequence of full rebuilds, and — worse — hides
//! whether the second failure is a separate bug or a consequence of the first.

use std::sync::Arc;
use std::time::Duration;

use crate::core::{CaseId, Digest, EffectKey, RunId, StepId};
use crate::journal::{Append, JournalStore, Record, RecordKind};

/// What a store got wrong.
#[derive(Debug, Clone)]
pub struct Violation {
    /// The guarantee, in the words [`JournalStore`] uses.
    pub invariant: &'static str,
    /// What happened instead, and why it matters.
    pub detail: String,
}

/// The result of running the battery.
#[derive(Debug, Default)]
pub struct Report {
    pub violations: Vec<Violation>,
    pub checked: usize,
}

impl Report {
    pub(crate) fn record(&mut self, invariant: &'static str, detail: impl Into<String>) {
        self.violations.push(Violation {
            invariant,
            detail: detail.into(),
        });
    }

    /// Fail the test if anything was violated.
    ///
    /// # Panics
    ///
    /// If any invariant was violated, or if the battery somehow checked
    /// nothing — a battery that silently ran zero checks is worse than none,
    /// because it reports success.
    pub fn assert_conforms(&self, store: &str) {
        assert!(
            self.checked > 0,
            "the conformance battery ran no checks against {store}"
        );
        assert!(
            self.violations.is_empty(),
            "{store} does not satisfy its store contract:\n{}",
            self.violations
                .iter()
                .map(|v| format!("  • {}: {}", v.invariant, v.detail))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// Produces a store with no history in it.
///
/// A factory rather than one store, because several checks need a clean chain
/// and sharing one would let an earlier check's writes decide a later one's
/// result.
pub type Factory<'a> =
    &'a (dyn Fn() -> std::pin::Pin<Box<dyn Future<Output = Arc<dyn JournalStore>> + Send>> + Sync);

const LEASE: Duration = Duration::from_mins(5);
/// The shortest lease a store is obliged to honour.
///
/// A zero TTL is not usable: the embedded store clamps it to a second, and any backend is
/// free to, because a lease that expires the instant it is granted is not a
/// lease. So the fencing check takes the short one and *waits* — the only way to
/// reach an expired lease through the public API, and therefore the only way a
/// battery that must work against an unknown backend can get there.
const SHORT: Duration = Duration::from_secs(1);

/// Exercise the storage-level governed-memory contract against any backend.
///
/// Backends remain free to choose indexes and transaction mechanisms, but they
/// do not get to choose different semantics for versions, scopes, lineage, or
/// erasure.
///
/// # Panics
///
/// Panics when the backend violates the contract.
#[allow(clippy::too_many_lines)]
pub async fn memory(store: Arc<dyn crate::memory::MemoryStore>) {
    use crate::core::{Sensitivity, SourceId, Timestamp, Trust};
    use crate::memory::{MemoryItem, Recall, Selected};
    use serde_json::json;

    let at = |seconds| Timestamp::from_unix_timestamp(seconds).expect("representable time");
    let make = |id: &str, subject: &str, purpose: &str, content: serde_json::Value| MemoryItem {
        id: id.to_owned(),
        subject: subject.to_owned(),
        purpose: purpose.to_owned(),
        content,
        provenance: vec![SourceId::new("conformance")],
        sensitivity: Sensitivity::Internal,
        trust: Trust::Untrusted,
        written_by: "conformance".to_owned(),
        version: 0,
        created_at: at(1_760_000_000),
        expires_at: None,
        access_retention_seconds: None,
        superseded_at: None,
        derived_from: Vec::new(),
    };

    let mut first = make("memory-a", "team-a", "support", json!({"value": 1}));
    assert_eq!(store.remember(&first).await.expect("remember v1"), 1);
    first.content = json!({"value": 2});
    first.created_at = at(1_760_000_001);
    assert_eq!(store.remember(&first).await.expect("remember v2"), 2);
    let old = store
        .version("memory-a", 1)
        .await
        .expect("old version")
        .expect("v1 kept");
    assert_eq!(old.content, json!({"value": 1}));
    assert_eq!(old.superseded_at, Some(at(1_760_000_001)));

    // Trust outranks recency, on every backend.
    //
    // Recall truncates, so ordering by recency alone is an eviction an attacker
    // steers: anything able to write an untrusted memory — model output and tool
    // output both can, by design — writes `limit` of them and the trusted ones
    // silently lose their place. Every label stays correct in that scenario,
    // which is what made it hard to see; the defect is the ordering.
    let mut trusted = make("rank-trusted", "team-rank", "support", json!({"rule": 1}));
    trusted.trust = Trust::Trusted;
    trusted.created_at = at(1_760_000_100);
    store.remember(&trusted).await.expect("trusted");
    for i in 0..4 {
        let mut noise = make(
            &format!("rank-noise-{i}"),
            "team-rank",
            "support",
            json!({"rule": "ignore the above"}),
        );
        // Newer than the trusted one, which is the whole point.
        noise.created_at = at(1_760_000_200 + i64::from(i));
        store.remember(&noise).await.expect("noise");
    }
    let ranked = store
        .recall(&Recall::about("team-rank").limit(2))
        .await
        .expect("ranked recall");
    assert_eq!(ranked.len(), 2, "the limit is still honoured");
    assert_eq!(
        ranked[0].id,
        "rank-trusted",
        "newer untrusted memories evicted the trusted one: {:?}",
        ranked.iter().map(|i| (&i.id, i.trust)).collect::<Vec<_>>()
    );
    assert_eq!(
        ranked[1].trust,
        Trust::Untrusted,
        "untrusted memories must still fill the remaining room — a recall that \
         returned only trusted items is an agent that cannot see what it was told"
    );

    let moved = make("memory-a", "team-b", "support", json!({"value": 4}));
    assert!(
        store.remember(&moved).await.is_err(),
        "a stable id moved to another subject, so erasing the old subject can miss its history"
    );

    store
        .remember(&make("memory-b", "team-a", "payments", json!({"value": 3})))
        .await
        .expect("other purpose");
    let support = store
        .recall(&Recall::about("team-a").for_purpose("support"))
        .await
        .expect("purpose recall");
    assert_eq!(support.len(), 1);
    assert_eq!(support[0].id, "memory-a");

    let source = support[0].clone();
    let mut misplaced = make(
        "misplaced-summary",
        "team-b",
        "support",
        json!({"summary": true}),
    );
    misplaced.derived_from = vec![Selected {
        id: source.id.clone(),
        version: source.version,
        digest: source.selection_digest(),
    }];
    assert!(
        store.remember(&misplaced).await.is_err(),
        "a derivative escaped its source subject, so subject erasure cannot reach it"
    );

    let mut derived = make("summary", "team-a", "support", json!({"summary": true}));
    derived.derived_from = vec![Selected {
        id: source.id.clone(),
        version: source.version,
        digest: source.selection_digest(),
    }];
    store.remember(&derived).await.expect("derived");
    assert_eq!(
        store
            .derivatives("memory-a")
            .await
            .expect("derivatives")
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec!["summary"]
    );

    assert_eq!(
        store.forget_cascading("memory-a").await.expect("cascade"),
        2
    );
    assert!(
        store
            .version("memory-a", 1)
            .await
            .expect("forgotten source")
            .is_none()
    );
    assert!(
        store
            .version("summary", 1)
            .await
            .expect("forgotten summary")
            .is_none()
    );
    assert_eq!(
        store
            .forget_subject("team-a")
            .await
            .expect("subject erasure"),
        1
    );
    assert!(
        store
            .recall(&Recall::about("team-a"))
            .await
            .expect("empty")
            .is_empty()
    );

    let mut expiring = make(
        "memory-expiring",
        "team-lifecycle",
        "support",
        json!({"temporary": true}),
    );
    expiring.expires_at = Some(at(1_760_000_100));
    store.remember(&expiring).await.expect("expiring memory");
    assert_eq!(
        store
            .recall(&Recall::about("team-lifecycle").at(at(1_760_000_099)))
            .await
            .expect("before expiry")
            .len(),
        1
    );
    assert!(
        store
            .recall(&Recall::about("team-lifecycle").at(at(1_760_000_100)))
            .await
            .expect("at expiry")
            .is_empty(),
        "expiry is inclusive"
    );
    assert!(
        store
            .version("memory-expiring", 1)
            .await
            .expect("exact replay version")
            .is_some(),
        "hiding an expired current item must not silently break replay"
    );

    store
        .set_legal_hold("memory-expiring", true)
        .await
        .expect("place legal hold");
    assert!(
        store
            .legal_hold("memory-expiring")
            .await
            .expect("read hold")
    );
    assert!(
        store.forget("memory-expiring").await.is_err(),
        "ordinary erasure bypassed legal hold"
    );
    assert_eq!(
        store
            .sweep_expired(at(1_760_000_101))
            .await
            .expect("held sweep"),
        0,
        "expiry sweep bypassed legal hold"
    );
    store
        .set_legal_hold("memory-expiring", false)
        .await
        .expect("release legal hold");
    assert_eq!(
        store
            .sweep_expired(at(1_760_000_101))
            .await
            .expect("expiry sweep"),
        1
    );
    assert!(
        store
            .version("memory-expiring", 1)
            .await
            .expect("swept version")
            .is_none()
    );

    let mut sliding = make(
        "memory-sliding",
        "team-retention",
        "support",
        json!({"sliding": true}),
    );
    sliding.expires_at = Some(at(1_760_000_200));
    sliding.access_retention_seconds = Some(60);
    store.remember(&sliding).await.expect("sliding memory");
    store
        .touch(&["memory-sliding".to_owned()], at(1_760_000_190))
        .await
        .expect("touch sliding retention");
    assert_eq!(
        store
            .recall(&Recall::about("team-retention").at(at(1_760_000_240)))
            .await
            .expect("extended recall")
            .len(),
        1,
        "journaled access did not extend retention past the fixed expiry"
    );
    assert!(
        store
            .recall(&Recall::about("team-retention").at(at(1_760_000_250)))
            .await
            .expect("after sliding expiry")
            .is_empty()
    );
}

fn admitted(run: RunId) -> Append {
    Append::new(
        run,
        RecordKind::RunAdmitted {
            capability: "conformance".into(),
            governed_by: None,
            input_label: crate::core::Label::trusted(),
            input: serde_json::Value::Null,
            policy_bundle: None,
        },
    )
}

/// The conclusion record the executor writes — what feeds the outcome index.
fn concluded(run: RunId, outcome: &str) -> Append {
    Append::new(
        run,
        RecordKind::RunSealed {
            outcome: outcome.to_owned(),
            chain_head: Digest::ZERO,
        },
    )
}

fn started(run: RunId, key: EffectKey) -> Append {
    Append::new(
        run,
        RecordKind::EffectStarted {
            descriptor: crate::core::EffectDescriptor::nullary("probe"),
            recovery: crate::core::Recovery::Retry,
            mutates: true,
            attempt: 1,
            backoff_ms: 0,
            outbound_label: None,
        },
    )
    .step(StepId(0))
    .effect(key)
}

fn key(n: u8) -> EffectKey {
    EffectKey::derive(
        StepId(0),
        crate::core::Phase::Forward,
        u32::from(n),
        1,
        "probe",
        &[n],
    )
}

/// Run every check.
///
/// # Panics
///
/// Only if the factory itself fails; contract violations are collected into the
/// [`Report`] rather than raised, so bringing up a backend surfaces all of them
/// at once.
pub async fn check(fresh: Factory<'_>) -> Report {
    let mut r = Report::default();
    head_of_an_unwritten_run_is_genesis(fresh, &mut r).await;
    append_assigns_contiguous_seq(fresh, &mut r).await;
    append_links_each_record_to_the_previous(fresh, &mut r).await;
    a_sound_chain_verifies(fresh, &mut r).await;
    a_second_start_for_one_effect_is_rejected(fresh, &mut r).await;
    the_same_effect_key_in_another_run_is_allowed(fresh, &mut r).await;
    a_stale_epoch_is_fenced(fresh, &mut r).await;
    a_fabricated_future_epoch_is_fenced(fresh, &mut r).await;
    a_live_lease_is_not_stolen(fresh, &mut r).await;
    a_takeover_advances_the_epoch(fresh, &mut r).await;
    a_rejected_batch_writes_nothing(fresh, &mut r).await;
    read_starts_where_it_is_told(fresh, &mut r).await;
    a_case_scan_selects_one_matter(fresh, &mut r).await;
    sealed_runs_are_findable_by_how_they_ended(fresh, &mut r).await;
    the_outcome_index_follows_the_last_conclusion(fresh, &mut r).await;
    a_sealed_run_refuses_appends(fresh, &mut r).await;
    a_stop_request_needs_no_lease(fresh, &mut r).await;
    the_first_asker_stays_on_the_record(fresh, &mut r).await;
    an_attestation_survives_the_round_trip(fresh, &mut r).await;
    the_log_only_grows(fresh, &mut r).await;
    a_released_lease_is_free_at_once(fresh, &mut r).await;
    a_release_does_not_forget_the_epoch(fresh, &mut r).await;
    a_fenced_caller_cannot_release_the_new_owners_lease(fresh, &mut r).await;
    r
}

/// A released lease is available immediately, without waiting out the TTL.
///
/// The counterpart to expiry, and the reason an owner can afford to be unique
/// per process. Without a release, a restart waits out the lease — and the
/// tempting fix is a constant owner string so the replacement "renews" instead,
/// which silently disables fencing, because two live instances then read each
/// other's lease as their own.
async fn a_released_lease_is_free_at_once(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(a) = store.acquire(run, "instance-a", LEASE).await else {
        return;
    };
    if let Err(e) = store.release_lease(run, a.epoch).await {
        r.record("fencing", format!("release() of a held lease failed: {e}"));
        return;
    }

    match store.acquire(run, "instance-b", LEASE).await {
        Ok(b) => {
            // The epoch *must* advance. An earlier version of this battery
            // asserted the opposite — "a handover is not a crash, so there is
            // nothing to fence" — which is wrong: releasing says the owner
            // intends to stop, not that it already has. An un-awaited task or a
            // crash between release and exit leaves an append in flight, and
            // the only thing that stops it is a bump. The property worth having
            // is that takeover is *immediate*, not that the epoch stands still.
            if b.epoch <= a.epoch {
                r.record(
                    "fencing",
                    format!(
                        "a released lease was reclaimed at epoch {} without advancing past \
                         {} — an append still in flight from the releasing owner would not \
                         be fenced",
                        b.epoch, a.epoch
                    ),
                );
            }
        }
        Err(e) => r.record(
            "fencing",
            format!(
                "a released lease was still held ({e}) — every restart then waits out the \
                 TTL, which is the pressure that makes deployments alias their owner strings"
            ),
        ),
    }

    // Releasing twice is releasing once.
    if let Err(e) = store.release_lease(run, a.epoch).await {
        r.record("fencing", format!("release() is not idempotent: {e}"));
    }
}

/// Releasing frees the lease without forgetting the epoch.
///
/// The epoch lives in the lease row, so a release that *deletes* the row throws
/// the fence away with it. Two things then go wrong at once, and both are
/// silent: `append` fences against the row it can no longer find, so a stale
/// writer is not stopped; and the next `acquire` sees nothing and starts again
/// at 1, so a previously fenced writer holding epoch 2 now **outranks** the new
/// legitimate owner. The mechanism does not merely stop working — it inverts.
async fn a_release_does_not_forget_the_epoch(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();

    // Take it, lose it to a takeover, so the epoch is above 1.
    let Ok(first) = store.acquire(run, "instance-a", SHORT).await else {
        return;
    };
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let Ok(second) = store.acquire(run, "instance-b", LEASE).await else {
        r.record("fencing", "an expired lease could not be taken over");
        return;
    };
    if second.epoch <= first.epoch {
        r.record("fencing", "a takeover did not advance the epoch");
        return;
    }

    // The current owner shuts down cleanly.
    if store.release_lease(run, second.epoch).await.is_err() {
        r.record("fencing", "release_lease of a held lease failed");
        return;
    }

    // The stale instance must still be fenced. If the epoch was forgotten there
    // is nothing left to compare against and this append succeeds.
    match store.append(first.epoch, vec![admitted(run)]).await {
        Err(crate::core::StoreError::Fenced { .. }) => {}
        Err(e) => r.record(
            "fencing",
            format!("unexpected error from a stale append: {e}"),
        ),
        Ok(_) => r.record(
            "fencing",
            "a fenced writer appended after the lease was released — releasing threw \
             away the epoch, so there was nothing left to fence against",
        ),
    }

    // And the next owner must rank *above* the fenced one, not restart at 1.
    match store.acquire(run, "instance-c", LEASE).await {
        Ok(third) => {
            if third.epoch <= first.epoch {
                r.record(
                    "fencing",
                    format!(
                        "after a release the epoch restarted at {} — a writer fenced at {} \
                         now outranks the legitimate owner",
                        third.epoch, first.epoch
                    ),
                );
            }
        }
        Err(e) => r.record(
            "fencing",
            format!("a released lease was not claimable: {e}"),
        ),
    }
}

/// A fenced caller cannot free the lease of whoever replaced it.
///
/// The safety half. A process that was taken over is still running and will
/// eventually shut down; if its release freed the *current* owner's lease, it
/// would hand the run to a third party while the rightful owner is mid-write —
/// manufacturing exactly the split-brain the epoch exists to prevent.
async fn a_fenced_caller_cannot_release_the_new_owners_lease(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(old) = store.acquire(run, "instance-a", SHORT).await else {
        return;
    };
    // Waited out rather than faked, because expiry is only reachable through
    // the public API — the same reason the fencing case does it this way.
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    // Expired, so the takeover is legitimate and bumps the epoch.
    let Ok(new) = store.acquire(run, "instance-b", LEASE).await else {
        r.record("fencing", "an expired lease could not be taken over");
        return;
    };
    if new.epoch == old.epoch {
        r.record("fencing", "a takeover did not advance the epoch");
        return;
    }

    // The stale instance shuts down and releases. It must not succeed, and it
    // must not be an error either: being fenced is not a reason to fail an
    // orderly exit.
    if let Err(e) = store.release_lease(run, old.epoch).await {
        r.record(
            "fencing",
            format!("a fenced caller's release must be a no-op, not an error: {e}"),
        );
    }

    match store.acquire(run, "instance-c", LEASE).await {
        Err(crate::core::StoreError::LeaseHeld { .. }) => {}
        Err(e) => r.record(
            "fencing",
            format!("unexpected error after a stale release: {e}"),
        ),
        Ok(_) => r.record(
            "fencing",
            "a fenced caller released the lease of the instance that replaced it, handing \
             the run to a third party while its rightful owner is still writing",
        ),
    }
}

/// A sealed run enters the log, and the log only ever grows.
///
/// Two properties, and the second is what makes the first useful. An inclusion
/// proof says a run is committed to *now*; a consistency proof says every run
/// committed to *before* still is. Without the second, an auditor comparing two
/// checkpoints learns nothing — the root moves on every ordinary seal, so
/// legitimate growth and deletion-plus-growth look identical.
///
/// The earlier checkpoints are **kept as they were taken**, which is what an
/// auditor holds. Recomputing them from the store's current leaves would ask the
/// store to confirm its own ordering, and a bug in that ordering would agree
/// with itself.
async fn the_log_only_grows(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;

    let mut sealed = Vec::new();
    let mut history: Vec<(u64, Digest)> = Vec::new();

    for _ in 0..4u8 {
        let run = RunId::generate();
        let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
            r.record("fencing", "acquire() failed on a fresh run");
            return;
        };
        if store
            .append(lease.epoch, vec![admitted(run)])
            .await
            .is_err()
        {
            r.record("merkle-log", "append failed under a fresh lease");
            return;
        }
        if store.seal(run, lease.epoch, "succeeded").await.is_err() {
            r.record("merkle-log", "seal failed");
            return;
        }
        sealed.push(run);

        // A backend may legitimately maintain no log. What it must not do is
        // claim an empty one, which is why a failure here returns rather than
        // recording — and why the size check below is not skippable once a
        // checkpoint has been produced at all.
        let Ok(cp) = store.checkpoint().await else {
            return;
        };
        if cp.size != sealed.len() as u64 {
            r.record(
                "merkle-log",
                format!(
                    "{} runs are sealed and the checkpoint commits to {} — a run \
                     that sealed without entering the log is a run no checkpoint \
                     covers",
                    sealed.len(),
                    cp.size
                ),
            );
            return;
        }
        history.push((cp.size, cp.root));
    }

    let Ok(latest) = store.checkpoint().await else {
        return;
    };

    // Every sealed run proves its own inclusion against the current root.
    for (i, run) in sealed.iter().enumerate() {
        match store.inclusion_proof(*run).await {
            Ok(Some(inc)) => {
                let leaf = crate::core::merkle::leaf_hash(&inc.seal);
                if !crate::core::merkle::verify_inclusion(
                    &leaf,
                    usize::try_from(inc.index).unwrap_or(usize::MAX),
                    usize::try_from(inc.size).unwrap_or(0),
                    &inc.proof,
                    &latest.root,
                ) {
                    r.record(
                        "merkle-log",
                        format!("run {i} is in the log and cannot prove it"),
                    );
                }
            }
            Ok(None) => r.record(
                "merkle-log",
                format!("run {i} sealed and the store has no position for it"),
            ),
            Err(e) => r.record("merkle-log", format!("inclusion_proof failed: {e}")),
        }
    }

    // And every checkpoint taken along the way proves the log only appended.
    for (size, root) in &history {
        let proof = match store.consistency_proof(*size).await {
            Ok(p) => p,
            Err(e) => {
                r.record(
                    "merkle-log",
                    format!("consistency_proof({size}) failed: {e}"),
                );
                continue;
            }
        };
        if !crate::core::merkle::verify_consistency(
            usize::try_from(*size).unwrap_or(0),
            root,
            usize::try_from(latest.size).unwrap_or(0),
            &latest.root,
            &proof,
        ) {
            r.record(
                "merkle-log",
                format!(
                    "the log could not prove it only appended between size {size} \
                     and {} — so a checkpoint published then proves nothing now",
                    latest.size
                ),
            );
        }
    }
}

/// A stop request must not be fenced.
///
/// Every other write here requires the lease, and for a stop request that would
/// be exactly backwards: the operator asking is not the owner, holds no epoch,
/// and is usually asking *because* the owner is busy doing the thing they want
/// stopped. A backend that reuses the append path for this — an easy mistake,
/// since every other write goes through it — makes the only party who can cancel
/// a running agent the process running it.
async fn a_stop_request_needs_no_lease(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();

    // Somebody else owns the run, at an epoch this caller does not have.
    let Ok(lease) = store.acquire(run, "the-owner", LEASE).await else {
        r.record("fencing", "acquire() failed on a fresh run");
        return;
    };
    if store
        .append(lease.epoch, vec![admitted(run)])
        .await
        .is_err()
    {
        r.record("chaining", "append failed under a fresh lease");
        return;
    }

    match store.request_cancel(run, "operator", "stop it").await {
        Ok(true) => {}
        Ok(false) => r.record(
            "cancellation",
            "the first stop request on a run reported that one already existed",
        ),
        Err(e) => r.record(
            "cancellation",
            format!(
                "a stop request from somebody who does not hold the lease was refused ({e}) — \
                 then the only party who can stop a running agent is the process running it"
            ),
        ),
    }

    match store.cancellation(run).await {
        Ok(Some(c)) if c.actor == "operator" && c.reason == "stop it" => {}
        Ok(Some(c)) => r.record(
            "cancellation",
            format!("the stop request read back as {c:?}, which is not what was written"),
        ),
        Ok(None) => r.record(
            "cancellation",
            "a recorded stop request was not readable — an operator's intervention \
             that the owner cannot see is not an intervention",
        ),
        Err(e) => r.record("cancellation", format!("cancellation() failed: {e}")),
    }

    // And a run nobody asked about has none.
    match store.cancellation(RunId::generate()).await {
        Ok(None) => {}
        Ok(Some(_)) => r.record(
            "cancellation",
            "an untouched run reported a stop request — every run would unwind",
        ),
        Err(e) => r.record("cancellation", format!("cancellation() failed: {e}")),
    }
}

/// A second request must not rewrite who intervened.
///
/// The obvious implementation is an upsert, and it silently reassigns the
/// intervention to whoever asked last. Six weeks later "who stopped this run?"
/// has the wrong answer, and it looks authoritative.
async fn the_first_asker_stays_on_the_record(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();

    if !matches!(store.request_cancel(run, "alice", "first").await, Ok(true)) {
        r.record("cancellation", "the first stop request was not recorded");
        return;
    }
    match store.request_cancel(run, "bob", "second").await {
        Ok(false) => {}
        Ok(true) => r.record(
            "cancellation",
            "a second stop request reported itself as the first — a retry would \
             read as a fresh intervention",
        ),
        Err(e) => r.record(
            "cancellation",
            format!("a repeated stop request failed: {e}"),
        ),
    }
    match store.cancellation(run).await {
        Ok(Some(c)) if c.actor == "alice" && c.reason == "first" => {}
        Ok(other) => r.record(
            "cancellation",
            format!(
                "the stop request now reads {other:?} — the second asker overwrote the \
                 first, so the permanent record names the wrong person"
            ),
        ),
        Err(e) => r.record("cancellation", format!("cancellation() failed: {e}")),
    }
}

/// A signature written must be a signature read back.
///
/// The easy way to get this wrong is to store the record and quietly drop the
/// two extra columns — nothing fails, the chain still verifies, and the loss is
/// invisible until an auditor asks who wrote something and every record answers
/// "nobody". A backend that hashes but silently discards authorship is worse
/// than one that never claimed to keep it.
async fn an_attestation_survives_the_round_trip(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
        r.record("fencing", "acquire() failed on a fresh run");
        return;
    };

    let Ok(written) = store.append(lease.epoch, vec![admitted(run)]).await else {
        r.record("attestation", "append failed under a fresh lease");
        return;
    };

    // Only stores configured with a signer produce one. An unsigned store is a
    // legitimate configuration, so the check is conditional on the write having
    // carried an attestation at all — what it must never do is *lose* one.
    let Some(expected) = written.first().and_then(|w| w.attestation.clone()) else {
        return;
    };

    match store.read(run, 1).await {
        Ok(back) => match back.first().and_then(|b| b.attestation.clone()) {
            Some(got) if got == expected => {}
            Some(got) => r.record(
                "attestation",
                format!(
                    "the signature read back is not the one written: wrote {:?}, read {:?}",
                    expected.key_id, got.key_id
                ),
            ),
            None => r.record(
                "attestation",
                "a signed record read back unsigned — the chain still verifies, and \
                 authorship is gone without anything reporting it",
            ),
        },
        Err(e) => r.record("attestation", format!("read failed: {e}")),
    }
}

async fn head_of_an_unwritten_run_is_genesis(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    match store.head(RunId::generate()).await {
        Ok(head) if head.seq == 0 && head.hash == Digest::ZERO => {}
        Ok(head) => r.record(
            "chaining",
            format!(
                "a run with no records must start at genesis (seq 0, zero hash), got seq {} — \
                 a chain that starts anywhere else cannot be verified from the beginning",
                head.seq
            ),
        ),
        Err(e) => r.record(
            "chaining",
            format!("head() of an unwritten run must succeed at genesis, got {e}"),
        ),
    }
}

async fn append_assigns_contiguous_seq(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
        r.record("fencing", "acquire() failed on a fresh run");
        return;
    };

    for i in 0..3u8 {
        if let Err(e) = store.append(lease.epoch, vec![admitted(run)]).await {
            r.record("chaining", format!("append {i} failed: {e}"));
            return;
        }
    }
    match store.read(run, 1).await {
        Ok(records) => {
            let seqs: Vec<u64> = records.iter().map(Record::seq).collect();
            if seqs != vec![1, 2, 3] {
                r.record(
                    "chaining",
                    format!(
                        "seq must be contiguous from 1, got {seqs:?} — a gap means a record was \
                         lost and verification cannot tell that from tampering"
                    ),
                );
            }
        }
        Err(e) => r.record("chaining", format!("read failed: {e}")),
    }
}

async fn append_links_each_record_to_the_previous(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
        return;
    };
    for _ in 0..3 {
        let _ = store.append(lease.epoch, vec![admitted(run)]).await;
    }
    let Ok(records) = store.read(run, 1).await else {
        return;
    };

    let mut prev = Digest::ZERO;
    for rec in &records {
        if rec.prev_hash != prev {
            r.record(
                "chaining",
                format!(
                    "record {} does not link to its predecessor — the chain is what makes \
                     deletion and reordering detectable, and an unlinked record is neither",
                    rec.seq()
                ),
            );
            return;
        }
        prev = rec.hash;
    }
}

async fn a_sound_chain_verifies(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
        return;
    };
    for _ in 0..4 {
        let _ = store.append(lease.epoch, vec![admitted(run)]).await;
    }
    if let Err(e) = store.verify(run).await {
        r.record(
            "chaining",
            format!("a chain this store wrote itself must verify, got {e}"),
        );
    }
}

async fn a_second_start_for_one_effect_is_rejected(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
        return;
    };
    let k = key(1);
    if let Err(e) = store.append(lease.epoch, vec![started(run, k)]).await {
        r.record("exactly-once", format!("the first start must succeed: {e}"));
        return;
    }
    match store.append(lease.epoch, vec![started(run, k)]).await {
        Err(crate::core::StoreError::DuplicateEffect(_)) => {}
        Err(e) => r.record(
            "exactly-once",
            format!("a second start must be rejected as DuplicateEffect, got {e}"),
        ),
        Ok(_) => r.record(
            "exactly-once",
            "a second EffectStarted for one effect key was accepted. Exactly-once is a \
             storage constraint here, not a code path — replay reads a completed effect \
             back, and this is what stops anything that gets past it from performing the \
             call twice",
        ),
    }
}

async fn the_same_effect_key_in_another_run_is_allowed(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let k = key(2);
    for _ in 0..2 {
        let run = RunId::generate();
        let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
            return;
        };
        if let Err(e) = store
            .append(lease.epoch, vec![started(run, k)].clone())
            .await
        {
            r.record(
                "exactly-once",
                format!(
                    "the constraint is per-run: two runs performing the same effect are two \
                     performances, and rejecting the second would make a batch of identical \
                     items unrunnable. Got {e}"
                ),
            );
            return;
        }
    }
}

async fn a_stale_epoch_is_fenced(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();

    // A lease that is already expired, so the takeover below is legitimate
    // rather than theft. This is the shape of the real failure: an instance
    // that was paused past its TTL and does not know it.
    let Ok(first) = store.acquire(run, "instance-a", SHORT).await else {
        r.record("fencing", "acquire() failed on a fresh run");
        return;
    };
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let Ok(second) = store.acquire(run, "instance-b", LEASE).await else {
        r.record(
            "fencing",
            "an expired lease must be claimable by another instance, or a crashed \
             owner strands its run forever",
        );
        return;
    };
    if second.epoch <= first.epoch {
        r.record(
            "fencing",
            "a takeover must advance the epoch, or the previous owner cannot be fenced",
        );
        return;
    }
    match store.append(first.epoch, vec![admitted(run)]).await {
        Err(crate::core::StoreError::Fenced { .. }) => {}
        Err(e) => r.record("fencing", format!("expected Fenced, got {e}")),
        Ok(_) => r.record(
            "fencing",
            "a superseded owner's write was accepted. The check must happen inside the same \
             transaction that writes: a read-then-write leaves a window a paused instance \
             wakes up into, which is split-brain",
        ),
    }
}

/// A fencing token is proof returned by `acquire`, not a sequence number a
/// caller may predict.
///
/// Checking only `writer < current` rejects zombies but accepts a fabricated
/// future epoch. The real owner can then append under the actual epoch as well,
/// so the store has admitted two writers while still claiming the lease is
/// exclusive. Equality is the ownership check.
async fn a_fabricated_future_epoch_is_fenced(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(lease) = store.acquire(run, "instance-a", LEASE).await else {
        r.record("fencing", "acquire() failed on a fresh run");
        return;
    };

    let invented = lease.epoch.saturating_add(1);
    match store.append(invented, vec![admitted(run)]).await {
        Err(crate::core::StoreError::Fenced { .. }) => {}
        Err(e) => r.record("fencing", format!("expected Fenced, got {e}")),
        Ok(_) => r.record(
            "fencing",
            "an epoch the store never issued was accepted. A fencing token is proof of a \
             lease, not a number a caller may outrank by adding one",
        ),
    }
}

/// A *live* lease is not stealable, and saying so is not the same as fencing.
///
/// The two errors call for opposite responses. A fenced writer has been taken
/// over and must drop the run; a writer refused a live lease is not stale at all
/// and should wait for expiry. A backend that returns one for the other sends an
/// operator — or a retry loop — in exactly the wrong direction.
async fn a_live_lease_is_not_stolen(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(_held) = store.acquire(run, "instance-a", LEASE).await else {
        return;
    };
    match store.acquire(run, "instance-b", LEASE).await {
        Err(crate::core::StoreError::LeaseHeld { .. }) => {}
        Err(e) => r.record(
            "fencing",
            format!(
                "taking a live lease must fail as LeaseHeld, not {e} — a writer that is \
                 merely early must not be told it has been superseded"
            ),
        ),
        Ok(_) => r.record(
            "fencing",
            "a live lease was handed to a second instance. Two owners writing one chain is \
             the split-brain the epoch exists to prevent",
        ),
    }
}

async fn a_takeover_advances_the_epoch(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(a) = store.acquire(run, "instance-a", LEASE).await else {
        return;
    };
    let Ok(again) = store.acquire(run, "instance-a", LEASE).await else {
        return;
    };
    if again.epoch != a.epoch {
        r.record(
            "fencing",
            format!(
                "renewing an owned lease must keep the epoch ({} became {}) — bumping it \
                 fences the owner against itself, and its in-flight writes start failing",
                a.epoch, again.epoch
            ),
        );
    }
}

async fn a_rejected_batch_writes_nothing(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
        return;
    };
    let k = key(3);
    let _ = store.append(lease.epoch, vec![started(run, k)]).await;
    let before = store.read(run, 1).await.map_or(0, |v| v.len());

    // A batch whose *second* record violates exactly-once. The first is
    // perfectly legal, and must not survive.
    let batch = vec![admitted(run), started(run, k)];
    if store.append(lease.epoch, batch).await.is_ok() {
        r.record(
            "atomicity",
            "a batch containing a duplicate effect start was accepted",
        );
        return;
    }
    let after = store.read(run, 1).await.map_or(0, |v| v.len());
    if after != before {
        r.record(
            "atomicity",
            format!(
                "a rejected batch left {} record(s) behind. The whole batch commits or none \
                 of it does — a partially written step describes something that never \
                 happened",
                after - before
            ),
        );
    }
}

/// A case's history is a scan over one matter, and only that matter.
///
/// The question is *show me everything about this matter*. Answering it by
/// listing the case's runs and reading each is a join that also **misses**
/// every record written by a run the case does not own — which is exactly what
/// a sweep is, since one tick may act on several cases and belongs to none.
///
/// Both halves are checked, because either alone passes for the wrong reason: a
/// scan that returns nothing satisfies "no foreign records", and a scan that
/// returns everything satisfies "finds its own".
/// A quarantined run is findable by the person who has to deal with it.
///
/// The most serious conclusion this runtime reaches used to produce a status, a
/// log line and a counter — none of which can be queried, and a run started with
/// `spawn` returns before the status exists. Every other backlog is findable by
/// whoever must clear it; this one was not, which is the shape production
/// studies of agent runtimes report as the most common failure: not an
/// undetected fault, but a detected one whose signal never reaches a human.
///
/// Both directions, because either alone passes for the wrong reason: a scan
/// returning nothing satisfies "no other outcome", and one returning everything
/// satisfies "finds its own".
async fn sealed_runs_are_findable_by_how_they_ended(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;

    let mut quarantined = Vec::new();
    for (outcome, count) in [("quarantined", 2usize), ("succeeded", 1)] {
        for _ in 0..count {
            let run = RunId::generate();
            let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
                return;
            };
            // The index derives from the chain's conclusion record, not from
            // the seal — the executor writes the record, then seals.
            let _ = store
                .append(lease.epoch, vec![admitted(run), concluded(run, outcome)])
                .await;
            if store.seal(run, lease.epoch, outcome).await.is_err() {
                return;
            }
            if outcome == "quarantined" {
                quarantined.push(run);
            }
        }
    }

    match store.runs_by_outcome("quarantined", 100).await {
        Ok(found) => {
            if found.len() != 2 {
                r.record(
                    "outcome index",
                    format!(
                        "runs_by_outcome must find both quarantined runs, got {}",
                        found.len()
                    ),
                );
            }
            if found.iter().any(|run| !quarantined.contains(run)) {
                r.record(
                    "outcome index",
                    "runs_by_outcome returned a run that ended some other way".to_owned(),
                );
            }
        }
        Err(e) => r.record("outcome index", format!("runs_by_outcome failed: {e}")),
    }

    // The bound is applied rather than advisory — **and it keeps the newest**.
    //
    // Checking only the count is a check that proves nothing: a page limit in
    // ascending order returns the right *number* of runs and the wrong ones,
    // so a plane whose backlog exceeds one page shows the same list forever and
    // the quarantine that just happened never appears. `quarantined` is in
    // creation order, so the last element is the one a bounded query must keep.
    let newest = quarantined.last().copied();
    match store.runs_by_outcome("quarantined", 1).await {
        Ok(found) if found.len() == 1 && Some(found[0]) == newest => {}
        Ok(found) if found.len() == 1 => r.record(
            "outcome index",
            "runs_by_outcome(limit=1) kept the oldest run — a bounded query in \
             ascending order never surfaces the quarantine that just happened"
                .to_owned(),
        ),
        Ok(found) => r.record(
            "outcome index",
            format!("runs_by_outcome(limit=1) returned {} runs", found.len()),
        ),
        Err(e) => r.record(
            "outcome index",
            format!("runs_by_outcome(limit=1) failed: {e}"),
        ),
    }
}

/// The outcome index follows the *last* conclusion, not the first.
///
/// A failed run is open: its conclusion is in the chain, so it must be
/// findable by whoever clears failures — and when it is resumed and succeeds,
/// it must *move*. An index that keeps the first conclusion lists a run as
/// failed for the rest of its life, and a backlog page that never drains is
/// worse than no page, because a wrong answer reads exactly like a right one.
async fn the_outcome_index_follows_the_last_conclusion(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
        return;
    };

    // A failed conclusion is indexed without any seal: failure leaves the run
    // open and resumable, and openness must not cost findability.
    if let Err(e) = store
        .append(lease.epoch, vec![admitted(run), concluded(run, "failed")])
        .await
    {
        r.record(
            "outcome index",
            format!("appending a conclusion failed: {e}"),
        );
        return;
    }
    match store.runs_by_outcome("failed", 10).await {
        Ok(found) if found.contains(&run) => {}
        Ok(_) => r.record(
            "outcome index",
            "a failed conclusion was not indexed — an unsealed run's failure is \
             a finding nobody can find"
                .to_owned(),
        ),
        Err(e) => r.record("outcome index", format!("runs_by_outcome failed: {e}")),
    }

    // The run resumes and succeeds: it must leave the failed listing and enter
    // the succeeded one — one run, one row, the latest answer.
    if let Err(e) = store
        .append(lease.epoch, vec![concluded(run, "succeeded")])
        .await
    {
        r.record("outcome index", format!("re-concluding failed: {e}"));
        return;
    }
    let _ = store.seal(run, lease.epoch, "succeeded").await;

    match store.runs_by_outcome("failed", 10).await {
        Ok(found) if found.contains(&run) => r.record(
            "outcome index",
            "a run that later succeeded is still listed as failed — the backlog \
             page never drains, and a wrong answer reads exactly like a right one"
                .to_owned(),
        ),
        Ok(_) => {}
        Err(e) => r.record("outcome index", format!("runs_by_outcome failed: {e}")),
    }
    match store.runs_by_outcome("succeeded", 10).await {
        Ok(found) if found.contains(&run) => {}
        Ok(_) => r.record(
            "outcome index",
            "the re-conclusion did not move the run into the succeeded listing".to_owned(),
        ),
        Err(e) => r.record("outcome index", format!("runs_by_outcome failed: {e}")),
    }
}

/// A sealed run's journal is frozen — an append after the seal is refused.
///
/// The Merkle leaf is the chain head *at seal time*. The fence answers "who
/// owns this run", and the caller that sealed it is exactly who still holds
/// the current epoch — so without this check, that caller can advance the true
/// head past the leaf every checkpoint attests, and an inclusion proof then
/// vouches for a prefix of a history that kept growing. The executor's own
/// refusal to resume a closed run is application logic a future caller can
/// bypass; the store's refusal is the constraint that cannot be.
async fn a_sealed_run_refuses_appends(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
        return;
    };
    // Positive half: the same batch shape is accepted before the seal, so a
    // store that refuses everything cannot pass by refusing this too.
    if let Err(e) = store.append(lease.epoch, vec![admitted(run)]).await {
        r.record("seal", format!("append before seal failed: {e}"));
        return;
    }
    if let Err(e) = store.seal(run, lease.epoch, "succeeded").await {
        r.record("seal", format!("seal failed: {e}"));
        return;
    }
    let Ok(frozen) = store.head(run).await else {
        r.record("seal", "head() failed after seal".to_owned());
        return;
    };

    match store
        .append(lease.epoch, vec![started(run, key(201))])
        .await
    {
        Ok(_) => r.record(
            "seal",
            "a sealed run accepted an append under the current epoch — the true \
             head has moved past the leaf every checkpoint attests"
                .to_owned(),
        ),
        Err(crate::core::StoreError::RunSealed { .. }) => {}
        Err(e) => r.record(
            "seal",
            format!(
                "an append after seal was refused, but as '{e}' rather than \
                 RunSealed — a caller cannot tell a frozen run from a store fault"
            ),
        ),
    }

    // And nothing was written: the refusal must leave the chain head exactly
    // where the seal froze it, or the checkpoint still lies by one record.
    match store.head(run).await {
        Ok(after) if after.hash == frozen.hash && after.seq == frozen.seq => {}
        Ok(_) => r.record(
            "seal",
            "the refused append still moved the chain head".to_owned(),
        ),
        Err(e) => r.record("seal", format!("head() failed after refusal: {e}")),
    }
}

async fn a_case_scan_selects_one_matter(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let mine = CaseId::generate();
    let theirs = CaseId::generate();

    // Two records for one matter and one for another, written by runs that
    // belong to neither — the shape a sweep produces.
    for (case, count) in [(mine, 2), (theirs, 1)] {
        let run = RunId::generate();
        let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
            return;
        };
        for _ in 0..count {
            let _ = store
                .append(lease.epoch, vec![admitted(run).case(case)])
                .await;
        }
    }

    match store.case_history(mine, 100).await {
        Ok(records) => {
            if records.len() != 2 {
                r.record(
                    "case history",
                    format!(
                        "case_history must return this matter's records, got {} of 2",
                        records.len()
                    ),
                );
            }
            if records.iter().any(|rec| rec.body.case != Some(mine)) {
                r.record(
                    "case history",
                    "case_history returned a record belonging to another matter".to_owned(),
                );
            }
        }
        Err(e) => r.record("case history", format!("case_history failed: {e}")),
    }

    // The bound is applied rather than advisory.
    match store.case_history(mine, 1).await {
        Ok(records) if records.len() == 1 => {}
        Ok(records) => r.record(
            "case history",
            format!("case_history(limit=1) returned {} records", records.len()),
        ),
        Err(e) => r.record("case history", format!("case_history(limit=1) failed: {e}")),
    }
}

async fn read_starts_where_it_is_told(fresh: Factory<'_>, r: &mut Report) {
    r.checked += 1;
    let store = fresh().await;
    let run = RunId::generate();
    let Ok(lease) = store.acquire(run, "conformance", LEASE).await else {
        return;
    };
    for _ in 0..4 {
        let _ = store.append(lease.epoch, vec![admitted(run)]).await;
    }
    match store.read(run, 3).await {
        Ok(records) => {
            let seqs: Vec<u64> = records.iter().map(Record::seq).collect();
            if seqs != vec![3, 4] {
                r.record(
                    "chaining",
                    format!("read(from=3) must return seq 3 onward, got {seqs:?}"),
                );
            }
        }
        Err(e) => r.record("chaining", format!("read(from=3) failed: {e}")),
    }
}

/// The standing-authority contract, applied to any backend.
///
/// One battery for both stores, because the guarantees here are the sort that
/// hold on a single-writer embedded store almost by accident and have to be
/// *built* on a shared one. Running it against redb proves the semantics;
/// running it against `PostgreSQL` proves the arbitration.
///
/// Panics with the property that failed, so a backend under development gets a
/// sentence rather than a diff of two structs.
///
/// # Panics
///
/// If the store violates any part of the contract.
#[allow(clippy::too_many_lines)]
pub async fn authority(store: Arc<dyn crate::authority::AuthorityStore>) {
    use crate::authority::{AuthorityError, AuthorityId, StandingAuthority};
    use crate::core::{EffectKey, Spend, Timestamp};

    let key = |n: u8| EffectKey::from_hex(&format!("{n:064x}")).expect("32 bytes of hex");
    let at = Timestamp::UNIX_EPOCH;

    // ── Draws accumulate, and the ceiling is cumulative ──────────────────────
    let id = AuthorityId::new("conformance-accumulate");
    store
        .issue(&StandingAuthority::new(
            "conformance-accumulate",
            "conformance",
            Spend::money(1_000),
        ))
        .await
        .expect("issue");

    let first = store
        .draw(&id, key(1), Spend::money(600), at)
        .await
        .expect("a draw within the ceiling");
    assert_eq!(
        first.remaining,
        Spend::money(400),
        "the receipt must report what is left after this draw"
    );

    let refused = store
        .draw(&id, key(2), Spend::money(500), at)
        .await
        .expect_err("the ceiling is cumulative across draws, not per draw");
    assert!(
        matches!(refused, AuthorityError::Exhausted { .. }),
        "an over-draw must be Exhausted, not {refused:?}"
    );

    // A refusal consumes nothing, or probing the ceiling would drain it.
    store
        .draw(&id, key(3), Spend::money(400), at)
        .await
        .expect("exactly the remainder is still available after a refusal");

    // ── A retry under one dispatch key consumes once ─────────────────────────
    let id = AuthorityId::new("conformance-retry");
    store
        .issue(&StandingAuthority::new(
            "conformance-retry",
            "conformance",
            Spend::money(1_000),
        ))
        .await
        .expect("issue");

    let original = store
        .draw(&id, key(10), Spend::money(300), at)
        .await
        .expect("draw");
    let repeat = store
        .draw(&id, key(10), Spend::money(300), at)
        .await
        .expect("a retry is not a second draw");
    assert_eq!(
        original, repeat,
        "a retried draw must return its original receipt"
    );
    let state = store.state(&id).await.expect("state").expect("issued");
    assert_eq!(
        state.drawn,
        Spend::money(300),
        "a retry spent the authority twice"
    );
    assert_eq!(state.draws, 1, "a retry counted as a second draw");

    // ── Revocation refuses new draws and preserves landed ones ───────────────
    store
        .revoke(&id, "conformance withdrew it", at)
        .await
        .expect("revoke");
    let after = store
        .draw(&id, key(10), Spend::money(300), at)
        .await
        .expect("a draw that already landed must stay landed on retry");
    assert_eq!(after, original);

    let refused = store
        .draw(&id, key(11), Spend::money(1), at)
        .await
        .expect_err("a new draw against a revoked authority");
    assert!(
        matches!(refused, AuthorityError::Revoked { .. }),
        "revoked must be distinguishable from exhausted, got {refused:?}"
    );

    // Idempotent, and the first reason stands.
    store
        .revoke(&id, "a second, different reason", at)
        .await
        .expect("revoking twice is a retry");
    let state = store.state(&id).await.expect("state").expect("issued");
    let revocation = state.revoked.expect("revoked");
    assert_eq!(
        revocation.reason, "conformance withdrew it",
        "the first reason must stand; overwriting loses why it was withdrawn"
    );

    // ── Terms are immutable ─────────────────────────────────────────────────
    let terms = StandingAuthority::new("conformance-terms", "conformance", Spend::money(500));
    store.issue(&terms).await.expect("issue");
    store
        .issue(&terms)
        .await
        .expect("an identical re-issue is a retried deploy");
    let conflict = store
        .issue(&StandingAuthority::new(
            "conformance-terms",
            "conformance",
            Spend::money(999_999),
        ))
        .await
        .expect_err("a ceiling must not be editable under whoever agreed to it");
    assert!(
        matches!(conflict, AuthorityError::AlreadyIssued(_)),
        "got {conflict:?}"
    );

    // ── Expiry is evaluated against the instant handed in ───────────────────
    store
        .issue(
            &StandingAuthority::new("conformance-expiry", "conformance", Spend::money(500))
                .expires_at(Timestamp::from_unix_timestamp(1_000).expect("representable")),
        )
        .await
        .expect("issue");
    let id = AuthorityId::new("conformance-expiry");
    store
        .draw(
            &id,
            key(20),
            Spend::money(1),
            Timestamp::from_unix_timestamp(999).expect("representable"),
        )
        .await
        .expect("before expiry the authority stands");
    let expired = store
        .draw(
            &id,
            key(21),
            Spend::money(1),
            Timestamp::from_unix_timestamp(2_000).expect("representable"),
        )
        .await
        .expect_err("past its expiry");
    assert!(
        matches!(expired, AuthorityError::Expired { .. }),
        "expiry must read the caller's instant, not a store clock; got {expired:?}"
    );

    // ── A draw ceiling bounds separately from a spend ceiling ───────────────
    store
        .issue(
            &StandingAuthority::new("conformance-draws", "conformance", Spend::money(10_000))
                .max_draws(1),
        )
        .await
        .expect("issue");
    let id = AuthorityId::new("conformance-draws");
    store
        .draw(&id, key(30), Spend::money(1), at)
        .await
        .expect("first");
    let spent = store
        .draw(&id, key(31), Spend::money(1), at)
        .await
        .expect_err("one draw was all it permitted");
    assert!(
        matches!(spent, AuthorityError::DrawsSpent { .. }),
        "a draw ceiling must refuse with money still left; got {spent:?}"
    );

    // ── An unissued authority is Unknown, not a silent allow ────────────────
    let unknown = store
        .draw(
            &AuthorityId::new("conformance-never-issued"),
            key(40),
            Spend::money(1),
            at,
        )
        .await
        .expect_err("never issued");
    assert!(
        matches!(unknown, AuthorityError::Unknown(_)),
        "got {unknown:?}"
    );
    assert!(
        store
            .state(&AuthorityId::new("conformance-never-issued"))
            .await
            .expect("state")
            .is_none()
    );

    // ── Concurrent carriers of ONE dispatch key all get the one receipt ──────
    //
    // The sequential retry case above cannot catch the racing form: a store
    // that checks the receipt before taking its lock lets two carriers of the
    // same key both pass the check, and the loser then re-evaluates the ceiling
    // *after* the winner spent it — refusing `Exhausted` for a draw that
    // stands, or tripping the receipt table's unique key. The ceiling here
    // covers exactly one such draw, so any double-spend or spurious refusal is
    // observable rather than absorbed by slack.
    //
    // The runtime's fencing cannot produce this race, which is exactly why the
    // battery must: the trait promises idempotence by key without qualifying
    // who carries it.
    let id = AuthorityId::new("conformance-racing-retry");
    store
        .issue(&StandingAuthority::new(
            "conformance-racing-retry",
            "conformance",
            Spend::money(500),
        ))
        .await
        .expect("issue");

    let carriers: Vec<_> = (0..8)
        .map(|_| {
            let store = Arc::clone(&store);
            let id = id.clone();
            tokio::spawn(async move { store.draw(&id, key(50), Spend::money(500), at).await })
        })
        .collect();
    let mut receipts = Vec::new();
    for carrier in carriers {
        receipts.push(
            carrier
                .await
                .expect("a carrier panicked")
                .expect("every carrier of the one key must get the receipt, not a refusal"),
        );
    }
    for r in &receipts {
        assert_eq!(
            *r, receipts[0],
            "two carriers of one dispatch key were given different receipts"
        );
    }
    let state = store.state(&id).await.expect("state").expect("issued");
    assert_eq!(
        state.drawn,
        Spend::money(500),
        "racing retries spent the authority more than once"
    );
    assert_eq!(state.draws, 1, "racing retries counted as several draws");
}
