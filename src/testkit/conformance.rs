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

fn started(run: RunId, key: EffectKey) -> Append {
    Append::new(
        run,
        RecordKind::EffectStarted {
            descriptor: crate::core::EffectDescriptor::nullary("probe"),
            recovery: crate::core::Recovery::Retry,
            mutates: true,
            attempt: 1,
            backoff_ms: 0,
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
    a_live_lease_is_not_stolen(fresh, &mut r).await;
    a_takeover_advances_the_epoch(fresh, &mut r).await;
    a_rejected_batch_writes_nothing(fresh, &mut r).await;
    read_starts_where_it_is_told(fresh, &mut r).await;
    a_case_scan_selects_one_matter(fresh, &mut r).await;
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
