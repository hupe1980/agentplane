//! Admitting a run at most once, under a key an emitter chose.
//!
//! One deployment shape throughout: something upstream delivers at least once,
//! and the receiver must not turn a redelivery into a second run.
//!
//! The blast radius is not wasted tokens. A duplicate run opens a duplicate
//! **decision task**, and a reviewer looking at two identical approvals for one
//! instruction is a four-eyes control degrading into a guess — which is why the
//! suspended case below is the load-bearing one.

// Tests sit outside the deterministic zone: they drive the runtime rather than
// run inside it, so reading a clock here is the harness establishing "now".
#![allow(clippy::disallowed_methods)]
#![cfg(feature = "redb")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::case::{CaseStore, EventStore};
use agentplane::core::{
    AwaitSpec, BudgetExceeded, CorrelationKey, DeadlineSpec, Digest, InboundEvent, Outcome,
    PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest, Skill, SkillDescriptor,
    SkillError, StepError, Tainted,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Admission, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

// ── Fixtures ────────────────────────────────────────────────────────────────

fn key(v: &str) -> CorrelationKey {
    CorrelationKey::new("doc", v)
}

/// The identity an at-least-once emitter's message carries.
///
/// Through `InboundEvent::dedup_key` rather than by hand: it is the spelling the
/// docs point callers at, so a test writing its own would not notice a drift.
fn dedup_key(source: &str, id: &str) -> String {
    InboundEvent::new(source, id, "order.placed", json!({})).dedup_key()
}

/// Counts how many times it actually ran.
#[derive(Debug)]
struct Counts(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Skill for Counts {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("counts").provides("demo.counts")
    }
    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Outcome::done(input))
    }
}

/// Opens a wait and parks, which is what a run awaiting a human decision does.
#[derive(Debug)]
struct WaitsForApproval(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Skill for WaitsForApproval {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("waits").provides("demo.waits")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        cx.deadline("approval", &DeadlineSpec::days(5), None)
            .await?;
        let reply = cx
            .await_event(&AwaitSpec::new("approval.given", "approval").correlate(key("D-1")))
            .await?;
        Ok(Outcome::done(reply))
    }
}

/// Fails every time, so a run concludes without succeeding.
#[derive(Debug)]
struct AlwaysFails;

#[async_trait::async_trait]
impl Skill for AlwaysFails {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("fails").provides("demo.fails")
    }
    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Err(SkillError::Other("the counterparty rejected it".into()))
    }
}

/// Stops on a budget so duplicate admission has to preserve a typed pause.
#[derive(Debug)]
struct Exhausts;

#[async_trait::async_trait]
impl Skill for Exhausts {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("exhausts").provides("demo.exhausts")
    }
    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Err(StepError::Budget(BudgetExceeded::Effects {
            allowed: 3,
            used: 3,
        })
        .into())
    }
}

/// Denies admission while `deny` is set, so the same call can be refused and
/// then permitted without rebuilding the plane.
#[derive(Debug, Default)]
struct Gate {
    deny: std::sync::atomic::AtomicBool,
}

impl PolicyEngine for Gate {
    fn authorize(&self, _request: &PolicyRequest<'_>) -> PolicyDecision {
        if self.deny.load(Ordering::SeqCst) {
            PolicyDecision::deny("the test policy refuses this")
        } else {
            PolicyDecision::Permit
        }
    }
    fn bundle(&self) -> PolicyBundleIdentity {
        PolicyBundleIdentity::new(
            Digest::of(b"admission-test"),
            "agentplane-test/admission-v1",
        )
    }
}

struct Fixture {
    rt: Arc<Runtime>,
    store: Arc<RedbStore>,
    runs: Arc<AtomicUsize>,
}

fn fixture() -> Fixture {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let runs = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .skill(Counts(Arc::clone(&runs)))
        .skill(WaitsForApproval(Arc::clone(&runs)))
        .skill(AlwaysFails)
        .skill(Exhausts)
        .build();
    Fixture { rt, store, runs }
}

/// How many runs this case actually holds.
///
/// Read from the case's own history, which is what an operator sees when they
/// ask what happened to a matter.
async fn runs_in_case(f: &Fixture, run: agentplane::RunId) -> usize {
    let case = f.rt.case_of(run).await.unwrap().expect("a case-bound run");
    f.store
        .case_history(case, 10_000)
        .await
        .unwrap()
        .iter()
        .map(|r| r.body.run)
        .collect::<std::collections::HashSet<_>>()
        .len()
}

// ── The core property ───────────────────────────────────────────────────────

/// A redelivery under the same key does not start a second run.
///
/// The emitter sends twice because it never saw the first 2xx; the receiver
/// must act once.
#[tokio::test]
async fn a_redelivery_under_one_key_admits_one_run() {
    let f = fixture();
    let k = dedup_key("urn:test:bus", "EV-1");

    let first =
        f.rt.run_correlated_once(
            "demo.counts",
            Tainted::trusted(json!({ "order": "O-1" })),
            "matter",
            &[key("D-1")],
            &k,
        )
        .await
        .unwrap();
    assert!(first.is_fresh(), "the first delivery admits: {first:?}");

    let again =
        f.rt.run_correlated_once(
            "demo.counts",
            Tainted::trusted(json!({ "order": "O-1" })),
            "matter",
            &[key("D-1")],
            &k,
        )
        .await
        .unwrap();

    assert!(
        matches!(again, Admission::Replayed(_)),
        "the redelivery must be answered with the original run, got {again:?}"
    );
    assert_eq!(
        again.run_id(),
        first.run_id(),
        "a retry that is told about a different run has learned nothing"
    );
    assert_eq!(
        f.runs.load(Ordering::SeqCst),
        1,
        "the skill ran twice, so the emitter's retry became a second fan-out"
    );
    assert_eq!(
        runs_in_case(&f, first.run_id()).await,
        1,
        "the case holds a second run — an operator reading this matter sees work \
         that never happened"
    );
}

/// The four-eyes case: a run parked on a decision answers its own redelivery.
///
/// The first delivery opens an approval and suspends. A redelivery that admitted
/// would put a second identical approval in front of a reviewer.
#[tokio::test]
async fn a_run_waiting_for_a_human_answers_its_own_redelivery() {
    let f = fixture();
    let k = dedup_key("urn:test:bus", "EV-2");

    let first =
        f.rt.run_correlated_once(
            "demo.waits",
            Tainted::trusted(json!({})),
            "matter",
            &[key("D-1")],
            &k,
        )
        .await
        .unwrap();
    assert!(matches!(
        first,
        Admission::Fresh(ref o) if o.status.is_suspended()
    ));

    let again =
        f.rt.run_correlated_once(
            "demo.waits",
            Tainted::trusted(json!({})),
            "matter",
            &[key("D-1")],
            &k,
        )
        .await
        .unwrap();

    let Admission::Replayed(outcome) = &again else {
        panic!("a suspended run is a resting point and must be replayed: {again:?}");
    };
    assert!(
        outcome.status.is_suspended(),
        "the redelivery must be told the original is waiting, not that it is \
         working: {:?}",
        outcome.status
    );
    assert!(
        outcome.reason().is_some_and(|r| r.contains("approval")),
        "the reason must name what is being waited for: {:?}",
        outcome.reason()
    );
    assert_eq!(
        f.runs.load(Ordering::SeqCst),
        1,
        "a second approval was opened for one instruction"
    );

    // And the original is still the run the delivery resumes — answering a
    // duplicate must not have disturbed it.
    let waiting = f.store.waiting(10).await.unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].run, first.run_id());
}

/// A failed run keeps its key: a failure is an answer, not an absence.
///
/// Freeing the key on failure would make the guarantee conditional on the
/// outcome, and an emitter retrying a permanent failure would re-run it forever.
#[tokio::test]
async fn a_failed_run_still_holds_its_key() {
    let f = fixture();
    let k = dedup_key("urn:test:bus", "EV-3");

    let first =
        f.rt.run_correlated_once(
            "demo.fails",
            Tainted::trusted(json!({})),
            "matter",
            &[key("D-1")],
            &k,
        )
        .await
        .unwrap();
    assert!(matches!(
        first,
        Admission::Fresh(ref o) if matches!(o.status, RunStatus::Failed(_))
    ));

    let again =
        f.rt.run_correlated_once(
            "demo.fails",
            Tainted::trusted(json!({})),
            "matter",
            &[key("D-1")],
            &k,
        )
        .await
        .unwrap();

    let Admission::Replayed(outcome) = &again else {
        panic!("a concluded run must be replayed, got {again:?}");
    };
    assert!(
        matches!(outcome.status, RunStatus::Failed(_)),
        "the replay must report the failure, not silence: {:?}",
        outcome.status
    );
    assert!(
        outcome.reason().is_some_and(|r| r.contains("counterparty")),
        "a refusal read back as an empty summary is the failure `reason()` \
         exists to prevent: {:?}",
        outcome.reason()
    );
    assert_eq!(again.run_id(), first.run_id());
}

/// A duplicate sees exhaustion as the resumable pause it is, not as a fault.
#[tokio::test]
async fn an_exhausted_run_keeps_its_typed_status_on_redelivery() {
    let f = fixture();
    let key = dedup_key("urn:test:bus", "EV-exhausted");

    let first =
        f.rt.run_once("demo.exhausts", Tainted::trusted(json!({})), &key)
            .await
            .unwrap();
    assert!(matches!(
        first,
        Admission::Fresh(ref outcome)
            if matches!(outcome.status, RunStatus::Exhausted(BudgetExceeded::Effects {
                allowed: 3,
                used: 3,
            }))
    ));

    let again =
        f.rt.run_once("demo.exhausts", Tainted::trusted(json!({})), &key)
            .await
            .unwrap();
    let Admission::Replayed(outcome) = again else {
        panic!("an exhausted run is a resting point and must answer its redelivery");
    };
    assert!(
        matches!(
            outcome.status,
            RunStatus::Exhausted(BudgetExceeded::Effects {
                allowed: 3,
                used: 3,
            })
        ),
        "string-only conclusion reconstruction collapsed exhaustion into a failure: {:?}",
        outcome.status
    );
}

/// Two different messages are two runs.
///
/// Without it, a store refusing every second admission passes everything above.
#[tokio::test]
async fn distinct_keys_admit_distinct_runs() {
    let f = fixture();
    let mut ids = Vec::new();
    for id in ["EV-a", "EV-b", "EV-c"] {
        let out =
            f.rt.run_correlated_once(
                "demo.counts",
                Tainted::trusted(json!({})),
                "matter",
                &[key("D-1")],
                &dedup_key("urn:test:bus", id),
            )
            .await
            .unwrap();
        assert!(out.is_fresh(), "{id} was refused as a duplicate");
        ids.push(out.run_id());
    }
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        3,
        "three messages produced fewer than three runs"
    );
    assert_eq!(f.runs.load(Ordering::SeqCst), 3);
}

/// The same id from two emitters is two messages, not a retry.
///
/// Why the key must carry its producer: an id is unique only within one emitter,
/// so a bare id lets two counterparties silently swallow each other's messages.
#[tokio::test]
async fn one_id_from_two_emitters_is_two_messages() {
    let f = fixture();
    for source in ["urn:test:bus-a", "urn:test:bus-b"] {
        let out =
            f.rt.run_correlated_once(
                "demo.counts",
                Tainted::trusted(json!({})),
                "matter",
                &[key("D-1")],
                &dedup_key(source, "EV-1"),
            )
            .await
            .unwrap();
        assert!(
            out.is_fresh(),
            "{source}'s message was swallowed as another emitter's retry"
        );
    }
    assert_eq!(f.runs.load(Ordering::SeqCst), 2);
}

// ── Refusals ────────────────────────────────────────────────────────────────

/// An admission that was refused spends no key.
///
/// A policy denial leaves no journal at all, so the key must still be free —
/// otherwise a transient misconfiguration permanently swallows a message.
#[tokio::test]
async fn a_denied_admission_leaves_its_key_free() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let runs = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(Gate::default());
    gate.deny.store(true, Ordering::SeqCst);
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .policy(Arc::clone(&gate) as Arc<dyn PolicyEngine>)
        .skill(Counts(Arc::clone(&runs)))
        .build();
    let k = dedup_key("urn:test:bus", "EV-4");

    let refused = rt
        .run_correlated_once(
            "demo.counts",
            Tainted::trusted(json!({})),
            "matter",
            &[key("D-1")],
            &k,
        )
        .await;
    assert!(refused.is_err(), "the policy was set to deny");
    assert_eq!(
        store.admitted_as(&k).await.unwrap(),
        None,
        "a denial that burns the key swallows the message permanently"
    );

    gate.deny.store(false, Ordering::SeqCst);
    let out = rt
        .run_correlated_once(
            "demo.counts",
            Tainted::trusted(json!({})),
            "matter",
            &[key("D-1")],
            &k,
        )
        .await
        .unwrap();
    assert!(
        out.is_fresh(),
        "once the misconfiguration is fixed the retry must be admitted"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

// ── Concurrency ─────────────────────────────────────────────────────────────

/// Racing redeliveries produce one run, and the losers are told which.
///
/// A sequential check cannot detect this. The read preceding admission is an
/// optimisation; every racer sees an empty index, so the outcome depends
/// entirely on whether the append refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn racing_redeliveries_admit_one_run() {
    let f = fixture();
    let k = dedup_key("urn:test:bus", "EV-race");

    let mut racers = Vec::new();
    for _ in 0..8 {
        let rt = Arc::clone(&f.rt);
        let k = k.clone();
        racers.push(tokio::spawn(async move {
            rt.run_correlated_once(
                "demo.counts",
                Tainted::trusted(json!({})),
                "matter",
                &[key("D-1")],
                &k,
            )
            .await
        }));
    }

    let mut admitted = Vec::new();
    let mut fresh = 0;
    for r in racers {
        let out = r.await.unwrap().expect("no racer should error");
        if out.is_fresh() {
            fresh += 1;
        }
        admitted.push(out.run_id());
    }

    assert_eq!(fresh, 1, "exactly one racer may be the one that admitted");
    admitted.dedup();
    assert_eq!(
        admitted
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        1,
        "every racer must be told about the same run"
    );
    assert_eq!(
        f.runs.load(Ordering::SeqCst),
        1,
        "eight redeliveries of one message ran the work more than once"
    );
    assert_eq!(
        runs_in_case(&f, admitted[0]).await,
        1,
        "a losing racer left its attachment behind, so the case lists runs with \
         no journal"
    );
}

// ── Spawning ────────────────────────────────────────────────────────────────

/// The non-blocking pair keeps the same guarantee and says which call started
/// the work.
#[tokio::test]
async fn spawning_twice_under_one_key_starts_one_run() {
    let f = fixture();
    let k = dedup_key("urn:test:bus", "EV-5");

    let first =
        f.rt.spawn_correlated_once(
            "demo.counts",
            Tainted::trusted(json!({})),
            "matter",
            &[key("D-1")],
            &k,
        )
        .await
        .unwrap();
    assert!(first.fresh);

    let again =
        f.rt.spawn_correlated_once(
            "demo.counts",
            Tainted::trusted(json!({})),
            "matter",
            &[key("D-1")],
            &k,
        )
        .await
        .unwrap();
    assert!(
        !again.fresh,
        "the second spawn reported that it started the work"
    );
    assert_eq!(again.run, first.run);
}

/// A plane with no case store still admits at most once.
///
/// Correlation and idempotency are independent: which matter a message belongs
/// to, and whether it is acted on at all.
#[tokio::test]
async fn a_plane_without_cases_still_admits_once() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let runs = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .skill(Counts(Arc::clone(&runs)))
        .build();
    let k = dedup_key("urn:test:bus", "EV-6");

    let first = rt
        .run_once("demo.counts", Tainted::trusted(json!({})), &k)
        .await
        .unwrap();
    let again = rt
        .run_once("demo.counts", Tainted::trusted(json!({})), &k)
        .await
        .unwrap();

    assert!(first.is_fresh() && !again.is_fresh());
    assert_eq!(again.run_id(), first.run_id());
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

// ── What the journal records ────────────────────────────────────────────────

/// The key is on the run's own record, so the index can be rebuilt from it.
///
/// A derived index whose source is not in the chain is one nobody can check.
#[tokio::test]
async fn the_key_is_recorded_on_the_run_it_admitted() {
    let f = fixture();
    let k = dedup_key("urn:test:bus", "EV-7");

    let out =
        f.rt.run_correlated_once(
            "demo.counts",
            Tainted::trusted(json!({})),
            "matter",
            &[key("D-1")],
            &k,
        )
        .await
        .unwrap();

    let records = f.store.read(out.run_id(), 1).await.unwrap();
    let recorded = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::RunAdmitted {
                idempotency_key, ..
            } => idempotency_key.clone(),
            _ => None,
        })
        .expect("the admission record must carry the key it claimed");
    assert_eq!(recorded, k);

    assert_eq!(
        f.store.admitted_as(&k).await.unwrap(),
        Some(out.run_id()),
        "the index must agree with the record it derives from"
    );
}

/// An ordinary run records no key and claims none.
///
/// The shape every existing caller uses.
#[tokio::test]
async fn an_ordinary_run_claims_no_key() {
    let f = fixture();
    for _ in 0..2 {
        f.rt.run_correlated(
            "demo.counts",
            Tainted::trusted(json!({})),
            "matter",
            &[key("D-2")],
        )
        .await
        .unwrap();
    }
    assert_eq!(f.runs.load(Ordering::SeqCst), 2);
    assert_eq!(f.store.admitted_as("").await.unwrap(), None);
}

/// The **constraint** arbitrates, not the read that precedes it.
///
/// `admit_once` reads the index before admitting, and in a sequential test that
/// read answers every duplicate — so the arm that handles the append's refusal,
/// the one a real race actually takes, is never reached. This blinds the read
/// the way a race does: both instances see nothing, and only the store decides.
#[derive(Debug)]
struct BlindToKeys(Arc<dyn JournalStore>);

#[async_trait::async_trait]
impl JournalStore for BlindToKeys {
    async fn admitted_as(
        &self,
        _key: &str,
    ) -> Result<Option<agentplane::RunId>, agentplane::core::StoreError> {
        Ok(None)
    }
    async fn append(
        &self,
        epoch: agentplane::core::Epoch,
        batch: Vec<agentplane::journal::Append>,
    ) -> Result<Vec<agentplane::journal::Record>, agentplane::core::StoreError> {
        self.0.append(epoch, batch).await
    }
    fn is_shared(&self) -> bool {
        self.0.is_shared()
    }
    async fn read(
        &self,
        run: agentplane::RunId,
        from: agentplane::core::Seq,
    ) -> Result<Vec<agentplane::journal::Record>, agentplane::core::StoreError> {
        self.0.read(run, from).await
    }
    async fn forget_admissions(
        &self,
        older_than: agentplane::core::Timestamp,
    ) -> Result<usize, agentplane::core::StoreError> {
        self.0.forget_admissions(older_than).await
    }
    async fn runs_by_outcome(
        &self,
        outcome: &str,
        limit: usize,
    ) -> Result<Vec<agentplane::RunId>, agentplane::core::StoreError> {
        self.0.runs_by_outcome(outcome, limit).await
    }
    async fn count_by_outcome(&self, outcome: &str) -> Result<u64, agentplane::core::StoreError> {
        self.0.count_by_outcome(outcome).await
    }
    async fn recent_runs(
        &self,
        after: Option<(u64, agentplane::RunId)>,
        limit: usize,
    ) -> Result<Vec<(agentplane::RunId, u64)>, agentplane::core::StoreError> {
        self.0.recent_runs(after, limit).await
    }
    async fn case_history(
        &self,
        case: agentplane::core::CaseId,
        limit: usize,
    ) -> Result<Vec<agentplane::journal::Record>, agentplane::core::StoreError> {
        self.0.case_history(case, limit).await
    }
    async fn head(
        &self,
        run: agentplane::RunId,
    ) -> Result<agentplane::journal::Head, agentplane::core::StoreError> {
        self.0.head(run).await
    }
    async fn acquire(
        &self,
        run: agentplane::RunId,
        owner: &str,
        ttl: std::time::Duration,
    ) -> Result<agentplane::journal::Lease, agentplane::core::StoreError> {
        self.0.acquire(run, owner, ttl).await
    }
    async fn renew(
        &self,
        run: agentplane::RunId,
        owner: &str,
        epoch: agentplane::core::Epoch,
        ttl: std::time::Duration,
    ) -> Result<agentplane::journal::Lease, agentplane::core::StoreError> {
        self.0.renew(run, owner, epoch, ttl).await
    }
    async fn abandoned_runs(
        &self,
        limit: usize,
    ) -> Result<Vec<agentplane::RunId>, agentplane::core::StoreError> {
        self.0.abandoned_runs(limit).await
    }
    async fn release_lease(
        &self,
        run: agentplane::RunId,
        epoch: agentplane::core::Epoch,
    ) -> Result<(), agentplane::core::StoreError> {
        self.0.release_lease(run, epoch).await
    }
    async fn seal(
        &self,
        run: agentplane::RunId,
        epoch: agentplane::core::Epoch,
        outcome: &str,
    ) -> Result<agentplane::core::Digest, agentplane::core::StoreError> {
        self.0.seal(run, epoch, outcome).await
    }
    async fn checkpoint(
        &self,
    ) -> Result<agentplane::journal::Checkpoint, agentplane::core::StoreError> {
        self.0.checkpoint().await
    }
    async fn consistency_proof(
        &self,
        old_size: u64,
    ) -> Result<Vec<agentplane::core::Digest>, agentplane::core::StoreError> {
        self.0.consistency_proof(old_size).await
    }
    async fn inclusion_proof(
        &self,
        run: agentplane::RunId,
    ) -> Result<Option<agentplane::journal::Inclusion>, agentplane::core::StoreError> {
        self.0.inclusion_proof(run).await
    }
    async fn request_cancel(
        &self,
        run: agentplane::RunId,
        actor: &str,
        reason: &str,
    ) -> Result<bool, agentplane::core::StoreError> {
        self.0.request_cancel(run, actor, reason).await
    }
    async fn cancellation(
        &self,
        run: agentplane::RunId,
    ) -> Result<Option<agentplane::journal::Cancellation>, agentplane::core::StoreError> {
        self.0.cancellation(run).await
    }
}

/// A duplicate the read never saw is still answered with the original's outcome.
///
/// The losing racer must be told *what happened*, not merely *which run won*:
/// reporting a concluded original as still in flight sends the emitter back to
/// retry a message that has already been answered.
#[tokio::test]
async fn a_duplicate_the_read_missed_is_still_answered_with_the_original() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let runs = Arc::new(AtomicUsize::new(0));
    let blind: Arc<dyn JournalStore> =
        Arc::new(BlindToKeys(store.clone() as Arc<dyn JournalStore>));
    let rt = Runtime::builder(blind)
        .skill(Counts(Arc::clone(&runs)))
        .build();
    let k = dedup_key("urn:test:bus", "EV-blind");

    let first = rt
        .run_once("demo.counts", Tainted::trusted(json!({})), &k)
        .await
        .unwrap();
    assert!(first.is_fresh());

    let again = rt
        .run_once("demo.counts", Tainted::trusted(json!({})), &k)
        .await
        .unwrap();

    assert!(
        matches!(again, Admission::Replayed(_)),
        "the store refused the duplicate, but the caller was told something other \
         than what the original did: {again:?}"
    );
    assert_eq!(again.run_id(), first.run_id());
    assert_eq!(
        again
            .outcome()
            .map(|o| matches!(o.status, RunStatus::Succeeded)),
        Some(true),
        "a concluded original reported as anything else sends the emitter back \
         to retry a message that is already answered"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

/// An empty key is refused, not accepted as a value.
///
/// The failure this prevents is silent and total: a missing header or an unset
/// variable arrives as `""`, `""` is a perfectly good key, and every later
/// message — a *different* message — is answered with the first one's run. Every
/// delivery after the first would be dropped, and the receiver would report
/// success for all of them.
#[tokio::test]
async fn an_empty_admission_key_is_refused() {
    let f = fixture();
    for key in ["", "   "] {
        let refused =
            f.rt.run_once("demo.counts", Tainted::trusted(json!({})), key)
                .await;
        assert!(
            refused.is_err(),
            "an empty key was accepted, so the next distinct message is answered \
             with this run"
        );
    }
    assert_eq!(
        f.runs.load(Ordering::SeqCst),
        0,
        "a refused admission ran the work anyway"
    );
}

/// A key the emitter can make arbitrarily long is refused at this crate's
/// boundary, with a reason, rather than at the backend's with an error code.
#[tokio::test]
async fn an_oversized_admission_key_is_refused() {
    let f = fixture();
    let huge = "x".repeat(agentplane::runtime::MAX_ADMISSION_KEY_BYTES + 1);
    assert!(
        f.rt.run_once("demo.counts", Tainted::trusted(json!({})), &huge)
            .await
            .is_err()
    );
    // The bound itself is usable: one byte under is an ordinary key.
    let ok = "x".repeat(agentplane::runtime::MAX_ADMISSION_KEY_BYTES);
    assert!(
        f.rt.run_once("demo.counts", Tainted::trusted(json!({})), &ok)
            .await
            .is_ok(),
        "the limit refuses a key at the limit, so it is one byte too tight"
    );
}

/// `recorded_outcome` reads without taking a lease.
///
/// What lets a duplicate be answered while the original is still running: a read
/// that acquired a lease would fence a healthy run in order to report on it.
#[tokio::test]
async fn reading_a_recorded_outcome_does_not_disturb_the_run() {
    let f = fixture();
    let out =
        f.rt.run_correlated(
            "demo.waits",
            Tainted::trusted(json!({})),
            "matter",
            &[key("D-1")],
        )
        .await
        .unwrap();
    let before = f.store.head(out.run_id).await.unwrap();

    let read =
        f.rt.recorded_outcome(out.run_id)
            .await
            .unwrap()
            .expect("a suspended run has reached a resting point");
    assert!(read.status.is_suspended());

    assert_eq!(
        f.store.head(out.run_id).await.unwrap(),
        before,
        "reading a run's recorded outcome appended to its chain"
    );
    // Still resumable, which is what "did not disturb it" has to mean.
    let delivered =
        f.rt.deliver(
            &InboundEvent::new(
                "urn:test:approver",
                "A-1",
                "approval.given",
                json!({ "ok": true }),
            )
            .correlate(key("D-1")),
        )
        .await
        .unwrap();
    assert!(
        format!("{delivered:?}").contains("Resumed"),
        "the run must still be the one a delivery wakes: {delivered:?}"
    );
}

/// A run with no records at all has nothing to report.
#[tokio::test]
async fn a_run_that_never_existed_has_no_recorded_outcome() {
    let f = fixture();
    assert!(
        f.rt.recorded_outcome(agentplane::RunId::generate())
            .await
            .unwrap()
            .is_none()
    );
}
