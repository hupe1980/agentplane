#![cfg(feature = "redb")]

//! Transactional effect groups and the frontier.
//!
//! A per-step saga leaves a gap: `Skill::compensate` receives the step's
//! **output**, and a step that failed has none. So a step that reserved
//! inventory, authorised a card and then failed hands its compensation the
//! absence of an output and asks it to guess. Every test here is a way that
//! guess goes wrong, written as something the runtime does instead.
//!
//! The world under test is a small ledger the effects actually mutate, so an
//! assertion says *what is standing* rather than *what was called*.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentplane::core::{
    Effect, EffectDescriptor, EffectError, Outcome, RetryPolicy, Skill, SkillDescriptor,
    SkillError, Tainted,
};
use agentplane::journal::JournalStore;
use agentplane::runtime::{Invariant, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

// ── A world the effects really change ───────────────────────────────────────

/// What actually happened out there, in order.
#[derive(Debug, Default)]
struct World {
    log: Mutex<Vec<String>>,
    /// Set to fail the named effect kind once it is reached.
    fail: Mutex<Option<(String, Failure)>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// The call was refused before it reached anything.
    DidNotHappen,
    /// Nobody can say whether it landed.
    InDoubt,
}

impl World {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn fail(self: &Arc<Self>, kind: &str, how: Failure) -> Arc<Self> {
        *self.fail.lock().expect("lock") = Some((kind.to_owned(), how));
        Arc::clone(self)
    }

    fn entries(&self) -> Vec<String> {
        self.log.lock().expect("lock").clone()
    }

    fn did(&self, entry: &str) -> bool {
        self.entries().iter().any(|e| e == entry)
    }

    fn record(&self, kind: &str, what: &str) -> Result<Value, EffectError> {
        if let Some((failing, how)) = self.fail.lock().expect("lock").clone()
            && failing == kind
        {
            return Err(match how {
                Failure::DidNotHappen => EffectError::Rejected(format!("{kind} refused")),
                Failure::InDoubt => EffectError::Other(format!("{kind} did not answer")),
            });
        }
        self.log.lock().expect("lock").push(what.to_owned());
        Ok(json!({ "ok": what }))
    }
}

/// One mutating call against the world.
///
/// Deliberately one type rather than four: what distinguishes a reserve from a
/// release here is what it writes to the log, and using four near-identical
/// structs would only make the tests longer without making them stricter.
#[derive(Debug)]
struct Call {
    kind: &'static str,
    what: String,
    world: Arc<World>,
}

impl Call {
    fn new(kind: &'static str, what: impl Into<String>, world: &Arc<World>) -> Self {
        Self {
            kind,
            what: what.into(),
            world: Arc::clone(world),
        }
    }
}

#[async_trait::async_trait]
impl Effect for Call {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(self.kind, json!({ "what": self.what }))
    }

    /// One attempt. These tests are about what happens *after* a call fails,
    /// and three attempts with backoff would only slow that down.
    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }

    /// Reconcilable, so an in-doubt failure reaches the group as doubt rather
    /// than being escalated by the effect layer before the group sees it.
    fn recovery(&self) -> agentplane::core::Recovery {
        agentplane::core::Recovery::Reconcile
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.world.record(self.kind, &self.what)
    }
}

/// A read inside a group: it changes nothing.
#[derive(Debug)]
struct Look {
    world: Arc<World>,
}

#[async_trait::async_trait]
impl Effect for Look {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::nullary("ledger.look")
    }

    fn mutates(&self) -> bool {
        false
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        Ok(json!({ "entries": self.world.entries().len() }))
    }
}

// ── A skill that drives one group, scripted by its input ────────────────────

/// Runs a checkout group. What it does after the members land is chosen by the
/// input, so one skill covers every ending a group has.
#[derive(Debug)]
struct Checkout {
    world: Arc<World>,
}

#[async_trait::async_trait]
impl Skill for Checkout {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("checkout").provides("checkout")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let script = input.peek().clone();
        let w = &self.world;
        let mut g = cx
            .group("checkout", ["inventory", "payments", "notify"])
            .await
            .map_err(SkillError::Step)?;

        if script["footprint_violation"].as_bool() == Some(true) {
            let err = g
                .reversible("shipping", Call::new("ship.book", "booked", w), |_| {
                    Call::new("ship.cancel", "cancelled", w)
                })
                .await
                .expect_err("a member outside the footprint was admitted");
            return Err(SkillError::Step(err));
        }

        if script["mutating_read"].as_bool() == Some(true) {
            let err = g
                .read("inventory", Call::new("stock.take", "taken", w))
                .await
                .expect_err("a mutating effect was admitted as a group read");
            return Err(SkillError::Step(err));
        }

        if script["nested"].as_bool() == Some(true) {
            let _ = g;
            let mut outer = cx
                .group("outer", ["inventory"])
                .await
                .map_err(SkillError::Step)?;
            let err = outer
                .reversible(
                    "inventory",
                    Look {
                        world: Arc::clone(w),
                    },
                    |_| Call::new("noop", "noop", w),
                )
                .await;
            // Reaching a second group is what is under test; the member is
            // incidental.
            let _ = err;
            let nested = cx.group("inner", ["inventory"]).await;
            let Err(refused) = nested else {
                panic!("a second group opened while one was still open");
            };
            return Err(SkillError::Step(refused));
        }

        // Two reversible members, in order.
        g.reversible(
            "inventory",
            Call::new("stock.hold", "held sku-1", w),
            |_| Call::new("stock.release", "released sku-1", w),
        )
        .await
        .map_err(SkillError::Step)?;

        g.reversible("payments", Call::new("card.auth", "authorised", w), |_| {
            Call::new("card.void", "voided", w)
        })
        .await
        .map_err(SkillError::Step)?;

        // A read has nothing to take back.
        g.read(
            "inventory",
            Look {
                world: Arc::clone(w),
            },
        )
        .await
        .map_err(SkillError::Step)?;

        // The irreversible send: held at the gate, so an abort never sends it.
        g.deferred("notify", Call::new("mail.send", "order confirmed", w))
            .map_err(SkillError::Step)?;

        match script["ending"].as_str().unwrap_or("commit") {
            // The step walks away without settling. The executor must not read
            // that as a commit.
            "walk away" => Ok(Outcome::done(Tainted::trusted(json!("left open")))),
            "abort" => {
                g.abort("the caller changed their mind")
                    .await
                    .map_err(SkillError::Step)?;
                Ok(Outcome::done(Tainted::trusted(json!("aborted"))))
            }
            "invariant" => {
                let err = g
                    .commit(&[
                        Invariant::new("the hold exists", true),
                        Invariant::new("the price still stands", false),
                    ])
                    .await
                    .expect_err("a false invariant committed");
                Err(SkillError::Step(err))
            }
            "fail after" => {
                g.commit(&[]).await.map_err(SkillError::Step)?;
                Err(SkillError::Other("failed past the frontier".to_owned()))
            }
            _ => {
                let deferred = g.commit(&[]).await.map_err(SkillError::Step)?;
                Ok(Outcome::done(Tainted::trusted(
                    json!({ "deferred": deferred.len() }),
                )))
            }
        }
    }
}

async fn run(world: &Arc<World>, script: Value) -> agentplane::runtime::RunOutcome {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Checkout {
            world: Arc::clone(world),
        })
        .build();
    rt.run("checkout", script).await.expect("run")
}

// ── A failure takes back what landed ────────────────────────────────────────

/// The gap a per-step saga leaves open, closed.
///
/// The step landed two mutations and then failed. Its own `compensate` would be
/// handed no output and would have to guess; the group knows, because each
/// member recorded the concrete call that undoes it at the moment it landed.
#[tokio::test]
async fn a_failed_group_takes_back_every_member_that_landed() {
    let world = World::new();
    // The gated send is what fails, before it has sent anything.
    let out = run(&world.fail("mail.send", Failure::DidNotHappen), json!({})).await;

    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "expected a plain failure, got {:?}",
        out.status
    );
    assert!(
        world.did("released sku-1") && world.did("voided"),
        "the group failed with members standing: {:?}",
        world.entries()
    );
}

/// Reversals run newest-first, because a later member may rest on an earlier
/// one still being in place.
#[tokio::test]
async fn reversals_run_in_the_opposite_order_to_the_members() {
    let world = World::new();
    run(&world.fail("mail.send", Failure::DidNotHappen), json!({})).await;

    let log = world.entries();
    let void = log.iter().position(|e| e == "voided").expect("voided");
    let release = log
        .iter()
        .position(|e| e == "released sku-1")
        .expect("released");
    assert!(
        void < release,
        "reversals ran in landing order rather than the reverse: {log:?}"
    );
}

// ── Deferral is stronger than compensation ──────────────────────────────────

/// The irreversible send never happens for a group that does not commit.
///
/// This is the property compensation cannot offer. A member that runs and is
/// undone leaves a trace someone saw — the email arrived, then a correction
/// arrived. A member held at the gate leaves none.
#[tokio::test]
async fn an_aborted_group_never_runs_its_deferred_member() {
    let world = World::new();
    let out = run(&world, json!({ "ending": "abort" })).await;

    assert_eq!(out.status, RunStatus::Succeeded);
    assert!(
        !world.did("order confirmed"),
        "an aborted group sent its irreversible member: {:?}",
        world.entries()
    );
    assert!(
        world.did("released sku-1") && world.did("voided"),
        "the abort left members standing: {:?}",
        world.entries()
    );
}

/// A deferred member runs only once every reversible member has landed.
#[tokio::test]
async fn a_deferred_member_runs_last_and_only_on_commit() {
    let world = World::new();
    let out = run(&world, json!({ "ending": "commit" })).await;

    assert_eq!(out.status, RunStatus::Succeeded);
    let log = world.entries();
    assert_eq!(
        log,
        vec!["held sku-1", "authorised", "order confirmed"],
        "the gated member did not run last, or ran when it should not have"
    );
    assert_eq!(
        out.output.as_ref().expect("output")["deferred"],
        1,
        "commit did not return the deferred member's output"
    );
}

// ── The frontier ────────────────────────────────────────────────────────────

/// An invariant is checked while failing it is still free.
///
/// Checked *at* the frontier rather than before the members ran, because the
/// facts it tests only exist once they have — and after the frontier there is
/// nothing left to take back.
#[tokio::test]
async fn a_broken_invariant_reverses_the_group_and_names_itself() {
    let world = World::new();
    let out = run(&world, json!({ "ending": "invariant" })).await;

    let RunStatus::Failed(why) = &out.status else {
        panic!("expected a failure, got {:?}", out.status);
    };
    assert!(
        why.contains("the price still stands"),
        "the abort did not name the invariant that broke it: {why}"
    );
    assert!(
        !world.did("order confirmed"),
        "a group whose invariant failed still sent its irreversible member"
    );
    assert!(
        world.did("released sku-1") && world.did("voided"),
        "a broken invariant left the group standing: {:?}",
        world.entries()
    );
}

/// Past the frontier, nothing unwinds.
///
/// The saga pivot rule at the granularity where the calls live: undoing a
/// committed group would reverse a decision the outside world has acted on.
#[tokio::test]
async fn a_failure_after_the_frontier_does_not_unwind() {
    let world = World::new();
    let out = run(&world, json!({ "ending": "fail after" })).await;

    assert!(matches!(out.status, RunStatus::Failed(_)));
    assert_eq!(
        world.entries(),
        vec!["held sku-1", "authorised", "order confirmed"],
        "a failure after the frontier reversed a committed group"
    );
}

// ── Doubt ───────────────────────────────────────────────────────────────────

/// Doubt is the one condition under which nothing may be reversed.
///
/// Reversing around a call that may or may not have landed is a coin flip with
/// the outside world's money on it, so the group is reported unsettled and the
/// run is quarantined instead.
#[tokio::test]
async fn a_group_in_doubt_is_quarantined_rather_than_reversed() {
    let world = World::new();
    let out = run(&world.fail("card.auth", Failure::InDoubt), json!({})).await;

    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "an in-doubt group was not quarantined: {:?}",
        out.status
    );
    assert!(
        !world.did("released sku-1"),
        "a group reversed a member while another was in doubt: {:?}",
        world.entries()
    );
}

// ── The footprint is enforced ───────────────────────────────────────────────

/// A member outside the declared resources is refused *before* it runs.
///
/// Without this the footprint is a comment, and a frontier over an unknown set
/// of resources is a frontier over nothing.
#[tokio::test]
async fn a_member_outside_the_footprint_is_refused_before_it_runs() {
    let world = World::new();
    let out = run(&world, json!({ "footprint_violation": true })).await;

    let RunStatus::Failed(why) = &out.status else {
        panic!("expected a failure, got {:?}", out.status);
    };
    assert!(
        why.contains("shipping"),
        "the refusal did not say what was outside the footprint: {why}"
    );
    assert!(
        !world.did("booked"),
        "the undeclared member ran before it was refused: {:?}",
        world.entries()
    );
}

/// A mutating effect cannot be smuggled in as a group read.
///
/// A read is exempt from declaring a reversal because it has nothing to take
/// back. An effect that mutates and claims to be a read would take that
/// exemption while leaving something standing.
#[tokio::test]
async fn a_mutating_effect_cannot_be_declared_a_group_read() {
    let world = World::new();
    let out = run(&world, json!({ "mutating_read": true })).await;

    let RunStatus::Failed(why) = &out.status else {
        panic!("expected a failure, got {:?}", out.status);
    };
    assert!(
        why.contains("mutates"),
        "the refusal did not explain itself: {why}"
    );
    assert!(
        !world.did("taken"),
        "the mutating effect ran despite being refused"
    );
}

/// Groups do not nest.
#[tokio::test]
async fn a_second_group_cannot_open_while_one_is_still_open() {
    let world = World::new();
    let out = run(&world, json!({ "nested": true })).await;

    let RunStatus::Failed(why) = &out.status else {
        panic!("expected a failure, got {:?}", out.status);
    };
    assert!(
        why.contains("nest"),
        "nesting was refused for an unrelated reason: {why}"
    );
}

// ── Forgetting to settle is not a commit ────────────────────────────────────

/// A group that is never settled does not take.
///
/// The safe reading of a forgotten group is that it was never meant to happen.
/// Committing by omission would make the most consequential thing a group does
/// the thing that happens when an author writes nothing.
#[tokio::test]
async fn a_group_left_open_is_reversed_rather_than_committed() {
    let world = World::new();
    let out = run(&world, json!({ "ending": "walk away" })).await;

    let RunStatus::Failed(why) = &out.status else {
        panic!(
            "a step that abandoned its group succeeded: {:?}",
            out.status
        );
    };
    assert!(
        why.contains("still open"),
        "the failure did not say the group was abandoned: {why}"
    );
    assert!(
        !world.did("order confirmed"),
        "an abandoned group sent its irreversible member"
    );
    assert!(
        world.did("released sku-1") && world.did("voided"),
        "an abandoned group was left standing: {:?}",
        world.entries()
    );
}

// ── A reversal is an effect like any other ──────────────────────────────────

/// Reversals go through the journal, so they replay.
///
/// Nothing about being an undo makes it privileged: it is keyed, recorded,
/// retried and metered like the forward call. If it were not, a replayed run
/// would perform the reversal *again* against a world that has already taken it.
#[tokio::test]
async fn a_reversal_is_journaled_and_is_not_repeated_on_replay() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let world = World::new();
    world.fail("mail.send", Failure::DidNotHappen);
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Checkout {
            world: Arc::clone(&world),
        })
        .build();

    let out = rt.run("checkout", json!({})).await.expect("run");
    assert!(matches!(out.status, RunStatus::Failed(_)));
    let after_live = world.entries();
    assert!(after_live.contains(&"voided".to_owned()));

    let records = store
        .read(out.run_id, 1)
        .await
        .expect("records")
        .into_iter()
        .filter_map(|r| serde_json::to_value(r.body.kind).ok())
        .collect::<Vec<_>>();
    let kinds: Vec<&str> = records.iter().filter_map(|v| v["kind"].as_str()).collect();
    assert!(
        kinds.contains(&"GroupOpened") && kinds.contains(&"GroupSettled"),
        "the group was not bracketed in the journal: {kinds:?}"
    );
    assert!(
        records
            .iter()
            .any(|v| v["kind"] == "GroupSettled" && v["outcome"] == "aborted"),
        "the journal does not say the group was aborted: {records:?}"
    );

    let replayed = rt
        .replay(out.run_id, agentplane::runtime::Mode::Strict)
        .await
        .expect("replay");
    assert!(matches!(replayed.status, RunStatus::Failed(_)));
    assert_eq!(
        world.entries(),
        after_live,
        "strict replay performed the reversal a second time, so replaying a \
         failed group double-undoes it"
    );
}

/// The abandoned-group guard does not fire on a healthy suspension.
#[tokio::test]
async fn a_group_survives_a_suspension_without_being_reversed() {
    /// Opens a group, lands a member, then waits for something.
    #[derive(Debug)]
    struct Waits {
        world: Arc<World>,
        seen: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Skill for Waits {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("waits").provides("waits")
        }

        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let mut g = cx
                .group("waits", ["inventory"])
                .await
                .map_err(SkillError::Step)?;
            g.reversible(
                "inventory",
                Call::new("stock.hold", "held", &self.world),
                |_| Call::new("stock.release", "released", &self.world),
            )
            .await
            .map_err(SkillError::Step)?;
            self.seen.fetch_add(1, Ordering::SeqCst);
            // The handle goes; the group does not. It lives on the context
            // precisely so a wait can happen inside it.
            let _ = g;
            // A durable wait: the frame is persisted and the task dropped.
            cx.sleep(std::time::Duration::from_hours(1))
                .await
                .map_err(SkillError::Step)?;
            cx.group("waits", ["inventory"])
                .await
                .map_err(SkillError::Step)?
                .commit(&[])
                .await
                .map_err(SkillError::Step)?;
            Ok(Outcome::done(Tainted::trusted(json!("done"))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let world = World::new();
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .timers(Arc::clone(&store) as Arc<dyn agentplane::case::TimerStore>)
        .skill(Waits {
            world: Arc::clone(&world),
            seen: Arc::new(AtomicUsize::new(0)),
        })
        .build();

    let out = rt.run("waits", json!({})).await.expect("run");
    assert!(
        out.status.is_suspended(),
        "expected a suspension, got {:?}",
        out.status
    );
    assert!(
        world.did("held") && !world.did("released"),
        "a suspended run had its group reversed — it is waiting, not failing: {:?}",
        world.entries()
    );
}

/// A reversal that will not come back is a quarantine, not a shrug.
#[tokio::test]
async fn a_failed_reversal_quarantines_rather_than_reporting_success() {
    let world = World::new();
    // The forward payment lands; taking it back is what fails.
    *world.fail.lock().expect("lock") = Some(("card.void".to_owned(), Failure::DidNotHappen));
    let out = run(&world, json!({ "ending": "abort" })).await;

    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "a group that could not be reversed reported {:?}",
        out.status
    );
    assert!(
        !world.did("released sku-1"),
        "the unwind continued past a reversal that failed: {:?}",
        world.entries()
    );
}

// ── How a group behaves beside every other mechanism ────────────────────────

/// A ceiling bounds work; it must not strand it half-done.
///
/// A reversal runs in the step's **forward** phase, so the phase — which is what
/// exempts a compensating effect from the gate — says nothing about it. Without
/// a separate exemption a run that reached its ceiling mid-group could not
/// release the hold it had already placed, which is the outcome the
/// compensation exemption exists to prevent, reached by a different road.
#[tokio::test]
async fn a_group_is_taken_back_even_when_the_budget_is_exhausted() {
    use agentplane::core::Budget;

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let world = World::new();
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        // Exactly the three forward members: the hold, the authorisation, the
        // read. The gated send is refused for want of allowance, and the two
        // reversals that follow have none left.
        .budget(Budget::unlimited().effects(3))
        .skill(Checkout {
            world: Arc::clone(&world),
        })
        .build();

    let out = rt.run("checkout", json!({})).await.expect("run");
    assert!(
        !matches!(out.status, RunStatus::Quarantined(_)),
        "the unwind was refused for want of budget: {:?}",
        out.status
    );
    assert!(
        world.did("released sku-1") && world.did("voided"),
        "a run that hit its ceiling could not undo the work it had already \
         done — a charged card and no order: {:?}",
        world.entries()
    );
    assert!(
        !world.did("order confirmed"),
        "the gated member ran despite the group not committing"
    );
}

/// Asking to replan is not settling the group.
///
/// `Outcome::Replan` is an `Ok`, so a group left open behind it would otherwise
/// slip past on the success path — the run would be re-planned with a hold and
/// an authorisation standing that nothing later knows about.
#[tokio::test]
async fn a_group_left_open_behind_a_replan_is_still_reversed() {
    #[derive(Debug)]
    struct Replans {
        world: Arc<World>,
    }

    #[async_trait::async_trait]
    impl Skill for Replans {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("replans").provides("replans")
        }

        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let mut g = cx
                .group("replans", ["inventory"])
                .await
                .map_err(SkillError::Step)?;
            g.reversible(
                "inventory",
                Call::new("stock.hold", "held", &self.world),
                |_| Call::new("stock.release", "released", &self.world),
            )
            .await
            .map_err(SkillError::Step)?;
            Ok(Outcome::Replan {
                reason: "the plan was wrong".to_owned(),
            })
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let world = World::new();
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Replans {
            world: Arc::clone(&world),
        })
        .build();

    let out = rt.run("replans", json!({})).await.expect("run");
    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "a replan carried an unsettled group through: {:?}",
        out.status
    );
    assert!(
        world.did("released"),
        "the group survived a replan with a member standing: {:?}",
        world.entries()
    );
}

/// A probe resolves a member's outcome, and the group acts on the answer.
///
/// The two verdicts lead opposite ways and neither is a guess: a probe that
/// finds the call **landed** means it must be reversed on abort, and one that
/// finds it **did not happen** means reversing it would undo nothing while
/// looking like diligence.
#[tokio::test]
async fn a_probe_decides_whether_a_group_member_needs_reversing() {
    /// Fails without saying what it did, then answers the probe.
    #[derive(Debug)]
    struct Ambiguous {
        landed: bool,
        world: Arc<World>,
    }

    #[async_trait::async_trait]
    impl Effect for Ambiguous {
        type Output = Value;

        fn descriptor(&self) -> EffectDescriptor {
            EffectDescriptor::new("card.auth", json!({ "probe": self.landed }))
        }

        fn retry(&self) -> RetryPolicy {
            RetryPolicy::never()
        }

        fn recovery(&self) -> agentplane::core::Recovery {
            agentplane::core::Recovery::Reconcile
        }

        async fn perform(&self) -> Result<Value, EffectError> {
            Err(EffectError::Other("the connection dropped".into()))
        }

        async fn reconcile(&self) -> Result<agentplane::core::Reconciliation<Value>, EffectError> {
            Ok(if self.landed {
                self.world
                    .log
                    .lock()
                    .expect("lock")
                    .push("authorised".to_owned());
                agentplane::core::Reconciliation::Landed(json!({ "auth": "a-1" }))
            } else {
                agentplane::core::Reconciliation::DidNotHappen
            })
        }
    }

    #[derive(Debug)]
    struct Probes {
        world: Arc<World>,
        landed: bool,
    }

    #[async_trait::async_trait]
    impl Skill for Probes {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("probes").provides("probes")
        }

        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let mut g = cx
                .group("probes", ["payments"])
                .await
                .map_err(SkillError::Step)?;
            let auth = g
                .reversible(
                    "payments",
                    Ambiguous {
                        landed: self.landed,
                        world: Arc::clone(&self.world),
                    },
                    |_| Call::new("card.void", "voided", &self.world),
                )
                .await;
            match auth {
                // The probe recovered it: it landed, so it is a member like any
                // other and the abort must reverse it.
                Ok(_) => {
                    g.abort("changed our mind")
                        .await
                        .map_err(SkillError::Step)?;
                    Ok(Outcome::done(Tainted::trusted(json!("aborted"))))
                }
                // The probe established it never happened, so there is nothing
                // registered to reverse.
                Err(e) => Err(SkillError::Step(e)),
            }
        }
    }

    for landed in [true, false] {
        let store = Arc::new(RedbStore::open_in_memory().expect("store"));
        let world = World::new();
        let rt = Runtime::builder(store as Arc<dyn JournalStore>)
            .skill(Probes {
                world: Arc::clone(&world),
                landed,
            })
            .build();
        rt.run("probes", json!({})).await.expect("run");

        assert_eq!(
            world.did("voided"),
            landed,
            "a probe that reported landed={landed} led to the wrong unwind: {:?}",
            world.entries()
        );
    }
}

/// A group inside a step that is later compensated.
///
/// Two undo mechanisms at different granularities, and they must not tread on
/// each other: the group commits inside the forward phase, and the *step's*
/// compensation later runs in its own phase with its own cursor.
#[tokio::test]
async fn a_committed_group_is_still_undone_by_the_step_s_own_compensation() {
    use agentplane::core::{ArgSource, Compensation, PlanIR, PlanNode, StepId};

    #[derive(Debug)]
    struct Books {
        world: Arc<World>,
    }

    #[async_trait::async_trait]
    impl Skill for Books {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("books").provides("books")
        }

        fn compensation(&self) -> Compensation {
            Compensation::Compensatable
        }

        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let mut g = cx
                .group("books", ["inventory"])
                .await
                .map_err(SkillError::Step)?;
            g.reversible(
                "inventory",
                Call::new("stock.hold", "held", &self.world),
                |_| Call::new("stock.release", "released by group", &self.world),
            )
            .await
            .map_err(SkillError::Step)?;
            g.commit(&[]).await.map_err(SkillError::Step)?;
            Ok(Outcome::done(Tainted::trusted(json!("booked"))))
        }

        async fn compensate(
            &self,
            cx: &mut StepCtx<'_>,
            _output: &Tainted<Value>,
        ) -> Result<(), SkillError> {
            cx.effect(Call::new(
                "stock.release",
                "released by the step",
                &self.world,
            ))
            .await
            .map_err(SkillError::Step)?;
            Ok(())
        }
    }

    #[derive(Debug)]
    struct Fails;

    #[async_trait::async_trait]
    impl Skill for Fails {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("fails").provides("fails")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Err(SkillError::Other("downstream refused".to_owned()))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let world = World::new();
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Books {
            world: Arc::clone(&world),
        })
        .skill(Fails)
        .build();

    let plan = PlanIR::new(vec![
        PlanNode::new(0, "books").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "fails")
            .arg("x", ArgSource::node(StepId(0)))
            .terminal(),
    ]);
    let out = rt.run_plan(plan, json!({})).await.expect("run");

    assert!(matches!(out.status, RunStatus::Failed(_)));
    assert_eq!(
        world.entries(),
        vec!["held", "released by the step"],
        "the group's own reversal fired for a group that committed, or the \
         step's compensation did not"
    );
}

/// Sibling steps each running their own group do not share one.
///
/// The open group lives on the step context, so two steps executing at once
/// have one each. A group on the *run* would let one step's abort reverse
/// another step's members.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_steps_each_get_their_own_group() {
    use agentplane::core::{ArgSource, PlanIR, PlanNode, StepId};

    #[derive(Debug)]
    struct Holds {
        world: Arc<World>,
        capability: &'static str,
        fails: bool,
    }

    #[async_trait::async_trait]
    impl Skill for Holds {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new(self.capability).provides(self.capability)
        }

        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let mut g = cx
                .group(self.capability, ["inventory"])
                .await
                .map_err(SkillError::Step)?;
            let tag = self.capability;
            g.reversible(
                "inventory",
                Call::new("stock.hold", format!("held by {tag}"), &self.world),
                move |_| Call::new("stock.release", format!("released by {tag}"), &self.world),
            )
            .await
            .map_err(SkillError::Step)?;
            if self.fails {
                return Err(SkillError::Other(format!("{tag} refused")));
            }
            g.commit(&[]).await.map_err(SkillError::Step)?;
            Ok(Outcome::done(Tainted::trusted(json!(tag))))
        }
    }

    #[derive(Debug)]
    struct Joins;

    #[async_trait::async_trait]
    impl Skill for Joins {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("join").provides("join")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Ok(Outcome::done(Tainted::trusted(json!("joined"))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let world = World::new();
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Holds {
            world: Arc::clone(&world),
            capability: "left",
            fails: false,
        })
        .skill(Holds {
            world: Arc::clone(&world),
            capability: "right",
            fails: true,
        })
        .skill(Joins)
        .build();

    let plan = PlanIR::new(vec![
        PlanNode::new(0, "left").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "right").arg("input", ArgSource::run_input()),
        PlanNode::new(2, "join")
            .arg("l", ArgSource::node(StepId(0)))
            .arg("r", ArgSource::node(StepId(1)))
            .terminal(),
    ]);
    rt.run_plan(plan, json!({})).await.expect("run");

    let log = world.entries();
    assert!(
        log.contains(&"released by right".to_owned()),
        "the failing sibling did not reverse its own member: {log:?}"
    );
    assert!(
        !log.contains(&"released by left".to_owned()),
        "one step's abort reversed a sibling's member — the group is not \
         scoped to the step: {log:?}"
    );
}

/// A group may span a durable wait for an inbound event, not only a sleep.
#[tokio::test]
async fn a_group_survives_waiting_for_an_event() {
    use agentplane::case::{CaseStore, EventStore};
    use agentplane::core::{AwaitSpec, CorrelationKey, DeadlineSpec};

    #[derive(Debug)]
    struct AwaitsReply {
        world: Arc<World>,
    }

    #[async_trait::async_trait]
    impl Skill for AwaitsReply {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("awaits").provides("awaits")
        }

        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let mut g = cx
                .group("awaits", ["inventory"])
                .await
                .map_err(SkillError::Step)?;
            g.reversible(
                "inventory",
                Call::new("stock.hold", "held", &self.world),
                |_| Call::new("stock.release", "released", &self.world),
            )
            .await
            .map_err(SkillError::Step)?;
            let _ = g;
            cx.deadline("reply-by", &DeadlineSpec::days(1), None)
                .await
                .map_err(SkillError::Step)?;
            cx.await_event(&AwaitSpec::new("carrier.reply", "reply-by"))
                .await
                .map_err(SkillError::Step)?;
            unreachable!("the wait never resolves in this test")
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let world = World::new();
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .events(Arc::clone(&store) as Arc<dyn EventStore>)
        .skill(AwaitsReply {
            world: Arc::clone(&world),
        })
        .build();

    let out = rt
        .run_in_case(
            "awaits",
            json!({}),
            "shipment",
            &[CorrelationKey::new("shipment", "S-1")],
        )
        .await
        .expect("run");
    assert!(
        out.status.is_suspended(),
        "expected a suspension, got {:?}",
        out.status
    );
    assert!(
        world.did("held") && !world.did("released"),
        "a run waiting for a reply had its group reversed — it is waiting, not \
         failing: {:?}",
        world.entries()
    );
}
