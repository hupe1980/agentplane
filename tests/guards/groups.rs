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
    /// The call took effect, but its response could not be used. It *did* reach
    /// the world, which is the strongest possible reason an abort may not claim
    /// to have taken the group back whole.
    Landed,
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
                Failure::Landed => EffectError::Performed(format!("{kind} took effect")),
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

    #[allow(clippy::too_many_lines)]
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

        if script["ambient_mutation"].as_bool() == Some(true) {
            // The handle goes out of use; the group does not. This is the
            // shape the hole had: a skill that stops using the handle and
            // reaches the world through the ordinary effect path.
            let _ = g;
            let err = cx
                .effect(Call::new("ledger.post", "posted", w))
                .await
                .expect_err("a mutating effect beside an open group was admitted");
            return Err(SkillError::Step(err));
        }

        if script["ambient_read"].as_bool() == Some(true) {
            let _ = g;
            // A read changes nothing there is to take back, so it stays legal.
            cx.effect(Look {
                world: Arc::clone(w),
            })
            .await
            .map_err(SkillError::Step)?;
            w.log.lock().expect("lock").push("looked".to_owned());
            return Ok(Outcome::done(Tainted::trusted(json!("looked"))));
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
            // A reported failure, with the group deliberately left to the
            // runtime. This is the ordinary path, not an author bug.
            "outcome fail" => Ok(Outcome::fail("the warehouse said no")),
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
    rt.run("checkout", Tainted::trusted(script))
        .await
        .expect("run")
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
        out.output.as_ref().expect("output").peek()["deferred"],
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

/// A deferred member that fails **Landed** is quarantined, never cheap-aborted.
///
/// `mail.send` is the deferred, irreversible send, and it is the only deferred
/// member — so when it fails, no prior deferred landed and no atomic member
/// committed. The abort path's completeness check must still refuse, because the
/// member's own disposition says it *did* reach the world: settling `Aborted`
/// and reversing the hold and the authorisation would take back everything
/// except the mail that actually went out. Excluding only `InDoubt` here let a
/// provider answering 200-with-an-unusable-body take the cheap abort over a send
/// that stands — the group rule that an abort is available only while nothing
/// has externalised, violated for the member with the strongest evidence it did.
#[tokio::test]
async fn a_deferred_member_that_landed_is_quarantined_not_cheap_aborted() {
    let world = World::new();
    let out = run(&world.fail("mail.send", Failure::Landed), json!({})).await;

    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "a deferred member that landed took the cheap abort instead of quarantining: {:?}",
        out.status
    );
    // Nothing may be reversed: the charge stands beside the send, and an
    // `Aborted` claiming otherwise would be a lie about both.
    assert!(
        !world.did("released sku-1") && !world.did("voided"),
        "the group reversed members around a send that landed: {:?}",
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

    let out = rt
        .run("checkout", Tainted::trusted(json!({})))
        .await
        .expect("run");
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
            cx.sleep(std::time::Duration::from_secs(3600))
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

    let out = rt
        .run("waits", Tainted::trusted(json!({})))
        .await
        .expect("run");
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

    let out = rt
        .run("checkout", Tainted::trusted(json!({})))
        .await
        .expect("run");
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

    let out = rt
        .run("replans", Tainted::trusted(json!({})))
        .await
        .expect("run");
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
        rt.run("probes", Tainted::trusted(json!({})))
            .await
            .expect("run");

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
    let out = rt
        .run_plan(plan, Tainted::trusted(json!({})))
        .await
        .expect("run");

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
    rt.run_plan(plan, Tainted::trusted(json!({})))
        .await
        .expect("run");

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
        .run_correlated(
            "awaits",
            Tainted::trusted(json!({})),
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

/// A step that *reports* a failure keeps its own reason.
///
/// `Outcome::Fail` is an `Ok` at the type level and a failure in fact. Treating
/// it as the forgot-to-settle bug replaces the author's reason with a message
/// about groups — so the operator reading the run is told the step "returned
/// successfully" and never sees why it actually stopped.
#[tokio::test]
async fn a_step_that_reports_failure_keeps_its_own_reason() {
    let world = World::new();
    let out = run(&world, json!({ "ending": "outcome fail" })).await;

    let RunStatus::Failed(why) = &out.status else {
        panic!("expected a failure, got {:?}", out.status);
    };
    assert!(
        why.contains("the warehouse said no"),
        "the step's own reason was replaced by a message about groups: {why}"
    );
    assert!(
        !why.contains("returned successfully"),
        "a step that reported a failure was described as succeeding: {why}"
    );
    assert!(
        world.did("released sku-1") && world.did("voided"),
        "the group was left standing: {:?}",
        world.entries()
    );
}

/// The gate exemption ends with the reversal that needed it.
///
/// Undo is exempt from the manifest check, policy and the budget, because a
/// ceiling exists to bound work rather than to strand it half-done. That
/// exemption is a hole for exactly as long as it is open, and nothing about a
/// step that *had* a group makes its later calls privileged. A reversal that
/// returned with the flag still set would leave every effect after it ungated —
/// reached by adding an ordinary `?` to a loop, and invisible without this test.
#[tokio::test]
async fn the_gate_exemption_ends_with_the_reversal() {
    use agentplane::core::Budget;

    #[derive(Debug)]
    struct AbortsThenActs {
        world: Arc<World>,
    }

    #[async_trait::async_trait]
    impl Skill for AbortsThenActs {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("aborts").provides("aborts")
        }

        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let mut g = cx
                .group("aborts", ["inventory"])
                .await
                .map_err(SkillError::Step)?;
            g.reversible(
                "inventory",
                Call::new("stock.hold", "held", &self.world),
                |_| Call::new("stock.release", "released", &self.world),
            )
            .await
            .map_err(SkillError::Step)?;
            g.abort("changed our mind")
                .await
                .map_err(SkillError::Step)?;

            // Past the group. This must be gated like any other call.
            cx.effect(Call::new("stock.hold", "held again", &self.world))
                .await
                .map_err(SkillError::Step)?;
            Ok(Outcome::done(Tainted::trusted(json!("done"))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let world = World::new();
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        // Exactly one admitted effect: the forward member. The reversal is
        // exempt and consumes none, so the call *after* the group has no
        // allowance left — unless the exemption leaked.
        .budget(Budget::unlimited().effects(1))
        .skill(AbortsThenActs {
            world: Arc::clone(&world),
        })
        .build();

    let out = rt
        .run("aborts", Tainted::trusted(json!({})))
        .await
        .expect("run");

    assert!(
        world.did("released"),
        "the reversal itself was refused, so the exemption is not working at all: {:?}",
        world.entries()
    );
    assert!(
        !world.did("held again"),
        "an effect after the group ran without an allowance — the reversal left \
         the gate open, and every later call skipped the manifest check, policy \
         and the budget: {:?}",
        world.entries()
    );
    assert!(
        matches!(out.status, RunStatus::Exhausted(_)),
        "expected the ceiling to refuse the call after the group, got {:?}",
        out.status
    );
}

/// A member that binds outbound arguments is refused when it is registered.
///
/// `cx.effect` refuses any effect exposing `sink_arguments`, because the
/// information-flow check cannot be skipped. A group has no labelled value to
/// bind on a member's behalf, so such a member cannot be a reversal or a
/// deferred call — and the place to say so is **registration**, which is free.
/// Left to dispatch, the reversal one fires during an abort: the run is already
/// failing, and the diagnostic arrives about the undo rather than about the
/// member that was wrong.
#[tokio::test]
async fn a_member_that_binds_outbound_arguments_is_refused_at_registration() {
    /// Exposes outbound arguments, so it must go through `cx.sink`.
    #[derive(Debug)]
    struct Bound {
        args: Value,
        world: Arc<World>,
    }

    #[async_trait::async_trait]
    impl Effect for Bound {
        type Output = Value;
        fn descriptor(&self) -> EffectDescriptor {
            EffectDescriptor::new("ledger.post", self.args.clone())
        }
        fn sink_arguments(&self) -> Option<&Value> {
            Some(&self.args)
        }
        async fn perform(&self) -> Result<Value, EffectError> {
            self.world.record("ledger.post", "posted")
        }
    }

    #[derive(Debug)]
    struct Registers {
        world: Arc<World>,
        /// Which registration is under test.
        deferred: bool,
    }

    #[async_trait::async_trait]
    impl Skill for Registers {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("registers").provides("registers")
        }

        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let w = &self.world;
            let bound = || Bound {
                args: json!({ "amount": 1 }),
                world: Arc::clone(w),
            };
            let mut g = cx
                .group("registers", ["inventory"])
                .await
                .map_err(SkillError::Step)?;

            let err = if self.deferred {
                g.deferred("inventory", bound())
                    .expect_err("a sink-bound member was accepted as deferred")
            } else {
                g.reversible("inventory", Call::new("stock.hold", "held", w), |_| bound())
                    .await
                    .expect_err("a sink-bound reversal was accepted")
            };
            Err(SkillError::Step(err))
        }
    }

    for deferred in [true, false] {
        let store = Arc::new(RedbStore::open_in_memory().expect("store"));
        let world = World::new();
        let rt = Runtime::builder(store as Arc<dyn JournalStore>)
            .skill(Registers {
                world: Arc::clone(&world),
                deferred,
            })
            .build();

        let out = rt
            .run("registers", Tainted::trusted(json!({})))
            .await
            .expect("run");
        // Deferred: nothing has run, so it is an ordinary refusal and the group
        // can still be taken back whole. Reversible: the forward member has
        // already landed and there is no usable way to undo it, which is a
        // quarantine — settling that as `Aborted` would say discharged while
        // the hold still stands.
        let why = match &out.status {
            RunStatus::Failed(why) if deferred => why,
            RunStatus::Quarantined(why) if !deferred => why,
            other => panic!("expected a refusal (deferred={deferred}), got {other:?}"),
        };
        assert!(
            why.contains("ledger.post"),
            "the refusal did not name the member that binds arguments \
             (deferred={deferred}): {why}"
        );
        assert!(
            !world.did("posted"),
            "the sink-bound member ran (deferred={deferred}): {:?}",
            world.entries()
        );
    }
}

/// Once an irreversible member is out, the group is never taken back.
///
/// The distinction the deferred phase turns on. If the *first* gated member
/// fails, nothing has externalised and the group can still be taken back whole.
/// If a *later* one fails, reversing would undo everything except the thing
/// that actually happened — which is the worst of the three answers available
/// and the one that looks tidiest in a log. So the group is reported unsettled
/// and the run quarantined instead.
#[tokio::test]
async fn a_gated_member_that_fails_after_another_landed_does_not_unwind() {
    #[derive(Debug)]
    struct TwoSends {
        world: Arc<World>,
    }

    #[async_trait::async_trait]
    impl Skill for TwoSends {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("two-sends").provides("two.sends")
        }

        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let w = &self.world;
            let mut g = cx
                .group("two-sends", ["inventory", "notify"])
                .await
                .map_err(SkillError::Step)?;
            g.reversible("inventory", Call::new("stock.hold", "held", w), |_| {
                Call::new("stock.release", "released", w)
            })
            .await
            .map_err(SkillError::Step)?;
            // Two gated members. The first lands; the second refuses.
            g.deferred("notify", Call::new("mail.send", "emailed", w))
                .map_err(SkillError::Step)?;
            g.deferred("notify", Call::new("sms.send", "texted", w))
                .map_err(SkillError::Step)?;
            g.commit(&[]).await.map_err(SkillError::Step)?;
            Ok(Outcome::done(Tainted::trusted(json!("sent"))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let world = World::new();
    world.fail("sms.send", Failure::DidNotHappen);
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(TwoSends {
            world: Arc::clone(&world),
        })
        .build();

    let out = rt
        .run("two.sends", Tainted::trusted(json!({})))
        .await
        .expect("run");

    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "a group with an irreversible member already out reported {:?}",
        out.status
    );
    assert!(
        world.did("emailed"),
        "the first gated member did not run, so this test proves nothing about \
         what happens after one has: {:?}",
        world.entries()
    );
    assert!(
        !world.did("released"),
        "the group unwound after an irreversible member had already gone out — \
         undoing everything except the thing that actually happened: {:?}",
        world.entries()
    );
}

/// A group that spans a suspension is bracketed once, not once per attempt.
///
/// `GroupOpened` is written by an ordinary annotation append, which is a no-op
/// while replay consumes history and live once it runs out. A group opened
/// right at the boundary would therefore be announced twice, and "an opened
/// group with no settlement beside it" — the query an operator runs to find
/// work that was neither taken nor taken back — would count one unit as two.
#[tokio::test]
async fn a_group_spanning_a_suspension_is_announced_once() {
    use agentplane::case::TimerStore;

    #[derive(Debug)]
    struct Waits {
        world: Arc<World>,
    }

    #[async_trait::async_trait]
    impl Skill for Waits {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("waits2").provides("waits2")
        }

        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let mut g = cx
                .group("waits2", ["inventory"])
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
            cx.sleep(std::time::Duration::from_secs(3600))
                .await
                .map_err(SkillError::Step)?;
            unreachable!("never resumes in this test")
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let world = World::new();
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .timers(Arc::clone(&store) as Arc<dyn TimerStore>)
        .skill(Waits {
            world: Arc::clone(&world),
        })
        .build();

    let out = rt
        .run("waits2", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert!(out.status.is_suspended());

    // Resume: the step re-runs from the top, replaying the member.
    let _ = rt
        .replay(out.run_id, agentplane::runtime::Mode::Resume)
        .await;

    let opened = store
        .read(out.run_id, 1)
        .await
        .expect("records")
        .into_iter()
        .filter(|r| {
            matches!(
                r.kind(),
                agentplane::journal::RecordKind::GroupOpened { .. }
            )
        })
        .count();
    assert_eq!(
        opened, 1,
        "the group was announced {opened} times across one suspension, so an \
         operator counting unsettled groups counts one unit as several"
    );
}

// ── Committing with the journal, rather than beside it ──────────────────────
//
// Gated on `testkit`: the fixture that lends a transaction lives there, because
// a store which *models* atomicity has no business in a shipped binary. The
// real property is checked against Postgres in `postgres.rs`.

/// A member that writes to a table in the journal's own database.
#[cfg(feature = "testkit")]
#[derive(Debug)]
struct Posts {
    account: String,
    amount: i64,
    refuses: bool,
    world: Arc<World>,
}

#[cfg(feature = "testkit")]
#[async_trait::async_trait]
impl agentplane::journal::AtomicResource for Posts {
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "ledger.post",
            json!({ "account": self.account, "amount": self.amount }),
        )
    }

    async fn apply(&self, tx: &dyn agentplane::journal::AtomicTx) -> Result<Value, EffectError> {
        if self.refuses {
            return Err(EffectError::Rejected("the account is closed".into()));
        }
        tx.execute(
            "UPDATE ledger SET balance = balance + $2 WHERE account = $1",
            &[
                agentplane::journal::SqlValue::from(self.account.as_str()),
                agentplane::journal::SqlValue::from(self.amount),
            ],
        )
        .await
        .map_err(|e| EffectError::Other(e.to_string()))?;
        self.world
            .log
            .lock()
            .expect("lock")
            .push("posted".to_owned());
        Ok(json!({ "posted": self.amount }))
    }
}

#[cfg(feature = "testkit")]
/// Drives a group with one atomic member and one reversible one.
#[derive(Debug)]
struct Books {
    world: Arc<World>,
    refuses: bool,
}

#[cfg(feature = "testkit")]
#[async_trait::async_trait]
impl Skill for Books {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("books").provides("books")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let w = &self.world;
        let mut g = cx
            .group("books", ["inventory", "ledger"])
            .await
            .map_err(SkillError::Step)?;

        // Eager and external: this is the class that needs taking back.
        g.reversible("inventory", Call::new("stock.hold", "held", w), |_| {
            Call::new("stock.release", "released", w)
        })
        .await
        .map_err(SkillError::Step)?;

        g.atomic(
            "ledger",
            Arc::new(Posts {
                account: "AC-1".to_owned(),
                amount: 129,
                refuses: self.refuses,
                world: Arc::clone(w),
            }),
        )
        .map_err(SkillError::Step)?;

        g.commit(&[]).await.map_err(SkillError::Step)?;
        Ok(Outcome::done(Tainted::trusted(json!("booked"))))
    }
}

#[cfg(feature = "testkit")]
fn staged() -> (
    Arc<agentplane::testkit::StagedAtomic>,
    Arc<agentplane::store::RedbStore>,
) {
    let redb = Arc::new(RedbStore::open_in_memory().expect("store"));
    let staged =
        agentplane::testkit::StagedAtomic::wrap(Arc::clone(&redb) as Arc<dyn JournalStore>);
    (staged, redb)
}

/// An atomic member runs at the frontier, with the record that it happened.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn an_atomic_member_commits_with_the_journal() {
    let (store, _redb) = staged();
    let world = World::new();
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Books {
            world: Arc::clone(&world),
            refuses: false,
        })
        .build();

    let out = rt
        .run("books", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(
        world.entries(),
        vec!["held", "posted"],
        "the atomic member ran before the frontier, or not at all"
    );
    assert_eq!(
        store.applied().len(),
        1,
        "the resource's statement was not applied: {:?}",
        store.applied()
    );

    // The settlement is written once, after everything — a group is not
    // finished when its transaction is, because deferred members run after it.
    let records: Vec<String> = store
        .read(out.run_id, 1)
        .await
        .expect("records")
        .iter()
        .map(|r| r.kind().kind_str().to_owned())
        .collect();
    assert!(
        records.contains(&"GroupSettled".to_owned()),
        "the group did not settle: {records:?}"
    );
    assert_eq!(
        records.iter().filter(|k| *k == "GroupSettled").count(),
        1,
        "the group settled twice — once inside the transaction and once beside \
         it: {records:?}"
    );
}

/// A member that refuses takes the whole unit with it, and the group is taken
/// back whole.
///
/// This is the class's reason for existing: nothing was externalised, so the
/// failure path is the *cheap* one — an abort — rather than a quarantine.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_refused_atomic_member_leaves_nothing_behind() {
    let (store, _redb) = staged();
    let world = World::new();
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Books {
            world: Arc::clone(&world),
            refuses: true,
        })
        .build();

    let out = rt
        .run("books", Tainted::trusted(json!({})))
        .await
        .expect("run");

    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "a refused atomic member quarantined rather than aborting — nothing was \
         externalised, so this should be the cheap path: {:?}",
        out.status
    );
    assert!(
        store.applied().is_empty(),
        "statements survived a unit of work that refused: {:?}",
        store.applied()
    );
    assert!(
        world.did("released"),
        "the eager member was not taken back: {:?}",
        world.entries()
    );
    let settled: Vec<String> = store
        .read(out.run_id, 1)
        .await
        .expect("records")
        .iter()
        .filter_map(|r| match r.kind() {
            agentplane::journal::RecordKind::GroupSettled { outcome, .. } => {
                Some(outcome.as_str().to_owned())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        settled,
        vec!["aborted".to_owned()],
        "the journal did not record the group as taken back"
    );
}

/// A lost commit acknowledgement quarantines the group — the cheap abort is gone.
///
/// The fixture commits everything — statements applied, records appended — and
/// then reports the outcome unknown, which is exactly what a connection dropped
/// between `COMMIT` and its acknowledgement tells a database client. This is
/// the world in which aborting is wrong twice over: the eager members would be
/// reversed around a write that stands, and the journal would settle on *taken
/// back whole* about work nobody took back. Doubt reverses nothing.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_lost_commit_acknowledgement_quarantines_the_group() {
    let (store, _redb) = staged();
    store.lose_commit_acknowledgement();
    let world = World::new();
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Books {
            world: Arc::clone(&world),
            refuses: false,
        })
        .build();

    let out = rt
        .run("books", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "a commit whose acknowledgement was lost took the cheap abort — the \
         journal now claims 'taken back whole' over a write that stands: {:?}",
        out.status
    );
    assert!(
        !world.did("released"),
        "doubt reversed something: the eager member was taken back around a \
         transaction that may be standing: {:?}",
        world.entries()
    );
    let settled: Vec<String> = store
        .read(out.run_id, 1)
        .await
        .expect("records")
        .iter()
        .filter_map(|r| match r.kind() {
            agentplane::journal::RecordKind::GroupSettled { outcome, .. } => {
                Some(outcome.as_str().to_owned())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        settled,
        vec!["quarantined".to_owned()],
        "the journal did not record the group as quarantined"
    );
}

/// A replayed run does not apply the statements a second time.
///
/// Atomicity exempts nothing from the effect protocol: a transaction re-run on
/// replay is a second real write, and the fact that it is transactional makes
/// it a *reliable* second write rather than an acceptable one.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_replayed_atomic_member_is_not_applied_again() {
    let (store, _redb) = staged();
    let world = World::new();
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Books {
            world: Arc::clone(&world),
            refuses: false,
        })
        .build();

    let out = rt
        .run("books", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert_eq!(out.status, RunStatus::Succeeded);
    let after_live = store.applied().len();
    assert_eq!(after_live, 1);

    let replayed = rt
        .replay(out.run_id, agentplane::runtime::Mode::Strict)
        .await
        .expect("replay");
    assert_eq!(replayed.status, RunStatus::Succeeded);
    assert_eq!(
        store.applied().len(),
        after_live,
        "strict replay applied the resource's statement again, so replaying a \
         committed group posts to the ledger twice"
    );
    assert_eq!(
        world.entries(),
        vec!["held", "posted"],
        "replay performed a member again: {:?}",
        world.entries()
    );
}

/// A store that cannot lend a transaction refuses the member at registration.
///
/// The capability is absent, not broken. Discovering it at the frontier would
/// mean every eager member had already run.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn an_atomic_member_is_refused_by_a_store_that_cannot_enlist() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let world = World::new();
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Books {
            world: Arc::clone(&world),
            refuses: false,
        })
        .build();

    let out = rt
        .run("books", Tainted::trusted(json!({})))
        .await
        .expect("run");
    let RunStatus::Failed(why) = &out.status else {
        panic!("expected a refusal, got {:?}", out.status);
    };
    assert!(
        why.contains("no transaction"),
        "the refusal did not explain that the capability is absent: {why}"
    );
    assert!(
        world.did("released"),
        "the eager member that had already landed was not taken back: {:?}",
        world.entries()
    );
}

/// An atomic member is gated like every other mutating effect.
///
/// It is a write to a real database, chosen by skill code and — in the
/// tool-calling tier — shaped by a model. Being wrapped in a transaction makes
/// it *reliable*, not *authorised*. A member that skipped the gate would be the
/// one mutating path in the runtime that policy, the manifest and the budget all
/// miss, and it would be the most consequential one: it commits.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn an_atomic_member_is_authorized_before_it_commits() {
    use agentplane::core::{PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest};

    #[derive(Debug)]
    struct RefusesTheLedger;

    impl PolicyEngine for RefusesTheLedger {
        fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
            if r.resource == "ledger.post" {
                PolicyDecision::deny("this agent may not post to the ledger".to_owned())
            } else {
                PolicyDecision::Permit
            }
        }
        fn bundle(&self) -> PolicyBundleIdentity {
            PolicyBundleIdentity::new(
                agentplane::core::Digest::of(b"refuses-the-ledger"),
                "agentplane-test/policy-v1",
            )
        }
    }

    let (store, _redb) = staged();
    let world = World::new();
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .policy(Arc::new(RefusesTheLedger))
        .skill(Books {
            world: Arc::clone(&world),
            refuses: false,
        })
        .build();

    let out = rt
        .run("books", Tainted::trusted(json!({})))
        .await
        .expect("run");

    let RunStatus::Failed(why) = &out.status else {
        panic!(
            "a denied atomic member committed anyway — policy has no say over \
             the one mutating path that commits: {:?}",
            out.status
        );
    };
    assert!(
        why.contains("may not post to the ledger"),
        "refused for an unrelated reason: {why}"
    );
    assert!(
        store.applied().is_empty(),
        "the denied member's statement was applied: {:?}",
        store.applied()
    );
    assert!(
        world.did("released"),
        "the eager member was not taken back after the denial: {:?}",
        world.entries()
    );
}

/// A deferred member that fails after the atomic members committed cannot be
/// reported as taken back whole.
///
/// The abort path's premise — "nothing has externalised, so the group can
/// still be taken back whole" — stops being true the moment the journal's
/// transaction commits: an atomic member's write is permanent, has no
/// registered reversal, and *cannot* have one. Settling `Aborted` there makes
/// the journal say "nothing is standing" while a ledger row stands, which is
/// precisely the shape a quarantine exists to name.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_deferred_failure_after_an_atomic_commit_is_not_an_abort() {
    #[derive(Debug)]
    struct PostThenSend {
        world: Arc<World>,
    }

    #[async_trait::async_trait]
    impl Skill for PostThenSend {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("post-then-send").provides("post.then.send")
        }

        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let w = &self.world;
            let mut g = cx
                .group("post-then-send", ["inventory", "ledger", "notify"])
                .await
                .map_err(SkillError::Step)?;
            g.reversible("inventory", Call::new("stock.hold", "held", w), |_| {
                Call::new("stock.release", "released", w)
            })
            .await
            .map_err(SkillError::Step)?;
            g.atomic(
                "ledger",
                Arc::new(Posts {
                    account: "AC-1".to_owned(),
                    amount: 129,
                    refuses: false,
                    world: Arc::clone(w),
                }),
            )
            .map_err(SkillError::Step)?;
            // The first deferred member refuses cleanly. Before the atomic
            // class existed, that genuinely meant nothing had externalised.
            g.deferred("notify", Call::new("mail.send", "emailed", w))
                .map_err(SkillError::Step)?;
            g.commit(&[]).await.map_err(SkillError::Step)?;
            Ok(Outcome::done(Tainted::trusted(json!("sent"))))
        }
    }

    let (store, _redb) = staged();
    let world = World::new();
    world.fail("mail.send", Failure::DidNotHappen);
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(PostThenSend {
            world: Arc::clone(&world),
        })
        .build();

    let out = rt
        .run("post.then.send", Tainted::trusted(json!({})))
        .await
        .expect("run");

    // The ledger row committed with the journal and cannot be taken back.
    assert_eq!(
        store.applied().len(),
        1,
        "the premise of this test is that the atomic member committed: {:?}",
        store.applied()
    );
    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "a group whose atomic members had already committed reported {:?} — \
         the journal says taken back whole while the ledger row stands",
        out.status
    );
    let settled: Vec<String> = store
        .read(out.run_id, 1)
        .await
        .expect("records")
        .iter()
        .filter_map(|r| match r.kind() {
            agentplane::journal::RecordKind::GroupSettled { outcome, .. } => {
                Some(outcome.as_str().to_owned())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        settled,
        vec!["quarantined".to_owned()],
        "the settlement claims an outcome the ledger contradicts"
    );
}

/// A mutating effect performed *beside* an open group is refused.
///
/// The footprint governs members. It never governed the ambient surface, so a
/// skill holding an open group could reach the world through the ordinary
/// effect path: journaled, gated and metered like anything else, but no
/// member — registering no reversal and surviving the unwind. The group would
/// then settle `Aborted`, which claims the world was taken back whole, over a
/// write that was still standing.
#[tokio::test]
async fn a_mutating_effect_beside_an_open_group_is_refused() {
    let world = World::new();
    let out = run(&world, json!({ "ambient_mutation": true })).await;

    let RunStatus::Failed(why) = &out.status else {
        panic!("expected a failure, got {:?}", out.status);
    };
    assert!(
        why.contains("not a member of the open group"),
        "the refusal did not name the reason: {why}"
    );
    assert!(
        !world.did("posted"),
        "the ambient mutation ran before it was refused: {:?}",
        world.entries()
    );
}

/// A **read** beside an open group stays legal.
///
/// The positive half, and it is what keeps the rule from being a blanket ban
/// on touching anything while a group is open: a read changes nothing there is
/// to take back, so an abort has nothing to apologise for. Without this half a
/// refuse-everything change would pass the test above.
#[tokio::test]
async fn a_read_beside_an_open_group_is_allowed() {
    let world = World::new();
    let out = run(&world, json!({ "ambient_read": true })).await;

    // The read runs. The run still fails, on the *older* rule that a step
    // returning with a group open is reversed rather than allowed to commit
    // by omission — so the assertion is about which rule spoke, not about the
    // run succeeding.
    assert!(
        world.did("looked"),
        "the read beside an open group did not happen: {:?}",
        world.entries()
    );
    let RunStatus::Failed(why) = &out.status else {
        panic!("expected the still-open failure, got {:?}", out.status);
    };
    assert!(
        !why.contains("not a member of the open group"),
        "a read was refused as an ambient mutation: {why}"
    );
    assert!(
        why.contains("still open"),
        "the run failed for an unexpected reason: {why}"
    );
}
