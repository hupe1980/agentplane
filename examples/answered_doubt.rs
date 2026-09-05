//! The call nobody can account for, and the person who answers it.
//!
//! ```sh
//! cargo run --example answered_doubt
//! ```
//!
//! A payment times out. The provider is asked and cannot say. The runtime
//! refuses to guess, so the run is **quarantined**: nothing is unwound,
//! because compensating around a call that may have landed is a refund for
//! money nobody took.
//!
//! Every durable engine reaches that wall. What happens next is the part worth
//! watching:
//!
//! 1. **The doubt is named, not described.** The run says which effect, which
//!    step, and whether it never heard back or heard back and was told nothing.
//! 2. **A person supplies a fact; the runtime keeps the verdict.** Reopening
//!    without answering reaches the same quarantine, on the record.
//! 3. **An answer completes the run without repeating the call.** The charge is
//!    never sent twice — and the value the person supplied is *untrusted*,
//!    because no effect produced it.
//! 4. **Giving up is an ending that keeps the evidence.** The alternative run
//!    is abandoned: nothing unwound, the backlog cleared, and what it left
//!    standing reported by `agentplane audit` for as long as the journal
//!    exists.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::{
    ArgSource, Assertion, Compensation, Effect, EffectDescriptor, EffectError, Outcome, PlanIR,
    PlanNode, QuarantineDecision, Reconciliation, Recovery, RetryPolicy, RunId, Skill,
    SkillDescriptor, SkillError, StepId, Tainted,
};
use agentplane::journal::JournalStore;
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// A capture that times out, and a provider that cannot say what happened.
#[derive(Debug, Clone)]
struct Capture {
    sent: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Effect for Capture {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("payments.capture", json!({ "order": "SO-4711" }))
    }

    fn mutates(&self) -> bool {
        true
    }

    fn recovery(&self) -> Recovery {
        Recovery::Reconcile
    }

    fn retry(&self) -> RetryPolicy {
        RetryPolicy::attempts(1)
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.sent.fetch_add(1, Ordering::SeqCst);
        Err(EffectError::Timeout {
            driver: "payments".into(),
            waited_ms: 30_000,
        })
    }

    async fn reconcile(&self) -> Result<Reconciliation<Value>, EffectError> {
        // The provider's search endpoint is down too. This is the honest
        // answer, and it is the one that costs a person's attention.
        Ok(Reconciliation::Inconclusive)
    }
}

/// Books the order. Compensatable, so there is something an unwind could
/// reverse — which is exactly what must not happen here.
#[derive(Debug, Clone)]
struct Booking {
    log: Arc<std::sync::Mutex<Vec<String>>>,
    what: &'static str,
}

#[async_trait::async_trait]
impl Effect for Booking {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("orders.book", json!({ "what": self.what }))
    }

    fn mutates(&self) -> bool {
        true
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.log.lock().expect("log").push(self.what.to_owned());
        Ok(json!({ "did": self.what }))
    }
}

#[derive(Debug)]
struct Book(Arc<std::sync::Mutex<Vec<String>>>);

#[async_trait::async_trait]
impl Skill for Book {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("orders.book").provides("orders.book")
    }

    fn compensation(&self) -> Compensation {
        Compensation::Compensatable
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let out = cx
            .effect(Booking {
                log: Arc::clone(&self.0),
                what: "booked",
            })
            .await?;
        Ok(Outcome::done(out))
    }

    async fn compensate(
        &self,
        cx: &mut StepCtx<'_>,
        _output: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        cx.effect(Booking {
            log: Arc::clone(&self.0),
            what: "cancelled the booking",
        })
        .await?;
        Ok(())
    }
}

#[derive(Debug)]
struct Charge(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Skill for Charge {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("payments.capture").provides("payments.capture")
    }

    fn compensation(&self) -> Compensation {
        Compensation::Compensatable
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let out = cx
            .effect(Capture {
                sent: Arc::clone(&self.0),
            })
            .await?;
        Ok(Outcome::done(out))
    }
}

fn plan() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "orders.book").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "payments.capture")
            .arg("order", ArgSource::node(StepId(0)))
            .terminal(),
    ])
}

struct Plane {
    store: Arc<RedbStore>,
    rt: Arc<Runtime>,
    sent: Arc<AtomicUsize>,
    log: Arc<std::sync::Mutex<Vec<String>>>,
}

fn plane() -> Result<Plane, Box<dyn std::error::Error>> {
    let sent = Arc::new(AtomicUsize::new(0));
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let store = Arc::new(RedbStore::open_in_memory()?);
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .owner("payments-plane")
        .skill(Book(Arc::clone(&log)))
        .skill(Charge(Arc::clone(&sent)))
        .build();
    Ok(Plane {
        store,
        rt,
        sent,
        log,
    })
}

async fn stuck(p: &Plane) -> Result<RunId, Box<dyn std::error::Error>> {
    let out = p.rt.run_plan(plan(), Tainted::trusted(json!({}))).await?;
    assert!(matches!(out.status, RunStatus::Quarantined(_)));
    Ok(out.run_id)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. The doubt is named ──────────────────────────────────────────────
    let p = plane()?;
    let run = stuck(&p).await?;
    let doubts = p.rt.undecided(run).await?;

    println!("1. the capture timed out and the provider could not say");
    println!("   run            → quarantined");
    for d in &doubts {
        println!(
            "   in doubt       → {} at step {} ({}) — key {}",
            d.kind,
            d.step,
            d.doubt.as_str(),
            d.effect
        );
    }
    println!(
        "   the booking    → {:?}, standing: nothing is unwound around an \
         unknown outcome",
        p.log.lock().expect("log").as_slice()
    );

    // ── 2. A person supplies a fact; the runtime keeps the verdict ─────────
    let same =
        p.rt.decide_quarantine(
            run,
            "ada",
            "had a look, seems fine",
            QuarantineDecision::Reopen,
        )
        .await?;
    println!("\n2. reopened without answering anything");
    println!("   run            → {}", same.status.as_str());
    println!("   captures sent  → {}", p.sent.load(Ordering::SeqCst));
    assert!(matches!(same.status, RunStatus::Quarantined(_)));

    // ── 3. The answer completes the run, and the call is not repeated ──────
    p.rt.reconcile_effect(
        run,
        doubts[0].effect,
        Assertion::Landed(json!({ "charge": "ch_9RtQ", "captured": true })),
        "ada",
        "charge ch_9RtQ exists in the provider console, created 12:41Z",
    )
    .await?;
    let done =
        p.rt.decide_quarantine(
            run,
            "ada",
            "the charge is in the provider's ledger",
            QuarantineDecision::Reopen,
        )
        .await?;
    println!("\n3. the effect is answered, and the run is judged again");
    println!("   run            → {}", done.status.as_str());
    println!(
        "   captures sent  → {} — the whole point: never twice",
        p.sent.load(Ordering::SeqCst)
    );
    assert_eq!(done.status, RunStatus::Succeeded);
    assert_eq!(p.sent.load(Ordering::SeqCst), 1);

    // ── 4. Giving up is an ending that keeps the evidence ──────────────────
    let q = plane()?;
    let lost = stuck(&q).await?;
    let key = q.rt.undecided(lost).await?[0].effect;
    let closed =
        q.rt.decide_quarantine(
            lost,
            "ada",
            "two weeks of provider tickets; nobody can say",
            QuarantineDecision::Abandon,
        )
        .await?;
    let journal = Arc::clone(&q.store) as Arc<dyn JournalStore>;
    let report =
        agentplane::audit::audit(&journal, &[lost], &agentplane::audit::Evidence::default())
            .await?;

    println!("\n4. a second run, abandoned because nobody could ever tell");
    println!("   run            → {}", closed.status.as_str());
    println!(
        "   the booking    → {:?}, still standing: abandoning is not cancelling",
        q.log.lock().expect("log").as_slice()
    );
    println!(
        "   quarantined    → {} (the backlog cleared)",
        journal.count_by_outcome("quarantined").await?
    );
    for finding in &report.findings {
        println!("   audit          → {finding}");
    }
    assert!(matches!(closed.status, RunStatus::Abandoned { .. }));
    assert_eq!(q.log.lock().expect("log").len(), 1);
    assert!(report.findings.iter().any(|f| matches!(
        f,
        agentplane::audit::Finding::EffectUndecided { effect, .. } if *effect == key
    )));

    println!(
        "\nThe status went away and the doubt did not. That is the difference \
         between\nclearing a backlog and answering it."
    );
    Ok(())
}
