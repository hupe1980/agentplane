//! Several calls that take together, or not at all.
//!
//! ```sh
//! cargo run --example effect_group
//! ```
//!
//! A step-level saga undoes whole steps, and its compensation is handed the
//! step's *output* — which a failed step does not have. This example works at
//! the granularity below that: a group whose members each carry the concrete
//! call that reverses them, built from what that call actually returned.
//!
//! It runs the same checkout twice. The first commits. The second fails at the
//! last member, and the run comes back with the world exactly as it started —
//! including the confirmation email, which was never sent rather than sent and
//! retracted.

use std::sync::{Arc, Mutex};

use agentplane::core::{
    Effect, EffectDescriptor, EffectError, Outcome, Recovery, RetryPolicy, Skill, SkillDescriptor,
    SkillError, Tainted,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Invariant, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// What the outside world has actually seen, in order.
type Ledger = Arc<Mutex<Vec<String>>>;

/// One call against a system that cannot share a transaction with the others.
#[derive(Debug)]
struct Call {
    kind: &'static str,
    entry: String,
    refuses: bool,
    ledger: Ledger,
}

impl Call {
    fn new(kind: &'static str, entry: impl Into<String>, ledger: &Ledger) -> Self {
        Self {
            kind,
            entry: entry.into(),
            refuses: false,
            ledger: Arc::clone(ledger),
        }
    }

    const fn refusing(mut self) -> Self {
        self.refuses = true;
        self
    }
}

#[async_trait::async_trait]
impl Effect for Call {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(self.kind, json!({ "entry": self.entry }))
    }

    /// Refused outright — the driver knows nothing happened, so an unwind is
    /// safe. An effect that could not say this would quarantine the group
    /// instead, which is the correct answer to genuine doubt.
    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        if self.refuses {
            return Err(EffectError::Rejected(format!("{} refused", self.kind)));
        }
        self.ledger.lock().unwrap().push(self.entry.clone());
        Ok(json!({ "reference": format!("{}-ref", self.kind) }))
    }
}

#[derive(Debug)]
struct Checkout {
    ledger: Ledger,
    /// Whether the gated notification refuses when the group commits.
    notify_fails: bool,
}

#[async_trait::async_trait]
impl Skill for Checkout {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("checkout").provides("shop.checkout")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let l = &self.ledger;
        let mut g = cx
            .group("checkout", ["inventory", "payments", "notify"])
            .await
            .map_err(SkillError::Step)?;

        // Each reversible member registers its undo from the reference this
        // call returned — not from state looked up later, which may have moved.
        let hold = g
            .reversible(
                "inventory",
                Call::new("stock.hold", "held ORD-42", l),
                |out| {
                    Call::new(
                        "stock.release",
                        format!("released {}", out["reference"].as_str().unwrap_or("?")),
                        l,
                    )
                },
            )
            .await
            .map_err(SkillError::Step)?;

        g.reversible(
            "payments",
            Call::new("card.auth", "authorised £129", l),
            |out| {
                Call::new(
                    "card.void",
                    format!("voided {}", out["reference"].as_str().unwrap_or("?")),
                    l,
                )
            },
        )
        .await
        .map_err(SkillError::Step)?;

        // The irreversible send. Held at the gate: an aborted group never
        // performs it, which beats sending it and following up with a
        // correction.
        let notify = Call::new("mail.send", "emailed confirmation", l);
        g.deferred(
            "notify",
            if self.notify_fails {
                notify.refusing()
            } else {
                notify
            },
        )
        .map_err(SkillError::Step)?;

        // The frontier: the last instant at which failing is free.
        g.commit(&[Invariant::new(
            "the hold has a reference",
            hold.peek()["reference"].is_string(),
        )])
        .await
        .map_err(SkillError::Step)?;

        Ok(Outcome::done(Tainted::trusted(json!("checked out"))))
    }
}

async fn checkout(
    notify_fails: bool,
) -> Result<(Ledger, agentplane::runtime::RunOutcome), Box<dyn std::error::Error>> {
    let store = Arc::new(RedbStore::open_in_memory()?);
    let ledger: Ledger = Arc::default();
    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Checkout {
            ledger: Arc::clone(&ledger),
            notify_fails,
        })
        .build();

    let out = runtime
        .run(
            "shop.checkout",
            Tainted::trusted(json!({ "order": "ORD-42" })),
        )
        .await?;

    // The group is bracketed in the journal, so "was this taken or taken back?"
    // is a query rather than an inference from the effects around it.
    let records = store.read(out.run_id, 1).await?;
    let settled = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::GroupSettled { group, outcome, .. } => {
                Some(format!("{group}: {}", outcome.as_str()))
            }
            _ => None,
        })
        .expect("the group was not settled");
    println!("   journal says — {settled}");
    store.verify(out.run_id).await?;

    Ok((ledger, out))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (ledger, out) = checkout(false).await?;
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(
        *ledger.lock().unwrap(),
        ["held ORD-42", "authorised £129", "emailed confirmation"]
    );
    println!(
        "1. committed: the gated email went out last, and only once every member had landed\n"
    );

    let (ledger, out) = checkout(true).await?;
    assert!(matches!(out.status, RunStatus::Failed(_)));
    let seen = ledger.lock().unwrap().clone();
    assert_eq!(
        seen,
        [
            "held ORD-42",
            "authorised £129",
            // Reversed newest-first: a later member may rest on an earlier one.
            "voided card.auth-ref",
            "released stock.hold-ref",
        ]
    );
    assert!(!seen.iter().any(|e| e == "emailed confirmation"));
    println!("2. aborted: both members taken back in reverse, and the email was never sent");
    println!("   — not sent and retracted, which is the difference deferral buys");

    Ok(())
}
