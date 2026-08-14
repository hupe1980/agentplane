//! Durable compensation across systems that cannot share a transaction.
//!
//! ```sh
//! cargo run --example saga_checkout
//! ```
//!
//! Inventory is reserved and payment is charged before fulfilment fails. The
//! runtime then refunds payment and releases inventory in reverse order. The
//! unwind has its own journal phase, and strict replay calls nothing again.

use std::sync::{Arc, Mutex};

use agentplane::core::{
    ArgSource, Compensation, Effect, EffectDescriptor, EffectError, Outcome, Phase, PlanIR,
    PlanNode, Recovery, RetryPolicy, Skill, SkillDescriptor, SkillError, StepId, Tainted,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

type EventLog = Arc<Mutex<Vec<String>>>;

#[derive(Debug)]
struct Operation {
    name: &'static str,
    fails: bool,
    events: EventLog,
}

#[async_trait::async_trait]
impl Effect for Operation {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("checkout.operation", json!({ "name": self.name }))
    }

    fn mutates(&self) -> bool {
        true
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.events.lock().unwrap().push(self.name.to_owned());
        if self.fails {
            Err(EffectError::Rejected(format!("{} refused", self.name)))
        } else {
            Ok(json!({ "completed": self.name }))
        }
    }
}

#[derive(Debug)]
struct SagaStep {
    capability: &'static str,
    forward: &'static str,
    compensation: &'static str,
    fails: bool,
    events: EventLog,
}

impl SagaStep {
    fn new(
        capability: &'static str,
        forward: &'static str,
        compensation: &'static str,
        events: &EventLog,
    ) -> Self {
        Self {
            capability,
            forward,
            compensation,
            fails: false,
            events: Arc::clone(events),
        }
    }

    fn failing(mut self) -> Self {
        self.fails = true;
        self
    }
}

#[async_trait::async_trait]
impl Skill for SagaStep {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.capability).provides(self.capability)
    }

    fn compensation(&self) -> Compensation {
        Compensation::Compensatable
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let result = cx
            .effect(Operation {
                name: self.forward,
                fails: self.fails,
                events: Arc::clone(&self.events),
            })
            .await?;
        Ok(Outcome::done(result))
    }

    async fn compensate(
        &self,
        cx: &mut StepCtx<'_>,
        _output: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        cx.effect(Operation {
            name: self.compensation,
            fails: false,
            events: Arc::clone(&self.events),
        })
        .await?;
        Ok(())
    }
}

fn checkout() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "checkout.reserve").arg("order", ArgSource::run_input()),
        PlanNode::new(1, "checkout.charge").arg("reservation", ArgSource::node(StepId(0))),
        PlanNode::new(2, "checkout.fulfil")
            .arg("payment", ArgSource::node(StepId(1)))
            .terminal(),
    ])
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);
    let events: EventLog = Arc::default();
    let runtime = Runtime::builder(Arc::clone(&store))
        .owner("checkout")
        .skill(SagaStep::new(
            "checkout.reserve",
            "reserve inventory",
            "release inventory",
            &events,
        ))
        .skill(SagaStep::new(
            "checkout.charge",
            "charge payment",
            "refund payment",
            &events,
        ))
        .skill(
            SagaStep::new(
                "checkout.fulfil",
                "book fulfilment",
                "cancel fulfilment",
                &events,
            )
            .failing(),
        )
        .build();

    let first = runtime
        .run_plan(
            checkout(),
            Tainted::trusted(json!({ "order": "ORD-42", "amount_minor": 12900 })),
        )
        .await?;
    assert!(matches!(first.status, RunStatus::Failed(_)));
    assert_eq!(
        *events.lock().unwrap(),
        [
            "reserve inventory",
            "charge payment",
            "book fulfilment",
            "refund payment",
            "release inventory",
        ]
    );
    println!("1. fulfilment failed; payment and inventory unwound in reverse");

    let records = store.read(first.run_id, 1).await?;
    let compensated: Vec<StepId> = records
        .iter()
        .filter_map(|record| match record.kind() {
            RecordKind::StepCompensated { .. } => record.body.step,
            _ => None,
        })
        .collect();
    assert_eq!(compensated, [StepId(1), StepId(0)]);
    assert!(
        records
            .iter()
            .any(|record| record.body.phase == Phase::Compensating)
    );
    store.verify(first.run_id).await?;
    println!("2. journal names the compensated steps and verifies end to end");

    let before_replay = events.lock().unwrap().clone();
    let replayed = runtime.replay(first.run_id, Mode::Strict).await?;
    assert_eq!(replayed.status, first.status);
    assert_eq!(*events.lock().unwrap(), before_replay);
    println!("3. strict replay reproduced the failure and unwind with zero calls");

    Ok(())
}
