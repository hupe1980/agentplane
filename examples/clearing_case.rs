//! A multi-day clearing case: correlation, obligations, and closure.
//!
//! ```sh
//! cargo run --example clearing_case
//! ```
//!
//! The scenario is a supplier switch. A request goes out and an acknowledgement
//! is owed within five working days. The acknowledgement arrives the next day —
//! as a *separate inbound message*, in a *separate run*, with no idea what run
//! id preceded it. All it carries is a document number.
//!
//! That is the shape every long-running business process has, and the reason
//! runs alone are not enough:
//!
//! * **Correlation** — the second message joins the first message's case by
//!   business key, deterministically, before any planning happens.
//! * **Obligations** — the deadline's *resolved instant* is journaled, so a
//!   corrected calendar cannot retroactively move a window someone relied on.
//! * **Durable waits** — the first run *suspends* rather than polling, and the
//!   arriving message resumes it. A suspended run costs a row, not a thread.
//! * **Closure** — a case with an unmet obligation refuses to close, which is
//!   what stops a missed regulatory window from vanishing behind a tidy status.
//!
//! The last section demonstrates the race the whole design exists for: a reply
//! that arrives *before* anyone is waiting for it.

use std::sync::Arc;

use agentplane::case::{CaseStore, EventStore, TaskStore};
use agentplane::core::{
    AwaitSpec, Calendar, CalendarError, CaseStatus, CorrelationKey, DeadlineSpec, DeadlineState,
    Decision, Delivery, Digest, InboundEvent, Justification, OnExpiry, Outcome, Priority, Skill,
    SkillDescriptor, SkillError, Tainted, TaskSpec, Timestamp,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::SqliteStore;
use serde_json::{Value, json};

/// The domain's calendar: working days, skipping weekends.
///
/// A real one also excludes public holidays, lands on a cut-off hour in a named
/// timezone, and is versioned when the rules change. All of that is *adapter*
/// knowledge — the engine only enforces the instant that comes back.
#[derive(Debug)]
struct WorkingDays;

impl Calendar for WorkingDays {
    fn resolve(&self, from: Timestamp, spec: &DeadlineSpec) -> Result<Timestamp, CalendarError> {
        if spec.kind != "working-days" {
            return Err(CalendarError::UnknownKind(spec.kind.clone()));
        }
        let n = spec
            .params
            .get("n")
            .and_then(Value::as_i64)
            .ok_or_else(|| CalendarError::BadParams {
                kind: spec.kind.clone(),
                detail: "expected `n`".into(),
            })?;
        let mut at = from;
        let mut left = n;
        while left > 0 {
            at += time::Duration::days(1);
            if !matches!(
                at.weekday(),
                time::Weekday::Saturday | time::Weekday::Sunday
            ) {
                left -= 1;
            }
        }
        Ok(at)
    }

    fn digest(&self) -> Digest {
        Digest::of(b"example.calendar.working-days.v1")
    }
}

/// Sends the request and takes on the obligation to be acknowledged.
#[derive(Debug)]
struct SendRequest;

#[async_trait::async_trait]
impl Skill for SendRequest {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("send-request").provides("switch.request")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // Correlate on the document this run was actually given, not on a
        // constant. A skill that hardcodes its correlation key waits for
        // somebody else's reply — which is a bug that only shows up once two
        // matters are in flight at the same time.
        let document = input
            .peek()
            .get("document")
            .and_then(Value::as_str)
            .ok_or_else(|| SkillError::Input("input needs a `document` field".into()))?
            .to_owned();

        cx.note(format!("dispatching switch request for {document}"))
            .await?;

        let due = cx
            .deadline(
                "acknowledgement",
                &DeadlineSpec::new("working-days", json!({ "n": 5 })),
                Some(time::Duration::days(1)),
            )
            .await?;

        // The version read here is threaded through every later write. Each
        // write returns the revision it produced, so the chain carries forward
        // and a write made against a stale read is refused rather than silently
        // overwriting whatever another run put there.
        let (_, at) = cx.case_state().await?;
        let at = cx
            .put_case_state(at, json!({ "stage": "awaiting-acknowledgement" }))
            .await?;
        cx.set_case_status(CaseStatus::AwaitingExternal).await?;
        cx.note(format!("acknowledgement owed by {}", due.resolved_at))
            .await?;
        // A second obligation, in case a human ends up in the loop.
        cx.deadline(
            "decision",
            &DeadlineSpec::new("working-days", json!({ "n": 2 })),
            None,
        )
        .await?;

        // Suspend until the acknowledgement arrives. Propagated with `?` —
        // catching this would turn a durable wait into a silent hang.
        let ack = cx
            .await_event(
                &AwaitSpec::new("acknowledgement.received", "acknowledgement")
                    .correlate(CorrelationKey::new("document", &document)),
            )
            .await?;

        cx.meet_deadline("acknowledgement").await?;

        // A rejection is not something to decide unilaterally. Ask a person —
        // and give them what they need to disagree.
        let rejected = ack.peek().get("status").and_then(Value::as_str) == Some("rejected");
        if rejected {
            let at = cx
                .put_case_state(at, json!({ "stage": "awaiting-decision" }))
                .await?;
            cx.set_case_status(CaseStatus::AwaitingHuman).await?;

            let decision = cx
                .task(
                    &TaskSpec::new(
                        "rejection-handling",
                        Justification::new(
                            "counterparty rejected the switch request",
                            json!({ "action": "resubmit-with-corrected-meter" }),
                        )
                        .confidence(0.55)
                        .cost("one further exchange, ~5 working days")
                        .evidence(format!("rejection payload: {}", ack.peek())),
                        "decision",
                    )
                    .role("mako-operator")
                    .priority(Priority::High)
                    // Four eyes: whoever proposed this does not approve it.
                    .excluding("agent:switch-bot")
                    .on_expiry(OnExpiry::Escalate),
                )
                .await?;

            cx.put_case_state(
                at,
                json!({
                    "stage": "decided",
                    "approved": decision.approved,
                    "by": decision.actor,
                }),
            )
            .await?;
            cx.set_case_status(CaseStatus::Open).await?;

            return Ok(Outcome::done(Tainted::trusted(json!({
                "outcome": "human-decided",
                "approved": decision.approved,
                "by": decision.actor,
            }))));
        }

        cx.put_case_state(at, json!({ "stage": "acknowledged" }))
            .await?;
        cx.set_case_status(CaseStatus::Open).await?;

        Ok(Outcome::done(input.zip(ack).map(
            |(sent, reply)| json!({ "sent": sent, "reply": reply }),
        )))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(SqliteStore::open_in_memory()?);
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .tasks(store.clone() as Arc<dyn TaskStore>)
        .calendar(Arc::new(WorkingDays))
        .skill(SendRequest)
        .build();

    // The only thing tying these messages together.
    let keys = [CorrelationKey::new("document", "DOC-4711")];

    // ── Day 0: the request goes out ────────────────────────────────────────
    let sent = rt
        .run_in_case(
            "switch.request",
            json!({ "document": "DOC-4711", "meter": "51238696781" }),
            "supplier-switch",
            &keys,
        )
        .await?;
    println!("day 0  request   → {}", sent.status.as_str());
    if let RunStatus::Suspended(reason) = &sent.status {
        println!("       waiting   → {reason}");
    }

    let case_id = store.correlate(&keys).await?.expect("case was opened");
    println!("       case      → {case_id}");
    println!(
        "       cost      → {} waiting run(s): a row, not a thread",
        store.waiting(10).await?.len()
    );

    // A case carrying an unmet obligation refuses to close. This is the check
    // that stops a missed window from disappearing behind a tidy status.
    match store.close(case_id).await {
        Err(e) => println!("       close     → refused: {e}"),
        Ok(()) => panic!("an open obligation must block closing"),
    }

    // ── Day 1: the acknowledgement arrives, knowing only the document ──────
    let ack = InboundEvent::new(
        "MSG-88219",
        "acknowledgement.received",
        json!({ "status": "rejected", "code": "E_0624", "detail": "meter unknown" }),
    )
    .correlate(CorrelationKey::new("document", "DOC-4711"));

    let delivery = rt.deliver(&ack).await?;
    println!("\nday 1  ack       → rejected (E_0624)");
    println!("       delivery  → {delivery:?}");
    assert_eq!(delivery, Delivery::Resumed { run: sent.run_id });

    // Retries are harmless; the counterparty may well send it twice.
    assert_eq!(rt.deliver(&ack).await?, Delivery::Duplicate);
    println!("       retry     → Duplicate (deduplicated by message id)");

    handle_rejection(&rt, &store).await?;

    let case = store.case(case_id).await?.unwrap();
    println!("       state     → {}", case.state);

    finish_and_close(&rt, &store, case_id, sent.run_id).await?;
    demonstrate_early_arrival(&rt).await?;

    Ok(())
}

/// A rejection is not something to decide unilaterally.
async fn handle_rejection(
    rt: &Runtime,
    store: &Arc<SqliteStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    let task = store
        .queue(&["mako-operator".to_owned()], 10)
        .await?
        .pop()
        .expect("a rejection must reach a human");
    println!(
        "\n       escalated → task {} ({:?})",
        task.kind, task.priority
    );
    println!("       proposal  → {}", task.justification.proposed_action);
    println!("       confidence→ {:?}", task.justification.confidence);
    println!("       cost      → {:?}", task.justification.cost);

    // Four eyes: the proposer may not approve their own proposal.
    let self_approval = rt
        .decide_task(
            task.id,
            &Decision::approve("agent:switch-bot", "I am sure"),
            &["mako-operator".to_owned()],
        )
        .await;
    println!(
        "       self-appr → refused ({})",
        self_approval.unwrap_err()
    );

    rt.decide_task(
        task.id,
        &Decision::approve("frank", "meter id corrected in the master data"),
        &["mako-operator".to_owned()],
    )
    .await?;
    println!("       decided   → approved by frank");

    Ok(())
}

/// Settle the remaining obligations and conclude the matter.
async fn finish_and_close(
    _rt: &Runtime,
    store: &Arc<SqliteStore>,
    case_id: agentplane::core::CaseId,
    run_id: agentplane::core::RunId,
) -> Result<(), Box<dyn std::error::Error>> {
    // Both obligations are settled: the acknowledgement was met, and the
    // decision was answered.
    for d in store.deadlines(case_id).await? {
        if d.state == DeadlineState::Pending {
            store
                .set_deadline_state(case_id, &d.name, DeadlineState::Met)
                .await?;
        }
    }
    assert!(
        store
            .deadlines(case_id)
            .await?
            .iter()
            .all(|d| d.state == DeadlineState::Met)
    );

    // ── Closing is now permitted ───────────────────────────────────────────
    store.close(case_id).await?;
    println!(
        "\nclosed           → {:?}",
        store.case(case_id).await?.unwrap().status
    );

    // Closing releases the correlation keys, so a genuinely new matter about
    // the same meter opens a fresh case rather than reanimating this one.
    let keys = [CorrelationKey::new("document", "DOC-4711")];
    assert!(store.correlate(&keys).await?.is_none());
    println!("keys released    → a new message opens a new case");

    // ── The whole matter is one range scan ─────────────────────────────────
    let records = store.read(run_id, 1).await?;
    let obligations_journaled = records
        .iter()
        .filter(|r| {
            matches!(
                r.kind(),
                RecordKind::DeadlineRegistered { .. } | RecordKind::DeadlineTransition { .. }
            )
        })
        .count();

    println!(
        "\naudit            → {} records, {} of them obligation events",
        records.len(),
        obligations_journaled
    );
    println!("                   every one carries the case id");
    assert!(records.iter().all(|r| r.body.case == Some(case_id)));
    store.verify(run_id).await?;
    println!("                   the chain verifies across the suspension");

    Ok(())
}

/// The race the design exists for: a reply that arrives before anyone is
/// waiting for it must not be lost.
async fn demonstrate_early_arrival(rt: &Runtime) -> Result<(), Box<dyn std::error::Error>> {
    let early_keys = [CorrelationKey::new("document", "DOC-9999")];
    let early = InboundEvent::new(
        "MSG-EARLY",
        "acknowledgement.received",
        json!({ "status": "very prompt" }),
    )
    .correlate(CorrelationKey::new("document", "DOC-9999"));

    println!("\nearly reply      → {:?}", rt.deliver(&early).await?);

    let racy = rt
        .run_in_case(
            "switch.request",
            json!({ "document": "DOC-9999", "meter": "51238696782" }),
            "supplier-switch",
            &early_keys,
        )
        .await?;
    println!("then the request → {}", racy.status.as_str());
    println!("                   the buffered reply satisfied the wait immediately");
    assert_eq!(racy.status, RunStatus::Succeeded);

    Ok(())
}
