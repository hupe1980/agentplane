//! Where a subject's data went.
//!
//! The report joins a subject's memory items to the outbound labels their
//! values reached, and names beside the result every class of flow it cannot
//! trace. These tests hold the join to the exact source, the coverage list to
//! every class, and the report to changing nothing.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::core::{
    DeclaredOutput, Digest, EffectDescriptor, EffectKey, Label, Recovery, RunId, Sensitivity,
    SourceId, Spend, StepId, Timestamp, Trust,
};
use agentplane::journal::{Append, BoundSubject, JournalStore, RecordKind, SubjectBinding};
use agentplane::memory::{MemoryItem, MemoryStore, Selected};
use agentplane::store::RedbStore;
use agentplane::subject::{Class, Sink, SubjectReport, Trace};
use serde_json::{Value, json};

const A: &str = "subject-a";
const B: &str = "subject-b";

fn item(id: &str, subject: &str, trust: Trust, expires_at: Option<i64>) -> MemoryItem {
    MemoryItem {
        id: id.to_owned(),
        subject: subject.to_owned(),
        purpose: "support".to_owned(),
        content: json!({ "note": "never read by the report" }),
        provenance: Vec::new(),
        sensitivity: Sensitivity::Confidential,
        trust,
        written_by: "triage".to_owned(),
        version: 0,
        created_at: Timestamp::from_unix_timestamp(1_760_000_000).unwrap(),
        expires_at: expires_at.map(|s| Timestamp::from_unix_timestamp(s).unwrap()),
        access_retention_seconds: None,
        superseded_at: None,
        derived_from: Vec::new(),
    }
}

/// A label naming exactly `sources`, or no source at all.
fn label(sources: &[&str]) -> Label {
    let mut label = Label::trusted();
    for s in sources {
        label.provenance.insert(SourceId::new(*s));
    }
    label
}

/// A run's binding of `subject` from a trusted input field, at index 0.
fn bound(run: RunId, subject: &str) -> Append {
    Append::new(
        run,
        RecordKind::DataSubjectBound {
            bindings: vec![BoundSubject {
                index: 0,
                binding: SubjectBinding::Input {
                    pointer: "/customer".into(),
                },
                trusted: true,
                subject: subject.to_owned(),
            }],
        },
    )
}

fn key(ordinal: u32) -> EffectKey {
    EffectKey::from_hex(&format!("{ordinal:064x}")).expect("a key")
}

fn admitted(run: RunId) -> Append {
    Append::new(
        run,
        RecordKind::RunAdmitted {
            capability: "support".into(),
            governed_by: None,
            input: json!({}),
            input_label: Label::trusted(),
            policy_bundle: None,
            canon: agentplane::core::canon::VERSION,
            idempotency_key: None,
            admitted_by: None,
            served_unchained: false,
            plane_chain: false,
        },
    )
}

fn started(run: RunId, ordinal: u32, attempt: u32, kind: &str, args: Value, out: Label) -> Append {
    Append::new(
        run,
        RecordKind::EffectStarted {
            descriptor: EffectDescriptor::new(kind, args),
            recovery: Recovery::Retry,
            mutates: false,
            attempt,
            backoff_ms: 0,
            outbound_label: Some(out),
            outbound_bytes: Some(42),
            content_rules: None,
            credential: None,
        },
    )
    .step(StepId(ordinal))
    .effect(key(ordinal))
}

fn tool_call(run: RunId, ordinal: u32, out: Label) -> Append {
    started(
        run,
        ordinal,
        1,
        "tool.call",
        json!({ "server": "crm", "tool": "upsert", "arguments": { "x": 1 } }),
        out,
    )
}

fn recall(run: RunId, ordinal: u32, kind: &str, id: &str) -> Vec<Append> {
    let chosen = Selected {
        id: id.to_owned(),
        version: 1,
        digest: Digest::of(id.as_bytes()),
    };
    let output = if kind == "memory.recall" {
        json!([chosen])
    } else {
        json!([{ "selected": chosen, "score": 0.9 }])
    };
    vec![
        started(
            run,
            ordinal,
            1,
            kind,
            json!({ "subject": A }),
            Label::trusted(),
        ),
        Append::new(
            run,
            RecordKind::EffectDone {
                output,
                source: None,
                by: None,
                spend: Spend::tokens(0),
                declared: DeclaredOutput {
                    trust: Trust::Trusted,
                    sensitivity: Sensitivity::Confidential,
                },
                content: None,
                elapsed_ms: None,
            },
        )
        .step(StepId(ordinal))
        .effect(key(ordinal)),
    ]
}

async fn append(
    journal: &Arc<dyn JournalStore>,
    records: impl FnOnce(RunId) -> Vec<Append>,
) -> RunId {
    let run = RunId::generate();
    let lease = journal
        .acquire(run, "subject", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    let mut all = vec![admitted(run)];
    all.extend(records(run));
    journal.append(lease.epoch, all).await.unwrap();
    run
}

struct Plane {
    store: Arc<RedbStore>,
    journal: Arc<dyn JournalStore>,
}

async fn plane(items: &[MemoryItem]) -> Plane {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    for item in items {
        MemoryStore::remember(store.as_ref(), item).await.unwrap();
    }
    let journal = Arc::clone(&store) as Arc<dyn JournalStore>;
    Plane { store, journal }
}

async fn report(p: &Plane, subject: &str, limit: usize) -> SubjectReport {
    Trace::new("default")
        .report(&p.journal, p.store.as_ref(), subject, limit)
        .await
        .expect("a report")
}

fn met(report: &SubjectReport, class: Class) -> bool {
    report
        .coverage
        .iter()
        .find(|c| c.class == class)
        .unwrap_or_else(|| panic!("class {class:?} is missing from the coverage list"))
        .met
}

/// **Only the subject's effects.** R1 names A's item, R2 names B's, R3 names
/// none.
#[tokio::test]
async fn a_subject_report_lists_only_the_subjects_effects() {
    let p = plane(&[
        item("a-1", A, Trust::Untrusted, None),
        item("b-1", B, Trust::Untrusted, None),
    ])
    .await;
    let r1 = append(&p.journal, |run| {
        vec![tool_call(run, 1, label(&["memory:a-1", "tool:search"]))]
    })
    .await;
    append(&p.journal, |run| {
        vec![tool_call(run, 1, label(&["memory:b-1"]))]
    })
    .await;
    append(&p.journal, |run| {
        vec![tool_call(run, 1, label(&["tool:search"]))]
    })
    .await;

    let report = report(&p, A, 100).await;
    assert_eq!(report.runs_scanned, 3);
    assert_eq!(report.effects.len(), 1, "{:#?}", report.effects);
    let e = &report.effects[0];
    assert_eq!(e.run, r1);
    assert_eq!(e.outbound_bytes, Some(42));
    assert_eq!(
        e.sink,
        Sink::Tool {
            server: "crm".into(),
            tool: "upsert".into()
        }
    );
    assert_eq!(e.ids.iter().collect::<Vec<_>>(), vec!["a-1"]);
    assert_eq!(report.items.len(), 1);
    assert_eq!(report.items[0].written_by.as_deref(), Some("triage"));
}

/// **The join is the exact source.** A source that merely starts with the
/// item's own is a different item.
#[tokio::test]
async fn a_source_that_merely_contains_the_id_is_not_traced() {
    let p = plane(&[item("a-1", A, Trust::Untrusted, None)]).await;
    append(&p.journal, |run| {
        vec![tool_call(run, 1, label(&["memory:a-1x", "memory-a-1"]))]
    })
    .await;
    let report = report(&p, A, 100).await;
    assert!(report.effects.is_empty(), "{:#?}", report.effects);
}

/// **Every id the erasure selects, expired or not, and in-flight runs too.**
#[tokio::test]
async fn an_expired_item_in_an_in_flight_run_is_traced() {
    let p = plane(&[item("a-old", A, Trust::Untrusted, Some(1_760_000_001))]).await;
    append(&p.journal, |run| {
        vec![tool_call(run, 1, label(&["memory:a-old"]))]
    })
    .await;
    let report = report(&p, A, 100).await;
    let selected = p.store.subject_ids(A).await.unwrap();
    assert_eq!(
        report
            .items
            .iter()
            .map(|i| i.id.clone())
            .collect::<Vec<_>>(),
        selected
    );
    assert_eq!(
        report.effects.len(),
        1,
        "a run with no conclusion was not scanned"
    );
}

/// **Every class on every report**, and each detectable one marked when seeded.
#[tokio::test]
async fn every_untraced_class_is_named_in_coverage() {
    let p = plane(&[item("a-1", A, Trust::Untrusted, None)]).await;
    append(&p.journal, |run| {
        vec![bound(run, A), tool_call(run, 1, label(&["memory:a-1"]))]
    })
    .await;
    let clean = report(&p, A, 100).await;
    let classes: Vec<Class> = clean.coverage.iter().map(|c| c.class).collect();
    assert_eq!(
        classes,
        Class::ALL,
        "the coverage list must carry every class"
    );
    assert_eq!(classes.len(), 12);
    for class in Class::ALL {
        assert!(!met(&clean, *class), "{class:?} met on a clean report");
    }

    // A trusted selected item leaves no source in any label.
    MemoryStore::remember(p.store.as_ref(), &item("a-2", A, Trust::Trusted, None))
        .await
        .unwrap();
    let trusted = report(&p, A, 100).await;
    assert!(
        met(&trusted, Class::TrustedItem),
        "a trusted item went unmarked"
    );

    // A run that binds no subject is not traced through its intake.
    append(&p.journal, |run| vec![tool_call(run, 1, label(&[]))]).await;
    let unbound = report(&p, A, 100).await;
    assert!(
        met(&unbound, Class::UnboundIngress),
        "an unbound run went unmarked"
    );
    assert!(!met(&unbound, Class::UntakenData), "never detectable");

    // With a limit of one, the scan is cut.
    let cut = report(&p, A, 1).await;
    assert!(met(&cut, Class::RunsNotScanned), "a cut scan went unmarked");
    assert!(cut.partial());
}

/// A run admitted with `input_label` and no binding of its own: a
/// commissioned run handed its parent's references.
async fn handed(
    journal: &Arc<dyn JournalStore>,
    input_label: Label,
    records: impl FnOnce(RunId) -> Vec<Append>,
) -> RunId {
    let run = RunId::generate();
    let lease = journal
        .acquire(run, "subject", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    let mut first = admitted(run);
    if let RecordKind::RunAdmitted { input_label: l, .. } = &mut first.kind {
        *l = input_label;
    }
    let mut all = vec![first];
    all.extend(records(run));
    journal.append(lease.epoch, all).await.unwrap();
    run
}

/// **A run handed the subject's references is not unbound ingress until it
/// reads beyond its input; a bound run's memory write is marked.**
#[tokio::test]
async fn a_handed_run_counts_only_once_it_reads_beyond_its_input() {
    let p = plane(&[]).await;
    let parent = append(&p.journal, |run| vec![bound(run, A)]).await;
    let mut carried = Label::trusted();
    carried.data_subjects.insert(agentplane::core::SubjectRef {
        run: parent,
        index: 0,
    });

    handed(&p.journal, carried.clone(), |run| {
        vec![tool_call(run, 1, carried.clone())]
    })
    .await;
    let input_only = report(&p, A, 100).await;
    assert!(
        !met(&input_only, Class::UnboundIngress),
        "a run whose whole intake is traced was counted"
    );
    assert!(!met(&input_only, Class::RememberedIntake));

    handed(&p.journal, carried.clone(), |run| {
        vec![started(
            run,
            1,
            1,
            "case.read_state",
            json!({}),
            Label::trusted(),
        )]
    })
    .await;
    assert!(
        met(&report(&p, A, 100).await, Class::UnboundIngress),
        "a handed run reading case state went unmarked"
    );

    handed(&p.journal, carried, |run| {
        vec![started(
            run,
            2,
            1,
            "memory.remember",
            json!({}),
            Label::trusted(),
        )]
    })
    .await;
    assert!(
        met(&report(&p, A, 100).await, Class::RememberedIntake),
        "a memory write by a run taking in the subject went unmarked"
    );
}

/// **A trusted item's recall is listed by run**, though no label names it.
#[tokio::test]
async fn a_trusted_recall_is_listed_by_run() {
    let p = plane(&[item("a-t", A, Trust::Trusted, None)]).await;
    let run = append(&p.journal, |run| {
        let mut r = recall(run, 1, "memory.recall", "a-t");
        r.extend(recall(run, 2, "memory.semantic-recall", "a-t"));
        r.extend(recall(run, 3, "memory.recall", "someone-else"));
        r
    })
    .await;
    let report = report(&p, A, 100).await;
    assert_eq!(report.recalls.len(), 2, "{:#?}", report.recalls);
    assert!(report.recalls.iter().all(|r| r.run == run && r.id == "a-t"));
    assert_eq!(report.recalls[1].step, Some(StepId(2)));
}

/// **The report changes nothing**: no record, no memory item.
#[tokio::test]
async fn a_subject_report_changes_no_store() {
    let p = plane(&[
        item("a-1", A, Trust::Untrusted, None),
        item("a-2", A, Trust::Trusted, None),
    ])
    .await;
    let run = append(&p.journal, |run| {
        vec![tool_call(run, 1, label(&["memory:a-1"]))]
    })
    .await;
    let head = p.journal.head(run).await.unwrap();
    let ids = p.store.subject_ids(A).await.unwrap();
    let version = p
        .store
        .current("a-1", None)
        .await
        .unwrap()
        .map(|m| m.version);

    let _ = report(&p, A, 100).await;

    assert_eq!(p.journal.head(run).await.unwrap(), head);
    assert_eq!(p.store.subject_ids(A).await.unwrap(), ids);
    assert_eq!(
        p.store
            .current("a-1", None)
            .await
            .unwrap()
            .map(|m| m.version),
        version
    );
}

/// **A sink is named by kind, and why**: sealed without a ring, erased when the
/// key is gone, a tool when opened. A sealed recall is counted, never listed.
#[cfg(all(feature = "keyring", feature = "testkit"))]
#[tokio::test]
async fn a_sink_is_named_by_kind_and_why_when_its_arguments_are_not_opened() {
    use agentplane::core::TenantId;
    use agentplane::keyring::{KeyRing, SealedJournal};
    use agentplane::subject::Why;
    use agentplane::testkit::MemoryKeyRing;

    let tenant = TenantId::default();
    let ring = Arc::new(MemoryKeyRing::default()) as Arc<dyn KeyRing>;
    let p = plane(&[item("a-1", A, Trust::Untrusted, None)]).await;
    let sealed = SealedJournal::wrap(Arc::clone(&p.journal), Arc::clone(&ring), tenant.clone())
        as Arc<dyn JournalStore>;
    let run = append(&sealed, |run| {
        let mut r = vec![tool_call(run, 1, label(&["memory:a-1"]))];
        r.extend(recall(run, 2, "memory.recall", "a-1"));
        r
    })
    .await;

    let blind = report(&p, A, 100).await;
    assert!(matches!(
        blind.effects[0].sink,
        Sink::Kind {
            why: Why::Sealed,
            ..
        }
    ));
    assert!(met(&blind, Class::UnopenedSink));
    assert!(met(&blind, Class::UnopenedRecall));
    assert!(blind.recalls.is_empty());

    let keyed = Trace::new(tenant.as_str())
        .with_keys(ring.as_ref())
        .report(&p.journal, p.store.as_ref(), A, 100)
        .await
        .unwrap();
    assert!(matches!(keyed.effects[0].sink, Sink::Tool { .. }));
    assert_eq!(keyed.recalls.len(), 1);

    agentplane::blob::erase_run(
        ring.as_ref(),
        None,
        &tenant,
        run,
        Timestamp::from_unix_timestamp(1_760_000_000).unwrap(),
        "subject exercised the right to erasure",
    )
    .await
    .unwrap();
    let erased = Trace::new(tenant.as_str())
        .with_keys(ring.as_ref())
        .report(&p.journal, p.store.as_ref(), A, 100)
        .await
        .unwrap();
    assert!(
        matches!(
            erased.effects[0].sink,
            Sink::Kind {
                why: Why::Erased,
                ..
            }
        ),
        "an erased sink read as {:?}",
        erased.effects[0].sink
    );
    assert!(erased.recalls.is_empty());
}

// ── Data a run took in, through the real runtime ────────────────────────────

mod intake {
    use std::sync::Arc;

    use agentplane::case::{CaseStore, EventStore};
    use agentplane::core::{
        AwaitSpec, CorrelationKey, DeadlineSpec, InboundEvent, Outcome, Skill, SkillDescriptor,
        SkillError, Tainted,
    };
    use agentplane::journal::JournalStore;
    use agentplane::runtime::effects::Recorded;
    use agentplane::runtime::{Finding, RunStatus, RunTerms, Runtime, StepCtx};
    use agentplane::store::RedbStore;
    use agentplane::subject::{SubjectReport, Trace};
    use serde_json::{Value, json};

    /// What a step forwards to its one outbound effect.
    #[derive(Debug, Clone, Copy)]
    enum Forward {
        Input,
        InputAfterWaiting,
        Event,
        CaseState,
        Commission,
        #[cfg(feature = "manifest")]
        Specialist,
    }

    #[derive(Debug)]
    struct Forwards(&'static str, Forward);

    fn key(v: &str) -> CorrelationKey {
        CorrelationKey::new("document", v)
    }

    async fn send(cx: &mut StepCtx<'_>, value: &Tainted<Value>) -> Result<(), SkillError> {
        let effect = Recorded::new("crm")
            .payload(value.peek().clone())
            .read_only();
        cx.sink(effect, value).await?;
        Ok(())
    }

    #[async_trait::async_trait]
    impl Skill for Forwards {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new(self.0).provides(self.0)
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let wait = AwaitSpec::new("reply.received", "reply").correlate(key("D-1"));
            if matches!(self.1, Forward::InputAfterWaiting | Forward::Event) {
                cx.deadline("reply", &DeadlineSpec::days(5), None).await?;
            }
            let value = match self.1 {
                Forward::Input => input,
                Forward::InputAfterWaiting => {
                    cx.await_event(&wait).await?;
                    input
                }
                Forward::Event => cx.await_event(&wait).await?,
                Forward::CaseState => cx.case_state().await?.0,
                Forward::Commission => cx.commission("child", input).await?,
                #[cfg(feature = "manifest")]
                Forward::Specialist => cx.commission("specialist", input).await?,
            };
            send(cx, &value).await?;
            Ok(Outcome::done(Tainted::trusted(json!({}))))
        }
    }

    fn runtime(store: &Arc<RedbStore>) -> Arc<Runtime> {
        Runtime::builder(Arc::clone(store) as Arc<dyn JournalStore>)
            .cases(Arc::clone(store) as Arc<dyn CaseStore>)
            .events(Arc::clone(store) as Arc<dyn EventStore>)
            .skill(Forwards("input", Forward::Input))
            .skill(Forwards("waits", Forward::InputAfterWaiting))
            .skill(Forwards("event", Forward::Event))
            .skill(Forwards("state", Forward::CaseState))
            .skill(Forwards("parent", Forward::Commission))
            .skill(Forwards("child", Forward::Input))
            .build()
    }

    async fn report(store: &Arc<RedbStore>, subject: &str) -> SubjectReport {
        let journal = Arc::clone(store) as Arc<dyn JournalStore>;
        Trace::new("default")
            .report(&journal, store.as_ref(), subject, 100)
            .await
            .expect("a report")
    }

    fn terms(subject: Option<&str>) -> RunTerms {
        let terms = RunTerms::default().correlated("matter", &[key("D-1")]);
        match subject {
            Some(s) => terms.subject(s),
            None => terms,
        }
    }

    async fn run(
        rt: &Runtime,
        target: &str,
        subject: Option<&str>,
    ) -> agentplane::runtime::RunOutcome {
        let admission = rt
            .run_under(
                target,
                Tainted::trusted(json!({ "customer": "x" })),
                terms(subject),
            )
            .await
            .expect("admitted");
        admission.outcome().expect("a fresh run").clone()
    }

    fn reply(id: &str) -> InboundEvent {
        InboundEvent::new("urn:test:acme", id, "reply.received", json!({ "ok": true }))
            .correlate(key("D-1"))
    }

    /// The runs whose effects a report lists.
    fn traced_runs(report: &SubjectReport) -> Vec<agentplane::core::RunId> {
        report.effects.iter().map(|e| e.run).collect()
    }

    /// **Each subject's report lists exactly its own run's effect.**
    #[tokio::test]
    async fn a_subject_named_by_run_input_is_traced_to_the_tool_it_reached() {
        let store = Arc::new(RedbStore::open_in_memory().unwrap());
        let rt = runtime(&store);
        let a = run(&rt, "input", Some("cust-17")).await;
        let b = run(&rt, "input", Some("cust-18")).await;
        assert_eq!(a.status, RunStatus::Succeeded);

        let for_a = report(&store, "cust-17").await;
        assert_eq!(traced_runs(&for_a), vec![a.run_id], "{:#?}", for_a.effects);
        assert!(for_a.items.is_empty());
        let for_b = report(&store, "cust-18").await;
        assert_eq!(traced_runs(&for_b), vec![b.run_id], "{:#?}", for_b.effects);
        assert!(report(&store, "cust-19").await.effects.is_empty());
    }

    /// **The bound runs and their cases are listed**: the units a journal
    /// erasure acts on.
    #[tokio::test]
    async fn a_subject_report_names_the_runs_an_erasure_acts_on() {
        let store = Arc::new(RedbStore::open_in_memory().unwrap());
        let rt = runtime(&store);
        let a = run(&rt, "input", Some("cust-17")).await;
        run(&rt, "input", Some("cust-18")).await;
        let report = report(&store, "cust-17").await;
        assert_eq!(report.bound.len(), 1, "{:#?}", report.bound);
        assert_eq!(report.bound[0].run, a.run_id);
        assert!(
            report.bound[0].case.is_some(),
            "the run's case was not named"
        );
        assert_eq!(report.bound[0].binding, "named by the embedder");
        assert!(!report.bound[0].asserted);
    }

    /// **A reference crosses into the run a value reaches.** A commissioned
    /// run binds nothing of its own; its input carries the parent's binding.
    #[tokio::test]
    async fn a_child_run_forwarding_a_parents_input_is_traced() {
        let store = Arc::new(RedbStore::open_in_memory().unwrap());
        let rt = runtime(&store);
        let parent = run(&rt, "parent", Some("cust-17")).await;
        assert_eq!(parent.status, RunStatus::Succeeded);
        let report = report(&store, "cust-17").await;
        assert!(
            report.effects.iter().any(|e| e.run != parent.run_id),
            "the child's effect was not traced: {:#?}",
            report.effects
        );
    }

    /// **A subject the commissioned run bound is traced back past the
    /// delegation boundary.** The parent binds nothing; the specialist binds
    /// its input's customer and answers with it, and the parent's effect that
    /// forwards the answer is listed for that customer.
    #[cfg(feature = "manifest")]
    #[tokio::test]
    async fn a_subject_a_commissioned_run_bound_is_traced_in_its_parent() {
        #[derive(Debug)]
        struct Answers;

        #[async_trait::async_trait]
        impl Skill for Answers {
            fn descriptor(&self) -> SkillDescriptor {
                SkillDescriptor::new("specialist").provides("specialist")
            }
            async fn invoke(
                &self,
                _cx: &mut StepCtx<'_>,
                input: Tainted<Value>,
            ) -> Result<Outcome, SkillError> {
                Ok(Outcome::done(input))
            }
        }

        let manifest = agentplane::manifest::Manifest::parse(
            r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: specialist, version: "1.0.0" }
spec:
  budgets: { max_steps: 5 }
  capabilities:
    provides: [specialist]
  data_subjects: ["$input/customer"]
"#,
        )
        .expect("parse");
        let store = Arc::new(RedbStore::open_in_memory().unwrap());
        let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
            .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
            .events(Arc::clone(&store) as Arc<dyn EventStore>)
            .skill(Forwards("delegates", Forward::Specialist))
            .agent(agentplane::runtime::Agent::new(&manifest).skill(Answers))
            .build();
        let parent = run(&rt, "delegates", None).await;
        assert_eq!(parent.status, RunStatus::Succeeded, "{:?}", parent.status);
        let report = report(&store, "x").await;
        assert_eq!(report.bound.len(), 1, "{:#?}", report.bound);
        assert_ne!(report.bound[0].run, parent.run_id);
        assert_eq!(
            traced_runs(&report),
            vec![parent.run_id],
            "the parent's effect was not traced: {:#?}",
            report.effects
        );
    }

    /// **A resumed run attributes as the live one did**, read back from its
    /// `DataSubjectBound`, and its strict replay agrees with it.
    #[tokio::test]
    async fn a_bound_run_resumed_in_a_new_process_keeps_its_subject() {
        let store = Arc::new(RedbStore::open_in_memory().unwrap());
        let suspended = run(&runtime(&store), "waits", Some("cust-17")).await;
        assert!(suspended.status.is_suspended(), "{:?}", suspended.status);

        // A fresh runtime over the same store: nothing of the live run's
        // process survives.
        let resumed = runtime(&store);
        resumed.deliver(&reply("EV-1")).await.expect("delivered");
        let report = report(&store, "cust-17").await;
        assert_eq!(
            traced_runs(&report),
            vec![suspended.run_id],
            "the effect after the resume was not traced"
        );
        let verdict = runtime(&store)
            .verify(suspended.run_id)
            .await
            .expect("strict replay");
        assert!(
            matches!(verdict.finding, Finding::Verified { .. }),
            "{:?}",
            verdict.finding
        );
    }

    /// **An event delivered to a bound run is attributed to its subject.**
    #[tokio::test]
    async fn an_event_forwarded_by_a_bound_run_is_traced() {
        let store = Arc::new(RedbStore::open_in_memory().unwrap());
        let rt = runtime(&store);
        let bound = run(&rt, "event", Some("cust-17")).await;
        assert!(bound.status.is_suspended(), "{:?}", bound.status);
        rt.deliver(&reply("EV-1")).await.expect("delivered");
        let report = report(&store, "cust-17").await;
        assert_eq!(
            traced_runs(&report),
            vec![bound.run_id],
            "{:#?}",
            report.effects
        );
    }

    /// **Case state read by a bound run is attributed to its subject**; the
    /// same read by an unbound run is not, and is counted.
    #[tokio::test]
    async fn case_state_forwarded_by_a_bound_run_is_traced() {
        let store = Arc::new(RedbStore::open_in_memory().unwrap());
        let rt = runtime(&store);
        let bound = run(&rt, "state", Some("cust-17")).await;
        assert_eq!(bound.status, RunStatus::Succeeded, "{:?}", bound.status);
        run(&rt, "state", None).await;
        let report = report(&store, "cust-17").await;
        assert_eq!(
            traced_runs(&report),
            vec![bound.run_id],
            "{:#?}",
            report.effects
        );
        assert!(
            report
                .coverage
                .iter()
                .any(|c| c.class == agentplane::subject::Class::UnboundIngress && c.met),
            "the unbound run went uncounted"
        );
    }
}
