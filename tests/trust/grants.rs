//! The grants an agent never used, read from an export.
//!
//! The report may call a grant unused only where every call under its digest
//! was readable, and the proposal it emits may only remove whole grants.

#![cfg(all(feature = "redb", feature = "manifest"))]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::core::{Digest, EffectDescriptor, EffectKey, Label, Recovery, RunId, StepId};
use agentplane::grants::{Declaration, GrantReport, Grants, Mark, MenuRow};
use agentplane::journal::{AgentIdentity, Append, JournalStore, RecordKind};
use agentplane::manifest::Manifest;
use agentplane::store::RedbStore;
use serde_json::{Value, json};

const A: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: desk, version: "1.0.0" }
spec:
  capabilities: { provides: [desk.support] }
  budgets: { max_steps: 25, max_egress_bytes: 1000 }
  tools:
    - ref: tool://crm/read
      mutates: false
      max_sensitivity: internal
    - ref: tool://crm/send
      mutates: true
      max_sensitivity: internal
      protected_fields:
        - path: /recipient
          one_of: [ops, audit, legal, sales]
    - ref: tool://crm/purge
      mutates: true
      max_sensitivity: internal
"#;

/// Two called tools, then an unused read-only tool, then an unused approval
/// tool whose preview names the read-only one.
const B: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: archivist, version: "1.0.0" }
spec:
  capabilities: { provides: [desk.archive] }
  models: { privileged: { provider: fake, model: m-1 } }
  execution: { kind: tool-calling, max_turns: 4 }
  oversight:
    approval: tools-only
    deadline: { name: purge-review, kind: hours, params: { n: 4 } }
  tools:
    - ref: tool://crm/read
      mutates: false
      max_sensitivity: internal
      description: Read a record.
    - ref: tool://crm/send
      mutates: false
      max_sensitivity: internal
      description: Send a record.
      requires_approval: true
    - ref: tool://archive/purge_preview
      mutates: false
      max_sensitivity: internal
      description: Count what a purge would delete.
    - ref: tool://archive/purge
      mutates: true
      description: Delete every record older than a date.
      requires_approval: true
      preview: tool://archive/purge_preview
      protected_fields:
        - path: /older_than
          allowed_sources: [model:fake/m-1]
          max_sensitivity: internal
  budgets: {}
"#;

fn identity(m: &Manifest) -> AgentIdentity {
    AgentIdentity {
        name: m.metadata.name.clone(),
        version: m.metadata.version.clone(),
        digest: m.digest().unwrap(),
        publisher: None,
    }
}

fn admitted(run: RunId, governed_by: Option<AgentIdentity>) -> Append {
    Append::new(
        run,
        RecordKind::RunAdmitted {
            capability: "desk.support".into(),
            governed_by: governed_by.map(Box::new),
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

fn effect(run: RunId, ordinal: u32, kind: &str, args: Value, bytes: Option<u64>) -> Append {
    Append::new(
        run,
        RecordKind::EffectStarted {
            descriptor: EffectDescriptor::new(kind, args),
            recovery: Recovery::Retry,
            mutates: false,
            attempt: 1,
            backoff_ms: 0,
            outbound_label: Some(Label::trusted()),
            outbound_bytes: bytes,
            content_rules: None,
            credential: None,
        },
    )
    .step(StepId(ordinal))
    .effect(EffectKey::from_hex(&format!("{ordinal:064x}")).expect("a key"))
}

fn call(run: RunId, ordinal: u32, server: &str, tool: &str, args: &Value, bytes: u64) -> Append {
    effect(
        run,
        ordinal,
        "tool.call",
        json!({ "server": server, "tool": tool, "arguments": args }),
        Some(bytes),
    )
}

fn refused(run: RunId) -> Append {
    Append::new(
        run,
        RecordKind::PolicyDenied {
            reason: "rule `no-purge` forbids it".into(),
            action: "effect:perform".into(),
            resource: "tool.call".into(),
        },
    )
}

type Run = Box<dyn FnOnce(RunId) -> Vec<Append>>;

/// A's runs: `read` once, `send` twice with two menu values, `purge` never;
/// plus one run under a digest nobody supplied and one code-tier run.
fn corpus(a: &Manifest, refusal: bool) -> Vec<Run> {
    let gov = Some(identity(a));
    let gov2 = gov.clone();
    let other = Some(AgentIdentity {
        digest: Digest::of(b"another revision"),
        ..gov.clone().unwrap()
    });
    vec![
        Box::new(move |run| {
            let mut r = vec![
                admitted(run, gov),
                call(run, 1, "crm", "read", &json!({}), 100),
                call(run, 2, "crm", "send", &json!({ "recipient": "ops" }), 300),
            ];
            if refusal {
                r.push(refused(run));
            }
            r
        }) as Run,
        Box::new(move |run| {
            vec![
                admitted(run, gov2),
                call(run, 1, "crm", "send", &json!({ "recipient": "audit" }), 50),
                effect(run, 2, "ledger.read", json!({}), None),
            ]
        }) as Run,
        Box::new(move |run| {
            vec![
                admitted(run, other),
                call(run, 1, "crm", "purge", &json!({}), 5),
            ]
        }) as Run,
        Box::new(move |run| {
            vec![
                admitted(run, None),
                call(run, 1, "crm", "purge", &json!({}), 5),
            ]
        }) as Run,
    ]
}

async fn write(journal: &Arc<dyn JournalStore>, runs: Vec<Run>) -> Vec<RunId> {
    let mut ids = Vec::new();
    for records in runs {
        let run = RunId::generate();
        let lease = journal
            .acquire(run, "grants", std::time::Duration::from_mins(1))
            .await
            .unwrap();
        journal.append(lease.epoch, records(run)).await.unwrap();
        ids.push(run);
    }
    ids
}

async fn export(journal: &Arc<dyn JournalStore>, runs: &[RunId]) -> Vec<u8> {
    let mut out = Vec::new();
    agentplane::export::to_jsonl(journal, &crate::no_cases(), runs, &mut out)
        .await
        .expect("export");
    out
}

async fn exported(runs: Vec<Run>) -> Vec<u8> {
    let journal = Arc::new(RedbStore::open_in_memory().unwrap()) as Arc<dyn JournalStore>;
    let ids = write(&journal, runs).await;
    export(&journal, &ids).await
}

async fn grants(manifests: &[Manifest], file: &[u8]) -> GrantReport {
    Grants::new(manifests).run(file).await.expect("a report")
}

fn marks(report: &GrantReport, i: usize) -> Vec<(String, Mark)> {
    report.digests[i]
        .grants
        .iter()
        .map(|g| (g.reference.clone(), g.mark))
        .collect()
}

fn supplied(report: &GrantReport) -> usize {
    report
        .digests
        .iter()
        .position(|d| matches!(d.declaration, Declaration::Supplied { .. }))
        .expect("the supplied digest is reported")
}

/// **Only the uncalled grant is unused**, attributed by reference; runs under
/// an unsupplied digest and code-tier runs are rows of their own; menus,
/// egress and the window are reported.
#[tokio::test]
async fn only_the_uncalled_grant_is_unused() {
    let a = Manifest::parse(A).unwrap();
    let file = exported(corpus(&a, false)).await;
    let report = grants(std::slice::from_ref(&a), &file).await;

    assert_eq!(report.digests.len(), 3);
    let declarations: Vec<_> = report
        .digests
        .iter()
        .map(|d| d.declaration.clone())
        .collect();
    assert!(declarations.contains(&Declaration::NotSupplied));
    assert!(declarations.contains(&Declaration::None));
    let i = supplied(&report);
    let row = &report.digests[i];
    assert_eq!(row.runs, 2);
    assert_eq!(
        marks(&report, i),
        vec![
            ("tool://crm/read".into(), Mark::Used),
            ("tool://crm/send".into(), Mark::Used),
            ("tool://crm/purge".into(), Mark::Unused),
        ]
    );
    assert_eq!((row.grants[1].calls, row.grants[1].runs), (2, 2));

    let MenuRow::Counted {
        chosen, unchosen, ..
    } = &row.grants[1].menus[0]
    else {
        panic!("a readable menu was not counted: {:?}", row.grants[1].menus);
    };
    assert_eq!(chosen.len(), 2);
    assert_eq!(unchosen, &["legal", "sales"]);

    let e = &row.egress;
    assert_eq!(
        (e.min, e.max, e.ceiling, e.headroom),
        (Some(50), Some(400), Some(1000), Some(600))
    );
    assert_eq!(e.uncounted, 1);

    assert_eq!(report.window.runs, 4);
    assert!(report.window.complete());
    let text = report.to_string();
    assert!(text.starts_with("window: 4 runs"), "{text}");
    assert!(text.contains("export: complete"));

    // The same file with its trailer cut is incomplete, and says so first.
    let cut: Vec<u8> = String::from_utf8(file)
        .unwrap()
        .lines()
        .filter(|l| !l.contains("agentplane.export.end"))
        .flat_map(|l| format!("{l}\n").into_bytes())
        .collect();
    let partial = grants(std::slice::from_ref(&a), &cut).await;
    assert!(!partial.window.complete());
    assert!(partial.partial());
    assert!(
        partial
            .to_string()
            .lines()
            .nth(1)
            .unwrap()
            .contains("INCOMPLETE")
    );
}

/// **A refusal is not plain unused**: no record names the refused grant.
#[tokio::test]
async fn a_refused_call_is_not_reported_unused() {
    let a = Manifest::parse(A).unwrap();
    let file = exported(corpus(&a, true)).await;
    let report = grants(std::slice::from_ref(&a), &file).await;
    let i = supplied(&report);
    assert_eq!(report.digests[i].refusals.get("tool.call"), Some(&1));
    assert_eq!(
        report.digests[i].grants[2].mark,
        Mark::UnusedRefusalsNotAttributable
    );
    let proposal = report.digests[i].proposal.as_ref().unwrap();
    assert_eq!(proposal.removed, Vec::<String>::new());
    assert!(!report.has_unused());
}

/// **The proposal only removes**: its tools are a subsequence of the input's,
/// each equal to its input grant, and every other field is the input's.
#[tokio::test]
async fn the_proposal_never_adds_or_widens() {
    let a = Manifest::parse(A).unwrap();
    let file = exported(corpus(&a, false)).await;
    let report = grants(std::slice::from_ref(&a), &file).await;
    let proposal = report.digests[supplied(&report)].proposal.clone().unwrap();
    assert_eq!(proposal.removed, vec!["tool://crm/purge".to_owned()]);

    let tools = &proposal.manifest.spec.tools;
    let mut input = a.spec.tools.iter();
    for kept in tools {
        assert!(
            input.any(|g| g == kept),
            "the proposal holds a grant the input does not, or changed one: {kept:?}"
        );
    }
    assert_eq!(tools.len(), a.spec.tools.len() - 1);
    let mut restored = proposal.manifest.clone();
    restored.spec.tools.clone_from(&a.spec.tools);
    assert_eq!(
        restored, a,
        "the proposal changed a field outside its tools"
    );
    proposal
        .manifest
        .validate()
        .expect("the proposal validates");
}

/// **A removal validation refuses is not made**, and is named.
#[tokio::test]
async fn a_removal_that_breaks_validation_is_not_made() {
    let b = Manifest::parse(B).unwrap();
    let file = exported(vec![Box::new({
        let gov = Some(identity(&b));
        move |run| {
            vec![
                admitted(run, gov),
                call(run, 1, "crm", "read", &json!({}), 10),
                call(run, 2, "crm", "send", &json!({}), 10),
            ]
        }
    }) as Run])
    .await;
    let report = grants(std::slice::from_ref(&b), &file).await;
    let proposal = report.digests[0].proposal.clone().unwrap();
    assert_eq!(
        proposal.removed,
        vec!["tool://archive/purge".to_owned()],
        "{:?}",
        proposal.kept
    );
    assert_eq!(proposal.kept.len(), 1);
    assert_eq!(proposal.kept[0].0, "tool://archive/purge_preview");
    proposal
        .manifest
        .validate()
        .expect("the proposal validates");
}

/// **A sealed call is not no call.** Without a ring nothing args-dependent is
/// derivable and no grant is unused; with one, every call is attributed; an
/// erased call is counted erased.
#[cfg(all(feature = "keyring", feature = "testkit"))]
#[tokio::test]
async fn every_args_dependent_figure_is_not_derivable_when_sealed() {
    use agentplane::core::{TenantId, Timestamp};
    use agentplane::keyring::{KeyRing, SealedJournal};
    use agentplane::testkit::MemoryKeyRing;

    let a = Manifest::parse(A).unwrap();
    let tenant = TenantId::default();
    let ring = Arc::new(MemoryKeyRing::default()) as Arc<dyn KeyRing>;
    let raw = Arc::new(RedbStore::open_in_memory().unwrap()) as Arc<dyn JournalStore>;
    let sealed = SealedJournal::wrap(Arc::clone(&raw), Arc::clone(&ring), tenant.clone())
        as Arc<dyn JournalStore>;
    let runs = write(&sealed, corpus(&a, false)).await;
    let file = export(&sealed, &runs).await;

    let blind = grants(std::slice::from_ref(&a), &file).await;
    let i = supplied(&blind);
    let row = &blind.digests[i];
    assert_eq!(row.sealed, 3, "every tool call under the digest is sealed");
    assert!(
        row.grants.iter().all(|g| g.mark == Mark::NotEstablished),
        "{:?}",
        marks(&blind, i)
    );
    assert!(matches!(
        row.grants[1].menus[0],
        MenuRow::NotDerivable { .. }
    ));
    assert_eq!(
        row.egress.max,
        Some(400),
        "bytes are clear on a sealed plane"
    );
    assert_eq!(row.proposal.as_ref().unwrap().removed, Vec::<String>::new());
    assert!(blind.to_string().contains("unused is not established"));

    let keyed = Grants::new(std::slice::from_ref(&a))
        .with_keys(tenant.as_str(), ring.as_ref())
        .run(file.as_slice())
        .await
        .unwrap();
    let i = supplied(&keyed);
    assert_eq!(keyed.digests[i].grants[2].mark, Mark::Unused);
    assert_eq!(keyed.digests[i].grants[1].calls, 2);

    agentplane::blob::erase_run(
        ring.as_ref(),
        None,
        &tenant,
        runs[1],
        Timestamp::from_unix_timestamp(1_760_000_000).unwrap(),
        "subject exercised the right to erasure",
    )
    .await
    .unwrap();
    let file = export(&sealed, &runs).await;
    let erased = Grants::new(std::slice::from_ref(&a))
        .with_keys(tenant.as_str(), ring.as_ref())
        .run(file.as_slice())
        .await
        .unwrap();
    let i = supplied(&erased);
    assert_eq!(erased.digests[i].erased, 1);
    assert_eq!(erased.digests[i].grants[2].mark, Mark::NotEstablished);
}
