//! The durable formats, held to their own bytes.
//!
//! The journal is the plan of record, and the chain commits to the **wire
//! bytes** rather than to a re-serialized form. Two things follow that nothing
//! else in this suite checks:
//!
//! * **A shape change is invisible in a diff.** Reordering two fields, adding a
//!   `skip_serializing_if`, renaming a serde attribute — each changes the bytes
//!   every future record hashes, and each looks like a tidy-up in review. The
//!   golden corpus below is what makes such a change a failing test instead of
//!   a silent break with every journal ever written.
//! * **A reader must know what it is reading.** A record carries `v`, and a
//!   reader that writes it and never reads it back has a version field for
//!   decoration: a journal written one shape ahead parses cleanly, with the
//!   fields this build has never heard of dropped on the floor.
//!
//! # Regenerating the corpus
//!
//! ```sh
//! AGENTPLANE_BLESS_GOLDEN=1 cargo test --test trust format::
//! ```
//!
//! Deliberately a separate command, and deliberately not a `--fix`: a format
//! change until the freeze is a **hard cut**, which means every journal written
//! by an older build stops being readable. Blessing the corpus is the moment
//! somebody decides that, so it is a thing they type.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet};

use agentplane::core::{
    BudgetExceeded, Compensation, CorrelationKey, DeadlineState, DeclaredOutput, Digest,
    Disposition, EffectDescriptor, GroupOutcome, Label, Principal, QuarantineDecision, Recovery,
    Release, ReleaseScope, RunId, Sensitivity, SourceId, Spend, StepId, SuspendReason, SweptAction,
    Timestamp, Trust,
};
use agentplane::journal::{AgentIdentity, Record, RecordBody, RecordKind};
use serde_json::{Value, json};

/// A run id that does not move between runs of the suite.
///
/// The corpus is bytes, so every value in it has to be fixed. A generated id
/// would make the file differ on every regeneration and turn a real change into
/// noise nobody reads.
fn run() -> RunId {
    RunId::parse("run_01ARZ3NDEKTSV4RRFFQ69G5FAV").expect("a fixed run id")
}

fn at() -> Timestamp {
    Timestamp::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
}

fn digest() -> Digest {
    Digest::of(b"golden")
}

/// One sample of every record kind, in the order `kind_str` lists them.
///
/// Every field is set to something **non-default**, because a corpus of
/// defaults would hash identically whether a field existed or not — the exact
/// change it is here to catch. Optional fields are present for the same reason.
/// Split by subject only because a single list of twenty-seven runs past what
/// the lint allows; the order is still `kind_str`'s, so a vector's position in
/// the file matches its position in the corpus.
fn corpus() -> Vec<RecordKind> {
    let mut all = admission_and_plan();
    all.extend(effects());
    all.extend(case_and_time());
    all.extend(endings());
    all
}

/// How a run starts, and the matter and clock it runs against.
fn admission_and_plan() -> Vec<RecordKind> {
    vec![
        RecordKind::RunAdmitted {
            capability: "billing.settle".into(),
            governed_by: Some(Box::new(AgentIdentity {
                name: "settler".into(),
                version: "1.2.3".into(),
                digest: digest(),
                publisher: Some("acme".into()),
            })),
            input: json!({ "batch": "B-7" }),
            input_label: Label::untrusted(SourceId::new("event:inbound")),
            policy_bundle: Some(Box::new(agentplane::core::PolicyBundleIdentity::new(
                digest(),
                "acme/policy-v4",
            ))),
            canon: 1,
            idempotency_key: Some("acme.erp\u{1f}MSG-1".into()),
        },
        RecordKind::QuotaPassStarted {
            period: Some("2026-09".into()),
            release_slot: true,
        },
        RecordKind::PlanFrozen {
            steps: vec!["book".into(), "pay".into()],
            plan: json!({ "nodes": [{ "id": 0 }] }),
        },
        RecordKind::StepStarted {
            skill: "orders.book".into(),
        },
        RecordKind::StepFinished {
            outcome: "succeeded".into(),
        },
        RecordKind::Note {
            text: "the customer asked for a refund".into(),
        },
    ]
}

/// Waiting, and the obligations a wait is measured against.
fn case_and_time() -> Vec<RecordKind> {
    vec![
        RecordKind::RunSuspended {
            reason: SuspendReason::AwaitingEvent {
                kind: "acknowledgement.received".into(),
                correlation: vec![CorrelationKey::new("document", "INV-9")],
                until: at(),
            },
        },
        RecordKind::CaseBound {
            case_kind: "dispute".into(),
            opened: true,
            correlation: vec![CorrelationKey::new("document", "INV-9")],
        },
        RecordKind::DeadlineRegistered {
            name: "respond".into(),
            resolved_at: at(),
            calendar_digest: digest(),
        },
        RecordKind::DeadlineTransition {
            name: "respond".into(),
            from: DeadlineState::Pending,
            to: DeadlineState::Breached,
        },
    ]
}

/// The outward calls, and everything said about whether they landed.
fn effects() -> Vec<RecordKind> {
    vec![
        RecordKind::EffectStarted {
            descriptor: EffectDescriptor::new("payments.capture", json!({ "order": "SO-4711" })),
            recovery: Recovery::Idempotent {
                key: "SO-4711".into(),
            },
            mutates: true,
            attempt: 2,
            backoff_ms: 250,
            outbound_label: Some(Label::trusted()),
        },
        RecordKind::EffectDone {
            output: json!({ "charge": "ch_9RtQ" }),
            source: Some("acme.psp".into()),
            spend: Spend::tokens(70),
            declared: DeclaredOutput {
                trust: Trust::Untrusted,
                sensitivity: Sensitivity::Secret,
            },
        },
        RecordKind::EffectFailed {
            error: "the gateway timed out after 30s".into(),
            spend: Spend::tokens(70),
            disposition: Disposition::InDoubt,
            permanent: true,
        },
        RecordKind::EffectReconciled {
            disposition: Disposition::Landed,
            output: Some(json!({ "charge": "ch_9RtQ" })),
            spend: Spend::tokens(30),
            detail: Some("the provider's console lists it".into()),
            declared: Some(DeclaredOutput::untrusted()),
            asserted_by: Some("ada".into()),
        },
        RecordKind::StepCompensated {
            compensation: Compensation::Compensatable,
            outcome: "compensated".into(),
        },
        RecordKind::QuarantineDecided {
            decider: "ada".into(),
            reason: "two weeks of provider tickets; nobody can say".into(),
            decision: QuarantineDecision::Abandon,
        },
        RecordKind::GroupOpened {
            group: "settlement".into(),
            resources: vec!["ledger:acme".into()],
        },
        RecordKind::GroupSettled {
            group: "settlement".into(),
            outcome: GroupOutcome::Quarantined,
            detail: Some("a member is in doubt".into()),
        },
        RecordKind::BudgetRefused {
            limit: "effects".into(),
            used: "2 of 2".into(),
        },
        RecordKind::BudgetReadmitted {
            limit: "effects raised to 5".into(),
        },
        RecordKind::IdentityBound {
            chain: vec![Principal::new(
                "acme/ops",
                agentplane::core::Scope::of(["effect:perform"]),
            )],
        },
        RecordKind::PolicyDenied {
            reason: "the destination is not on this tenant's allowlist".into(),
            action: "effect:perform".into(),
            resource: "tool://payments/charge".into(),
        },
    ]
}

/// Ceilings, decisions, and how a run ends.
fn endings() -> Vec<RecordKind> {
    vec![
        RecordKind::Released {
            releaser: "ada".into(),
            release: Release::fields(
                ReleaseScope::trust(),
                ["/iban"],
                "four-eyes approval T-42",
                "tool://payments/charge",
                ["task:T-42"],
            ),
            label: Label::untrusted(SourceId::new("event:inbound")),
            field_labels: BTreeMap::from([(
                "/iban".to_owned(),
                Label::untrusted(SourceId::new("event:inbound")),
            )]),
            value: digest(),
        },
        RecordKind::RunCancelled {
            actor: "ada".into(),
            reason: "the counterparty withdrew".into(),
        },
        RecordKind::RunConcluded {
            outcome: "exhausted".into(),
            reason: Some("effect budget exhausted".into()),
            exhaustion: Some(BudgetExceeded::Effects {
                allowed: 2,
                used: 2,
            }),
            live_spend: Spend::tokens(140),
            chain_head: digest(),
        },
        RecordKind::BreakGlass {
            actor: "ada".into(),
            roles: vec!["incident-commander".into()],
            reason: "SEV-1: reading tenant acme under incident 4711".into(),
        },
        RecordKind::Swept {
            subject: "respond".into(),
            action: SweptAction::DeadlineBreached,
            detail: Some("the window closed unmet".into()),
        },
    ]
}

/// The body a sample is wrapped in.
///
/// Every routing field is present and non-default, so a change to *those* —
/// the fields the stores index on — is caught by the same vectors.
fn body(kind: RecordKind) -> RecordBody {
    RecordBody {
        seq: 7,
        run: run(),
        case: Some(agentplane::core::CaseId::parse("case_01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap()),
        step: Some(StepId(1)),
        phase: agentplane::core::Phase::Compensating,
        epoch: 3,
        v: kind.version(),
        effect_key: None,
        kind,
    }
}

fn golden_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/records.jsonl")
}

/// **The record format's own regression test.**
///
/// For every kind: the bytes this build writes, and the chain digest over them.
/// A mismatch is a format change — deliberate or not — and the message says
/// which kind moved and how to bless it once somebody has decided it was meant.
#[test]
fn every_record_kind_hashes_to_its_golden_vector() {
    let produced: Vec<String> = corpus()
        .into_iter()
        .map(|kind| {
            let name = kind.kind_str().to_owned();
            // Sealed, never re-serialized. `Record::seal` is the one function
            // every backend appends through, so these bytes and this digest
            // are what a store holds — and a vector derived any other way
            // pins a shape the runtime does not write, which is a corpus that
            // agrees with itself about a format nobody uses.
            let sealed = Record::seal(body(kind), Digest::ZERO).expect("a record seals");
            let line = json!({
                "kind": name,
                "hash": sealed.hash.to_hex(),
                "raw": String::from_utf8(sealed.raw().to_vec())
                    .expect("canonical records are UTF-8"),
            });
            serde_json::to_string(&line).expect("a vector serialises")
        })
        .collect();

    if std::env::var_os("AGENTPLANE_BLESS_GOLDEN").is_some() {
        std::fs::create_dir_all(golden_path().parent().expect("a parent")).expect("mkdir");
        std::fs::write(golden_path(), produced.join("\n") + "\n").expect("write");
        return;
    }

    let text = std::fs::read_to_string(golden_path()).expect(
        "tests/golden/records.jsonl is missing — regenerate it with \
         AGENTPLANE_BLESS_GOLDEN=1",
    );

    // Keyed by kind rather than compared line by line: the file's *order* is
    // presentation, and an assertion that depends on it reports "the format
    // changed" when two vectors were merely swapped — which is the failure
    // people learn to re-bless past without reading.
    let stored = by_kind(text.lines().filter(|l| !l.is_empty()));
    let produced = by_kind(produced.iter().map(String::as_str));

    for (kind, want) in &stored {
        let got = produced.get(kind).map_or("<no vector>", String::as_str);
        assert_eq!(
            want, got,
            "the wire form of {kind} changed. Every journal ever written hashes under the \
             old shape, so this is a hard cut rather than a diff — decide that \
             deliberately, then re-bless with AGENTPLANE_BLESS_GOLDEN=1"
        );
    }
    assert_eq!(
        stored.keys().collect::<Vec<_>>(),
        produced.keys().collect::<Vec<_>>(),
        "the corpus and the vector file disagree about which kinds exist"
    );
}

/// Vectors by the kind they pin, so a reordering is not a format change.
fn by_kind<'a>(lines: impl Iterator<Item = &'a str>) -> BTreeMap<String, String> {
    lines
        .map(|line| {
            let value: Value = serde_json::from_str(line).expect("each vector is JSON");
            let kind = value["kind"].as_str().expect("a vector names its kind");
            (kind.to_owned(), line.to_owned())
        })
        .collect()
}

/// The corpus covers every kind, so a new one cannot arrive unpinned.
///
/// Read from the source rather than from a count: a number here would be
/// updated by whoever added the kind, in the same commit, which is the case a
/// guard is not needed for. What it must catch is the kind added and forgotten.
#[test]
fn the_corpus_covers_every_record_kind() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/journal/record.rs"),
    )
    .expect("record.rs");
    let declared: BTreeSet<String> = src
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("Self::")?;
            let name: String = rest.chars().take_while(char::is_ascii_alphabetic).collect();
            l.contains("{ .. } => \"").then_some(name)
        })
        .collect();
    assert!(
        declared.len() > 20,
        "found {declared:?} — the guard is reading the wrong span rather than passing"
    );

    let covered: BTreeSet<String> = corpus().iter().map(|k| k.kind_str().to_owned()).collect();
    assert_eq!(
        declared, covered,
        "a record kind has no golden vector, so its bytes are pinned by nothing and a \
         change to them would break every journal silently"
    );
}

// ── What a reader does with bytes it does not fully understand ──────────────

/// **A version this build does not read is refused, not read anyway.**
///
/// The record parses — that is the whole danger. Its unknown fields would take
/// their serde defaults, and every decision downstream would be made over a
/// record nobody fully read.
#[test]
fn a_record_from_a_shape_this_build_does_not_know_is_refused() {
    let mut value = serde_json::to_value(body(RecordKind::StepStarted {
        skill: "orders.book".into(),
    }))
    .expect("serialises");
    value["v"] = json!(2);
    let raw = serde_json::to_vec(&value).expect("serialises");
    let hash = Digest::chain(Digest::ZERO, &raw);

    let err = Record::from_stored(raw, Digest::ZERO, hash).expect_err("a v2 record is not read");
    assert!(
        matches!(
            err,
            agentplane::core::StoreError::UnknownRecordVersion {
                version: 2,
                reads: 1,
                ..
            }
        ),
        "got {err:?}"
    );
}

/// And it is refused as a **version**, never as damage.
///
/// A rolling deploy that put a writer ahead of its readers must not reach an
/// operator as *the history has been altered*. That alarm has to stay
/// believable, so a build skew gets its own class — the same distinction the
/// sealed envelope draws for its own format byte.
#[test]
fn a_version_skew_is_not_reported_as_tampering() {
    let mut value = serde_json::to_value(body(RecordKind::StepStarted {
        skill: "orders.book".into(),
    }))
    .expect("serialises");
    value["v"] = json!(2);
    let raw = serde_json::to_vec(&value).expect("serialises");
    let hash = Digest::chain(Digest::ZERO, &raw);

    let err = Record::from_stored(raw, Digest::ZERO, hash).expect_err("refused");
    let lifted = agentplane::core::RuntimeError::from_store(err);
    assert!(
        !matches!(lifted, agentplane::core::RuntimeError::ChainBroken { .. }),
        "a version skew reported as a broken chain sends an operator to hunt tampering: \
         {lifted}"
    );
    assert!(
        lifted.to_string().contains("deploy readers before writers"),
        "the refusal has to say what to do about it: {lifted}"
    );
}

/// A field this build has never heard of is refused too, at the version it
/// claims to be.
///
/// The version gates *declared* evolution; this gates the undeclared kind — a
/// writer that extended a record and did not bump. There is no forward-tolerant
/// reading of a record here, and that is the policy rather than an oversight:
/// the fields a record carries are the inputs to authorization, retry and
/// recovery decisions, so a reader that drops one reaches a verdict over
/// evidence it did not see.
#[test]
fn a_field_this_build_does_not_know_is_refused() {
    let mut value = serde_json::to_value(body(RecordKind::StepStarted {
        skill: "orders.book".into(),
    }))
    .expect("serialises");
    value["settlement_id"] = json!("stl-1");
    let raw = serde_json::to_vec(&value).expect("serialises");
    let hash = Digest::chain(Digest::ZERO, &raw);

    let err = Record::from_stored(raw, Digest::ZERO, hash).expect_err("refused");
    assert!(
        err.to_string().contains("settlement_id"),
        "the refusal has to name the field nobody knows: {err}"
    );
}

/// **The upcaster seam, exercised end to end before it is needed.**
///
/// The first migration after the format freeze must not also be the first time
/// this mechanism runs. A stand-in upcaster lifts a record written at an older
/// shape — one that does not even parse into today's struct — and the read
/// succeeds, with `raw` and `hash` untouched: the chain commits to the bytes
/// that were written, whatever age of reader is looking at them.
#[test]
fn an_older_shape_is_lifted_and_the_hash_still_covers_the_written_bytes() {
    #[derive(Debug)]
    struct RenamedTheSkillField;

    impl agentplane::journal::Upcaster for RenamedTheSkillField {
        fn current_version(&self, _kind: &str) -> u16 {
            1
        }

        fn upcast(
            &self,
            kind: &str,
            version: u16,
            mut payload: Value,
        ) -> Result<Value, agentplane::core::StoreError> {
            if kind != "StepStarted" || version != 0 {
                return Err(agentplane::core::StoreError::UnknownRecordVersion {
                    kind: kind.to_owned(),
                    version,
                    reads: 1,
                });
            }
            let old = payload["name"].take();
            let object = payload.as_object_mut().expect("a record is an object");
            object.remove("name");
            object.insert("skill".into(), old);
            object.insert("v".into(), json!(1));
            Ok(payload)
        }
    }

    // A record as the older build wrote it: `name`, not `skill`, and v0. It
    // does not parse into this build's struct at all.
    let mut value = serde_json::to_value(body(RecordKind::StepStarted {
        skill: "orders.book".into(),
    }))
    .expect("serialises");
    let object = value.as_object_mut().expect("an object");
    object.remove("skill");
    object.insert("name".into(), json!("orders.book"));
    object.insert("v".into(), json!(0));
    let raw = serde_json::to_vec(&value).expect("serialises");
    let hash = Digest::chain(Digest::ZERO, &raw);

    assert!(
        Record::from_stored(raw.clone(), Digest::ZERO, hash).is_err(),
        "without an upcaster the older shape is refused, which is the default"
    );

    let record =
        Record::from_stored_with(&RenamedTheSkillField, raw.clone(), Digest::ZERO, hash, None)
            .expect("the upcaster lifts it");
    assert!(matches!(
        record.kind(),
        RecordKind::StepStarted { skill } if skill == "orders.book"
    ));
    assert_eq!(
        record.raw(),
        raw.as_slice(),
        "an upcast is a read-time view: the bytes the chain commits to are the ones that \
         were written, and rehashing the lifted form would destroy tamper evidence for \
         every record older than the reader"
    );
    assert_eq!(record.hash, hash);
    assert_eq!(
        Digest::chain(Digest::ZERO, record.raw()),
        hash,
        "and the link still verifies from the bytes alone"
    );
}

// ── The export format, pinned to an artifact rather than to this build ──────

/// **The artifact a third party verifies, frozen.**
///
/// An export is the one thing this project hands to somebody who does not have
/// the crate, and the promise attached to it is that it stays checkable. A test
/// that exports and then verifies in the same process proves only that the
/// build agrees with itself; what has to hold is that a *later* build still
/// reads a file this one wrote.
///
/// So the file is checked in, and this reads it back through the ordinary
/// verifier with no store and no network. Regenerate with the same
/// `AGENTPLANE_BLESS_GOLDEN=1` — and for the same reason: an export a future
/// build cannot verify is a broken promise, not a diff.
#[test]
fn a_frozen_export_still_verifies_offline() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/export.jsonl");

    if std::env::var_os("AGENTPLANE_BLESS_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(&path, frozen_export()).expect("write");
        return;
    }

    let bytes = std::fs::read(&path).expect(
        "tests/golden/export.jsonl is missing — regenerate it with AGENTPLANE_BLESS_GOLDEN=1",
    );
    let report = agentplane::export::verify(std::io::Cursor::new(&bytes), None, None)
        .expect("the file reads");

    assert!(
        report.findings.is_empty(),
        "a build that cannot verify an export this project published has broken the one \
         promise the artifact carries: {:?}",
        report.findings
    );
    assert_eq!(report.records, 3, "{report:?}");
    assert_eq!(report.sound.len(), 1, "{report:?}");
    assert_eq!(
        report.checkpoint.size, 1,
        "the checkpoint the file claims to be a copy of has to survive too"
    );

    assert_eq!(
        bytes,
        frozen_export(),
        "this build writes a different export for the same journal — the reader above \
         still accepted the old file, which is the half that matters, but a writer that \
         has drifted will hand the next auditor a file the last one cannot diff against"
    );
}

/// One sealed run **and one case**, written from fixed bytes so the file is
/// reproducible.
///
/// Deliberately not produced by running a skill: a run id is a ULID and a plan
/// is compiled, so an export taken from a live run differs on every regeneration
/// and a real change would arrive buried in noise.
///
/// The case layer is in the fixture because the format calls it mandatory. A
/// vector that carries only journal lines leaves the case block, its deadlines,
/// its blob digests and the cross-layer settlement — a record naming a matter
/// the file must also carry — with no checked-in bytes at all, in either this
/// implementation or a second one.
fn frozen_export() -> Vec<u8> {
    use agentplane::journal::{Append, JournalStore};
    use std::sync::Arc;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let redb = Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
        let store: Arc<dyn JournalStore> = redb.clone();
        let cases: Arc<dyn agentplane::case::CaseStore> = redb;
        let run = run();
        let case = agentplane::core::CaseId::parse("case_01ARZ3NDEKTSV4RRFFQ69G5FAV")
            .expect("a fixed case id");
        let at = agentplane::core::Timestamp::from_unix_timestamp(1_700_000_000)
            .expect("a fixed instant");
        cases
            .import_case(
                &agentplane::core::Case {
                    id: case,
                    kind: "billing.settlement".into(),
                    status: agentplane::core::CaseStatus::Open,
                    correlation: vec![agentplane::core::CorrelationKey::new("batch", "B-7")],
                    state: json!({ "stage": "settling" }),
                    version: agentplane::core::CaseVersion::INITIAL,
                    opened_at: at,
                    runs: vec![run],
                },
                &[agentplane::core::Deadline {
                    case,
                    name: "acknowledge".into(),
                    resolved_at: at,
                    calendar_digest: Digest::of(b"golden-calendar"),
                    warn_at: None,
                    state: agentplane::core::DeadlineState::Pending,
                    acknowledged: None,
                }],
                &[Digest::of(b"golden-artifact")],
            )
            .await
            .expect("import the case");
        let lease = store
            .acquire(run, "golden", std::time::Duration::from_secs(60))
            .await
            .expect("lease");
        store
            .append(
                lease.epoch,
                vec![
                    Append::new(
                        run,
                        RecordKind::RunAdmitted {
                            capability: "billing.settle".into(),
                            governed_by: None,
                            input: json!({ "batch": "B-7" }),
                            input_label: Label::trusted(),
                            policy_bundle: None,
                            canon: agentplane::core::canon::VERSION,
                            idempotency_key: None,
                        },
                    ),
                    // Stamped with the case, so the file exercises the
                    // cross-layer settlement: a record naming a matter the
                    // export must also carry.
                    Append::new(
                        run,
                        RecordKind::StepStarted {
                            skill: "orders.book".into(),
                        },
                    )
                    .step(StepId(0))
                    .case(case),
                ],
            )
            .await
            .expect("append");
        let head = store.head(run).await.expect("head");
        store
            .append(
                lease.epoch,
                vec![Append::new(
                    run,
                    RecordKind::RunConcluded {
                        outcome: "succeeded".into(),
                        reason: None,
                        exhaustion: None,
                        live_spend: Spend::ZERO,
                        chain_head: head.hash,
                    },
                )],
            )
            .await
            .expect("conclude");
        store
            .seal(run, lease.epoch, "succeeded")
            .await
            .expect("seal");

        let mut out = Vec::new();
        agentplane::export::to_jsonl(&store, Some(&cases), &[run], &mut out)
            .await
            .expect("export");
        out
    })
}
