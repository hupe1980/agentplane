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

/// An operator for a fixture, on the weakest basis a real caller could present.
///
/// `Asserted`: a suite that only built the authenticated form would leave the
/// basis a store persists untested on the path an incident actually takes.
fn operator(actor: &str) -> agentplane::core::Operator {
    agentplane::core::Operator::asserted(actor).expect("a fixture names its operator")
}

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
            admitted_by: None,
            served_unchained: false,
            plane_chain: false,
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
/// A label naming a data subject, so the vector pins the reference's wire shape.
fn subject_bound_label() -> Label {
    let mut label = Label::trusted();
    label.data_subjects.insert(agentplane::core::SubjectRef {
        run: run(),
        index: 0,
    });
    label
}

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
            outbound_label: Some(subject_bound_label()),
            outbound_bytes: None,
            content_rules: Some(vec!["pan".into(), "codename".into()]),
            credential: Some(agentplane::core::CredentialBinding::Subject {
                audience: "settlement".into(),
                subject: "alice".into(),
            }),
        },
        RecordKind::EffectDone {
            output: json!({ "charge": "ch_9RtQ" }),
            source: Some("acme.psp".into()),
            by: None,
            spend: Spend::tokens(70),
            declared: DeclaredOutput {
                trust: Trust::Untrusted,
                sensitivity: Sensitivity::Secret,
            },
            content: Some(agentplane::core::ContentVerdict {
                rules: vec!["aws-key".into()],
                sensitivity: Some(Sensitivity::Secret),
                refused: Some(agentplane::core::ContentRefusal {
                    rule: "aws-key".into(),
                    pointer: "/notes/*".into(),
                }),
            }),
            elapsed_ms: Some(1840),
        },
        RecordKind::EffectFailed {
            error: "the gateway timed out after 30s".into(),
            spend: Spend::tokens(70),
            disposition: Disposition::InDoubt,
            permanent: true,
            elapsed_ms: Some(30_000),
        },
        RecordKind::EffectReconciled {
            disposition: Disposition::Landed,
            output: Some(json!({ "charge": "ch_9RtQ" })),
            spend: Spend::tokens(30),
            // A person asserted this, so their account is the clear `note`
            // and the provider-facing `detail` is empty. The vector carried
            // the operator's own sentence in `detail` — which is the
            // conflation the two fields now separate.
            detail: None,
            note: Some("the provider's console lists it".into()),
            declared: Some(DeclaredOutput::untrusted()),
            asserted_by: Some(operator("ada")),
        },
        RecordKind::StepCompensated {
            compensation: Compensation::Compensatable,
            outcome: "compensated".into(),
        },
        RecordKind::QuarantineDecided {
            decider: operator("ada"),
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
        RecordKind::AuthorityWithheld {
            subject: "acme/ops".into(),
            reason: "credential withdrawn: laptop lost".into(),
            by: operator("ops"),
        },
        RecordKind::AuthorityRestored {
            subject: "acme/ops".into(),
        },
        RecordKind::IdentityBound {
            chain: vec![Principal::new(
                "acme/ops",
                agentplane::core::Scope::of(["effect:perform"]),
            )],
        },
        RecordKind::DataSubjectBound {
            bindings: vec![
                agentplane::journal::BoundSubject {
                    index: 0,
                    binding: agentplane::journal::SubjectBinding::Input {
                        pointer: "/customer/id".into(),
                    },
                    trusted: false,
                    subject: "cust-17".into(),
                },
                agentplane::journal::BoundSubject {
                    index: 1,
                    binding: agentplane::journal::SubjectBinding::Case,
                    trusted: true,
                    // The record's own case, which is what `$case` resolves to.
                    subject: "case_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
                },
            ],
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
            actor: operator("ada"),
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
            actor: operator("ada"),
            roles: vec!["incident-commander".into()],
            reason: "SEV-1: reading tenant acme under incident 4711".into(),
        },
        RecordKind::HaltLifted {
            scope: "agent:payments-clerk".into(),
            by: operator("carol"),
            at: at(),
            reason: "INC-4711: refunds misrouted".into(),
            thrown_by: operator("bob"),
            thrown_at: at(),
        },
        RecordKind::HoldReleased {
            by: operator("carol"),
            at: at(),
            placed_by: operator("bob"),
            placed_at: at(),
        },
        RecordKind::Swept {
            subject: "respond".into(),
            action: SweptAction::DeadlineBreached,
            detail: Some("the window closed unmet".into()),
        },
        RecordKind::Observed {
            session: "sess_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            reported: agentplane::core::ObservedStep::Decision {
                call: "call_1".into(),
                outcome: agentplane::core::ObservedDecision::Selected {
                    option: "allow".into(),
                    kind: "allow_once".into(),
                },
            },
            detail: Some("write to src/main.rs".into()),
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
            // Canonical, not `serde_json::to_string`. The envelope's own key
            // order is not a property of the record format, and it was
            // nevertheless load-bearing: each line is compared as a *string*,
            // and `serde_json::Map` orders by insertion when anything in the
            // build enables `preserve_order` and by sort when nothing does.
            // Nothing here asks for it — `cedar-policy` does, and so did a
            // dev-dependency — so the corpus passed under `--all-features` and
            // under the default set for two different reasons, and removing an
            // unrelated dev-dependency made the default set disagree with a
            // file that had not moved.
            //
            // `canon::to_bytes` is the writer this crate already owns for
            // exactly this: its order comes from the canonicalizer rather than
            // from whichever map serde_json happened to compile.
            String::from_utf8(
                agentplane::core::canon::to_bytes(&line).expect("a vector serialises"),
            )
            .expect("canonical JSON is UTF-8")
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

    let err = Record::from_stored_signed(raw, Digest::ZERO, hash, None)
        .expect_err("a v2 record is not read");
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

/// **A field this build does not know is refused at a version it does know.**
///
/// The version check above cannot see this one. Every durable version here is
/// `1` until the format freezes, and a hard cut changes a shape without touching
/// it, so *same version, different shape* is the skew this format actually meets
/// — and the arm that would catch a version difference is never taken for it.
///
/// What refuses it is `deny_unknown_fields` on `RecordKind`, which is flattened
/// into the body. That pairing is a serde combination with its own caveats
/// rather than an obvious one, so it is pinned here: a reader that took serde's
/// defaults for a field it could not see would decide over a record it had not
/// fully read, which is the same danger the version arm exists for.
#[test]
fn a_record_with_a_field_this_build_does_not_know_is_refused() {
    let mut value = serde_json::to_value(body(RecordKind::StepStarted {
        skill: "orders.book".into(),
    }))
    .expect("serialises");
    value
        .as_object_mut()
        .expect("a record body is an object")
        .insert("smuggled".into(), json!("x"));
    let raw = serde_json::to_vec(&value).expect("serialises");
    let hash = Digest::chain(Digest::ZERO, &raw);

    let err = Record::from_stored_signed(raw, Digest::ZERO, hash, None)
        .expect_err("an unknown field is not read past");
    assert!(
        matches!(
            err,
            agentplane::core::StoreError::UnreadableRecordShape { version: 1, .. }
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

    let err = Record::from_stored_signed(raw, Digest::ZERO, hash, None).expect_err("refused");
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

    let err = Record::from_stored_signed(raw, Digest::ZERO, hash, None).expect_err("refused");
    assert!(
        err.to_string().contains("settlement_id"),
        "the refusal has to name the field nobody knows: {err}"
    );
}

/// **A member nobody knows is refused inside the payload too, at every depth
/// the record's own types reach.**
///
/// The top-level refusal covers the record's fields and none of the structs
/// they hold. A nested struct that skipped an unknown member let a writer
/// extend an effect descriptor, a spend, a principal or a label and have
/// this reader decide over the part it happened to know. Every nested object
/// the record types own is listed here, taken from the golden corpus; free
/// payload values (`input`, `output`, `args`, `plan`) are the caller's JSON
/// and are not on the list.
#[test]
fn a_member_nobody_knows_is_refused_inside_the_payload() {
    const NESTED: &[(&str, &str)] = &[
        ("RunAdmitted", "/governed_by"),
        ("RunAdmitted", "/input_label"),
        ("RunAdmitted", "/policy_bundle"),
        ("EffectStarted", "/descriptor"),
        ("EffectStarted", "/outbound_label"),
        ("EffectStarted", "/outbound_label/data_subjects/0"),
        ("EffectStarted", "/recovery"),
        ("EffectDone", "/declared"),
        ("EffectDone", "/spend"),
        ("EffectFailed", "/spend"),
        ("EffectReconciled", "/asserted_by"),
        ("EffectReconciled", "/declared"),
        ("IdentityBound", "/chain/0"),
        ("DataSubjectBound", "/bindings/0"),
        ("DataSubjectBound", "/bindings/0/binding"),
        ("RunSuspended", "/reason"),
        ("RunSuspended", "/reason/correlation/0"),
        ("CaseBound", "/correlation/0"),
        ("Released", "/label"),
        ("Released", "/field_labels/~1iban"),
        ("Released", "/release"),
        ("RunConcluded", "/exhaustion"),
        ("RunConcluded", "/live_spend"),
        ("RunCancelled", "/actor"),
        ("QuarantineDecided", "/decider"),
        ("AuthorityWithheld", "/by"),
        ("BreakGlass", "/actor"),
        ("HaltLifted", "/by"),
        ("HaltLifted", "/thrown_by"),
        ("HoldReleased", "/by"),
        ("HoldReleased", "/placed_by"),
        ("Observed", "/reported"),
        ("Observed", "/reported/outcome"),
    ];
    let golden = std::fs::read_to_string(golden_path()).expect("the golden corpus");
    let mut accepted = Vec::new();
    for (kind, pointer) in NESTED {
        let line = golden
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).expect("json"))
            .find(|v| v["kind"] == json!(kind))
            .unwrap_or_else(|| panic!("no golden {kind}"));
        let mut body: Value =
            serde_json::from_str(line["raw"].as_str().expect("raw")).expect("json");
        assert!(
            serde_json::from_value::<RecordBody>(body.clone()).is_ok(),
            "the golden {kind} does not parse unedited"
        );
        body.pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("golden {kind} has no object at {pointer}"))
            .insert("smuggled".into(), json!(1));
        if serde_json::from_value::<RecordBody>(body).is_ok() {
            accepted.push(format!("{kind}{pointer}"));
        }
    }
    assert!(
        accepted.is_empty(),
        "a member nobody knows was read past inside: {accepted:?}"
    );
}

/// **The skew a hard cut produces is classified, and it is the only skew a
/// pre-freeze deployment can meet.**
///
/// The version gates *declared* evolution, and until the format freezes
/// nothing declares: a shape change is a hard cut and `v` stays at 1 on both
/// sides of it. So the arm that names a build skew and says which binary to
/// run is the arm no shipped change reaches, while every rolling deploy this
/// project has actually performed lands on the other one — which handed an
/// operator `invalid type: map, expected a string at line 1 column 388`.
///
/// Read against a real pair of builds rather than imagined: between two
/// releases five record kinds moved `actor` from a string to a struct and one
/// gained a field, at `v` 1 throughout. Each direction refuses the other's
/// records, which is the hard cut working; what was missing was the sentence
/// saying so.
///
/// The classification is safe to make because of the order the read happens
/// in. The stored hash is verified before the body is parsed, so a record that
/// reaches the parse carries the bytes that were written and the chain commits
/// to them. A failure after that point cannot be an edit.
#[test]
fn a_shape_this_build_cannot_read_at_its_own_version_is_a_build_skew() {
    for (case, mutate) in [
        // The undeclared field: a later build extended the record.
        (
            "an added field",
            (|value: &mut Value| value["settlement_id"] = json!("stl-1")) as fn(&mut Value),
        ),
        // The moved type: the shape of a field a later build kept the name of.
        // This is the one that actually happened, five kinds at once.
        ("a field whose type moved", |value: &mut Value| {
            value["skill"] = json!({ "name": "orders.book", "basis": "asserted" });
        }),
    ] {
        let mut value = serde_json::to_value(body(RecordKind::StepStarted {
            skill: "orders.book".into(),
        }))
        .expect("serialises");
        mutate(&mut value);
        let raw = serde_json::to_vec(&value).expect("serialises");
        let hash = Digest::chain(Digest::ZERO, &raw);

        let err = Record::from_stored_signed(raw, Digest::ZERO, hash, None).expect_err("refused");
        assert!(
            matches!(
                err,
                agentplane::core::StoreError::UnreadableRecordShape { ref kind, version: 1, .. }
                    if kind == "StepStarted"
            ),
            "{case}: a shape skew reported as an encoding fault: {err:?}"
        );

        let lifted = agentplane::core::RuntimeError::from_store(err);
        assert!(
            !matches!(lifted, agentplane::core::RuntimeError::ChainBroken { .. }),
            "{case}: a build skew reported as a broken chain sends an operator to hunt \
             tampering: {lifted}"
        );
        let text = lifted.to_string();
        assert!(
            text.contains("hash as written"),
            "{case}: the refusal has to say the bytes are intact, or it reads as damage: \
             {text}"
        );
        assert!(
            text.contains("another build wrote this journal"),
            "{case}: the refusal has to name the remedy: {text}"
        );
    }
}

/// Bytes that are not a record keep the parse error, which is the answer.
///
/// The arm above claims a skew from two facts: the hash verified, and the
/// bytes name a kind at a version. Without the second there is nobody to
/// blame — a blob that hashes correctly and is not a record is not evidence
/// that somebody is running a different build.
#[test]
fn bytes_that_are_not_a_record_are_still_an_encoding_fault() {
    let raw = br#"{"not":"a record"}"#.to_vec();
    let hash = Digest::chain(Digest::ZERO, &raw);

    let err = Record::from_stored_signed(raw, Digest::ZERO, hash, None).expect_err("refused");
    assert!(
        matches!(err, agentplane::core::StoreError::Encoding(_)),
        "a line with no kind and no version cannot be attributed to a build: {err:?}"
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
        Record::from_stored_signed(raw.clone(), Digest::ZERO, hash, None).is_err(),
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
    let report = agentplane::export::verify(std::io::Cursor::new(&bytes), None, &[])
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

/// **A disclosure package, frozen, in both readers.** The package of the golden
/// case verifies with its one disclosed leaf proved by its path; with one
/// sibling of that path altered, both readers refuse it.
#[test]
fn a_frozen_package_verifies_by_its_paths_in_both_readers() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/package.jsonl");
    if std::env::var_os("AGENTPLANE_BLESS_GOLDEN").is_some() {
        std::fs::write(&path, frozen_package()).expect("write");
        return;
    }
    let bytes = std::fs::read(&path).expect(
        "tests/golden/package.jsonl is missing — regenerate it with AGENTPLANE_BLESS_GOLDEN=1",
    );
    assert_eq!(
        bytes,
        frozen_package(),
        "this build writes a different package"
    );
    let report = agentplane::export::verify(std::io::Cursor::new(&bytes), None, &[])
        .expect("the file reads");
    assert!(report.is_sound(), "{report:#?}");
    assert_eq!(report.sound, vec![run()], "{report:?}");
    assert_eq!(
        report.checkpoint.size, 3,
        "two undisclosed leaves around the one disclosed"
    );

    let damaged = damaged_sibling(&bytes);
    let report = agentplane::export::verify(std::io::Cursor::new(&damaged), None, &[])
        .expect("the file reads");
    assert!(report.sound.is_empty(), "{report:#?}");

    let second = |file: &[u8], name: &str| {
        let dir =
            std::env::temp_dir().join(format!("agentplane-package-reader-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let at = dir.join(name);
        std::fs::write(&at, file).expect("write");
        let out = std::process::Command::new("python3")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg("tools/verify_export.py")
            .arg(&at)
            .output()
            .expect("python3 runs the second reader");
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let (status, said) = second(&bytes, "package.jsonl");
    assert_eq!(
        status,
        Some(0),
        "the second reader refuses the golden package:\n{said}"
    );
    let (status, said) = second(&damaged, "damaged.jsonl");
    assert_eq!(
        status,
        Some(1),
        "the second reader accepts a damaged path:\n{said}"
    );
}

/// `bytes` with the first sibling of the first path flipped in its last bit.
fn damaged_sibling(bytes: &[u8]) -> Vec<u8> {
    let mut out = String::new();
    let mut done = false;
    for line in std::str::from_utf8(bytes).expect("utf-8").lines() {
        let mut value: Value = serde_json::from_str(line).expect("a JSON line");
        if !done && let Some(first) = value.get_mut("proof").and_then(|p| p.get_mut(0)) {
            let hex = first.as_str().expect("hex").to_owned();
            let last = u8::from_str_radix(&hex[62..], 16).expect("hex") ^ 1;
            *first = Value::String(format!("{}{last:02x}", &hex[..62]));
            done = true;
        }
        out.push_str(&serde_json::to_string(&value).expect("serialise"));
        out.push('\n');
    }
    assert!(done, "the package carries a path");
    out.into_bytes()
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
///
/// One literal journal, top to bottom, so its length is the fixture's.
fn frozen_export() -> Vec<u8> {
    golden_export(None)
}

/// The fixed journal, appended through a store that signs each record as
/// `signer` when one is given — the production signing path, so a signed
/// export differs from the unsigned one only in its `signature` members.
fn golden_export(signer: Option<std::sync::Arc<dyn agentplane::core::Signer>>) -> Vec<u8> {
    golden_file_of(signer, false)
}

/// The golden journal with a case-less run sealed on each side of it, disclosed
/// as a package of its case: the disclosed leaf sits at position 1 of 3, so its
/// path carries two siblings a reader must use.
fn frozen_package() -> Vec<u8> {
    golden_file_of(None, true)
}

/// A run with an admission and a conclusion, sealed — a leaf for the package's
/// tree and nothing else.
async fn seal_bare(store: &std::sync::Arc<dyn agentplane::journal::JournalStore>, run: RunId) {
    use agentplane::journal::Append;
    let lease = store
        .acquire(run, "golden", std::time::Duration::from_secs(60))
        .await
        .expect("lease");
    store
        .append(
            lease.epoch,
            vec![Append::new(
                run,
                RecordKind::RunAdmitted {
                    capability: "billing.audit".into(),
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
            )],
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
}

#[allow(clippy::too_many_lines)]
fn golden_file_of(
    signer: Option<std::sync::Arc<dyn agentplane::core::Signer>>,
    package: bool,
) -> Vec<u8> {
    use agentplane::journal::{Append, JournalStore};
    use std::sync::Arc;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let mut redb = agentplane::store::RedbStore::open_in_memory().expect("store");
        if let Some(signer) = signer {
            redb = redb.signing_as(signer);
        }
        let redb = Arc::new(redb);
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
        // Held, so the hold member carries a value rather than `null` and its
        // shape is pinned by bytes a second reader can check.
        cases
            .place_hold(
                case,
                &agentplane::core::LegalHold {
                    placed_at: at,
                    reason: "litigation L-12".into(),
                    by: agentplane::core::Operator::authenticated("counsel@example")
                        .expect("an operator"),
                },
            )
            .await
            .expect("hold the case");
        if package {
            seal_bare(
                &store,
                RunId::parse("run_01ARZ3NDEKTSV4RRFFQ69G5FAA").expect("a fixed run id"),
            )
            .await;
        }
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
                            admitted_by: None,
                            served_unchained: false,
                            plane_chain: false,
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
        if package {
            seal_bare(
                &store,
                RunId::parse("run_01ARZ3NDEKTSV4RRFFQ69G5FAB").expect("a fixed run id"),
            )
            .await;
            let selection = agentplane::export::Selection {
                cases: vec![case],
                runs: Vec::new(),
            };
            agentplane::export::package_to_jsonl(&store, &cases, &selection, &mut out)
                .await
                .expect("package");
        } else {
            agentplane::export::to_jsonl(&store, &cases, &[run], &mut out)
                .await
                .expect("export");
        }
        out
    })
}

// ── The signed golden artifacts ─────────────────────────────────────────────
//
// The same journal as the unsigned export, signed through the production path,
// plus a witness cosignature over its checkpoint and a signed grader verdict
// over a prefix of its run. A second reader checks every signature in these
// files against the public keys in `tests/golden/keys.txt`.

/// Published test material for the record key — never a deployment key.
#[cfg(feature = "signing")]
const RECORD_SEED: [u8; 32] = [0x52; 32];
/// Published test material for the witness key — never a deployment key.
#[cfg(feature = "signing")]
const WITNESS_SEED: [u8; 32] = [0x57; 32];
/// Published test material for the grader key — never a deployment key.
#[cfg(feature = "signing")]
const GRADER_SEED: [u8; 32] = [0x47; 32];
/// The instant the golden witness claims it saw the log.
#[cfg(feature = "signing")]
const WITNESS_AT: i64 = 1_700_000_600;

#[cfg(feature = "signing")]
fn record_signer() -> agentplane::policy::Ed25519Signer {
    agentplane::policy::Ed25519Signer::new("golden-record", &RECORD_SEED)
}

#[cfg(feature = "signing")]
fn witness_signer() -> agentplane::policy::Ed25519Signer {
    agentplane::policy::Ed25519Signer::new("golden-witness", &WITNESS_SEED)
}

#[cfg(feature = "signing")]
fn grader_signer() -> agentplane::policy::Ed25519Signer {
    agentplane::policy::Ed25519Signer::new("golden-grader", &GRADER_SEED)
}

#[cfg(feature = "signing")]
fn signed_frozen_export() -> Vec<u8> {
    golden_export(Some(std::sync::Arc::new(record_signer())))
}

/// The signed export's checkpoint as a `signed-note`, cosigned once by the
/// golden witness at [`WITNESS_AT`].
#[cfg(feature = "signing")]
fn cosigned_golden_note() -> String {
    use agentplane::journal::{MemoryWitness, NoteSignature, SignedNote, Witness as _};

    let export = signed_frozen_export();
    let checkpoint = agentplane::export::verify(std::io::Cursor::new(&export), None, &[])
        .expect("the export reads")
        .checkpoint;
    let signer = witness_signer();
    let public = signer.verifying_key();
    let witness = MemoryWitness::new(
        std::sync::Arc::new(signer),
        Timestamp::from_unix_timestamp(WITNESS_AT).expect("a fixed instant"),
    )
    .expect("a witness");
    let cosignature = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime")
        .block_on(witness.cosign(&checkpoint, 0, &[]))
        .expect("cosign");
    SignedNote::new(checkpoint.to_note())
        .expect("a note body")
        .with_signature(NoteSignature {
            name: "golden-witness".into(),
            key_id: agentplane::journal::key_id("golden-witness", 0x04, &public),
            signature: cosignature.signature,
        })
        .expect("a valid name")
        .to_wire()
}

/// A grader verdict bound to the first two records of the signed export's run
/// and signed by the golden grader, written as `bind` writes a sidecar.
#[cfg(feature = "signing")]
fn signed_golden_sidecar() -> String {
    let export = signed_frozen_export();
    let mut sidecar = agentplane::grader_verdict::bind(
        std::io::Cursor::new(&export),
        run(),
        Some(2),
        b"pass".to_vec(),
    )
    .expect("bind");
    sidecar.sign(&grader_signer());
    serde_json::to_string_pretty(&sidecar).expect("serialise") + "\n"
}

/// The three public keys, one flag per line, in the form each flag takes.
#[cfg(feature = "signing")]
fn golden_keys() -> String {
    use base64::Engine as _;
    format!(
        "--key golden-record={}\n--witness-key golden-witness={}\n--grader-key golden-grader={}\n",
        hex::encode(record_signer().verifying_key()),
        base64::engine::general_purpose::STANDARD.encode(witness_signer().verifying_key()),
        hex::encode(grader_signer().verifying_key()),
    )
}

#[cfg(feature = "signing")]
fn golden_file(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name)
}

/// The signed golden files and the producer each is written by.
#[cfg(feature = "signing")]
fn signed_golden_files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("export.signed.jsonl", signed_frozen_export()),
        (
            "checkpoint.cosigned.note",
            cosigned_golden_note().into_bytes(),
        ),
        (
            "export.grader-verdict.json",
            signed_golden_sidecar().into_bytes(),
        ),
        ("keys.txt", golden_keys().into_bytes()),
    ]
}

#[cfg(feature = "signing")]
fn read_golden(name: &str) -> Vec<u8> {
    std::fs::read(golden_file(name)).unwrap_or_else(|e| {
        panic!("tests/golden/{name}: {e} — regenerate it with AGENTPLANE_BLESS_GOLDEN=1")
    })
}

/// **The signed artifacts, frozen.** Every record of the signed export
/// verifies under the golden record key, and every file is the bytes its
/// producer writes today — signing is deterministic, so a drift is a change to
/// what an auditor's second reader is checked against. Regenerate with
/// `AGENTPLANE_BLESS_GOLDEN=1`.
#[cfg(feature = "signing")]
#[test]
fn a_signed_frozen_export_still_verifies_offline() {
    if std::env::var_os("AGENTPLANE_BLESS_GOLDEN").is_some() {
        for (name, bytes) in signed_golden_files() {
            std::fs::write(golden_file(name), bytes).expect("write");
        }
        return;
    }

    let bytes = read_golden("export.signed.jsonl");
    let verifier = agentplane::policy::Ed25519Verifier::new()
        .trust("golden-record", &record_signer().verifying_key())
        .expect("a key");
    let report = agentplane::export::verify(std::io::Cursor::new(&bytes), Some(&verifier), &[])
        .expect("the file reads");
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.records, 3, "{report:?}");
    assert_eq!(report.sound.len(), 1, "{report:?}");
    let signed = String::from_utf8(bytes)
        .expect("utf-8")
        .lines()
        .filter(|l| l.contains("\"key_id\":\"golden-record\""))
        .count();
    assert_eq!(
        signed, 3,
        "every record line carries the golden record signature"
    );

    for (name, produced) in signed_golden_files() {
        assert_eq!(
            read_golden(name),
            produced,
            "tests/golden/{name} is not what this build writes — a second reader is checked \
             against these bytes; re-bless with AGENTPLANE_BLESS_GOLDEN=1 once that is meant"
        );
    }
}

/// **Both readers, one verdict — the Rust half.** The signed export is sound
/// under the golden record key, and the signed sidecar is bound under the
/// golden grader key. The second reader's half runs the same files through
/// `tools/verify_export.py`.
#[cfg(feature = "signing")]
#[test]
fn the_signed_golden_artifacts_verify_in_both_readers() {
    let export = read_golden("export.signed.jsonl");
    let records = agentplane::policy::Ed25519Verifier::new()
        .trust("golden-record", &record_signer().verifying_key())
        .expect("a key");
    let graders = agentplane::policy::Ed25519Verifier::new()
        .trust("golden-grader", &grader_signer().verifying_key())
        .expect("a key");
    let checked = agentplane::grader_verdict::check(
        std::io::Cursor::new(&export),
        Some(&records),
        &[],
        &[read_golden("export.grader-verdict.json")],
        Some(&graders),
    )
    .expect("the export reads");
    assert!(
        checked.export.findings.is_empty(),
        "{:?}",
        checked.export.findings
    );
    assert_eq!(checked.sidecars.len(), 1);
    assert_eq!(
        checked.sidecars[0].status,
        agentplane::grader_verdict::Status::Bound,
        "{:?}",
        checked.sidecars[0]
    );
}

/// The second reader's flags for every golden key.
#[cfg(feature = "signing")]
fn golden_key_flags() -> Vec<String> {
    String::from_utf8(read_golden("keys.txt"))
        .expect("utf-8")
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// Run `tools/verify_export.py` over `export` written to a scratch file, with
/// `args` after it: its exit status and its standard output. A missing
/// interpreter fails the test — `just ci` needs it anyway.
#[cfg(feature = "signing")]
fn second_reader(name: &str, export: &[u8], args: &[String]) -> (i32, String) {
    let dir = std::env::temp_dir().join(format!("agentplane-second-reader-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join(format!("{name}.jsonl"));
    std::fs::write(&path, export).expect("write");
    let out = std::process::Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("tools/verify_export.py")
        .arg(&path)
        .args(args)
        .output()
        .expect("python3 runs the second reader");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    (out.status.code().unwrap_or(-1), format!("{stdout}{stderr}"))
}

/// The second reader's own self-test reports every case.
///
/// The self-test is where each strictness rule meets a signature that verifies
/// but for that rule; running it here is what lets a mutation of the reader be
/// killed by `cargo test`.
#[test]
fn the_second_readers_self_test_reports_every_case() {
    let out = std::process::Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "tools/verify_export.py",
            "tests/golden/export.jsonl",
            "--self-test",
        ])
        .output()
        .expect("python3 runs the second reader");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("every case reported"),
        "the second reader's self-test missed a case:\n{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The signed export's lines, parsed; the record lines are those carrying `raw`.
#[cfg(feature = "signing")]
fn signed_lines() -> Vec<Value> {
    String::from_utf8(read_golden("export.signed.jsonl"))
        .expect("utf-8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("a JSON line"))
        .collect()
}

#[cfg(feature = "signing")]
fn record_index(lines: &[Value], seq: u64) -> usize {
    lines
        .iter()
        .position(|l| l.get("raw").is_some() && l["seq"] == seq)
        .expect("a record at that seq")
}

#[cfg(feature = "signing")]
fn joined(lines: &[Value]) -> Vec<u8> {
    let mut out = String::new();
    for line in lines {
        out.push_str(&serde_json::to_string(line).expect("serialise"));
        out.push('\n');
    }
    out.into_bytes()
}

/// A signature over record `seq`'s chain hash under `domain` by `signer`, as
/// the export's `signature` member carries it, labelled `key_id`.
#[cfg(feature = "signing")]
fn resigned(
    lines: &[Value],
    seq: u64,
    domain: &str,
    signer: &dyn agentplane::core::Signer,
    key_id: &str,
) -> Value {
    let hash = Digest::from_hex(
        lines[record_index(lines, seq)]["hash"]
            .as_str()
            .expect("hash"),
    )
    .expect("a digest");
    let signature = signer.sign(&agentplane::core::signing_hash(domain, &hash));
    json!({ "key_id": key_id, "signature": hex::encode(signature) })
}

/// The record-signature damage cases: a name, the damaged lines, and the seq
/// the second reader must name.
#[cfg(feature = "signing")]
fn record_signature_damage() -> Vec<(&'static str, Vec<Value>, u64)> {
    use agentplane::core::{DOMAIN_MANIFEST, DOMAIN_RECORD};
    let clean = signed_lines();
    let (one, two) = (record_index(&clean, 1), record_index(&clean, 2));
    let mut cases = Vec::new();

    let mut flipped = clean.clone();
    let hex = flipped[two]["signature"]["signature"]
        .as_str()
        .expect("hex")
        .to_owned();
    let mut bytes = hex::decode(hex).expect("hex");
    bytes[10] ^= 0x01;
    flipped[two]["signature"]["signature"] = json!(hex::encode(bytes));
    cases.push(("one signature byte flipped", flipped, 2));

    let mut swapped = clean.clone();
    let first = swapped[one]["signature"].clone();
    swapped[one]["signature"] = swapped[two]["signature"].clone();
    swapped[two]["signature"] = first;
    cases.push(("a signature swapped between two records", swapped, 1));

    let mut stripped = clean.clone();
    stripped[two]["signature"] = Value::Null;
    cases.push(("a signature set to null", stripped, 2));

    let mut manifest = clean.clone();
    manifest[two]["signature"] = resigned(
        &clean,
        2,
        DOMAIN_MANIFEST,
        &record_signer(),
        "golden-record",
    );
    cases.push(("a record re-signed under the manifest domain", manifest, 2));

    let mut renamed = clean.clone();
    renamed[two]["signature"]["key_id"] = json!("golden-nobody");
    cases.push(("a key id nobody supplied", renamed, 2));

    let other = agentplane::policy::Ed25519Signer::new("golden-other", &[0x4f; 32]);
    let mut mislabelled = clean.clone();
    mislabelled[two]["signature"] = resigned(&clean, 2, DOMAIN_RECORD, &other, "golden-record");
    cases.push((
        "a second supplied key's signature labelled as the first",
        mislabelled,
        2,
    ));

    // S + L: the same group element, a second spelling of a valid signature.
    // Ed25519 requires S < L; without that rule a signature is malleable.
    let mut non_canonical = clean;
    let hex = non_canonical[two]["signature"]["signature"]
        .as_str()
        .expect("hex")
        .to_owned();
    let mut bytes = hex::decode(hex).expect("hex");
    let order: [u8; 32] = {
        let mut l = [0u8; 32];
        l[..16].copy_from_slice(&0x14de_f9de_a2f7_9cd6_5812_631a_5cf5_d3ed_u128.to_le_bytes());
        l[31] = 0x10;
        l
    };
    let mut carry = 0u16;
    for (byte, add) in bytes[32..].iter_mut().zip(order) {
        let sum = u16::from(*byte) + u16::from(add) + carry;
        let [low, high] = sum.to_le_bytes();
        *byte = low;
        carry = u16::from(high);
    }
    non_canonical[two]["signature"]["signature"] = json!(hex::encode(bytes));
    cases.push(("a signature with S + L in place of S", non_canonical, 2));

    cases
}

/// The golden key flags of one kind (`--key`, `--witness-key`,
/// `--grader-key`), each followed by its value.
#[cfg(feature = "signing")]
fn key_flags(kind: &str) -> Vec<String> {
    golden_key_flags()
        .chunks(2)
        .filter(|pair| pair[0] == kind)
        .flat_map(<[String]>::to_vec)
        .collect()
}

/// Write `bytes` beside the second reader's scratch exports, returning the path.
#[cfg(feature = "signing")]
fn scratch(name: &str, bytes: &[u8]) -> String {
    let dir = std::env::temp_dir().join(format!("agentplane-second-reader-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write");
    path.display().to_string()
}

/// The golden note's body, its one line's name, and that line's decoded
/// `key_id ‖ timestamp ‖ signature`.
#[cfg(feature = "signing")]
fn golden_note_parts() -> (String, String, Vec<u8>) {
    use base64::Engine as _;
    let note = String::from_utf8(read_golden("checkpoint.cosigned.note")).expect("utf-8");
    let (body, lines) = note.split_once("\n\n").expect("a signed note");
    let (name, encoded) = lines
        .trim_end()
        .strip_prefix("\u{2014} ")
        .and_then(|l| l.split_once(' '))
        .expect("one signature line");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("base64");
    (format!("{body}\n"), name.to_owned(), decoded)
}

#[cfg(feature = "signing")]
fn note_from(body: &str, name: &str, decoded: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    format!(
        "{body}\n\u{2014} {name} {}\n",
        base64::engine::general_purpose::STANDARD.encode(decoded)
    )
    .into_bytes()
}

/// The cosignature damage cases: a name and the damaged note.
#[cfg(feature = "signing")]
fn cosignature_damage() -> Vec<(&'static str, Vec<u8>)> {
    let (body, name, clean) = golden_note_parts();
    let mut cases = Vec::new();
    let mut flipped = clean.clone();
    flipped[12 + 10] ^= 0x01;
    cases.push((
        "a cosignature byte flipped",
        note_from(&body, &name, &flipped),
    ));
    let mut retimed = clean.clone();
    retimed[11] ^= 0x01;
    cases.push((
        "the payload's timestamp edited",
        note_from(&body, &name, &retimed),
    ));
    let edited = body.replacen("agentplane\n", "agentplanf\n", 1);
    assert_ne!(edited, body, "the golden note's origin line is agentplane");
    cases.push(("a body line edited", note_from(&edited, &name, &clean)));
    let mut renumbered = clean.clone();
    renumbered[0] ^= 0x01;
    cases.push((
        "the key id changed with the name kept",
        note_from(&body, &name, &renumbered),
    ));
    cases.push((
        "the name changed with the key id kept",
        note_from(&body, "golden-witnesz", &clean),
    ));
    let mut short = clean.clone();
    short.pop();
    cases.push(("a payload of 71 bytes", note_from(&body, &name, &short)));
    let mut zero = clean;
    zero[4..12].fill(0);
    cases.push(("a zero timestamp", note_from(&body, &name, &zero)));
    cases
}

/// The grader-verdict damage cases: a name and the damaged sidecar.
#[cfg(feature = "signing")]
fn sidecar_damage() -> Vec<(&'static str, Vec<u8>)> {
    use agentplane::core::DOMAIN_RECORD;
    let clean: Value =
        serde_json::from_slice(&read_golden("export.grader-verdict.json")).expect("json");
    let mut cases = Vec::new();
    let mut swapped = clean.clone();
    swapped["content"] = json!("ZmFpbA==");
    cases.push(("the verdict's content swapped", swapped));
    let mut record_domain = clean.clone();
    let sidecar: agentplane::grader_verdict::Sidecar =
        serde_json::from_value(clean.clone()).expect("a sidecar");
    let digest = sidecar.signing_digest();
    record_domain["signature"]["signature"] = json!(hex::encode(agentplane::core::Signer::sign(
        &grader_signer(),
        &agentplane::core::signing_hash(DOMAIN_RECORD, &digest)
    )));
    cases.push(("re-signed under the record domain", record_domain));
    let mut unsigned = clean;
    unsigned
        .as_object_mut()
        .expect("object")
        .remove("signature");
    cases.push(("the signature removed", unsigned));
    cases
        .into_iter()
        .map(|(name, value)| (name, serde_json::to_vec_pretty(&value).expect("serialise")))
        .collect()
}

/// **The second reader checks every signature in the signed golden
/// artifacts.** Clean, every record signature verifies under the golden key
/// and the reader says how many it verified; each damaged copy is a finding
/// naming the run and the record. A mutation row against the second reader is
/// killed here, because its own self-test is not something `cargo test` runs.
#[cfg(feature = "signing")]
#[test]
fn the_second_reader_checks_every_signature_in_the_signed_golden_artifacts() {
    let mut keys = golden_key_flags();
    let other = agentplane::policy::Ed25519Signer::new("golden-other", &[0x4f; 32]);
    keys.extend([
        "--key".to_owned(),
        format!("golden-other={}", hex::encode(other.verifying_key())),
    ]);
    let record_keys: Vec<String> = keys
        .chunks(2)
        .filter(|pair| pair[0] == "--key")
        .flat_map(<[String]>::to_vec)
        .collect();

    let (status, out) = second_reader("clean", &read_golden("export.signed.jsonl"), &record_keys);
    assert_eq!(status, 0, "the signed golden export must verify:\n{out}");
    assert!(
        out.contains("3 record signatures verified"),
        "the reader must say it verified every record signature — a reader that checked \
         nothing would also exit 0:\n{out}"
    );

    let run = run();
    for (name, lines, seq) in record_signature_damage() {
        let (status, out) = second_reader(name, &joined(&lines), &record_keys);
        assert_eq!(status, 1, "{name}: the second reader accepted it:\n{out}");
        let named = format!("run {run}: record {seq}'s signature");
        assert!(
            out.lines()
                .any(|l| l.starts_with("finding:") && l.contains(&named)),
            "{name}: no finding named {named:?}:\n{out}"
        );
    }

    let export = read_golden("export.signed.jsonl");
    second_reader_checks_cosignatures(&export);
    second_reader_checks_grader_signatures(&export);
}

/// The cosignature and freshness half of the signed-artifact test. The golden
/// witness signed at `WITNESS_AT`, which is 2023-11-14T22:23:20Z.
#[cfg(feature = "signing")]
fn second_reader_checks_cosignatures(export: &[u8]) {
    let note = scratch(
        "checkpoint.cosigned.note",
        &read_golden("checkpoint.cosigned.note"),
    );
    let witness = key_flags("--witness-key");
    let with = |anchor: &str, extra: &[&str]| -> Vec<String> {
        let mut args = vec![anchor.to_owned()];
        args.extend(witness.iter().cloned());
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        args
    };
    let (status, out) = second_reader("cosigned", export, &with(&note, &[]));
    assert_eq!(status, 0, "the cosigned golden note must verify:\n{out}");
    assert!(
        out.contains("is cosigned by golden-witness at 2023-11-14T22:23:20Z"),
        "the reader must name the witness and its signed time:\n{out}"
    );
    for (name, damaged) in cosignature_damage() {
        let path = scratch(&format!("{name}.note"), &damaged);
        let (_, out) = second_reader(name, export, &with(&path, &[]));
        assert!(
            out.contains("is not cosigned") && !out.contains("is cosigned by"),
            "{name}: the second reader honoured the line:\n{out}"
        );
    }

    // Freshness, against a fixed clock.
    let age = ["--max-checkpoint-age", "60"];
    let fresh = [&age[..], &["--now", "2023-11-14T22:23:50Z"]].concat();
    let (status, out) = second_reader("fresh", export, &with(&note, &fresh));
    assert_eq!(status, 0, "a witness 30 s old under a 60 s maximum:\n{out}");
    let stale = [&age[..], &["--now", "2023-11-14T22:25:20Z"]].concat();
    let (status, out) = second_reader("stale", export, &with(&note, &stale));
    assert_eq!(
        status, 1,
        "a witness 120 s old under a 60 s maximum:\n{out}"
    );
    assert!(
        out.lines().any(|l| l.starts_with("finding:")
            && l.contains("golden-witness is stale")
            && l.contains("120 s old")),
        "no stale finding naming the witness:\n{out}"
    );
    let ahead = [&age[..], &["--now", "2023-11-14T22:21:20Z"]].concat();
    let (status, out) = second_reader("ahead", export, &with(&note, &ahead));
    assert_eq!(
        status, 1,
        "a witness 120 s ahead under a 60 s maximum:\n{out}"
    );
    assert!(
        out.lines().any(|l| l.starts_with("finding:")
            && l.contains("golden-witness")
            && l.contains("120 s ahead")),
        "no time-ahead finding naming the witness:\n{out}"
    );
    // A line that does not verify carries a fresh time, and it is not judged.
    let (_, unverified) = cosignature_damage().swap_remove(0);
    let path = scratch("unverified.note", &unverified);
    let at = [&age[..], &["--now", "2023-11-14T22:23:20Z"]].concat();
    let (status, out) = second_reader("unverified", export, &with(&path, &at));
    assert_eq!(
        status, 0,
        "an uncosigned anchor that matches is not a finding:\n{out}"
    );
    assert!(
        out.contains("not checked: freshness — a maximum age was given and no anchor"),
        "an unverified time was judged:\n{out}"
    );
}

/// The grader-verdict half of the signed-artifact test.
#[cfg(feature = "signing")]
fn second_reader_checks_grader_signatures(export: &[u8]) {
    let graders = key_flags("--grader-key");
    let sidecar = scratch(
        "export.grader-verdict.json",
        &read_golden("export.grader-verdict.json"),
    );
    let mut args = vec!["--grader-verdict".to_owned(), sidecar.clone()];
    args.extend(graders.iter().cloned());
    let (status, out) = second_reader("graded", export, &args);
    assert_eq!(status, 0, "the signed golden sidecar must hold:\n{out}");
    assert!(
        out.contains(": holds") && out.contains("signed by grader key 'golden-grader'"),
        "the reader must name the grader key:\n{out}"
    );
    let (status, out) = second_reader(
        "ungraded",
        export,
        &["--grader-verdict".to_owned(), sidecar],
    );
    assert_eq!(status, 0, "{out}");
    assert!(
        out.contains("no --grader-key was given, so who signed the verdict is not checked"),
        "without a grader key the signature is not checked, and says so:\n{out}"
    );
    for (name, damaged) in sidecar_damage() {
        let path = scratch(&format!("{name}.json"), &damaged);
        let mut args = vec!["--grader-verdict".to_owned(), path];
        args.extend(graders.iter().cloned());
        let (status, out) = second_reader(name, export, &args);
        assert_eq!(status, 1, "{name}: the second reader accepted it:\n{out}");
        assert!(
            out.contains(": refused (signature)"),
            "{name}: not refused naming signature:\n{out}"
        );
    }
}

/// **Both readers refuse the same damaged sidecars, naming the same
/// component.** The library half of the second reader's sidecar cases.
#[cfg(feature = "signing")]
#[test]
fn the_damaged_golden_sidecars_are_refused_by_both_readers() {
    let export = read_golden("export.signed.jsonl");
    let records = agentplane::policy::Ed25519Verifier::new()
        .trust("golden-record", &record_signer().verifying_key())
        .expect("a key");
    let graders = agentplane::policy::Ed25519Verifier::new()
        .trust("golden-grader", &grader_signer().verifying_key())
        .expect("a key");
    for (name, damaged) in sidecar_damage() {
        let checked = agentplane::grader_verdict::check(
            std::io::Cursor::new(&export),
            Some(&records),
            &[],
            &[damaged],
            Some(&graders),
        )
        .expect("the export reads");
        let report = &checked.sidecars[0];
        assert_eq!(
            (report.status, report.component),
            (
                agentplane::grader_verdict::Status::Refused,
                Some(agentplane::grader_verdict::Component::Signature)
            ),
            "{name}: {report:?}"
        );
    }
}

/// **The artifact says what it never carries, on every pass.**
///
/// A restored plane's runs and cases come back; the operational rows beside them
/// do not. A webhook delivery cursor and a worklist decision no run has consumed
/// are store rows rather than records, so nothing in this file can reconstruct
/// them — and an operator who reads a clean report and is told nothing concludes
/// the restore was total. Both losses degrade safely (a cursor costs repetition,
/// a decision is taken again under the same four-eyes), which is the argument for
/// leaving them out; saying so is what stops that argument from being silent.
///
/// Asserted against an export with **no case layer**, which is the half that
/// matters: these are properties of the format, not of a file that happens to
/// reference something, so a statement made only where cases are carried would
/// be absent from exactly the minimal artifact a reader is most likely to meet.
#[tokio::test]
async fn an_export_names_the_operational_state_it_cannot_carry() {
    let store = std::sync::Arc::new(agentplane::store::RedbStore::open_in_memory().unwrap());
    let s = store.clone() as std::sync::Arc<dyn agentplane::journal::JournalStore>;
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&s, &crate::no_cases(), &[], &mut out)
        .await
        .expect("an empty export still writes a header and a trailer");

    let report =
        agentplane::export::verify(std::io::Cursor::new(&out), None, &[]).expect("the file reads");
    let said = report.not_checked.join("\n");
    assert!(
        said.contains("webhook delivery cursors"),
        "the artifact does not say it carries no delivery cursors: {said}"
    );
    assert!(
        said.contains("worklist decisions no run has consumed"),
        "the artifact does not say it carries no unconsumed worklist decisions: {said}"
    );
}

// ── An upgrade across a shape change, rehearsed ──────────────────────────────

/// The frozen export, one record shape older than this build writes.
///
/// No build writes an older version, so the older build's output is crafted
/// from the frozen export: its `StepStarted` record moved to the older shape and
/// the file re-linked around it.
#[cfg(feature = "testkit")]
fn older_export() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/export.jsonl");
    agentplane::testkit::older_shape::older_shape(
        &std::fs::read_to_string(path).expect("tests/golden/export.jsonl"),
    )
}

/// Every record line's `(raw, hash)`, in file order.
#[cfg(feature = "testkit")]
fn written(export: &str) -> Vec<(String, String)> {
    export
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|l| l.get("kind").is_none())
        .map(|l| {
            (
                l["raw"].as_str().expect("raw").to_owned(),
                l["hash"].as_str().expect("hash").to_owned(),
            )
        })
        .collect()
}

/// **An export at an older record shape verifies under an upcaster that
/// reaches it, and is a skew — never an edit — under one that does not.**
///
/// The verifier compares the record's version before it believes the record's
/// shape. A verifier that parsed first would meet the older shape as a body it
/// cannot read and file it before the upcaster was ever asked.
#[cfg(feature = "testkit")]
#[test]
fn an_export_at_an_older_record_shape_verifies_under_an_upcaster() {
    use agentplane::testkit::older_shape::LiftsTheOlderShape;

    let older = older_export();
    let report = agentplane::export::verify_with(
        std::io::Cursor::new(older.as_bytes()),
        None,
        &[],
        &LiftsTheOlderShape,
    )
    .expect("the file reads");
    assert!(
        report.findings.is_empty(),
        "an export one shape older did not verify under the upcaster that lifts it: {:?}",
        report.findings
    );
    assert_eq!(report.records, 3, "{report:?}");
    assert_eq!(report.sound.len(), 1, "{report:?}");

    let unlifted = agentplane::export::verify(std::io::Cursor::new(older.as_bytes()), None, &[])
        .expect("the file reads");
    assert!(
        unlifted
            .findings
            .iter()
            .any(|f| f.contains("build skew rather than an edit")),
        "with no path from the older version the record must be a skew: {:?}",
        unlifted.findings
    );
    assert!(
        !unlifted.findings.iter().any(|f| f.contains("edited")),
        "a record whose bytes hash as written was reported as an edit: {:?}",
        unlifted.findings
    );
}

/// **A restore across a shape change rebuilds the chain that was exported.**
///
/// The store indexes the lifted body and keeps the bytes as written, so every
/// restored record hashes as it did in the export. A restore that re-sealed
/// the lifted body would write this build's serialization of it — new bytes,
/// a new hash — and the chain would no longer be the exported one.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_restored_chain_hashes_as_the_exported_one_under_an_upcaster() {
    use agentplane::journal::JournalStore;
    use agentplane::testkit::older_shape::LiftsTheOlderShape;
    use std::sync::Arc;

    let older = older_export();
    let store: Arc<dyn JournalStore> = Arc::new(
        agentplane::store::RedbStore::open_in_memory()
            .expect("store")
            .upcasting_with(Arc::new(LiftsTheOlderShape)),
    );
    let report = agentplane::export::from_jsonl_with(
        &store,
        None,
        std::io::Cursor::new(older.as_bytes()),
        &LiftsTheOlderShape,
    )
    .await
    .expect("an older export restores under the upcaster that lifts it");
    assert!(
        report.is_faithful(),
        "the restored checkpoint is not the exported one: {report:?}"
    );

    let restored: Vec<(String, String)> = store
        .read(run(), 1)
        .await
        .expect("the restored records read")
        .iter()
        .map(|r| {
            (
                String::from_utf8(r.raw().to_vec()).expect("utf-8"),
                r.hash.to_string(),
            )
        })
        .collect();
    assert_eq!(
        restored,
        written(&older),
        "the store holds bytes other than the ones the export carried"
    );
}

/// **Two builds, rehearsed: the upgrade, and the rollback window.**
///
/// The older build's history is the crafted export; this build plays the newer
/// one. Readers first: it verifies, restores and exports the older history
/// unchanged, so until it writes, the older build could still read every
/// record — the rollback window is open. The first record this build writes is at its own
/// version, which the older build's reader refuses as a version it has never
/// heard of — a skew, never damage — and from that write on the window is
/// closed.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn two_builds_rehearse_the_upgrade_and_the_rollback_window() {
    use agentplane::core::StoreError;
    use agentplane::journal::JournalStore;
    use agentplane::testkit::older_shape::{LiftsTheOlderShape, OLDER, ReadsOnlyTheOlderShape};
    use std::sync::Arc;

    let older = older_export();

    // The newer build reads the older history.
    let report = agentplane::export::verify_with(
        std::io::Cursor::new(older.as_bytes()),
        None,
        &[],
        &LiftsTheOlderShape,
    )
    .expect("the file reads");
    assert!(report.findings.is_empty(), "{:?}", report.findings);

    let redb = Arc::new(
        agentplane::store::RedbStore::open_in_memory()
            .expect("store")
            .upcasting_with(Arc::new(LiftsTheOlderShape)),
    );
    let store: Arc<dyn JournalStore> = redb.clone();
    let cases: Arc<dyn agentplane::case::CaseStore> = redb;
    let restored = agentplane::export::from_jsonl_with(
        &store,
        Some(&cases),
        std::io::Cursor::new(older.as_bytes()),
        &LiftsTheOlderShape,
    )
    .await
    .expect("restore");
    assert!(restored.is_faithful(), "{restored:?}");

    // The window is open: every record is the older build's bytes.
    let history = store.read(run(), 1).await.expect("read");
    let bytes: Vec<String> = history
        .iter()
        .map(|r| String::from_utf8(r.raw().to_vec()).expect("utf-8"))
        .collect();
    assert_eq!(
        bytes,
        written(&older)
            .into_iter()
            .map(|(raw, _)| raw)
            .collect::<Vec<_>>(),
        "the upgrade rewrote history the older build wrote"
    );
    assert!(
        history.iter().any(|r| {
            serde_json::from_slice::<Value>(r.raw()).expect("json")["v"] == json!(OLDER)
        }),
        "nothing in the rehearsal was written at the older version"
    );

    // It exports what it holds as the older build wrote it.
    let mut again = Vec::new();
    agentplane::export::to_jsonl(&store, &cases, &[run()], &mut again)
        .await
        .expect("the newer build exports the older history");
    let again = String::from_utf8(again).expect("utf-8");
    assert_eq!(
        written(&again),
        written(&older),
        "the export carries bytes other than the ones the older build wrote"
    );
    let reverified = agentplane::export::verify_with(
        std::io::Cursor::new(again.as_bytes()),
        None,
        &[],
        &LiftsTheOlderShape,
    )
    .expect("the file reads");
    assert!(reverified.findings.is_empty(), "{:?}", reverified.findings);

    // The newer build writes; the window closes.
    let step = a_step_this_build_writes(&store).await;
    assert!(
        step.body.v > OLDER,
        "this build wrote at the older version, so the window never closed"
    );
    let refused = Record::from_stored_with(
        &ReadsOnlyTheOlderShape,
        step.raw().to_vec(),
        step.prev_hash,
        step.hash,
        None,
    )
    .expect_err("the older build read a record the newer one wrote");
    assert!(
        matches!(refused, StoreError::UnknownRecordVersion { .. }),
        "the older build must see a version skew, never damage: {refused}"
    );
}

/// A step record the newer build writes, on a run of its own.
#[cfg(feature = "testkit")]
async fn a_step_this_build_writes(
    store: &std::sync::Arc<dyn agentplane::journal::JournalStore>,
) -> Record {
    use agentplane::journal::Append;

    let next = RunId::parse("run_01ARZ3NDEKTSV4RRFFQ69G5FAW").expect("a fixed run id");
    let lease = store
        .acquire(next, "newer", std::time::Duration::from_secs(60))
        .await
        .expect("lease");
    let written_now = store
        .append(
            lease.epoch,
            vec![
                Append::new(
                    next,
                    RecordKind::RunAdmitted {
                        capability: "billing.settle".into(),
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
                ),
                Append::new(
                    next,
                    RecordKind::StepStarted {
                        skill: "orders.book".into(),
                    },
                )
                .step(StepId(0)),
            ],
        )
        .await
        .expect("append");
    written_now
        .into_iter()
        .find(|r| matches!(r.kind(), RecordKind::StepStarted { .. }))
        .expect("the step record")
}
