//! No serialized type may put a `time` component array on a wire.
//!
//! # The bug this is a guard for
//!
//! [`Timestamp`](agentplane::core::Timestamp) is `time::OffsetDateTime`, whose
//! **derived** `Serialize` — without the `serde-human-readable` feature, which
//! this crate deliberately does not enable — emits nine numbers:
//!
//! ```text
//! [2027, 15, 8, 0, 0, 0, 0, 0, 0]
//! ```
//!
//! It parses. It round-trips. And every consumer that expected a date gets an
//! array whose first element looks like a year and whose second is an ordinal
//! day. A model asked to subtract two of them answers confidently and wrongly; a
//! dashboard renders `2027` as an hour. Nothing anywhere reports a problem,
//! which is why a review cannot be the control.
//!
//! Adding `#[serde(with = "time::serde::rfc3339")]` is one line, and forgetting
//! it is one line too. So the check is mechanical: build a value of each
//! serialized type that carries an instant, serialise it, and refuse anything
//! that looks like a component array.
//!
//! # Why the detector is shape-based rather than a field list
//!
//! A field list is a second place to remember, and the failure being prevented
//! *is* forgetting. This walks the whole JSON tree, so a timestamp nested three
//! levels inside a record body is caught by the same assertion as a top-level
//! one — including in types added after this file was written, as long as they
//! are in the fixture list below.

use agentplane::core::{
    CorrelationKey, Justification, OnExpiry, Priority, RunId, Sensitivity, SourceId, TaskId,
    TaskState, Timestamp, Trust, format_timestamp,
};
use serde_json::Value;

/// Whether a JSON value is a `time` component array.
///
/// Nine numbers, the first of them a plausible year. Both halves matter: nine
/// numbers alone is an ordinary vector, and a year alone is an ordinary field.
/// Together they are the exact shape `OffsetDateTime`'s derived `Serialize`
/// produces and essentially nothing else does.
fn looks_like_a_component_array(value: &Value) -> bool {
    let Some(items) = value.as_array() else {
        return false;
    };
    items.len() == 9
        && items.iter().all(Value::is_number)
        && items[0]
            .as_i64()
            .is_some_and(|year| (1900..=9999).contains(&year))
}

/// Every path in a value that carries a component array.
fn component_arrays(value: &Value, path: &str, found: &mut Vec<String>) {
    if looks_like_a_component_array(value) {
        found.push(path.to_owned());
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                component_arrays(nested, &format!("{path}/{key}"), found);
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                component_arrays(nested, &format!("{path}/{index}"), found);
            }
        }
        _ => {}
    }
}

fn assert_no_component_array<T: serde::Serialize>(label: &str, value: &T) {
    let json = serde_json::to_value(value).expect("the fixture serialises");
    let mut found = Vec::new();
    component_arrays(&json, "", &mut found);
    assert!(
        found.is_empty(),
        "{label} serialises a `time` component array at {found:?} — a consumer \
         expecting a date gets nine numbers, and it parses. Add \
         `#[serde(with = \"time::serde::rfc3339\")]` to the field, or \
         `agentplane::core::format_timestamp` if it is inside a `json!` literal.\n\
         {json:#}"
    );
}

fn at() -> Timestamp {
    Timestamp::from_unix_timestamp(1_800_000_000).expect("a representable instant")
}

/// The detector itself, exercised on a known input first.
///
/// Without this the test cannot fail for the right reason: on a clean tree a
/// working detector and a broken one both report nothing, so deleting the rule
/// would leave a green test guarding an empty set.
#[test]
fn the_detector_recognises_the_shape_it_exists_to_catch() {
    // What `time`'s derived `Serialize` actually produces, verbatim.
    let raw = serde_json::to_value(at()).expect("a bare timestamp serialises");
    assert!(
        looks_like_a_component_array(&raw),
        "a bare `Timestamp` no longer serialises as a component array ({raw}) — \
         either the `time` dependency gained `serde-human-readable`, or the crate \
         changed. Either way this whole guard is now inert and must be revisited"
    );

    // And it is not fooled by ordinary data.
    for benign in [
        serde_json::json!([1, 2, 3, 4, 5, 6, 7, 8, 9]),
        serde_json::json!([2027, 15, 8]),
        serde_json::json!({ "at": "2027-01-15T08:00:00Z" }),
        serde_json::json!(["2027", 15, 8, 0, 0, 0, 0, 0, 0]),
    ] {
        assert!(
            !looks_like_a_component_array(&benign),
            "{benign} is not a component array"
        );
    }

    // Nested, because that is where a real one hides.
    let mut found = Vec::new();
    component_arrays(&serde_json::json!({ "a": { "b": raw } }), "", &mut found);
    assert_eq!(found, vec!["/a/b".to_owned()]);
}

/// `format_timestamp` is RFC 3339, which is what a `json!` literal needs.
#[test]
fn the_json_literal_helper_produces_rfc_3339() {
    let formatted = format_timestamp(at());
    assert_eq!(formatted, "2027-01-15T08:00:00Z");
    assert!(!looks_like_a_component_array(&serde_json::json!(formatted)));
}

/// Durable memory, which is the type that had the defect.
#[test]
fn a_memory_item_carries_no_component_array() {
    let item = agentplane::memory::MemoryItem {
        id: "m-1".to_owned(),
        subject: "malo:DE-1234".to_owned(),
        purpose: "clearing".to_owned(),
        content: serde_json::json!({ "note": "kept" }),
        provenance: vec![SourceId::new("model.complete")],
        sensitivity: Sensitivity::Internal,
        trust: Trust::Untrusted,
        written_by: RunId::generate().to_string(),
        version: 2,
        created_at: at(),
        expires_at: Some(at()),
        access_retention_seconds: Some(600),
        superseded_at: Some(at()),
        derived_from: Vec::new(),
    };
    assert_no_component_array("MemoryItem", &item);

    // The recall query travels into the `memory.recall` effect descriptor, so
    // its cutoff is written into the journal an auditor reads.
    assert_no_component_array(
        "Recall",
        &agentplane::memory::Recall::about("malo:DE-1234").at(at()),
    );
}

/// The worklist rows a person is served over HTTP.
#[test]
fn a_task_carries_no_component_array() {
    let task = agentplane::core::Task {
        id: TaskId::derive(
            RunId::generate(),
            agentplane::core::EffectKey::from_hex(&"0".repeat(64)).expect("a key"),
        ),
        run: RunId::generate(),
        case: None,
        kind: "agent.triage/breach".to_owned(),
        justification: Justification::new("a deadline was missed", serde_json::json!({})),
        candidate_roles: vec!["grid-operations".to_owned()],
        escalate_to: Vec::new(),
        excluded_actors: Vec::new(),
        assignee: None,
        priority: Priority::High,
        state: TaskState::Open,
        on_expiry: OnExpiry::Deny,
        created_at: at(),
        due_at: Some(at()),
    };
    assert_no_component_array("Task", &task);
}

/// The long-lived business fact, and the obligations hanging off it.
#[test]
fn a_case_and_its_deadlines_carry_no_component_array() {
    let case = agentplane::core::Case {
        id: agentplane::core::CaseId::generate(),
        kind: "gpke.supplier-switch".to_owned(),
        status: agentplane::core::CaseStatus::Open,
        correlation: vec![CorrelationKey::new("malo", "DE-1234")],
        state: serde_json::json!({ "step": "sent" }),
        version: agentplane::core::CaseVersion::INITIAL,
        opened_at: at(),
        runs: Vec::new(),
    };
    assert_no_component_array("Case", &case);

    let deadline = agentplane::core::Deadline {
        case: case.id,
        name: "ack".to_owned(),
        resolved_at: at(),
        calendar_digest: agentplane::core::Digest::of(b"cal"),
        warn_at: Some(at()),
        state: agentplane::core::DeadlineState::Pending,
        acknowledged: None,
    };
    assert_no_component_array("Deadline", &deadline);
}

/// Every journal record kind that carries an instant.
///
/// The journal is the artifact an independent party reads, and it is the one
/// place a component array survives forever: records are append-only, so a
/// shape written wrong is never corrected in place.
#[test]
fn journal_records_carry_no_component_array() {
    use agentplane::journal::RecordKind;

    let kinds = vec![
        RecordKind::DeadlineRegistered {
            name: "ack".to_owned(),
            resolved_at: at(),
            calendar_digest: agentplane::core::Digest::of(b"cal"),
        },
        RecordKind::RunSuspended {
            reason: agentplane::core::SuspendReason::AwaitingTime { until: at() },
        },
        RecordKind::RunSuspended {
            reason: agentplane::core::SuspendReason::AwaitingEvent {
                kind: "ack".to_owned(),
                correlation: vec![CorrelationKey::new("malo", "DE-1234")],
                until: at(),
            },
        },
    ];
    for kind in &kinds {
        assert_no_component_array(kind.kind_str(), kind);
    }
}
