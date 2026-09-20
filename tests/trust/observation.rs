//! A record beside an agent this plane does not execute.
//!
//! The seat produces evidence, not control, and the whole of the design is in
//! what the evidence may not claim: an observation is the observed party's
//! account of itself, and it must never read as something this runtime
//! dispatched.

#![cfg(feature = "acp")]

use std::sync::Arc;

use agentplane::core::{ObservedDecision, ObservedStatus, ObservedStep};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::observe::Session;
use agentplane::observe::acp::{self, Mapped};
use agentplane::store::RedbStore;

/// The wire's own bytes, so the adapter is exercised the way a client delivers
/// them rather than through hand-built Rust values that cannot disagree with
/// the schema.
fn update(json: &str) -> acp::Update {
    let n: acp::Notification =
        serde_json::from_str(json).expect("an ACP session/update notification parses");
    n.update
}

/// **The discharge.** A session's updates land as records at the asserted rung,
/// an `audit` reports over them, and none of them reads as a dispatched effect.
#[tokio::test]
async fn an_acp_session_is_recorded_audited_and_never_reads_as_an_effect() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let journal: Arc<dyn JournalStore> = Arc::clone(&store) as Arc<dyn JournalStore>;
    let mut session = Session::new(Arc::clone(&journal), "sess-1");
    let run = session.run();

    // What the user asked.
    let prompted = update(
        r#"{"sessionId":"sess-1","update":{"sessionUpdate":"user_message_chunk",
            "title":"rename the config loader"}}"#,
    );
    let Mapped::Step { step, detail } = acp::step_of(&prompted) else {
        panic!("a user turn is evidence and must be recorded");
    };
    assert_eq!(step, ObservedStep::Prompted);
    session.step(step, detail).await.expect("record");

    // What the agent reported doing.
    let called = update(
        r#"{"sessionId":"sess-1","update":{"sessionUpdate":"tool_call",
            "toolCallId":"call-7","status":"in_progress","title":"write src/config.rs"}}"#,
    );
    let Mapped::Step { step, detail } = acp::step_of(&called) else {
        panic!("a reported tool call is evidence");
    };
    assert_eq!(
        step,
        ObservedStep::ToolCall {
            call: "call-7".to_owned(),
            status: ObservedStatus::InProgress,
        }
    );
    session.step(step, detail).await.expect("record");

    // What a person allowed — the one step where a control was exercised.
    let request: acp::PermissionRequest = serde_json::from_str(
        r#"{"sessionId":"sess-1","toolCall":{"toolCallId":"call-7","title":"write src/config.rs"},
            "options":[{"optionId":"allow","kind":"allow_once"},
                       {"optionId":"reject","kind":"reject_once"}]}"#,
    )
    .expect("a permission request parses");
    let response: acp::PermissionResponse =
        serde_json::from_str(r#"{"outcome":{"outcome":"selected","optionId":"allow"}}"#)
            .expect("a permission response parses");
    // The wire shape maps to the variant this plane thinks it does. Asserted
    // against a constructed value rather than trusted: a rename on either side
    // would otherwise deserialise into the *other* arm and record a refusal as
    // an approval, which is the one error on this wire that matters.
    assert_eq!(
        response.outcome,
        acp::PermissionOutcome::Selected {
            option_id: "allow".to_owned()
        }
    );
    let Mapped::Step { step, detail } = acp::decision_of(&request, &response) else {
        panic!("a decision is the evidence this seat exists for");
    };
    assert_eq!(
        step,
        ObservedStep::Decision {
            call: "call-7".to_owned(),
            outcome: ObservedDecision::Selected {
                option: "allow".to_owned(),
                // Carried from the option the agent offered, not decided here.
                kind: "allow_once".to_owned(),
            },
        }
    );
    session.step(step, detail).await.expect("record");

    let Mapped::Step { step, .. } = acp::turn_ended("end_turn") else {
        panic!("the end of a turn is evidence");
    };
    session.step(step, None).await.expect("record");

    let sealed = session.seal().await.expect("seal").expect("a sealed run");
    assert_eq!(sealed, run);

    assert_rung(&journal, run).await;

    // ── The audit reports over it ───────────────────────────────────────────
    let report =
        agentplane::audit::audit(&journal, &[run], &agentplane::audit::Evidence::default())
            .await
            .expect("audit");
    assert!(
        report.findings.is_empty(),
        "an observed session is not a finding: {:?}",
        report.findings
    );
    assert!(
        report.sound.contains(&run),
        "the observation's chain did not verify like any other run's"
    );
    let unadmitted = report
        .unadmitted
        .iter()
        .find(|u| u.run == run)
        .expect("an observed session has no admission and the audit must say so");
    assert_eq!(
        unadmitted.outcome.as_deref(),
        Some("observed"),
        "the audit must name the outcome, or a reader cannot tell a session this \
         plane watched from a run that should have been admitted and was not"
    );
    assert!(
        report.warrants.iter().all(|w| w.run != run),
        "an observed session produced a warrant — this plane would be claiming it \
         governed an agent it does not execute"
    );
}

/// Every record is an observation, and none of them is an effect.
///
/// The claim the whole design rests on: sharing a record kind with a dispatched
/// effect would launder a report into an execution record and falsify every
/// answer the journal gives about what authorized an action.
async fn assert_rung(journal: &Arc<dyn JournalStore>, run: agentplane::RunId) {
    let history = journal.read(run, 1).await.expect("history");
    for record in &history {
        let kind = record.kind().kind_str();
        assert!(
            matches!(kind, "Observed" | "RunConcluded"),
            "an observed session wrote a '{kind}' record — sharing a kind with \
             this plane's own work is the one thing this design forbids"
        );
    }
    assert!(
        history
            .iter()
            .all(|r| !matches!(r.kind(), RecordKind::RunAdmitted { .. })),
        "an observed session carries an admission, which claims this plane let it run"
    );
}

/// The updates this plane deliberately does not keep say so.
///
/// Silence would make a partial record look complete, which is the failure the
/// whole report is arranged against. A caller gets the wire's own spelling back
/// so it can say what its record does not cover.
#[test]
fn a_presentation_update_is_reported_rather_than_dropped() {
    for kind in [
        "agent_message_chunk",
        "agent_thought_chunk",
        "plan",
        "available_commands_update",
        "current_mode_update",
    ] {
        let u = update(&format!(
            r#"{{"sessionId":"s","update":{{"sessionUpdate":"{kind}"}}}}"#
        ));
        match acp::step_of(&u) {
            Mapped::NotRecorded { session_update } => assert_eq!(session_update, kind),
            Mapped::Step { step, .. } => {
                panic!("'{kind}' is presentation and was recorded as {step:?}")
            }
        }
    }
}

/// An update kind from a revision this build has never seen is reported, not
/// refused.
///
/// The wire grows, and a plane that dropped a notification because a newer
/// agent sent an unfamiliar kind would stop recording the session it is there
/// to record.
#[test]
fn an_unknown_update_kind_is_named_rather_than_refused() {
    let u = update(r#"{"sessionId":"s","update":{"sessionUpdate":"something_v3_added"}}"#);
    assert_eq!(
        acp::step_of(&u),
        Mapped::NotRecorded {
            session_update: "something_v3_added".to_owned()
        }
    );
}

/// A tool call whose status the agent spells in a word this build does not know
/// reads as `Pending`, never as finished.
///
/// The only honest default: `Completed` would put a claim on the record that
/// the agent did not make, on the strength of a word nobody recognised.
#[test]
fn an_unfamiliar_tool_status_claims_the_least() {
    let u = update(
        r#"{"sessionId":"s","update":{"sessionUpdate":"tool_call",
            "toolCallId":"c1","status":"awaiting_review"}}"#,
    );
    let Mapped::Step { step, .. } = acp::step_of(&u) else {
        panic!("a tool call is evidence");
    };
    assert_eq!(
        step,
        ObservedStep::ToolCall {
            call: "c1".to_owned(),
            status: ObservedStatus::Pending,
        }
    );
}

/// The refusal an agent leaves when it offers no refusing option.
///
/// ACP's client cannot answer *deny*: it selects from a list the agent wrote,
/// and stopping the turn is the only refusal always available. Recording that
/// as its own outcome is what lets a reader see a session where the client was
/// never given a way to say no.
#[test]
fn a_cancelled_permission_is_its_own_outcome() {
    let request: acp::PermissionRequest = serde_json::from_str(
        r#"{"sessionId":"s","toolCall":{"toolCallId":"c9"},
            "options":[{"optionId":"yes","kind":"allow_always"}]}"#,
    )
    .expect("parses");
    let response: acp::PermissionResponse =
        serde_json::from_str(r#"{"outcome":{"outcome":"cancelled"}}"#).expect("parses");
    let Mapped::Step { step, .. } = acp::decision_of(&request, &response) else {
        panic!("a decision is evidence");
    };
    assert_eq!(
        step,
        ObservedStep::Decision {
            call: "c9".to_owned(),
            outcome: ObservedDecision::Cancelled,
        }
    );
}

/// A session that saw nothing seals nothing.
#[tokio::test]
async fn an_empty_session_leaves_no_leaf() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let session = Session::new(Arc::clone(&store) as Arc<dyn JournalStore>, "sess-quiet");
    assert!(
        session.seal().await.expect("seal").is_none(),
        "a session with nothing to report opened a run, and a log of nothings is \
         where the somethings hide"
    );
}

/// **A session bound to a case is findable by the identifier the asker holds.**
///
/// The evidence is worth nothing if the only way to reach it is a scan of every
/// session this plane ever watched. A case correlated on the session id makes
/// *show me the record for session X* one indexed read — the mechanism this
/// plane already has for that question, rather than a second one invented for
/// this altitude.
#[tokio::test]
async fn an_observed_session_is_reachable_through_the_case_it_names() {
    use agentplane::case::CaseStore;
    use agentplane::core::{CorrelationKey, Timestamp};

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let journal: Arc<dyn JournalStore> = Arc::clone(&store) as Arc<dyn JournalStore>;
    let cases: Arc<dyn CaseStore> = Arc::clone(&store) as Arc<dyn CaseStore>;
    let now = Timestamp::from_unix_timestamp(1_800_000_000).expect("time");

    let case = cases
        .correlate_or_open(
            "acp-session",
            &[CorrelationKey::new("session", "sess-42")],
            now,
        )
        .await
        .expect("open")
        .case_id();

    let mut session = Session::new(Arc::clone(&journal), "sess-42").in_case(case);
    let run = session.run();
    session
        .step(ObservedStep::Prompted, Some("rename the loader".to_owned()))
        .await
        .expect("record");
    session.seal().await.expect("seal").expect("a sealed run");

    // The question an auditor actually asks, answered by correlation rather
    // than by walking every observed run.
    let found = cases
        .correlate(&[CorrelationKey::new("session", "sess-42")])
        .await
        .expect("correlate")
        .expect("the session's matter");
    assert_eq!(found, case);

    // **The observations themselves, not merely the conclusion.** A case walk
    // that reaches only the sealing record answers *this session happened* and
    // not *this is what it did* — and the conclusion carries its own stamp, so
    // asserting on the run alone passes over records that escaped.
    let history = journal.case_history(case, 100).await.expect("case history");
    let observed: Vec<_> = history
        .iter()
        .filter(|r| r.body.run == run && matches!(r.kind(), RecordKind::Observed { .. }))
        .collect();
    assert_eq!(
        observed.len(),
        1,
        "the session's observations are not reachable from the matter that names \
         it — the case walk found {} of them",
        observed.len()
    );
    assert!(
        history
            .iter()
            .filter(|r| r.body.run == run)
            .all(|r| r.body.case == Some(case)),
        "an observed record escaped the case stamp, so a case walk would miss it"
    );
}
