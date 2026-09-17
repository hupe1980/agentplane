//! What a run's own history says about it, on the surfaces that answer.
//!
//! Two of this plane's endings are runs it writes about *itself* — a sweep's
//! pass and an operator crossing a tenant boundary — and both seal like any
//! other. The reader that turns a recorded ending back into a status is a match
//! over strings with a catch-all, so it went on compiling while those two were
//! added to the writer's list, and answered `Quarantined` about records this
//! plane had written itself.

#![cfg(feature = "redb")]

use std::sync::Arc;

use agentplane::journal::JournalStore;
use agentplane::runtime::{RunStatus, Runtime};
use agentplane::store::RedbStore;

/// An operator for a fixture, on the weakest basis a real caller could present.
///
/// `Asserted`: a suite that only built the authenticated form would leave the
/// basis a store persists untested on the path an incident actually takes.
fn operator(actor: &str) -> agentplane::core::Operator {
    agentplane::core::Operator::asserted(actor).expect("a fixture names its operator")
}

fn plane() -> (Arc<Runtime>, Arc<RedbStore>) {
    let store = Arc::new(RedbStore::open_in_memory().expect("a store"));
    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>).build();
    (runtime, store)
}

/// **A crossing names who crossed, and says why in their words.**
///
/// The whole value of break-glass is the record, and the record is two facts.
/// Reported as a quarantine, the operator's reason is replaced by a sentence
/// about the build — so an incident review reading the surface the operations
/// page sends it to learns neither.
#[tokio::test]
async fn a_break_glass_crossing_names_who_crossed() {
    let (runtime, _store) = plane();
    let run = runtime
        .record_break_glass(
            &operator("ops:hupe"),
            &["admin".to_owned()],
            "INC-42: stuck settlement",
        )
        .await
        .expect("the crossing is recorded");

    let outcome = runtime
        .recorded_outcome(run)
        .await
        .expect("a readable journal")
        .expect("a concluded run");

    assert_eq!(
        outcome.status.as_str(),
        "broke-glass",
        "{:?}",
        outcome.status
    );
    assert_eq!(
        outcome.status.actor(),
        Some(&operator("ops:hupe")),
        "a crossing must name the operator who made it: {:?}",
        outcome.status
    );
    assert_eq!(
        outcome.reason().as_deref(),
        Some("INC-42: stuck settlement"),
        "a crossing must answer with the reason it refused to be recorded \
         without, not with a sentence about this build"
    );
    assert!(
        !outcome.status.is_quarantined(),
        "a crossing this plane wrote itself is not a run the runtime could not \
         decide about"
    );
}

/// The sweep's own pass reads back as what it is.
///
/// No reason, deliberately: it pursued no goal, and what it decided is on its
/// own records rather than in a one-line summary.
#[tokio::test]
async fn a_sweep_reads_back_as_a_sweep() {
    use agentplane::case::CaseStore;
    use agentplane::core::{CorrelationKey, Deadline, DeadlineState, Digest, Timestamp};

    let store = Arc::new(RedbStore::open_in_memory().expect("a store"));
    let cases = Arc::clone(&store) as Arc<dyn CaseStore>;
    let now = Timestamp::from_unix_timestamp(1_800_000_000).expect("a time");

    // A sweep with nothing to decide writes no run at all — deliberately, so a
    // quiet plane does not mint a sealed run every tick. So give it one.
    let case = cases
        .correlate_or_open("matter", &[CorrelationKey::new("matter", "M-1")], now)
        .await
        .expect("a case")
        .case_id();
    cases
        .register_deadline(&Deadline {
            case,
            name: "respond-by".to_owned(),
            resolved_at: now - std::time::Duration::from_secs(3600),
            calendar_digest: Digest::of(b"test-calendar"),
            warn_at: None,
            state: DeadlineState::Pending,
            acknowledged: None,
        })
        .await
        .expect("a deadline");

    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&cases))
        .build();
    runtime
        .sweep(now, std::time::Duration::from_secs(3600))
        .await
        .expect("a sweep");

    let swept = runtime
        .journal()
        .runs_by_outcome("swept", 10)
        .await
        .expect("the outcome index");
    let run = *swept.first().expect("the sweep sealed a run of its own");

    let outcome = runtime
        .recorded_outcome(run)
        .await
        .expect("a readable journal")
        .expect("a concluded run");
    assert!(
        matches!(outcome.status, RunStatus::Swept),
        "the sweep's own run reads back as {:?}",
        outcome.status
    );
    assert!(outcome.status.actor().is_none());
    assert!(
        outcome.reason().is_none(),
        "a sweep pursued no goal, so there is no ending to explain"
    );
}
