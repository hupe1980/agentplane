//! Streaming A2A updates, read from the journal.
//!
//! # The stream is a view of the journal, not an event bus
//!
//! The obvious way to stream progress is an in-process broadcast channel: a step
//! finishes, it publishes, subscribers receive. It is also wrong here, in three
//! ways that only show up in production.
//!
//! A channel's events live in memory, so a subscriber that reconnects has
//! **missed** whatever happened while it was away, and nothing can tell it what.
//! A channel is per process, so a subscriber attached to the instance that is
//! *not* running the work receives nothing — and which instance that is changes
//! after every failover. And a channel is a second record of what happened,
//! which can disagree with the first.
//!
//! So updates are read from the journal instead. That makes the stream exactly
//! as durable as the run: a client that drops and re-subscribes picks up the
//! current state and continues, any instance can serve it, and the events cannot
//! disagree with history because they *are* history.
//!
//! The cost is a poll rather than a push. It is a real cost and it is stated
//! rather than hidden: one indexed read per subscriber per interval, against a
//! store that is already answering worse queries. What it buys is a stream that
//! survives the things streams are asked to survive.
//!
//! # When the stream ends
//!
//! The spec requires closing on a terminal state. This also closes on
//! `INPUT_REQUIRED`, which is *not* terminal, and the reason is that a suspended
//! run may be waiting on a human for a week. Holding a connection open for that
//! is not streaming, it is a leak with a spec reference. The client is told the
//! run is waiting and can subscribe again — which costs it nothing, because the
//! stream is rebuilt from the journal rather than resumed from memory.

use std::sync::Arc;
use std::time::Duration;

use axum::response::sse::{Event, Sse};
use futures_util::stream::Stream;
use serde_json::{Value, json};

use crate::core::{RunId, Seq};
use crate::journal::RecordKind;
use crate::runtime::Runtime;

use super::a2a::{A2aArtifact, A2aTask, TaskState, sealed_state, task_artifacts, task_of};

/// How often a subscriber re-reads the journal.
///
/// Short enough that progress feels live, long enough that a hundred
/// subscribers are not a hundred reads per millisecond. A push would avoid the
/// question and lose the properties in the module docs.
const POLL: Duration = Duration::from_millis(200);

/// One `StreamResponse`, as the wire carries it.
///
/// A oneof: exactly one field is present. Built here rather than by the caller
/// so the "exactly one" part cannot be got wrong in four places.
fn stream_response(id: &Value, payload: &Value) -> Event {
    Event::default().data(json!({"jsonrpc": "2.0", "id": id, "result": payload}).to_string())
}

/// `TaskStatusUpdateEvent`.
///
/// `contextId` is required by the schema, and a run without a case has no case
/// id to put there. It carries the **run's own id** rather than an empty string:
/// a standalone run genuinely is its whole context, so this is a true statement
/// about grouping rather than a placeholder a client has to special-case.
fn status_update(run: RunId, case: Option<&str>, state: TaskState, detail: &str) -> Value {
    json!({
        "statusUpdate": {
            "taskId": run.to_string(),
            "contextId": case.unwrap_or(&run.to_string()),
            "status": {
                "state": state,
                "message": {
                    "messageId": format!("{run}-{detail}"),
                    "role": "ROLE_AGENT",
                    "parts": [{"text": detail}],
                    "taskId": run.to_string(),
                },
            },
        }
    })
}

fn artifact_update(run: RunId, case: Option<&str>, artifact: &A2aArtifact) -> Value {
    json!({
        "artifactUpdate": {
            "taskId": run.to_string(),
            "contextId": case.unwrap_or(&run.to_string()),
            "artifact": artifact,
            "append": false,
            "lastChunk": true,
        }
    })
}

/// What a journal record says about progress, if anything a caller can use.
///
/// Deliberately not every record: a subscriber wants to know *what is
/// happening*, and a stream that narrates internal bookkeeping is one people
/// stop reading. Records with no caller-visible meaning produce no event.
fn progress_of(kind: &RecordKind) -> Option<(TaskState, String)> {
    match kind {
        RecordKind::StepStarted { skill } => Some((TaskState::Working, format!("started {skill}"))),
        RecordKind::StepFinished { outcome } => {
            Some((TaskState::Working, format!("finished: {outcome}")))
        }
        RecordKind::RunSuspended { reason } => {
            Some((TaskState::InputRequired, format!("waiting: {reason}")))
        }
        RecordKind::RunSealed { outcome, .. } => Some((sealed_state(outcome), outcome.clone())),
        _ => None,
    }
}

/// Whether a state ends the stream.
///
/// Only terminal states end a subscription. `INPUT_REQUIRED` can receive a
/// later message or out-of-band authorization and therefore remains live under
/// A2A 1.0.
const fn closes(state: TaskState) -> bool {
    matches!(
        state,
        TaskState::Completed | TaskState::Failed | TaskState::Canceled | TaskState::Rejected
    )
}

/// Stream a run's progress, starting from `from`.
///
/// The first event is always the `Task` itself, which the spec requires: a
/// subscriber must be able to learn the current state without having been
/// present for the events that produced it.
pub fn tail(
    runtime: Arc<Runtime>,
    run: RunId,
    case: Option<String>,
    id: Value,
    first: A2aTask,
    from: Seq,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    // Whether the run is *already* over when the stream opens. Checked here and
    // not only in the loop below: the record that ended it was consumed before
    // this subscriber existed, so the loop would never see it and would poll a
    // finished run forever. Subscribing to a completed task is the ordinary
    // case — a client reconnecting after a drop does exactly that.
    let already_over = closes(first.status.state);
    let stream = async_stream::stream! {
        yield Ok(stream_response(&id, &json!({ "task": first })));
        if already_over {
            return;
        }

        let mut next = from;
        loop {
            // A read that fails is not a run that failed. The stream ends rather
            // than reporting a terminal state the run never reached — a client
            // that reconnects gets the truth from the journal.
            let Ok(records) = runtime.journal().read(run, next).await else {
                return;
            };

            let mut done = false;
            for record in &records {
                next = record.body.seq + 1;
                if let RecordKind::RunSealed { outcome, .. } = record.kind() {
                    let state = sealed_state(outcome);
                    if state == TaskState::Completed
                        && let Some(artifacts) = task_artifacts(&runtime, run, state).await
                    {
                        for artifact in artifacts {
                            yield Ok(stream_response(
                                &id,
                                &artifact_update(run, case.as_deref(), &artifact),
                            ));
                        }
                    }
                    yield Ok(stream_response(
                        &id,
                        &status_update(run, case.as_deref(), state, outcome),
                    ));
                    done = true;
                    continue;
                }
                if let Some((state, detail)) = progress_of(record.kind()) {
                    yield Ok(stream_response(
                        &id,
                        &status_update(run, case.as_deref(), state, &detail),
                    ));
                    done |= closes(state);
                }
            }
            if done {
                return;
            }
            tokio::time::sleep(POLL).await;
        }
    };

    // Deliberately **no** keep-alive. It was tried, and with it the response
    // body did not end when the stream did: the connection outlived the task,
    // which is precisely the failure this whole module is shaped to avoid — a
    // client holding a socket open for a run that already finished.
    //
    // The trade is that a very idle stream may be reaped by an intermediary. That
    // is the better failure: the client reconnects and is told the current state
    // from the journal, because the stream is a view of history rather than a
    // subscription to memory. A connection that never ends cannot be recovered
    // from by anybody.
    Sse::new(stream)
}

/// The task a stream opens with, read from the journal as it stands now.
pub async fn current(runtime: &Runtime, run: RunId) -> Option<(A2aTask, Option<String>, Seq)> {
    let records = runtime.journal().read(run, 1).await.ok()?;
    let last = records.last()?;
    let (state, detail) = match last.kind() {
        RecordKind::RunSuspended { reason } => (TaskState::InputRequired, reason.to_string()),
        RecordKind::RunSealed { outcome, .. } => (sealed_state(outcome), outcome.clone()),
        _ => (TaskState::Working, "running".to_owned()),
    };
    let case = records
        .iter()
        .find_map(|r| r.body.case.map(|c| c.to_string()));
    let next = last.body.seq + 1;
    let mut task = task_of(run, state, &detail, case.clone());
    task.artifacts = task_artifacts(runtime, run, state).await;
    Some((task, case, next))
}
