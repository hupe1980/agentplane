//! Mapping the Agent Client Protocol's session updates onto observations.
//!
//! # Why a mapping and not a client
//!
//! ACP's client side is the governing end: the client spawns the agent, holds
//! the filesystem and terminal capabilities, and answers the one baseline
//! permission request. That client is an editor, and this plane is not one.
//! What it can be is the thing beside the editor that keeps the record — so
//! what belongs here is the **adapter**, and the connection stays where the
//! session already is.
//!
//! # Why the types are written out rather than taken as a dependency
//!
//! The protocol's official Rust crate has moved to its **v2** major, which is
//! published as a draft and still shipping alphas. Taking it would pin this
//! plane's *durable record* to a wire surface with no stabilization commitment
//! behind it, and a record shape is forever where a wire is versioned per
//! release. So the subset consumed here is written against **v1**, the stable
//! revision, and it is a subset: four of the eleven update kinds, because the
//! rest are presentation.
//!
//! Reading the v2 draft was still worth it, and it decided one field. Its
//! permission options gain an open `other` kind — so the kind an agent gives an
//! option is carried here as a string rather than as an enum this plane
//! defines. A closed vocabulary would have been wrong the first time the party
//! under observation offered a word this plane had not heard of, and *that
//! party owns the vocabulary* is the whole finding about using this wire for
//! oversight.
//!
//! [`REVISION`] names what this maps, because a mapping that does not say which
//! revision it read is a mapping nobody can check.

use serde::Deserialize;

use crate::core::{ObservedDecision, ObservedStatus, ObservedStep};

/// The protocol revision this adapter is written against.
///
/// Recorded as a constant rather than left in prose: the interop promise this
/// project makes is *a revision plus the extensions named with it*, and an
/// adapter whose revision is a comment is one nobody can hold to it.
pub const REVISION: &str = "acp/v1";

/// One `session/update` notification, in the subset this plane records.
#[derive(Debug, Clone, Deserialize)]
pub struct Notification {
    /// The session the update belongs to.
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// The update itself.
    pub update: Update,
}

/// The update, carrying its discriminator and whatever else came with it.
///
/// Deliberately **not** an enum with a variant per kind. An unknown
/// `sessionUpdate` must be reportable rather than a parse failure: this wire
/// gains update kinds, and a plane that refused a notification because a newer
/// agent sent one it had not heard of would stop recording the session it was
/// there to record. So the tag is a string, the rest is deferred, and
/// [`step_of`] decides.
#[derive(Debug, Clone, Deserialize)]
pub struct Update {
    /// The discriminator, in the wire's own spelling.
    #[serde(rename = "sessionUpdate")]
    pub session_update: String,
    /// The call, where the update is about one.
    #[serde(rename = "toolCallId", default)]
    pub tool_call_id: Option<String>,
    /// The agent's word for where the call had got to.
    #[serde(default)]
    pub status: Option<String>,
    /// A human-readable title for the call.
    #[serde(default)]
    pub title: Option<String>,
    /// Why the turn stopped, where the update says so.
    #[serde(rename = "stopReason", default)]
    pub stop_reason: Option<String>,
}

/// A `session/request_permission` request, in the subset this plane records.
#[derive(Debug, Clone, Deserialize)]
pub struct PermissionRequest {
    /// The session the question belongs to.
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// The call being asked about.
    #[serde(rename = "toolCall")]
    pub tool_call: PermissionToolCall,
    /// What the agent offered as answers.
    pub options: Vec<PermissionOption>,
}

/// The call a permission request is about.
#[derive(Debug, Clone, Deserialize)]
pub struct PermissionToolCall {
    #[serde(rename = "toolCallId")]
    pub tool_call_id: String,
    #[serde(default)]
    pub title: Option<String>,
}

/// One answer the agent offered.
#[derive(Debug, Clone, Deserialize)]
pub struct PermissionOption {
    #[serde(rename = "optionId")]
    pub option_id: String,
    /// The kind the *agent* gave it. A string, not an enum: see the module
    /// documentation.
    pub kind: String,
}

/// The answer that came back.
#[derive(Debug, Clone, Deserialize)]
pub struct PermissionResponse {
    pub outcome: PermissionOutcome,
}

/// The two shapes an answer takes on this wire.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PermissionOutcome {
    /// An offered option was chosen.
    Selected {
        #[serde(rename = "optionId")]
        option_id: String,
    },
    /// No option was chosen and the turn was stopped.
    Cancelled,
}

/// What an update produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mapped {
    /// A step to record, with the observed party's own words for it.
    Step {
        step: ObservedStep,
        detail: Option<String>,
    },
    /// An update this plane deliberately does not record.
    ///
    /// Message and thought chunks, mode changes, the command list: the
    /// streaming and presentation surface, named rather than dropped so a
    /// caller can say what its record does **not** cover. Silence here would be
    /// a record that looks complete.
    NotRecorded {
        /// The wire's own spelling for what arrived.
        session_update: String,
    },
}

/// Map one session update.
///
/// `None` is never returned: an update either becomes a step or is reported as
/// deliberately unrecorded, so a caller cannot mistake *we do not keep this*
/// for *nothing arrived*.
#[must_use]
pub fn step_of(update: &Update) -> Mapped {
    let unrecorded = || Mapped::NotRecorded {
        session_update: update.session_update.clone(),
    };
    match update.session_update.as_str() {
        // The user's turn: the instruction is the evidence, and it is theirs.
        "user_message_chunk" => Mapped::Step {
            step: ObservedStep::Prompted,
            detail: update.title.clone(),
        },
        "tool_call" | "tool_call_update" => {
            let Some(call) = update.tool_call_id.clone() else {
                // A call update naming no call cannot be tied to anything, and
                // recording it under an invented id would be worse than not
                // recording it.
                return unrecorded();
            };
            Mapped::Step {
                step: ObservedStep::ToolCall {
                    call,
                    status: status_of(update.status.as_deref()),
                },
                detail: update.title.clone(),
            }
        }
        _ => unrecorded(),
    }
}

/// Map a permission exchange — the question and the answer that came back.
///
/// The one step in a session where a control was exercised, which is why both
/// halves are taken together: a request with no answer is a question, and a
/// record of questions is not a record of what was allowed.
#[must_use]
pub fn decision_of(request: &PermissionRequest, response: &PermissionResponse) -> Mapped {
    let outcome = match &response.outcome {
        PermissionOutcome::Cancelled => ObservedDecision::Cancelled,
        PermissionOutcome::Selected { option_id } => ObservedDecision::Selected {
            option: option_id.clone(),
            // The kind the agent gave the option it offered. Absent when the
            // answer names an option the request never offered, which is a
            // claim about the client rather than about the agent — recorded as
            // the empty string rather than guessed at, because inventing a kind
            // here would put a disposition on the record that nobody offered.
            kind: request
                .options
                .iter()
                .find(|o| &o.option_id == option_id)
                .map(|o| o.kind.clone())
                .unwrap_or_default(),
        },
    };
    Mapped::Step {
        step: ObservedStep::Decision {
            call: request.tool_call.tool_call_id.clone(),
            outcome,
        },
        detail: request.tool_call.title.clone(),
    }
}

/// Map the end of a turn.
#[must_use]
pub fn turn_ended(stop_reason: &str) -> Mapped {
    Mapped::Step {
        step: ObservedStep::TurnEnded {
            reason: stop_reason.to_owned(),
        },
        detail: None,
    }
}

/// The agent's status word, in this plane's vocabulary.
///
/// An unfamiliar one — or none — reads as `Pending`, which is the only honest
/// default: it is the status that claims the least, and claiming a call
/// completed because a word was not recognised is the one error that matters
/// here.
fn status_of(status: Option<&str>) -> ObservedStatus {
    match status {
        Some("in_progress") => ObservedStatus::InProgress,
        Some("completed") => ObservedStatus::Completed,
        Some("failed") => ObservedStatus::Failed,
        _ => ObservedStatus::Pending,
    }
}
