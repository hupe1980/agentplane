//! What an agent this plane does not execute reported doing.
//!
//! # The vocabulary is deliberately small, and deliberately not the wire's
//!
//! An observation record is evidence at the *asserted* rung, and the honest
//! thing to keep is what the seat actually establishes: **what a coding agent
//! was asked, what it reported doing, and what a person allowed.** That is the
//! gap nothing in the editor ecosystem fills with a tamper-evident,
//! offline-verifiable account, and it is a different artifact from a
//! transcript.
//!
//! So the streaming surface is not recorded. Message and thought chunks are
//! presentation — they arrive token by token, they are the agent's prose about
//! itself, and journaling them would turn an evidence log into a chat history
//! whose bulk hides the four events that matter. A deployment that wants the
//! transcript has one already; what it does not have is this.
//!
//! The vocabulary is also not a copy of the protocol's. A record kind that
//! mirrored one wire's discriminators would have to move when that wire moved,
//! and this plane would be storing somebody else's revision in its own durable
//! format. What travels is the *meaning*, which is stable across both published
//! revisions of the wire that prompted it.

use serde::{Deserialize, Serialize};

/// One thing an observed agent reported.
///
/// Typed rather than prose, for the reason every other journal vocabulary is:
/// an operator alerting on what an unattended agent did should not be matching
/// on sentences, and a variant added here is one every reader must consider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "step")]
pub enum ObservedStep {
    /// The agent was given a turn.
    ///
    /// The instruction itself is the `detail`, sealed — it is the user's words
    /// and the one part of a session most likely to carry somebody's data.
    Prompted,

    /// The agent reported calling a tool, at the status it reported.
    ///
    /// *Reported* is doing the work in that sentence. This plane did not
    /// dispatch the call, cannot say it happened, and is recording a claim —
    /// which is exactly why this is not an effect record.
    ToolCall {
        /// The call's id, as the agent minted it, so a later status update can
        /// be tied to the call it updates.
        call: String,
        /// Where the agent said the call had got to.
        status: ObservedStatus,
    },

    /// A person was asked whether to permit a call, and an answer came back.
    ///
    /// The one step in a session where a control was exercised, and therefore
    /// the one whose fidelity matters most.
    Decision {
        /// The call the question was about.
        call: String,
        /// What came back.
        outcome: ObservedDecision,
    },

    /// The turn ended, for the reason the agent gave.
    TurnEnded {
        /// The agent's own word for why it stopped.
        ///
        /// A `String` rather than an enum: the reason is the agent's, the wire
        /// grows them, and a plane that refused an unfamiliar one would be
        /// dropping the end of a session because a vocabulary it does not own
        /// gained a word.
        reason: String,
    },
}

/// Where the agent said a tool call had got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedStatus {
    /// Announced and not started.
    Pending,
    /// Running, as far as the agent knows.
    InProgress,
    /// The agent says it finished.
    Completed,
    /// The agent says it failed.
    Failed,
}

/// What came back when a person was asked to permit a call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum ObservedDecision {
    /// An option the agent offered was selected.
    ///
    /// **Both halves are the agent's, and neither is interpreted here.** The
    /// party under observation supplies the options a client may pick from,
    /// including what each one is called and what kind it claims to be — so a
    /// plane that folded them into its own *allowed* / *refused* would be
    /// deciding what somebody else's vocabulary meant, and would be wrong the
    /// first time that party offered a kind it had invented. Recorded as
    /// given; a reader judges.
    Selected {
        /// The option's id, as offered.
        option: String,
        /// The kind the offering party gave it — `allow_once`, `reject_always`
        /// and whatever else that party's revision admits.
        kind: String,
    },
    /// No option was selected and the turn was stopped instead.
    ///
    /// Distinct from selecting a refusing option, and the distinction is the
    /// finding: stopping the turn is the only refusal available when an agent
    /// offers none, so a session full of these is a client that was never
    /// given a way to say no.
    Cancelled,
}

impl ObservedStep {
    /// Stable discriminator, for a reader grouping a session's steps.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Prompted => "prompted",
            Self::ToolCall { .. } => "tool_call",
            Self::Decision { .. } => "decision",
            Self::TurnEnded { .. } => "turn_ended",
        }
    }
}
