//! Inbound events and durable waits.
//!
//! # The race that makes this hard
//!
//! A run sends a request and then waits for an acknowledgement. The obvious
//! implementation registers a subscription, then suspends. It has a hole: the
//! acknowledgement can arrive *before the run reaches the wait at all* — a fast
//! counterparty, a slow first step, a retry that overtakes. With no subscription
//! yet, the event has nowhere to go, and the run then waits forever for
//! something that already happened.
//!
//! Every durable-execution system solves this the same way and it is worth
//! stating plainly: **inbound events are buffered durably on arrival, whether or
//! not anyone is waiting.** A wait first looks in the buffer, and only suspends
//! if nothing is there. Delivery and waiting meet in the store rather than in
//! time.
//!
//! Dead-lettering therefore happens on a *sweep* of the buffer, never on
//! arrival: "nobody is waiting for this yet" and "nobody will ever want this"
//! are different claims, and only the second is safe to act on.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{CorrelationKey, EffectKey, RunId, Timestamp};

/// A message from outside, correlated by business key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InboundEvent {
    /// Who sent it, as a URI — [CloudEvents]' `source`.
    ///
    /// Load-bearing twice over, and neither use is decoration.
    ///
    /// **It completes the dedup identity.** `CloudEvents` defines uniqueness as
    /// `(source, id)`, and for good reason: `id` alone is unique only within one
    /// producer. Two counterparties numbering their messages from one — or
    /// minting ids from different UUID versions — collide, and the collision is
    /// silent, because the second message looks exactly like a retry of the
    /// first and is dropped as one.
    ///
    /// **It is the payload's provenance.** An inbound message is untrusted
    /// whoever sent it, but *which* untrusted party matters: a sink may name the
    /// sources an authority-bearing field may derive from, and `event:kind` says
    /// what arrived while saying nothing about who sent it.
    ///
    /// It is not authority. A producer writes this string; anyone may claim to
    /// be anyone. What it buys is a label a policy can reason about once the
    /// transport has authenticated the sender by other means — which is why an
    /// event arriving as a [`CloudEvent`](crate::core::CloudEvent) takes this
    /// from the authenticated transport and keeps the producer's own claim
    /// inside [`id`](Self::id). See
    /// [`CloudEvent::into_inbound`](crate::core::CloudEvent::into_inbound).
    ///
    /// [CloudEvents]: https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md
    pub source: String,
    /// Stable identity for deduplication, unique **within a source**. A
    /// counterparty that retries must reuse this, or the same message is
    /// delivered twice.
    pub id: String,
    /// What kind of message, e.g. `"acknowledgement.received"`.
    pub kind: String,
    /// The business keys this message carries. Real messages do not know run
    /// ids; they carry document numbers and meter ids.
    pub correlation: Vec<CorrelationKey>,
    pub payload: Value,
}

impl InboundEvent {
    pub fn new(
        source: impl Into<String>,
        id: impl Into<String>,
        kind: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            source: source.into(),
            id: id.into(),
            kind: kind.into(),
            correlation: Vec::new(),
            payload,
        }
    }

    #[must_use]
    pub fn correlate(mut self, key: CorrelationKey) -> Self {
        self.correlation.push(key);
        self
    }

    /// The identity a store deduplicates on: `(source, id)`.
    ///
    /// Derived here and nowhere else. Every store has to agree byte for byte
    /// about which two messages are the same message, and a second place
    /// building this string is a second answer to that question.
    ///
    /// The separator is a unit separator (U+001F) rather than a printable
    /// character because a `source` is a URI and an `id` is arbitrary: any
    /// character a producer might reasonably use would let one pair spell
    /// another, and two distinct messages would deduplicate into one.
    #[must_use]
    pub fn dedup_key(&self) -> String {
        format!("{}\u{1f}{}", self.source, self.id)
    }
}

/// What a run is waiting for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AwaitSpec {
    pub kind: String,
    pub correlation: Vec<CorrelationKey>,
    /// The obligation that bounds this wait.
    ///
    /// Mandatory by design. An unbounded wait is a run that can hang forever
    /// with nothing to notice it — the failure mode that presents as "the
    /// process just stalled" and is invisible until someone asks.
    pub deadline: String,
}

impl AwaitSpec {
    pub fn new(kind: impl Into<String>, deadline: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            correlation: Vec::new(),
            deadline: deadline.into(),
        }
    }

    #[must_use]
    pub fn correlate(mut self, key: CorrelationKey) -> Self {
        self.correlation.push(key);
        self
    }
}

/// A durable registration of interest in a future event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subscription {
    pub run: RunId,
    /// The matter this wait belongs to.
    ///
    /// Carried so delivery can stamp the record it writes with the case — every
    /// record of a case-bound run must — and so "what is this matter waiting
    /// for?" is one query rather than a join through runs.
    pub case: Option<crate::core::CaseId>,
    /// The effect whose output this event will become. Delivering the event
    /// journals an `EffectDone` under this key, so resuming the run replays the
    /// wait as an ordinary completed effect.
    pub effect: EffectKey,
    /// Which step is waiting, and in which pass.
    ///
    /// Delivery journals the `EffectDone` under this position, and replay
    /// verifies effects per step — so a wait recorded against the wrong step is
    /// a wait the resumed run never finds. An earlier version hardcoded step
    /// zero here, which worked only because every wait happened to be in a
    /// single-step plan; a wait in a later step, or in a compensation, suspended
    /// forever.
    pub step: crate::core::StepId,
    pub phase: crate::core::Phase,
    pub kind: String,
    pub correlation: Vec<CorrelationKey>,
}

/// A run's durable wake-up.
///
/// A timer is a wait whose event is the clock. It reuses the effect protocol
/// wholesale — the wake instant is journaled under an effect key, so replay
/// reads it back rather than sleeping again, and a fired timer is recorded
/// before the run is resumed.
///
/// Unlike a correlated wait it needs no case: there is nothing to correlate and
/// no business horizon to bound it, because the instant *is* the horizon. That
/// makes durable sleep available to any run, which is what lets a long retry
/// backoff release its worker instead of holding one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timer {
    pub run: crate::core::RunId,
    /// Carried so a fired timer can stamp the record it writes with the case —
    /// every record of a case-bound run must.
    pub case: Option<crate::core::CaseId>,
    /// The effect whose output this wake-up becomes.
    pub effect: EffectKey,
    /// Where the sleeping step is. Replay verifies effects per step, so a
    /// wake-up journaled against the wrong step is one the resumed run never
    /// finds.
    pub step: crate::core::StepId,
    pub phase: crate::core::Phase,
    pub fire_at: Timestamp,
}

/// Why a run stopped without finishing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuspendReason {
    /// Waiting for an inbound message that has not arrived.
    AwaitingEvent {
        kind: String,
        correlation: Vec<CorrelationKey>,
        #[serde(with = "time::serde::rfc3339")]
        until: Timestamp,
    },
    /// Waiting for an instant to arrive.
    ///
    /// Nothing to correlate: the clock is the event. Distinct from
    /// [`AwaitingEvent`](Self::AwaitingEvent) because the two fail differently —
    /// a message that never comes is a correlation bug worth alerting on, and an
    /// instant that has not arrived yet is the system working.
    AwaitingTime {
        #[serde(with = "time::serde::rfc3339")]
        until: Timestamp,
    },
}

impl std::fmt::Display for SuspendReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwaitingEvent {
                kind,
                correlation,
                until,
                ..
            } => {
                write!(f, "awaiting '{kind}'")?;
                if let Some(k) = correlation.first() {
                    write!(f, " for {k}")?;
                }
                write!(f, " until {until}")
            }
            Self::AwaitingTime { until } => write!(f, "sleeping until {until}"),
        }
    }
}

/// What happened to a delivered event.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Delivery {
    /// A waiting run consumed it and ran to its next stopping point.
    Resumed { run: RunId },
    /// Stored, but nobody is waiting for it *yet*.
    ///
    /// Not an error and not a dead letter. The counterpart run may not have
    /// reached its wait, or may not have started. The event stays claimable
    /// until a wait finds it or the sweep ages it out.
    Buffered,
    /// This event id was already delivered. Retries are safe.
    Duplicate,
}

impl Delivery {
    #[must_use]
    pub fn resumed_run(&self) -> Option<RunId> {
        match self {
            Self::Resumed { run } => Some(*run),
            _ => None,
        }
    }
}

/// An event that aged out of the buffer without anyone claiming it.
///
/// Reaching this list means a correlation key is wrong somewhere — the message
/// arrived, was held, and no run ever asked for it. That is a bug worth paging
/// on, and it is precisely the failure that otherwise presents as a process
/// silently never completing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeadLetter {
    pub event: InboundEvent,
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: Timestamp,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `resumed_run` names the run only when one actually resumed.
    ///
    /// The three delivery outcomes are easy to conflate at a call site — all
    /// three mean "the event was accepted" — and only one of them means a run
    /// moved. A caller that treated `Buffered` as a resumption would report
    /// progress for a message nobody has claimed yet, which is precisely the
    /// failure the buffered state exists to make visible.
    #[test]
    fn only_a_resumed_delivery_names_a_run() {
        let run = RunId::generate();

        assert_eq!(Delivery::Resumed { run }.resumed_run(), Some(run));
        assert_eq!(Delivery::Buffered.resumed_run(), None);
        assert_eq!(Delivery::Duplicate.resumed_run(), None);
    }
}
