//! Rebuilding an `OpenAI` Responses answer from its event stream.
//!
//! # The asymmetry that decides the failure mapping
//!
//! Anthropic reports usage incrementally, so a severed stream still knows what
//! it burned. **`OpenAI` does not.** The Responses stream carries `usage` only
//! inside its terminal event — `response.completed`, `response.incomplete` or
//! `response.failed` — and every event before it either omits the field or
//! carries it as `null`.
//!
//! So a connection cut after four hundred tokens of `response.output_text.delta`
//! leaves this driver knowing, for certain, that generation **happened**, and
//! knowing nothing at all about what it cost.
//!
//! Neither existing variant says that:
//!
//! * [`Unavailable`](super::ModelError::Unavailable) means *it may not have
//!   generated*, and is therefore safe to repeat. Here we watched it generate;
//!   asking again buys a second bill for the same question.
//! * [`Interrupted`](super::ModelError::Interrupted) carries a `Usage`, and
//!   filling it with zeroes is the "guessing free" failure this crate refuses
//!   everywhere else — it reads as *this cost nothing* rather than as *nobody
//!   knows*.
//!
//! [`Unaccounted`](super::ModelError::Unaccounted) is the honest third answer,
//! and it exists because this protocol can produce the state. The under-count is
//! real and documented rather than hidden; what it buys is that the runtime
//! stops paying twice for it.
//!
//! # Why not just read the response back
//!
//! `response.created` carries an id, and a stored response can be fetched
//! afterwards to learn what it cost. That is a *reconciliation*, and this crate
//! has a vocabulary for those — but it is a second network call on a failure
//! path, made by a component whose contract is one call per effect. It belongs
//! to the caller's [`Recovery`](crate::core::Recovery) policy, not to a driver
//! quietly making requests nobody journaled. The id is surfaced so a caller can
//! do it; the driver does not.

use serde_json::Value;

/// A Responses answer being rebuilt from events.
#[derive(Debug, Default)]
pub struct Accumulator {
    /// The terminal event's `response` object, in the same shape the
    /// non-streaming call returns — so the driver reuses one parser for both.
    terminal: Option<Value>,
    /// Which terminal event arrived.
    outcome: Option<Outcome>,
    /// Whether any output token was seen.
    ///
    /// The distinction this whole module turns on: generation began, so the call
    /// landed, whatever the connection did next.
    generated: bool,
    /// The provider's id for this response, from `response.created`.
    id: Option<String>,
    /// A transport-level `error` event inside a 200 response.
    error: Option<String>,
}

/// Which terminal event ended the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    /// Ran out of room. Carries usage, and the answer is real but cut short.
    Incomplete,
    /// The provider gave up mid-response. Carries usage.
    Failed,
}

impl Accumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether any output token was observed.
    #[must_use]
    pub const fn generated(&self) -> bool {
        self.generated
    }

    #[must_use]
    pub const fn outcome(&self) -> Option<Outcome> {
        self.outcome
    }

    /// The terminal `response` object, when one arrived.
    #[must_use]
    pub const fn terminal(&self) -> Option<&Value> {
        self.terminal.as_ref()
    }

    /// The provider's response id, for a caller who wants to reconcile.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Absorb one event.
    ///
    /// Unknown types are ignored: `OpenAI` adds event types for new tool
    /// families regularly, and a driver that rejected them would break on a
    /// release that changed nothing it uses.
    pub fn event(&mut self, name: &str, data: &str) {
        let Ok(value) = serde_json::from_str::<Value>(data) else {
            return;
        };
        let kind = if name.is_empty() {
            value
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
        } else {
            name
        };

        match kind {
            "response.created" => {
                self.id = value
                    .get("response")
                    .and_then(|r| r.get("id"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
            }
            // Every kind of delta means one thing here, which is why they share
            // an arm: *tokens were produced*. Text, a refusal, a reasoning
            // summary, tool arguments — all four are billed, and what decides
            // the failure mapping is not whether the caller can read them but
            // whether asking again pays for them twice.
            //
            // Nothing is accumulated. A stream that dies mid-answer holds
            // partial text, and handing that back as a whole answer is the
            // silent truncation this crate refuses everywhere else; a stream
            // that completes carries the provider's own assembled text in the
            // terminal event, which cannot disagree with its own usage.
            "response.output_text.delta"
            | "response.refusal.delta"
            | "response.reasoning_summary_text.delta"
            | "response.function_call_arguments.delta" => self.generated = true,
            "response.completed" => self.finish(&value, Outcome::Completed),
            "response.incomplete" => self.finish(&value, Outcome::Incomplete),
            "response.failed" => self.finish(&value, Outcome::Failed),
            "error" => {
                self.error = Some(
                    value
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("the provider sent an error event")
                        .to_owned(),
                );
            }
            _ => {}
        }
    }

    fn finish(&mut self, value: &Value, outcome: Outcome) {
        self.outcome = Some(outcome);
        if let Some(r) = value.get("response") {
            self.terminal = Some(r.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(acc: &mut Accumulator, events: &[(&str, &str)]) {
        for (name, data) in events {
            acc.event(name, data);
        }
    }

    const CREATED: (&str, &str) = (
        "response.created",
        r#"{"type":"response.created","sequence_number":0,
            "response":{"id":"resp_abc","status":"in_progress","usage":null}}"#,
    );

    const DELTA: (&str, &str) = (
        "response.output_text.delta",
        r#"{"type":"response.output_text.delta","sequence_number":3,"delta":"Hel"}"#,
    );

    const COMPLETED: (&str, &str) = (
        "response.completed",
        r#"{"type":"response.completed","sequence_number":9,
            "response":{"id":"resp_abc","status":"completed",
              "output":[{"type":"message","content":[{"type":"output_text","text":"Hello"}]}],
              "usage":{"input_tokens":25,"output_tokens":15,"total_tokens":40}}}"#,
    );

    #[test]
    fn a_whole_stream_yields_the_terminal_response_object() {
        let mut acc = Accumulator::new();
        feed(&mut acc, &[CREATED, DELTA, COMPLETED]);

        assert_eq!(acc.outcome(), Some(Outcome::Completed));
        assert_eq!(acc.id(), Some("resp_abc"));
        let terminal = acc.terminal().expect("the terminal event carries it");
        assert_eq!(terminal["usage"]["output_tokens"], 15);
        assert_eq!(terminal["status"], "completed");
    }

    /// The asymmetry with Anthropic, asserted rather than assumed.
    ///
    /// If this ever stops being true — if `OpenAI` starts reporting usage
    /// incrementally — the driver should report `Interrupted` with real numbers
    /// instead of `Unaccounted`, and this test is where that shows up.
    #[test]
    fn nothing_before_the_terminal_event_says_what_it_cost() {
        let mut acc = Accumulator::new();
        feed(&mut acc, &[CREATED, DELTA]);
        assert!(
            acc.terminal().is_none(),
            "usage arrives only in the terminal event; a severed stream cannot \
             bill what it does not know"
        );
        assert!(acc.generated(), "but it certainly generated");
    }

    #[test]
    fn generation_is_not_claimed_before_any_output() {
        let mut acc = Accumulator::new();
        feed(&mut acc, &[CREATED]);
        assert!(
            !acc.generated(),
            "an id and an in_progress status are not evidence that tokens were \
             produced — treating them as such makes every failed handshake \
             un-retryable"
        );
    }

    /// Billed output the caller never sees is still evidence of generation.
    #[test]
    fn reasoning_refusal_and_tool_deltas_all_count_as_generation() {
        for event in [
            "response.refusal.delta",
            "response.reasoning_summary_text.delta",
            "response.function_call_arguments.delta",
        ] {
            let mut acc = Accumulator::new();
            acc.event(event, &format!(r#"{{"type":"{event}","delta":"x"}}"#));
            assert!(acc.generated(), "{event} is billed output");
        }
    }

    #[test]
    fn an_incomplete_response_is_terminal_and_carries_usage() {
        let mut acc = Accumulator::new();
        feed(
            &mut acc,
            &[
                CREATED,
                DELTA,
                (
                    "response.incomplete",
                    r#"{"type":"response.incomplete","response":{"status":"incomplete",
                        "incomplete_details":{"reason":"max_output_tokens"},
                        "usage":{"input_tokens":25,"output_tokens":999}}}"#,
                ),
            ],
        );
        assert_eq!(acc.outcome(), Some(Outcome::Incomplete));
        let t = acc.terminal().unwrap();
        assert_eq!(t["incomplete_details"]["reason"], "max_output_tokens");
        assert_eq!(t["usage"]["output_tokens"], 999);
    }

    #[test]
    fn a_failed_response_is_terminal() {
        let mut acc = Accumulator::new();
        feed(
            &mut acc,
            &[
                CREATED,
                (
                    "response.failed",
                    r#"{"type":"response.failed","response":{"status":"failed",
                        "error":{"code":"server_error","message":"boom"},
                        "usage":{"input_tokens":25,"output_tokens":3}}}"#,
                ),
            ],
        );
        assert_eq!(acc.outcome(), Some(Outcome::Failed));
        assert_eq!(acc.terminal().unwrap()["status"], "failed");
    }

    #[test]
    fn an_error_event_is_captured() {
        let mut acc = Accumulator::new();
        acc.event("error", r#"{"type":"error","message":"upstream exploded"}"#);
        assert_eq!(acc.error(), Some("upstream exploded"));
    }

    #[test]
    fn unknown_event_types_are_ignored() {
        let mut acc = Accumulator::new();
        feed(
            &mut acc,
            &[
                CREATED,
                (
                    "response.some_new_tool.delta",
                    r#"{"type":"response.some_new_tool.delta"}"#,
                ),
                COMPLETED,
            ],
        );
        assert_eq!(acc.outcome(), Some(Outcome::Completed));
    }

    #[test]
    fn a_malformed_event_does_not_lose_the_rest() {
        let mut acc = Accumulator::new();
        acc.event("response.created", "{not json");
        feed(&mut acc, &[CREATED, COMPLETED]);
        assert_eq!(acc.outcome(), Some(Outcome::Completed));
    }
}
