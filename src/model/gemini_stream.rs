//! Reassembling a `streamGenerateContent` SSE stream into one response.
//!
//! Gemini streams *whole* `GenerateContentResponse` objects, not field deltas:
//! every event carries a complete envelope whose `candidates[0].content.parts`
//! holds the slice generated since the last one. So reassembly is concatenation
//! rather than patching, and the accumulator's job is to produce the identical
//! envelope a buffered call returns — which is what lets both paths share one
//! interpretation and makes it impossible for them to disagree about what a
//! usable answer is.
//!
//! # Parts are merged, never rewritten
//!
//! Only *adjacent text-only* parts are joined. Everything else is kept in
//! arrival order, byte for byte, because a part may carry a `thoughtSignature`
//! — the encrypted reasoning token Gemini 3 requires back on the next turn and
//! rejects the turn without. An accumulator that rebuilt parts from the fields
//! it understood would drop exactly that, and the failure would not appear
//! until the *second* tool turn of a conversation.
//!
//! A text-only part is the one shape that can be merged safely: it has nothing
//! attached to lose. The test that matters is the one asserting a signature
//! survives a stream, because concatenating text is the obvious thing to do to
//! every part and it is right for only one of them.

use serde_json::{Value, json};

/// Reassembles streamed chunks into one `GenerateContentResponse`.
#[derive(Debug, Default)]
pub(super) struct Accumulator {
    /// Parts in arrival order, adjacent text-only ones already merged.
    parts: Vec<Value>,
    /// The role the model answered under, as it named it.
    role: Option<String>,
    finish_reason: Option<String>,
    /// The latest `usageMetadata` seen.
    ///
    /// Gemini reports cumulative totals rather than increments, so the last one
    /// wins rather than being summed — summing would multiply the bill by the
    /// number of chunks, which is the kind of error a small fixture hides
    /// because two chunks look plausible either way.
    usage: Option<Value>,
    /// Whether any content at all has arrived.
    ///
    /// The whole judgement a severed stream needs: before the first part the
    /// call is safe to repeat, after it the provider generated tokens this
    /// driver may not be able to count.
    generated: bool,
    prompt_feedback: Option<Value>,
}

impl Accumulator {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Absorb one SSE event's data, returning any visible text it added.
    ///
    /// The returned text is what an observer may be shown live. Opaque
    /// reasoning is never returned: a part marked `thought` is the model's
    /// internal reasoning, which this crate does not expose to callers on any
    /// provider — it is kept for the continuation and nothing else.
    pub(super) fn push(&mut self, data: &str) -> Option<String> {
        let chunk: Value = serde_json::from_str(data).ok()?;
        let candidate = chunk.get("candidates")?.get(0)?;

        if let Some(usage) = chunk.get("usageMetadata") {
            self.usage = Some(usage.clone());
        }
        if let Some(feedback) = chunk.get("promptFeedback") {
            self.prompt_feedback = Some(feedback.clone());
        }
        if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str) {
            self.finish_reason = Some(reason.to_owned());
        }
        let content = candidate.get("content");
        if let Some(role) = content.and_then(|c| c.get("role")).and_then(Value::as_str) {
            self.role = Some(role.to_owned());
        }

        let mut visible = String::new();
        for part in content
            .and_then(|c| c.get("parts"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            self.generated = true;
            if is_plain_text(part) {
                let text = part.get("text").and_then(Value::as_str).unwrap_or_default();
                visible.push_str(text);
                match self.parts.last_mut().filter(|last| is_plain_text(last)) {
                    // Merged in place: a stream that emitted one part per token
                    // would otherwise produce a parts array as long as the
                    // answer, which is a different document from the one a
                    // buffered call returns.
                    Some(last) => {
                        let joined = format!(
                            "{}{text}",
                            last.get("text").and_then(Value::as_str).unwrap_or_default()
                        );
                        *last = json!({ "text": joined });
                    }
                    None => self.parts.push(part.clone()),
                }
            } else {
                // Verbatim. A `thoughtSignature`, a `functionCall`, an
                // `inlineData` — anything with something attached is kept as
                // sent, because the next request has to return it exactly.
                self.parts.push(part.clone());
            }
        }
        (!visible.is_empty()).then_some(visible)
    }

    /// Whether the model said why it stopped.
    pub(super) fn done(&self) -> bool {
        self.finish_reason.is_some()
    }

    /// Whether anything was generated, for classifying a severed stream.
    pub(super) const fn generated(&self) -> bool {
        self.generated
    }

    /// The usage block as last reported, wrapped in the envelope shape the
    /// buffered path's parser reads.
    ///
    /// Gemini sends `usageMetadata` on the chunks themselves and reports it
    /// cumulatively, so a stream that dies mid-answer has already been told
    /// what it burned. That is the whole reason streaming is this driver's
    /// default, and reaching it needs an accessor: a severed stream that could
    /// not see this would report a cost of zero for tokens the provider will
    /// invoice.
    ///
    /// The envelope rather than the bare block, so the caller parses it with
    /// the *same* function the buffered path uses. That normalisation — thought
    /// tokens billed as output and added, cached input a subset and not added —
    /// is the part that costs real money when got wrong, and a second spelling
    /// of it here would be free to disagree with the first.
    pub(super) fn usage_envelope(&self) -> Option<Value> {
        self.usage
            .clone()
            .map(|usage| json!({ "usageMetadata": usage }))
    }

    /// The envelope a buffered call would have returned.
    pub(super) fn into_response(self) -> Value {
        let mut response = json!({
            "candidates": [{
                "content": {
                    "role": self.role.unwrap_or_else(|| "model".to_owned()),
                    "parts": self.parts,
                },
                "finishReason": self.finish_reason,
            }],
        });
        if let Some(usage) = self.usage {
            response["usageMetadata"] = usage;
        }
        if let Some(feedback) = self.prompt_feedback {
            response["promptFeedback"] = feedback;
        }
        response
    }
}

/// Whether a part is text and nothing else.
///
/// Deliberately strict: `text` may be the only key. A part carrying `text`
/// *and* `thoughtSignature` is a signed part that merging would destroy, and a
/// part carrying `text` and `thought: true` is opaque reasoning rather than the
/// answer. Both fail this test and are kept whole.
fn is_plain_text(part: &Value) -> bool {
    part.as_object()
        .is_some_and(|object| object.len() == 1 && object.contains_key("text"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjacent_text_is_joined_and_signed_parts_survive() {
        let mut acc = Accumulator::new();
        assert_eq!(
            acc.push(r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"Hel"}]}}]}"#),
            Some("Hel".to_owned())
        );
        assert_eq!(
            acc.push(r#"{"candidates":[{"content":{"parts":[{"text":"lo"}]}}]}"#),
            Some("lo".to_owned())
        );
        // A signed function call, arriving whole in its own chunk.
        assert_eq!(
            acc.push(
                r#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"f","args":{}},
                   "thoughtSignature":"SIG"}]},"finishReason":"STOP"}],
                   "usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":4}}"#
            ),
            None,
            "a function call is not visible text"
        );
        assert!(acc.done());
        assert!(acc.generated());

        let response = acc.into_response();
        let parts = response["candidates"][0]["content"]["parts"]
            .as_array()
            .expect("parts");
        assert_eq!(parts.len(), 2, "text was not merged: {parts:?}");
        assert_eq!(parts[0]["text"], "Hello");
        assert_eq!(
            parts[1]["thoughtSignature"], "SIG",
            "the signature Gemini 3 requires back was lost reassembling the stream"
        );
        assert_eq!(response["usageMetadata"]["candidatesTokenCount"], 4);
    }

    /// Usage is cumulative, so the last chunk wins rather than the sum.
    #[test]
    fn usage_is_taken_from_the_last_chunk_not_summed() {
        let mut acc = Accumulator::new();
        acc.push(r#"{"candidates":[{"content":{"parts":[{"text":"a"}]}}],"usageMetadata":{"candidatesTokenCount":1}}"#);
        acc.push(r#"{"candidates":[{"content":{"parts":[{"text":"b"}]},"finishReason":"STOP"}],"usageMetadata":{"candidatesTokenCount":9}}"#);
        assert_eq!(
            acc.into_response()["usageMetadata"]["candidatesTokenCount"],
            9
        );
    }

    /// Nothing generated is the state that makes a severed stream repeatable.
    #[test]
    fn an_empty_stream_reports_nothing_generated() {
        let acc = Accumulator::new();
        assert!(!acc.generated());
        assert!(!acc.done());
    }
}
