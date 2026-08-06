//! Rebuilding a Chat Completions answer from its chunk stream.
//!
//! The wire is simpler than the Responses event stream — every chunk is a
//! `data:` line holding a partial `chat.completion.chunk`, and the stream ends
//! with the literal `data: [DONE]` — but the reassembly has one genuinely
//! fiddly part: **tool-call arguments arrive as string fragments**, keyed by a
//! call `index`, with the id and name only on the first fragment. An
//! accumulator that keyed on id would attach every later fragment to nothing.
//!
//! The failure mapping mirrors the Responses stream's, because the wire shares
//! its blind spot: usage arrives only at the end (and only when
//! `stream_options.include_usage` is honoured), so a connection cut after
//! visible deltas leaves the driver certain generation happened and ignorant
//! of the cost — [`Unaccounted`](super::ModelError::Unaccounted), never a
//! free retry.

use serde_json::{Value, json};

/// A Chat Completions answer being rebuilt from chunks.
#[derive(Debug, Default)]
pub struct Accumulator {
    content: String,
    refusal: String,
    /// Keyed by the wire's `index`, which is the only field present on every
    /// fragment of one call.
    calls: std::collections::BTreeMap<u64, PartialCall>,
    finish_reason: Option<String>,
    usage: Option<Value>,
    /// Whether any content or tool-call fragment was seen — the judgement the
    /// severed-stream mapping turns on.
    generated: bool,
    done: bool,
}

#[derive(Debug, Default)]
struct PartialCall {
    id: String,
    name: String,
    arguments: String,
}

impl Accumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one `data:` payload. Returns the visible text delta, if this chunk
    /// carried one, for a live observer.
    pub fn push(&mut self, data: &str) -> Option<String> {
        let data = data.trim();
        if data == "[DONE]" {
            self.done = true;
            return None;
        }
        let chunk: Value = serde_json::from_str(data).ok()?;
        // The usage-bearing chunk has an empty `choices` array on the real
        // wire, so usage is read independently of the choice.
        if let Some(usage) = chunk.get("usage").filter(|u| !u.is_null()) {
            self.usage = Some(usage.clone());
        }
        let delta = chunk.get("choices")?.get(0).map_or(&Value::Null, |c| {
            if let Some(reason) = c.get("finish_reason").and_then(Value::as_str) {
                self.finish_reason = Some(reason.to_owned());
            }
            c.get("delta").unwrap_or(&Value::Null)
        });
        if let Some(refusal) = delta.get("refusal").and_then(Value::as_str) {
            self.refusal.push_str(refusal);
            self.generated = true;
        }
        for fragment in delta
            .get("tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let index = fragment.get("index").and_then(Value::as_u64).unwrap_or(0);
            let call = self.calls.entry(index).or_default();
            if let Some(id) = fragment.get("id").and_then(Value::as_str) {
                call.id.push_str(id);
            }
            if let Some(f) = fragment.get("function") {
                if let Some(name) = f.get("name").and_then(Value::as_str) {
                    call.name.push_str(name);
                }
                if let Some(arguments) = f.get("arguments").and_then(Value::as_str) {
                    call.arguments.push_str(arguments);
                }
            }
            self.generated = true;
        }
        let text = delta.get("content").and_then(Value::as_str)?;
        if text.is_empty() {
            return None;
        }
        self.content.push_str(text);
        self.generated = true;
        Some(text.to_owned())
    }

    /// Whether any output was seen — see the module docs.
    #[must_use]
    pub const fn generated(&self) -> bool {
        self.generated
    }

    /// Whether the `[DONE]` terminal arrived.
    #[must_use]
    pub const fn done(&self) -> bool {
        self.done
    }

    /// The reassembled answer, in the exact envelope a buffered call returns —
    /// so the driver reuses one parser and one interpretation for both paths.
    #[must_use]
    pub fn into_response(self) -> Value {
        json!({
            "choices": [{
                "message": {
                    "content": self.content,
                    "refusal": if self.refusal.is_empty() { Value::Null } else { Value::String(self.refusal) },
                    "tool_calls": self.calls.into_values().map(|c| json!({
                        "id": c.id,
                        "type": "function",
                        "function": { "name": c.name, "arguments": c.arguments },
                    })).collect::<Vec<_>>(),
                },
                "finish_reason": self.finish_reason,
            }],
            "usage": self.usage,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Concatenating every delta must reproduce the buffered text byte for
    /// byte — the property an observer that appends into a buffer depends on.
    #[test]
    fn deltas_reassemble_the_text_exactly() {
        let mut acc = Accumulator::new();
        let mut seen = String::new();
        for (data, expect) in [
            (
                r#"{"choices":[{"delta":{"role":"assistant","content":"Hel"}}]}"#,
                Some("Hel"),
            ),
            (r#"{"choices":[{"delta":{"content":"lo"}}]}"#, Some("lo")),
            (r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#, None),
            (
                r#"{"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2}}"#,
                None,
            ),
            ("[DONE]", None),
        ] {
            let delta = acc.push(data);
            assert_eq!(delta.as_deref(), expect, "for {data}");
            if let Some(d) = delta {
                seen.push_str(&d);
            }
        }
        assert!(acc.done());
        let out = acc.into_response();
        assert_eq!(out["choices"][0]["message"]["content"], "Hello");
        assert_eq!(seen, "Hello");
        assert_eq!(out["usage"]["prompt_tokens"], 3);
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
    }

    /// Tool-call arguments arrive as string fragments keyed by `index`, with
    /// the id and name only on the first — the reassembly this module exists
    /// for.
    #[test]
    fn tool_call_fragments_reassemble_under_their_index() {
        let mut acc = Accumulator::new();
        for data in [
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup","arguments":""}}]}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"id\":"}}]}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"x\"}"}}]}}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
            "[DONE]",
        ] {
            acc.push(data);
        }
        assert!(acc.generated());
        let out = acc.into_response();
        let call = &out["choices"][0]["message"]["tool_calls"][0];
        assert_eq!(call["id"], "call_1");
        assert_eq!(call["function"]["name"], "lookup");
        assert_eq!(call["function"]["arguments"], r#"{"id":"x"}"#);
    }

    /// Nothing seen means nothing generated — the severed-stream mapping's
    /// safe-to-repeat half.
    #[test]
    fn an_empty_stream_reports_nothing_generated() {
        let acc = Accumulator::new();
        assert!(!acc.generated());
        assert!(!acc.done());
    }
}
