//! A model provider with no model behind it.
//!
//! For tests, examples, and local runs where the point is the *plane* rather
//! than the answer. Lives in `testkit` — off by default, never in a production
//! build — for the same reason [`StubSigner`](super::StubSigner) does: something
//! that stands in for a real component must not be reachable by accident.
//!
//! # Two traps, both of which make a fake worse than useless
//!
//! **A fake that is not deterministic destroys the property under test.** This
//! crate exists so a run replays to the same answer; a fake returning arbitrary
//! text would make every example non-replayable and every replay test a
//! coin-toss that mostly passes. So the default answer is a pure function of the
//! prompt, and scripted answers are consumed in a fixed order.
//!
//! **A fake that reports zero usage makes every budget test vacuous.** Token
//! ceilings, cost ceilings, the metered-failure path — all of them read
//! [`Usage`], and a provider that always answers "free" lets them pass over a
//! runtime that has stopped counting. So usage is derived from the prompt, and
//! scripted failures can carry usage of their own.
//!
//! # What it does not fake
//!
//! Intelligence. The default answer is an echo, not a plausible completion. A
//! fake that produced convincing prose would invite tests that assert on
//! *content*, which is the one thing a real provider will never reproduce.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::model::{Completion, ModelError, ModelId, ModelProvider, Request, Usage};

/// What the fake was asked.
#[derive(Debug, Clone, PartialEq)]
pub struct Ask {
    pub model: ModelId,
    pub prompt: Value,
    pub schema: Option<Value>,
}

/// A `ModelProvider` that answers without a model.
#[derive(Debug, Default)]
pub struct FakeProvider {
    /// Answers handed out in order, before the default takes over.
    scripted: Mutex<std::collections::VecDeque<Result<Completion, ModelError>>>,
    /// Every call, in order.
    asked: Mutex<Vec<Ask>>,
}

impl FakeProvider {
    /// A provider that always echoes.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Queue one answer. Consumed before the default echo.
    ///
    /// Takes `&self` rather than `self` so a test can arrange a provider it has
    /// already handed to a runtime — which is the usual shape, because the
    /// runtime wants an `Arc` at construction.
    pub fn will_answer(&self, completion: Completion) -> &Self {
        self.scripted
            .lock()
            .expect("fake")
            .push_back(Ok(completion));
        self
    }

    /// Queue one failure.
    ///
    /// Use the metered variants — `Unusable`, `Interrupted` — to exercise the
    /// path that matters: a call that generated, cost money, and produced
    /// nothing usable. A fake that can only fail for free cannot test the
    /// ceiling that exists for exactly that case.
    pub fn will_fail(&self, error: ModelError) -> &Self {
        self.scripted.lock().expect("fake").push_back(Err(error));
        self
    }

    /// Queue a plain text answer with usage derived from its length.
    pub fn will_say(&self, text: impl Into<String>) -> &Self {
        let text = text.into();
        let usage = usage_for(&json!(&text));
        self.will_answer(Completion {
            text,
            usage,
            stop_reason: Some("end_turn".to_owned()),
            truncated: false,
            structured: None,
        })
    }

    /// Everything it was asked, in order.
    #[must_use]
    pub fn asked(&self) -> Vec<Ask> {
        self.asked.lock().expect("fake").clone()
    }

    /// How many times it was called.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.asked.lock().expect("fake").len()
    }

    /// Whether every scripted answer was used.
    ///
    /// Worth asserting at the end of a test: leftover answers mean the run made
    /// fewer calls than the test believed, and a test that scripts three
    /// responses and checks the result of one is not testing what it thinks.
    #[must_use]
    pub fn script_exhausted(&self) -> bool {
        self.scripted.lock().expect("fake").is_empty()
    }
}

/// Deterministic token counts, so budgets are exercised rather than bypassed.
///
/// Four bytes to a token is wrong for every real tokenizer and right for this
/// purpose: it is stable, monotonic in prompt size, and never zero — which are
/// the three properties a budget test actually depends on.
fn usage_for(prompt: &Value) -> Usage {
    let len = prompt.to_string().len() as u64;
    Usage {
        input_tokens: (len / 4).max(1),
        output_tokens: (len / 8).max(1),
        cache_write_tokens: 0,
        cache_read_tokens: 0,
        minor_units: 0,
    }
}

/// The default answer: a pure function of the request.
///
/// An echo rather than plausible prose, deliberately. A fake that produced
/// convincing text would invite assertions on content, and content is the one
/// thing a real provider will never reproduce.
fn echo(request: &Request<'_>) -> Completion {
    let usage = usage_for(request.prompt);
    match request.schema {
        // A schema was asked for, so the answer must satisfy the *shape*
        // contract: valid JSON. Built from the schema's declared properties so
        // it is at least plausibly conformant, without this file becoming a
        // JSON Schema implementation.
        Some(schema) => {
            let value = sample(schema);
            Completion {
                text: value.to_string(),
                usage,
                stop_reason: Some("end_turn".to_owned()),
                truncated: false,
                structured: Some(value),
            }
        }
        None => Completion {
            text: format!("fake answer to {}", request.prompt),
            usage,
            stop_reason: Some("end_turn".to_owned()),
            truncated: false,
            structured: None,
        },
    }
}

/// A minimal value satisfying a schema's declared types.
///
/// Handles the shapes a test is likely to declare and falls back to `null`
/// elsewhere. Not a JSON Schema implementation and not trying to be — the
/// crate deliberately does not validate schemas, so a fake that did would be
/// asserting a contract the real path never checks.
fn sample(schema: &Value) -> Value {
    match schema.get("type").and_then(Value::as_str) {
        Some("object") => {
            let mut out = serde_json::Map::new();
            if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                for (name, sub) in props {
                    out.insert(name.clone(), sample(sub));
                }
            }
            Value::Object(out)
        }
        Some("array") => match schema.get("items") {
            Some(items) => json!([sample(items)]),
            None => json!([]),
        },
        Some("string") => json!("fake"),
        Some("number" | "integer") => json!(0),
        Some("boolean") => json!(false),
        _ => Value::Null,
    }
}

#[async_trait]
impl ModelProvider for FakeProvider {
    async fn complete(&self, request: Request<'_>) -> Result<Completion, ModelError> {
        self.asked.lock().expect("fake").push(Ask {
            model: request.model.clone(),
            prompt: request.prompt.clone(),
            schema: request.schema.cloned(),
        });

        // Scoped so the guard is gone before anything else happens: a lock held
        // across a suspension is held on the thread, and this one is taken on
        // every model call in the suite.
        let scripted = self.scripted.lock().expect("fake").pop_front();
        scripted.unwrap_or_else(|| Ok(echo(&request)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> ModelId {
        ModelId::new("fake", "m")
    }

    fn ask(schema: Option<&Value>) -> Request<'static> {
        // Leaked so the borrow is `'static` and the test reads as one line.
        // A test binary's leak is a test binary's problem.
        let prompt: &'static Value = Box::leak(Box::new(json!({"q": "what is the balance"})));
        let model: &'static ModelId = Box::leak(Box::new(model()));
        Request {
            model,
            prompt,
            schema: schema.map(|s| &*Box::leak(Box::new(s.clone()))),
        }
    }

    /// The property the whole crate rests on. A fake that broke it would make
    /// every replay test a coin-toss that mostly passes.
    #[tokio::test]
    async fn the_same_question_gets_the_same_answer() {
        let p = FakeProvider::new();
        let a = p.complete(ask(None)).await.unwrap();
        let b = p.complete(ask(None)).await.unwrap();
        assert_eq!(a.text, b.text);
        assert_eq!(a.usage, b.usage);
    }

    /// Trap two: a provider that always answers "free" lets every budget test
    /// pass over a runtime that has stopped counting.
    #[tokio::test]
    async fn an_answer_is_never_free() {
        let p = FakeProvider::new();
        let c = p.complete(ask(None)).await.unwrap();
        assert!(
            c.usage.spend().tokens > 0,
            "a fake reporting zero usage makes every ceiling test vacuous"
        );
    }

    /// Longer prompt, more tokens — so a test can drive a run *over* a ceiling
    /// rather than merely up to a non-zero one.
    #[tokio::test]
    async fn usage_grows_with_the_prompt() {
        let p = FakeProvider::new();
        let short: &'static Value = Box::leak(Box::new(json!("hi")));
        let long: &'static Value = Box::leak(Box::new(json!("hi".repeat(500))));
        let m = model();
        let a = p
            .complete(Request {
                model: &m,
                prompt: short,
                schema: None,
            })
            .await
            .unwrap();
        let b = p
            .complete(Request {
                model: &m,
                prompt: long,
                schema: None,
            })
            .await
            .unwrap();
        assert!(b.usage.spend().tokens > a.usage.spend().tokens);
    }

    #[tokio::test]
    async fn scripted_answers_come_back_in_order_then_the_default_takes_over() {
        let p = FakeProvider::new();
        p.will_say("first").will_say("second");

        assert_eq!(p.complete(ask(None)).await.unwrap().text, "first");
        assert_eq!(p.complete(ask(None)).await.unwrap().text, "second");
        assert!(p.script_exhausted());
        assert!(
            p.complete(ask(None)).await.unwrap().text.contains("fake"),
            "past the script, the default echo answers"
        );
        assert_eq!(p.calls(), 3);
    }

    /// The path that matters: a call that generated, was billed, and produced
    /// nothing usable.
    #[tokio::test]
    async fn a_scripted_failure_can_carry_usage() {
        let p = FakeProvider::new();
        p.will_fail(ModelError::Interrupted {
            model: model(),
            usage: Usage {
                input_tokens: 100,
                output_tokens: 300,
                ..Usage::default()
            },
            detail: "reset".to_owned(),
        });
        let e = p.complete(ask(None)).await.expect_err("scripted");
        assert_eq!(e.usage().spend().tokens, 400);
    }

    #[tokio::test]
    async fn a_schema_gets_json_shaped_like_it() {
        let schema = json!({
            "type": "object",
            "properties": {
                "verdict": {"type": "string"},
                "score":   {"type": "integer"},
                "flags":   {"type": "array", "items": {"type": "boolean"}},
            },
        });
        let p = FakeProvider::new();
        let c = p.complete(ask(Some(&schema))).await.unwrap();
        let v = c.structured.expect("a schema was asked for");
        assert_eq!(v["verdict"], json!("fake"));
        assert_eq!(v["score"], json!(0));
        assert_eq!(v["flags"], json!([false]));
        assert_eq!(
            c.text,
            v.to_string(),
            "`text` holds the raw string even when a schema was parsed"
        );
    }

    #[tokio::test]
    async fn no_schema_means_no_structured_value() {
        let p = FakeProvider::new();
        assert!(p.complete(ask(None)).await.unwrap().structured.is_none());
    }

    #[tokio::test]
    async fn it_records_what_it_was_asked() {
        let schema = json!({"type": "string"});
        let p = FakeProvider::new();
        p.complete(ask(None)).await.unwrap();
        p.complete(ask(Some(&schema))).await.unwrap();

        let asked = p.asked();
        assert_eq!(asked.len(), 2);
        assert_eq!(asked[0].model, model());
        assert_eq!(asked[0].schema, None);
        assert_eq!(asked[1].schema, Some(schema));
    }
}
