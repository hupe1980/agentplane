//! One prompt every driver reads the same way.
//!
//! A prompt is a [`Value`] the effect key covers, and each driver accepts its
//! own wire's shape beside a shared one: `{ system, input }`, each a string or
//! a list of **text parts**. A part is `{ "type": "text", "text": .., "cache":
//! "5m" | "1h" }`, and `cache` closes a cached prefix there.
//!
//! What each driver does with a part:
//!
//! | Driver | Parts | A breakpoint |
//! |---|---|---|
//! | Anthropic | text blocks | `cache_control` on the block |
//! | Bedrock | text blocks | a `cachePoint` after the block |
//! | `OpenAI` Responses | `input_text` parts; `instructions` joined | ignored: the provider caches every prefix |
//! | Gemini | `parts` of one turn | ignored: Gemini caches implicitly or by a cached-content resource |
//! | Chat Completions | joined text | ignored: the server caches, or nothing does |
//!
//! Joined parts are separated by a blank line. A turn list in a driver's own
//! wire shape still passes through untouched; [`Prompt`] builds the shared one
//! with each part's label kept.

use serde_json::{Value, json};

use crate::core::Tainted;
use crate::model::CacheTtl;

/// An instruction and a question as text parts, any of which may close a
/// cached prefix — written once, sent to whichever driver is linked.
///
/// Every part is a [`Tainted`] string, so each keeps its own label in the
/// assembled prompt: the instruction slot is a protected field that only
/// trusted material may fill, and a part's provenance is the caller's to
/// state rather than this builder's to assume.
///
/// ```
/// # use agentplane::core::{SourceId, Tainted};
/// # use agentplane::model::{CacheTtl, Prompt};
/// let prompt = Prompt::new()
///     .system_cached(Tainted::trusted("You review patches.".to_owned()), CacheTtl::OneHour)
///     .input(Tainted::from_source("diff --git …".to_owned(), SourceId::new("tool://git/diff")))
///     .build();
/// assert_eq!(prompt.peek()["system"][0]["cache"], "1h");
/// ```
#[derive(Debug, Clone, Default)]
pub struct Prompt {
    system: Vec<Tainted<Value>>,
    input: Vec<Tainted<Value>>,
}

impl Prompt {
    /// An empty prompt.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a part to the instruction.
    #[must_use]
    pub fn system(mut self, text: Tainted<String>) -> Self {
        self.system.push(part(text, None));
        self
    }

    /// Append a part to the instruction, and cache everything up to it.
    #[must_use]
    pub fn system_cached(mut self, text: Tainted<String>, ttl: CacheTtl) -> Self {
        self.system.push(part(text, Some(ttl)));
        self
    }

    /// Append a part to the question.
    #[must_use]
    pub fn input(mut self, text: Tainted<String>) -> Self {
        self.input.push(part(text, None));
        self
    }

    /// Append a part to the question, and cache everything up to it.
    #[must_use]
    pub fn input_cached(mut self, text: Tainted<String>, ttl: CacheTtl) -> Self {
        self.input.push(part(text, Some(ttl)));
        self
    }

    /// The prompt, with every part's label kept at its own path.
    #[must_use]
    pub fn build(self) -> Tainted<Value> {
        let mut fields = Vec::with_capacity(2);
        if !self.system.is_empty() {
            fields.push(("system", Tainted::array(self.system)));
        }
        fields.push(("input", Tainted::array(self.input)));
        Tainted::object(fields)
    }
}

fn part(text: Tainted<String>, cache: Option<CacheTtl>) -> Tainted<Value> {
    text.map(|text| match cache {
        Some(ttl) => json!({ "type": "text", "text": text, "cache": ttl.as_str() }),
        None => json!({ "type": "text", "text": text }),
    })
}

/// One text part, as a driver reads it.
#[cfg(any(feature = "providers", feature = "bedrock"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Part<'a> {
    pub(crate) text: std::borrow::Cow<'a, str>,
    pub(crate) cache: Option<CacheTtl>,
}

#[cfg(any(feature = "providers", feature = "bedrock"))]
impl<'a> Part<'a> {
    fn plain(text: impl Into<std::borrow::Cow<'a, str>>) -> Self {
        Self {
            text: text.into(),
            cache: None,
        }
    }
}

/// The question, in the one vocabulary every driver reads.
#[cfg(any(feature = "providers", feature = "bedrock"))]
#[derive(Debug)]
pub(crate) enum Turns<'a> {
    /// The driver's own turn list, passed through untouched.
    Native(&'a [Value]),
    /// One user turn of text parts.
    Parts(Vec<Part<'a>>),
}

/// The instruction, when the prompt has one.
#[cfg(any(feature = "providers", feature = "bedrock"))]
#[derive(Debug)]
pub(crate) enum System<'a> {
    /// Text parts — a bare string is one.
    Parts(Vec<Part<'a>>),
    /// Any other value: a driver whose wire has a structured form passes it
    /// through, and every other driver sends its JSON text.
    #[cfg_attr(
        not(feature = "providers"),
        expect(
            dead_code,
            reason = "Converse refuses a structured instruction outright"
        )
    )]
    Native(&'a Value),
}

/// `value` as text parts, when it is a non-empty list of them.
///
/// A part carries `type: "text"`, a string `text`, and at most a `cache`; a
/// list holding anything else is a wire's own turn list, whose items always
/// carry a `role` or another `type`.
#[cfg(any(feature = "providers", feature = "bedrock"))]
pub(crate) fn parts(value: &Value) -> Option<Vec<Part<'_>>> {
    let items = value.as_array().filter(|items| !items.is_empty())?;
    items
        .iter()
        .map(|item| {
            let map = item.as_object()?;
            if map.get("type").and_then(Value::as_str) != Some("text")
                || !map
                    .keys()
                    .all(|k| matches!(k.as_str(), "type" | "text" | "cache"))
            {
                return None;
            }
            let cache = match map.get("cache") {
                None => None,
                Some(ttl) => Some(serde_json::from_value::<CacheTtl>(ttl.clone()).ok()?),
            };
            Some(Part {
                text: map.get("text")?.as_str()?.into(),
                cache,
            })
        })
        .collect()
}

/// The question a prompt asks.
///
/// `natives` are the keys under which this driver's wire takes its own turn
/// list. A bare string, an `input` string, and an `input` list of parts are
/// text; an object that is not an envelope is content, sent as its JSON text
/// without `system`, which is an instruction about it rather than part of it.
#[cfg(any(feature = "providers", feature = "bedrock"))]
pub(crate) fn turns<'a>(prompt: &'a Value, natives: &[&str]) -> Turns<'a> {
    match prompt {
        Value::String(text) => return Turns::Parts(vec![Part::plain(text.as_str())]),
        Value::Array(items) => {
            return parts(prompt).map_or(Turns::Native(items), Turns::Parts);
        }
        _ => {}
    }
    for key in natives {
        if let Some(list @ Value::Array(items)) = super::prompt_envelope(prompt, key) {
            return parts(list).map_or(Turns::Native(items), Turns::Parts);
        }
    }
    if let Some(input) = super::prompt_envelope(prompt, "input") {
        return match input {
            Value::String(text) => Turns::Parts(vec![Part::plain(text.as_str())]),
            other => parts(other).map_or_else(
                || Turns::Parts(vec![Part::plain(other.to_string())]),
                Turns::Parts,
            ),
        };
    }
    let mut rest = prompt.clone();
    if let Some(map) = rest.as_object_mut() {
        map.remove("system");
    }
    Turns::Parts(vec![Part::plain(rest.to_string())])
}

/// The instruction a prompt carries, if any.
#[cfg(any(feature = "providers", feature = "bedrock"))]
pub(crate) fn system(prompt: &Value) -> Option<System<'_>> {
    let system = prompt.get("system").filter(|s| !s.is_null())?;
    Some(match system {
        Value::String(text) => System::Parts(vec![Part::plain(text.as_str())]),
        other => parts(other).map_or(System::Native(other), System::Parts),
    })
}

/// Parts as one string, for a wire that takes no blocks.
#[cfg(feature = "providers")]
pub(crate) fn joined(parts: &[Part<'_>]) -> String {
    parts
        .iter()
        .map(|part| part.text.as_ref())
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// The instruction as one string, for a wire whose instruction is text.
#[cfg(feature = "providers")]
pub(crate) fn system_text(prompt: &Value) -> Option<String> {
    system(prompt).map(|system| match system {
        System::Parts(parts) => joined(&parts),
        System::Native(other) => other.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::Prompt;
    use crate::core::{SourceId, Tainted};

    /// **Every part keeps its own label.** The instruction slot is a protected
    /// field only trusted material may fill, so a builder that trusted what it
    /// was handed would launder an untrusted part into it — and one that
    /// flattened the parts would taint a trusted instruction with the question.
    #[test]
    fn each_part_keeps_its_label() {
        let prompt = Prompt::new()
            .system(Tainted::trusted("policy".to_owned()))
            .system(Tainted::from_source(
                "a page".to_owned(),
                SourceId::new("web"),
            ))
            .input(Tainted::trusted("the task".to_owned()))
            .build();
        let label = |path: &str| prompt.label_at(path).expect(path).is_untrusted();
        assert!(!label("/system/0"), "a trusted part was tainted");
        assert!(label("/system/1"), "an untrusted part was trusted");
        assert!(
            label("/system"),
            "the slot does not carry its untrusted part"
        );
        assert!(!label("/input"));
    }
}
