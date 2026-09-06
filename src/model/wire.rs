//! What an HTTP failure means for a model call.
//!
//! Shared by every driver that speaks HTTP, because the mapping is **doctrine
//! rather than vendor detail** and two copies of it would drift. The question a
//! driver has to answer is not "what did the provider say" but:
//!
//! 1. did it reach them, and
//! 2. did it cost anything.
//!
//! Those two answers decide whether the runtime may ask again and whether the
//! budget ceiling is telling the truth. Everything else — field names, envelope
//! shapes, which key holds the token counts — is per-provider and stays in the
//! driver.

use super::{ModelError, ModelId};

/// Classify a non-success HTTP status.
///
/// Every driver routes its non-2xx responses through here, so the rules live in
/// one place:
///
/// * **429 and 529** are rate limiting. Separate from an ordinary refusal
///   because the response is different: this one is worth retrying, and it is
///   the one case where retrying is unambiguously safe *and* free. The
///   provider's `Retry-After` rides along, because it is the only number that
///   makes the retry useful — see [`ModelError::RateLimited`].
/// * **408 and 425** are the transient 4xx: a request the *server* timed out
///   or declined to process early, not one it judged wrong. Classed with the
///   retryable failures, because `Refused` means *repeating is pointless* and
///   these are the two 4xx codes for which repeating is the documented remedy.
/// * **every other 4xx** is a refusal before generating — bad request, unknown
///   model, bad key, content filtered on the way in. Nothing was metered, and
///   repeating is pointless rather than merely unsafe: the retry loop spends
///   no attempt on it.
/// * **anything else** reached the provider and did not say what it cost. See
///   [`ModelError::Unavailable`]: guessing "free" lets a retry loop spend
///   against a ceiling reading zero, and guessing "fatal" makes a transient blip
///   end a run.
pub fn classify_status(
    model: &ModelId,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> ModelError {
    let detail = format!("HTTP {status}: {}", trim(body));
    match status {
        429 | 529 => ModelError::RateLimited {
            model: model.clone(),
            detail,
            retry_after: retry_after(headers),
        },
        408 | 425 => ModelError::Unavailable {
            model: model.clone(),
            detail,
        },
        400..=499 => ModelError::Refused {
            model: model.clone(),
            detail,
        },
        _ => ModelError::Unavailable {
            model: model.clone(),
            detail,
        },
    }
}

/// The provider's `Retry-After`, in seconds, when it named one.
///
/// The parsing rule is [`core::retry_after_seconds`](crate::core::retry_after_seconds),
/// shared with every other wire this crate reads advice on: delta-seconds only,
/// because the HTTP-date form means trusting somebody else's clock against ours.
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    crate::core::retry_after_seconds(headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?)
}

/// Classify a failure to read a provider's answer.
///
/// One table, because the two arms are not the same claim and four drivers
/// would otherwise each decide. A **size refusal is this plane's**: the call
/// generated, so it is billed and `Landed`, and repeating it reaches the same
/// wall — that is [`ModelError::Unusable`], the same variant a 200 whose body
/// will not parse already produces, and for the same reason. A **transport
/// failure is the provider's or the network's**, and goes down the ladder every
/// driver already has for a call that died mid-answer.
///
/// `usage` is what the wire had already reported when the read stopped, and it
/// is the caller's to supply because only the caller knows. Zero on the buffered
/// path, which knowingly under-counts exactly as the parse-failure arm beside it
/// does. On the streamed path it is Anthropic's accumulator figure — that wire
/// reports usage incrementally — and zero for the other three, which report it
/// only at the end, for the same reason a severed stream there is `Unaccounted`:
/// what is unknown is the amount, not whether it happened.
pub fn classify_intake(
    model: &ModelId,
    usage: crate::model::Usage,
    e: &crate::netguard::intake::IntakeError,
) -> ModelError {
    if let Some(transport) = e.transport() {
        return classify_transport(model, transport);
    }
    ModelError::Unusable {
        model: model.clone(),
        usage,
        detail: e.to_string(),
    }
}

/// Classify a transport failure.
///
/// The distinction that matters is whether anything was written. A connection
/// that was never established sent nothing; one that failed later may have
/// delivered the request and generated an answer nobody will see.
pub fn classify_transport(model: &ModelId, e: &reqwest::Error) -> ModelError {
    if e.is_connect() {
        return ModelError::Unreachable {
            model: model.clone(),
            detail: format!("could not connect: {e}"),
        };
    }
    ModelError::Unavailable {
        model: model.clone(),
        detail: e.to_string(),
    }
}

/// Parse the answer when a schema was declared.
///
/// Provider constrained generation is the first line of defence. This also
/// parses and locally validates the answer against the exact requested schema,
/// so a provider bug or ignored constraint becomes a loud, metered `Unusable`
/// rather than invalid data reaching a later step. External schema reference
/// resolution is disabled, so validation cannot introduce hidden I/O.
///
/// # Errors
///
/// [`ModelError::Unusable`], carrying the usage — because a malformed answer was
/// still generated and still billed.
pub fn structured(
    schema: Option<&serde_json::Value>,
    text: &str,
    tool_calls: &[super::ToolCall],
    model: &ModelId,
    usage: super::Usage,
) -> Result<Option<serde_json::Value>, ModelError> {
    let Some(schema) = schema else {
        return Ok(None);
    };
    // A turn that asks for tools is not the final answer, and a schema binds
    // only the final answer — the same exemption `honour_declared_schema`
    // applies at the effect boundary. Spelled once here rather than once per
    // driver, because the copy that drifts is on whichever driver a
    // deployment does not exercise: failing a tool-asking turn does worse
    // than waste it — the error path carries no continuation, so a provider's
    // signed reasoning blocks are dropped from the retry, which the provider
    // then rejects. Emulated forced-tool answers pass an empty slice: there
    // the tool call *is* the answer, and its arguments must parse.
    if !tool_calls.is_empty() {
        return Ok(None);
    }
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| ModelError::Unusable {
            model: model.clone(),
            usage,
            detail: format!("a schema was required and the answer is not JSON: {e}"),
        })?;
    super::validate_schema(schema, &value).map_err(|detail| ModelError::Unusable {
        model: model.clone(),
        usage,
        detail,
    })?;
    Ok(Some(value))
}

/// The name of the single tool used when emulating structured output.
///
/// Fixed rather than caller-chosen: it goes into the request, and a name that
/// varied per call would change the request bytes without changing the
/// question, which is noise in anything that diffs them.
pub const RESPOND_TOOL: &str = "agentplane_respond";

/// Why a schema cannot be used with strict constrained decoding, if it cannot.
///
/// `OpenAI`'s strict mode accepts a **subset** of JSON Schema, and a schema that
/// is perfectly valid elsewhere is rejected with a 400 that does not say which
/// rule it broke. Checking here turns that into a refusal naming the exact
/// problem, before anything is sent and before anything is billed.
///
/// Deliberately **not** auto-corrected. Rewriting the caller's schema would mean
/// the effect key records one shape and the wire carries another — and a run
/// whose journal disagrees with what it asked for is exactly the class of quiet
/// divergence this crate exists to prevent. The caller fixes the schema.
pub fn strict_schema_problem(schema: &serde_json::Value) -> Option<String> {
    fn walk(node: &serde_json::Value, path: &str, out: &mut Vec<String>) {
        let Some(obj) = node.as_object() else { return };

        if obj.contains_key("default") {
            out.push(format!(
                "`{path}` uses `default`, which strict mode rejects"
            ));
        }

        if obj.get("type").and_then(|t| t.as_str()) == Some("object") {
            if obj.get("additionalProperties") != Some(&serde_json::Value::Bool(false)) {
                out.push(format!(
                    "`{path}` is an object without `additionalProperties: false`"
                ));
            }
            let properties = obj.get("properties").and_then(|p| p.as_object());
            if let Some(properties) = properties {
                let required: Vec<&str> = obj
                    .get("required")
                    .and_then(|r| r.as_array())
                    .map(|r| r.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                for key in properties.keys() {
                    if !required.contains(&key.as_str()) {
                        out.push(format!(
                            "`{path}.{key}` is optional; strict mode requires every \
                             property to be listed in `required`"
                        ));
                    }
                }
            }
        }

        for (key, child) in obj {
            match key.as_str() {
                "properties" | "$defs" | "definitions" => {
                    if let Some(map) = child.as_object() {
                        for (name, sub) in map {
                            walk(sub, &format!("{path}.{name}"), out);
                        }
                    }
                }
                "items" | "not" => walk(child, &format!("{path}.{key}"), out),
                "anyOf" | "oneOf" | "allOf" => {
                    if let Some(list) = child.as_array() {
                        for (i, sub) in list.iter().enumerate() {
                            walk(sub, &format!("{path}.{key}[{i}]"), out);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let mut problems = Vec::new();
    walk(schema, "schema", &mut problems);
    if problems.is_empty() {
        return None;
    }
    Some(problems.join("; "))
}

/// Keep an error body short enough to log.
///
/// A provider's error payload can carry the echoed prompt, and a prompt can
/// carry whatever the run was working on. Truncating here keeps a failure from
/// becoming an exfiltration channel into the operator's log aggregator.
fn trim(body: &str) -> String {
    const LIMIT: usize = 400;
    if body.len() <= LIMIT {
        return body.to_owned();
    }
    let mut cut = LIMIT;
    while cut > 0 && !body.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}… ({} bytes)", &body[..cut], body.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Disposition;

    fn model() -> ModelId {
        ModelId::new("test", "m")
    }

    fn no_headers() -> reqwest::header::HeaderMap {
        reqwest::header::HeaderMap::new()
    }

    fn advising(value: &str) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_str(value).expect("a header value"),
        );
        headers
    }

    /// The window is the whole point of the classification: without it the
    /// retry loop computes a schedule in hundreds of milliseconds against a
    /// limit measured in tens of seconds, spends every permitted attempt
    /// inside the window, and reports the provider as down.
    #[test]
    fn a_named_rate_limit_window_survives_classification() {
        let e = classify_status(&model(), 429, &advising("42"), "");
        assert!(
            matches!(
                e,
                ModelError::RateLimited {
                    retry_after: Some(42),
                    ..
                }
            ),
            "the provider named its window and the classification dropped it: {e}"
        );
    }

    /// A provider that throttles without saying when to come back is ordinary,
    /// and the effect's own schedule applies. What must not happen is a
    /// fabricated window: `None` is *no advice*, not zero seconds.
    #[test]
    fn an_unnamed_window_is_absent_rather_than_invented() {
        for value in [
            "",
            "  ",
            "0",
            "later",
            "-5",
            "Wed, 21 Oct 2026 07:28:00 GMT",
        ] {
            let e = classify_status(&model(), 429, &advising(value), "");
            assert!(
                matches!(
                    e,
                    ModelError::RateLimited {
                        retry_after: None,
                        ..
                    }
                ),
                "'{value}' is not advice this crate can act on, and reading it as \
                 one would replace a real backoff with a made-up schedule: {e}"
            );
        }
        assert!(matches!(
            classify_status(&model(), 429, &no_headers(), ""),
            ModelError::RateLimited {
                retry_after: None,
                ..
            }
        ));
    }

    #[test]
    fn rate_limiting_is_told_apart_from_refusal() {
        for s in [429u16, 529] {
            assert!(matches!(
                classify_status(&model(), s, &no_headers(), ""),
                ModelError::RateLimited { .. }
            ));
        }
    }

    #[test]
    fn a_client_error_did_not_generate() {
        for s in [400u16, 401, 403, 404, 422] {
            let e = classify_status(&model(), s, &no_headers(), "");
            assert_eq!(e.disposition(), Disposition::DidNotHappen);
            assert_eq!(e.usage().spend().tokens, 0);
            assert!(
                matches!(e, ModelError::Refused { .. }),
                "HTTP {s} is a judgement about the request, and repeating a \
                 judged request asks the same rule the same question"
            );
        }
    }

    /// 408 and 425 are the transient 4xx: the server timed out or declined to
    /// process *early*, not judged the request wrong. Classing them as
    /// `Refused` would make a hiccup terminal — the retry loop spends no
    /// attempt on a refusal, and these are the two 4xx codes whose documented
    /// remedy is the retry.
    #[test]
    fn the_transient_4xx_are_not_judgements() {
        for s in [408u16, 425] {
            let e = classify_status(&model(), s, &no_headers(), "");
            assert_eq!(e.disposition(), Disposition::DidNotHappen);
            assert!(
                matches!(e, ModelError::Unavailable { .. }),
                "HTTP {s} is transient and must stay retryable, got: {e}"
            );
        }
    }

    #[test]
    fn a_server_error_says_it_does_not_know() {
        assert!(matches!(
            classify_status(&model(), 500, &no_headers(), ""),
            ModelError::Unavailable { .. }
        ));
    }

    /// A provider's error body can echo the prompt back.
    #[test]
    fn a_long_error_body_is_trimmed() {
        let secret = "x".repeat(5_000);
        let e = classify_status(&model(), 400, &no_headers(), &secret);
        let rendered = e.to_string();
        assert!(
            rendered.len() < 600,
            "an error body went into the log at full length ({} chars), and a \
             provider echoes the prompt back in it",
            rendered.len()
        );
        assert!(rendered.contains("5000 bytes"), "{rendered}");
    }

    /// Multi-byte characters must not be cut through.
    #[test]
    fn trimming_respects_character_boundaries() {
        let body = "ü".repeat(1_000);
        let _ = trim(&body);
    }
}

#[cfg(test)]
mod schema_validation_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parseable_but_nonconforming_structured_output_is_unusable() {
        let model = ModelId::new("test", "structured");
        let usage = super::super::Usage {
            output_tokens: 5,
            ..Default::default()
        };
        let error = structured(
            Some(&json!({
                "type": "object",
                "properties": {"id": {"type": "string", "minLength": 5}},
                "required": ["id"]
            })),
            r#"{"id":"abc"}"#,
            &[],
            &model,
            usage,
        )
        .expect_err("provider-constrained output still needs defense-in-depth validation");
        assert!(matches!(error, ModelError::Unusable { usage: u, .. } if u == usage));
    }
}
