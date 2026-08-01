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
///   the one case where retrying is unambiguously safe *and* free.
/// * **4xx** is a refusal before generating — bad request, unknown model, bad
///   key, content filtered on the way in. Nothing was metered, and repeating is
///   pointless rather than merely unsafe.
/// * **anything else** reached the provider and did not say what it cost. See
///   [`ModelError::Unavailable`]: guessing "free" lets a retry loop spend
///   against a ceiling reading zero, and guessing "fatal" makes a transient blip
///   end a run.
pub fn classify_status(model: &ModelId, status: u16, body: &str) -> ModelError {
    let detail = format!("HTTP {status}: {}", trim(body));
    match status {
        429 | 529 => ModelError::RateLimited {
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
/// The provider enforced the shape *during generation*, which is the whole point
/// of asking for a schema — a constraint applied afterwards rejects an answer you
/// have already paid for. What this adds is the parse, so a provider bug becomes
/// a loud, metered `Unusable` rather than a panic three steps downstream.
///
/// **The schema is deliberately not re-validated here.** A second JSON Schema
/// implementation could disagree with the one that did the enforcing, and the
/// disagreement would surface as a run refusing an answer that is in fact
/// conformant. A caller who needs certainty beyond "it parsed" validates it.
///
/// # Errors
///
/// [`ModelError::Unusable`], carrying the usage — because a malformed answer was
/// still generated and still billed.
pub fn structured(
    schema: Option<&serde_json::Value>,
    text: &str,
    model: &ModelId,
    usage: super::Usage,
) -> Result<Option<serde_json::Value>, ModelError> {
    let Some(_) = schema else { return Ok(None) };
    serde_json::from_str(text)
        .map(Some)
        .map_err(|e| ModelError::Unusable {
            model: model.clone(),
            usage,
            detail: format!("a schema was required and the answer is not JSON: {e}"),
        })
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

    #[test]
    fn rate_limiting_is_told_apart_from_refusal() {
        for s in [429u16, 529] {
            assert!(matches!(
                classify_status(&model(), s, ""),
                ModelError::RateLimited { .. }
            ));
        }
    }

    #[test]
    fn a_client_error_did_not_generate() {
        for s in [400u16, 401, 403, 404, 422] {
            let e = classify_status(&model(), s, "");
            assert_eq!(e.disposition(), Disposition::DidNotHappen);
            assert_eq!(e.usage().spend().tokens, 0);
        }
    }

    #[test]
    fn a_server_error_says_it_does_not_know() {
        assert!(matches!(
            classify_status(&model(), 500, ""),
            ModelError::Unavailable { .. }
        ));
    }

    /// A provider's error body can echo the prompt back.
    #[test]
    fn a_long_error_body_is_trimmed() {
        let secret = "x".repeat(5_000);
        let e = classify_status(&model(), 400, &secret);
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
