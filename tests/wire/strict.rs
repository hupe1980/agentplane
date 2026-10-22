//! Which schemas each provider's strict mode accepts, held to what the
//! providers were seen to do.
//!
//! The `OpenAI` half is a probe: every shape in `strict-probe.json` was sent to
//! the Responses API as a strict function tool on the date the file names, and
//! the file records what came back. The live battery sends the same table
//! again, so a provider change is measured rather than argued. The Anthropic
//! half is held to its published limitations, because no credential here can
//! probe it.

#![cfg(feature = "providers")]

use agentplane::model::{StrictSubset, strict_schema_problem};
use serde_json::{Value, json};

fn probe() -> Value {
    serde_json::from_str(include_str!("strict-probe.json")).expect("the probe table is JSON")
}

/// **Every probed shape is classified as `OpenAI` classified it.**
///
/// The checker this replaced passed sixteen of the shapes below that the API
/// answers with a 400 — among them every argument-less tool (an object with no
/// `properties`) and every documented field of struct type (a `$ref` with a
/// sibling `description`) — so the drivers sent them `strict: true` and the
/// request failed. A shape the subset refuses although the API accepts it is
/// allowed only when the table says why: refusing costs a tool its strictness,
/// never its call.
#[test]
fn every_probed_shape_is_classified_as_openai_did() {
    let table = probe();
    let by_choice = table["refused_by_choice"]
        .as_object()
        .expect("the reasons for refusing an accepted shape");
    let cases = table["cases"].as_object().expect("the probed shapes");
    assert!(cases.len() > 60, "the probe table lost its rows");

    let mut wrong = Vec::new();
    for (name, case) in cases {
        let accepted = case["accepted"].as_bool().expect("a verdict per shape");
        let problem = StrictSubset::OpenAi.problem(&case["schema"]);
        match (accepted, &problem) {
            (false, None) => wrong.push(format!(
                "{name}: the API answers 400 and the subset passes it, so the driver sends it strict"
            )),
            (true, Some(problem)) if !by_choice.contains_key(name) => wrong.push(format!(
                "{name}: the API accepts it and the subset refuses it with no reason given: {problem}"
            )),
            (true, None) if by_choice.contains_key(name) => wrong.push(format!(
                "{name}: listed as refused by choice, and the subset accepts it"
            )),
            _ => {}
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

fn closed(properties: Value, required: &[&str]) -> Value {
    let mut schema =
        json!({ "type": "object", "required": required, "additionalProperties": false });
    schema["properties"] = properties;
    schema
}

/// **Anthropic draws the subset differently, and each driver applies its own.**
///
/// Numeric and length constraints are a 400 there and fine on `OpenAI`;
/// optional properties are the other way round. One checker for both made one
/// of them wrong whichever way it leaned.
#[test]
fn anthropic_and_openai_disagree_where_their_documentation_does() {
    let bounded = closed(json!({ "n": { "type": "integer", "minimum": 0 } }), &["n"]);
    assert_eq!(StrictSubset::OpenAi.problem(&bounded), None);
    assert!(StrictSubset::Anthropic.problem(&bounded).is_some());

    let optional = closed(json!({ "a": { "type": "string" } }), &[]);
    assert!(StrictSubset::OpenAi.problem(&optional).is_some());
    assert_eq!(StrictSubset::Anthropic.problem(&optional), None);

    let uri = closed(
        json!({ "u": { "type": "string", "format": "uri" } }),
        &["u"],
    );
    assert!(StrictSubset::OpenAi.problem(&uri).is_some());
    assert_eq!(StrictSubset::Anthropic.problem(&uri), None);

    // The cross-provider answer refuses what either refuses, and says which.
    let both = strict_schema_problem(&bounded).expect("Anthropic refuses it");
    assert!(both.starts_with("Anthropic:"), "{both}");
}

/// Anthropic's documented refusals, one shape each.
#[test]
fn anthropic_refuses_what_its_limitations_list() {
    let refused = [
        (
            "recursion",
            json!({
                "type": "object",
                "properties": { "child": { "$ref": "#/$defs/Node" } },
                "required": ["child"],
                "additionalProperties": false,
                "$defs": { "Node": closed(json!({ "next": { "$ref": "#/$defs/Node" } }), &["next"]) },
            }),
        ),
        (
            "length",
            closed(json!({ "s": { "type": "string", "maxLength": 3 } }), &["s"]),
        ),
        (
            "maxItems",
            closed(
                json!({ "a": { "type": "array", "items": { "type": "string" }, "maxItems": 2 } }),
                &["a"],
            ),
        ),
        (
            "minItems above one",
            closed(
                json!({ "a": { "type": "array", "items": { "type": "string" }, "minItems": 2 } }),
                &["a"],
            ),
        ),
        (
            "lookahead",
            closed(
                json!({ "s": { "type": "string", "pattern": "^(?=a)" } }),
                &["s"],
            ),
        ),
        (
            "allOf with a ref",
            json!({
                "type": "object",
                "properties": { "x": { "allOf": [{ "$ref": "#/$defs/X" }] } },
                "required": ["x"],
                "additionalProperties": false,
                "$defs": { "X": closed(json!({ "a": { "type": "string" } }), &["a"]) },
            }),
        ),
    ];
    for (what, schema) in refused {
        assert!(
            StrictSubset::Anthropic.problem(&schema).is_some(),
            "{what} is documented as a 400 and was passed: {schema}"
        );
    }

    // A definition two properties share is not recursion.
    let shared = json!({
        "type": "object",
        "properties": { "a": { "$ref": "#/$defs/X" }, "b": { "$ref": "#/$defs/X" } },
        "required": ["a", "b"],
        "additionalProperties": false,
        "$defs": { "X": closed(json!({ "v": { "type": "string" } }), &["v"]) },
    });
    assert_eq!(StrictSubset::Anthropic.problem(&shared), None);
}
