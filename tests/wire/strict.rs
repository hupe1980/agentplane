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

/// **A typed tool with numbers is strict-ready for both providers.** `schemars`
/// derives a `format` and the type's own bounds, which Anthropic refuses and
/// `serde` already enforces; a range somebody declared is kept.
#[test]
fn a_rust_number_type_does_not_cost_a_tool_its_strictness() {
    #[derive(schemars::JsonSchema)]
    #[allow(dead_code)]
    struct Counts {
        small: u8,
        signed: i16,
        count: u32,
        total: u64,
        index: usize,
        offset: i64,
        ratio: f64,
    }
    #[derive(schemars::JsonSchema)]
    #[allow(dead_code)]
    struct Ranged {
        #[schemars(range(min = 1, max = 10))]
        pages: u32,
    }

    let counts = agentplane::tools::strict_schema::<Counts>();
    for subset in [StrictSubset::OpenAi, StrictSubset::Anthropic] {
        assert_eq!(subset.problem(&counts), None, "{subset:?}: {counts}");
    }
    let ranged = agentplane::tools::strict_schema::<Ranged>();
    assert_eq!(ranged["properties"]["pages"]["minimum"], 1, "{ranged}");
    assert_eq!(ranged["properties"]["pages"]["maximum"], 10, "{ranged}");
}

/// **An argument-less tool is strict-ready for both providers.** Both refuse an
/// object with no `properties`, which is what `schemars` writes for a struct
/// with no fields — whether it is the tool's own type or a field's.
#[test]
fn an_argument_less_tool_does_not_cost_its_strictness() {
    #[derive(schemars::JsonSchema)]
    #[allow(dead_code)]
    struct GitStatus {}
    #[derive(schemars::JsonSchema)]
    #[allow(dead_code)]
    struct Holds {
        nothing: GitStatus,
    }

    for schema in [
        agentplane::tools::strict_schema::<GitStatus>(),
        agentplane::tools::strict_schema::<Holds>(),
    ] {
        for subset in StrictSubset::ALL {
            assert_eq!(subset.problem(&schema), None, "{subset:?}: {schema}");
        }
    }
    let foreign = agentplane::tools::closed_schema(&json!({
        "type": "object",
        "additionalProperties": false,
    }));
    for subset in StrictSubset::ALL {
        assert_eq!(subset.problem(&foreign), None, "{subset:?}: {foreign}");
    }
}

/// **A typed tool's `required` is one order in every build.** The nullable
/// fields are appended sorted, not in map order, which
/// `serde_json/preserve_order` makes declaration order. Fields declared out of
/// alphabetical order tell the two apart; CI runs both feature sets.
#[test]
fn a_typed_tools_required_order_does_not_depend_on_the_build() {
    #[derive(schemars::JsonSchema)]
    #[allow(dead_code)]
    struct ReadFile {
        path: String,
        start_line: Option<u32>,
        end_line: Option<u32>,
    }
    let schema = agentplane::tools::strict_schema::<ReadFile>();
    assert_eq!(
        schema["required"],
        json!(["path", "end_line", "start_line"]),
        "{schema}"
    );
}

/// The reasons a schema is not strict are recorded with the refusal, so they
/// come in one order whatever order the schema's map keeps.
#[test]
fn the_reasons_a_schema_is_not_strict_come_in_one_order() {
    let schema = json!({
        "type": "object",
        "properties": { "zeta": { "type": "string" }, "alpha": { "type": "string" } },
        "additionalProperties": false,
    });
    let problem = StrictSubset::OpenAi
        .problem(&schema)
        .expect("both are optional");
    let alpha = problem.find("alpha").expect("alpha is named");
    let zeta = problem.find("zeta").expect("zeta is named");
    assert!(alpha < zeta, "{problem}");
}

/// **A schema somebody else wrote is only narrowed.** Making an optional
/// property nullable sends `null` where the server expected nothing, and
/// dropping a declared bound lets a model send what the server never
/// re-checks: both are `serde`'s to allow, so only a typed tool's schema gets
/// them. A free-form object stays free-form.
#[test]
fn a_foreign_schema_is_narrowed_and_never_rewritten() {
    let declared = json!({
        "type": "object",
        "properties": {
            "note": { "type": ["string", "null"] },
            "pages": { "type": "integer", "format": "uint8", "minimum": 0, "maximum": 255 },
            "labels": { "type": "object" },
            "target": {
                "type": "object",
                "properties": { "account": { "type": "string" } },
                "required": ["account"],
            },
        },
        "required": ["pages", "labels", "target"],
    });
    let closed = agentplane::tools::closed_schema(&declared);

    assert_eq!(closed["additionalProperties"], false, "{closed}");
    assert_eq!(
        closed["properties"]["target"]["additionalProperties"],
        false
    );
    assert_eq!(
        closed["required"], declared["required"],
        "an optional became required"
    );
    assert_eq!(
        closed["properties"]["pages"],
        declared["properties"]["pages"]
    );
    assert_eq!(
        closed["properties"]["labels"], declared["properties"]["labels"],
        "a free-form object was closed to an empty one"
    );
}

/// **A composed schema is left as written.** Under `oneOf`, a branch closed
/// into no longer matching a value can leave another branch matching it
/// alone — admitting a value the schema refused. A property merely *named*
/// after a composing keyword is a name, not a composition.
#[test]
fn closing_never_widens_a_composed_schema() {
    let composed = json!({
        "type": "object",
        "properties": {
            "to": { "oneOf": [
                { "type": "object", "properties": { "iban": { "type": "string" } } },
                { "type": "object", "properties": { "email": { "type": "string" } } },
            ] },
        },
    });
    assert_eq!(agentplane::tools::closed_schema(&composed), composed);

    let named = json!({
        "type": "object",
        "properties": { "not": { "type": "string" } },
        "required": ["not"],
    });
    assert_eq!(
        agentplane::tools::closed_schema(&named)["additionalProperties"],
        false
    );
}
