//! The published manifest schema, held to the code.
//!
//! The schema is generated from the same types the parser deserializes into,
//! which removes structural drift by construction — but only for the copy the
//! code generates. Two other copies exist and each needs its own guard: the
//! file the site serves (pinned byte-for-byte to the generator here), and the
//! *claim* that schema acceptance tracks parser acceptance (exercised on a
//! full-featured manifest and on the refusals both sides must share).

use agentplane::manifest::Manifest;

/// A manifest exercising every top-level `spec` block, so a schema that lost
/// a field or an enum spelling fails here rather than in somebody's editor.
const FULL: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: clearing-triage
  version: 1.4.0
spec:
  identity:
    role: Triage clearing exceptions
    constraints: Isolate structural failures.
  security:
    max_sensitivity_egress: internal
    max_delegation_depth: 0
  capabilities:
    provides: ["triage"]
  budgets:
    max_tokens: 200000
    max_wallclock_secs: 300
  tools:
    - ref: tool://clearing/resolve_case
      description: Close one clearing exception by case id.
      mutates: true
      requires_approval: true
      protected_fields:
        - path: /case_id
          require_trusted: true
          max_sensitivity: internal
  context:
    prompts:
      - server: clearing
        name: triage-preamble
  oversight:
    approval: tools-only
    approvers: ["ops"]
    deadline:
      name: review
      kind: hours
      params: { n: 4 }
    on_expiry: deny
    triage:
      - name: high-value
        summary: A high-value exception was triaged.
        audience: ["ops"]
        when:
          - path: /severity
            equals: "high"
        deadline:
          name: triage-review
          kind: hours
          params: { n: 8 }
        priority: high
  execution:
    kind: tool-calling
    max_turns: 6
  topology:
    mode: single
    role: specialist
  models:
    privileged:
      provider: anthropic
      model: claude-fable-5
      max_tokens: 4096
      reasoning_effort: medium
    quarantined:
      provider: anthropic
      model: claude-haiku-4-5-20251001
  output:
    schema:
      type: object
      properties:
        severity: { type: string }
  memory:
    recall:
      subject: $correlation/case
      purpose: triage
      limit: 5
    formation:
      subject: $correlation/case
      purpose: triage
      instruction: Keep durable facts about recurring failure shapes.
      max_items: 3
      retention_seconds: 2592000
"#;

fn schema_validator() -> jsonschema::Validator {
    jsonschema::validator_for(&Manifest::json_schema()).expect("the generated schema compiles")
}

fn as_json(yaml: &str) -> serde_json::Value {
    serde_yaml_ng::from_str(yaml).expect("well-formed YAML")
}

/// The file the site serves is the document the code generates.
///
/// The schema's only defence against drift is being generated; a stale copy at
/// the published URL has none of it, and a stale copy is what every editor
/// actually reads. Regenerate with:
/// `cargo run --features cli -- schema > site/static/agent.schema.json`
#[test]
fn the_published_schema_is_the_generated_document() {
    let published = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/site/static/agent.schema.json"
    ))
    .expect("site/static/agent.schema.json exists");
    let published: serde_json::Value =
        serde_json::from_str(&published).expect("the published schema is JSON");
    assert_eq!(
        published,
        Manifest::json_schema(),
        "site/static/agent.schema.json is stale — regenerate it with \
         `cargo run --features cli -- schema > site/static/agent.schema.json`"
    );
}

/// A manifest the parser accepts is schema-valid.
///
/// The schema may be *weaker* than the parser — the semantic refusals run only
/// there — but never stricter: a schema refusing a document the parser accepts
/// would paint valid manifests red in every editor that trusts the modeline.
#[test]
fn what_the_parser_accepts_the_schema_accepts() {
    Manifest::parse(FULL).expect("the full manifest parses");
    let document = as_json(FULL);
    let outcome = schema_validator().validate(&document);
    assert!(
        outcome.is_ok(),
        "the schema refused a manifest the parser accepts: {:?}",
        outcome.err().map(|e| e.to_string())
    );
}

/// The refusals both sides must share: shape errors.
///
/// An unknown field and a mistyped value are the failures the schema exists to
/// move into the editor, so each must fail the schema *and* the parser — a
/// schema that accepted either would advertise the permissive parser this
/// format refuses to be.
#[test]
fn an_unknown_field_and_a_wrong_type_fail_the_schema_and_the_parser_alike() {
    let validator = schema_validator();
    for (what, yaml) in [
        (
            "an unknown field",
            &FULL.replace("max_wallclock_secs: 300", "max_wallclock_seconds: 300"),
        ),
        ("a wrong type", &FULL.replace("limit: 5", "limit: five")),
        (
            "an enum spelling the format does not have",
            &FULL.replace("kind: tool-calling", "kind: tool_calling"),
        ),
    ] {
        assert!(Manifest::parse(yaml).is_err(), "the parser accepted {what}");
        assert!(
            validator.validate(&as_json(yaml)).is_err(),
            "the schema accepted {what} the parser refuses"
        );
    }
}

/// The schema's descriptions are hover text, not essays.
///
/// Prose is single-sourced from the types' documentation and cut to the first
/// paragraph on the way out; rustdoc's `[`X`]` link spelling renders literally
/// in an editor, so none may survive. A multi-paragraph description here means
/// the trim stopped running.
#[test]
fn schema_descriptions_are_single_paragraph_hover_text() {
    fn check(value: &serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(serde_json::Value::String(text)) = object.get("description") {
                    assert!(
                        !text.contains("\n\n"),
                        "{path}: description carries more than one paragraph"
                    );
                    assert!(
                        !text.contains("[`"),
                        "{path}: description carries rustdoc link syntax: {text}"
                    );
                }
                for (key, value) in object {
                    check(value, &format!("{path}/{key}"));
                }
            }
            serde_json::Value::Array(items) => {
                for (index, value) in items.iter().enumerate() {
                    check(value, &format!("{path}/{index}"));
                }
            }
            _ => {}
        }
    }
    check(&Manifest::json_schema(), "");
}
