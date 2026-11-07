//! Which schemas a provider's strict mode accepts.
//!
//! Strict constrained decoding takes a provider-specific **subset** of JSON
//! Schema, and a schema outside it is a 400. So the drivers ask here first: a
//! tool that does not qualify is sent non-strict, and a response schema that
//! does not qualify is refused locally, naming keyword and path, before
//! anything is billed.
//!
//! **Each subset is an allow-list** — `OpenAI`'s as probed against its API,
//! Anthropic's as documented — because a deny-list passes every shape nobody
//! thought to list. Anything neither names is refused, which costs a tool its
//! strictness and never its call. The walk descends only the keywords it
//! accepts, so no subschema escapes it; `patternProperties` is refused for
//! that reason.
//!
//! Not auto-corrected: rewriting a caller's schema would make the effect key
//! record one shape while the wire carries another. A schema this crate
//! *generates* is made strict-ready where it is generated.

use serde_json::{Map, Value};

/// A provider's strict-mode subset of JSON Schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictSubset {
    /// `OpenAI` structured outputs and strict function tools.
    OpenAi,
    /// Anthropic structured outputs and strict tool use.
    Anthropic,
}

/// What one schema costs against Anthropic's per-request strict budget.
#[cfg(any(feature = "providers", feature = "bedrock"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StrictCost {
    /// Properties not listed in their object's `required`.
    optional: usize,
    /// Properties whose schema is a union: `anyOf` or a type array.
    unions: usize,
}

/// Anthropic's per-request ceilings across every strict schema in a request,
/// as documented: past them the request is a 400, not a degraded one.
#[cfg(any(feature = "providers", feature = "bedrock"))]
const ANTHROPIC_STRICT_TOOLS: usize = 20;
#[cfg(any(feature = "providers", feature = "bedrock"))]
const ANTHROPIC_OPTIONAL: usize = 24;
#[cfg(any(feature = "providers", feature = "bedrock"))]
const ANTHROPIC_UNIONS: usize = 16;

/// What is left of one Anthropic request's strict budget.
///
/// A schema is admitted strict only if it is in the subset **and** fits what
/// remains; the first to arrive is served first, so a driver charges the
/// response schema before any tool.
#[cfg(any(feature = "providers", feature = "bedrock"))]
#[derive(Debug, Default)]
pub(crate) struct AnthropicBudget {
    tools: usize,
    spent: StrictCost,
}

#[cfg(any(feature = "providers", feature = "bedrock"))]
impl AnthropicBudget {
    /// Admit `schema` as a strict tool if it qualifies and fits.
    pub(crate) fn tool(&mut self, schema: &Value) -> bool {
        if self.tools >= ANTHROPIC_STRICT_TOOLS || self.admit(schema).is_err() {
            return false;
        }
        self.tools += 1;
        true
    }

    /// Charge a schema the request cannot do without, or say why it does not
    /// fit.
    pub(crate) fn admit(&mut self, schema: &Value) -> Result<(), String> {
        if let Some(problem) = StrictSubset::Anthropic.problem(schema) {
            return Err(problem);
        }
        let mut cost = StrictCost::default();
        count_cost(schema, schema, &mut cost);
        let optional = self.spent.optional + cost.optional;
        let unions = self.spent.unions + cost.unions;
        if optional > ANTHROPIC_OPTIONAL || unions > ANTHROPIC_UNIONS {
            return Err(format!(
                "the request's strict schemas would declare {optional} optional and {unions} \
                 union parameters, past Anthropic's {ANTHROPIC_OPTIONAL} and {ANTHROPIC_UNIONS}"
            ));
        }
        self.spent = StrictCost { optional, unions };
        Ok(())
    }
}

/// `OpenAI`'s documented ceilings.
const OPENAI_DEPTH: usize = 10;
const OPENAI_PROPERTIES: usize = 5000;
const OPENAI_ENUM_VALUES: usize = 1000;
const OPENAI_STRING_BUDGET: usize = 120_000;
const OPENAI_LARGE_ENUM: usize = 250;
const OPENAI_LARGE_ENUM_BUDGET: usize = 15_000;

/// Keywords every subset accepts: structure, and the annotations both document.
const SHARED: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "anyOf",
    "enum",
    "const",
    "$ref",
    "$defs",
    "definitions",
    "description",
    "title",
    "default",
    "format",
    "pattern",
];

/// Probed against `OpenAI`. Anthropic documents none of the annotations among
/// these, and an undocumented keyword there is a 400, so it does not get them.
const OPENAI_ONLY: &[&str] = &[
    "examples",
    "deprecated",
    "readOnly",
    "writeOnly",
    "$comment",
    "$id",
    "$schema",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "nullable",
];

const ANTHROPIC_ONLY: &[&str] = &["allOf", "minItems"];

const OPENAI_FORMATS: &[&str] = &[
    "date-time",
    "time",
    "date",
    "duration",
    "email",
    "hostname",
    "ipv4",
    "ipv6",
    "uuid",
];

const ANTHROPIC_FORMATS: &[&str] = &[
    "date-time",
    "time",
    "date",
    "duration",
    "email",
    "hostname",
    "uri",
    "ipv4",
    "ipv6",
    "uuid",
];

const TYPES: &[&str] = &[
    "object", "array", "string", "integer", "number", "boolean", "null",
];

impl StrictSubset {
    /// Every subset a driver in this crate applies.
    pub const ALL: [Self; 2] = [Self::OpenAi, Self::Anthropic];

    fn name(self) -> &'static str {
        match self {
            Self::OpenAi => "OpenAI",
            Self::Anthropic => "Anthropic",
        }
    }

    /// Why `schema` cannot be used with this provider's strict mode, if it
    /// cannot: every problem, each naming its path.
    #[must_use]
    pub fn problem(self, schema: &Value) -> Option<String> {
        let mut walk = Walk {
            subset: self,
            problems: Vec::new(),
            properties: 0,
            enum_values: 0,
            strings: 0,
        };
        if schema.get("type").and_then(Value::as_str) != Some("object") {
            walk.problems.push(format!(
                "`schema` must be `type: \"object\"` at its root, which {} strict mode requires",
                self.name()
            ));
        }
        walk.node(schema, "schema", 1);
        if self == Self::Anthropic
            && let Some(path) = recursive_ref(schema)
        {
            walk.problems.push(format!(
                "`{path}` makes the schema recursive, which Anthropic strict mode does not accept"
            ));
        }
        if self == Self::OpenAi {
            walk.limits();
        }
        if walk.problems.is_empty() {
            None
        } else {
            // Sorted, not in map order: this text is recorded with the refusal.
            walk.problems.sort_unstable();
            Some(walk.problems.join("; "))
        }
    }
}

/// Why `schema` cannot be used with strict constrained decoding on **every**
/// provider this crate drives, if it cannot.
///
/// The question an embedder asks of a schema it means to offer anywhere. A
/// driver asks its own provider's [`StrictSubset`] instead, so a schema strict
/// on one provider is not made non-strict on another by this answer.
#[must_use]
pub fn strict_schema_problem(schema: &Value) -> Option<String> {
    let problems: Vec<String> = StrictSubset::ALL
        .iter()
        .filter_map(|subset| {
            subset
                .problem(schema)
                .map(|problem| format!("{}: {problem}", subset.name()))
        })
        .collect();
    if problems.is_empty() {
        None
    } else {
        Some(problems.join(" | "))
    }
}

struct Walk {
    subset: StrictSubset,
    problems: Vec<String>,
    properties: usize,
    enum_values: usize,
    strings: usize,
}

impl Walk {
    fn refuse(&mut self, path: &str, what: impl std::fmt::Display) {
        self.problems.push(format!(
            "`{path}` {what}, which {} strict mode does not accept",
            self.subset.name()
        ));
    }

    fn accepts(&self, keyword: &str) -> bool {
        SHARED.contains(&keyword)
            || match self.subset {
                StrictSubset::OpenAi => OPENAI_ONLY.contains(&keyword),
                StrictSubset::Anthropic => ANTHROPIC_ONLY.contains(&keyword),
            }
    }

    #[allow(clippy::too_many_lines)]
    fn node(&mut self, node: &Value, path: &str, depth: usize) {
        let Some(obj) = node.as_object() else {
            self.refuse(path, "is a boolean schema");
            return;
        };

        for keyword in obj.keys() {
            if !self.accepts(keyword) {
                self.refuse(path, format_args!("uses `{keyword}`"));
            }
        }

        // `$ref` stands alone: OpenAI refuses any sibling, an annotation
        // included, and Anthropic documents nothing beside it.
        if let Some(target) = obj.get("$ref") {
            if obj.len() > 1 {
                self.refuse(path, "puts keywords beside `$ref`");
            }
            if !target.as_str().is_some_and(|t| t.starts_with('#')) {
                self.refuse(path, "points `$ref` outside the schema");
            }
            return;
        }

        // Every subschema says what it is. `const` alone does not count:
        // OpenAI wants a `type` beside it.
        if !["type", "anyOf", "enum", "allOf"]
            .iter()
            .any(|k| obj.contains_key(*k))
        {
            self.refuse(path, "has no `type`");
        }

        let types: Vec<&str> = match obj.get("type") {
            Some(Value::String(t)) => vec![t.as_str()],
            Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        for t in &types {
            if !TYPES.contains(t) {
                self.refuse(path, format_args!("names type `{t}`"));
            }
        }

        if let Some(Value::Array(values)) = obj.get("enum") {
            for value in values {
                if value.is_object() || value.is_array() {
                    self.refuse(path, "lists a compound value in `enum`");
                    break;
                }
            }
            self.enum_values += values.len();
            let text: usize = values.iter().filter_map(Value::as_str).map(str::len).sum();
            self.strings += text;
            if self.subset == StrictSubset::OpenAi
                && values.len() > OPENAI_LARGE_ENUM
                && text > OPENAI_LARGE_ENUM_BUDGET
            {
                self.refuse(
                    path,
                    format_args!(
                        "lists more than {OPENAI_LARGE_ENUM} enum strings totalling over \
                         {OPENAI_LARGE_ENUM_BUDGET} characters"
                    ),
                );
            }
        }
        if let Some(Value::String(text)) = obj.get("const") {
            self.strings += text.len();
        }

        if let Some(Value::String(format)) = obj.get("format") {
            let strings_only = match self.subset {
                // Probed: OpenAI ignores a format on a number.
                StrictSubset::OpenAi => types.contains(&"string"),
                StrictSubset::Anthropic => true,
            };
            let known = match self.subset {
                StrictSubset::OpenAi => OPENAI_FORMATS,
                StrictSubset::Anthropic => ANTHROPIC_FORMATS,
            };
            let on_string = types.contains(&"string");
            if strings_only && (!on_string || !known.contains(&format.as_str())) {
                self.refuse(path, format_args!("uses format `{format}`"));
            }
        }

        if self.subset == StrictSubset::Anthropic {
            if let Some(min) = obj.get("minItems").and_then(Value::as_u64)
                && min > 1
            {
                self.refuse(path, format_args!("sets `minItems: {min}`"));
            }
            if let Some(Value::String(pattern)) = obj.get("pattern")
                && let Some(construct) = unsupported_regex(pattern)
            {
                self.refuse(path, format_args!("uses {construct} in `pattern`"));
            }
            if let Some(Value::Array(branches)) = obj.get("allOf")
                && branches.iter().any(|b| b.get("$ref").is_some())
            {
                self.refuse(path, "puts a `$ref` inside `allOf`");
            }
        }

        if types.contains(&"object") {
            self.object(obj, path, depth);
        }

        if types.contains(&"array") {
            match obj.get("items") {
                Some(items @ Value::Object(_)) => {
                    self.node(items, &format!("{path}[]"), depth + 1);
                }
                Some(_) => self.refuse(path, "has `items` that is not a schema"),
                None => self.refuse(path, "is an array without `items`"),
            }
        }

        for key in ["anyOf", "allOf"] {
            if let Some(Value::Array(branches)) = obj.get(key) {
                for (i, branch) in branches.iter().enumerate() {
                    self.node(branch, &format!("{path}.{key}[{i}]"), depth);
                }
            }
        }

        for key in ["$defs", "definitions"] {
            if let Some(Value::Object(table)) = obj.get(key) {
                for (name, def) in table {
                    self.strings += name.len();
                    self.node(def, &format!("{path}.{key}.{name}"), depth);
                }
            }
        }
    }

    fn object(&mut self, obj: &Map<String, Value>, path: &str, depth: usize) {
        if self.subset == StrictSubset::OpenAi && depth > OPENAI_DEPTH {
            self.refuse(
                path,
                format_args!("nests objects deeper than {OPENAI_DEPTH} levels"),
            );
        }
        if obj.get("additionalProperties") != Some(&Value::Bool(false)) {
            self.refuse(path, "is an object without `additionalProperties: false`");
        }
        let Some(properties) = obj.get("properties").and_then(Value::as_object) else {
            self.refuse(path, "is an object without `properties`");
            return;
        };
        let required: Vec<&str> = obj
            .get("required")
            .and_then(Value::as_array)
            .map(|r| r.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        for name in &required {
            if !properties.contains_key(*name) {
                self.refuse(
                    path,
                    format_args!("requires `{name}`, which it does not declare"),
                );
            }
        }
        for (name, property) in properties {
            self.properties += 1;
            self.strings += name.len();
            if self.subset == StrictSubset::OpenAi && !required.contains(&name.as_str()) {
                self.refuse(
                    &format!("{path}.{name}"),
                    "is optional (every property must be listed in `required`)",
                );
            }
            self.node(property, &format!("{path}.{name}"), depth + 1);
        }
    }

    fn limits(&mut self) {
        if self.properties > OPENAI_PROPERTIES {
            self.refuse(
                "schema",
                format_args!("declares more than {OPENAI_PROPERTIES} properties"),
            );
        }
        if self.enum_values > OPENAI_ENUM_VALUES {
            self.refuse(
                "schema",
                format_args!("lists more than {OPENAI_ENUM_VALUES} enum values"),
            );
        }
        if self.strings > OPENAI_STRING_BUDGET {
            self.refuse(
                "schema",
                format_args!(
                    "spends more than {OPENAI_STRING_BUDGET} characters on names and values"
                ),
            );
        }
    }
}

/// A regex construct Anthropic's strict decoder documents as unsupported.
fn unsupported_regex(pattern: &str) -> Option<&'static str> {
    for (needle, name) in [
        ("(?=", "a lookahead"),
        ("(?!", "a lookahead"),
        ("(?<=", "a lookbehind"),
        ("(?<!", "a lookbehind"),
        ("\\k<", "a backreference"),
        ("\\b", "a word boundary"),
        ("\\B", "a word boundary"),
    ] {
        if pattern.contains(needle) {
            return Some(name);
        }
    }
    let bytes = pattern.as_bytes();
    bytes
        .windows(2)
        .any(|w| w[0] == b'\\' && w[1].is_ascii_digit() && w[1] != b'0')
        .then_some("a backreference")
}

/// The first `$ref` that reaches back into its own definition, if any.
fn recursive_ref(schema: &Value) -> Option<String> {
    fn refs(node: &Value, out: &mut Vec<String>) {
        match node {
            Value::Object(obj) => {
                if let Some(Value::String(target)) = obj.get("$ref") {
                    out.push(target.clone());
                }
                for (key, child) in obj {
                    if key != "$defs" && key != "definitions" {
                        refs(child, out);
                    }
                }
            }
            Value::Array(list) => list.iter().for_each(|child| refs(child, out)),
            _ => {}
        }
    }
    // Depth-first with the path on a stack: a definition two branches share
    // is reached twice without being a cycle; only one on its own path is.
    fn cycles<'a>(
        target: &str,
        on_path: &mut Vec<String>,
        definition: &dyn Fn(&str) -> Option<&'a Value>,
    ) -> bool {
        if target == "#" || on_path.iter().any(|t| t == target) {
            return true;
        }
        let Some(def) = definition(target) else {
            return false;
        };
        let mut next = Vec::new();
        refs(def, &mut next);
        on_path.push(target.to_owned());
        let found = next.iter().any(|t| cycles(t, on_path, definition));
        on_path.pop();
        found
    }
    let definition = |target: &str| local_target(schema, target);
    let mut root = Vec::new();
    refs(schema, &mut root);
    root.into_iter()
        .find(|start| cycles(start, &mut Vec::new(), &definition))
}

/// What a local `$ref` names within `root`: a JSON Pointer after the `#`,
/// escapes and nesting included. `None` for a reference outside the document.
fn local_target<'a>(root: &'a Value, target: &str) -> Option<&'a Value> {
    root.pointer(target.strip_prefix('#')?)
}

/// Whether a parameter's schema is a union: an `anyOf` or a type array.
#[cfg(any(feature = "providers", feature = "bedrock"))]
fn is_union(schema: &Value) -> bool {
    schema.get("anyOf").is_some() || schema.get("type").is_some_and(Value::is_array)
}

/// What a property stands for: its local `$ref`'s target, followed until it
/// names no other, or the property itself. A parameter that points at a union
/// is a union parameter, and Anthropic charges it as one.
#[cfg(any(feature = "providers", feature = "bedrock"))]
fn referent<'a>(property: &'a Value, root: &'a Value) -> &'a Value {
    // Bounded although `problem` has refused a cycle by now: this walk must
    // not depend on running second.
    const HOPS: usize = 32;
    let mut at = property;
    for _ in 0..HOPS {
        let Some(target) = at.get("$ref").and_then(Value::as_str) else {
            return at;
        };
        match local_target(root, target) {
            Some(next) => at = next,
            None => return at,
        }
    }
    at
}

#[cfg(any(feature = "providers", feature = "bedrock"))]
fn count_cost(node: &Value, root: &Value, cost: &mut StrictCost) {
    let Some(obj) = node.as_object() else { return };
    if let Some(properties) = obj.get("properties").and_then(Value::as_object) {
        let required: Vec<&str> = obj
            .get("required")
            .and_then(Value::as_array)
            .map(|r| r.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        for (name, property) in properties {
            if !required.contains(&name.as_str()) {
                cost.optional += 1;
            }
            if is_union(referent(property, root)) {
                cost.unions += 1;
            }
            count_cost(property, root, cost);
        }
    }
    if let Some(items) = obj.get("items") {
        count_cost(items, root, cost);
    }
    for key in ["anyOf", "allOf"] {
        if let Some(Value::Array(branches)) = obj.get(key) {
            for branch in branches {
                count_cost(branch, root, cost);
            }
        }
    }
    for key in ["$defs", "definitions"] {
        if let Some(Value::Object(table)) = obj.get(key) {
            for definition in table.values() {
                count_cost(definition, root, cost);
            }
        }
    }
}

#[cfg(all(test, any(feature = "providers", feature = "bedrock")))]
mod budget_tests {
    use super::{ANTHROPIC_UNIONS, AnthropicBudget};
    use serde_json::{Map, Value, json};

    /// A tool whose `count` parameters each point at a union definition.
    fn referencing(count: usize) -> Value {
        let properties: Map<String, Value> = (0..count)
            .map(|i| (format!("p{i}"), json!({ "$ref": "#/$defs/Either" })))
            .collect();
        let required: Vec<String> = properties.keys().cloned().collect();
        json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false,
            "$defs": { "Either": { "anyOf": [{ "type": "string" }, { "type": "integer" }] } },
        })
    }

    /// **A parameter that points at a union is charged as one.** Counted only
    /// where `anyOf` stands on the property, a request of untagged enums passed
    /// this budget and was refused by the provider.
    #[test]
    fn a_property_referencing_a_union_is_charged_to_the_budget() {
        let mut budget = AnthropicBudget::default();
        assert!(budget.admit(&referencing(ANTHROPIC_UNIONS)).is_ok());
        let mut budget = AnthropicBudget::default();
        let refused = budget.admit(&referencing(ANTHROPIC_UNIONS + 1));
        assert!(
            refused.as_ref().is_err_and(|why| why.contains("union")),
            "{refused:?}"
        );
    }
}
