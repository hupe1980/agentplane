//! Argument schemas made ready for strict decoding.
//!
//! A driver sends a tool's schema strict only when its provider's subset holds
//! it, and drops to unconstrained generation otherwise — which makes the
//! arguments a suggestion rather than a constraint, with nothing failing to say
//! so. Two passes close that gap, and they differ in what they may assume:
//!
//! - [`closed_schema`] only **narrows**: every value it admits, the schema it
//!   was given admitted. It may run on a schema somebody else wrote — an MCP
//!   server's, a grant's — because the far side still accepts every call it
//!   can produce.
//! - [`strict_schema`] narrows and then rewrites what `serde` enforces anyway,
//!   so it runs only on a schema generated from a Rust type this process
//!   deserializes into.
//!
//! Neither makes an optional property nullable nor drops a bound somebody
//! declared: both change what a call means, and a schema neither pass can make
//! ready is sent non-strict, which is the honest outcome.

use serde_json::{Map, Value, json};

/// Keywords under which closing an object could admit a value the schema
/// refused, or refuse every value. `oneOf` and `not` turn a narrower branch
/// into a wider whole; `allOf` and the conditional and unevaluated keywords
/// let an object's properties come from a sibling that closing would forbid.
const COMPOSING: &[&str] = &[
    "oneOf",
    "allOf",
    "not",
    "if",
    "then",
    "else",
    "dependentSchemas",
    "unevaluatedProperties",
    "unevaluatedItems",
    "$dynamicRef",
    "$recursiveRef",
];

/// The dialects whose `$schema` names nothing a provider reads differently from
/// the one it assumes. An older dialect stays named, since its keywords mean
/// other things.
const MODERN_DIALECTS: &[&str] = &[
    "https://json-schema.org/draft/2020-12/schema",
    "https://json-schema.org/draft/2019-09/schema",
    "http://json-schema.org/draft-07/schema",
];

/// `schema`, narrowed so a provider's strict mode can hold a model to it.
///
/// For a schema this crate did not generate: a server's input schema, or a
/// grant's `arguments`. Applied by [`ToolGrant::drafted_from`], so a reviewed
/// grant carries the form that is offered.
///
/// - An object that lists `properties` and does not state
///   `additionalProperties` is closed. A server still accepts every call the
///   closed form admits. An object with no `properties` is free-form and stays
///   open.
/// - A closed object without `properties` gains empty `properties` and
///   `required`, which both strict subsets need of an argument-less tool.
/// - A `$ref` with siblings becomes a one-branch `anyOf` carrying them.
/// - A root `$schema` naming a current dialect is dropped.
///
/// Returned unchanged when it composes with `oneOf`, `allOf`, `not`, a
/// conditional, or an unevaluated keyword: there, closing an object can admit
/// what the schema refused or refuse everything. Whether a provider then takes
/// the result strictly is [`StrictSubset::problem`]'s answer.
///
/// [`ToolGrant::drafted_from`]: crate::manifest::ToolGrant::drafted_from
/// [`StrictSubset::problem`]: crate::model::StrictSubset::problem
#[must_use]
pub fn closed_schema(schema: &Value) -> Value {
    let mut closed = schema.clone();
    if composes(schema) {
        return closed;
    }
    if let Some(map) = closed.as_object_mut()
        && map
            .get("$schema")
            .and_then(Value::as_str)
            .is_some_and(|dialect| MODERN_DIALECTS.contains(&dialect.trim_end_matches('#')))
    {
        map.remove("$schema");
    }
    close(&mut closed, Grounds::Narrowing);
    closed
}

/// The schema of `T`, made ready for strict decoding as a typed tool's is.
///
/// What [`ToolBox::with`] declares, for a schema an embedder generates and
/// sends itself. On top of [`closed_schema`]'s narrowing:
///
/// - An optional property that admits `null` is listed in `required`: `serde`
///   reads `null` as `None` exactly as it reads an absent field, and strict
///   mode has no optional properties. A property optional for another reason
///   (`#[serde(default)]`) is left alone and keeps the tool non-strict.
/// - The root's `$schema` is dropped whatever it names: `schemars` wrote it.
/// - A number's `format`, and a `minimum` or `maximum` equal to its Rust type's
///   own bound, are dropped: `schemars` derives them from the type and `serde`
///   refuses what they exclude. A range somebody declared stays.
///
/// Every object is closed whatever it composes with, since `serde` hands the
/// tool its declared fields and ignores the rest.
///
/// [`ToolBox::with`]: crate::tools::ToolBox::with
#[must_use]
pub fn strict_schema<T: schemars::JsonSchema>() -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(T))
        .expect("a schemars-generated schema must serialize to JSON");
    if let Some(map) = schema.as_object_mut() {
        map.remove("$schema");
    }
    close(&mut schema, Grounds::Serde);
    schema
}

/// What a rewrite may rely on: only that it narrows, or also that `serde` is
/// the reader.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Grounds {
    Narrowing,
    Serde,
}

fn close(node: &mut Value, grounds: Grounds) {
    let Some(map) = node.as_object_mut() else {
        return;
    };
    if grounds == Grounds::Serde {
        drop_type_bounds(map);
    }
    if map.contains_key("$ref") && map.len() > 1 {
        let target = map.remove("$ref").expect("checked above");
        map.insert("anyOf".to_owned(), json!([{ "$ref": target }]));
    }
    if names_object(map) {
        // A free-form object states no shape to close to; `serde` reads one
        // only into a type that declares its fields.
        if grounds == Grounds::Serde || map.contains_key("properties") {
            map.entry("additionalProperties")
                .or_insert_with(|| json!(false));
        }
        if map.get("additionalProperties") == Some(&json!(false)) && !map.contains_key("properties")
        {
            map.insert("properties".to_owned(), json!({}));
            map.entry("required").or_insert_with(|| json!([]));
        }
        if grounds == Grounds::Serde {
            require_nullable(map);
        }
    }
    for key in ["properties", "$defs", "definitions"] {
        if let Some(children) = node.get_mut(key).and_then(Value::as_object_mut) {
            for child in children.values_mut() {
                close(child, grounds);
            }
        }
    }
    if let Some(items) = node.get_mut("items") {
        close(items, grounds);
    }
    if let Some(branches) = node.get_mut("anyOf").and_then(Value::as_array_mut) {
        for branch in branches {
            close(branch, grounds);
        }
    }
}

fn names_object(map: &Map<String, Value>) -> bool {
    match map.get("type") {
        Some(Value::String(t)) => t == "object",
        Some(Value::Array(types)) => types.iter().any(|t| t == "object"),
        _ => false,
    }
}

/// Whether `node` uses a [`COMPOSING`] keyword at any schema position. Walks
/// only where a subschema can stand, so a property *named* `not` is a name.
fn composes(node: &Value) -> bool {
    let Some(map) = node.as_object() else {
        return false;
    };
    if COMPOSING.iter().any(|key| map.contains_key(*key)) {
        return true;
    }
    let tables = ["properties", "patternProperties", "$defs", "definitions"]
        .iter()
        .filter_map(|key| map.get(*key).and_then(Value::as_object))
        .flat_map(Map::values);
    let lists = ["anyOf", "prefixItems", "items"]
        .iter()
        .filter_map(|key| map.get(*key).and_then(Value::as_array))
        .flatten();
    let single = ["items", "additionalProperties", "contains", "propertyNames"]
        .iter()
        .filter_map(|key| map.get(*key));
    tables.chain(lists).chain(single).any(composes)
}

/// List every property that admits `null` in `required`, appended sorted.
///
/// Sorted, not in map order, which `serde_json/preserve_order` makes
/// insertion order: the array is in every model call's effect key.
fn require_nullable(map: &mut Map<String, Value>) {
    let mut nullable: Vec<String> = map
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| {
            properties
                .iter()
                .filter(|(_, schema)| admits_null(schema))
                .map(|(name, _)| name.clone())
                .collect()
        })
        .unwrap_or_default();
    if nullable.is_empty() {
        return;
    }
    nullable.sort_unstable();
    let required = map
        .entry("required")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(required) = required.as_array_mut() {
        for name in nullable {
            if !required.iter().any(|r| r == name.as_str()) {
                required.push(Value::String(name));
            }
        }
    }
}

/// Whether a property's schema accepts `null`: a type array naming it, or a
/// union with a `null` branch.
fn admits_null(schema: &Value) -> bool {
    let null = json!("null");
    match schema.get("type") {
        Some(Value::Array(types)) if types.contains(&null) => return true,
        _ => {}
    }
    schema
        .get("anyOf")
        .and_then(Value::as_array)
        .is_some_and(|branches| branches.iter().any(|b| b.get("type") == Some(&null)))
}

/// The bounds `schemars` derives from a Rust number type, by its `format`.
const NUMBER_FORMATS: &[(&str, Option<i64>, Option<i64>)] = &[
    ("int8", Some(-128), Some(127)),
    ("int16", Some(-32_768), Some(32_767)),
    ("int32", None, None),
    ("int64", None, None),
    ("int128", None, None),
    ("int", None, None),
    ("uint8", Some(0), Some(255)),
    ("uint16", Some(0), Some(65_535)),
    ("uint32", Some(0), None),
    ("uint64", Some(0), None),
    ("uint128", Some(0), None),
    ("uint", Some(0), None),
    ("float", None, None),
    ("double", None, None),
];

fn drop_type_bounds(map: &mut Map<String, Value>) {
    let Some((_, min, max)) = map
        .get("format")
        .and_then(Value::as_str)
        .and_then(|format| NUMBER_FORMATS.iter().find(|(name, ..)| *name == format))
    else {
        return;
    };
    map.remove("format");
    for (key, bound) in [("minimum", min), ("maximum", max)] {
        if bound.is_some() && map.get(key).and_then(Value::as_i64) == *bound {
            map.remove(key);
        }
    }
}
