//! Opening a human task *beside* an answer, rather than in front of it.
//!
//! # The shape [`Approval`] cannot express
//!
//! [`Approval::Required`] gates the answer and [`Approval::ToolsOnly`] gates the
//! calls. Both are the right control for an agent that **acts**. Neither is any
//! use for the large class this runtime guarantees cannot act at all: a
//! `tool-calling` agent's arguments come from a model completion, so a mutating
//! call with no protected fields is refused by the taint gate on every run —
//! which is why [`Manifest::validate`] refuses that grant outright. Such an
//! agent is advisory *by construction*.
//!
//! For those, `required` is a worklist that blocks — every run suspends until a
//! person approves a **report** — and `tools-only` gates nothing, because there
//! is no mutating call to gate. What a regulated advisory plane actually needs
//! is: *return the answer immediately, and open a task when the answer says
//! something a person must see.*
//!
//! [`Approval`]: super::Approval
//! [`Approval::Required`]: super::Approval::Required
//! [`Approval::ToolsOnly`]: super::Approval::ToolsOnly
//! [`Manifest::validate`]: super::Manifest::validate
//!
//! # Why this is a predicate when `approval` is not
//!
//! `spec.oversight.approval` has no condition, deliberately: *"require approval
//! when severity is high"* changes **what the agent does**, and config that
//! branches on its own results is a poor programming language wearing YAML.
//!
//! A triage rule changes nothing about the run. The answer is produced, checked
//! against the declared schema, returned, and the memories are formed —
//! identically whether a rule matched or not. The only effect is a row in
//! somebody's worklist. That is reporting, not control flow, and reporting is
//! the one place a declaration can hold a predicate without becoming an `if`.
//!
//! Three properties keep it that way, and each is enforced rather than advised:
//!
//! * **The predicate is total.** Five operators, no nesting, no negation, no
//!   `or`. Conditions within a rule are conjunctive; rules are independent, and
//!   two matching rules open two tasks.
//! * **It is typed against the declared shape.** `spec.output.schema` is
//!   required beside `triage`, and a condition whose pointer the schema
//!   *provably* cannot produce is refused at parse — see
//!   [`Condition::check_against`].
//! * **It cannot read what the answer does not contain.** A pointer that
//!   selects nothing does not match. It is never an error at run time, because
//!   an optional field's absence is an ordinary answer and failing the run over
//!   it would make triage a control after all.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One reason to put an answer in front of a person, and who.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriageRule {
    /// What the task is called, so a worklist can be filtered on it.
    ///
    /// Free text rather than an enum: the categories a regulated worklist sorts
    /// by belong to the domain, and this crate has no business enumerating
    /// them. It is prefixed with `agent.triage/` when the task is opened, so a
    /// name here cannot collide with the runtime's own task kinds.
    pub name: String,
    /// Every condition that must hold. Conjunctive, and an empty list is
    /// refused — a rule matching everything is a task per run written as a
    /// filter.
    pub when: Vec<Condition>,
    /// Roles that may act on the task. Empty means anyone, which is a choice
    /// worth making on purpose rather than by omission.
    #[serde(default)]
    pub audience: Vec<String>,
    /// What the worklist row says, in the words a reviewer reads.
    ///
    /// In the manifest for the same reason the system prompt is: it is text a
    /// person acts on, so it belongs where a reviewer sees it as a diff and the
    /// digest covers it.
    pub summary: String,
    /// The obligation that bounds the task.
    ///
    /// Its own rather than shared with `oversight.deadline`, because the two
    /// answer different questions: how long a *run* may wait for approval, and
    /// how long a *worklist row* may sit. A deployment that wants one figure
    /// writes it twice, which is cheaper than a shared field that means two
    /// things.
    pub deadline: super::OversightDeadline,
    /// How urgent the row is.
    #[serde(default)]
    pub priority: TriagePriority,
}

/// How a triage task is ranked in a worklist.
///
/// Mirrors [`crate::core::Priority`] rather than re-exporting it, so the
/// manifest's spelling is `kebab-case` YAML and stays a wire format this crate
/// owns. Named apart from `core::Priority` because both are reachable from a
/// glob import, and a type whose two spellings differ only by module is one
/// somebody writes wrong once.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum TriagePriority {
    Low,
    #[default]
    Normal,
    High,
    Urgent,
}

impl From<TriagePriority> for crate::core::Priority {
    fn from(p: TriagePriority) -> Self {
        match p {
            TriagePriority::Low => Self::Low,
            TriagePriority::Normal => Self::Normal,
            TriagePriority::High => Self::High,
            TriagePriority::Urgent => Self::Urgent,
        }
    }
}

/// One field of the answer, and one thing that must be true of it.
///
/// `deny_unknown_fields` is absent because serde forbids it beside
/// [`flatten`](https://serde.rs/attr-flatten.html) — and it would buy nothing:
/// the flattened [`Predicate`] is an externally tagged enum, so a key that is
/// not one of the five operators fails to name a variant and the parse is
/// refused anyway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Condition {
    /// RFC 6901 pointer into the answer, e.g. `/deadline_status`.
    ///
    /// The same spelling the plan tier's references use and the same the label
    /// machinery projects with, because a reader who has learned one pointer
    /// syntax should not have to learn a second.
    pub path: String,
    /// What must be true of the value at `path`.
    #[serde(flatten)]
    pub predicate: Predicate,
}

/// The total set of things a triage condition may say.
///
/// Five, and the list is closed. Each is decidable on one JSON value with no
/// evaluation order, no coercion between types, and no way to express *not*: a
/// negation invites the reviewer to reason about the empty case, and the empty
/// case here — a field the answer does not carry — is exactly where a
/// mis-specified alert goes quiet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    /// Deep JSON equality against a constant.
    Equals(Value),
    /// Deep JSON equality against any of several constants.
    ///
    /// An empty list is refused: it matches nothing, so a rule carrying one is
    /// a worklist that silently never fills.
    #[serde(rename = "in")]
    OneOf(Vec<Value>),
    /// A number at or above this. Non-numbers do not match.
    AtLeast(f64),
    /// A number at or below this. Non-numbers do not match.
    AtMost(f64),
    /// The pointer selects something — anything, including `null`.
    Exists(bool),
}

impl Condition {
    /// Whether this condition holds of an answer.
    ///
    /// A pointer selecting nothing is `false` for every predicate except
    /// `exists: false`. It is never an error: an optional field's absence is an
    /// ordinary answer, and failing the run over it would make triage a control
    /// over the run rather than a report beside it.
    #[must_use]
    pub fn holds(&self, answer: &Value) -> bool {
        let found = answer.pointer(&self.path);
        match (&self.predicate, found) {
            (Predicate::Exists(expected), found) => found.is_some() == *expected,
            (_, None) => false,
            (Predicate::Equals(expected), Some(actual)) => actual == expected,
            (Predicate::OneOf(expected), Some(actual)) => expected.contains(actual),
            (Predicate::AtLeast(floor), Some(actual)) => {
                actual.as_f64().is_some_and(|value| value >= *floor)
            }
            (Predicate::AtMost(ceiling), Some(actual)) => {
                actual.as_f64().is_some_and(|value| value <= *ceiling)
            }
        }
    }

    /// Everything wrong with the condition on its own terms.
    ///
    /// # Errors
    ///
    /// A message for a blank or non-RFC-6901 pointer, an empty `in` list, or a
    /// bound that is not a finite number.
    pub fn validate(&self) -> Result<(), String> {
        if self.path.is_empty() {
            return Err(
                "a condition path is empty — the whole answer is not a field, so name \
                 one with an RFC 6901 pointer such as '/deadline_status'"
                    .to_owned(),
            );
        }
        if !self.path.starts_with('/') {
            return Err(format!(
                "'{}' is not an RFC 6901 pointer — it must begin with '/', e.g. \
                 '/deadline_status'",
                self.path
            ));
        }
        match &self.predicate {
            Predicate::OneOf(options) if options.is_empty() => Err(format!(
                "'{}' has an empty `in` list, which matches nothing — a triage rule that \
                 can never fire is a worklist somebody believes is being filled",
                self.path
            )),
            Predicate::AtLeast(bound) | Predicate::AtMost(bound) if !bound.is_finite() => {
                Err(format!(
                    "'{}' compares against a bound that is not a finite number",
                    self.path
                ))
            }
            _ => Ok(()),
        }
    }

    /// Refuse a condition the declared output schema **provably** cannot
    /// produce.
    ///
    /// # Provably, and only provably
    ///
    /// The check walks `properties` and `items` and refuses only where the
    /// schema *closes* the door: a `type: object` with `additionalProperties:
    /// false` whose `properties` lack the token cannot ever carry it, so a rule
    /// naming it is an alert that will never fire and a reviewer reading the
    /// file would believe it does. Anything the walk cannot interpret —
    /// `$ref`, `anyOf`, an open object — passes, because a check that guessed
    /// would refuse valid manifests, and this crate's rule is that a declared
    /// control must bind, not that every mistake must be catchable.
    ///
    /// That asymmetry is deliberate and is the reason this returns `Ok` far
    /// more often than a schema validator would.
    ///
    /// # Errors
    ///
    /// A message naming the pointer and the field of the schema that closes it.
    pub fn check_against(&self, schema: &Value) -> Result<(), String> {
        let mut node = schema;
        // Skip the leading empty token that a pointer's leading '/' produces.
        for token in self.path.split('/').skip(1) {
            let token = token.replace("~1", "/").replace("~0", "~");
            match node.get("type").and_then(Value::as_str) {
                Some("object") => {
                    let properties = node.get("properties").and_then(Value::as_object);
                    match properties.and_then(|p| p.get(&token)) {
                        Some(next) => node = next,
                        // Closed and absent: provably unreachable.
                        None if node.get("additionalProperties") == Some(&Value::Bool(false)) => {
                            return Err(format!(
                                "'{}' names '{token}', which `spec.output.schema` does not \
                                 declare and cannot carry (`additionalProperties: false`) — \
                                 the rule would never fire while reading in review as an \
                                 alert that does",
                                self.path
                            ));
                        }
                        // Open, or no `properties` at all: unknowable here.
                        None => return Ok(()),
                    }
                }
                Some("array") => match node.get("items") {
                    // An index into an array: the element schema governs.
                    Some(items) if token.chars().all(|c| c.is_ascii_digit()) => node = items,
                    _ => return Ok(()),
                },
                // A scalar with pointer tokens still to consume cannot carry
                // them, whatever else the schema says.
                Some(scalar) => {
                    return Err(format!(
                        "'{}' reaches into '{token}' below a `{scalar}` in \
                         `spec.output.schema` — a scalar has no fields, so the rule would \
                         never fire",
                        self.path
                    ));
                }
                // `anyOf`, `$ref`, an untyped schema: not something this walk
                // can decide, so it is not refused.
                None => return Ok(()),
            }
        }
        Ok(())
    }
}

impl TriageRule {
    /// Whether every condition holds of this answer.
    #[must_use]
    pub fn matches(&self, answer: &Value) -> bool {
        self.when.iter().all(|c| c.holds(answer))
    }

    /// The task kind this rule opens, namespaced so it cannot collide with the
    /// runtime's own kinds.
    #[must_use]
    pub fn task_kind(&self) -> String {
        format!("agent.triage/{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn condition(path: &str, predicate: Predicate) -> Condition {
        Condition {
            path: path.to_owned(),
            predicate,
        }
    }

    /// Each operator decides exactly what it says, including on the wrong type.
    ///
    /// The type cases are the ones worth pinning: a numeric bound that
    /// coerced `"12"` to twelve would make a rule fire on a status string, and
    /// the deployments this feature exists for are the ones where a spurious
    /// worklist row costs somebody an afternoon.
    #[test]
    fn every_operator_is_total_and_never_coerces() {
        let answer = json!({
            "deadline_status": "BREACH",
            "days_left": 2,
            "amount": "12",
            "nested": { "flag": null }
        });

        assert!(condition("/deadline_status", Predicate::Equals(json!("BREACH"))).holds(&answer));
        assert!(!condition("/deadline_status", Predicate::Equals(json!("OK"))).holds(&answer));
        assert!(
            condition(
                "/deadline_status",
                Predicate::OneOf(vec![json!("WARN"), json!("BREACH")])
            )
            .holds(&answer)
        );
        assert!(condition("/days_left", Predicate::AtMost(3.0)).holds(&answer));
        assert!(!condition("/days_left", Predicate::AtLeast(3.0)).holds(&answer));
        assert!(
            !condition("/amount", Predicate::AtLeast(3.0)).holds(&answer),
            "a numeric bound must not coerce the string \"12\""
        );
        // `null` is present, and presence is what `exists` asks about.
        assert!(condition("/nested/flag", Predicate::Exists(true)).holds(&answer));
        assert!(condition("/nowhere", Predicate::Exists(false)).holds(&answer));
        // An absent pointer is false for everything else, never an error.
        for predicate in [
            Predicate::Equals(json!("BREACH")),
            Predicate::OneOf(vec![json!("BREACH")]),
            Predicate::AtLeast(0.0),
            Predicate::AtMost(1e9),
        ] {
            assert!(!condition("/nowhere", predicate).holds(&answer));
        }
    }

    /// The schema check refuses only what the schema provably closes.
    #[test]
    fn a_pointer_is_refused_only_when_the_schema_forbids_it() {
        let closed = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "deadline_status": { "type": "string" },
                "detail": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": { "days_left": { "type": "number" } }
                }
            }
        });
        assert!(
            condition("/deadline_status", Predicate::Exists(true))
                .check_against(&closed)
                .is_ok()
        );
        assert!(
            condition("/detail/days_left", Predicate::AtMost(1.0))
                .check_against(&closed)
                .is_ok()
        );
        let refused = condition("/deadline_stauts", Predicate::Exists(true))
            .check_against(&closed)
            .expect_err("a typo under a closed schema is refused");
        assert!(refused.contains("additionalProperties"), "{refused}");
        let scalar = condition("/deadline_status/inner", Predicate::Exists(true))
            .check_against(&closed)
            .expect_err("reaching below a scalar is refused");
        assert!(scalar.contains("has no fields"), "{scalar}");

        // Open, and everything this walk cannot decide, passes.
        for permissive in [
            json!({ "type": "object", "properties": { "a": { "type": "string" } } }),
            json!({ "anyOf": [{ "type": "object" }] }),
            json!({ "$ref": "#/definitions/answer" }),
        ] {
            assert!(
                condition("/whatever/deep", Predicate::Exists(true))
                    .check_against(&permissive)
                    .is_ok(),
                "{permissive} must not be refused"
            );
        }
    }

    /// A rule that cannot fire, and a pointer that is not one.
    #[test]
    fn a_rule_that_can_never_fire_is_refused() {
        assert!(
            condition("/status", Predicate::OneOf(Vec::new()))
                .validate()
                .expect_err("an empty `in` list is refused")
                .contains("never fire")
        );
        assert!(
            condition("status", Predicate::Exists(true))
                .validate()
                .expect_err("a pointer without a leading slash is refused")
                .contains("RFC 6901")
        );
        assert!(
            condition("/n", Predicate::AtLeast(f64::NAN))
                .validate()
                .expect_err("a non-finite bound is refused")
                .contains("finite")
        );
    }

    /// The YAML a manifest author actually writes, parsed.
    #[test]
    fn the_manifest_spelling_of_a_rule_parses() {
        let rule: TriageRule = serde_yaml_ng::from_str(
            r#"
            name: breach
            summary: "a regulatory deadline was missed"
            audience: [grid-operations]
            priority: high
            when:
              - path: /deadline_status
                equals: BREACH
              - path: /days_left
                at_most: 0
            deadline: { name: triage-breach, kind: working-days, params: { n: 2 } }
            "#,
        )
        .expect("a triage rule in manifest spelling");
        assert_eq!(rule.task_kind(), "agent.triage/breach");
        assert_eq!(rule.priority, TriagePriority::High);
        assert!(rule.matches(&json!({ "deadline_status": "BREACH", "days_left": 0 })));
        assert!(!rule.matches(&json!({ "deadline_status": "BREACH", "days_left": 3 })));
    }
}
