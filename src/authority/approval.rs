//! Call shapes a person approved in advance.
//!
//! A standing authority that carries [`ApprovalRule`]s pre-answers the
//! approval task a matching call would have opened. It decides approval only:
//! the grant's field rules, policy and egress still judge the call at dispatch,
//! so a rule can never admit what the grant refuses.
//!
//! Matching is lexical and fails closed. A path is compared segment by segment
//! after `.` and empty segments are dropped and each `..` removes the segment
//! before it; a `..` with nothing left to remove never matches. Symlinks are
//! not resolved: that depends on the filesystem at dispatch time, which replay
//! cannot read back, so resolving them is the tool's.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One call shape: a tool, and what its arguments must hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRule {
    /// The grant's reference, `tool://server/name`.
    pub tool: String,
    /// Every one must hold. At least one: a rule that approves any arguments
    /// removes `requires_approval`, which is the reviewed declaration's to say.
    pub fields: Vec<FieldMatch>,
}

/// What one argument must be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldMatch {
    /// A JSON pointer into the call's arguments, e.g. `/path`.
    pub pointer: String,
    #[serde(flatten)]
    pub matcher: Matcher,
}

/// How an argument is compared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Matcher {
    /// Exactly this value.
    Exact(Value),
    /// A path at or under this one, compared by normalised segments.
    PathPrefix(String),
    /// A string array beginning with exactly these elements: `["cargo", "test"]`
    /// matches `cargo test --lib` and not `cargo testify`.
    ArgvPrefix(Vec<String>),
}

/// Which standing approval decided a call, and in whose name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingApproval {
    pub authority: super::AuthorityId,
    /// The person who answered this call's approval in advance.
    pub issued_by: crate::core::Operator,
    pub basis: String,
}

impl ApprovalRule {
    /// A rule for `tool`, with its first field constraint.
    #[must_use]
    pub fn new(tool: impl Into<String>, pointer: impl Into<String>, matcher: Matcher) -> Self {
        Self {
            tool: tool.into(),
            fields: vec![FieldMatch {
                pointer: pointer.into(),
                matcher,
            }],
        }
    }

    /// Add a constraint every matching call must also meet.
    #[must_use]
    pub fn and(mut self, pointer: impl Into<String>, matcher: Matcher) -> Self {
        self.fields.push(FieldMatch {
            pointer: pointer.into(),
            matcher,
        });
        self
    }

    /// Whether a call to `tool` with `arguments` is one this rule approves.
    #[must_use]
    pub fn matches(&self, tool: &str, arguments: &Value) -> bool {
        self.tool == tool
            && !self.fields.is_empty()
            && self.fields.iter().all(|field| {
                arguments
                    .pointer(&field.pointer)
                    .is_some_and(|value| field.matcher.matches(value))
            })
    }

    /// Why this rule cannot be issued, if it cannot.
    pub(crate) fn problem(&self) -> Option<&'static str> {
        if self.tool.trim().is_empty() {
            return Some("an approval rule names no tool");
        }
        if self.fields.is_empty() {
            return Some(
                "an approval rule constrains no argument — approving every call to a tool \
                 is removing `requires_approval`, which the reviewed declaration says",
            );
        }
        for field in &self.fields {
            if !field.pointer.starts_with('/') {
                return Some("an approval rule's pointer is not a JSON pointer");
            }
            match &field.matcher {
                Matcher::Exact(_) => {}
                Matcher::PathPrefix(prefix) => match normalise(prefix) {
                    Some(segments) if !segments.is_empty() => {}
                    _ => {
                        return Some(
                            "an approval rule's path prefix is empty or leaves its own root",
                        );
                    }
                },
                Matcher::ArgvPrefix(argv) => {
                    if argv.is_empty() {
                        return Some("an approval rule's argv prefix is empty");
                    }
                }
            }
        }
        None
    }
}

impl Matcher {
    fn matches(&self, value: &Value) -> bool {
        match self {
            Self::Exact(expected) => value == expected,
            Self::PathPrefix(prefix) => {
                let (Some(prefix), Some(path)) =
                    (normalise(prefix), value.as_str().and_then(normalise))
                else {
                    return false;
                };
                prefix.absolute == path.absolute && path.segments.starts_with(&prefix.segments)
            }
            Self::ArgvPrefix(prefix) => value.as_array().is_some_and(|argv| {
                argv.len() >= prefix.len()
                    && prefix
                        .iter()
                        .zip(argv)
                        .all(|(want, got)| got.as_str() == Some(want.as_str()))
            }),
        }
    }
}

/// A path reduced to its segments, or `None` when it leaves its own root or
/// holds a byte no path does.
struct Normal<'a> {
    absolute: bool,
    segments: Vec<&'a str>,
}

impl Normal<'_> {
    const fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
}

fn normalise(path: &str) -> Option<Normal<'_>> {
    if path.contains('\0') {
        return None;
    }
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            other => segments.push(other),
        }
    }
    Some(Normal {
        absolute: path.starts_with('/'),
        segments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn under(prefix: &str) -> ApprovalRule {
        ApprovalRule::new(
            "tool://fs/write",
            "/path",
            Matcher::PathPrefix(prefix.into()),
        )
    }

    #[test]
    fn a_path_matches_by_segment_and_never_through_an_escape() {
        let rule = under("src");
        for inside in [
            "src/lib.rs",
            "src",
            "./src/a/b.rs",
            "src//x",
            "src/a/../b.rs",
        ] {
            assert!(
                rule.matches("tool://fs/write", &json!({ "path": inside })),
                "{inside}"
            );
        }
        for outside in [
            "srcs/lib.rs",
            "src/../etc/passwd",
            "../src/lib.rs",
            "/src/lib.rs",
            "lib.rs",
            "src/../../x",
            "src\0/x",
        ] {
            assert!(
                !rule.matches("tool://fs/write", &json!({ "path": outside })),
                "{outside}"
            );
        }
        assert!(!rule.matches("tool://fs/delete", &json!({ "path": "src/lib.rs" })));
        assert!(!rule.matches("tool://fs/write", &json!({ "path": 7 })));
        assert!(!rule.matches("tool://fs/write", &json!({})));
    }

    #[test]
    fn an_argv_prefix_matches_whole_elements() {
        let rule = ApprovalRule::new(
            "tool://shell/run",
            "/argv",
            Matcher::ArgvPrefix(vec!["cargo".into(), "test".into()]),
        );
        assert!(rule.matches(
            "tool://shell/run",
            &json!({ "argv": ["cargo", "test", "--lib"] })
        ));
        assert!(rule.matches("tool://shell/run", &json!({ "argv": ["cargo", "test"] })));
        assert!(!rule.matches("tool://shell/run", &json!({ "argv": ["cargo", "testify"] })));
        assert!(!rule.matches("tool://shell/run", &json!({ "argv": ["cargo"] })));
        assert!(!rule.matches("tool://shell/run", &json!({ "argv": "cargo test" })));
    }

    #[test]
    fn every_constraint_must_hold() {
        let rule = under("src").and("/mode", Matcher::Exact(json!("overwrite")));
        assert!(rule.matches(
            "tool://fs/write",
            &json!({ "path": "src/a", "mode": "overwrite" })
        ));
        assert!(!rule.matches(
            "tool://fs/write",
            &json!({ "path": "src/a", "mode": "append" })
        ));
    }

    #[test]
    fn a_rule_that_could_approve_anything_is_refused() {
        let no_fields = ApprovalRule {
            tool: "tool://fs/write".into(),
            fields: Vec::new(),
        };
        assert!(no_fields.problem().is_some());
        assert!(under("..").problem().is_some());
        assert!(under("").problem().is_some());
        assert!(under("src").problem().is_none());
    }
}
