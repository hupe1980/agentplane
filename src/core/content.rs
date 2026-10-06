//! What a declared content rule decided about a value, as the journal records
//! it.
//!
//! Unconditional, because records are: a reader built without the `manifest`
//! feature still has to read an export written by a plane built with it.

use serde::{Deserialize, Serialize};

use crate::core::Sensitivity;

/// The content rules' verdict on a value that arrived, or on a run's input.
///
/// Written only when a rule matched, beside the value it judged, so a replay
/// rebuilds the label and the refusal from the record and never evaluates a
/// rule. Ids and a pointer only: nothing matched is recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentVerdict {
    /// The rules that matched.
    pub rules: Vec<String>,
    /// The join of every matched classification. The value's label is its
    /// declared sensitivity joined with this — never lower.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<Sensitivity>,
    /// The rule that refused the value, and where it matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<ContentRefusal>,
}

/// Which rule refused a value, and where. The pointer writes an object key a
/// rule matched as `*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRefusal {
    pub rule: String,
    pub pointer: String,
}

impl ContentVerdict {
    /// `declared` joined with this verdict's classification: never lower.
    #[must_use]
    pub fn raise(verdict: Option<&Self>, declared: Sensitivity) -> Sensitivity {
        joined(declared, verdict.and_then(|v| v.sensitivity))
    }
}

/// `declared` joined with a classification. The one place a content verdict
/// touches a sensitivity, so no path can assign where it must join.
#[must_use]
pub fn joined(declared: Sensitivity, classified: Option<Sensitivity>) -> Sensitivity {
    classified.map_or(declared, |raised| declared.max(raised))
}
