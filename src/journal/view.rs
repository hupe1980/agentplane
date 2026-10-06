//! One record, as a reader outside the plane is shown it.
//!
//! One function for every surface that shows a run's records — the operator
//! API's run and case histories and the terminal's `history` — because two
//! renderers are free to disagree about what a record *is*, and the one that
//! drifts is whichever surface nobody reads.

use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;

/// One journal record with its envelope; see [`record_view`].
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct RecordView {
    pub seq: crate::core::Seq,
    pub run: String,
    pub case: Option<String>,
    pub step: Option<String>,
    pub phase: String,
    pub effect_key: Option<String>,
    pub kind: String,
    #[schemars(extend("x-agentplane-holds" = "The record's payload in the published record format, tagged by `kind`."))]
    pub record: Value,
}

/// One record, envelope and payload.
///
/// The **envelope** belongs here as much as the payload. Without it a reader
/// sees that an effect started and not which effect, cannot pair a start with
/// its outcome or one attempt with the next, cannot tell a forward record from
/// a compensating one, and has no way back to the span that performed it. A
/// step id, a phase and an effect key are identifiers, and the key is a digest
/// — it names the call rather than reproducing what it sent.
#[must_use]
pub fn record_view(r: &super::Record) -> RecordView {
    RecordView {
        seq: r.seq(),
        run: r.body.run.to_string(),
        case: r.body.case.map(|c| c.to_string()),
        step: r.body.step.map(|s| s.to_string()),
        // Always, rather than only when compensating: a reader who has to know
        // the default in order to read the absence is a reader who will not.
        phase: r.body.phase.as_str().to_owned(),
        // The join to `agentplane.effect.key` on the span that performed it.
        effect_key: r.effect_key().map(|k| k.to_string()),
        kind: r.kind().kind_str().to_owned(),
        record: serde_json::to_value(r.kind()).unwrap_or(Value::Null),
    }
}
