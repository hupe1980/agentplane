//! A run's effects, each read as one call: its announcement and its outcome.
//!
//! The journal writes an effect as two records — [`EffectStarted`] before it
//! is performed, a terminal record after — joined by the envelope's effect
//! key. The descriptor lives on the first and the result on the second, so
//! every reader that asks *what did this call return* or *which tool answered
//! this* performs the same join. It is performed once, here.
//!
//! [`EffectStarted`]: RecordKind::EffectStarted

use serde_json::Value;

use super::{Record, RecordKind};
use crate::core::{EffectDescriptor, EffectKey, Phase, Seq, StepId};

/// One effect attempt: the record that announced it and the one that settled
/// it, borrowed from the history they were read from.
#[derive(Debug, Clone, Copy)]
pub struct Call<'a> {
    started: &'a Record,
    outcome: Option<&'a Record>,
}

impl<'a> Call<'a> {
    /// The key joining the two records.
    #[must_use]
    pub fn key(&self) -> EffectKey {
        self.started
            .effect_key()
            .expect("a call is built only from a start that carries a key")
    }

    /// The step that performed it; `None` for an effect outside any step.
    #[must_use]
    pub fn step(&self) -> Option<StepId> {
        self.started.body.step
    }

    /// Forward, or compensating an earlier forward call.
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.started.body.phase
    }

    /// Where the announcement sits in the run's history.
    #[must_use]
    pub fn seq(&self) -> Seq {
        self.started.seq()
    }

    /// What was asked for: the kind and the arguments, as announced.
    #[must_use]
    pub fn descriptor(&self) -> &'a EffectDescriptor {
        match self.started.kind() {
            RecordKind::EffectStarted { descriptor, .. } => descriptor,
            _ => unreachable!("a call is built only from an EffectStarted record"),
        }
    }

    /// The announcement itself.
    #[must_use]
    pub const fn started(&self) -> &'a Record {
        self.started
    }

    /// The last record that settled this attempt — `EffectDone`,
    /// `EffectFailed` or `EffectReconciled` — or `None` while nothing has:
    /// the call is undecided, and the run's recovery says what happens next.
    ///
    /// The last rather than the first, because a reconciliation answers a
    /// failure that left the outcome in doubt.
    #[must_use]
    pub const fn outcome(&self) -> Option<&'a Record> {
        self.outcome
    }

    /// What the call returned: the output of an `EffectDone`, or the recovered
    /// result of a reconciliation that found it landed. `None` for a failure,
    /// an undecided call, and a reconciliation that recovered nothing.
    #[must_use]
    pub fn output(&self) -> Option<&'a Value> {
        match self.outcome?.kind() {
            RecordKind::EffectDone { output, .. } => Some(output),
            RecordKind::EffectReconciled { output, .. } => output.as_ref(),
            _ => None,
        }
    }

    /// The server and tool a `tool.call` named; `None` for any other kind.
    #[must_use]
    pub fn tool(&self) -> Option<crate::tools::ToolId> {
        crate::tools::ToolId::called(self.descriptor())
    }
}

/// Every effect attempt in `records`, in the order they were announced.
///
/// One entry per announcement: two calls to one tool are two entries, and a
/// retry is a second attempt under a second key. An announcement nothing
/// settled is listed with no outcome rather than dropped — it is the entry a
/// reader auditing a crash needs most. A terminal record with no announcement
/// in `records` (a page that began after it) is not a call and is skipped.
#[must_use]
pub fn calls(records: &[Record]) -> Vec<Call<'_>> {
    let mut found: Vec<Call<'_>> = Vec::new();
    let mut at: std::collections::HashMap<EffectKey, usize> = std::collections::HashMap::new();
    for record in records {
        let Some(key) = record.effect_key() else {
            continue;
        };
        match record.kind() {
            RecordKind::EffectStarted { .. } => {
                at.entry(key).or_insert_with(|| {
                    found.push(Call {
                        started: record,
                        outcome: None,
                    });
                    found.len() - 1
                });
            }
            RecordKind::EffectDone { .. }
            | RecordKind::EffectFailed { .. }
            | RecordKind::EffectReconciled { .. } => {
                if let Some(&i) = at.get(&key) {
                    found[i].outcome = Some(record);
                }
            }
            _ => {}
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::calls;
    use crate::core::{Digest, EffectDescriptor, EffectKey, Recovery, RunId, Spend, StepId};
    use crate::journal::{Append, Record, RecordKind};
    use serde_json::json;

    fn key(n: u8) -> EffectKey {
        EffectKey::from_hex(&Digest::of(&[n]).to_hex()).unwrap()
    }

    fn history(entries: Vec<(EffectKey, RecordKind)>) -> Vec<Record> {
        let run = RunId::generate();
        let mut prev = Digest::ZERO;
        let mut out = Vec::new();
        for (i, (k, kind)) in entries.into_iter().enumerate() {
            let a = Append::new(run, kind).step(StepId(0)).effect(k);
            let r = Record::seal(a.into_body(i as u64 + 1, 1), prev).unwrap();
            prev = r.hash;
            out.push(r);
        }
        out
    }

    fn tool_call(tool: &str) -> RecordKind {
        RecordKind::EffectStarted {
            descriptor: EffectDescriptor::new(
                "tool.call",
                json!({"server": "crm", "tool": tool, "arguments": {}}),
            ),
            recovery: Recovery::Retry,
            mutates: false,
            attempt: 1,
            backoff_ms: 0,
            outbound_label: None,
            outbound_bytes: None,
            content_rules: None,
            credential: None,
        }
    }

    fn done(output: serde_json::Value) -> RecordKind {
        RecordKind::EffectDone {
            declared: crate::core::DeclaredOutput::untrusted(),
            output,
            source: None,
            by: None,
            spend: Spend::default(),
            content: None,
            elapsed_ms: None,
        }
    }

    /// Two calls to one tool are two calls, each with its own answer — the
    /// join a reader keyed by tool name gets wrong, checking a sentence that
    /// cites the first call against the second call's output.
    #[test]
    fn two_calls_to_one_tool_stay_two_calls() {
        // Interleaved, as a parallel group writes them: both announced, then
        // both answered, so an outcome joined by position lands on the wrong
        // call.
        let records = history(vec![
            (key(1), tool_call("lookup")),
            (key(2), tool_call("lookup")),
            (key(1), done(json!({"customer": "A"}))),
            (key(2), done(json!({"customer": "B"}))),
        ]);
        let found = calls(&records);
        assert_eq!(found.len(), 2, "two calls collapsed into {}", found.len());
        assert_eq!(found[0].output(), Some(&json!({"customer": "A"})));
        assert_eq!(found[1].output(), Some(&json!({"customer": "B"})));
        let tool = found[0].tool().expect("a tool call names its tool");
        assert_eq!(
            (tool.server.as_str(), tool.tool.as_str()),
            ("crm", "lookup")
        );
        assert_eq!(found[0].key(), key(1));
        assert_eq!(found[1].seq(), 2);
    }

    /// A call nothing settled is listed, undecided — never dropped.
    #[test]
    fn an_unsettled_call_is_listed_without_an_outcome() {
        let records = history(vec![
            (key(1), tool_call("send")),
            (key(2), tool_call("lookup")),
            (key(2), done(json!(1))),
        ]);
        let found = calls(&records);
        assert_eq!(found.len(), 2, "the unsettled call was dropped");
        assert!(found[0].outcome().is_none());
        assert!(found[0].output().is_none());
        assert_eq!(found[1].output(), Some(&json!(1)));
    }

    /// A retry is a second attempt under a second key, and a compensation is
    /// listed with its phase — a reader can tell both from the forward call.
    #[test]
    fn a_retry_and_a_compensation_are_calls_of_their_own() {
        use crate::core::Phase;
        let run = RunId::generate();
        let mut prev = Digest::ZERO;
        let mut records = Vec::new();
        for (i, (k, phase, kind)) in [
            (key(1), Phase::Forward, tool_call("send")),
            (key(2), Phase::Forward, tool_call("send")),
            (key(2), Phase::Forward, done(json!("sent"))),
            (key(3), Phase::Compensating, tool_call("recall")),
            (key(3), Phase::Compensating, done(json!("recalled"))),
        ]
        .into_iter()
        .enumerate()
        {
            let a = Append::new(run, kind)
                .step(StepId(0))
                .phase(phase)
                .effect(k);
            let r = Record::seal(a.into_body(i as u64 + 1, 1), prev).unwrap();
            prev = r.hash;
            records.push(r);
        }
        let found = calls(&records);
        assert_eq!(found.len(), 3);
        assert!(
            found[0].outcome().is_none(),
            "the first attempt never settled"
        );
        assert_eq!(found[1].output(), Some(&json!("sent")));
        assert_eq!(found[2].phase(), Phase::Compensating);
        assert_eq!(found[2].output(), Some(&json!("recalled")));
    }

    /// A kind that is not a tool call names no tool.
    #[test]
    fn only_a_tool_call_names_a_tool() {
        let mut kind = tool_call("x");
        if let RecordKind::EffectStarted { descriptor, .. } = &mut kind {
            descriptor.kind = "model.complete".into();
        }
        let records = history(vec![(key(1), kind)]);
        assert!(calls(&records)[0].tool().is_none());
    }
}
