//! A run's model calls, read back from its journal.

use std::collections::BTreeMap;

use crate::core::{EffectKey, Seq};
use crate::journal::{Record, RecordKind};

use super::{Completion, ModelId};

/// One answered model call, as the journal holds it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ModelTurn {
    /// The record that holds the answer.
    pub seq: Seq,
    /// The call's effect key, which pairs it with its start and its span.
    pub key: EffectKey,
    /// The model the call asked for; [`Completion::model`] is the one that
    /// answered.
    pub model: ModelId,
    /// The answer, or `None` where the record no longer reads as one — its
    /// payload sealed under a key this reader was not given, or erased.
    pub completion: Option<Completion>,
}

/// Every answered model call in `history`, in journal order.
///
/// Paired by effect key, not by position: a retried call starts once per
/// attempt and is answered once, and a run's other effects interleave. A call
/// that failed or has not answered is not a turn.
///
/// The completion comes back without a label, as the record holds it. It is
/// for showing a person what the model said; a step reads the labelled value
/// the run was given, live and in replay.
#[must_use]
pub fn turns(history: &[Record]) -> Vec<ModelTurn> {
    let mut asked: BTreeMap<EffectKey, ModelId> = BTreeMap::new();
    let mut turns = Vec::new();
    for record in history {
        let Some(key) = record.effect_key() else {
            continue;
        };
        match record.kind() {
            RecordKind::EffectStarted { descriptor, .. } if descriptor.kind == "model.complete" => {
                let field = |name: &str| {
                    descriptor
                        .args
                        .get(name)
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                asked.insert(key, ModelId::new(field("provider"), field("model")));
            }
            RecordKind::EffectDone { output, .. } => {
                if let Some(model) = asked.remove(&key) {
                    turns.push(ModelTurn {
                        seq: record.seq(),
                        key,
                        model,
                        completion: serde_json::from_value(output.clone()).ok(),
                    });
                }
            }
            _ => {}
        }
    }
    turns
}
