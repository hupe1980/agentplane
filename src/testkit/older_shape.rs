//! An export as a build one record shape older would have written it.
//!
//! No build writes an older version: the writer stamps
//! [`RecordKind::version`](crate::journal::RecordKind::version) and nothing
//! selects another, which is the point of it. So a rehearsal of an upgrade
//! across a shape change starts from bytes crafted here, out of an export this
//! build wrote. [`older_shape`] rewrites every `StepStarted` record to the older
//! shape — its `skill` field named `name`, at version [`OLDER`] — and re-links
//! the file, so every hash, every sealing record's `chain_head`, every run's
//! seal and the header's root agree with the rewritten bytes. What is left is
//! the shape change alone.
//!
//! [`LiftsTheOlderShape`] is the upcaster the newer build ships for that
//! change, and [`ReadsOnlyTheOlderShape`] is the reader the older build
//! shipped: it reads `StepStarted` at [`OLDER`] and nothing newer.

use serde_json::{Value, json};

use crate::core::{Digest, StoreError};
use crate::journal::Upcaster;

/// The record version the crafted shape is written at.
pub const OLDER: u16 = 0;

/// The kind whose shape the crafted export moves.
const MOVED: &str = "StepStarted";

/// `export`, with every `StepStarted` record at the older shape and the file
/// re-linked around it.
///
/// # Panics
///
/// If `export` is not an export this build wrote, or carries no `StepStarted`
/// record — a fixture that moved nothing would rehearse nothing.
#[must_use]
pub fn older_shape(export: &str) -> String {
    let mut moved = 0usize;
    let older = relinked(export, |wire| {
        if wire["kind"] == json!(MOVED) {
            let object = wire.as_object_mut().expect("a record is an object");
            let skill = object
                .remove("skill")
                .expect("a StepStarted names its skill");
            object.insert("name".into(), skill);
            object.insert("v".into(), json!(OLDER));
            moved += 1;
        }
    });
    assert!(moved > 0, "the export carries no {MOVED} record to move");
    older
}

/// Re-link every record in an export after `edit` has rewritten some of them.
///
/// The file comes back exactly as internally consistent as its writer's own
/// output: each record's bytes canonical, each hash over its own bytes and its
/// predecessor, each sealing record's `chain_head`, each run block's seal and
/// the header's root. What is left different is only what `edit` did.
///
/// # Panics
///
/// If a line of `export` is not JSON, or a record line carries no wire bytes.
pub fn relinked(export: &str, mut edit: impl FnMut(&mut Value)) -> String {
    let mut lines: Vec<Value> = export
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("every export line is JSON"))
        .collect();
    let mut prev = Digest::ZERO;
    let mut block: Option<usize> = None;
    for at in 0..lines.len() {
        if lines[at]["kind"] == json!("agentplane.export.run") {
            prev = Digest::ZERO;
            block = Some(at);
            continue;
        }
        if lines[at].get("kind").is_some() {
            continue;
        }
        let line = &mut lines[at];
        let mut wire: Value =
            serde_json::from_str(line["raw"].as_str().expect("wire bytes")).expect("json");
        edit(&mut wire);
        if wire["kind"] == json!("RunConcluded") {
            wire["chain_head"] = json!(prev);
        }
        let raw = String::from_utf8(crate::core::canon::value_bytes(&wire)).expect("utf-8");
        let hash = Digest::chain(prev, raw.as_bytes());
        line["body"] = wire;
        line["prev_hash"] = json!(prev);
        line["hash"] = json!(hash);
        line["raw"] = json!(raw);
        prev = hash;
        if let Some(b) = block
            && lines[b].get("seal").is_some()
        {
            lines[b]["seal"] = json!(hash);
        }
    }
    let mut seals: Vec<(u64, Digest)> = lines
        .iter()
        .filter(|v| v["kind"] == json!("agentplane.export.run"))
        .filter_map(|v| {
            Some((
                v.get("index")?.as_u64()?,
                serde_json::from_value(v.get("seal")?.clone()).ok()?,
            ))
        })
        .collect();
    seals.sort_by_key(|(i, _)| *i);
    let root = crate::core::merkle::root(
        &seals
            .iter()
            .map(|(_, s)| crate::core::merkle::leaf_hash(s))
            .collect::<Vec<_>>(),
    );
    if let Some(header) = lines
        .iter_mut()
        .find(|l| l["kind"] == json!("agentplane.export"))
    {
        header["checkpoint"]["root"] = json!(root);
    }
    let mut out = lines
        .iter()
        .map(|l| serde_json::to_string(l).expect("serialises"))
        .collect::<Vec<_>>()
        .join("\n");
    out.push('\n');
    out
}

/// The upcaster a newer build ships for the crafted shape change: it lifts a
/// `StepStarted` at [`OLDER`] to this build's shape and refuses every other
/// version it is asked about.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiftsTheOlderShape;

impl Upcaster for LiftsTheOlderShape {
    fn current_version(&self, _kind: &str) -> u16 {
        1
    }

    fn upcast(&self, kind: &str, version: u16, mut payload: Value) -> Result<Value, StoreError> {
        if kind != MOVED || version != OLDER {
            return Err(StoreError::UnknownRecordVersion {
                kind: kind.to_owned(),
                version,
                reads: 1,
            });
        }
        let object = payload
            .as_object_mut()
            .ok_or_else(|| StoreError::Backend("a record is an object".into()))?;
        let name = object.remove("name").unwrap_or(Value::Null);
        object.insert("skill".into(), name);
        object.insert("v".into(), json!(1));
        Ok(payload)
    }
}

/// The reader the older build shipped: `StepStarted` at [`OLDER`], every
/// other kind at 1, and nothing lifted — so a record the newer build writes is
/// a version it has never heard of.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadsOnlyTheOlderShape;

impl Upcaster for ReadsOnlyTheOlderShape {
    fn current_version(&self, kind: &str) -> u16 {
        if kind == MOVED { OLDER } else { 1 }
    }

    fn upcast(&self, kind: &str, version: u16, _payload: Value) -> Result<Value, StoreError> {
        Err(StoreError::UnknownRecordVersion {
            kind: kind.to_owned(),
            version,
            reads: self.current_version(kind),
        })
    }
}
