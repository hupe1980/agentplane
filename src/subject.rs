//! Where a subject's data went.
//!
//! A read-only report: the subject's governed memory items, selected exactly
//! as an erasure selects them; the runs whose `DataSubjectBound` names the
//! subject, with their cases — the units a journal erasure acts on; and every
//! outbound effect whose clear label names one of those items in its
//! provenance or one of those bindings in its data-subject references. A
//! value is listed as *influenced by* an item or a run's intake, never as
//! *containing* it. Beside the result stands a coverage list naming
//! every class of flow the report cannot trace, so an absent run never reads
//! as *not reached* when it means *not traced*.
//!
//! The report appends nothing, writes no store and takes no operator. It is
//! evidence an operator hands to somebody, not a statement that a deployment
//! met any access obligation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use serde::Serialize;

use crate::core::{
    CaseId, EffectKey, Label, RunId, Sensitivity, SourceId, StepId, StoreError, SubjectRef, Trust,
};
use crate::journal::{JournalStore, RecordBody, RecordKind, payload};
use crate::memory::{MemoryStore, Selected, SemanticHit};

const RECALL: &str = "memory.recall";
const SEMANTIC_RECALL: &str = "memory.semantic-recall";
/// The effect kind of a case-state read, which a run attributes to its own
/// bindings only.
const CASE_STATE_READ: &str = "case.read_state";
/// The effect kind of a memory write, which carries no outbound label.
const REMEMBER: &str = "memory.remember";

/// One memory item the erasure would select. Never its content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Item {
    pub id: String,
    /// `None` when no version is current: forgotten, swept or never written.
    pub version: Option<u64>,
    pub trust: Option<Trust>,
    pub sensitivity: Option<Sensitivity>,
    pub written_by: Option<String>,
}

/// Why a sink is named by its kind alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Why {
    /// The effect is not a tool call.
    NotATool,
    /// The arguments are sealed and no key ring was given.
    Sealed,
    /// The arguments' key was destroyed.
    Erased,
}

/// Where an outbound value went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "by")]
pub enum Sink {
    Tool { server: String, tool: String },
    Kind { kind: String, why: Why },
}

/// One outbound effect a selected item's value influenced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Traced {
    pub run: RunId,
    pub case: Option<CaseId>,
    pub effect: Option<EffectKey>,
    pub kind: String,
    pub sink: Sink,
    pub outbound_bytes: Option<u64>,
    /// The selected ids the outbound label names.
    pub ids: BTreeSet<String>,
    /// The subject's bindings the outbound label references.
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub bindings: BTreeSet<SubjectRef>,
}

/// One run whose `DataSubjectBound` names the subject: what an erasure of the
/// subject's journaled data names, by run or by case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundRun {
    pub run: RunId,
    pub case: Option<CaseId>,
    pub index: u16,
    /// Where the run read the subject from, as its declaration spells it.
    pub binding: String,
    /// Whether the subject was read from untrusted input.
    pub asserted: bool,
}

/// One recall record that read a selected item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Recalled {
    pub run: RunId,
    pub case: Option<CaseId>,
    pub step: Option<StepId>,
    pub id: String,
    pub version: u64,
}

/// A class of flow the report cannot trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// A run with no data-subject binding: its input, events and case state
    /// are not traced. A run handed referenced input is counted only once it
    /// reads an event or case state, which it attributes to its own bindings.
    UnboundIngress,
    /// A binding sealed with no key ring given.
    UnopenedBinding,
    /// A binding whose key was destroyed.
    ErasedBinding,
    /// Data about the subject from a source the run did not take it in from.
    UntakenData,
    /// A trusted item's recall puts no source in any label.
    TrustedItem,
    /// Recall records whose output could not be opened.
    UnopenedRecall,
    /// Forgotten and swept ids are not enumerable by subject.
    ForgottenIds,
    /// A sink whose arguments were not opened is named by kind only.
    UnopenedSink,
    /// `memory:{id}` names an item, not a version.
    PerItem,
    /// A coded step that does not join its inputs' labels drops the source.
    CodedStep,
    /// A memory write keeps no data-subject reference, so a subject's data
    /// written by a bound run is traced again only through items filed under
    /// the subject.
    RememberedIntake,
    /// Runs past the limit, or unreadable.
    RunsNotScanned,
}

impl Class {
    /// Every class, in the order a report prints them.
    pub const ALL: &[Self] = &[
        Self::UnboundIngress,
        Self::UnopenedBinding,
        Self::ErasedBinding,
        Self::UntakenData,
        Self::TrustedItem,
        Self::UnopenedRecall,
        Self::ForgottenIds,
        Self::UnopenedSink,
        Self::PerItem,
        Self::CodedStep,
        Self::RememberedIntake,
        Self::RunsNotScanned,
    ];

    /// What the class means, for the person reading the report.
    #[must_use]
    pub const fn says(self) -> &'static str {
        match self {
            Self::UnboundIngress => {
                "a run that binds no data subject is not traced through its input, events \
                 or case state; one handed referenced input, as a commissioned run is, is \
                 traced through that input and counted once it reads an event or case state"
            }
            Self::UnopenedBinding => {
                "a sealed subject binding cannot be matched without the key ring"
            }
            Self::ErasedBinding => "an erased subject binding names nobody",
            Self::UntakenData => {
                "data about the subject from a tool, model or peer is traced only once \
                 joined with what a bound run took in"
            }
            Self::TrustedItem => {
                "a trusted item's recall leaves no source in any label, so the effects its \
                 value reached are not traced"
            }
            Self::UnopenedRecall => "recall records that could not be opened are not listed",
            Self::ForgottenIds => "forgotten and swept ids are not enumerable by subject",
            Self::UnopenedSink => "a sink whose arguments were not opened is named by kind only",
            Self::PerItem => "the trace is per item, not per version",
            Self::CodedStep => {
                "a coded step that passes a value on without joining its inputs' labels \
                 drops the item's source"
            }
            Self::RememberedIntake => {
                "a bound run's memory write keeps no data-subject reference, so what it \
                 wrote is traced again only through items filed under the subject"
            }
            Self::RunsNotScanned => "runs past the limit, or unreadable, were not scanned",
        }
    }
}

/// One coverage line: a class, and whether this report met an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Coverage {
    pub class: Class,
    pub says: &'static str,
    pub met: bool,
    /// For unopened recalls: how many were sealed and how many erased.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<Unopened>,
}

/// Recall records left unopened, by reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Unopened {
    pub sealed: usize,
    pub erased: usize,
}

/// Where one subject's data went, and what the report could not see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SubjectReport {
    pub subject: String,
    pub items: Vec<Item>,
    /// The coverage list, every class on every report.
    pub coverage: Vec<Coverage>,
    pub effects: Vec<Traced>,
    pub recalls: Vec<Recalled>,
    /// The runs whose intake is bound to the subject.
    pub bound: Vec<BoundRun>,
    pub runs_scanned: usize,
    /// Each listing cut by the limit, and each run that would not read.
    pub not_scanned: Vec<String>,
}

impl SubjectReport {
    /// Whether the scan was cut or named an unreadable run.
    #[must_use]
    pub fn partial(&self) -> bool {
        !self.not_scanned.is_empty()
    }
}

/// Why the report could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum SubjectError {
    #[error("reading the store failed: {0}")]
    Store(#[from] StoreError),
    /// A key ring failed for a reason other than a destroyed key.
    #[error("opening a sealed payload failed: {0}")]
    Keys(String),
}

/// Whether a record's sealed payloads were opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opening {
    Clear,
    Sealed,
    #[cfg_attr(not(feature = "keyring"), allow(dead_code))]
    Erased,
}

/// The report's inputs beyond the stores: whose plane, and the ring that opens
/// what is sealed.
#[derive(Debug, Clone, Copy)]
pub struct Trace<'a> {
    tenant: &'a str,
    #[cfg(feature = "keyring")]
    keys: Option<&'a dyn crate::keyring::KeyRing>,
}

impl<'a> Trace<'a> {
    /// A report over `tenant`'s runs, opening nothing sealed.
    #[must_use]
    pub const fn new(tenant: &'a str) -> Self {
        Self {
            tenant,
            #[cfg(feature = "keyring")]
            keys: None,
        }
    }

    /// Open sealed arguments and recall outputs with `keys`. A destroyed key is
    /// an erasure; any other ring failure fails the report.
    #[cfg(feature = "keyring")]
    #[must_use]
    pub const fn with_keys(mut self, keys: &'a dyn crate::keyring::KeyRing) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Where `subject`'s data went, over at most `limit` runs per listing.
    ///
    /// `journal` is the raw store, never a sealing decorator.
    ///
    /// # Errors
    ///
    /// When a store cannot be read, or a supplied ring fails for a reason other
    /// than a destroyed key.
    #[allow(clippy::too_many_lines)]
    pub async fn report(
        &self,
        journal: &Arc<dyn JournalStore>,
        memories: &dyn MemoryStore,
        subject: &str,
        limit: usize,
    ) -> Result<SubjectReport, SubjectError> {
        let ids = memories.subject_ids(subject).await?;
        let mut items = Vec::with_capacity(ids.len());
        for id in &ids {
            let current = memories.current(id, None).await?;
            items.push(Item {
                id: id.clone(),
                version: current.as_ref().map(|m| m.version),
                trust: current.as_ref().map(|m| m.trust),
                sensitivity: current.as_ref().map(|m| m.sensitivity),
                written_by: current.map(|m| m.written_by),
            });
        }
        let sources: BTreeMap<SourceId, String> = ids
            .iter()
            .map(|id| (SourceId::new(format!("memory:{id}")), id.clone()))
            .collect();
        let selected: BTreeSet<&str> = ids.iter().map(String::as_str).collect();

        let outcomes: Vec<String> = crate::runtime::OUTCOMES_OF_RECORD
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let found = crate::export::runs_to_read(journal, &outcomes, true, limit).await?;
        let mut not_scanned = found.reached;
        not_scanned.extend(
            found
                .unreadable
                .iter()
                .map(|(run, why)| format!("run {run}: {why}")),
        );

        let mut scanned = Vec::new();
        for run in found.runs {
            match journal.read(run, 1).await {
                Ok(records) => scanned.push((run, records)),
                Err(e) => not_scanned.push(format!("run {run}: {e}")),
            }
        }
        let runs_scanned = scanned.len();

        // Every binding first, across every scanned run: a reference reaches
        // another run's labels whenever a value does, as a commissioned
        // run's input does.
        let mut bound = Vec::new();
        let mut refs = BTreeSet::new();
        let mut bindings_unopened = Unopened::default();
        let mut unbound_runs = 0;
        for (run, records) in &scanned {
            let mut admitted = false;
            let mut binds = false;
            // A run that binds nothing may still have been handed referenced
            // input — a commissioned run is — and that input is traced. What
            // it reads beyond its input is attributed to its own bindings
            // only, so an event or a case-state read leaves it untraced.
            let mut handed_refs = false;
            let mut reads_beyond_input = false;
            for record in records {
                let body = &record.body;
                match &body.kind {
                    RecordKind::RunAdmitted { input_label, .. } => {
                        admitted = true;
                        handed_refs = !input_label.data_subjects.is_empty();
                    }
                    RecordKind::RunSuspended {
                        reason: crate::core::SuspendReason::AwaitingEvent { .. },
                    } => reads_beyond_input = true,
                    RecordKind::EffectStarted { descriptor, .. }
                        if descriptor.kind == CASE_STATE_READ =>
                    {
                        reads_beyond_input = true;
                    }
                    RecordKind::DataSubjectBound { .. } => {
                        binds = true;
                        let mut kind = body.kind.clone();
                        match self.open(body, &mut kind).await? {
                            Opening::Sealed => bindings_unopened.sealed += 1,
                            Opening::Erased => bindings_unopened.erased += 1,
                            Opening::Clear => {
                                let RecordKind::DataSubjectBound { bindings } = kind else {
                                    continue;
                                };
                                for b in bindings.into_iter().filter(|b| b.subject == subject) {
                                    refs.insert(SubjectRef {
                                        run: *run,
                                        index: b.index,
                                    });
                                    let entry = BoundRun {
                                        run: *run,
                                        case: body.case,
                                        index: b.index,
                                        binding: b.binding.to_string(),
                                        asserted: !b.trusted,
                                    };
                                    bound.push(entry);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            if admitted && !binds && (!handed_refs || reads_beyond_input) {
                unbound_runs += 1;
            }
        }

        let mut effects = Vec::new();
        let mut recalls = Vec::new();
        let mut unopened = Unopened::default();
        let mut remembered = false;
        for (run, records) in &scanned {
            let run = *run;
            let mut seen = BTreeSet::new();
            let mut recall_keys = BTreeSet::new();
            // Whether this run's intake names the subject: it bound it, or it
            // was handed a value that carried one of its references.
            let mut takes_in = refs.iter().any(|r| r.run == run);
            for record in records {
                let body = &record.body;
                match &body.kind {
                    RecordKind::RunAdmitted { input_label, .. } => {
                        takes_in |= input_label.data_subjects.iter().any(|r| refs.contains(r));
                    }
                    RecordKind::EffectStarted {
                        descriptor,
                        outbound_label,
                        outbound_bytes,
                        ..
                    } => {
                        if matches!(descriptor.kind.as_str(), RECALL | SEMANTIC_RECALL) {
                            recall_keys.extend(body.effect_key);
                        }
                        remembered |= takes_in && descriptor.kind == REMEMBER;
                        let Some(label) = outbound_label else {
                            continue;
                        };
                        let named: BTreeSet<String> = sources
                            .iter()
                            .filter(|(source, _)| names(label, source))
                            .map(|(_, id)| id.clone())
                            .collect();
                        let bindings: BTreeSet<SubjectRef> =
                            label.data_subjects.intersection(&refs).copied().collect();
                        if (named.is_empty() && bindings.is_empty())
                            || body.effect_key.is_some_and(|k| !seen.insert(k))
                        {
                            continue;
                        }
                        let sink = self.sink(body).await?;
                        effects.push(Traced {
                            run,
                            case: body.case,
                            effect: body.effect_key,
                            kind: descriptor.kind.clone(),
                            sink,
                            outbound_bytes: *outbound_bytes,
                            ids: named,
                            bindings,
                        });
                    }
                    RecordKind::EffectDone { .. }
                        if body.effect_key.is_some_and(|k| recall_keys.contains(&k)) =>
                    {
                        let mut kind = body.kind.clone();
                        match self.open(body, &mut kind).await? {
                            Opening::Sealed => unopened.sealed += 1,
                            Opening::Erased => unopened.erased += 1,
                            Opening::Clear => {
                                let RecordKind::EffectDone { output, .. } = kind else {
                                    continue;
                                };
                                for chosen in recalled(output) {
                                    if selected.contains(chosen.id.as_str()) {
                                        recalls.push(Recalled {
                                            run,
                                            case: body.case,
                                            step: body.step,
                                            id: chosen.id,
                                            version: chosen.version,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let coverage = Class::ALL
            .iter()
            .map(|&class| Coverage {
                class,
                says: class.says(),
                met: match class {
                    Class::UnboundIngress => unbound_runs > 0,
                    Class::UnopenedBinding => bindings_unopened.sealed > 0,
                    Class::ErasedBinding => bindings_unopened.erased > 0,
                    Class::UntakenData
                    | Class::ForgottenIds
                    | Class::PerItem
                    | Class::CodedStep => false,
                    Class::TrustedItem => items.iter().any(|i| i.trust == Some(Trust::Trusted)),
                    Class::UnopenedRecall => unopened.sealed + unopened.erased > 0,
                    Class::UnopenedSink => effects.iter().any(|e| {
                        matches!(
                            e.sink,
                            Sink::Kind {
                                why: Why::Sealed | Why::Erased,
                                ..
                            }
                        )
                    }),
                    Class::RememberedIntake => remembered,
                    Class::RunsNotScanned => !not_scanned.is_empty(),
                },
                count: match class {
                    Class::UnopenedRecall => Some(unopened),
                    Class::UnopenedBinding | Class::ErasedBinding => Some(bindings_unopened),
                    _ => None,
                },
            })
            .collect();

        Ok(SubjectReport {
            subject: subject.to_owned(),
            items,
            coverage,
            effects,
            recalls,
            bound,
            runs_scanned,
            not_scanned,
        })
    }

    async fn sink(&self, body: &RecordBody) -> Result<Sink, SubjectError> {
        let RecordKind::EffectStarted { descriptor, .. } = &body.kind else {
            unreachable!("only an effect start names a sink");
        };
        if descriptor.kind != "tool.call" {
            return Ok(Sink::Kind {
                kind: descriptor.kind.clone(),
                why: Why::NotATool,
            });
        }
        let mut kind = body.kind.clone();
        let why = match self.open(body, &mut kind).await? {
            Opening::Clear => {
                let RecordKind::EffectStarted { descriptor, .. } = kind else {
                    unreachable!("opening keeps the record's kind");
                };
                let field = |name: &str| {
                    descriptor
                        .args
                        .get(name)
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                return Ok(Sink::Tool {
                    server: field("server"),
                    tool: field("tool"),
                });
            }
            Opening::Sealed => Why::Sealed,
            Opening::Erased => Why::Erased,
        };
        Ok(Sink::Kind {
            kind: descriptor.kind.clone(),
            why,
        })
    }

    /// Open `kind`'s sealed payloads if a ring was given.
    #[cfg_attr(
        not(feature = "keyring"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn open(
        &self,
        body: &RecordBody,
        kind: &mut RecordKind,
    ) -> Result<Opening, SubjectError> {
        #[cfg(feature = "keyring")]
        if let Some(keys) = self.keys {
            let opened =
                crate::keyring::open_payloads(keys, self.tenant, body.run, body.effect_key, kind)
                    .await
                    .map_err(|e| SubjectError::Keys(e.to_string()))?;
            if opened.erased > 0 {
                return Ok(Opening::Erased);
            }
        }
        let _ = (body, self.tenant);
        let sealed = payload::payloads(kind)
            .into_iter()
            .any(|field| match field {
                payload::SealedField::Value(v) => payload::is_sealed(v),
                payload::SealedField::Text(t) => payload::is_sealed_text(t),
            });
        Ok(if sealed {
            Opening::Sealed
        } else {
            Opening::Clear
        })
    }
}

/// Whether `label` names `source` exactly.
fn names(label: &Label, source: &SourceId) -> bool {
    label.provenance.contains(source)
}

/// The items a recall's output selected, from either recall's shape.
fn recalled(output: serde_json::Value) -> Vec<Selected> {
    if let Ok(selected) = serde_json::from_value::<Vec<Selected>>(output.clone()) {
        return selected;
    }
    serde_json::from_value::<Vec<SemanticHit>>(output)
        .map(|hits| hits.into_iter().map(|h| h.selected).collect())
        .unwrap_or_default()
}

impl fmt::Display for SubjectReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "subject {}", self.subject)?;
        writeln!(
            f,
            "coverage — what this report cannot trace ([x] met in this report):"
        )?;
        for line in &self.coverage {
            let mark = if line.met { "x" } else { " " };
            write!(f, "  [{mark}] {}", line.says)?;
            if let Some(n) = line.count.filter(|_| line.met) {
                write!(f, " ({} sealed, {} erased)", n.sealed, n.erased)?;
            }
            writeln!(f)?;
        }
        for cut in &self.not_scanned {
            writeln!(f, "  not scanned: {cut}")?;
        }
        writeln!(f, "items ({}):", self.items.len())?;
        for item in &self.items {
            match item.version {
                Some(v) => writeln!(
                    f,
                    "  {} v{v} {:?} {:?} written by {}",
                    item.id,
                    item.trust.unwrap_or(Trust::Untrusted),
                    item.sensitivity.unwrap_or(Sensitivity::Secret),
                    item.written_by.as_deref().unwrap_or("-")
                )?,
                None => writeln!(f, "  {} (no current version)", item.id)?,
            }
        }
        writeln!(
            f,
            "runs whose intake is bound to the subject ({}):",
            self.bound.len()
        )?;
        for b in &self.bound {
            let case = b.case.map_or_else(|| "-".to_owned(), |c| c.to_string());
            let asserted = if b.asserted {
                ", asserted by untrusted input"
            } else {
                ""
            };
            writeln!(
                f,
                "  run {} case {case} binding {}{asserted}",
                b.run, b.binding
            )?;
        }
        writeln!(
            f,
            "outbound effects influenced by these items or bound runs ({} runs scanned):",
            self.runs_scanned
        )?;
        for e in &self.effects {
            let sink = match &e.sink {
                Sink::Tool { server, tool } => format!("tool://{server}/{tool}"),
                Sink::Kind { kind, why } => format!("{kind} ({why:?})"),
            };
            let ids: Vec<&str> = e.ids.iter().map(String::as_str).collect();
            let bound: Vec<String> = e.bindings.iter().map(|r| r.run.to_string()).collect();
            writeln!(
                f,
                "  run {} effect {} -> {sink}, {} bytes, ids {}, bound by {}",
                e.run,
                e.effect.map_or_else(|| "-".to_owned(), EffectKey::to_hex),
                e.outbound_bytes
                    .map_or_else(|| "?".to_owned(), |b| b.to_string()),
                if ids.is_empty() {
                    "-".to_owned()
                } else {
                    ids.join(",")
                },
                if bound.is_empty() {
                    "-".to_owned()
                } else {
                    bound.join(",")
                }
            )?;
        }
        writeln!(f, "recall records ({}):", self.recalls.len())?;
        for r in &self.recalls {
            writeln!(f, "  run {} read {} v{}", r.run, r.id, r.version)?;
        }
        Ok(())
    }
}
