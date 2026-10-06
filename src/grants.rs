//! The grants an agent never used, read from an export.
//!
//! Per manifest digest, each tool grant with the runs and calls that exercised
//! it; the menu values chosen; observed outbound bytes against the egress
//! ceiling; and a proposed manifest with the unused grants removed, for a
//! person to review, sign and publish. Nothing here applies it.
//!
//! A grant is named only where a call's arguments were readable: on an
//! unsealed export always, on a sealed one only with a caller-supplied ring
//! and a standing key. Where any call under a digest could not be read,
//! *unused* is not established for that digest and the report says so.
//!
//! Reads one export and the manifests it is handed. It opens no store and
//! holds no client.

use std::io::BufRead;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;
use serde_json::Value;

use crate::core::{Digest, EffectKey, RunId};
use crate::journal::{RecordBody, RecordKind, payload};
use crate::manifest::Manifest;
use crate::tools::ToolId;

const TOOL_CALL: &str = "tool.call";
const COMMISSION: &str = "agent.commission";

/// Why the report could not answer at all.
#[derive(Debug, thiserror::Error)]
pub enum GrantsError {
    #[error("reading the export failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    NotAnExport(String),
    /// A key ring was supplied and failed for a reason other than erasure.
    #[error("opening a sealed payload failed: {0}")]
    Keys(String),
    /// A supplied manifest has no digest.
    #[error("a supplied manifest could not be digested: {0}")]
    Manifest(String),
}

/// What one grant's record of use establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mark {
    Used,
    /// No call under the digest named it, and every call was readable.
    Unused,
    /// No call named it, and the digest has refusals no record attributes.
    UnusedRefusalsNotAttributable,
    /// No readable call named it, and some calls could not be read.
    NotEstablished,
}

/// The values one protected field's menu saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "menu")]
pub enum MenuRow {
    Counted {
        path: String,
        chosen: BTreeMap<String, usize>,
        unchosen: Vec<String>,
    },
    /// A call's arguments could not be read, so no count is a count.
    NotDerivable { path: String },
}

/// One tool grant under one digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrantRow {
    pub reference: String,
    /// Distinct effect keys whose arguments named this grant.
    pub calls: usize,
    pub runs: usize,
    pub mark: Mark,
    pub menus: Vec<MenuRow>,
}

/// Observed outbound bytes against the declared ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EgressRow {
    pub min: Option<u64>,
    pub median: Option<u64>,
    pub max: Option<u64>,
    /// Effects that recorded no byte count.
    pub uncounted: usize,
    /// `None`: no ceiling declared.
    pub ceiling: Option<u64>,
    /// The ceiling less the largest run's total.
    pub headroom: Option<i128>,
}

/// Which declaration governed a group of runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "declaration")]
pub enum Declaration {
    Supplied {
        name: String,
        version: String,
    },
    NotSupplied,
    /// The runs name no declaration: the code tier.
    None,
}

/// A proposed manifest: the input less whole unused grants.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Proposal {
    pub manifest: Manifest,
    pub removed: Vec<String>,
    /// Each unused grant kept because removing it failed validation, and why.
    pub kept: Vec<(String, String)>,
}

/// One manifest digest's runs.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DigestRow {
    pub digest: Option<String>,
    pub declaration: Declaration,
    pub runs: usize,
    pub calls_read: usize,
    pub sealed: usize,
    pub erased: usize,
    pub refusals: BTreeMap<String, usize>,
    pub grants: Vec<GrantRow>,
    pub egress: EgressRow,
    pub proposal: Option<Proposal>,
}

impl DigestRow {
    /// Whether *unused* is established for this digest.
    #[must_use]
    pub const fn established(&self) -> bool {
        self.sealed + self.erased == 0
    }
}

/// The runs read and whether the file was whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Window {
    pub runs: usize,
    /// Run-id times, on the admitting instance's clock, as unix milliseconds.
    pub earliest_ms: Option<u64>,
    pub latest_ms: Option<u64>,
    pub trailer: bool,
    pub unreadable: Vec<RunId>,
    pub verified: bool,
}

impl Window {
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.trailer && self.unreadable.is_empty()
    }
}

/// The grant exercise report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GrantReport {
    pub window: Window,
    pub digests: Vec<DigestRow>,
    /// Supplied manifests no run in the export names.
    pub unexercised_manifests: Vec<String>,
}

impl GrantReport {
    /// Whether any supplied manifest has a grant marked unused.
    #[must_use]
    pub fn has_unused(&self) -> bool {
        self.digests
            .iter()
            .flat_map(|d| &d.grants)
            .any(|g| g.mark == Mark::Unused)
    }

    /// Whether the export was incomplete or some calls could not be read.
    #[must_use]
    pub fn partial(&self) -> bool {
        !self.window.complete() || self.digests.iter().any(|d| !d.established())
    }
}

/// The manifests to measure, and the ring that opens sealed arguments.
#[derive(Debug, Clone, Copy)]
pub struct Grants<'a> {
    manifests: &'a [Manifest],
    #[cfg(feature = "keyring")]
    keys: Option<(&'a str, &'a dyn crate::keyring::KeyRing)>,
}

/// Whether a call's arguments were readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opening {
    Clear,
    Sealed,
    #[cfg_attr(not(feature = "keyring"), allow(dead_code))]
    Erased,
}

#[derive(Default)]
struct Group {
    runs: BTreeSet<RunId>,
    bytes: BTreeMap<RunId, u64>,
    uncounted: usize,
    calls: BTreeMap<ToolId, BTreeSet<(RunId, Option<EffectKey>)>>,
    arguments: Vec<(ToolId, Value)>,
    sealed: usize,
    erased: usize,
    refusals: BTreeMap<String, usize>,
}

impl<'a> Grants<'a> {
    /// A report measuring the export against `manifests`.
    #[must_use]
    pub const fn new(manifests: &'a [Manifest]) -> Self {
        Self {
            manifests,
            #[cfg(feature = "keyring")]
            keys: None,
        }
    }

    /// Open sealed arguments with `keys`, as `tenant`'s. A destroyed key is
    /// counted erased; any other ring failure fails the report.
    #[cfg(feature = "keyring")]
    #[must_use]
    pub const fn with_keys(
        mut self,
        tenant: &'a str,
        keys: &'a dyn crate::keyring::KeyRing,
    ) -> Self {
        self.keys = Some((tenant, keys));
        self
    }

    /// Read `input` and report.
    ///
    /// # Errors
    ///
    /// When the input is unreadable or not an export, a supplied manifest has
    /// no digest, or a supplied ring fails for a reason other than erasure.
    pub async fn run<R: BufRead>(&self, input: R) -> Result<GrantReport, GrantsError> {
        let read = crate::export::read_runs(input).map_err(|e| match e {
            crate::export::ReadError::Io(e) => GrantsError::Io(e),
            crate::export::ReadError::NotAnExport(e) => GrantsError::NotAnExport(e),
        })?;
        let mut supplied = Vec::with_capacity(self.manifests.len());
        for manifest in self.manifests {
            let digest = manifest
                .digest()
                .map_err(|e| GrantsError::Manifest(e.to_string()))?;
            supplied.push((digest, manifest));
        }

        let times: Vec<u64> = read.runs.iter().map(|(r, _)| r.0.timestamp_ms()).collect();
        let window = Window {
            runs: read.runs.len(),
            earliest_ms: times.iter().min().copied(),
            latest_ms: times.iter().max().copied(),
            trailer: read.trailer,
            unreadable: read.unreadable,
            verified: false,
        };

        let mut groups: BTreeMap<Option<Digest>, Group> = BTreeMap::new();
        for (run, records) in read.runs {
            let digest = records.iter().find_map(|b| match &b.kind {
                RecordKind::RunAdmitted { governed_by, .. } => {
                    Some(governed_by.as_ref().map(|g| g.digest))
                }
                _ => None,
            });
            let group = groups.entry(digest.flatten()).or_default();
            group.runs.insert(run);
            for body in &records {
                self.read_record(run, body, group).await?;
            }
        }

        let mut digests = Vec::new();
        for (digest, group) in groups {
            let manifest = digest.and_then(|d| supplied.iter().find(|(s, _)| *s == d));
            digests.push(row(digest, manifest.map(|(_, m)| *m), &group));
        }
        let unexercised_manifests = supplied
            .iter()
            .filter(|(d, _)| !digests.iter().any(|r| r.digest == Some(d.to_hex())))
            .map(|(d, _)| d.to_hex())
            .collect();
        Ok(GrantReport {
            window,
            digests,
            unexercised_manifests,
        })
    }

    async fn read_record(
        &self,
        run: RunId,
        body: &RecordBody,
        group: &mut Group,
    ) -> Result<(), GrantsError> {
        match &body.kind {
            RecordKind::EffectStarted {
                descriptor,
                outbound_bytes,
                ..
            } => {
                match outbound_bytes {
                    Some(n) => *group.bytes.entry(run).or_default() += n,
                    None => group.uncounted += 1,
                }
                if !matches!(descriptor.kind.as_str(), TOOL_CALL | COMMISSION) {
                    return Ok(());
                }
                let mut kind = body.kind.clone();
                match self.open(body, &mut kind).await? {
                    Opening::Sealed => group.sealed += 1,
                    Opening::Erased => group.erased += 1,
                    Opening::Clear => {
                        let RecordKind::EffectStarted { descriptor, .. } = kind else {
                            unreachable!("opening keeps the record's kind");
                        };
                        if let Some(called) = called(&descriptor.kind, &descriptor.args) {
                            group
                                .calls
                                .entry(called.clone())
                                .or_default()
                                .insert((run, body.effect_key));
                            let arguments = descriptor.args.get("arguments").cloned();
                            group
                                .arguments
                                .push((called, arguments.unwrap_or(Value::Null)));
                        }
                    }
                }
            }
            RecordKind::PolicyDenied { resource, .. } => {
                *group.refusals.entry(resource.clone()).or_default() += 1;
            }
            _ => {}
        }
        Ok(())
    }

    #[cfg_attr(
        not(feature = "keyring"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn open(&self, body: &RecordBody, kind: &mut RecordKind) -> Result<Opening, GrantsError> {
        #[cfg(feature = "keyring")]
        if let Some((tenant, keys)) = self.keys {
            let opened =
                crate::keyring::open_payloads(keys, tenant, body.run, body.effect_key, kind)
                    .await
                    .map_err(|e| GrantsError::Keys(e.to_string()))?;
            if opened.erased > 0 {
                return Ok(Opening::Erased);
            }
        }
        let _ = body;
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

/// The grant a readable call's arguments name.
fn called(kind: &str, args: &Value) -> Option<ToolId> {
    let text = |name: &str| args.get(name).and_then(Value::as_str);
    match kind {
        TOOL_CALL => Some(ToolId::new(text("server")?, text("tool")?)),
        COMMISSION => Some(ToolId::new("agent", text("capability")?)),
        _ => None,
    }
}

/// Whether a call exercised a grant: by the reference, never by the kind.
fn exercises(grant: Option<&ToolId>, called: &ToolId) -> bool {
    grant == Some(called)
}

fn mark(calls: usize, unread: usize, refused: bool) -> Mark {
    if calls > 0 {
        Mark::Used
    } else if unread > 0 {
        Mark::NotEstablished
    } else if refused {
        Mark::UnusedRefusalsNotAttributable
    } else {
        Mark::Unused
    }
}

fn row(digest: Option<Digest>, manifest: Option<&Manifest>, group: &Group) -> DigestRow {
    let unread = group.sealed + group.erased;
    let refused = group.refusals.contains_key(TOOL_CALL) || group.refusals.contains_key(COMMISSION);
    let mut grants = Vec::new();
    if let Some(manifest) = manifest {
        for grant in &manifest.spec.tools {
            let id = ToolId::parse(&grant.reference);
            let mut keys = BTreeSet::new();
            for (called, calls) in &group.calls {
                if exercises(id.as_ref(), called) {
                    keys.extend(calls.iter().copied());
                }
            }
            let runs: BTreeSet<RunId> = keys.iter().map(|(r, _)| *r).collect();
            let mark = mark(keys.len(), unread, refused);
            let menus = grant
                .protected_fields
                .iter()
                .filter(|f| !f.allowed_values().is_empty())
                .filter(|_| mark == Mark::Used || unread > 0)
                .map(|field| {
                    if unread > 0 {
                        return MenuRow::NotDerivable {
                            path: field.path().to_owned(),
                        };
                    }
                    let mut chosen = BTreeMap::new();
                    for (called, arguments) in &group.arguments {
                        if !exercises(id.as_ref(), called) {
                            continue;
                        }
                        if let Some(v) = arguments.pointer(field.path()) {
                            *chosen.entry(spelled(v)).or_default() += 1;
                        }
                    }
                    let unchosen = field
                        .allowed_values()
                        .iter()
                        .map(spelled)
                        .filter(|v| !chosen.contains_key(v))
                        .collect();
                    MenuRow::Counted {
                        path: field.path().to_owned(),
                        chosen,
                        unchosen,
                    }
                })
                .collect();
            grants.push(GrantRow {
                reference: grant.reference.clone(),
                calls: keys.len(),
                runs: runs.len(),
                mark,
                menus,
            });
        }
    }

    let mut totals: Vec<u64> = group
        .runs
        .iter()
        .filter_map(|r| group.bytes.get(r).copied())
        .collect();
    totals.sort_unstable();
    let max = totals.last().copied();
    let ceiling = manifest.and_then(|m| m.budget().max_egress_bytes);
    let egress = EgressRow {
        min: totals.first().copied(),
        median: totals.get(totals.len() / 2).copied(),
        max,
        uncounted: group.uncounted,
        ceiling,
        headroom: ceiling.map(|c| i128::from(c) - i128::from(max.unwrap_or(0))),
    };

    DigestRow {
        digest: digest.map(Digest::to_hex),
        declaration: match (digest, manifest) {
            (_, Some(m)) => Declaration::Supplied {
                name: m.metadata.name.clone(),
                version: m.metadata.version.clone(),
            },
            (Some(_), None) => Declaration::NotSupplied,
            (None, None) => Declaration::None,
        },
        runs: group.runs.len(),
        calls_read: group.calls.values().map(BTreeSet::len).sum(),
        sealed: group.sealed,
        erased: group.erased,
        refusals: group.refusals.clone(),
        proposal: manifest.map(|m| propose(m, &grants)),
        grants,
        egress,
    }
}

/// A menu value as the report prints it.
fn spelled(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

/// The input less each unused grant whose removal still validates, tried one
/// at a time in declaration order.
fn propose(manifest: &Manifest, grants: &[GrantRow]) -> Proposal {
    let mut proposal = manifest.clone();
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    for grant in grants.iter().filter(|g| g.mark == Mark::Unused) {
        let mut candidate = proposal.clone();
        candidate
            .spec
            .tools
            .retain(|t| t.reference != grant.reference);
        match candidate.validate() {
            Ok(()) => {
                proposal = candidate;
                removed.push(grant.reference.clone());
            }
            Err(e) => kept.push((grant.reference.clone(), e.to_string())),
        }
    }
    Proposal {
        manifest: proposal,
        removed,
        kept,
    }
}

fn instant(ms: Option<u64>) -> String {
    ms.and_then(|ms| i64::try_from(ms / 1000).ok())
        .and_then(|s| crate::core::Timestamp::from_unix_timestamp(s).ok())
        .map_or_else(|| "-".to_owned(), crate::core::format_timestamp)
}

impl fmt::Display for GrantReport {
    #[allow(clippy::too_many_lines, clippy::many_single_char_names)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let w = &self.window;
        writeln!(
            f,
            "window: {} runs, {} to {} (run-id time, the admitting instance's clock)",
            w.runs,
            instant(w.earliest_ms),
            instant(w.latest_ms)
        )?;
        if w.complete() {
            writeln!(f, "export: complete")?;
        } else {
            writeln!(
                f,
                "export: INCOMPLETE (trailer {}, {} unreadable runs)",
                if w.trailer { "present" } else { "missing" },
                w.unreadable.len()
            )?;
        }
        writeln!(
            f,
            "this report did not verify the export; `verify` does. Unused means unused in \
             this window."
        )?;
        for d in &self.digests {
            writeln!(f)?;
            let digest = d.digest.as_deref().unwrap_or("-");
            match &d.declaration {
                Declaration::Supplied { name, version } => {
                    writeln!(f, "digest {digest} ({name} {version}), {} runs", d.runs)?;
                }
                Declaration::NotSupplied => {
                    writeln!(
                        f,
                        "digest {digest}: declaration not supplied, {} runs",
                        d.runs
                    )?;
                }
                Declaration::None => writeln!(f, "no declaration (code tier), {} runs", d.runs)?,
            }
            write!(
                f,
                "  a grant is named only where a call's arguments were readable: {} sealed, \
                 {} erased",
                d.sealed, d.erased
            )?;
            if d.established() {
                writeln!(f)?;
            } else {
                writeln!(f, " — unused is not established for this digest")?;
            }
            for (kind, n) in &d.refusals {
                writeln!(
                    f,
                    "  refused: {n} x {kind} (the record does not name the grant)"
                )?;
            }
            for g in &d.grants {
                writeln!(
                    f,
                    "  {:?}  {}  ({} calls, {} runs)",
                    g.mark, g.reference, g.calls, g.runs
                )?;
                for m in &g.menus {
                    match m {
                        MenuRow::Counted {
                            path,
                            chosen,
                            unchosen,
                        } => writeln!(
                            f,
                            "    {path}: chosen {chosen:?}, never chosen {unchosen:?}"
                        )?,
                        MenuRow::NotDerivable { path } => {
                            writeln!(f, "    {path}: not derivable from this export")?;
                        }
                    }
                }
            }
            let e = &d.egress;
            let opt = |v: Option<u64>| v.map_or_else(|| "-".to_owned(), |v| v.to_string());
            write!(
                f,
                "  egress per run: min {} median {} max {}, {} effects uncounted; ",
                opt(e.min),
                opt(e.median),
                opt(e.max),
                e.uncounted
            )?;
            match (e.ceiling, e.headroom) {
                (Some(c), Some(h)) => writeln!(f, "ceiling {c}, headroom {h}")?,
                _ => writeln!(f, "no ceiling declared")?,
            }
            if let Some(p) = &d.proposal {
                writeln!(f, "  proposal removes: {:?}", p.removed)?;
                for (r, why) in &p.kept {
                    writeln!(f, "  kept {r}: removing it fails validation: {why}")?;
                }
            }
        }
        for m in &self.unexercised_manifests {
            writeln!(f, "\nsupplied manifest {m}: no run in this export")?;
        }
        Ok(())
    }
}
