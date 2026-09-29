//! A policy verdict re-derived from an export, and a candidate bundle measured
//! against it.
//!
//! The record claims that a permit's inputs are on it: the effect gate's
//! request is `EffectStarted`'s descriptor, `mutates` and outbound label, the
//! admission and identity records, and a tenant. This reads an export, rebuilds
//! every gated request those records support through the **same builders the
//! live gates call** ([`super::requests`]), and evaluates each one
//! offline. With the bundle a run recorded, a disagreement is a finding; with a
//! candidate, the per-run difference is what the candidate would have refused.
//!
//! # What it proves, and what it does not
//!
//! It proves agreement between a bundle and a record. It does not prove the
//! record is complete or unedited — that is [`export::verify`](crate::export::verify),
//! and a check over an unverified file is a check over whatever the file says.
//!
//! A recorded run's outcomes are permits: every `EffectStarted` that passed
//! the gate, every `Released`, the admission itself. A refusal is recorded as
//! `PolicyDenied`, which names the action and resource and **not the request**
//! — the arguments, label and `mutates` the rule read are not on it — so a
//! recorded denial is reported as not evaluable rather than judged over a
//! request the gate never saw.
//!
//! # What it never does
//!
//! It opens no store, takes no lease, writes nothing and calls no network other
//! than a key ring the caller hands it. It is reachable from no replay, resume
//! or executor path, and its answer is an input to no gate: replay does not
//! re-judge history, and this is a report about history, not a way back into
//! it.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;

use serde::Serialize;
use serde_json::Value;

use crate::core::{
    ACTIONS, Delegation, Digest, EffectKey, GroupOutcome, PolicyBundleIdentity, PolicyDecision,
    PolicyEngine, RunId, StepId,
};
use crate::journal::{AgentIdentity, RecordBody, RecordKind, payload};

use super::requests::{self, Acting, GatedRequest};

/// The effect kinds a durable wait announces without passing the gate.
///
/// Nothing reserves them for waits, so a skill's own effect of either kind is
/// gated live and indistinguishable here — which is why a record of one is
/// reported as not evaluable rather than skipped.
const WAIT_KINDS: &[&str] = &["timer.sleep", "event.await"];

/// What every report states once, rather than per request.
pub const OUTSIDE_EXPORT: &str = "a refused admission leaves no journal, and the served \
                                  surfaces' gates journal neither their roles nor their callers; \
                                  none of these is in an export, and none is evaluated";

/// Where the tenant every request carries came from. No record carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantSource {
    /// The checker named it.
    Supplied,
    /// Nobody named it, so the single-tenant default was assumed.
    Default,
}

/// Why a gated request the export shows could not be rebuilt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unevaluable {
    /// Its payload is sealed and no key ring was supplied.
    Sealed,
    /// Its payload's key has been destroyed.
    Erased,
    /// A recorded refusal: `PolicyDenied` does not carry the request.
    RequestNotJournaled,
    /// A compensating effect, which never passes the gate.
    GateSkipped,
    /// A record that may or may not have passed the gate, and nothing on it
    /// says which: a member of a group that did not commit (its reversals
    /// skipped the gate and are not marked), or an effect of a durable wait's
    /// kind.
    GateIndistinguishable,
    /// A step of a run whose steps ran more than one skill. The gate presents
    /// the acting skill's declaration, and only the admitted one's is recorded.
    AgentNotJournaled,
    /// The recorded delegation chain does not rehydrate.
    ChainUnreadable,
}

/// A gated request the export shows and the check could not rebuild.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotEvaluable {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<StepId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect_key: Option<EffectKey>,
    pub action: String,
    pub resource: String,
    pub reason: Unevaluable,
}

/// One request rebuilt from the records, with where it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct Rebuilt {
    pub step: Option<StepId>,
    pub effect_key: Option<EffectKey>,
    pub request: GatedRequest,
}

/// Everything one run's records support.
#[derive(Debug, Clone, PartialEq)]
pub struct RunRequests {
    pub run: RunId,
    /// The bundle `RunAdmitted` names; `None` for an ungoverned run and for
    /// one with no admission record.
    pub recorded_bundle: Option<PolicyBundleIdentity>,
    /// Every recorded permit rebuilt, retried attempts counted once.
    pub requests: Vec<Rebuilt>,
    pub not_evaluable: Vec<NotEvaluable>,
}

/// How a run was judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// The supplied bundle is the one the run recorded, so it was evaluated.
    Recorded,
    /// The run recorded another bundle, so a disagreement would say nothing
    /// about the record. Not evaluated against the supplied bundle.
    Mismatch,
    /// No bundle governed the run: no gate ran, so there is no verdict to
    /// re-derive. Never reported as clean.
    Ungoverned,
}

/// A recorded outcome a bundle disagrees with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<StepId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect_key: Option<EffectKey>,
    pub action: String,
    pub resource: String,
    /// The bundle's own words.
    pub reason: String,
    /// The rules could not be evaluated on this request, rather than a rule
    /// refusing it.
    pub malformed: bool,
}

/// A candidate bundle against what happened.
///
/// Against the **recorded outcome**, never against the recorded bundle
/// re-evaluated: the question is what the candidate would have changed, and a
/// run whose recorded bundle is not the supplied one still happened.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Diff {
    /// Recorded permits the candidate's rules refuse.
    pub newly_denied: Vec<Finding>,
    /// Recorded permits the candidate cannot evaluate — refused at a live
    /// gate, but a defect in the rules rather than a rule firing.
    pub malformed_under_candidate: Vec<Finding>,
}

impl Diff {
    fn is_empty(&self) -> bool {
        self.newly_denied.is_empty() && self.malformed_under_candidate.is_empty()
    }
}

/// One run's part of the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunReport {
    pub run: RunId,
    pub mode: Mode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded_bundle: Option<Digest>,
    /// Requests evaluated against the supplied bundle.
    pub evaluated: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<Diff>,
    pub not_evaluable: Vec<NotEvaluable>,
}

/// The tenant the requests were rebuilt under, and whether anyone said so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tenant {
    pub value: String,
    pub source: TenantSource,
}

/// What the check found. Output, not a durable format: it carries no version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub bundle: Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate: Option<Digest>,
    pub tenant: Tenant,
    pub runs: Vec<RunReport>,
    /// Runs the export's own trailer says it could not read.
    pub unreadable: Vec<RunId>,
    pub outside_export: &'static str,
}

/// The answer, as a scheduler reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// At least one request was evaluated and nothing disagreed.
    Clean,
    /// A finding, a mismatched run, or a non-empty candidate diff.
    Findings,
    /// Nothing was evaluated, so nothing was established.
    Partial,
}

impl Report {
    /// Requests evaluated against the supplied bundle, over every run.
    #[must_use]
    pub fn evaluated(&self) -> usize {
        self.runs.iter().map(|r| r.evaluated).sum()
    }

    /// Findings first: a disagreement is an answer whatever else was unread.
    /// A check that evaluated nothing is never clean — it found nothing
    /// because it read nothing.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        let disagrees = self.runs.iter().any(|r| {
            r.mode == Mode::Mismatch
                || !r.findings.is_empty()
                || r.diff.as_ref().is_some_and(|d| !d.is_empty())
        });
        if disagrees {
            return Verdict::Findings;
        }
        if self.evaluated() == 0 {
            return Verdict::Partial;
        }
        Verdict::Clean
    }
}

/// Why the check could not answer at all.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// The input could not be read.
    #[error("reading the export failed: {0}")]
    Io(#[from] std::io::Error),
    /// The input is not an export this build reads.
    #[error("{0}")]
    NotAnExport(String),
    /// A key ring was supplied and failed for a reason other than erasure.
    #[error("opening a sealed payload failed: {0}")]
    Keys(String),
}

/// The inputs a request needs that no record carries, and the ring that opens
/// the ones sealed.
#[derive(Debug, Clone, Copy)]
pub struct Check<'a> {
    tenant: &'a str,
    source: TenantSource,
    #[cfg(feature = "keyring")]
    keys: Option<&'a dyn crate::keyring::KeyRing>,
}

impl<'a> Check<'a> {
    /// A check rebuilding every request under `tenant`.
    #[must_use]
    pub const fn new(tenant: &'a str, source: TenantSource) -> Self {
        Self {
            tenant,
            source,
            #[cfg(feature = "keyring")]
            keys: None,
        }
    }

    /// Open sealed arguments and inputs with `keys`. Without a ring they are
    /// [`Unevaluable::Sealed`]; with one, a destroyed key is
    /// [`Unevaluable::Erased`].
    #[cfg(feature = "keyring")]
    #[must_use]
    pub const fn with_keys(mut self, keys: &'a dyn crate::keyring::KeyRing) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Evaluate every rebuildable request against `bundle`, and against
    /// `candidate` when one is given.
    ///
    /// # Errors
    ///
    /// When the input is unreadable or not an export, or a supplied ring
    /// fails for a reason other than erasure.
    pub async fn run<R: BufRead>(
        &self,
        input: R,
        bundle: &dyn PolicyEngine,
        candidate: Option<&dyn PolicyEngine>,
    ) -> Result<Report, CheckError> {
        let (rebuilt, unreadable) = self.read(input).await?;
        let digest = bundle.digest();
        let runs = rebuilt
            .into_iter()
            .map(|run| judge(run, bundle, digest, candidate))
            .collect();
        Ok(Report {
            bundle: digest,
            candidate: candidate.map(PolicyEngine::digest),
            tenant: Tenant {
                value: self.tenant.to_owned(),
                source: self.source,
            },
            runs,
            unreadable,
            outside_export: OUTSIDE_EXPORT,
        })
    }

    /// Every request the export's records support, evaluated by nobody.
    ///
    /// # Errors
    ///
    /// As [`run`](Self::run).
    pub async fn rebuild<R: BufRead>(&self, input: R) -> Result<Vec<RunRequests>, CheckError> {
        Ok(self.read(input).await?.0)
    }

    async fn read<R: BufRead>(
        &self,
        input: R,
    ) -> Result<(Vec<RunRequests>, Vec<RunId>), CheckError> {
        let (runs, unreadable) = read_export(input)?;
        let mut out = Vec::with_capacity(runs.len());
        for (run, records) in runs {
            out.push(self.rebuild_run(run, records).await?);
        }
        Ok((out, unreadable))
    }

    /// Open `kind`'s sealed payloads if a ring was supplied, reporting what
    /// could not be opened.
    #[cfg_attr(
        not(feature = "keyring"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn open(
        &self,
        body: &RecordBody,
        kind: &mut RecordKind,
    ) -> Result<Option<Unevaluable>, CheckError> {
        #[cfg(feature = "keyring")]
        if let Some(keys) = self.keys {
            let opened =
                crate::keyring::open_payloads(keys, self.tenant, body.run, body.effect_key, kind)
                    .await
                    .map_err(|e| CheckError::Keys(e.to_string()))?;
            if opened.erased > 0 {
                return Ok(Some(Unevaluable::Erased));
            }
        }
        let _ = body;
        // Whatever is still sealed was not opened, for whichever reason: a
        // request rebuilt around a sealed envelope is a request nobody asked.
        let sealed = payload::payloads(kind)
            .into_iter()
            .any(|field| match field {
                payload::SealedField::Value(v) => payload::is_sealed(v),
                payload::SealedField::Text(t) => payload::is_sealed_text(t),
            });
        Ok(sealed.then_some(Unevaluable::Sealed))
    }

    #[allow(clippy::too_many_lines)]
    async fn rebuild_run(
        &self,
        run: RunId,
        records: Vec<RecordBody>,
    ) -> Result<RunRequests, CheckError> {
        let mut out = RunRequests {
            run,
            recorded_bundle: None,
            requests: Vec::new(),
            not_evaluable: Vec::new(),
        };

        let mut admitted: Option<(RecordBody, String, Option<AgentIdentity>)> = None;
        let mut chain_links = None;
        let mut skills = BTreeSet::new();
        for body in &records {
            match &body.kind {
                RecordKind::RunAdmitted {
                    capability,
                    governed_by,
                    policy_bundle,
                    ..
                } if admitted.is_none() => {
                    out.recorded_bundle = policy_bundle.as_deref().cloned();
                    admitted = Some((
                        body.clone(),
                        capability.clone(),
                        governed_by.as_deref().cloned(),
                    ));
                }
                RecordKind::IdentityBound { chain } if chain_links.is_none() => {
                    chain_links = Some(chain.clone());
                }
                RecordKind::StepStarted { skill } if body.phase.is_forward() => {
                    skills.insert(skill.clone());
                }
                _ => {}
            }
        }
        // No admission record: no gate asked anything this reader can name.
        let Some((admission, capability, governed_by)) = admitted else {
            return Ok(out);
        };
        let Ok(chain) = chain_links.map(Delegation::rehydrate).transpose() else {
            out.not_evaluable.push(NotEvaluable {
                step: None,
                effect_key: None,
                action: crate::core::ACTION_ADMIT.to_owned(),
                resource: capability,
                reason: Unevaluable::ChainUnreadable,
            });
            return Ok(out);
        };
        let acting = Acting {
            tenant: self.tenant,
            capability: &capability,
            agent: governed_by.as_ref(),
            chain: chain.as_ref(),
        };
        // A step presents its own skill's declaration. Only the admitted
        // skill's is recorded, and it is the only one when every step ran one
        // skill.
        let one_skill = skills.len() <= 1;
        let mut seen = BTreeSet::new();

        // Admission.
        let mut kind = admission.kind.clone();
        match self.open(&admission, &mut kind).await? {
            Some(reason) => out.not_evaluable.push(NotEvaluable {
                step: None,
                effect_key: None,
                action: crate::core::ACTION_ADMIT.to_owned(),
                resource: capability.clone(),
                reason,
            }),
            None => {
                if let RecordKind::RunAdmitted { input, .. } = &kind {
                    push(
                        &mut out,
                        &mut seen,
                        None,
                        None,
                        requests::admission(&acting, input),
                    );
                }
            }
        }

        // Effects inside an open group wait for the group's settlement: only a
        // committed group's members all passed the gate.
        let mut groups: BTreeMap<StepId, Vec<RecordBody>> = BTreeMap::new();
        let mut settled: Vec<RecordBody> = Vec::new();
        for body in records {
            let step = body.step;
            match &body.kind {
                RecordKind::GroupOpened { .. } if body.phase.is_forward() => {
                    if let Some(step) = step {
                        groups.insert(step, Vec::new());
                    }
                }
                RecordKind::GroupSettled { outcome, .. } if body.phase.is_forward() => {
                    let members = step.and_then(|s| groups.remove(&s)).unwrap_or_default();
                    if *outcome == GroupOutcome::Committed {
                        settled.extend(members);
                    } else {
                        for member in members {
                            out.not_evaluable.push(unevaluable_effect(
                                &member,
                                Unevaluable::GateIndistinguishable,
                            ));
                        }
                    }
                }
                RecordKind::EffectStarted { descriptor, .. } => {
                    if !body.phase.is_forward() {
                        out.not_evaluable
                            .push(unevaluable_effect(&body, Unevaluable::GateSkipped));
                    } else if WAIT_KINDS.contains(&descriptor.kind.as_str()) {
                        out.not_evaluable.push(unevaluable_effect(
                            &body,
                            Unevaluable::GateIndistinguishable,
                        ));
                    } else if let Some(members) = step.and_then(|s| groups.get_mut(&s)) {
                        members.push(body);
                    } else {
                        settled.push(body);
                    }
                }
                RecordKind::Released { .. } => settled.push(body),
                // Manifest and sink refusals share the record and are no
                // bundle's decision; only the actions an engine is asked are
                // verdicts.
                RecordKind::PolicyDenied {
                    action, resource, ..
                } if ACTIONS.contains(&action.as_str()) => {
                    out.not_evaluable.push(NotEvaluable {
                        step,
                        effect_key: body.effect_key,
                        action: action.clone(),
                        resource: resource.clone(),
                        reason: Unevaluable::RequestNotJournaled,
                    });
                }
                _ => {}
            }
        }
        // A group never settled may have been reversed by a pass this export
        // does not hold.
        for member in groups.into_values().flatten() {
            out.not_evaluable.push(unevaluable_effect(
                &member,
                Unevaluable::GateIndistinguishable,
            ));
        }

        for body in settled {
            let Some(step) = body.step else { continue };
            if !one_skill {
                out.not_evaluable
                    .push(unevaluable_effect(&body, Unevaluable::AgentNotJournaled));
                continue;
            }
            let mut kind = body.kind.clone();
            if let Some(reason) = self.open(&body, &mut kind).await? {
                out.not_evaluable.push(unevaluable_effect(&body, reason));
                continue;
            }
            let request = match &kind {
                RecordKind::EffectStarted {
                    descriptor,
                    mutates,
                    outbound_label,
                    ..
                } => requests::effect(
                    &acting,
                    run,
                    step,
                    &descriptor.kind,
                    &descriptor.args,
                    *mutates,
                    outbound_label.as_ref(),
                ),
                RecordKind::Released { release, label, .. } => {
                    requests::release(&acting, run, step, release, label)
                }
                _ => continue,
            };
            push(&mut out, &mut seen, Some(step), body.effect_key, request);
        }
        Ok(out)
    }
}

/// Keep a rebuilt request unless an identical one is already held: a retried
/// attempt repeats the gate with the same context, and is one request.
fn push(
    out: &mut RunRequests,
    seen: &mut BTreeSet<Vec<u8>>,
    step: Option<StepId>,
    effect_key: Option<EffectKey>,
    request: GatedRequest,
) {
    let identity = crate::core::canon::value_bytes(&serde_json::json!([
        request.principal,
        request.action,
        request.resource,
        request.context,
    ]));
    if seen.insert(identity) {
        out.requests.push(Rebuilt {
            step,
            effect_key,
            request,
        });
    }
}

/// A recorded effect or release that could not be rebuilt, named by what it
/// was asked about.
fn unevaluable_effect(body: &RecordBody, reason: Unevaluable) -> NotEvaluable {
    let (action, resource) = match &body.kind {
        RecordKind::Released { .. } => (crate::core::ACTION_RELEASE, requests::RELEASE_RESOURCE),
        RecordKind::EffectStarted { descriptor, .. } => {
            (crate::core::ACTION_PERFORM, descriptor.kind.as_str())
        }
        other => (crate::core::ACTION_PERFORM, other.kind_str()),
    };
    NotEvaluable {
        step: body.step,
        effect_key: body.effect_key,
        action: action.to_owned(),
        resource: resource.to_owned(),
        reason,
    }
}

/// One run against the supplied bundle, and against a candidate.
fn judge(
    run: RunRequests,
    bundle: &dyn PolicyEngine,
    digest: Digest,
    candidate: Option<&dyn PolicyEngine>,
) -> RunReport {
    let recorded = run
        .recorded_bundle
        .as_ref()
        .map(PolicyBundleIdentity::digest);
    let mode = match recorded {
        None => Mode::Ungoverned,
        Some(recorded) if recorded == digest => Mode::Recorded,
        Some(_) => Mode::Mismatch,
    };
    let mut report = RunReport {
        run: run.run,
        mode,
        recorded_bundle: recorded,
        evaluated: 0,
        findings: Vec::new(),
        diff: None,
        not_evaluable: Vec::new(),
    };
    // An ungoverned run passed no gate: there is nothing to re-derive and
    // nothing a candidate would be changing.
    if mode == Mode::Ungoverned {
        return report;
    }
    report.not_evaluable = run.not_evaluable;
    if mode == Mode::Recorded {
        for rebuilt in &run.requests {
            report.evaluated += 1;
            if let Some(finding) =
                disagreement(rebuilt, &bundle.authorize(&rebuilt.request.as_request()))
            {
                report.findings.push(finding);
            }
        }
    }
    if let Some(candidate) = candidate {
        let mut diff = Diff::default();
        for rebuilt in &run.requests {
            let decision = candidate.authorize(&rebuilt.request.as_request());
            if let Some(finding) = disagreement(rebuilt, &decision) {
                if finding.malformed {
                    diff.malformed_under_candidate.push(finding);
                } else {
                    diff.newly_denied.push(finding);
                }
            }
        }
        report.diff = Some(diff);
    }
    report
}

/// A recorded permit the decision does not permit.
fn disagreement(rebuilt: &Rebuilt, decision: &PolicyDecision) -> Option<Finding> {
    let reason = decision.reason()?;
    Some(Finding {
        step: rebuilt.step,
        effect_key: rebuilt.effect_key,
        action: rebuilt.request.action.to_owned(),
        resource: rebuilt.request.resource.clone(),
        reason: reason.to_owned(),
        malformed: decision.is_malformed(),
    })
}

/// The export's runs, in file order, each with its records' bodies.
///
/// Parsed from each record's `raw` — the bytes the chain hashed — never from
/// the display copy beside them. Integrity is not checked here; that is
/// `export::verify`'s.
#[allow(clippy::type_complexity)]
fn read_export<R: BufRead>(
    input: R,
) -> Result<(Vec<(RunId, Vec<RecordBody>)>, Vec<RunId>), CheckError> {
    let mut runs: Vec<(RunId, Vec<RecordBody>)> = Vec::new();
    let mut unreadable = Vec::new();
    let mut header = false;
    for (index, line) in input.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(&line)
            .map_err(|e| CheckError::NotAnExport(format!("line {} is not JSON: {e}", index + 1)))?;
        match value.get("kind").and_then(Value::as_str) {
            Some("agentplane.export") => {
                let version = value.get("version").and_then(Value::as_u64);
                if version != Some(u64::from(crate::export::FORMAT_VERSION)) {
                    return Err(CheckError::NotAnExport(format!(
                        "the export is at format version {version:?}, and this build reads {}",
                        crate::export::FORMAT_VERSION
                    )));
                }
                header = true;
            }
            _ if !header => {
                return Err(CheckError::NotAnExport(
                    "the first line is not an agentplane export header".into(),
                ));
            }
            Some("agentplane.export.run") => {
                let run = value
                    .get("run")
                    .cloned()
                    .and_then(|r| serde_json::from_value::<RunId>(r).ok())
                    .ok_or_else(|| {
                        CheckError::NotAnExport(format!("line {} names no run", index + 1))
                    })?;
                runs.push((run, Vec::new()));
            }
            Some("agentplane.export.end") => {
                if let Some(list) = value.get("unreadable").and_then(Value::as_array) {
                    unreadable.extend(list.iter().filter_map(|u| {
                        u.get("run")
                            .cloned()
                            .and_then(|r| serde_json::from_value::<RunId>(r).ok())
                    }));
                }
            }
            Some(_) => {}
            None => {
                let raw = value.get("raw").and_then(Value::as_str).ok_or_else(|| {
                    CheckError::NotAnExport(format!("line {} carries no wire bytes", index + 1))
                })?;
                let body: RecordBody = serde_json::from_str(raw).map_err(|e| {
                    CheckError::NotAnExport(format!(
                        "line {} holds a record this build does not read: {e}",
                        index + 1
                    ))
                })?;
                let Some((run, records)) = runs.last_mut() else {
                    return Err(CheckError::NotAnExport(format!(
                        "line {} is a record before any run block",
                        index + 1
                    )));
                };
                if body.run != *run {
                    return Err(CheckError::NotAnExport(format!(
                        "line {} belongs to run {}, filed under {run}",
                        index + 1,
                        body.run
                    )));
                }
                records.push(body);
            }
        }
    }
    if !header {
        return Err(CheckError::NotAnExport("the input is empty".into()));
    }
    Ok((runs, unreadable))
}
