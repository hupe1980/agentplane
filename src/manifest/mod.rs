//! The declaration an agent is built from.
//!
//! Everything security-relevant about an agent — which tools it may call, what
//! it may spend, how sensitive a value it may send outward, and how far it may
//! delegate — lives here rather than in the calling code, for one
//! reason: **a builder call is invisible in review, and a file is not.** A
//! grant added by editing three lines of Rust is a grant nobody notices; the
//! same grant added to a manifest is a diff with a reviewer on it.
//!
//! Five properties make that worth anything, and each is a refusal:
//!
//! * **Unknown fields are rejected, never ignored.** `max_tokns: 100` is a typo
//!   that, in a permissive parser, silently means *no token ceiling at all*.
//!   That is the single most dangerous failure a config format can have, so
//!   every struct here is `deny_unknown_fields`.
//! * **The document says what it is.** A manifest for a different `apiVersion`
//!   or `kind` is refused rather than best-effort parsed, because a format that
//!   guesses is a format whose meaning changes under you.
//! * **The prompt is part of the declaration.** [`Identity`] puts the agent's
//!   own instructions inside the digested document, so a reworded prompt is a
//!   version bump rather than an untracked deploy. A prompt composed in Rust has
//!   no version at all: it changes, the journal records the run, and nothing
//!   connects the two.
//! * **A model id is a behaviour change, so it is versioned like one.**
//!   [`Models`] puts the provider and model in the digest. A swap made in a
//!   deploy has no version, no diff, and nothing connecting it to the runs whose
//!   outputs changed.
//! * **A manifest has a digest.** Content-addressed over canonical bytes, so
//!   "which declaration was this run governed by" has an answer that survives
//!   the file being edited. That digest is what a [`Registry`] pins, and what a
//!   journal can record.
//!
//! What this module does *not* do is execute anything: it parses, refuses, and
//! hands back a value. Enforcement lives where dispatch does —
//! `RuntimeBuilder::agent` binds the document to an identity and applies its
//! budget, and `StepCtx::gate` refuses an effect naming a model or tool this
//! document never listed.
//!
//! Every field is either enforced by the runtime or is descriptive identity.
//! Architectural injection-pattern labels are intentionally absent: arbitrary
//! skill code cannot be proven to follow one, and a security document must not
//! appear to enforce a control it cannot bind.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::{Budget, Digest, Sensitivity, canon};

mod binding;
pub use binding::MemorySubject;

mod error;
pub use error::ManifestError;

/// The registry seam, and the rules every backend must apply identically.
///
/// Public because a durable or remote registry is somebody else's to write, and
/// the immutability and publisher rules are the whole security argument for
/// having a registry at all — an implementation that re-derived them would be
/// an implementation that could get them subtly wrong.
pub mod registry;
pub use registry::{MemoryRegistry, Registry, RegistryError};

mod triage;
pub use triage::{Condition, Predicate, TriagePriority, TriageRule};

/// The only API group this crate understands.
pub const API_VERSION: &str = "agentplane.hupe1980.github.io/v1alpha1";

/// The only kind.
pub const KIND: &str = "Agent";

/// A parsed, validated agent declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Which schema this document claims to be.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// What kind of object. `Agent`.
    pub kind: String,
    pub metadata: Metadata,
    pub spec: Spec,
}

/// Who this agent is, for the record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
    /// Free-form, and compared only for equality. The crate does not parse
    /// semver: it has no version-ordering decision to make, and pretending to
    /// understand a scheme it never checks would invite one.
    pub version: String,
    /// Facts about this agent that the runtime never reads.
    ///
    /// # Why an opaque map is not a hole in `deny_unknown_fields`
    ///
    /// Everywhere else a field is enforced or refused, which is what makes the
    /// manifest a review artifact. *Business owner*, *risk class* and *ticket*
    /// are facts no `spec` field should enforce, and a document that cannot
    /// hold them gets a second registry kept beside it that drifts. One map
    /// holds them without weakening the rule, because the map is **intent by
    /// construction**:
    ///
    /// * **The runtime never reads it.** No key here reaches a gate, a grant,
    ///   a prompt or a decision. There is no accessor that resolves a key to
    ///   behaviour, and adding one would be the change this doc-comment exists
    ///   to argue against. So no value here can become a security decision,
    ///   which is what an advisory *control* would be.
    /// * **The digest covers it.** Changing an owner changes
    ///   [`Manifest::digest`], so it is a version bump with a reviewer on it —
    ///   which is exactly what a governance process wants from an ownership
    ///   record, and what a wiki page cannot give it.
    /// * **Keys are namespaced, in Kubernetes' grammar.** Every key is
    ///   `prefix/name` — a DNS-subdomain prefix and a name of at most 63
    ///   characters, with 256 KiB of keys and values in all — so an entry
    ///   carries into a Kubernetes object unchanged. The prefix is required
    ///   here where Kubernetes makes it optional: an unqualified key is
    ///   exactly the name a future first-class field would want. The prefix
    ///   under [`API_VERSION`]'s own group is reserved, as `kubernetes.io/` is
    ///   there, so a first-class field is never shadowed by an annotation
    ///   somebody wrote first.
    ///
    /// Who may read them is the line Kubernetes draws between its API server
    /// and its controllers. Controllers read annotations as configuration all
    /// the time — an ingress controller's rewrite rules, cert-manager's
    /// issuer — while the API server never acts on one. The runtime is the
    /// API server here; the embedder's wiring is the controller, and this map
    /// is public so that a deploy pipeline or a cluster controller can read
    /// it and act. What the runtime refuses is only to be that controller:
    /// `kubernetes.io/ingress.class` was read as configuration with no schema
    /// and no version until it had to be promoted to a real field, and
    /// anything an agent's behaviour depends on goes in `spec` for the same
    /// reason.
    ///
    /// ```yaml
    /// metadata:
    ///   name: pattern-compliance-auditor
    ///   version: "2.0.0"
    ///   annotations:
    ///     example.com/business-owner: "Compliance, F. Meier"
    ///     example.com/risk-class: "C"
    /// ```
    ///
    /// A `BTreeMap`, so the serialization a digest is taken over does not
    /// depend on the order somebody typed the keys in.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// The annotation prefix this format keeps for itself.
///
/// Everything under the API group is reserved, so a deployment cannot write
/// `agentplane.hupe1980.github.io/budgets` today and have it mean something
/// else tomorrow. Reserving it is the price of promising that annotations
/// never collide with a field.
pub const RESERVED_ANNOTATION_PREFIX: &str = "agentplane.hupe1980.github.io/";

/// The most one manifest may carry in annotation keys and values, combined.
///
/// Kubernetes' limit, taken as is. Annotations enter the digest, the registry
/// row and every copy of the reviewed file; they are facts about the agent,
/// not a place to keep its documents.
pub const MAX_ANNOTATIONS_BYTES: usize = 256 * 1024;

/// A DNS subdomain as Kubernetes validates one: lowercase labels of letters,
/// digits and `-`, each beginning and ending alphanumeric, joined by dots, at
/// most 253 characters in all.
fn is_dns_subdomain(prefix: &str) -> bool {
    prefix.len() <= 253
        && prefix.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// An annotation name segment as Kubernetes validates one.
fn is_annotation_name(name: &str) -> bool {
    let alnum = |b: u8| b.is_ascii_alphanumeric();
    name.len() <= 63
        && name.as_bytes().first().is_some_and(|&b| alnum(b))
        && name.as_bytes().last().is_some_and(|&b| alnum(b))
        && name
            .bytes()
            .all(|b| alnum(b) || b == b'-' || b == b'_' || b == b'.')
}

/// The declaration proper.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    /// Who the agent is told it is.
    ///
    /// Optional, because an embedder may compose its prompt in code. Supplying
    /// it here is what makes the prompt part of the manifest's digest — see
    /// [`Identity`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    #[serde(default)]
    pub security: Security,
    #[serde(default)]
    pub capabilities: Capabilities,
    /// Absent means *unbounded*, and that is a decision the manifest has to
    /// state out loud — see [`Manifest::validate`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budgets: Option<Budgets>,
    /// Tools this agent may call. An empty list grants nothing.
    #[serde(default)]
    pub tools: Vec<ToolGrant>,
    /// External context this agent may retrieve.
    ///
    /// Separate from tools because reads of prompts/resources do not grant an
    /// action, but they still cross a trust and data-egress boundary and must
    /// not be invisible in a manifested agent's review artifact.
    #[serde(default, skip_serializing_if = "ContextGrants::is_empty")]
    pub context: ContextGrants,
    /// Whether a human decides before this agent's answer is returned.
    ///
    /// Only meaningful with [`execution`](Self::execution): a hand-written skill
    /// chooses its own moment to ask, and a declaration this crate could not
    /// enforce would be exactly the decoration [`Manifest::validate`] refuses.
    /// So `oversight` without `execution` is rejected rather than ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oversight: Option<Oversight>,
    /// How this agent runs — and whether it needs any code at all.
    ///
    /// Declaring it makes the agent **fully declarative**: the runtime supplies
    /// the behaviour and the embedder writes no skill. Omitting it means the
    /// behaviour is a registered [`Skill`](crate::core::Skill), and this manifest
    /// governs its boundary rather than its conduct.
    ///
    /// The difference is what the digest covers. A declarative agent is
    /// content-addressed *in its entirety*; a coded one is content-addressed
    /// only as far as its declaration reaches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<Execution>,
    /// What this agent is in a multi-agent arrangement.
    ///
    /// Absent means [`Topology::default`] — a lone specialist, which is the
    /// only shape with **no** inter-agent failure surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology: Option<Topology>,
    /// Which models this agent runs on.
    ///
    /// Absent means *wired in code*. `models: {}` means **no inference at all**,
    /// declared on purpose — a rules-only agent is a legitimate design, and
    /// saying so out loud is what distinguishes it from one whose model wiring
    /// somebody forgot.
    ///
    /// Unlike [`budgets`](Self::budgets), absence is not refused: an unstated
    /// budget is unbounded spend, whereas an unstated model is simply a wiring
    /// decision the embedder makes. The asymmetry is deliberate — refuse the
    /// silence that costs money, not the silence that costs nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models: Option<Models>,
    /// The shape of what this agent returns.
    ///
    /// Optional, because not every agent has a machine-readable result. See
    /// [`Output`] for why declaring it here rather than in code is the point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Output>,
    /// What this agent reads from and writes to durable memory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<Memory>,
}

/// A declarative agent's two halves of durable memory: what it reads, and what
/// it writes.
///
/// # Why there is no semantic search here
///
/// [`StepCtx::semantic_recall`] exists and is deliberately not declarable.
/// Similarity is computed over item content, so anything able to write a memory
/// is a ranking signal: an attacker who cannot taint a value can still decide
/// *which* clean values a model is shown, and no label anywhere in the run shows
/// it. A deterministic recall's order is a fixed rule no stored item can move,
/// which is what makes it safe to spell as one reviewed line — accepting the
/// other channel belongs where somebody visibly decides to.
///
/// [`StepCtx::semantic_recall`]: crate::runtime::StepCtx::semantic_recall
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    /// Read memories into the prompt, before the model is called.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall: Option<MemoryRecall>,
    /// Form bounded durable facts from each answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formation: Option<MemoryFormation>,
}

impl Memory {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.recall.is_none() && self.formation.is_none()
    }
}

/// What a declarative agent is given to remember, before it answers.
///
/// The recalled items are folded into the prompt under `/memory`, beside the
/// trusted `/system` instruction and the caller's `/input`, and they arrive
/// carrying **their own labels** — a memory formed from a model's answer is
/// untrusted here exactly as it was when it was written. So a recall does not
/// widen what the agent may then do: the same egress ceiling governs the model
/// call, and the same protected-field rules govern every tool the answer
/// reaches for.
///
/// One consequence: a memory above
/// [`security.max_sensitivity_egress`](Security::max_sensitivity_egress)
/// **fails the run** at the model call rather than being filtered out — a
/// silent drop would make the answer depend on a ceiling nothing in the
/// transcript mentions. Partition with `purpose`, or raise the ceiling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryRecall {
    /// Which pile to read, with the same three bindings formation writes
    /// under. See [`MemorySubject`].
    pub subject: MemorySubject,
    /// Restrict to memories kept for one purpose.
    ///
    /// Absent reads every purpose under the subject, which is the wider
    /// answer and rarely the wanted one: `purpose` is what keeps a memory
    /// written for support triage out of a payments decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// How many, at most.
    ///
    /// A ceiling on prompt size and on blast radius both. Selection is most
    /// trusted first, then newest — so a subject with more memories than this
    /// drops the *least* trusted and oldest, never a trusted memory in favour
    /// of an attacker's fresh one.
    #[serde(default = "default_recall_limit")]
    pub limit: usize,
    /// Slide each selected memory's access-retention window forward.
    ///
    /// Off by default. On, a recall is no longer a pure read — it writes a
    /// second journaled effect — which is the trade for memories that should
    /// live as long as they keep being useful.
    #[serde(default)]
    pub refresh_access: bool,
}

const fn default_recall_limit() -> usize {
    5
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextGrants {
    #[serde(default)]
    pub prompts: Vec<ContextPrompt>,
    #[serde(default)]
    pub resources: Vec<ContextResource>,
    /// Servers this agent may answer `tasks/update` input requests on.
    ///
    /// An elicitation is a server asking this plane for data — the direction
    /// an operator most needs to have said yes to — so the authority to answer
    /// belongs in the reviewed artifact beside prompts and resources, not in
    /// unreviewable wiring code.
    #[serde(default)]
    pub task_input: Vec<ContextTaskInput>,
}

impl ContextGrants {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prompts.is_empty() && self.resources.is_empty() && self.task_input.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextPrompt {
    pub server: String,
    pub name: String,
    #[serde(default = "public_sensitivity")]
    pub max_input_sensitivity: Sensitivity,
    #[serde(default = "public_sensitivity")]
    pub output_sensitivity: Sensitivity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextResource {
    pub server: String,
    pub uri: String,
    #[serde(default = "public_sensitivity")]
    pub output_sensitivity: Sensitivity,
}

/// One server this agent may send task input responses to.
///
/// Per server rather than per task: a task id is minted by the server at
/// runtime, and an operator cannot review a name that does not exist yet.
/// Only an input ceiling — `tasks/update` returns nothing to label.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextTaskInput {
    pub server: String,
    #[serde(default = "public_sensitivity")]
    pub max_input_sensitivity: Sensitivity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryFormation {
    /// Where the formed memories are filed.
    ///
    /// A literal names one fixed pile. A **binding** —
    /// `$correlation/<namespace>`, `$case`, `$input/<pointer>` — resolves per
    /// run, which is what lets one declaration serve every customer without
    /// pooling their facts under one key. See [`MemorySubject`] for why the
    /// sources are those three and why an unrecognised `$` value is refused
    /// rather than taken as a constant.
    pub subject: MemorySubject,
    pub purpose: String,
    pub instruction: String,
    #[serde(default = "default_formation_items")]
    pub max_items: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_retention_seconds: Option<u64>,
    #[serde(default = "public_sensitivity")]
    pub max_sensitivity: crate::core::Sensitivity,
}

const fn default_formation_items() -> usize {
    3
}

const fn public_sensitivity() -> crate::core::Sensitivity {
    crate::core::Sensitivity::Public
}

/// The words an agent is given about itself.
///
/// This is the field that makes "which exact prompt produced this decision?"
/// answerable six months later. A prompt composed in Rust is a prompt with no
/// version: it changes in a deploy, the journal records the run, and nothing
/// connects the two. Declared here it is covered by [`Manifest::digest`], so a
/// reworded instruction **is** a new manifest version, visible as a diff and
/// pinnable by a consumer.
///
/// agentplane does not own the words. It owns their hash, and the one rule that
/// makes the hash mean anything: [`Identity::system_prompt`] is pure and its
/// layout is pinned by a test, because a template that changed under you would
/// alter every agent's prompt without altering a single manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// What the agent is for, in one line.
    pub role: String,
    /// How it must behave. Kept separate from [`role`](Self::role) because the
    /// two are reviewed by different people and change on different schedules.
    ///
    /// There is deliberately no third field. A `workload_id` ("the SPIFFE ID
    /// this agent runs as") would be an identity claim in a reviewed file that
    /// the runtime never checks — a reviewer would take it as binding while
    /// the plane ran the agent as whatever identity it actually held.
    /// Workload identity is configured on the plane and recorded in the
    /// journal (`IdentityBound`), where it is evidence rather than
    /// aspiration. The same rule keeps out `capabilities.requires` and
    /// `security.pattern`: a control the runtime does not check is what a
    /// reviewable file exists to eliminate.
    #[serde(default)]
    pub constraints: String,
}

impl Identity {
    /// The system prompt these words render to.
    ///
    /// Deliberately the dullest possible template: the role, a blank line, the
    /// constraints. Anything cleverer would be agentplane putting words in an
    /// agent's mouth that no reviewer of the manifest ever saw.
    ///
    /// **The layout is a compatibility surface.** Changing it changes the
    /// prompt of every agent that uses this, without changing any manifest or
    /// any digest — the one edit in this crate that could silently alter model
    /// behaviour everywhere. `a_rendered_prompt_has_a_pinned_layout` exists to
    /// make that edit a test failure.
    #[must_use]
    pub fn system_prompt(&self) -> String {
        if self.constraints.trim().is_empty() {
            self.role.trim().to_owned()
        } else {
            format!("{}\n\n{}", self.role.trim(), self.constraints.trim())
        }
    }
}

/// Human oversight, declared rather than remembered.
///
/// The Article 14 half of the manifest, and the reason it can be declared at all
/// is that the machinery already exists: durable worklists, four-eyes, and
/// declared expiry behaviour. A field naming an oversight this runtime could not
/// perform would fail the binding rule.
///
/// **[`approval`](Self::approval) carries no condition, and that is
/// deliberate.** "Require approval when severity is high" changes what the
/// agent *does*, and a predicate that changes behaviour is one step from an
/// `if` — the point where a config format stops being config. An agent whose
/// conduct depends on what it found is a skill, written in a language built for
/// decisions.
///
/// [`triage`](Self::triage) does carry one, and the distinction is the whole
/// justification: a triage rule changes nothing about the run. The answer is
/// produced, validated, returned and remembered identically whether a rule
/// matched or not; the only effect is a row in a worklist. That is *reporting*,
/// and reporting is the one place a declaration can hold a predicate without
/// becoming control flow. See [`TriageRule`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oversight {
    /// What a human decides **before** the run continues.
    pub approval: Approval,
    /// Who may decide. Empty means anyone — a choice worth making on purpose
    /// rather than by omission.
    #[serde(default)]
    pub approvers: Vec<String>,
    /// The obligation that bounds the wait.
    pub deadline: OversightDeadline,
    /// What happens when the window closes.
    #[serde(default)]
    pub on_expiry: Expiry,
    /// Who is added to the audience when an unanswered task escalates.
    ///
    /// Required by `on_expiry: escalate` and refused beside anything else.
    /// Escalation's one enforceable meaning is *these people can now see it*:
    /// the runtime widens the task's audience to this list, clears the stale
    /// reservation, and keeps waiting. A declaration that escalates to nobody
    /// promises a wider audience the runtime cannot produce, and a list here
    /// under a policy that never escalates is a declaration nothing reads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalate_to: Vec<String>,
    /// Explicit consent to act with no human when the window closes.
    ///
    /// Required for [`Expiry::Proceed`] and refused otherwise, so that acting
    /// unattended is a greppable decision somebody made rather than an enum
    /// variant they picked off a list.
    #[serde(default)]
    pub allow_unattended: bool,
    /// Tasks opened **beside** a completed answer, not in front of it.
    ///
    /// Each rule is a predicate over [`Output::schema`] and an audience. The run
    /// finishes and returns; a matching rule adds a worklist row. Requires
    /// `spec.output` — a predicate over a shape nothing declares is a rule
    /// nobody can check — and every condition is typed against that schema at
    /// parse time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triage: Vec<TriageRule>,
}

/// The obligation that bounds an oversight wait.
///
/// # Why this is not just a name
///
/// It was, and the feature did not work. A declarative agent writes no code, so
/// naming an obligation it cannot register left the run failing with *"wait
/// references deadline 'review', which is not registered on this case"* — the
/// one configuration the whole declarative tier exists for. The row claiming
/// oversight was built had only ever been checked by parse tests.
///
/// So the declaration carries what registering needs, and the agent registers
/// it. `kind` and `params` are handed to the deployment's `Calendar` unchanged,
/// so *five working days* means whatever that domain says it means and this
/// crate never guesses — which is the same reason the name alone was never
/// enough.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OversightDeadline {
    /// What the obligation is called on the case.
    pub name: String,
    /// The resolution rule, e.g. `hours`, `days`, `working-days`.
    ///
    /// Interpreted by the deployment's `Calendar`. A kind it does not know is a
    /// refusal at resolution time, not a silent default.
    pub kind: String,
    /// Parameters for that rule, e.g. `{ n: 2 }`.
    #[serde(default)]
    pub params: serde_json::Value,
}

impl OversightDeadline {
    /// The runtime shape, for registering the obligation.
    #[must_use]
    pub fn spec(&self) -> crate::core::DeadlineSpec {
        crate::core::DeadlineSpec::new(
            self.kind.clone(),
            if self.params.is_null() {
                serde_json::json!({})
            } else {
                self.params.clone()
            },
        )
    }
}

/// What a human decides on **before the run continues**.
///
/// Three values, all enforced, and none is a predicate — "require approval when
/// severity is high" is one step from an `if`, which is where a config format
/// stops being config. A condition that only *reports* is
/// [`Oversight::triage`], which is a different thing and says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Approval {
    /// Every answer waits for a person.
    Required,
    /// Only the tool calls that ask for it wait; the answer returns unattended.
    ///
    /// The shape most deployments actually want, and the one that was missing.
    /// Gating the *answer* of a tool-calling agent is a review that arrives
    /// after the agent has already moved the money — the tool ran several turns
    /// ago, and a reviewer refusing now is refusing a summary of something that
    /// already happened. Gating the **call** is the control the answer gate
    /// reads like.
    ///
    /// Declaring it obliges the grants: every **mutating** grant must set
    /// `requires_approval: true`, or the manifest is refused at parse. The
    /// mode's claim is that a person sees the calls that change the world;
    /// enforced only where somebody remembered to also write
    /// `requires_approval`, it would be runtime-identical to
    /// [`None`](Self::None) — a mode in the reviewed file that the runtime
    /// cannot tell from its absence. Read-only grants stay ungated, because
    /// the mode never claimed a person reviews reads.
    ToolsOnly,
    /// Nothing waits. The run completes and
    /// [`Oversight::triage`] decides what a person is shown afterwards.
    ///
    /// # The mode an advisory agent needs
    ///
    /// A `tool-calling` agent that grants no mutating tool **cannot act**: its
    /// arguments come from a model completion, so a mutating call with no
    /// protected fields is refused by the taint gate on every run — which is
    /// why [`Manifest::validate`] refuses that grant outright rather than
    /// letting it read as a capability. A whole class of agents is therefore
    /// advisory by construction, and for those the other two modes are both
    /// wrong: `tools-only` gates nothing because there is no mutating call to
    /// gate, and `required` suspends every run until somebody approves a
    /// *report* — a worklist that blocks, at whatever rate the world produces
    /// findings.
    ///
    /// `none` is not "no oversight". It is refused unless something else in the
    /// block does work: a `triage` rule, or a grant asking for per-call
    /// approval. An oversight block that performs nothing is the decoration
    /// this format exists to reject.
    None,
}

/// What happens when the approval window closes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Expiry {
    /// Refuse the answer. The safe default, and the default here.
    #[default]
    Deny,
    /// Widen the audience and keep waiting.
    Escalate,
    /// Return the answer with nobody having looked.
    Proceed,
}

/// How a declarative agent runs.
///
/// Present means *no Rust*: the runtime registers the behaviour itself, driven
/// entirely by this document. That is the tier where the manifest digest covers
/// the whole agent rather than only its boundary — and where the claim this
/// project can make goes past the declarative-agent standards, because the run
/// is also journaled and deterministically replayable.
///
/// **A manifest declares; it never branches.** There is no sequencing, no
/// condition, no loop keyword here and there will not be: config that encodes
/// control flow stops being config and becomes a poor programming language.
/// Where genuine structure is needed it belongs in a plan, which is
/// contract-validated data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    /// Which built-in behaviour runs this agent.
    pub kind: ExecutionKind,
    /// How many model turns a tool-calling agent may take.
    ///
    /// A ceiling rather than a suggestion: a model that keeps asking for tools
    /// would otherwise run until the budget stopped it, and a budget stops it
    /// *after* paying for every turn. Bounded here so the failure is "this agent
    /// did not converge" rather than an invoice.
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,
}

/// Enough turns for a real chain of tool calls, few enough to notice a loop.
const fn default_max_turns() -> u32 {
    8
}

/// The built-in behaviours a manifest may ask for.
///
/// Deliberately an enum and deliberately short. Every variant is a behaviour
/// this crate implements and tests; a config format whose behaviours are
/// open-ended is one nobody can review, because the reviewer would have to know
/// what the string does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionKind {
    /// One model call, answered in the declared [`Output`] shape.
    ///
    /// The prompt is [`Identity::system_prompt`], the model is
    /// [`Models::privileged`], the schema is [`Output::schema`], and the input
    /// is whatever the run was started with. No tools, no second turn — which
    /// covers a large and useful class of agents exactly, and covers nothing
    /// else *at all*, which is the more important half.
    ///
    Completion,

    /// Call tools until the model stops asking, then answer.
    ///
    /// Each turn is a model call; every tool the model asks for is dispatched
    /// through the ordinary governed path, so grants, field provenance, the
    /// egress ceiling and the budget all apply exactly as they would to a skill
    /// that called the tool itself. Both the model calls and the tool calls are
    /// journaled effects, so a replay reads every one back instead of asking
    /// again.
    ///
    /// **Declaring is not authorizing.** The model is offered exactly the tools
    /// the manifest grants, and the name it picks is matched against that list
    /// byte for byte. A name that matches nothing is reported back to the model
    /// as a failed call rather than ending the run: the model gets a chance to
    /// correct itself, and it never gets the tool it nearly named.
    ToolCalling,

    /// Plan first over trusted input, then execute without the model.
    ///
    /// One privileged call reads the run's input — which MUST be trusted, and
    /// an untrusted input is refused outright — and emits a plan in a bounded
    /// schema: which granted tools to call, in what order, with which
    /// arguments. The runtime validates every step against the manifest's
    /// grants and executes the plan itself. Step outputs travel between steps
    /// as **labelled data bound by reference** (`$step0/txn/id`), never back
    /// through a model's context, so a hostile tool output cannot steer the
    /// steps that follow it: control flow was fixed before anything untrusted
    /// was read, and the data it touches keeps its provenance into every
    /// protected-field and taint gate.
    ///
    /// This is the dual-model pattern completed (`CaMeL`'s shape): a `parse`
    /// step hands a prior output to the **quarantined** model under a
    /// declared schema and a fixed extraction-only instruction, and the only
    /// thing a parse can say out of band is *not enough information*, which
    /// fails the step. Nothing a parse returns becomes trusted — schema-shaped
    /// is not trusted, and the only promotion anywhere is a typed, journaled
    /// release.
    ///
    /// Bought at a price [`ToolCalling`](Self::ToolCalling) does not pay: a
    /// plan cannot react to what it discovers mid-flight. Choose `planned`
    /// when the task's shape is known up front and the inputs the tools
    /// return are hostile; choose `tool-calling` when the shape is the
    /// discovery.
    Planned,
}

impl ExecutionKind {
    /// The kind, spelled the way a manifest spells it.
    ///
    /// So a diagnostic quotes the word an author would search their own file
    /// for, rather than a Rust variant name that appears nowhere in the YAML.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completion => "completion",
            Self::ToolCalling => "tool-calling",
            Self::Planned => "planned",
        }
    }
}

/// Where this agent sits in a multi-agent arrangement.
///
/// The field's justification is a measurement: MAST finds **inter-agent
/// misalignment is 36.9 % of observed multi-agent failures** — a failure class
/// that exists only if you chose it. So the arrangement is declared rather than
/// emergent, and the combinations that describe nothing are refused.
///
/// [`mode`](Self::mode) is *how many agents and why*. [`role`](Self::role) is
/// *what this one is*. They are separate because the same shape supports
/// different roles: a collaborative arrangement has one orchestrator and several
/// specialists, and each has its own manifest.
///
/// The rule that carries real weight is **a specialist may not delegate**. The
/// consistently reported top failure mode of handoff architectures is the
/// infinite loop — A hands to B, B to C, C back to A — and the structural answer
/// is that most agents in an arrangement have no authority to hand off at all.
/// A specialist declaring [`Security::max_delegation_depth`] above zero is
/// refused, because it is an orchestrator that nobody reviewed as one.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Topology {
    /// How many agents, and therefore how much coordination risk.
    #[serde(default)]
    pub mode: TopologyMode,
    /// What this agent is within that shape.
    #[serde(default)]
    pub role: Role,
    /// Why collaboration is warranted.
    ///
    /// Required for [`TopologyMode::Collaborative`] and refused otherwise:
    /// collaboration costs roughly an order of magnitude more tokens and opens
    /// the whole inter-agent failure surface, so *why* belongs in the file where
    /// a reviewer can disagree with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Justification>,
}

/// How many agents contribute to one task.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum TopologyMode {
    /// One agent, one context, many tools. Inter-agent failure is structurally
    /// absent, which is why it is the default.
    #[default]
    Single,
    /// Several agents contribute to one task. The full failure surface.
    Collaborative,
}

/// What an agent is within an arrangement.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Does one thing and hands off to nobody.
    ///
    /// The default, and the only role safe to assume: an agent that turns out to
    /// delegate when nobody expected it to is how a bounded task becomes an
    /// unbounded one.
    #[default]
    Specialist,
    /// Decomposes a task, delegates to specialists, assembles the result.
    ///
    /// The only role permitted to delegate, which is what makes the depth
    /// ceiling in [`Security::max_delegation_depth`] a bound on the arrangement
    /// rather than on one agent's manners.
    Orchestrator,
}

/// Why collaboration is worth its cost.
///
/// Each is checkable in principle rather than rhetorical, which is the point of
/// enumerating them instead of taking free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Justification {
    /// Sub-tasks operate on provably disjoint inputs.
    ///
    /// Overlapping inputs are **false parallelism**: paying the coordination
    /// cost and gaining nothing.
    ParallelDisjoint,
    /// Sub-tasks require strictly different capabilities.
    ///
    /// The reason worth emphasising, because neither side of the public
    /// multi-agent debate raises it: **the best reason to split agents is often
    /// security, not capability.** If a sub-task needs credentials the parent
    /// should not hold, delegating to a narrower agent is least privilege, and
    /// the coordination cost buys a real security property rather than
    /// hypothetical speed.
    DistinctAuthority,
}

/// The models an agent runs on, by role.
///
/// Declared here rather than in code because **a model id is a behaviour
/// change**: swapping a model alters what the agent does far more than most
/// code edits, and a swap made in a deploy has no version, no diff, and nothing
/// connecting it to the runs whose outputs changed. In the manifest it is
/// covered by [`Manifest::digest`], so it is a version bump.
///
/// The roles are not decoration: a hand-written skill can choose a quarantined
/// model for untrusted material while the manifest keeps that model choice in
/// the reviewed, digested allowlist — and in the declarative tier, **memory
/// formation runs on the quarantined model when one is declared**. Formation
/// is the dual-model pattern's quarantined job to the letter: it reads content
/// derived from untrusted input, is offered no tools, and must answer in a
/// bounded schema, so the model designated for untrusted contact is the one
/// that writes durable memory from it. The answer itself stays on the
/// privileged model.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Models {
    /// The model trusted with tool calls and decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<ModelRef>,
    /// The model that reads untrusted material and holds no authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined: Option<ModelRef>,
}

/// One model, named the way a provider names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRef {
    /// The driver: `anthropic`, `openai`, or whatever an embedder registered.
    ///
    /// Not an enum. This crate does not own the set of providers, and a closed
    /// enum here would make adding a driver a breaking change to the manifest
    /// format for everyone who never used it.
    pub provider: String,
    /// The provider's own model identifier, pinned exactly.
    pub model: String,
    /// A per-call output ceiling, if this role needs one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Explicit reasoning depth. Omitted uses the selected model's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<crate::model::ReasoningEffort>,
}

/// A declared [`ModelRef`] in the model layer's vocabulary.
fn role(r: &ModelRef) -> crate::model::ModelRole {
    crate::model::ModelRole {
        model: crate::model::ModelId::new(&r.provider, &r.model),
        max_output_tokens: r.max_tokens,
        reasoning_effort: r.reasoning_effort,
    }
}

/// The shape an agent promises its callers.
///
/// `capabilities.provides` names a capability; this says what comes back. A
/// schema that lives in the embedder's Rust is a contract with no version: it
/// changes in a deploy, every consumer parsing the old shape breaks, and
/// nothing connects the break to the change. Declared here it is covered by
/// [`Manifest::digest`], so narrowing a field is a version bump a consumer can
/// pin against.
///
/// The provider enforces this during generation and the driver validates the
/// parsed result locally as defense in depth. The first prevents invalid output
/// from consuming tokens; the second stops provider or emulation drift from
/// becoming malformed application data.
///
/// What the schema is *not* is inert. Handed to
/// [`ModelCall::expecting`](crate::model::ModelCall::expecting) it goes into the
/// **effect key**, so editing it makes a replay report divergence rather than
/// quietly reinterpreting last year's stored answer under today's rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Output {
    /// A JSON Schema, carried opaquely.
    ///
    /// Never parsed as a schema by this crate — only checked to be a non-empty
    /// object, because `{}` is a *valid* JSON Schema meaning "anything", and an
    /// output contract that constrains nothing is the trap this field exists to
    /// close. An agent with no machine-readable result omits `output` entirely.
    pub schema: serde_json::Value,
}

/// The constraints a runtime enforces.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Security {
    /// The highest sensitivity any value may reach an outward sink at. Combined
    /// with the sink's own ceiling at dispatch; the stricter limit wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sensitivity_egress: Option<Sensitivity>,
    /// The highest sensitivity a value may reach an effect **whose arguments
    /// the journal records**.
    ///
    /// A different question from [`max_sensitivity_egress`](Self::max_sensitivity_egress),
    /// and the one that decides whether personal data in a run can ever be
    /// erased. The journal is append-only, so an argument recorded there — a
    /// model prompt, a tool call's arguments — is never removed. Egress asks
    /// *may this leave*; this asks *may this be written down forever*.
    ///
    /// This is the **refuse it** answer. The **seal it** answer is
    /// `RuntimeBuilder::keyring`, which puts the same payloads under a per-case
    /// data key that `erase_case` destroys, reaching every copy including
    /// backups. They compose rather than compete: a sealed deployment may still
    /// declare a ceiling for the classes it would rather never hold at all,
    /// since a sealed record is still a record and a key ring is still an
    /// operational dependency.
    ///
    /// Absent means unbounded, which is the behaviour every deployment had
    /// before this field existed. Setting it makes the mistake a refusal at
    /// dispatch rather than a discovery at an erasure request: bytes above the
    /// ceiling belong in a blob, with the chain committing to the digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sensitivity_journaled: Option<Sensitivity>,
    /// How far authority may be re-delegated. Checked both against the runtime's
    /// configured identity and against every delegating sink before dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u8>,
}

/// What this agent offers, as capability strings.
///
/// `provides` is enforced: the plane refuses to build if a declared capability
/// has no skill behind it, and an Agent Card advertises exactly these. There
/// is no `requires` twin: parsed and digest-covered but never checked, it
/// would be the advisory-control shape I12 forbids, and its enforced meaning
/// (does a requirement bind a plane-mate's capability, a `tool://agent`
/// grant, or a peer?) is not pinned. A build check that every required
/// capability is available on the plane is a well-formed future control;
/// until it exists, the field does not.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    #[serde(default)]
    pub provides: Vec<String>,
}

/// Ceilings, in the manifest's own vocabulary.
///
/// Every ceiling here except `max_replans` is checked **before** the work and
/// against *every* effect the run performs, not only its model calls. An
/// omitted field means no limit; a field set to `0` therefore means the run may
/// not take its first step or perform its first effect of any kind, and
/// [`validate`](Manifest::validate) refuses it — see
/// [`max_tokens`](Self::max_tokens).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    /// Plan nodes this run may execute, checked before each one starts.
    ///
    /// Refused at `0`, which would stop the run before its first step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_steps: Option<usize>,
    /// Externally visible operations of **every** kind — a tool call, a clock
    /// read and a model completion each cost one, so this is not a model
    /// ceiling.
    ///
    /// Refused at `0`, which would refuse the run's first effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_effects: Option<usize>,
    /// Metered units consumed, compared against the run's total before **every**
    /// effect — including effects that consume no tokens at all.
    ///
    /// That is the misreading this field attracts, so it is worth stating
    /// plainly: this is not "how much the model may spend", it is a gate every
    /// effect passes through, and a run that has reached the ceiling performs no
    /// further operation of any kind. `0` is refused for exactly that reason —
    /// it reads as "no permission to spend" and behaves as "this agent can never
    /// do anything", including on an agent that declares no models.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    /// Money in minor units — cents, not euros. A float here would make a
    /// budget that fails to bind by a rounding error, and money is the one
    /// number nobody accepts "approximately" for.
    ///
    /// Gates **every** effect, exactly like [`max_tokens`](Self::max_tokens),
    /// and `0` is refused for the same reason: a free tool call still has to
    /// pass the ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_minor_units: Option<u64>,
    /// How many times the run may change its plan.
    ///
    /// `0` is meaningful and accepted: it means the plan the run started with is
    /// the plan it finishes with. Unlike the ceilings above, this one is
    /// consumed by an event that may simply never happen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_replans: Option<u32>,
    /// Seconds. Named for its unit so a manifest cannot mean minutes.
    ///
    /// Checked before each step and effect against elapsed time, which starts at
    /// zero — so `0` refuses the first step and is refused at parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wallclock_secs: Option<u64>,
    /// How many times the policy may refuse this run before it is stopped.
    ///
    /// The declarative half of the control the security model names: refusals
    /// carry a uniform message so a model cannot tell one from another, but the
    /// refused/allowed bit still leaks once per attempt, and what bounds that
    /// channel is bounding the attempts. A run that keeps hitting the policy is
    /// probing it — and, read operationally, has stopped making progress.
    ///
    /// `0` is meaningful and accepted, like [`max_replans`](Self::max_replans)
    /// and unlike every ceiling above: it is counted *after* the refusal, so it
    /// says the first refusal ends the run. A run nothing refuses never notices
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_denials: Option<u32>,
}

/// One tool this agent may call, and on what terms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolGrant {
    /// Which tool, as `tool://server/name`.
    ///
    /// Transport-neutral on purpose: the deployment's wiring decides whether
    /// `server` is an MCP connection, tools compiled into the binary, `agent`
    /// for another agent on this plane, or the id of a registered A2A peer —
    /// so this document states only what a reviewer can actually check.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Whether calling it changes the world.
    ///
    /// Defaults to **true**, which is the whole posture: a tool nobody thought
    /// about gets the treatment that makes the runtime cautious, not the one
    /// that makes it fast.
    #[serde(default = "yes")]
    pub mutates: bool,
    /// The highest sensitivity this tool may be shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sensitivity: Option<Sensitivity>,
    /// Authority-bearing JSON arguments and the lineage each is allowed to
    /// derive from. These rules are part of the canonical manifest digest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_fields: Vec<crate::core::ProtectedField>,
    /// What this tool does, in the words the **model** is given.
    ///
    /// It lives in the manifest rather than in code for the same reason the
    /// system prompt does: it is text that steers what an agent reaches for, so
    /// it belongs where a reviewer sees it as a diff and where the digest covers
    /// it. A tool description edited in a deploy changes which tool a model
    /// picks, with no version and nothing connecting it to the runs whose
    /// behaviour changed.
    ///
    /// Only a `tool-calling` agent uses it; a skill knows what it is calling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether a person approves each call, before it happens.
    ///
    /// The gate for a high-impact action. The task shows the **exact tool and
    /// the exact arguments** that will be dispatched — not a description of
    /// them, and not the answer they will eventually produce — because a
    /// reviewer who cannot see what will happen is not reviewing.
    ///
    /// Needs `spec.oversight`, which supplies the approvers, the obligation
    /// bounding the wait and what happens when it closes. Refused without it:
    /// a grant claiming a human is in the loop when nothing would ask one is
    /// exactly the decoration this format rejects.
    ///
    /// There is deliberately no diff. A diff needs the resource's current state,
    /// which is domain knowledge this runtime does not have — and a field named
    /// `diff` that showed arguments would be a control claiming more than it
    /// does.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub requires_approval: bool,
    /// A read-only tool that computes what this call *will do*, shown to the
    /// reviewer beside the call itself.
    ///
    /// [`requires_approval`](Self::requires_approval) shows the exact call, and
    /// for `transfer(to: "GB-4471", amount: 12000)` that **is** the change.
    /// `archive(older_than: "2024-01-01")` shows an instruction and not the
    /// four thousand records it touches; a reviewer of an instruction approves
    /// a sentence. The runtime cannot compute the consequences — that needs
    /// the tool's own dry run — but a manifest can name one, and then *the
    /// reviewer sees consequences* is a claim the declaration asserts and the
    /// runtime enforces.
    ///
    /// ```yaml
    /// - ref: "tool://archive/purge"
    ///   mutates: true
    ///   requires_approval: true
    ///   preview: "tool://archive/purge_preview"   # read-only, same arguments
    /// ```
    ///
    /// Before the task opens the preview is called **with the same
    /// arguments** and its answer lands in
    /// [`Justification::evidence`](crate::core::Justification::evidence) — an
    /// ordinary effect, journaled and replayed rather than repeated. If it
    /// fails the task opens anyway and says so: refusing a payment over an
    /// unavailable convenience would be the wrong trade.
    ///
    /// Refused at parse: a `preview` without `requires_approval` (nothing would
    /// call it), one naming a grant declared `mutates: true` (a dry run that
    /// changes the world), one naming an ungranted tool (a call with no
    /// declared safety), and one naming the grant itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    /// A JSON Schema for the arguments, carried opaquely.
    ///
    /// Sent to providers that enforce it during generation, so a well-shaped
    /// schema means fewer malformed calls — and fewer arguments that reach the
    /// protected-field check only to be refused after the tokens are paid for.
    ///
    /// Not a security control. A schema constrains *shape*, and every value it
    /// admits is still untrusted; what refuses an authority-bearing argument is
    /// [`protected_fields`](Self::protected_fields).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Value>,
}

const fn yes() -> bool {
    true
}

/// Cut every schema description down to its first paragraph.
///
/// The prose is single-sourced from the types' own documentation, which is
/// written for a Rust reader at essay length; a hover box wants the opening
/// sentence. Rustdoc's `` [`X`] `` link spelling renders literally in an
/// editor, so it is reduced to plain code formatting on the way.
fn trim_descriptions(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(serde_json::Value::String(text)) = object.get_mut("description") {
                *text = text
                    .split("\n\n")
                    .next()
                    .unwrap_or_default()
                    .replace("[`", "`")
                    .replace("`]", "`")
                    .replace('\n', " ");
            }
            for value in object.values_mut() {
                trim_descriptions(value);
            }
        }
        serde_json::Value::Array(items) => {
            for value in items {
                trim_descriptions(value);
            }
        }
        _ => {}
    }
}

/// Every `tool://server/name` written in a piece of prose.
///
/// Scans for the scheme and takes the run of characters a reference may
/// contain, so surrounding punctuation — a backtick, a comma, a closing
/// parenthesis, the end of a sentence — is not swallowed into the name. Anything
/// the reference parser then refuses is skipped rather than reported: prose
/// containing the literal text `tool://` in a sentence about the scheme itself
/// is not a grant somebody forgot.
fn tool_references_in(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(crate::tools::TOOL_SCHEME) {
        let candidate: String = rest[at..]
            .chars()
            .take_while(|c| {
                c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '-' | '_' | '.' | '+')
            })
            .collect();
        if crate::tools::ToolId::parse(&candidate).is_some() {
            found.push(candidate.clone());
        }
        // Advance past the scheme, never past the candidate: two references
        // written back to back must both be seen.
        rest = &rest[at + crate::tools::TOOL_SCHEME.len()..];
    }
    found.sort();
    found.dedup();
    found
}

impl Manifest {
    /// The privileged role, resolved to the model layer's vocabulary.
    ///
    /// The **whole** role — id plus the `max_tokens` and `reasoning_effort`
    /// declared beside it — because a role's ceilings are half the
    /// declaration, and every seam that carried the id alone has ended up
    /// silently dropping the other half.
    #[must_use]
    pub fn privileged_role(&self) -> Option<crate::model::ModelRole> {
        self.spec.models.as_ref()?.privileged.as_ref().map(role)
    }

    /// The quarantined role for untrusted contact, when one is declared.
    ///
    /// `None` means the manifest designates no separate model for hostile
    /// content; callers fall back to the privileged role's own declaration,
    /// never to a driver default.
    #[must_use]
    pub fn quarantined_role(&self) -> Option<crate::model::ModelRole> {
        self.spec.models.as_ref()?.quarantined.as_ref().map(role)
    }

    /// Begin a programmatic declaration with the required identity fields.
    ///
    /// YAML and Rust construction converge on [`Manifest::build`]; neither gets
    /// a weaker validation path. The builder is intentionally small rather than
    /// mirroring every nested field with dozens of forwarding methods: callers
    /// configure the public typed [`Spec`] directly and the final build
    /// normalizes and validates it.
    #[must_use]
    pub fn builder(name: impl Into<String>, version: impl Into<String>) -> ManifestBuilder {
        ManifestBuilder {
            metadata: Metadata {
                name: name.into(),
                version: version.into(),
                annotations: BTreeMap::new(),
            },
            spec: Spec::default(),
        }
    }

    /// Normalize and validate a typed manifest value.
    ///
    /// Use this after direct struct construction. It is the programmatic twin
    /// of [`Manifest::parse`] and prevents the common DX failure where a caller
    /// can build a value that YAML would have refused.
    pub fn build(mut self) -> Result<Self, ManifestError> {
        self.normalize();
        self.validate()?;
        Ok(self)
    }

    /// Parse and validate a YAML manifest.
    ///
    /// # Errors
    ///
    /// [`ManifestError::Syntax`] if it is not well-formed — which includes an
    /// unknown field, because a field this crate does not recognise in a
    /// security document is a mistake and not an extension. See
    /// [`Manifest::validate`] for the rest.
    pub fn parse(yaml: &str) -> Result<Self, ManifestError> {
        let mut m: Self =
            serde_yaml_ng::from_str(yaml).map_err(|e| ManifestError::Syntax(e.to_string()))?;
        m.normalize();
        m.validate()?;
        Ok(m)
    }

    /// Parse a file holding **several** manifests, separated by `---`.
    ///
    /// The Kubernetes packaging convention, adopted for the same reason it won
    /// there: a multi-agent room is one deployable thing, and three files that
    /// only make sense together are three chances to deploy two of them.
    ///
    /// **The file is packaging; identity stays per-agent.** Each document
    /// keeps its own digest, so pinning, signing and "a model swap is a
    /// version bump" are unchanged — a bundle digest would make one agent's
    /// prompt edit move its neighbours' identities. Empty documents (a stray
    /// leading or trailing `---`) are skipped, as Kubernetes skips them; a
    /// file with *no* manifest in it is refused rather than answered with an
    /// empty room.
    ///
    /// # Errors
    ///
    /// [`ManifestError::Syntax`] naming the failing document's position, the
    /// same validation errors [`Manifest::parse`] raises per document, and a
    /// refusal for two documents sharing one `metadata.name` — one file
    /// declaring the same agent twice is a merge conflict, not a room.
    pub fn parse_all(yaml: &str) -> Result<Vec<Self>, ManifestError> {
        use serde::Deserialize as _;

        let mut manifests: Vec<Self> = Vec::new();
        for (index, document) in serde_yaml_ng::Deserializer::from_str(yaml).enumerate() {
            let ordinal = index + 1;
            let value = serde_yaml_ng::Value::deserialize(document)
                .map_err(|e| ManifestError::Syntax(format!("document {ordinal}: {e}")))?;
            if value.is_null() {
                continue;
            }
            let mut m: Self = serde_yaml_ng::from_value(value)
                .map_err(|e| ManifestError::Syntax(format!("document {ordinal}: {e}")))?;
            m.normalize();
            m.validate()?;
            if let Some(twin) = manifests
                .iter()
                .find(|prior| prior.metadata.name == m.metadata.name)
            {
                return Err(ManifestError::Syntax(format!(
                    "document {ordinal} declares agent '{}' a second time (first at \
                     version {}) — one file declaring the same agent twice is a merge \
                     conflict, not a room",
                    m.metadata.name, twin.metadata.version
                )));
            }
            manifests.push(m);
        }
        if manifests.is_empty() {
            return Err(ManifestError::Syntax(
                "the file contains no manifest documents".to_owned(),
            ));
        }
        Ok(manifests)
    }

    /// Parse a **set of separately embedded documents**, keyed by declared name.
    ///
    /// # The shape [`parse_all`](Self::parse_all) does not cover
    ///
    /// `parse_all` is for a *room*: several agents in one file, because they are
    /// one deployable thing. The other common layout is one file per agent, a
    /// directory of them, and `include_str!` in the binary — and it had no
    /// support at all, so every embedder wrote the same table by hand:
    ///
    /// ```text
    /// const AGENTS: &[(&str, &str)] = &[
    ///     ("obligation-watch", include_str!(agents/obligation-watch.yaml)),
    ///     ("clearing-triage",  include_str!(agents/clearing-triage.yaml)),
    /// ];
    /// ```
    ///
    /// That table has two defects and both are silent. The name beside each path
    /// is **already in the document** as `metadata.name`, so it is one fact
    /// written twice and nothing checks that the two agree. And a file included
    /// under two constants — a copy-paste while adding the next agent — builds,
    /// runs, and registers one agent twice while the other is simply absent.
    ///
    /// This takes `(origin, yaml)` pairs, where `origin` is used **only in
    /// diagnostics**, and keys the result by the name each document declares.
    /// A name declared twice is refused and the message names both origins.
    /// [`manifests!`](crate::manifests) writes the pairs for you from path
    /// literals.
    ///
    /// # Errors
    ///
    /// [`ManifestError::Syntax`] naming the failing document's origin, the same
    /// validation errors [`parse`](Self::parse) raises, and a refusal for two
    /// documents declaring one `metadata.name`.
    pub fn parse_each<'a>(
        documents: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<std::collections::BTreeMap<String, Self>, ManifestError> {
        let mut out: std::collections::BTreeMap<String, Self> = std::collections::BTreeMap::new();
        let mut origins: std::collections::BTreeMap<String, &str> =
            std::collections::BTreeMap::new();
        for (origin, yaml) in documents {
            let m =
                Self::parse(yaml).map_err(|e| ManifestError::Syntax(format!("{origin}: {e}")))?;
            if let Some(first) = origins.get(&m.metadata.name) {
                return Err(ManifestError::Syntax(format!(
                    "'{origin}' and '{first}' both declare agent '{}' — a name resolves to \
                     one declaration, so one of the two would silently not be the one that \
                     runs. Two agents need two names; one agent needs one file",
                    m.metadata.name
                )));
            }
            origins.insert(m.metadata.name.clone(), origin);
            out.insert(m.metadata.name.clone(), m);
        }
        if out.is_empty() {
            return Err(ManifestError::Syntax(
                "no manifest documents were supplied".to_owned(),
            ));
        }
        Ok(out)
    }

    fn normalize(&mut self) {
        for grant in &mut self.spec.tools {
            grant
                .protected_fields
                .sort_by(|left, right| left.path().cmp(right.path()));
        }
    }

    /// Everything that is wrong beyond the shape.
    ///
    /// # Errors
    ///
    /// [`ManifestError::WrongDocument`] for a foreign `apiVersion` or `kind`,
    /// [`ManifestError::Empty`] for a field that is present but says nothing,
    /// and [`ManifestError::Unbounded`] when no budget is declared — because an
    /// absent ceiling is a decision, and a decision has to be visible. Declare
    /// `budgets: {}` to mean it.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.api_version != API_VERSION || self.kind != KIND {
            return Err(ManifestError::WrongDocument {
                api_version: self.api_version.clone(),
                kind: self.kind.clone(),
            });
        }
        if self.metadata.name.trim().is_empty() {
            return Err(ManifestError::Empty("metadata.name"));
        }
        if self.metadata.version.trim().is_empty() {
            return Err(ManifestError::Empty("metadata.version"));
        }
        self.validate_annotations()?;
        if let Some(identity) = &self.spec.identity {
            // A declared-but-blank role is the worst of both worlds: the digest
            // covers a prompt that says nothing, and a reviewer sees a field
            // that looks answered.
            if identity.role.trim().is_empty() {
                return Err(ManifestError::Empty("spec.identity.role"));
            }
        }
        // A declarative agent provides exactly one capability. The behaviour
        // cannot tell two apart — the capability never reaches the prompt, so
        // both names would run the identical model call — and accepting YAML
        // that declares a distinction nothing executes is the `routed`/`router`
        // mistake again. Two capabilities are two agents: two documents, one
        // room file, each with its own digest. A *coded* agent may provide
        // several, because each capability has its own skill behind it.
        if self.spec.execution.is_some() && self.spec.capabilities.provides.len() > 1 {
            return Err(ManifestError::Unenforceable {
                field: "spec.capabilities.provides",
                detail: "a declarative agent provides exactly one capability — the \
                         behaviour cannot tell two apart, so a second name would be a \
                         distinction nothing executes. Split into two documents in one \
                         room file, each with its own digest",
            });
        }
        self.validate_prompt_tool_references()?;
        self.validate_oversight()?;
        self.validate_tool_approval()?;
        self.validate_tool_previews()?;
        self.validate_tool_grants()?;
        self.validate_mutating_grants_can_fire()?;
        self.validate_agent_grants()?;
        self.validate_context_grants()?;
        self.validate_topology()?;
        self.validate_models()?;
        self.validate_output()?;
        self.validate_memory()?;
        let mut tool_ids = std::collections::BTreeSet::new();
        for grant in &self.spec.tools {
            if grant.reference.trim().is_empty() {
                return Err(ManifestError::Empty("spec.tools[].ref"));
            }
            let Some(id) = crate::tools::ToolId::parse(&grant.reference) else {
                return Err(ManifestError::Syntax(format!(
                    "spec.tools: '{}' is not an exact tool://server/name reference",
                    grant.reference
                )));
            };
            if !tool_ids.insert(id.clone()) {
                return Err(ManifestError::Syntax(format!(
                    "spec.tools: '{}' is granted more than once — two safety declarations \
                     for one tool make list order decide which one governs",
                    grant.reference
                )));
            }
            let mut paths = std::collections::BTreeSet::new();
            for field in &grant.protected_fields {
                field.validate().map_err(|detail| {
                    ManifestError::Syntax(format!(
                        "spec.tools[].protected_fields entry '{}': {detail}",
                        field.path()
                    ))
                })?;
                if !paths.insert(field.path()) {
                    return Err(ManifestError::Syntax(
                        "spec.tools[].protected_fields must have unique paths".to_owned(),
                    ));
                }
            }
        }
        if self.spec.budgets.is_none() {
            return Err(ManifestError::Unbounded);
        }
        self.validate_budgets()
    }

    /// A ceiling of zero is refused, because it does not do what the person who
    /// wrote it meant.
    ///
    /// Every ceiling below is accumulate-and-compare, checked *before* the work
    /// and refusing once consumption has **reached** the limit. At zero the
    /// limit is reached before anything has happened, so the run is refused its
    /// first step or its first effect — of any kind, on any agent. Reported
    /// from a deployment that wrote `max_tokens: 0` on an agent with no models
    /// at all, meaning "this one does not get to spend money"; every run it
    /// ever made died on a read-only tool call with `token budget exhausted: 0
    /// permitted, 0 consumed`.
    ///
    /// It is refused rather than reinterpreted because both readings are
    /// defensible — "no budget" and "no limit" are the two things a zero could
    /// mean — and a ceiling whose meaning the runtime guesses at is the failure
    /// this whole document exists to remove. The two ways to say it are already
    /// there, and the message names them.
    ///
    /// `max_replans` and `max_denials` are deliberately absent: zero is a
    /// coherent instruction for both, because each counts an event that may
    /// never occur, so forbidding it forbids nothing the run needs.
    fn validate_budgets(&self) -> Result<(), ManifestError> {
        // Which ceilings are bricked is `Budget`'s rule, not this layer's: the
        // same budget reaches the runtime through `RuntimeBuilder::budget`
        // without passing here, and two copies of the list would agree until
        // somebody added a sixth ceiling to one of them.
        let Some(field) = self.budget().bricked_ceiling() else {
            return Ok(());
        };
        Err(ManifestError::Syntax(format!(
            "spec.budgets.{field} is 0, which permits nothing at all — not merely no \
             model spend. This ceiling is checked before every step and every effect, \
             so at 0 it is already reached and the run is refused its first operation \
             of any kind: a read-only tool call, a local lookup, an agent that declares \
             no models at all. Such an agent does not run once and stop, it fails \
             identically on every run it will ever make. Omit the field to mean 'no \
             limit'. To stop a tenant doing work, use the operator's emergency stop \
             (`QuotaStore::set_halt`), which refuses new runs with a reason attached — \
             a halt says somebody is dealing with an incident, where a ceiling only \
             says not right now"
        )))
    }

    /// Annotation keys are `prefix/name`, and the prefix is somebody else's.
    ///
    /// The grammar is Kubernetes' own — a DNS-subdomain prefix of at most 253
    /// characters, a name of at most 63 beginning and ending alphanumeric with
    /// `-`, `_` and `.` inside, and at most 256 KiB of keys and values on one
    /// object — so an entry carries into a Kubernetes object unchanged, which
    /// is the shape a deployment tooling a manifest into a cluster needs. One
    /// rule is stricter: the prefix is **required** where Kubernetes makes it
    /// optional. An unqualified `owner` is exactly the name a future
    /// first-class field would want, and a format that accepted it could
    /// never add one. The prefix must also contain a dot, because a
    /// single-label "domain" names nothing anybody owns.
    ///
    /// The value is otherwise unconstrained. It is never parsed, so there is
    /// nothing to constrain it *for*; a blank one is refused because a key
    /// that answers nothing reads, to a reviewer, like a question that was
    /// answered.
    fn validate_annotations(&self) -> Result<(), ManifestError> {
        let mut total = 0usize;
        for (key, value) in &self.metadata.annotations {
            let Some((prefix, name)) = key.split_once('/') else {
                return Err(ManifestError::Syntax(format!(
                    "metadata.annotations: '{key}' is not namespaced — a key must be \
                     'prefix/name' with a dotted prefix you control (e.g. \
                     'example.com/business-owner'), so it cannot collide with a field \
                     this format may grow"
                )));
            };
            if name.contains('/') {
                return Err(ManifestError::Syntax(format!(
                    "metadata.annotations: '{key}' must be exactly one 'prefix/name' pair"
                )));
            }
            if !prefix.contains('.') || !is_dns_subdomain(prefix) {
                return Err(ManifestError::Syntax(format!(
                    "metadata.annotations: '{key}' has no valid prefix — it must be a DNS \
                     subdomain you control, like 'example.com/{name}': lowercase labels of \
                     letters, digits and '-', joined by dots, at most 253 characters"
                )));
            }
            if !is_annotation_name(name) {
                return Err(ManifestError::Syntax(format!(
                    "metadata.annotations: '{key}' has an invalid name — at most 63 characters, \
                     beginning and ending with a letter or digit, with '-', '_' and '.' between"
                )));
            }
            if key.starts_with(RESERVED_ANNOTATION_PREFIX) {
                return Err(ManifestError::Syntax(format!(
                    "metadata.annotations: '{key}' is under '{RESERVED_ANNOTATION_PREFIX}', which \
                     this format reserves so an annotation can never shadow a field it grows. \
                     Use a prefix you control"
                )));
            }
            if value.trim().is_empty() {
                return Err(ManifestError::Syntax(format!(
                    "metadata.annotations: '{key}' has no value — a key that answers nothing \
                     reads to a reviewer like a question that was answered"
                )));
            }
            total += key.len() + value.len();
        }
        if total > MAX_ANNOTATIONS_BYTES {
            return Err(ManifestError::Syntax(format!(
                "metadata.annotations: {total} bytes of keys and values, and the limit is \
                 {MAX_ANNOTATIONS_BYTES} — annotations are facts about the agent, not a \
                 place to keep its documents; store the document and annotate its address"
            )));
        }
        Ok(())
    }

    fn validate_context_grants(&self) -> Result<(), ManifestError> {
        let mut prompts = std::collections::BTreeSet::new();
        for grant in &self.spec.context.prompts {
            if grant.server.trim().is_empty() || grant.name.trim().is_empty() {
                return Err(ManifestError::Empty("spec.context.prompts[].server/name"));
            }
            if !prompts.insert((&grant.server, &grant.name)) {
                return Err(ManifestError::Syntax(format!(
                    "spec.context.prompts contains duplicate '{}/{}'",
                    grant.server, grant.name
                )));
            }
        }
        let mut resources = std::collections::BTreeSet::new();
        for grant in &self.spec.context.resources {
            if grant.server.trim().is_empty() || grant.uri.trim().is_empty() {
                return Err(ManifestError::Empty("spec.context.resources[].server/uri"));
            }
            if !resources.insert((&grant.server, &grant.uri)) {
                return Err(ManifestError::Syntax(format!(
                    "spec.context.resources contains duplicate '{}/{}'",
                    grant.server, grant.uri
                )));
            }
        }
        Ok(())
    }

    /// A tool-calling agent's grants must be describable to a model.
    ///
    /// The model picks from what it is told. A grant with no description gives
    /// it a bare name to guess from, and a guessed call is refused at the
    /// protected-field check *after* the tokens are paid for — so an
    /// undescribed tool is not a smaller feature, it is a slower refusal.
    ///
    /// Only for `tool-calling`. A skill knows what it is calling, so requiring
    /// prose there would be the decoration this format refuses.
    fn validate_tool_grants(&self) -> Result<(), ManifestError> {
        let Some(execution) = &self.spec.execution else {
            return Ok(());
        };
        if !matches!(
            execution.kind,
            ExecutionKind::ToolCalling | ExecutionKind::Planned
        ) {
            return Ok(());
        }
        for grant in &self.spec.tools {
            if grant
                .description
                .as_ref()
                .is_none_or(|d| d.trim().is_empty())
            {
                return Err(ManifestError::Syntax(format!(
                    "spec.tools: '{}' has no description, and a `tool-calling` or `planned` \
                     agent offers its tools to a model by name and description. Without one \
                     the model guesses, and a guessed call is refused at the field check \
                     after it has been paid for",
                    grant.reference
                )));
            }
        }
        Ok(())
    }

    /// A mutating grant a tool loop can never dispatch is refused at parse.
    ///
    /// The three facts compose, and each is right on its own. A model
    /// completion is labelled **untrusted** unconditionally — its source is the
    /// model. The tool loop builds a call's arguments from that completion, so
    /// they carry its label. And a mutating sink whose grant names **no**
    /// protected fields refuses an untrusted argument bundle outright, because
    /// a tool that has not been told which of its fields are authority-bearing
    /// has had no such decision made about it, and fail-closed is the answer to
    /// a question nobody asked.
    ///
    /// Together: `mutates: true` with no `protected_fields`, on a
    /// `tool-calling` agent, is a grant that cannot fire. It reads to a
    /// reviewer as *this specialist may dispatch, with a human in front of it*
    /// and is decoration — the same shape as a `quarantined` model nothing
    /// selects, found the same way, by running it rather than reading it. The
    /// run does not even fail cleanly: it succeeds, having quietly done
    /// nothing the model asked for.
    ///
    /// **Not refused for `planned`.** A planned step's arguments are resolved
    /// by the runtime from `$input/…` and `$stepN/…` references, so they carry
    /// the *input's* labels rather than a completion's — which is exactly the
    /// provenance distinction the loop structurally cannot make.
    ///
    /// The remedy the message leads with is `protected_fields`, and that
    /// ordering is deliberate: declaring which arguments are authority-bearing
    /// is what makes a mutating call reachable *and* governed, and it is the
    /// feature that exists for this. Moving to `planned` or dropping `mutates`
    /// are the other two honest answers, and both are smaller agents.
    fn validate_mutating_grants_can_fire(&self) -> Result<(), ManifestError> {
        let Some(execution) = &self.spec.execution else {
            return Ok(());
        };
        if execution.kind != ExecutionKind::ToolCalling {
            return Ok(());
        }
        for grant in &self.spec.tools {
            // An `agent` grant dispatches through commission rather than a
            // sink, so the taint gate this check is about never runs for it —
            // and the parser already refuses `mutates` on one.
            if grant.reference.starts_with("tool://agent/") {
                continue;
            }
            if grant.mutates && grant.protected_fields.is_empty() {
                return Err(ManifestError::Syntax(format!(
                    "spec.tools: '{}' declares `mutates: true` with no `protected_fields`, \
                     and this agent is `execution.kind: tool-calling`. A tool \
                     loop's arguments come from a model completion, which is \
                     always untrusted, so a mutating call with no field rules is \
                     refused by the taint gate on every run — the grant reads as \
                     a capability and is decoration. Three honest fixes: declare \
                     the authority-bearing arguments in `protected_fields` \
                     (ordinary untrusted content may sit beside them, which is \
                     what the feature is for); or use `execution.kind: planned`, \
                     whose step arguments are resolved by the runtime and keep \
                     the input's labels; or set `mutates: false` if the call \
                     really does not change anything",
                    grant.reference
                )));
            }
            // The inverse trap: fields declared, none of them about authority.
            // Declaring `protected_fields` is what lifts the whole-object
            // taint gate on a mutating sink — the runtime then trusts the
            // per-field rules to be the decision about who may author what.
            // A sensitivity ceiling is not that decision: it bounds how
            // *secret* an argument may be, and the model's own untrusted
            // completion is happily below any ceiling — so a grant whose only
            // rules are ceilings lifts the gate while constraining nobody,
            // and the recipient, amount and command fields dispatch exactly
            // as the model wrote them. Authority needs a provenance rule or a
            // value menu: `one_of` counts, because a field that can carry
            // only reviewer-enumerated values is constrained in *content*,
            // which no author — the model included — can widen.
            if grant.mutates
                && !grant.protected_fields.is_empty()
                && grant.protected_fields.iter().all(|f| {
                    !f.requires_trusted()
                        && f.allowed_sources().is_empty()
                        && f.allowed_values().is_empty()
                })
            {
                return Err(ManifestError::Syntax(format!(
                    "spec.tools: '{}' declares `mutates: true` and every \
                     `protected_fields` entry carries only a sensitivity \
                     ceiling. Declaring protected fields is what lifts the \
                     whole-object taint gate on a mutating sink, and a ceiling \
                     bounds how secret an argument may be — not who authored \
                     it — so the model's own untrusted completion would fill \
                     every authority-bearing field unconstrained. At least one \
                     protected field must carry a trust, source, or value \
                     rule: `require_trusted: true`, `allowed_sources` naming \
                     where the value must come from, or `one_of` enumerating \
                     what may stand in it (a ceiling may sit beside any)",
                    grant.reference
                )));
            }
        }
        Ok(())
    }

    /// The rules an `agent`-server grant must satisfy, checked at parse.
    ///
    /// A grant spelled `tool://agent/<capability>` consults another agent via
    /// the commission effect, which is a dispatch path the ordinary tool
    /// safety machinery never sees. Every field that would be enforced on the
    /// transport path and silently unenforced here is refused rather than
    /// accepted as decoration — no declared control may be advisory:
    ///
    /// * `mutates: false` is a claim this manifest cannot make. The
    ///   consultation runs another agent, and what *it* does to the world is
    ///   governed by its own declaration, not by this one's optimism.
    /// * `protected_fields` and `max_sensitivity` act at the sink-binding
    ///   gate, which the commission path does not take. Accepting them would
    ///   put a field-provenance rule in a reviewed file that nothing checks.
    /// * The granting agent must declare `topology.role: orchestrator`.
    ///   Consulting an agent **is** delegation; a specialist may not delegate,
    ///   and the default topology is a lone specialist — so reaching for
    ///   another agent requires declaring the arrangement, exactly as it does
    ///   for a hand-written skill calling `commission`.
    fn validate_agent_grants(&self) -> Result<(), ManifestError> {
        for grant in &self.spec.tools {
            let Some(rest) = grant.reference.strip_prefix("tool://agent/") else {
                continue;
            };
            let reference = &grant.reference;
            if rest.is_empty() {
                return Err(ManifestError::Syntax(format!(
                    "spec.tools: '{reference}' names no capability"
                )));
            }
            // An agent granted the capability it itself provides is granted a
            // call to itself. Whether that regress terminates depends on a
            // model's judgement, which is the one thing a ceiling cannot bound
            // — and both halves of the contradiction are on this page.
            if self.spec.capabilities.provides.iter().any(|c| c == rest) {
                return Err(ManifestError::Unenforceable {
                    field: "spec.tools[].ref",
                    detail: "this grant names a capability the agent itself provides, so it \
                             is a grant to call itself. The recursion terminates only if a \
                             model decides it should, which is not something the declaration \
                             can bound — grant the capability of a *different* agent, or \
                             drop the grant",
                });
            }
            if !grant.mutates {
                return Err(ManifestError::Unenforceable {
                    field: "spec.tools[].mutates",
                    detail: "an agent consulted as a tool runs under its own declaration, \
                             and what it does to the world is its manifest's statement to \
                             make — `mutates: false` here is a claim this document cannot \
                             back",
                });
            }
            if !grant.protected_fields.is_empty() {
                return Err(ManifestError::Unenforceable {
                    field: "spec.tools[].protected_fields",
                    detail: "an agent consultation dispatches through `commission`, not \
                             through the sink-binding gate — a protected-field rule here \
                             would be reviewed and never checked",
                });
            }
            if grant.max_sensitivity.is_some() {
                return Err(ManifestError::Unenforceable {
                    field: "spec.tools[].max_sensitivity",
                    detail: "an agent consultation dispatches through `commission`, not \
                             through the sink gate that enforces a sensitivity ceiling — \
                             declare ceilings on the consulted agent instead",
                });
            }
            if self
                .spec
                .topology
                .as_ref()
                .is_none_or(|t| t.role != Role::Orchestrator)
            {
                return Err(ManifestError::Syntax(format!(
                    "spec.tools: '{reference}' consults another agent, which is delegation \
                     — declare `topology.role: orchestrator`, because a specialist may not \
                     delegate and the default topology is a lone specialist"
                )));
            }
        }
        Ok(())
    }

    /// A prompt naming a tool this agent was never granted is refused.
    ///
    /// # The failure it closes, and the half it cannot
    ///
    /// An unknown tool name is reported back to the model as a **failed call**
    /// rather than ending the run — deliberately, so the model can correct
    /// itself and never gets the tool it nearly named. The cost is that a
    /// *procedure* naming an ungranted tool does not fail loudly: the model
    /// asks, is refused, improvises, and the step silently does not happen.
    /// Nothing in the journal says the instruction was unfollowable, because
    /// from the runtime's side nothing went wrong.
    ///
    /// So the check runs where the two facts are in one document. Any
    /// `tool://server/name` written in [`Identity::role`] or
    /// [`Identity::constraints`] must be a tool `spec.tools` grants.
    ///
    /// **It only sees references spelled as references.** A prompt that says
    /// *"call `list_overdue_processes`"* names a tool in prose, and prose is not
    /// something this crate can tell from an ordinary noun — a check that
    /// guessed would refuse manifests over the word "search". Writing the
    /// grant's own `ref` in the prompt is therefore the spelling that gets
    /// checked, and it is also the spelling a reviewer can follow.
    ///
    /// It is deliberately not softened for *illustrative* references either: a
    /// prompt containing the literal text `tool://server/name` as a placeholder
    /// is refused. The trade is one-sided — a false positive is a parse error
    /// naming the exact string, and a false negative is an instruction the agent
    /// silently cannot follow.
    fn validate_prompt_tool_references(&self) -> Result<(), ManifestError> {
        let Some(identity) = &self.spec.identity else {
            return Ok(());
        };
        let granted: std::collections::BTreeSet<&str> = self
            .spec
            .tools
            .iter()
            .map(|g| g.reference.as_str())
            .collect();
        // The extraction model reads its own instruction and is offered the
        // same grants, so a tool named there goes the same way a tool named in
        // the role does: asked for, refused, improvised around.
        let mut prose = vec![
            ("spec.identity.role", identity.role.as_str()),
            ("spec.identity.constraints", identity.constraints.as_str()),
        ];
        if let Some(formation) = self.spec.memory.as_ref().and_then(|m| m.formation.as_ref()) {
            prose.push((
                "spec.memory.formation.instruction",
                formation.instruction.as_str(),
            ));
        }
        for (field, text) in prose {
            for reference in tool_references_in(text) {
                if !granted.contains(reference.as_str()) {
                    return Err(ManifestError::Syntax(format!(
                        "{field} instructs the agent to use '{reference}', which \
                         `spec.tools` does not grant. An ungranted name is reported to the \
                         model as a failed call, so the model improvises and the \
                         instruction silently does not happen — grant the tool, or stop \
                         naming it"
                    )));
                }
            }
        }
        Ok(())
    }

    /// A control nothing performs is worse than no control at all.
    fn validate_oversight(&self) -> Result<(), ManifestError> {
        let Some(o) = &self.spec.oversight else {
            return Ok(());
        };
        // A hand-written skill picks its own moment to ask, so there is nothing
        // here for the runtime to apply — and a declaration it cannot apply is
        // the decoration the binding rule exists to refuse.
        if self.spec.execution.is_none() {
            return Err(ManifestError::Unenforceable {
                field: "spec.oversight",
                detail: "oversight is applied by a declarative agent; a hand-written skill \
                         chooses its own moment to ask, so declaring it here would name a \
                         control nothing performs",
            });
        }
        if o.deadline.name.trim().is_empty() {
            return Err(ManifestError::Empty("spec.oversight.deadline.name"));
        }
        if o.deadline.kind.trim().is_empty() {
            return Err(ManifestError::Empty("spec.oversight.deadline.kind"));
        }
        let gates_a_call = self.spec.tools.iter().any(|grant| grant.requires_approval);
        // `tools-only` with nothing asking for it gates nothing at all, and
        // reads in review as oversight that is present.
        if o.approval == Approval::ToolsOnly && !gates_a_call {
            return Err(ManifestError::Unenforceable {
                field: "spec.oversight.approval",
                detail: "'tools-only' with no tool grant requesting approval gates nothing — \
                         set `requires_approval: true` on the calls a person must see, or \
                         use 'required' to gate the answer",
            });
        }
        // And the mode's claim is about the calls that change the world, so a
        // mutating grant it does not gate is the claim broken where it counts.
        // Before this check, `tools-only` was runtime-identical to `none` the
        // moment one grant asked: the file read as "a person sees this agent's
        // actions" while the transfer beside the gated call ran unattended —
        // a declared control enforced only where somebody remembered to also
        // write `requires_approval`, which is no mode at all. Read-only grants
        // stay ungated: the mode never claimed a person reviews reads.
        if o.approval == Approval::ToolsOnly
            && let Some(silent) = self
                .spec
                .tools
                .iter()
                .find(|grant| grant.mutates && !grant.requires_approval)
        {
            return Err(ManifestError::Syntax(format!(
                "spec.oversight.approval: 'tools-only' names per-call approval as this \
                 agent's human control, and '{}' is a mutating grant with no \
                 `requires_approval` — a mode that gates tool calls while a call that \
                 changes the world needs nobody is a declared control nothing enforces. \
                 Set `requires_approval: true` on every mutating grant, or use \
                 'required' to gate the answer instead",
                silent.reference
            )));
        }
        // `none` is the advisory mode, not an off switch: something in the
        // block still has to perform. Without this, `approval: none` with an
        // empty `triage` is a whole oversight declaration that does nothing
        // while reading in review as a human control.
        if o.approval == Approval::None && !gates_a_call && o.triage.is_empty() {
            return Err(ManifestError::Unenforceable {
                field: "spec.oversight.approval",
                detail: "'none' with no `triage` rule and no grant requesting approval is an \
                         oversight block that performs nothing — declare the rules that open \
                         a task beside the answer, set `requires_approval: true` on the calls \
                         a person must see, or remove `spec.oversight` entirely",
            });
        }
        self.validate_triage(&o.triage)?;
        // The same explicitness the runtime demands, demanded in the file.
        if o.on_expiry == Expiry::Proceed && !o.allow_unattended {
            return Err(ManifestError::Unenforceable {
                field: "spec.oversight.on_expiry",
                detail: "'proceed' needs `allow_unattended: true` — acting with no human when \
                         the window closes must be a decision somebody wrote down, not a \
                         value picked off a list",
            });
        }
        // Escalation must describe something the runtime can do. Its one
        // enforceable meaning is widening the audience, so the declaration
        // has to say who is added — and every audience it would widen has to
        // be bounded, because an empty list already means *anyone* and there
        // is no wider audience than that. These mirror the coded tier's
        // refusals in `StepCtx`: which tier an agent was written in must not
        // decide whether its oversight declaration is checked.
        if o.on_expiry == Expiry::Escalate {
            if o.escalate_to.is_empty() {
                return Err(ManifestError::Unenforceable {
                    field: "spec.oversight.on_expiry",
                    detail: "'escalate' promises a wider audience and `escalate_to` names \
                             nobody — declare the roles the task widens to, or use 'deny'",
                });
            }
            if (o.approval != Approval::None || gates_a_call) && o.approvers.is_empty() {
                return Err(ManifestError::Unenforceable {
                    field: "spec.oversight.approvers",
                    detail: "'escalate' needs a bounded audience to widen, and an empty \
                             `approvers` already means anyone — name the initial reviewers, \
                             or use 'deny'",
                });
            }
            if let Some(rule) = o.triage.iter().find(|r| r.audience.is_empty()) {
                return Err(ManifestError::Syntax(format!(
                    "spec.oversight.triage: 'escalate' needs a bounded audience to widen, \
                     and triage rule '{}' declares none — name its audience, or use 'deny'",
                    rule.name
                )));
            }
        } else if !o.escalate_to.is_empty() {
            return Err(ManifestError::Unenforceable {
                field: "spec.oversight.escalate_to",
                detail: "`escalate_to` names an escalation audience, but `on_expiry` never \
                         escalates — set `on_expiry: escalate` or drop the list, so the \
                         declaration and the policy say the same thing",
            });
        }
        Ok(())
    }

    /// A grant that asks for a human needs somewhere for that request to go.
    fn validate_tool_approval(&self) -> Result<(), ManifestError> {
        let asking: Vec<&str> = self
            .spec
            .tools
            .iter()
            .filter(|grant| grant.requires_approval)
            .map(|grant| grant.reference.as_str())
            .collect();
        if asking.is_empty() {
            return Ok(());
        }
        if self.spec.oversight.is_none() {
            return Err(ManifestError::Unenforceable {
                field: "spec.tools[].requires_approval",
                detail: "a grant asks for approval but `spec.oversight` is absent, so there \
                         is nobody to ask, no window to wait in and no rule for what happens \
                         when it closes — a grant claiming a human is in the loop when none is",
            });
        }
        // The loop that would open the task is the declarative one. Beside a
        // coded skill nothing would apply this, which is the decoration the
        // whole format refuses.
        if !matches!(
            self.spec.execution.as_ref().map(|e| e.kind),
            Some(ExecutionKind::ToolCalling | ExecutionKind::Planned)
        ) {
            return Err(ManifestError::Unenforceable {
                field: "spec.tools[].requires_approval",
                detail: "per-call approval is applied by the `tool-calling` loop and the \
                         `planned` executor; a hand-written skill chooses its own moment \
                         to ask, and a `completion` agent calls no tools at all",
            });
        }
        Ok(())
    }

    /// A declared preview has to be a dry run, and a reachable one.
    ///
    /// Each refusal here is the same shape as `oversight` without `execution`:
    /// a control that reads as present in the reviewed file and would do
    /// nothing, or the opposite of what it says, at run time.
    fn validate_tool_previews(&self) -> Result<(), ManifestError> {
        for grant in &self.spec.tools {
            let Some(preview) = grant.preview.as_deref() else {
                continue;
            };
            let named = grant.reference.as_str();
            if !grant.requires_approval {
                return Err(ManifestError::Unenforceable {
                    field: "spec.tools[].preview",
                    detail: "a preview is computed to show a reviewer what a call will do, \
                             and nothing would ever call it without `requires_approval: \
                             true` — a field in the reviewed file that the runtime never \
                             reaches",
                });
            }
            if preview == named {
                return Err(ManifestError::Syntax(format!(
                    "spec.tools: '{named}' names itself as its own preview, so the dry run \
                     would be the mutation"
                )));
            }
            let Some(target) = self.spec.tools.iter().find(|g| g.reference == preview) else {
                return Err(ManifestError::Syntax(format!(
                    "spec.tools: '{named}' names the preview '{preview}', which this \
                     manifest does not grant — a call with no declared safety, no \
                     sensitivity ceiling and no protected fields"
                )));
            };
            if target.mutates {
                return Err(ManifestError::Unenforceable {
                    field: "spec.tools[].preview",
                    detail: "a preview that this manifest declares `mutates: true` is a dry \
                             run that changes the world, which is the opposite of what the \
                             field claims. Declare the preview grant `mutates: false`, or \
                             name a different tool",
                });
            }
        }
        Ok(())
    }

    /// The arrangement has to describe something.
    ///
    /// Each field here is individually fine; it is the *combination* that can
    /// describe nothing, which is why these are separate from the empty-value
    /// checks above.
    fn validate_topology(&self) -> Result<(), ManifestError> {
        let Some(t) = &self.spec.topology else {
            return Ok(());
        };
        // A specialist that may delegate is an orchestrator nobody reviewed
        // as one. This is the structural answer to the handoff loop: most
        // agents in an arrangement have no authority to hand off at all.
        if t.role == Role::Specialist
            && self
                .spec
                .security
                .max_delegation_depth
                .is_some_and(|d| d > 0)
        {
            return Err(ManifestError::IncoherentTopology {
                detail: "role 'specialist' with security.max_delegation_depth above zero \
                                 — a specialist that may hand off is an orchestrator that was \
                                 never reviewed as one",
            });
        }

        if t.mode == TopologyMode::Single && t.role != Role::Specialist {
            return Err(ManifestError::IncoherentTopology {
                detail: "mode 'single' with a role other than 'specialist' — there is \
                                 nobody to orchestrate or route to",
            });
        }

        // Collaboration costs roughly an order of magnitude more tokens and
        // opens the whole inter-agent failure surface, so the reason belongs
        // in the file where a reviewer can disagree with it.
        match (t.mode, t.reason) {
            (TopologyMode::Collaborative, None) => {
                return Err(ManifestError::IncoherentTopology {
                    detail: "mode 'collaborative' with no reason — collaboration opens a \
                                     failure surface the other modes structurally do not have, so \
                                     why it is warranted has to be in the file",
                });
            }
            (mode, Some(_)) if mode != TopologyMode::Collaborative => {
                return Err(ManifestError::IncoherentTopology {
                    detail: "a collaboration reason on a mode that is not collaborative \
                                     — a justification for something this agent does not do reads \
                                     in review as one that was required",
                });
            }
            _ => {}
        }
        Ok(())
    }

    /// Model roles, and the one combination that removes a control.
    fn validate_models(&self) -> Result<(), ManifestError> {
        // A declarative agent's whole behaviour is a model call, and the model
        // is named rather than defaulted — the runtime will not fall back to
        // some other registered driver, because that would run the agent on a
        // model its own declaration does not name. So `execution` without
        // `models.privileged` is a document that cannot ever assemble, and
        // both halves of that are on this page.
        //
        // The builder refuses it too (`BuildError::DeclarativeWithoutModel`),
        // which is not the same check twice: `Manifest`'s fields are public, so
        // a caller may construct one without going through `parse` or `build`,
        // and the builder is the backstop for that. What this adds is the
        // refusal arriving from `agentplane validate`, before a deploy, rather
        // than from whichever process first tried to assemble a plane.
        // A declarative agent's capabilities are what the runtime registers its
        // driver under, so an empty `provides` is a declaration the runtime
        // reads as "register nothing": the model, the tools and the prompt are
        // all named, and no run can ever reach them.
        if self.spec.execution.is_some() && self.spec.capabilities.provides.is_empty() {
            return Err(ManifestError::Unenforceable {
                field: "spec.capabilities.provides",
                detail: "this agent's behaviour is declared but it advertises no capability, \
                         and a declarative agent's driver is registered once per capability \
                         it provides — so nothing would be registered and no run could ever \
                         reach the model, tools and prompt named here. Name what this agent \
                         answers",
            });
        }
        if self.spec.execution.is_some()
            && self
                .spec
                .models
                .as_ref()
                .and_then(|m| m.privileged.as_ref())
                .is_none()
        {
            return Err(ManifestError::Unenforceable {
                field: "spec.execution",
                detail: "this agent's behaviour is declared, so the runtime drives it by \
                         calling a model — and no `spec.models.privileged` names one. The \
                         model is named rather than defaulted, because falling back to \
                         another registered driver would run the agent on a model its own \
                         declaration does not name, so there is nothing to call and the \
                         plane will refuse to assemble. Name a privileged model, or drop \
                         `spec.execution` and attach a coded skill instead",
            });
        }

        let Some(models) = &self.spec.models else {
            return Ok(());
        };
        for (field, m) in [
            ("spec.models.privileged", &models.privileged),
            ("spec.models.quarantined", &models.quarantined),
        ] {
            if let Some(m) = m
                && (m.provider.trim().is_empty() || m.model.trim().is_empty())
            {
                return Err(ManifestError::Empty(field));
            }
        }

        if let (Some(privileged), Some(quarantined)) = (&models.privileged, &models.quarantined)
            && privileged.provider == quarantined.provider
            && privileged.model == quarantined.model
        {
            return Err(ManifestError::Unenforceable {
                field: "spec.models.quarantined",
                detail: "the quarantined role names the same provider and model as the \
                         privileged role, so the declared dual-model isolation has only one \
                         model behind both sides",
            });
        }

        // A quarantined model nothing can select is a declared control that
        // governs nothing. Exactly two things point a model at
        // untrusted-derived content on their own: a plan's `parse` steps, and
        // memory formation. A `completion` or `tool-calling` agent with neither
        // sends every call to the privileged model, so the second role reads as
        // dual-model isolation while one model does all the work.
        if models.quarantined.is_some() {
            let kind = self.spec.execution.as_ref().map(|e| e.kind);
            let selectable = matches!(kind, Some(ExecutionKind::Planned))
                || self
                    .spec
                    .memory
                    .as_ref()
                    .is_some_and(|m| m.formation.is_some())
                // A coded skill chooses its own models, so the declaration is a
                // reviewed allowlist rather than something the tier selects
                // from — that is a different claim and a legitimate one.
                || kind.is_none();
            if !selectable {
                return Err(ManifestError::Unenforceable {
                    field: "spec.models.quarantined",
                    detail: "nothing in this declaration would ever select it: `parse` steps \
                             (execution.kind: planned) and memory formation are the only two \
                             places the declarative tier points a model at untrusted-derived \
                             content, and this agent has neither — so every call would go to \
                             the privileged model while the file reads as dual-model \
                             isolation. Use `execution.kind: planned`, declare \
                             `memory.formation`, or drop the role",
                });
            }
        }

        Ok(())
    }

    /// Triage rules, checked against the shape they claim to read.
    ///
    /// Two refusals carry the weight, and both are the same rule: a worklist
    /// nobody is filling reads exactly like one that is.
    ///
    /// * **`triage` needs `spec.output`.** The predicate is over the answer, and
    ///   an answer with no declared shape is one no reviewer can check a pointer
    ///   against — so the rule would be prose about a document nobody wrote.
    /// * **Every condition is typed against that schema.** Only where the schema
    ///   *provably* closes the door, which is deliberately narrower than a
    ///   validator would be. See [`Condition::check_against`].
    fn validate_triage(&self, rules: &[TriageRule]) -> Result<(), ManifestError> {
        if rules.is_empty() {
            return Ok(());
        }
        // No check here that `spec.execution` is present. `validate_oversight`
        // already refuses the whole block beside a coded skill, and it is the
        // only caller — a second copy would read as a control and never run,
        // which is the shape this format refuses in the documents it parses and
        // should not carry in the parser.
        let Some(schema) = self.output_schema() else {
            return Err(ManifestError::Unenforceable {
                field: "spec.oversight.triage",
                detail: "a triage rule is a predicate over the agent's answer, and this \
                         agent declares no `spec.output.schema` — so there is no shape a \
                         reviewer could check the rule's pointers against. Declare the \
                         answer's schema, or drop the rules",
            });
        };
        let mut names = std::collections::BTreeSet::new();
        for rule in rules {
            if rule.name.trim().is_empty() {
                return Err(ManifestError::Empty("spec.oversight.triage[].name"));
            }
            if rule.summary.trim().is_empty() {
                return Err(ManifestError::Empty("spec.oversight.triage[].summary"));
            }
            if rule.deadline.name.trim().is_empty() {
                return Err(ManifestError::Empty(
                    "spec.oversight.triage[].deadline.name",
                ));
            }
            if rule.deadline.kind.trim().is_empty() {
                return Err(ManifestError::Empty(
                    "spec.oversight.triage[].deadline.kind",
                ));
            }
            if !names.insert(rule.name.as_str()) {
                return Err(ManifestError::Syntax(format!(
                    "spec.oversight.triage: two rules are both named '{}' — a worklist \
                     filtered on the kind could not tell them apart",
                    rule.name
                )));
            }
            // An empty `when` matches every answer, which is a task per run
            // wearing the shape of a filter.
            if rule.when.is_empty() {
                return Err(ManifestError::Syntax(format!(
                    "spec.oversight.triage: rule '{}' has no conditions, so it matches \
                     every answer — that is a task on every run, and writing it as a rule \
                     hides the decision. State the condition, or use \
                     `approval: required` if a person really must see every answer",
                    rule.name
                )));
            }
            for condition in &rule.when {
                condition.validate().map_err(|detail| {
                    ManifestError::Syntax(format!(
                        "spec.oversight.triage: rule '{}': {detail}",
                        rule.name
                    ))
                })?;
                condition.check_against(schema).map_err(|detail| {
                    ManifestError::Syntax(format!(
                        "spec.oversight.triage: rule '{}': {detail}",
                        rule.name
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Both halves of `spec.memory`, and the tier they need.
    ///
    /// The shared refusal is the declarative one: reading and writing durable
    /// memory are behaviours the *runtime* supplies, so a block beside a coded
    /// skill is a control nothing performs.
    fn validate_memory(&self) -> Result<(), ManifestError> {
        let Some(memory) = &self.spec.memory else {
            return Ok(());
        };
        // `memory: {}` parses, digests, reviews as a memory declaration and
        // does nothing. Refused for the same reason an oversight block that
        // performs nothing is.
        if memory.is_empty() {
            return Err(ManifestError::Unenforceable {
                field: "spec.memory",
                detail: "this block declares neither `recall` nor `formation`, so it \
                         reads in review as a memory declaration and performs nothing. \
                         State one, or drop the block",
            });
        }
        if self.spec.execution.is_none() {
            return Err(ManifestError::Unenforceable {
                field: "spec.memory",
                detail: "reading and writing durable memory are behaviours the \
                         declarative tier supplies; a coded skill calls \
                         `StepCtx::recall` and `StepCtx::form_memories` at the moments \
                         it chooses, and this block would govern nothing",
            });
        }
        if let Some(recall) = &memory.recall {
            self.validate_memory_recall(recall)?;
        }
        if let Some(formation) = &memory.formation {
            self.validate_memory_formation(formation)?;
        }
        Ok(())
    }

    /// A recall reads memories **into the prompt**, which is why the execution
    /// kind matters.
    ///
    /// A `planned` agent refuses untrusted input because its plan is compiled
    /// from what the planner reads, and a recalled memory is untrusted whenever
    /// whatever wrote it was. Refused here, where both facts are on one page.
    fn validate_memory_recall(&self, recall: &MemoryRecall) -> Result<(), ManifestError> {
        if self.spec.execution.as_ref().map(|e| e.kind) == Some(ExecutionKind::Planned) {
            return Err(ManifestError::Unenforceable {
                field: "spec.memory.recall",
                detail: "a `planned` agent compiles its plan from what the planner reads \
                         and refuses untrusted input for that reason — and a recalled \
                         memory is untrusted whenever whatever wrote it was. Use \
                         `execution.kind: tool-calling`, or recall inside a `parse` \
                         step's own agent",
            });
        }
        if let MemorySubject::Literal(literal) = &recall.subject
            && literal.trim().is_empty()
        {
            return Err(ManifestError::Empty("spec.memory.recall.subject"));
        }
        if recall.purpose.as_ref().is_some_and(|p| p.trim().is_empty()) {
            return Err(ManifestError::Empty("spec.memory.recall.purpose"));
        }
        // A recall that returns nothing is not a narrower recall, it is the
        // absence of one — spelled as a number a reviewer reads as a ceiling.
        if !(1..=50).contains(&recall.limit) {
            return Err(ManifestError::Syntax(
                "spec.memory.recall.limit must be between 1 and 50 — 0 is a recall that \
                 reads nothing while reading as a ceiling, and a prompt is not the place \
                 for an unbounded corpus"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_memory_formation(&self, formation: &MemoryFormation) -> Result<(), ManifestError> {
        if self
            .spec
            .models
            .as_ref()
            .and_then(|models| models.privileged.as_ref())
            .is_none()
        {
            return Err(ManifestError::Unenforceable {
                field: "spec.memory.formation",
                detail: "formation extracts facts with a model, and this agent declares \
                         no privileged model to extract them with",
            });
        }
        for (field, value) in [
            ("spec.memory.formation.purpose", formation.purpose.as_str()),
            (
                "spec.memory.formation.instruction",
                formation.instruction.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(ManifestError::Empty(field));
            }
        }
        match &formation.subject {
            MemorySubject::Literal(literal) if literal.trim().is_empty() => {
                return Err(ManifestError::Empty("spec.memory.formation.subject"));
            }
            // Whether the run has a case is a deployment fact this document
            // cannot see — `RuntimeBuilder::try_build` refuses a plane with no
            // case store, and the run itself refuses if it was admitted without
            // correlation keys. Both are loud, and neither can be decided here.
            _ => {}
        }
        if !(1..=10).contains(&formation.max_items) {
            return Err(ManifestError::Syntax(
                "spec.memory.formation.max_items must be between 1 and 10".to_owned(),
            ));
        }
        if formation.retention_seconds == Some(0) || formation.access_retention_seconds == Some(0) {
            return Err(ManifestError::Syntax(
                "memory formation retention windows must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }

    /// A result contract that constrains nothing is not a contract.
    fn validate_output(&self) -> Result<(), ManifestError> {
        let Some(output) = &self.spec.output else {
            return Ok(());
        };
        match &output.schema {
            serde_json::Value::Object(m) if !m.is_empty() => {}
            // `{}` parses as JSON Schema and permits everything, so it
            // reads as a declared contract while promising nothing.
            serde_json::Value::Object(_) => {
                return Err(ManifestError::Empty("spec.output.schema"));
            }
            other => {
                return Err(ManifestError::NotASchema {
                    found: match other {
                        serde_json::Value::Null => "null",
                        serde_json::Value::Bool(_) => "a boolean",
                        serde_json::Value::Number(_) => "a number",
                        serde_json::Value::String(_) => "a string",
                        serde_json::Value::Array(_) => "an array",
                        serde_json::Value::Object(_) => unreachable!(),
                    },
                });
            }
        }
        Ok(())
    }

    /// The manifest format, as one JSON Schema document (draft-07).
    ///
    /// This is the *shape* of the format, generated from the same types the
    /// parser deserializes into, so it cannot drift from what `parse` accepts
    /// structurally — unknown fields, missing required fields, wrong types and
    /// wrong enum spellings all fail the schema exactly as they fail the
    /// parser. What it deliberately does **not** carry is the semantic layer:
    /// every refusal [`validate`](Self::validate) adds on top — an unbounded
    /// budget, a control nothing performs, an incoherent topology — fires only
    /// in the parser, which stays authoritative. A document the schema accepts
    /// is well-shaped, not yet well-formed.
    ///
    /// Published at the URL in its own `$id`, which is what an editor's YAML
    /// language server wants in a modeline:
    ///
    /// ```yaml
    /// # yaml-language-server: $schema=https://hupe1980.github.io/agentplane/agent.schema.json
    /// ```
    ///
    /// Descriptions are the first paragraph of each item's own documentation —
    /// one source of prose, trimmed for a hover box. `agentplane schema`
    /// prints this document; a guard test pins the published copy to it.
    #[must_use]
    pub fn json_schema() -> serde_json::Value {
        /// Where the generated schema is served from. In the document itself
        /// (`$id`), so a copy that escapes the site still names its origin.
        const SCHEMA_ID: &str = "https://hupe1980.github.io/agentplane/agent.schema.json";

        let generator = schemars::generate::SchemaSettings::draft07().into_generator();
        let mut value = serde_json::to_value(generator.into_root_schema_for::<Self>())
            .expect("a schemars-generated schema must serialize to JSON");
        trim_descriptions(&mut value);
        let root = value.as_object_mut().expect("a root schema is an object");
        root.insert(
            "$id".to_owned(),
            serde_json::Value::String(SCHEMA_ID.to_owned()),
        );
        root.insert(
            "title".to_owned(),
            serde_json::Value::String("agentplane Agent manifest".to_owned()),
        );
        root.insert(
            "description".to_owned(),
            serde_json::Value::String(
                "The shape of an agentplane Agent manifest. The crate's parser stays \
                 authoritative: this schema refuses unknown fields, missing fields, and \
                 wrong types exactly as the parser does, but the parser's semantic \
                 refusals (an unstated budget, a declared control nothing performs) run \
                 only there — `agentplane validate` is the full check."
                    .to_owned(),
            ),
        );
        value
    }

    /// What this declaration is, as a digest.
    ///
    /// Over canonical bytes, so key order and formatting cannot change it: two
    /// files that declare the same thing have the same digest, and a file that
    /// declares something different cannot share one. That is what makes
    /// "which manifest governed this run" answerable after the file has moved
    /// on.
    ///
    /// # Errors
    ///
    /// If the manifest cannot be canonicalised.
    pub fn digest(&self) -> Result<Digest, ManifestError> {
        let mut normalized = self.clone();
        normalized.normalize();
        let value =
            serde_json::to_value(normalized).map_err(|e| ManifestError::Syntax(e.to_string()))?;
        Ok(Digest::of(&canon::value_bytes(&value)))
    }

    /// Whether this manifest permits calling that model.
    ///
    /// `None` declared models means *not declared here* — the embedder wires the
    /// model in code, and this returns `true` because refusing everything would
    /// make an unset field a deny-all. A declared set is exhaustive: the whole
    /// point of naming the models is that the ones not named are refused.
    #[must_use]
    pub fn permits_model(&self, provider: &str, model: &str) -> bool {
        let Some(models) = &self.spec.models else {
            return true;
        };
        let declared = [models.privileged.as_ref(), models.quarantined.as_ref()];
        // `models: {}` declares a rules-only agent: nothing is permitted, and
        // that is the field meaning what it says rather than an oversight.
        declared
            .into_iter()
            .flatten()
            .any(|m| m.provider == provider && m.model == model)
    }

    /// The digest-covered grant for one exact tool reference.
    ///
    /// `None` is a refusal, not an absence: an empty `tools` list grants
    /// nothing, which is the same rule as an empty Cedar policy set. A security
    /// document that means "everything" when it says nothing is a document
    /// nobody can review.
    #[must_use]
    pub fn tool_grant(&self, reference: &str) -> Option<&ToolGrant> {
        self.spec.tools.iter().find(|g| g.reference == reference)
    }

    #[must_use]
    pub fn prompt_grant(&self, server: &str, name: &str) -> Option<&ContextPrompt> {
        self.spec
            .context
            .prompts
            .iter()
            .find(|grant| grant.server == server && grant.name == name)
    }

    #[must_use]
    pub fn resource_grant(&self, server: &str, uri: &str) -> Option<&ContextResource> {
        self.spec
            .context
            .resources
            .iter()
            .find(|grant| grant.server == server && grant.uri == uri)
    }

    #[must_use]
    pub fn task_input_grant(&self, server: &str) -> Option<&ContextTaskInput> {
        self.spec
            .context
            .task_input
            .iter()
            .find(|grant| grant.server == server)
    }

    /// The declared output schema, if there is one.
    ///
    /// Hand it to [`ModelCall::expecting`](crate::model::ModelCall::expecting)
    /// to put it in the effect key, which is what makes editing it a replay
    /// divergence rather than a silent reinterpretation.
    #[must_use]
    pub fn output_schema(&self) -> Option<&serde_json::Value> {
        self.spec.output.as_ref().map(|o| &o.schema)
    }

    /// The budget this manifest declares.
    #[must_use]
    pub fn budget(&self) -> Budget {
        let b = self.spec.budgets.clone().unwrap_or_default();
        Budget {
            max_steps: b.max_steps,
            max_effects: b.max_effects,
            max_tokens: b.max_tokens,
            max_minor_units: b.max_minor_units,
            max_replans: b.max_replans,
            max_wallclock_secs: b.max_wallclock_secs,
            max_denials: b.max_denials,
        }
    }
}

/// Minimal programmatic builder for a manifest.
#[derive(Debug, Clone)]
pub struct ManifestBuilder {
    metadata: Metadata,
    spec: Spec,
}

impl ManifestBuilder {
    /// Record a fact about this agent that the runtime will never read.
    ///
    /// Namespaced — `example.com/business-owner` — and covered by the digest,
    /// so changing it is a version bump. See
    /// [`Metadata::annotations`] for why an opaque map is not a hole in
    /// `deny_unknown_fields`.
    #[must_use]
    pub fn annotate(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.annotations.insert(key.into(), value.into());
        self
    }

    /// Configure the declaration body as one typed unit.
    #[must_use]
    pub fn spec(mut self, spec: Spec) -> Self {
        self.spec = spec;
        self
    }

    /// Mutate the typed declaration body without moving it out of the builder.
    #[must_use]
    pub fn configure(mut self, configure: impl FnOnce(&mut Spec)) -> Self {
        configure(&mut self.spec);
        self
    }

    /// Produce the same normalized, validated value as YAML parsing.
    pub fn build(self) -> Result<Manifest, ManifestError> {
        Manifest {
            api_version: API_VERSION.to_owned(),
            kind: KIND.to_owned(),
            metadata: self.metadata,
            spec: self.spec,
        }
        .build()
    }
}
