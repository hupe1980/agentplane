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

use serde::{Deserialize, Serialize};

use crate::core::{Budget, Digest, Sensitivity, canon};

mod error;
pub use error::ManifestError;

mod registry;
pub use registry::{MemoryRegistry, Registry, RegistryError};

/// The only API group this crate understands.
pub const API_VERSION: &str = "agentplane.hupe1980.github.io/v1alpha1";

/// The only kind.
pub const KIND: &str = "Agent";

/// A parsed, validated agent declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
    /// Free-form, and compared only for equality. The crate does not parse
    /// semver: it has no version-ordering decision to make, and pretending to
    /// understand a scheme it never checks would invite one.
    pub version: String,
}

/// The declaration proper.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
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
    /// Form bounded durable facts from each declarative agent answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_formation: Option<MemoryFormation>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextGrants {
    #[serde(default)]
    pub prompts: Vec<ContextPrompt>,
    #[serde(default)]
    pub resources: Vec<ContextResource>,
}

impl ContextGrants {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prompts.is_empty() && self.resources.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPrompt {
    pub server: String,
    pub name: String,
    #[serde(default = "public_sensitivity")]
    pub max_input_sensitivity: Sensitivity,
    #[serde(default = "public_sensitivity")]
    pub output_sensitivity: Sensitivity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextResource {
    pub server: String,
    pub uri: String,
    #[serde(default = "public_sensitivity")]
    pub output_sensitivity: Sensitivity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryFormation {
    pub subject: String,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// What the agent is for, in one line.
    pub role: String,
    /// How it must behave. Kept separate from [`role`](Self::role) because the
    /// two are reviewed by different people and change on different schedules.
    #[serde(default)]
    pub constraints: String,
    /// The workload identity this agent runs as, e.g. a SPIFFE ID.
    ///
    /// Recorded, never minted: this crate does not issue identities, and a
    /// manifest that claimed one it could not prove would be worse than a
    /// manifest that stayed quiet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
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
/// **There is no condition here, and that is deliberate.** "Require approval
/// when severity is high" is a predicate, and a predicate is one step from an
/// `if` — the point where a config format stops being config. An agent whose
/// oversight depends on what it found is a skill, written in a language built
/// for decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oversight {
    /// Unconditional. The only value, because the alternative is a predicate.
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
    /// Explicit consent to act with no human when the window closes.
    ///
    /// Required for [`Expiry::Proceed`] and refused otherwise, so that acting
    /// unattended is a greppable decision somebody made rather than an enum
    /// variant they picked off a list.
    #[serde(default)]
    pub allow_unattended: bool,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// What a human decides on.
///
/// Two values, both enforced, and neither is a predicate — "require approval
/// when severity is high" is one step from an `if`, which is where a config
/// format stops being config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    ToolsOnly,
}

/// What happens when the approval window closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
/// the reviewed, digested allowlist.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Security {
    /// The highest sensitivity any value may reach an outward sink at. Combined
    /// with the sink's own ceiling at dispatch; the stricter limit wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sensitivity_egress: Option<Sensitivity>,
    /// How far authority may be re-delegated. Checked both against the runtime's
    /// configured identity and against every delegating sink before dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u8>,
}

/// What this agent offers, as capability strings.
///
/// `provides` is enforced: the plane refuses to build if a declared capability
/// has no skill behind it, and an Agent Card advertises exactly these. A twin
/// `requires` field was removed rather than left as review-only intent — it was
/// parsed, digest-covered and never checked, which is the advisory-control shape
/// I12 forbids, and its enforced meaning (does a requirement bind a plane-mate's
/// capability, a `tool://agent` grant, or a peer?) was never pinned. A build
/// check that every required capability is available on the plane is a
/// well-formed future control; until it exists, the field does not.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    #[serde(default)]
    pub provides: Vec<String>,
}

/// Ceilings, in the manifest's own vocabulary.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_steps: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_effects: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    /// Money in minor units — cents, not euros. A float here would make a
    /// budget that fails to bind by a rounding error, and money is the one
    /// number nobody accepts "approximately" for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_minor_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_replans: Option<u32>,
    /// Seconds. Named for its unit so a manifest cannot mean minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wallclock_secs: Option<u64>,
}

/// One tool this agent may call, and on what terms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolGrant {
    /// Which tool, as `tool://server/name`.
    ///
    /// Transport-neutral on purpose: the deployment's router decides whether
    /// `server` is an MCP connection or tools compiled into the binary, so this
    /// document states only what a reviewer can actually check.
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

impl Manifest {
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
        if let Some(identity) = &self.spec.identity {
            // A declared-but-blank role is the worst of both worlds: the digest
            // covers a prompt that says nothing, and a reviewer sees a field
            // that looks answered.
            if identity.role.trim().is_empty() {
                return Err(ManifestError::Empty("spec.identity.role"));
            }
        }
        self.validate_oversight()?;
        self.validate_tool_approval()?;
        self.validate_tool_grants()?;
        self.validate_agent_grants()?;
        self.validate_context_grants()?;
        self.validate_topology()?;
        self.validate_models()?;
        self.validate_output()?;
        self.validate_memory_formation()?;
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

    /// The arrangement has to describe something.
    ///
    /// Each field here is individually fine; it is the *combination* that can
    /// describe nothing, which is why these are separate from the empty-value
    /// checks above.
    /// A control nothing performs is worse than no control at all.
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
        if execution.kind != ExecutionKind::ToolCalling {
            return Ok(());
        }
        for grant in &self.spec.tools {
            if grant
                .description
                .as_ref()
                .is_none_or(|d| d.trim().is_empty())
            {
                return Err(ManifestError::Syntax(format!(
                    "spec.tools: '{}' has no description, and a `tool-calling` agent offers \
                     its tools to a model by name and description. Without one the model \
                     guesses, and a guessed call is refused at the field check after it has \
                     been paid for",
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
        // `tools-only` with nothing asking for it gates nothing at all, and
        // reads in review as oversight that is present.
        if o.approval == Approval::ToolsOnly
            && !self.spec.tools.iter().any(|grant| grant.requires_approval)
        {
            return Err(ManifestError::Unenforceable {
                field: "spec.oversight.approval",
                detail: "'tools-only' with no tool grant requesting approval gates nothing — \
                         set `requires_approval: true` on the calls a person must see, or \
                         use 'required' to gate the answer",
            });
        }
        // The same explicitness the runtime demands, demanded in the file.
        if o.on_expiry == Expiry::Proceed && !o.allow_unattended {
            return Err(ManifestError::Unenforceable {
                field: "spec.oversight.on_expiry",
                detail: "'proceed' needs `allow_unattended: true` — acting with no human when \
                         the window closes must be a decision somebody wrote down, not a \
                         value picked off a list",
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
            Some(ExecutionKind::ToolCalling)
        ) {
            return Err(ManifestError::Unenforceable {
                field: "spec.tools[].requires_approval",
                detail: "per-call approval is applied by the `tool-calling` loop; a \
                         hand-written skill chooses its own moment to ask, and a \
                         `completion` agent calls no tools at all",
            });
        }
        Ok(())
    }

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

        Ok(())
    }

    fn validate_memory_formation(&self) -> Result<(), ManifestError> {
        let Some(formation) = &self.spec.memory_formation else {
            return Ok(());
        };
        if self.spec.execution.is_none() {
            return Err(ManifestError::Unenforceable {
                field: "spec.memory_formation",
                detail: "automatic formation is implemented by declarative execution; a coded skill must call StepCtx::form_memories explicitly",
            });
        }
        if self
            .spec
            .models
            .as_ref()
            .and_then(|models| models.privileged.as_ref())
            .is_none()
        {
            return Err(ManifestError::Unenforceable {
                field: "spec.memory_formation",
                detail: "formation needs a declared privileged model",
            });
        }
        for (field, value) in [
            ("spec.memory_formation.subject", formation.subject.as_str()),
            ("spec.memory_formation.purpose", formation.purpose.as_str()),
            (
                "spec.memory_formation.instruction",
                formation.instruction.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(ManifestError::Empty(field));
            }
        }
        if !(1..=10).contains(&formation.max_items) {
            return Err(ManifestError::Syntax(
                "spec.memory_formation.max_items must be between 1 and 10".to_owned(),
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
            ..Budget::default()
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
