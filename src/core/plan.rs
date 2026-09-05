//! Plans — compiled artifacts, and the authorization graph.
//!
//! Whatever produced a plan — a manifest, capability routing, or a model — the
//! output is one validated [`PlanIR`], frozen and content-addressed before
//! anything runs.
//!
//! # The plan is an authorization graph
//!
//! Because a plan is compiled from *trusted* input only and frozen before any
//! untrusted data is touched, it is more than a schedule: it is a statement of
//! what this run is permitted to do, made before anything could have influenced
//! it. The journal that follows can then be checked against it.
//!
//! That check goes further than "which tools may run". Every argument declares
//! where it comes from — a named upstream node, the run's input, or a constant —
//! and the executor refuses an argument whose actual provenance does not match.
//! Labels say *how much to trust* a value; source bindings say *where it came
//! from*. Both are needed: a label alone permits substituting one untrusted
//! value for another.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{Capability, Digest, StepId, canon};

/// How many agents contribute to one task.
///
/// Declared rather than emergent, because the choice is expensive in a way that
/// is easy to make by accident: coordination between agents is the largest
/// measured failure category in multi-agent systems after specification, and it
/// is a category that *only exists if you opt into it*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Topology {
    /// One agent, one context, many tools. No inter-agent surface at all.
    #[default]
    Single,
    /// Several agents contribute to one task.
    ///
    /// Requires a justification (see [`Collaboration`]) that the plan contract
    /// checks, because the cost is real and the benefit is often assumed.
    Collaborative(Collaboration),
}

/// Why collaboration is worth its cost here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Collaboration {
    // Every justification here is one the contract can check against the
    // graph, and that is the admission rule rather than a coincidence. A
    // context-window justification is the tempting variant and is deliberately
    // absent: whether work exceeds a context window is not a property of the
    // graph, so nothing could check it — and an unchecked justification is not
    // a weak control but an *escape hatch*, since a plan refused as false
    // parallelism would be approved by editing one word, making the two real
    // checks optional for anyone who noticed. I12 leaves two choices for a
    // control nothing enforces, and this enum takes the other one.
    /// Sub-tasks operate on disjoint inputs.
    ///
    /// Checked, not taken on trust: overlapping inputs are *false parallelism*,
    /// where the coordination cost is paid and no parallelism is obtained.
    ParallelDisjoint,
    /// Sub-tasks need strictly different authority.
    ///
    /// The best reason to split agents, and the one least often named: if a
    /// sub-task needs credentials the parent should not hold, delegating to a
    /// narrower agent buys least privilege rather than hypothetical speed.
    DistinctAuthority,
}

/// Where one argument comes from.
///
/// The whole point of naming this: an argument whose actual provenance differs
/// from its declaration is refused before the effect is dispatched.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum ArgSource {
    /// The run's own input, optionally a field of it.
    RunInput {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field: Option<String>,
    },
    /// An upstream node's output, optionally a field of it.
    Node {
        step: StepId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field: Option<String>,
    },
    /// A value fixed in the plan. Trusted by construction: it was frozen before
    /// anything untrusted was read.
    Const { value: Value },
}

impl ArgSource {
    #[must_use]
    pub fn run_input() -> Self {
        Self::RunInput { field: None }
    }

    #[must_use]
    pub fn input_field(f: impl Into<String>) -> Self {
        Self::RunInput {
            field: Some(f.into()),
        }
    }

    #[must_use]
    pub fn node(step: StepId) -> Self {
        Self::Node { step, field: None }
    }

    #[must_use]
    pub fn node_field(step: StepId, f: impl Into<String>) -> Self {
        Self::Node {
            step,
            field: Some(f.into()),
        }
    }

    #[must_use]
    pub fn constant(v: Value) -> Self {
        Self::Const { value: v }
    }

    /// The node this argument depends on, if any.
    #[must_use]
    pub fn depends_on(&self) -> Option<StepId> {
        match self {
            Self::Node { step, .. } => Some(*step),
            _ => None,
        }
    }
}

/// One unit of work in a plan.
///
/// # A panel is several nodes, not a field on one
///
/// There is deliberately no `quorum` here. A panel is *k* judgements of one
/// piece of work and an aggregator that tallies them — a shape the graph
/// already expresses exactly: *k* nodes depending on the subject, each
/// [`verifies`](Self::verifies), and a terminal node depending on all of them
/// that decides with [`Quorum`](crate::core::Quorum). A field would be a second
/// spelling of it, and one the runtime cannot execute: there is no way to hand
/// a node a *lens*, so the declaration would ride inside the plan digest with
/// its behaviour living nowhere.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanNode {
    pub id: StepId,
    /// What this node needs done. Resolved against registered skills.
    pub capability: Capability,
    /// Nodes that must complete first.
    ///
    /// Structural, not conversational: a node cannot run before its
    /// predecessors' outputs are bound to its inputs, which is how "one agent
    /// ignored another's result" stops being possible rather than discouraged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<StepId>,
    /// Each argument and where it comes from.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, ArgSource>,
    /// Whether the plan is complete once this node is done.
    #[serde(default)]
    pub terminal: bool,
    /// Whether this node checks another's work.
    ///
    /// Named so the contract can require one: nothing checking the work is a
    /// fifth of observed multi-agent failures. Structural rather than
    /// advisory — a node claiming it verifies must depend on what it checks,
    /// and [`RuntimeBuilder::require_verifier`] makes "every plan carries one"
    /// a condition of admission, on a replanner's successor as much as on the
    /// plan an embedder wrote.
    ///
    /// [`RuntimeBuilder::require_verifier`]: crate::runtime::RuntimeBuilder::require_verifier
    #[serde(default)]
    pub verifies: bool,
}

impl PlanNode {
    pub fn new(id: u32, capability: impl Into<Capability>) -> Self {
        Self {
            id: StepId(id),
            capability: capability.into(),
            depends_on: Vec::new(),
            args: BTreeMap::new(),
            terminal: false,
            verifies: false,
        }
    }

    /// Bind an argument, recording the dependency it implies.
    #[must_use]
    pub fn arg(mut self, name: impl Into<String>, source: ArgSource) -> Self {
        if let Some(dep) = source.depends_on()
            && !self.depends_on.contains(&dep)
        {
            self.depends_on.push(dep);
        }
        self.args.insert(name.into(), source);
        self
    }

    #[must_use]
    pub fn after(mut self, step: u32) -> Self {
        let s = StepId(step);
        if !self.depends_on.contains(&s) {
            self.depends_on.push(s);
        }
        self
    }

    #[must_use]
    pub fn terminal(mut self) -> Self {
        self.terminal = true;
        self
    }

    #[must_use]
    pub fn verifies(mut self) -> Self {
        self.verifies = true;
        self
    }
}

/// A frozen, content-addressed plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanIR {
    pub version: u32,
    /// The plan this one replaced, if any.
    ///
    /// Replanning produces a *new version* rather than mutating in place, so the
    /// audit trail shows what the run intended before it changed its mind —
    /// usually the interesting part, and structurally absent from any system
    /// that edits a plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub topology: Topology,
    pub nodes: Vec<PlanNode>,
}

impl PlanIR {
    #[must_use]
    pub fn new(nodes: Vec<PlanNode>) -> Self {
        Self {
            version: 1,
            derived_from: None,
            reason: None,
            topology: Topology::Single,
            nodes,
        }
    }

    /// A one-step plan, for the common case of "just run this".
    #[must_use]
    pub fn single(capability: impl Into<Capability>) -> Self {
        Self::new(vec![
            PlanNode::new(0, capability)
                .arg("input", ArgSource::run_input())
                .terminal(),
        ])
    }

    /// Run several capabilities on the same input, concurrently, then feed
    /// every result to one aggregator.
    ///
    /// The shape people mean by "fan out to all the matching specialists and
    /// combine what they say", written once instead of by hand. The branches
    /// have no edge between them, so they are one ready set and are dispatched
    /// **concurrently**; the aggregator depends on all of them, so it runs when
    /// the last finishes.
    ///
    /// ```
    /// # use agentplane::core::PlanIR;
    /// let plan = PlanIR::fan_out(
    ///     ["billing.anomaly", "billing.regulatory"],
    ///     "billing.decide",
    /// );
    /// assert_eq!(plan.nodes.len(), 3);
    /// ```
    ///
    /// The aggregator receives one argument per branch, named for the
    /// capability that produced it — so adding a specialist does not silently
    /// renumber what the aggregator reads, which hand-wiring by `StepId` does.
    ///
    /// # Why this is a plan rather than an effect
    ///
    /// A `race`-style primitive — dispatch N, take the first, abandon the rest —
    /// is deliberately **not** offered. Abandoning an in-flight branch
    /// manufactures exactly the unknown outcome the effect protocol exists to
    /// prevent: the loser was announced, it may have reached a model or a tool,
    /// and cancelling it mid-flight leaves a started effect with no terminal
    /// record. Every branch here therefore runs to completion and every outcome
    /// is on the record, which costs more and is the only version that can be
    /// replayed or recovered from a crash.
    ///
    /// # Panics
    ///
    /// If `branches` is empty. A fan-out with nothing to fan out to is a
    /// one-node plan written the long way, and accepting it would produce an
    /// aggregator with no subject — the shape [`validate`](crate::plan::validate)
    /// refuses for verifiers, for the same reason.
    #[must_use]
    pub fn fan_out(
        branches: impl IntoIterator<Item = impl Into<Capability>>,
        aggregate: impl Into<Capability>,
    ) -> Self {
        let branches: Vec<Capability> = branches.into_iter().map(Into::into).collect();
        assert!(
            !branches.is_empty(),
            "a fan-out needs at least one branch; with none the aggregator has \
             nothing to aggregate"
        );

        let mut nodes: Vec<PlanNode> = branches
            .iter()
            .enumerate()
            .map(|(i, capability)| {
                PlanNode::new(u32::try_from(i).unwrap_or(u32::MAX), capability.clone())
                    .arg("input", ArgSource::run_input())
            })
            .collect();

        let join_id = u32::try_from(branches.len()).unwrap_or(u32::MAX);
        let mut join = PlanNode::new(join_id, aggregate).terminal();
        for (i, capability) in branches.iter().enumerate() {
            let step = StepId(u32::try_from(i).unwrap_or(u32::MAX));
            join = join.arg(&capability.0, ArgSource::node(step));
        }
        nodes.push(join);
        Self::new(nodes)
    }

    #[must_use]
    pub fn topology(mut self, t: Topology) -> Self {
        self.topology = t;
        self
    }

    /// Content address over the canonical form.
    ///
    /// Routed through [`canon::value_bytes`] rather than [`canon::to_bytes`],
    /// so that the *one* rule about an uncanonicalizable value lives in one
    /// place and this identity inherits it. That rule is a loud abort, and it
    /// is stated where the writer is: a fallback makes two different values
    /// hash identically, which for a plan means two different authorization
    /// graphs sharing an identity.
    ///
    /// This read `to_bytes(self).unwrap_or_default()`, which is exactly the
    /// fallback `canon` refuses — and the worst available one, because
    /// `Digest::of(&[])` is a *constant*: every plan that failed to serialize
    /// would collide with every other, under a digest that is journaled at
    /// admission and is what binds a run to what it was authorized to do. The
    /// nodes, arguments, topology and lineage would all be absent from their
    /// own content address and nothing would say so.
    ///
    /// # Panics
    ///
    /// Only if a plan cannot be serialized, which is unreachable by
    /// construction: every field is a string, an integer, an enum, a `Digest`
    /// or a `serde_json::Value`, and none of those can fail. It is written as
    /// an abort rather than trusted silently because the *reason* it is
    /// unreachable is a property of the fields, and a field added later is
    /// exactly what would change it — loudly here, invisibly before.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let value = serde_json::to_value(self)
            .expect("a plan holds only strings, integers, enums, digests and JSON values");
        Digest::of(&canon::value_bytes(&value))
    }

    #[must_use]
    pub fn node(&self, id: StepId) -> Option<&PlanNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Nodes whose dependencies are all satisfied and which have not run.
    ///
    /// Returned in a deterministic total order — topological rank, then id — so
    /// replay reproduces dispatch order exactly. Without that, a plan with any
    /// parallelism would replay differently every time.
    #[must_use]
    pub fn ready(&self, done: &BTreeSet<StepId>) -> Vec<StepId> {
        let mut ready: Vec<StepId> = self
            .nodes
            .iter()
            .filter(|n| !done.contains(&n.id))
            .filter(|n| n.depends_on.iter().all(|d| done.contains(d)))
            .map(|n| n.id)
            .collect();
        ready.sort_unstable();
        ready
    }

    /// Whether every terminal node has run.
    ///
    /// Completion is this, and only this. A workload asserting it finished is
    /// not evidence — agents announce success on unmet objectives often enough
    /// that self-report cannot be the signal.
    #[must_use]
    pub fn is_complete(&self, done: &BTreeSet<StepId>) -> bool {
        self.nodes
            .iter()
            .filter(|n| n.terminal)
            .all(|n| done.contains(&n.id))
    }
}

/// A plan that must not run, and why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    #[error("the plan has no nodes")]
    Empty,

    #[error("step {0} appears more than once")]
    DuplicateStep(StepId),

    #[error("step {step} depends on {missing}, which is not in the plan")]
    MissingDependency { step: StepId, missing: StepId },

    #[error("the plan has a dependency cycle involving {0}")]
    Cycle(StepId),

    /// Without a terminal node nothing ever declares the plan finished, and the
    /// run would either loop or stop for no stated reason.
    #[error("the plan has no terminal node, so nothing marks it complete")]
    NoTerminal,

    #[error("step {step} is unreachable: nothing depends on it and it is not terminal")]
    Unreachable { step: StepId },

    #[error("no skill provides capability '{capability}' required by step {step}")]
    NoProvider { step: StepId, capability: String },

    // Not named `source`: `thiserror` reserves that for an error cause.
    #[error("step {step} takes argument '{arg}' from {from_step}, which is not an upstream node")]
    ArgumentNotUpstream {
        step: StepId,
        arg: String,
        from_step: StepId,
    },

    #[error("step {step} has no bound arguments, so its input is undefined")]
    NoArguments { step: StepId },

    /// A verifier that could not have seen the work it claims to check.
    #[error("step {step} verifies nothing: a verifier must depend on what it checks")]
    VerifierWithoutSubject { step: StepId },

    #[error("this plan requires a verifier node and has none")]
    VerifierRequired,

    #[error(
        "collaboration claims parallel-disjoint, but steps {a} and {b} read the same source — \
         paying coordination cost for parallelism that is not there"
    )]
    FalseParallelism { a: StepId, b: StepId },

    #[error(
        "collaboration claims distinct-authority, but every step needs the same capability \
         '{capability}' — there is no authority to separate"
    )]
    NoAuthorityToSeparate { capability: String },

    #[error("the plan needs {steps} steps but the budget allows {allowed}")]
    TooManySteps { steps: usize, allowed: usize },
}
