//! The plan contract.
//!
//! Validation is total and side-effect free, and it happens **before the first
//! step runs**. A plan that would fail at step seven must not begin at step one:
//! the cost of finding out early is a few microseconds of graph checking, and
//! the cost of finding out late is half an operation performed and half not.
//!
//! Each check exists because of a *measured* failure mode. Roughly four fifths
//! of observed multi-agent failures are specification and coordination problems
//! rather than model-quality problems — that is, things a graph checker can see.

mod replan;

pub use replan::{ReplanError, Replanner};

use std::collections::{BTreeMap, BTreeSet};

use crate::core::{ArgSource, Capability, Collaboration, PlanError, PlanIR, StepId, Topology};

/// What the contract is checked against.
#[derive(Debug, Clone, Default)]
pub struct Contract {
    /// Capabilities the runtime can actually provide.
    pub provided: BTreeSet<Capability>,
    /// Whether this plan must contain a verifier.
    pub require_verifier: bool,
    /// Upper bound on plan size.
    pub max_steps: Option<usize>,
}

impl Contract {
    #[must_use]
    pub fn new(provided: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            provided: provided.into_iter().collect(),
            require_verifier: false,
            max_steps: None,
        }
    }

    #[must_use]
    pub fn require_verifier(mut self) -> Self {
        self.require_verifier = true;
        self
    }

    /// Bound how many nodes a plan may hold.
    ///
    /// A validator option, not a runtime one: a run's step ceiling is
    /// [`Budget::max_steps`](crate::core::Budget::max_steps), which counts what
    /// actually executes across every version of the plan, and two ceilings of
    /// the same name would be two answers to one question. This is here for a
    /// caller checking a plan it did not write before handing it over.
    #[must_use]
    pub fn max_steps(mut self, n: usize) -> Self {
        self.max_steps = Some(n);
        self
    }
}

/// Check a plan, or explain precisely why it must not run.
///
/// Every rejection names the step and the reason, because a planner — human or
/// otherwise — can only correct a fault it can see. "Invalid plan" is not a
/// diagnosis.
pub fn validate(plan: &PlanIR, contract: &Contract) -> Result<(), PlanError> {
    if plan.nodes.is_empty() {
        return Err(PlanError::Empty);
    }
    if let Some(max) = contract.max_steps
        && plan.nodes.len() > max
    {
        return Err(PlanError::TooManySteps {
            steps: plan.nodes.len(),
            allowed: max,
        });
    }

    let mut seen = BTreeSet::new();
    for n in &plan.nodes {
        if !seen.insert(n.id) {
            return Err(PlanError::DuplicateStep(n.id));
        }
    }

    check_dependencies(plan)?;
    check_acyclic(plan)?;
    check_terminals(plan)?;
    check_capabilities(plan, contract)?;
    check_arguments(plan)?;
    check_verifiers(plan, contract)?;
    check_topology(plan)?;

    Ok(())
}

/// Every dependency must exist, or the graph is describing something that is
/// not there.
fn check_dependencies(plan: &PlanIR) -> Result<(), PlanError> {
    let ids: BTreeSet<StepId> = plan.nodes.iter().map(|n| n.id).collect();
    for n in &plan.nodes {
        for d in &n.depends_on {
            if !ids.contains(d) {
                return Err(PlanError::MissingDependency {
                    step: n.id,
                    missing: *d,
                });
            }
        }
    }
    Ok(())
}

/// Depth-first visit state.
#[derive(Clone, Copy, PartialEq)]
enum Mark {
    /// On the current path — reaching it again is a cycle.
    Open,
    /// Fully explored.
    Closed,
}

/// A cycle means the run can never finish, and would sit there looking busy.
///
/// # Why this is an explicit stack rather than recursion
///
/// The obvious depth-first walk recurses once per edge, so its stack depth is
/// the length of the longest dependency chain — a number the plan chooses. A
/// linear plan of fifty thousand nodes overflowed the stack and aborted the
/// process, and *aborted* is the operative word: a stack overflow is not a
/// `PlanError` a caller can catch and refuse, it is `SIGABRT` taking the plane
/// and every other tenant's in-flight run down with it.
///
/// [`Contract::max_steps`] does not save this, for two reasons. It is optional,
/// so the default configuration is the vulnerable one; and it is the caller's
/// declaration of how big a plan it wants, not a bound the validator may assume
/// when deciding whether it is safe to look at one. A validator whose job is to
/// refuse malformed input must survive the malformed input.
///
/// So the traversal carries its own stack on the heap, where depth costs memory
/// that fails gracefully rather than address space that does not. Node ids are
/// pushed and popped explicitly; a node is closed when its last child is done.
fn check_acyclic(plan: &PlanIR) -> Result<(), PlanError> {
    let deps: BTreeMap<StepId, &[StepId]> = plan
        .nodes
        .iter()
        .map(|n| (n.id, n.depends_on.as_slice()))
        .collect();
    let mut marks: BTreeMap<StepId, Mark> = BTreeMap::new();

    // Each frame is a node being explored and how far through its dependencies
    // the walk has got. Popping a frame is what recursion's return did.
    let mut stack: Vec<(StepId, usize)> = Vec::new();

    for root in plan.nodes.iter().map(|n| n.id) {
        if marks.get(&root) == Some(&Mark::Closed) {
            continue;
        }
        marks.insert(root, Mark::Open);
        stack.push((root, 0));

        while let Some(&mut (id, ref mut next)) = stack.last_mut() {
            let children = deps.get(&id).copied().unwrap_or(&[]);
            let Some(&child) = children.get(*next) else {
                marks.insert(id, Mark::Closed);
                stack.pop();
                continue;
            };
            *next += 1;
            match marks.get(&child) {
                Some(Mark::Closed) => {}
                // Reaching a node still on the current path closes a loop.
                // Naming the node reached, not the one that reached it, so the
                // message points at the step a reader has to break.
                Some(Mark::Open) => return Err(PlanError::Cycle(child)),
                None => {
                    marks.insert(child, Mark::Open);
                    stack.push((child, 0));
                }
            }
        }
    }
    Ok(())
}

/// Something must declare the plan finished, and every node must matter.
fn check_terminals(plan: &PlanIR) -> Result<(), PlanError> {
    if !plan.nodes.iter().any(|n| n.terminal) {
        return Err(PlanError::NoTerminal);
    }

    // A node nothing depends on, that is not terminal, is work whose result is
    // discarded — almost always a plan that meant to wire it somewhere.
    let depended: BTreeSet<StepId> = plan
        .nodes
        .iter()
        .flat_map(|n| n.depends_on.iter().copied())
        .collect();
    for n in &plan.nodes {
        if !n.terminal && !depended.contains(&n.id) {
            return Err(PlanError::Unreachable { step: n.id });
        }
    }
    Ok(())
}

/// A plan may only ask for what the runtime can do.
fn check_capabilities(plan: &PlanIR, contract: &Contract) -> Result<(), PlanError> {
    for n in &plan.nodes {
        if !contract.provided.contains(&n.capability) {
            return Err(PlanError::NoProvider {
                step: n.id,
                capability: n.capability.to_string(),
            });
        }
    }
    Ok(())
}

/// Every argument must be bound, and bound to something upstream.
///
/// An argument sourced from a node that is not a dependency would read a value
/// that may not exist yet — a race the graph is supposed to prevent.
fn check_arguments(plan: &PlanIR) -> Result<(), PlanError> {
    for n in &plan.nodes {
        if n.args.is_empty() {
            return Err(PlanError::NoArguments { step: n.id });
        }
        for (name, source) in &n.args {
            if let ArgSource::Node { step, .. } = source
                && !n.depends_on.contains(step)
            {
                return Err(PlanError::ArgumentNotUpstream {
                    step: n.id,
                    arg: name.clone(),
                    from_step: *step,
                });
            }
        }
    }
    Ok(())
}

/// A verifier must be able to see what it checks.
fn check_verifiers(plan: &PlanIR, contract: &Contract) -> Result<(), PlanError> {
    for n in plan.nodes.iter().filter(|n| n.verifies) {
        if n.depends_on.is_empty() {
            return Err(PlanError::VerifierWithoutSubject { step: n.id });
        }
    }
    if contract.require_verifier && !plan.nodes.iter().any(|n| n.verifies) {
        return Err(PlanError::VerifierRequired);
    }
    Ok(())
}

/// Collaboration must be worth what it costs.
fn check_topology(plan: &PlanIR) -> Result<(), PlanError> {
    let Topology::Collaborative(reason) = plan.topology else {
        return Ok(());
    };

    match reason {
        // Steps that read the same source are not disjoint. This is the case
        // worth catching: the coordination cost is paid, and the parallelism it
        // was paid for does not exist.
        Collaboration::ParallelDisjoint => {
            let mut sources: BTreeMap<String, StepId> = BTreeMap::new();
            for n in &plan.nodes {
                for source in n.args.values() {
                    let fingerprint = match source {
                        ArgSource::RunInput { field } => {
                            format!("input:{}", field.as_deref().unwrap_or("*"))
                        }
                        ArgSource::Node { step, field } => {
                            format!("node:{}:{}", step.0, field.as_deref().unwrap_or("*"))
                        }
                        // Constants are shared by definition and say nothing
                        // about whether the work overlaps.
                        ArgSource::Const { .. } => continue,
                    };
                    if let Some(other) = sources.insert(fingerprint, n.id)
                        && other != n.id
                    {
                        return Err(PlanError::FalseParallelism { a: other, b: n.id });
                    }
                }
            }
        }
        // Splitting for authority requires there to be authority to split.
        Collaboration::DistinctAuthority => {
            let caps: BTreeSet<&Capability> = plan.nodes.iter().map(|n| &n.capability).collect();
            if caps.len() <= 1
                && let Some(only) = caps.into_iter().next()
            {
                return Err(PlanError::NoAuthorityToSeparate {
                    capability: only.to_string(),
                });
            }
        }
    }
    Ok(())
}
