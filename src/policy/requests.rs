//! The request each runtime gate puts to a policy engine, built in one place.
//!
//! Three gates inside the runtime ask a [`PolicyEngine`](crate::core::PolicyEngine):
//! admission, the effect gate and the release gate. Each question is built
//! here, from values that are either journaled or supplied to whoever is
//! asking — so the live gate and an offline re-derivation over an export
//! ([`check`](super::check)) present the same request by construction rather
//! than by two authors agreeing. A second builder would be free to drift, and
//! the drift would be invisible: both would still compile and both would still
//! be asked.
//!
//! What each value is on the record:
//!
//! | input | record |
//! |---|---|
//! | run, step | every record's body |
//! | capability (the chainless principal) | `RunAdmitted.capability` |
//! | agent block | `RunAdmitted.governed_by` |
//! | chain | `IdentityBound` |
//! | effect kind, arguments | `EffectStarted.descriptor` |
//! | `mutates` | `EffectStarted.mutates` — the value the gate was asked with |
//! | outbound label | `EffectStarted.outbound_label` |
//! | release, label | `Released.release`, `Released.label` |
//! | admission input | `RunAdmitted.input` |
//! | tenant | not in any record; the checker is told it |

use serde_json::Value;

use crate::core::{
    ACTION_ADMIT, ACTION_PERFORM, ACTION_RELEASE, Delegation, Label, PolicyRequest, Release, RunId,
    StepId,
};
use crate::journal::AgentIdentity;

/// The resource every release is asked about.
pub const RELEASE_RESOURCE: &str = "information_flow.label";

/// Who is asking, as every gate inside one run states it.
///
/// The same four values at every gate of a run, so `principal == X` and
/// `context.agent.digest == Y` mean the same thing wherever a rule is
/// evaluated.
#[derive(Debug, Clone, Copy)]
pub struct Acting<'a> {
    /// The tenant the plane serves.
    pub tenant: &'a str,
    /// The capability the run was admitted for — the principal when the run
    /// acts under no chain, because it claims nothing: it is what was asked
    /// for, not who asked.
    pub capability: &'a str,
    /// The declaration governing the acting skill, when a declared one does.
    pub agent: Option<&'a AgentIdentity>,
    /// The delegation chain the run acts under.
    pub chain: Option<&'a Delegation>,
}

impl Acting<'_> {
    /// The principal every question is asked under: the chain's subject, and
    /// otherwise the admitted capability.
    #[must_use]
    pub fn principal(&self) -> &str {
        self.chain
            .map_or(self.capability, |chain| chain.subject().id.as_str())
    }
}

/// One gate's question, owned.
///
/// Owned rather than borrowed so an offline reader can hold it beside the
/// record it came from; [`as_request`](Self::as_request) is the view an engine
/// is handed.
#[derive(Debug, Clone, PartialEq)]
pub struct GatedRequest {
    pub principal: String,
    pub action: &'static str,
    pub resource: String,
    pub context: Value,
}

impl GatedRequest {
    /// The borrowed shape [`PolicyEngine::authorize`](crate::core::PolicyEngine::authorize) takes.
    #[must_use]
    pub fn as_request(&self) -> PolicyRequest<'_> {
        PolicyRequest {
            principal: &self.principal,
            action: self.action,
            resource: &self.resource,
            context: &self.context,
        }
    }
}

/// The effect gate's question about one dispatch.
///
/// `label` is present only for a call that binds a labelled value (`sink`),
/// so a rule reading it must guard on `context has label`: Cedar evaluates
/// every rule against every request, an absent attribute **errors**, and an
/// unevaluable rule refuses the call whatever it would have decided.
#[must_use]
pub fn effect(
    acting: &Acting<'_>,
    run: RunId,
    step: StepId,
    kind: &str,
    args: &Value,
    mutates: bool,
    label: Option<&Label>,
) -> GatedRequest {
    let mut context = serde_json::json!({
        "run": run.to_string(),
        "step": step.0,
        // Every request carries the tenant, not only admission: a gate that
        // knows which tenant acts at the door and forgets by the time an
        // effect reaches the world cannot express "this tenant may not call
        // that tool".
        "tenant": acting.tenant,
        "mutates": mutates,
        "args": args,
    });
    // **Where the value came from**, not only what it is: without the label a
    // deployment can say "amounts over 5000 need approval" and cannot say
    // "not with data that passed through that peer".
    if let Some(label) = label {
        context["label"] = serde_json::to_value(label).unwrap_or(Value::Null);
    }
    finish(acting, ACTION_PERFORM, kind, context)
}

/// The release gate's question about lowering one value's label.
#[must_use]
pub fn release(
    acting: &Acting<'_>,
    run: RunId,
    step: StepId,
    release: &Release,
    label: &Label,
) -> GatedRequest {
    let context = serde_json::json!({
        "run": run.to_string(),
        "step": step.0,
        "tenant": acting.tenant,
        "release": release,
        "label": label,
    });
    finish(acting, ACTION_RELEASE, RELEASE_RESOURCE, context)
}

/// The admission gate's question, asked once before a run exists.
#[must_use]
pub fn admission(acting: &Acting<'_>, input: &Value) -> GatedRequest {
    let context = serde_json::json!({ "input": input, "tenant": acting.tenant });
    finish(acting, ACTION_ADMIT, acting.capability, context)
}

/// The parts every gate adds the same way: the acting revision and the chain.
fn finish(
    acting: &Acting<'_>,
    action: &'static str,
    resource: &str,
    mut context: Value,
) -> GatedRequest {
    // **Which revision is acting.** No gate makes a manifest's name its
    // principal, because a name is whatever the author typed; rules bind to
    // `context.agent.digest` instead.
    if let Some(id) = acting.agent {
        context["agent"] = agent_context(id);
    }
    merge_identity(&mut context, acting.chain);
    GatedRequest {
        principal: acting.principal().to_owned(),
        action,
        resource: resource.to_owned(),
        context,
    }
}

/// The agent block of a policy context.
///
/// `name` is beside the digest for readability and must not be authorized on:
/// a file claims a name, but only the holder of a key can claim a publisher.
///
/// **Publisher absent, never `null`.** Most manifests are unpublished, and
/// Cedar refuses a context containing a JSON `null` — not the field, the
/// whole record. A policy asks `context.agent has publisher` and then reads it.
#[must_use]
pub fn agent_context(id: &AgentIdentity) -> Value {
    let mut agent = serde_json::json!({
        "name": id.name,
        "version": id.version,
        "digest": id.digest.to_hex(),
    });
    if let Some(value) = id
        .publisher
        .as_ref()
        .and_then(|p| serde_json::to_value(p).ok())
    {
        agent["publisher"] = value;
    }
    agent
}

/// Fold a delegation chain into a policy context object.
///
/// Merged rather than nested under a key, so a rule reads `context.owner` and
/// `context.delegation_depth` directly.
pub fn merge_identity(context: &mut Value, identity: Option<&Delegation>) {
    let (Some(chain), Some(obj)) = (identity, context.as_object_mut()) else {
        return;
    };
    if let Some(extra) = chain.as_context().as_object() {
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
        }
    }
}
