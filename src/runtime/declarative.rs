//! The agent that is only a file.
//!
//! Everywhere else in this crate, behaviour is a [`Skill`] somebody wrote. That
//! is the right answer when an agent does real work — a solver, a database, a
//! calculation a model cannot be trusted with. It is the wrong answer for the
//! large class of agents that are *a prompt, a model, and a result shape*,
//! because the code adds nothing a reviewer can check while removing something
//! they could: **the manifest digest then covers only part of the agent.**
//!
//! A declarative agent closes that gap. `spec.execution.kind` names a behaviour
//! this crate implements, and the runtime registers it. Nothing else is
//! written, so the digest covers the agent *in its entirety* — and unlike the
//! declarative-agent formats the field has converged on, the run is also
//! journaled and deterministically replayable.
//!
//! What is deliberately absent is control flow. There is no sequencing keyword,
//! no condition, no loop, and there will not be: config that encodes control
//! flow stops being config and becomes a poor programming language, which is the
//! lesson of every YAML workflow DSL that grew an `if`. Structure belongs in a
//! plan, which is contract-validated data.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use crate::manifest::{ExecutionKind, Identity, Manifest};
use crate::model::{ModelCall, ModelId, ModelProvider};

use super::StepCtx;

/// A skill assembled from a manifest rather than written.
///
/// It holds the provider — which is a *driver*, not a decision — and reads
/// everything else from the agent it is running as. Which model, what prompt,
/// what shape: all of it comes from `cx.manifest()`, so the file is the only
/// place any of it is decided.
#[derive(Debug)]
pub(super) struct Declarative {
    kind: ExecutionKind,
    /// The capability this agent answers, from `spec.capabilities.provides`.
    capability: String,
    name: String,
    provider: Arc<dyn ModelProvider>,
    /// The operator's catalogue and client, for a tool-calling agent.
    tools: Option<(
        Arc<crate::tools::ToolCatalog>,
        Arc<dyn crate::tools::ToolClient>,
    )>,
    /// How many model turns before this agent is stopped.
    max_turns: u32,
}

impl Declarative {
    pub(super) fn new(
        kind: ExecutionKind,
        capability: String,
        name: String,
        provider: Arc<dyn ModelProvider>,
        tools: Option<(
            Arc<crate::tools::ToolCatalog>,
            Arc<dyn crate::tools::ToolClient>,
        )>,
        max_turns: u32,
    ) -> Self {
        Self {
            kind,
            capability,
            name,
            provider,
            tools,
            max_turns,
        }
    }

    /// Call tools until the model stops asking, then answer.
    ///
    /// Its own function because the loop is the interesting part and reads
    /// badly wedged inside a match arm — and because every governance decision
    /// in it is a separate thing worth finding.
    #[allow(clippy::too_many_lines)]
    async fn tool_loop(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
        system: String,
        model_role: (ModelId, Option<u32>, Option<crate::model::ReasoningEffort>),
        egress: Option<crate::core::Sensitivity>,
        granted: Vec<crate::manifest::ToolGrant>,
    ) -> Result<Outcome, SkillError> {
        let (model, max_output_tokens, reasoning_effort) = model_role;
        let (catalog, client) = self.tools.clone().ok_or_else(|| {
            SkillError::Other(
                "this agent declares `tool-calling` but the plane has no tool \
                     catalogue — `RuntimeBuilder::tools` is what lets a declarative \
                     agent reach one"
                    .into(),
            )
        })?;

        // Offered exactly what the manifest grants, resolved through the
        // operator's catalogue. A tool granted by a manifest but absent
        // from the catalogue is not offered: the model would choose it,
        // and the call would be refused after the tokens were paid for.
        // Offered with the manifest's own words and argument shape. A bare name
        // makes the model guess, and a guess is refused at the field check after
        // it has been paid for — so the declaration is where the description
        // belongs, reviewable and covered by the digest.
        let offered: Vec<(crate::tools::ToolId, &crate::manifest::ToolGrant)> = granted
            .iter()
            .filter_map(|g| catalog.resolve_reference(&g.reference).map(|id| (id, g)))
            .collect();
        let declared: Vec<crate::model::ToolDeclaration> = offered
            .iter()
            .map(|(id, grant)| {
                let (description, arguments) = catalog.declaration(id).map_or_else(
                    || {
                        (
                            grant.description.clone().unwrap_or_default(),
                            grant
                                .arguments
                                .clone()
                                .unwrap_or_else(|| json!({ "type": "object" })),
                        )
                    },
                    |(description, arguments)| (description.to_owned(), arguments.clone()),
                );
                crate::model::ToolDeclaration::new(id.wire_name(), description, arguments)
            })
            .collect();

        // `Tainted::object`, not `input.map(...)`. The instruction comes from the
        // manifest — reviewed, and inside the digest — so it is trusted; the
        // input is whoever called us and stays whatever it arrived as. `map`
        // cannot prove how a closure reshaped a value, so it taints the whole
        // result and the *declared* instruction becomes indistinguishable from
        // the caller's data. `/system` is a protected field precisely so that
        // conflation is refused rather than obeyed.
        let prompt = Tainted::object([
            ("system".to_owned(), Tainted::trusted(json!(system))),
            ("input".to_owned(), input),
        ]);
        let mut exchanges: Vec<crate::model::ToolExchange> = Vec::new();

        for _turn in 0..self.max_turns {
            let mut call = ModelCall::new(
                Arc::clone(&self.provider),
                model.clone(),
                prompt.peek().clone(),
            )
            .with_tools(declared.clone())
            .continuing(exchanges.clone());
            if let Some(max_output_tokens) = max_output_tokens {
                call = call.with_max_output_tokens(max_output_tokens);
            }
            if let Some(effort) = reasoning_effort {
                call = call.with_reasoning_effort(effort);
            }
            if let Some(ceiling) = egress {
                call = call.with_max_sensitivity(ceiling);
            }
            let completion = cx.sink(call, &prompt).await?;

            // No tools asked for: the model is answering, and the turn
            // that answers is the last one.
            if completion.peek().tool_calls.is_empty() {
                let answer =
                    completion.map(|c| c.structured.unwrap_or_else(|| json!({ "text": c.text })));
                return Ok(Outcome::done(answer));
            }

            exchanges.clear();
            // Providers may emit several calls in one response. Execute them in
            // response order: `StepCtx` is the deterministic admission boundary
            // and cannot be borrowed concurrently without moving journal,
            // policy and budget decisions outside it. Parallel execution needs
            // an explicit runtime primitive that pre-admits an ordered batch and
            // journals completion order; spawning here would trade latency for
            // replay correctness. Callers needing concurrency should expose one
            // aggregate tool whose own implementation owns that contract.
            for asked in completion.peek().tool_calls.clone() {
                // Matched byte for byte. A name that resolves to nothing
                // is reported back as a failed call rather than ending
                // the run: the model gets to correct itself, and it never
                // gets the tool it nearly named.
                let Some(id) = catalog
                    .resolve(&asked.name)
                    .filter(|id| offered.iter().any(|(o, _)| o == id))
                else {
                    exchanges.push(crate::model::ToolExchange::failed(
                        asked,
                        "no tool of that name is granted to this agent",
                    ));
                    continue;
                };

                let prepared = crate::tools::ToolCall::prepare(
                    &catalog,
                    Arc::clone(&client),
                    id,
                    asked.arguments.clone(),
                )
                .map_err(|e| SkillError::Other(e.to_string()))?;

                // The arguments *are* part of the completion, so they carry
                // the completion's own label rather than one invented
                // here. Synthesising a label would assert a provenance
                // nothing established — and the first version of this did
                // exactly that, producing a sensitivity the model call
                // never had and a refusal nobody could explain.
                //
                // Untrusted either way, so the grant's protected fields
                // and the sink's ceiling decide, exactly as they would
                // for a skill that called the tool itself.
                let args = crate::core::Tainted::with_label(
                    asked.arguments.clone(),
                    completion.label().clone(),
                );
                match cx.sink(prepared, &args).await {
                    Ok(result) => {
                        exchanges
                            .push(crate::model::ToolExchange::ok(asked, result.peek().clone()));
                    }
                    Err(e) => match model_facing(&e) {
                        Some(detail) => {
                            exchanges.push(crate::model::ToolExchange::failed(asked, detail));
                        }
                        // Not something to tell the model and carry on. It
                        // leaves this loop the way it would leave a hand-written
                        // skill, so the executor reaches its own verdict.
                        None => return Err(e.into()),
                    },
                }
            }
        }

        // Out of turns. Reported as a failure rather than answered from
        // the last completion: an agent still asking for tools has not
        // finished, and returning its half-formed reasoning as the answer
        // is the failure that looks like success.
        Ok(Outcome::fail(format!(
            "'{}' did not finish within {} model turns — it was still asking for tools",
            self.name, self.max_turns
        )))
    }
}

#[async_trait]
impl Skill for Declarative {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.name.clone())
            .provides(crate::core::Capability::new(self.capability.clone()))
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // Read into owned values before any effect runs, so nothing borrows the
        // agent across an await.
        let (
            system,
            model,
            max_output_tokens,
            reasoning_effort,
            schema,
            egress,
            oversight,
            granted,
        ) = {
            let m = cx.manifest().ok_or_else(|| {
                // Unreachable through the builder, which only registers this
                // skill when a manifest declared it. Stated rather than
                // unwrapped: a panic here would be a runtime crash for a wiring
                // mistake, and this is a library.
                SkillError::Other(
                    "a declarative agent ran without a manifest — it has nothing to be".into(),
                )
            })?;
            let (model, max_output_tokens, reasoning_effort) = privileged(m).ok_or_else(|| {
                SkillError::Other(format!(
                    "manifest '{}' declares execution but no privileged model — a \
                     declarative agent has nothing to call",
                    m.metadata.name
                ))
            })?;
            (
                m.spec
                    .identity
                    .as_ref()
                    .map(Identity::system_prompt)
                    .unwrap_or_default(),
                model,
                max_output_tokens,
                reasoning_effort,
                m.output_schema().cloned(),
                m.spec.security.max_sensitivity_egress,
                m.spec.oversight.as_ref().map(Proposal::from_manifest),
                m.spec.tools.clone(),
            )
        };

        match self.kind {
            ExecutionKind::Completion => {
                // `Tainted::object`, not `input.map(...)`. The instruction comes from the
                // manifest — reviewed, and inside the digest — so it is trusted; the
                // input is whoever called us and stays whatever it arrived as. `map`
                // cannot prove how a closure reshaped a value, so it taints the whole
                // result and the *declared* instruction becomes indistinguishable from
                // the caller's data. `/system` is a protected field precisely so that
                // conflation is refused rather than obeyed.
                let prompt = Tainted::object([
                    ("system".to_owned(), Tainted::trusted(json!(system))),
                    ("input".to_owned(), input),
                ]);
                let mut call =
                    ModelCall::new(Arc::clone(&self.provider), model, prompt.peek().clone());
                if let Some(max_output_tokens) = max_output_tokens {
                    call = call.with_max_output_tokens(max_output_tokens);
                }
                if let Some(effort) = reasoning_effort {
                    call = call.with_reasoning_effort(effort);
                }
                if let Some(schema) = schema {
                    call = call.expecting(schema);
                }
                // The declared egress ceiling, applied to the one sink a
                // declarative agent has. Without it the call keeps `ModelCall`'s
                // conservative default of `Public`, so a declarative agent could
                // only ever handle public data — and an agent commissioned with
                // a *specialist's* answer is handling untrusted data by
                // definition, which is `Internal` at least.
                //
                // A manifest that declares no ceiling keeps the default: a
                // deployment that never said what may leave does not get to send
                // internal data because it was convenient.
                if let Some(ceiling) = egress {
                    call = call.with_max_sensitivity(ceiling);
                }

                let completion = cx.sink(call, &prompt).await?;
                // wanted — the manifest already said.
                let answer =
                    completion.map(|c| c.structured.unwrap_or_else(|| json!({ "text": c.text })));

                let Some(spec) = oversight else {
                    return Ok(Outcome::done(answer));
                };

                // A human decides before the answer leaves. The proposal shown
                // is the answer itself, not a description of it — a reviewer who
                // cannot see what will happen is not reviewing.
                let decision = cx.task(&spec.with_action(answer.peek().clone())).await?;
                if decision.approved {
                    Ok(Outcome::done(answer))
                } else {
                    // Named and quoted, because "the agent failed" is not
                    // something an operator can act on and "Carol refused,
                    // because X" is.
                    Ok(Outcome::fail(format!(
                        "{} refused this answer: {}",
                        decision.actor, decision.reason
                    )))
                }
            }

            ExecutionKind::ToolCalling => {
                self.tool_loop(
                    cx,
                    input,
                    system,
                    (model, max_output_tokens, reasoning_effort),
                    egress,
                    granted,
                )
                .await
            }
        }
    }
}

/// The declared oversight, carried as far as it can go without the answer.
///
/// A [`TaskSpec`] needs the proposal, and the proposal is what the model
/// produced — so the declarable half is built up front and the answer joined to
/// it once there is one.
#[derive(Debug, Clone)]
struct Proposal {
    approvers: Vec<String>,
    deadline: String,
    on_expiry: crate::core::OnExpiry,
    allow_unattended: bool,
}

impl Proposal {
    fn from_manifest(o: &crate::manifest::Oversight) -> Self {
        use crate::manifest::Expiry;
        Self {
            approvers: o.approvers.clone(),
            deadline: o.deadline.clone(),
            on_expiry: match o.on_expiry {
                Expiry::Deny => crate::core::OnExpiry::Deny,
                Expiry::Escalate => crate::core::OnExpiry::Escalate,
                Expiry::Proceed => crate::core::OnExpiry::Proceed,
            },
            allow_unattended: o.allow_unattended,
        }
    }

    fn with_action(&self, action: Value) -> crate::core::TaskSpec {
        let mut spec = crate::core::TaskSpec::new(
            "agent.approve",
            crate::core::Justification::new("approve this agent's answer", action),
            self.deadline.clone(),
        );
        spec.candidate_roles.clone_from(&self.approvers);
        spec.on_expiry = self.on_expiry;
        spec.allow_unattended = self.allow_unattended;
        spec
    }
}

fn privileged(
    m: &Manifest,
) -> Option<(ModelId, Option<u32>, Option<crate::model::ReasoningEffort>)> {
    let r = m.spec.models.as_ref()?.privileged.as_ref()?;
    Some((
        ModelId::new(&r.provider, &r.model),
        r.max_tokens,
        r.reasoning_effort,
    ))
}

/// What a failed tool call may tell the model, if anything.
///
/// `Some(text)` continues the loop with that text as the tool's result.
/// **`None` means the error is not the model's business and must leave the
/// loop**, so the executor reaches the verdict it would reach for a
/// hand-written skill.
///
/// This used to be `e.to_string()` for every error, which is two different
/// mistakes wearing one match arm.
///
/// # A refusal produced here is an oracle
///
/// Every [`PolicyError`](crate::core::PolicyError) message is written for an
/// operator reading a journal and is precise on purpose: which sink, which
/// field, what sensitivity, which ceiling. Handing that to a model turns the
/// policy into a queryable service — injected content varies the request,
/// watches which variants come back refused, and reads the boundary off the
/// answers. `EgressCeiling` is the sharpest: it names the *sensitivity of the
/// data*, so a few probes classify what the run was never allowed to reveal
/// without any of it crossing the boundary.
///
/// So a refusal is [`REFUSED`](crate::core::REFUSED) and nothing else. The
/// journal still keeps the full reason. `PolicyError::for_model` has said this
/// since it was written; until now nothing called it, and the one path that
/// feeds a refusal to a model used `Display`.
///
/// # An unknown outcome is not a failed call
///
/// [`StepError::Undecidable`](crate::core::StepError::Undecidable) is the
/// runtime saying it cannot tell "never applied" from "applied,
/// acknowledgement lost" — a timed-out payment may well have been taken. The
/// executor quarantines on it. Reported to the model as a failed call, the
/// quarantine never happens: the model apologises, the loop continues, and the
/// run ends **`Succeeded`** over a mutation nobody can account for. That is I5
/// inverted by an error-handling convenience.
///
/// Suspension, budget ceilings, store failures and divergence leave for the
/// same reason: each has a handler above this loop, and each is silently
/// disarmed by being turned into a chat message.
///
/// # What does reach the model
///
/// The far side's own answer, and only that. A tool that was unreachable,
/// declined the request, or ran and reported failure is information the model
/// needs in order to try something else — and it is text the far side already
/// controls, so withholding it protects nothing.
fn model_facing(e: &crate::core::StepError) -> Option<String> {
    match e {
        crate::core::StepError::Policy(p) => Some(p.for_model().to_owned()),
        // The far side spoke, or demonstrably did not — and `disposition` is
        // the crate's own name for that distinction, so this reads it rather
        // than re-deriving it from the variant list and drifting from it.
        // `InDoubt` never becomes a chat message: whether it also quarantines
        // is the recovery policy's call, made above this loop, and reporting it
        // here would take that call away.
        crate::core::StepError::Effect(inner)
            if inner.disposition() != crate::core::Disposition::InDoubt =>
        {
            Some(inner.to_string())
        }
        _ => None,
    }
}
