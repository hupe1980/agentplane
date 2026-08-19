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
use crate::model::{ModelCall, ModelProvider, ModelRole};

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
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn tool_loop(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
        remembered: Option<Tainted<Value>>,
        system: String,
        role: ModelRole,
        egress: Option<crate::core::Sensitivity>,
        granted: Vec<crate::manifest::ToolGrant>,
        oversight: Option<Proposal>,
        formation: Option<crate::manifest::MemoryFormation>,
        output_schema: Option<Value>,
    ) -> Result<Outcome, SkillError> {
        let (catalog, client) = self.tools.clone().ok_or_else(|| {
            SkillError::Other(
                "this agent declares `tool-calling` but the plane has no tool \
                     catalogue — `RuntimeBuilder::tools` is what lets a declarative \
                     agent reach one"
                    .into(),
            )
        })?;

        let (offered, declared) = offered_tools(&catalog, &granted);

        // Kept beside the prompt rather than only inside it. `$input/…` in a
        // memory subject resolves against the run's input *with its labels*, and
        // the prompt has already folded it under a `/input` key beside a trusted
        // instruction — resolving against that would make every pointer in a
        // reviewed file wrong by one level.
        let bindable_input = input.clone();

        // `Tainted::object`, not `input.map(...)`. The instruction comes from the
        // manifest — reviewed, and inside the digest — so it is trusted; the
        // input is whoever called us and stays whatever it arrived as. `map`
        // cannot prove how a closure reshaped a value, so it taints the whole
        // result and the *declared* instruction becomes indistinguishable from
        // the caller's data. `/system` is a protected field precisely so that
        // conflation is refused rather than obeyed.
        let prompt = prompt_object(&system, input, remembered);
        let mut exchanges: Vec<crate::model::ToolExchange> = Vec::new();
        let mut continuation: Option<crate::model::ProviderContinuation> = None;
        let mut conversation_label = prompt.label().clone();

        for _turn in 0..self.max_turns {
            // No `with_output_sensitivity`: the completion's floor derives
            // from the call's own egress ceiling, which is exactly the level
            // this loop used to restate by hand from the conversation label —
            // dispatch refuses a conversation above the ceiling, so the two
            // spellings could only ever agree, and the derived one cannot be
            // forgotten at the next call site.
            let outbound = prompt.with_joined_label(&conversation_label);
            let completion = cx
                .sink_with(&outbound, |value| {
                    let mut call =
                        ModelCall::new(Arc::clone(&self.provider), role.model.clone(), value)
                            .with_tools(declared.clone())
                            .continuing(exchanges.clone());
                    // The declared output shape rides on **every** turn, not
                    // only the last. Which turn answers is the model's choice,
                    // so there is no moment before dispatch at which "this is
                    // the final turn" is known — and a schema attached only
                    // where the runtime guessed the answer would land is a
                    // contract the model can step around by answering a turn
                    // early. `honour_declared_schema` exempts a completion
                    // that asks for tools, so mid-loop turns are untouched;
                    // the turn that answers is provider-constrained during
                    // generation and validated at the effect boundary, exactly
                    // as `completion` and `planned` already are. Parsed for
                    // intent is not a release state (I12): triage rules are
                    // typed against this schema, so an answer the schema never
                    // bound would put rows in a worklist that the reviewed
                    // predicate provably cannot describe.
                    if let Some(schema) = output_schema.clone() {
                        call = call.expecting(schema);
                    }
                    if let Some(state) = continuation.take() {
                        call = call.with_continuation(state);
                    }
                    call = role.applied_to(call);
                    if let Some(ceiling) = egress {
                        call = call.with_max_sensitivity(ceiling);
                    }
                    call
                })
                .await?;
            let label = completion.label().join(&conversation_label);
            let completion = Tainted::with_label(completion.into_unlabelled(), label);

            // **A cut-off turn is not a turn.**
            //
            // `Completion::truncated` says the provider stopped because it ran
            // out of output budget, and it is deliberately not an error at the
            // driver: a coded caller holding the `Completion` knows whether
            // early-stopping prose is still useful to them. Here there is no
            // such caller — this loop *is* the caller — so the judgement has to
            // be made, and made in the direction the rest of the crate takes
            // (P7): a partial result must never be shaped like a whole one.
            //
            // The two halves are separated because only one of them is
            // dangerous rather than merely wrong. A truncated turn carrying
            // tool calls has been cut somewhere inside its own output, and the
            // arguments of the last call are whatever survived the cut —
            // syntactically valid JSON that says something the model did not
            // finish saying. Executing that is not a degraded answer, it is a
            // side effect performed on a request nobody wrote, which is the
            // failure this runtime exists to make impossible.
            if completion.peek().truncated {
                let reason = if completion.peek().tool_calls.is_empty() {
                    "the model ran out of output budget mid-answer, so this is a                      partial answer and not the agent's answer — raise                      `max_output_tokens` for this role, or narrow what the agent                      is asked to produce"
                } else {
                    "the model ran out of output budget while it was still asking                      for tools, so the last call's arguments are whatever survived                      the cut — running them would act on a request the model never                      finished writing. Raise `max_output_tokens` for this role"
                };
                return Ok(Outcome::fail(reason));
            }

            // No tools asked for: the model is answering, and the turn
            // that answers is the last one.
            if completion.peek().tool_calls.is_empty() {
                let formed_source = Tainted::with_label(
                    completion
                        .peek()
                        .structured
                        .clone()
                        .unwrap_or_else(|| json!({ "text": completion.peek().text.clone() })),
                    completion.label().clone(),
                );
                let answer =
                    completion.map(|c| c.structured.unwrap_or_else(|| json!({ "text": c.text })));
                // Belt and braces beside the boundary check, the same pair
                // `planned` keeps: the provider constrained generation and the
                // effect boundary validated the completion, and the answer is
                // still checked here because what settles is *this* value —
                // an extraction step between the two would otherwise be a gap
                // the declared shape never crossed.
                if let Some(schema) = output_schema.as_ref()
                    && let Err(detail) = crate::model::validate_schema(schema, answer.peek())
                {
                    return Ok(Outcome::fail(format!(
                        "the answer does not satisfy the declared output shape: {detail}"
                    )));
                }
                // A tool-calling agent reaches oversight by the same path a
                // completion does. It did not, and the manifest said nothing
                // about that: `oversight` parsed, built and ran while no human
                // was ever asked — a declared control the runtime silently did
                // not apply, on the execution kind that most needs it, since it
                // is the one that has already touched the world by the time it
                // answers.
                return self
                    .settle(
                        cx,
                        answer,
                        formed_source,
                        &bindable_input,
                        oversight,
                        formation.as_ref(),
                        &role,
                    )
                    .await;
            }

            continuation.clone_from(&completion.peek().continuation);
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
                // The grant travels with the id: it carries whether this call
                // needs a person, and resolving it twice is one decision read
                // from two places.
                let Some((id, grant)) = catalog.resolve(&asked.name).and_then(|id| {
                    offered
                        .iter()
                        .find(|(offered, _)| *offered == id)
                        .map(|(_, grant)| (id, *grant))
                }) else {
                    exchanges.push(crate::model::ToolExchange::failed(
                        asked,
                        "no tool of that name is granted to this agent",
                    ));
                    continue;
                };

                let Some(declaration) = declared.iter().find(|tool| tool.name == asked.name) else {
                    exchanges.push(crate::model::ToolExchange::failed(
                        asked,
                        "the selected tool has no model-facing declaration",
                    ));
                    continue;
                };
                if let Err(detail) =
                    crate::model::validate_schema(&declaration.parameters, &asked.arguments)
                {
                    exchanges.push(crate::model::ToolExchange::failed(asked, detail));
                    continue;
                }

                let reference = id.reference();

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

                // A person sees the call **before** it is dispatched, when the
                // grant asks for one. Gating the agent's final answer instead
                // would be a review that arrives after the money moved: the
                // tool ran turns ago, and refusing now refuses a summary of
                // something that already happened.
                //
                // What the task carries is the exact tool and the exact
                // arguments about to be sent — not a description of them, and
                // not the answer they will produce.
                if grant.requires_approval {
                    let Some(spec) = oversight.as_ref() else {
                        // Unreachable through the parser, which refuses the
                        // pair. Stated rather than unwrapped: a panic here
                        // would be a crash for a wiring mistake.
                        return Err(SkillError::Other(
                            "a tool grant requires approval but the agent declares no                              oversight policy — there is nobody to ask"
                                .into(),
                        ));
                    };
                    cx.deadline(spec.deadline.name.clone(), &spec.deadline.spec(), None)
                        .await?;
                    let decision = cx
                        .task(&spec.approve_call(&reference, &asked.arguments))
                        .await?;
                    if !decision.approved {
                        // Reported to the model the way every other refused call
                        // is, and without the reviewer's words. A human's free
                        // text steering the next turn is untrusted content in
                        // the one slot this design keeps clean; the reason
                        // belongs in the journal, where the operator reads it.
                        exchanges.push(crate::model::ToolExchange::failed(
                            asked,
                            "a reviewer did not approve this call",
                        ));
                        continue;
                    }
                }

                // An agent consulted as a tool dispatches through `commission`,
                // never through a transport: the consultation is a journaled
                // delegation effect, so it replays without waking the
                // specialist, the label travels with the answer, the sub-run's
                // spend bills this run, and the depth ceiling sees the hop.
                // Placed **after** the approval gate above, so a grant that
                // requires a person applies to consultations exactly as it
                // does to transported calls — a reviewer sees the capability
                // and the arguments before any specialist runs.
                if id.server == crate::tools::AGENT_SERVER {
                    match cx.commission(&id.tool, args).await {
                        Ok(answer) => {
                            conversation_label = conversation_label.join(answer.label());
                            exchanges
                                .push(crate::model::ToolExchange::ok(asked, answer.peek().clone()));
                        }
                        Err(e) => match model_facing(&e) {
                            Some(detail) => {
                                exchanges.push(crate::model::ToolExchange::failed(asked, detail));
                            }
                            // Not something to tell the model and carry on —
                            // the specialist may have acted before failing, and
                            // the executor reaches its own verdict, exactly as
                            // it would for a transported call in doubt.
                            None => return Err(e.into()),
                        },
                    }
                    continue;
                }

                let dispatched = cx
                    .sink_with(&args, |value| {
                        crate::tools::ToolCall::prepare(&catalog, Arc::clone(&client), id, value)
                            .map_err(|e| {
                                crate::core::StepError::Effect(crate::core::EffectError::Rejected(
                                    e.to_string(),
                                ))
                            })
                    })
                    .await;
                match dispatched {
                    Ok(result) => {
                        conversation_label = conversation_label.join(result.label());
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

    /// Ask the human, then keep what they approved.
    ///
    /// Both execution kinds end here, and the **order** is the whole reason it
    /// is one function rather than two tails.
    ///
    /// Forming memories before the decision was a real defect, and a quiet one.
    /// A declared `oversight.approval: required` refused the answer as a *return
    /// value* while the same answer had already been written into the agent's
    /// durable memory — which a later run reads into its context window as
    /// established fact. So a rejected answer became a standing fact, and the
    /// only thing the reviewer's refusal accomplished was failing the run that
    /// produced it. Memory is delayed code; a control that governs the reply and
    /// not the write governs the less important half.
    ///
    /// It also ran when oversight *failed* for an unrelated reason — a missing
    /// case store, an expired window — so the write did not even need a rejection
    /// to survive a decision nobody made.
    #[allow(clippy::too_many_arguments)]
    async fn settle(
        &self,
        cx: &mut StepCtx<'_>,
        answer: Tainted<Value>,
        formed_source: Tainted<Value>,
        input: &Tainted<Value>,
        oversight: Option<Proposal>,
        formation: Option<&crate::manifest::MemoryFormation>,
        role: &ModelRole,
    ) -> Result<Outcome, SkillError> {
        if let Some(spec) = oversight.as_ref().filter(|s| s.gates_the_answer()) {
            // Register the obligation the wait is bounded by. A declarative
            // agent writes no code, so nothing else can — and naming an
            // unregistered obligation is what made this feature fail outright
            // in the only configuration it exists for. `register_deadline` is
            // idempotent by primary key, so a second run joining the same case
            // shares the obligation rather than colliding with it.
            cx.deadline(spec.deadline.name.clone(), &spec.deadline.spec(), None)
                .await?;
            // The proposal shown is the answer itself, not a description of it —
            // a reviewer who cannot see what will happen is not reviewing.
            let decision = cx.task(&spec.approve_answer(answer.peek().clone())).await?;
            if !decision.approved {
                // Named and quoted, because "the agent failed" is not something
                // an operator can act on and "Carol refused, because X" is.
                return Ok(Outcome::fail(format!(
                    "{} refused this answer: {}",
                    decision.actor, decision.reason
                )));
            }
        }
        self.form_answer(cx, formation, formed_source, input, role)
            .await?;
        // **After** the approval gate and after formation, for the same reason
        // formation is after the gate: a triage row raised from an answer a
        // reviewer then refused is a compliance desk acting on a finding this
        // plane retracted. Ordering it last means every row in a worklist
        // corresponds to an answer that was actually returned.
        if let Some(spec) = oversight.as_ref() {
            self.triage(cx, spec, &answer).await?;
        }
        Ok(Outcome::done(answer))
    }

    /// Open a task beside the answer for every rule that matches it.
    ///
    /// Rules are independent: two matching rules open two rows, because a
    /// breached deadline and an implausible reading are two things two different
    /// desks act on, and collapsing them would put one desk's work in the
    /// other's queue. Evaluation order is declaration order, so a worklist's
    /// arrival sequence is a property of the reviewed file rather than of a
    /// hash map.
    ///
    /// What a reviewer sees is the **answer itself**, not a description of it —
    /// a reviewer who cannot see what was found is not reviewing. It is untrusted
    /// content, deliberately: a worklist whose rows had to be trusted could only
    /// carry findings nobody needs to look at.
    async fn triage(
        &self,
        cx: &mut StepCtx<'_>,
        oversight: &Proposal,
        answer: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        for rule in oversight.triage.iter().filter(|r| r.matches(answer.peek())) {
            // Each rule's own obligation, registered by the agent for the same
            // reason the approval deadline is: a file-only agent writes no code,
            // so nothing else could register it, and a task naming an
            // unregistered obligation has no horizon.
            cx.deadline(rule.deadline.name.clone(), &rule.deadline.spec(), None)
                .await?;
            let mut spec = crate::core::TaskSpec::new(
                rule.task_kind(),
                crate::core::Justification::new(rule.summary.clone(), answer.peek().clone()),
                rule.deadline.name.clone(),
            );
            spec.candidate_roles.clone_from(&rule.audience);
            spec.priority = rule.priority.into();
            // Never `Proceed`: there is nothing to proceed past, and
            // `StepCtx::open_task` refuses it. Escalation stays available
            // because widening the audience of an unanswered row is a real
            // thing to want.
            spec.on_expiry = match oversight.on_expiry {
                crate::core::OnExpiry::Escalate => crate::core::OnExpiry::Escalate,
                _ => crate::core::OnExpiry::Deny,
            };
            cx.open_task(&spec).await?;
        }
        Ok(())
    }

    async fn form_answer(
        &self,
        cx: &mut StepCtx<'_>,
        declaration: Option<&crate::manifest::MemoryFormation>,
        answer: Tainted<Value>,
        input: &Tainted<Value>,
        role: &ModelRole,
    ) -> Result<(), SkillError> {
        let Some(declaration) = declaration else {
            return Ok(());
        };
        let subject = resolve_subject(cx, "memory.formation", &declaration.subject, input)?;
        // The extraction runs on the **quarantined** model when one is
        // declared. Formation is the dual-model pattern's quarantined job to
        // the letter — it reads content derived from untrusted input, is
        // offered no tools, and must answer in a bounded schema — so the model
        // the reviewer designated for untrusted contact is the one that should
        // be writing durable memory from it, not the one holding the agent's
        // authority. Falling back to the answer's model when no quarantined
        // role is declared keeps the single-model manifest exactly as it was.
        //
        // The **whole** role travels: `StepCtx::form_memories` applies its
        // `max_tokens` and `reasoning_effort` to the formation call, so the
        // ceilings the reviewer put beside the quarantined model govern the
        // one call the declarative tier makes on it here.
        let formation_role = match cx.manifest() {
            Some(m) => untrusted_contact_model(m, role),
            None => role.clone(),
        };
        let expires_at = if let Some(seconds) = declaration.retention_seconds {
            let now = cx.now().await?;
            Some(now + time::Duration::seconds(i64::try_from(seconds).unwrap_or(i64::MAX)))
        } else {
            None
        };
        cx.form_memories(
            crate::memory::Formation {
                subject,
                purpose: declaration.purpose.clone(),
                instruction: declaration.instruction.clone(),
                max_items: declaration.max_items,
                expires_at,
                access_retention_seconds: declaration.access_retention_seconds,
                max_sensitivity: declaration.max_sensitivity,
            },
            answer,
            Arc::clone(&self.provider),
            formation_role,
        )
        .await?;
        Ok(())
    }

    /// Read declared memories, before the prompt exists.
    ///
    /// Each item arrives as its id, purpose, content and write time — **not**
    /// its trust. Printing *"trust: untrusted"* would ask the model to
    /// adjudicate a security property from text, which is the content-inferred
    /// trust this module refuses; the label does that work at the sinks the
    /// answer later reaches.
    ///
    /// The key is present even when nothing was recalled. A prompt whose shape
    /// depends on what the store happened to hold is one no reviewer can read
    /// against the manifest.
    async fn recall_into(
        &self,
        cx: &mut StepCtx<'_>,
        memory: Option<&crate::manifest::Memory>,
        input: &Tainted<Value>,
    ) -> Result<Option<Tainted<Value>>, SkillError> {
        let Some(declaration) = memory.and_then(|m| m.recall.as_ref()) else {
            return Ok(None);
        };
        let subject = resolve_subject(cx, "memory.recall", &declaration.subject, input)?;
        let mut query = crate::memory::Recall::about(subject).limit(declaration.limit);
        if let Some(purpose) = &declaration.purpose {
            query = query.for_purpose(purpose.clone());
        }
        if declaration.refresh_access {
            query = query.refresh_access();
        }
        let recalled = cx.recall(query).await?;
        Ok(Some(Tainted::array(recalled.into_iter().map(|item| {
            item.map(|item| {
                json!({
                    "id": item.id,
                    "purpose": item.purpose,
                    "content": item.content,
                    "written_at": crate::core::format_timestamp(item.created_at),
                })
            })
        }))))
    }

    /// Plan first over trusted input, then execute without the model.
    ///
    /// The `CaMeL` shape, on this runtime's machinery: one privileged call
    /// fixes the control flow **before anything untrusted is read**, and from
    /// then on data moves between steps by *reference* — `$step0/txn/id` is
    /// resolved by the runtime with its labels intact, never pasted through a
    /// model's context. A hostile tool output therefore cannot steer the
    /// steps that follow it, and an argument bound by reference reaches the
    /// protected-field gate carrying the provenance of the value it actually
    /// names, which is what lets a rule like *recipient must come from the
    /// CRM* be genuinely satisfiable rather than laundered through a model's
    /// retyping.
    ///
    /// Everything here is an ordinary journaled effect — the planning call,
    /// each tool call, each parse — so a strict replay reassembles the whole
    /// plan without dispatching anything, which is the half of `CaMeL` their
    /// own interpreter cannot offer.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn planned(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
        system: String,
        role: ModelRole,
        egress: Option<crate::core::Sensitivity>,
        granted: Vec<crate::manifest::ToolGrant>,
        oversight: Option<Proposal>,
        formation: Option<crate::manifest::MemoryFormation>,
        output_schema: Option<Value>,
    ) -> Result<Outcome, SkillError> {
        // The plan is this run's authorization order, and the planner reads
        // the input to write it. Untrusted input authoring a plan is the
        // attacker choosing the control flow — the thing I8 refuses for
        // replanning, applied at step zero. Refused outright rather than
        // degraded: hostile content reaches a planned agent through a tool
        // or a parse step, where it arrives as data.
        if input.label().trust != crate::core::Trust::Trusted {
            return Err(SkillError::Other(
                "a `planned` agent refuses untrusted input: the plan is compiled from \
                 what the planner reads, and untrusted input authoring a plan is the \
                 attacker choosing the control flow. Hand hostile content to this \
                 agent through a tool or a parse step, or use `tool-calling`"
                    .into(),
            ));
        }

        let tools = match (granted.is_empty(), self.tools.clone()) {
            (true, _) => None,
            (false, Some(wired)) => Some(wired),
            (false, None) => {
                return Err(SkillError::Other(
                    "this agent declares `planned` with tool grants but the plane has \
                     no tool catalogue — `RuntimeBuilder::tools` is what lets a \
                     declarative agent reach one"
                        .into(),
                ));
            }
        };
        let (offered, declared) = tools
            .as_ref()
            .map(|(catalog, _)| offered_tools(catalog, &granted))
            .unwrap_or_default();

        // One planning call. The plan format travels in the response schema,
        // not in prompt text — the instruction slot stays exactly the
        // reviewed identity, and `CaMeL`'s reference implementation makes the
        // same choice: "there is no need to specify the expected output
        // format in the query itself".
        let surface: Vec<Value> = declared
            .iter()
            .map(|t| {
                json!({
                    "tool": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                })
            })
            .collect();
        let prompt = Tainted::object([
            ("system".to_owned(), Tainted::trusted(json!(system))),
            ("input".to_owned(), input.clone()),
            ("tools".to_owned(), Tainted::trusted(json!(surface))),
        ]);
        // The completion's floor derives from the egress ceiling below; see
        // the loop's model call for why nothing restates it here.
        let completion = cx
            .sink_with(&prompt, |value| {
                let mut call =
                    ModelCall::new(Arc::clone(&self.provider), role.model.clone(), value)
                        .expecting(plan_schema(self.max_turns));
                call = role.applied_to(call);
                if let Some(ceiling) = egress {
                    call = call.with_max_sensitivity(ceiling);
                }
                call
            })
            .await?;
        // Everything the planner wrote is a model completion: plan literals
        // carry this label, so a constant the planner invented arrives at
        // every gate as untrusted model output — while a *reference* carries
        // the label of the value it names.
        let plan_label = completion.label().join(prompt.label()).clone();
        let Some(plan_value) = completion.peek().structured.clone() else {
            return Ok(Outcome::fail("the planner returned no structured plan"));
        };
        let plan: PlanDoc = match serde_json::from_value(plan_value) {
            Ok(plan) => plan,
            Err(e) => {
                return Ok(Outcome::fail(format!(
                    "the planner's output is not a plan: {e}"
                )));
            }
        };
        // The schema already bounds this; checked again here because the
        // bound is a control, and a control enforced only by what a provider
        // did with a schema is a control the next driver quietly loses.
        if plan.steps.is_empty() || plan.steps.len() > self.max_turns as usize {
            return Ok(Outcome::fail(format!(
                "the plan has {} steps and this agent is bounded to {}",
                plan.steps.len(),
                self.max_turns
            )));
        }

        let mut outputs: Vec<Tainted<Value>> = Vec::new();
        for (index, step) in plan.steps.iter().enumerate() {
            match (&step.tool, &step.parse) {
                // ── A tool call, with arguments assembled by reference ────
                (Some(name), None) => {
                    let Some((catalog, client)) = tools.as_ref() else {
                        return Ok(Outcome::fail(format!(
                            "plan step {index} calls '{name}' but this agent grants no tools"
                        )));
                    };
                    // Matched byte for byte against the grants, exactly as the
                    // loop matches — a planner that names a near miss never
                    // gets the tool it nearly named, and unlike the loop there
                    // is no next turn to correct in, so the run fails.
                    let Some((id, grant)) = catalog.resolve(name).and_then(|id| {
                        offered
                            .iter()
                            .find(|(offered, _)| *offered == id)
                            .map(|(_, grant)| (id, *grant))
                    }) else {
                        // "Not granted" reads as a *policy* finding, and for a
                        // hand-written plan it is usually a *spelling* one: the
                        // grant is right there in the manifest, under the other
                        // of this tool's two names. `wire_name` renders `.` as
                        // `-`, so `tool://agent/blog.research` is
                        // `agent__blog-research` on the wire, and an author who
                        // writes the manifest reference — or the dotted
                        // `agent__blog.research` — goes looking in the policy
                        // for a mistake that is in the rendering. A planner is
                        // offered the wire names and will not hit this; a
                        // person writing a plan in a test will.
                        //
                        // Both spellings are already derived here, so the hint
                        // costs a lookup rather than a second source of truth.
                        let near_miss = offered.iter().find_map(|(id, _)| {
                            (id.reference() == *name
                                || format!("{}__{}", id.server, id.tool) == *name)
                                .then(|| (id.reference(), id.wire_name()))
                        });
                        return Ok(Outcome::fail(match near_miss {
                            Some((reference, wire)) => format!(
                                "plan step {index} calls '{name}', which is not granted to \
                                 this agent — but '{reference}' is, and a plan step names a \
                                 tool by its wire name: did you mean '{wire}'?"
                            ),
                            None => format!(
                                "plan step {index} calls '{name}', which is not granted to \
                                 this agent"
                            ),
                        }));
                    };
                    let Some(declaration) = declared.iter().find(|tool| &tool.name == name) else {
                        return Ok(Outcome::fail(format!(
                            "plan step {index}: '{name}' has no model-facing declaration"
                        )));
                    };
                    let args = step.args.clone().unwrap_or_default();
                    let assembled = match assemble_arguments(
                        &Value::Object(args),
                        &plan_label,
                        &input,
                        &outputs,
                    ) {
                        Ok(assembled) => assembled,
                        Err(why) => {
                            return Ok(Outcome::fail(format!("plan step {index}: {why}")));
                        }
                    };
                    if let Err(detail) =
                        crate::model::validate_schema(&declaration.parameters, assembled.peek())
                    {
                        return Ok(Outcome::fail(format!("plan step {index}: {detail}")));
                    }

                    let reference = id.reference();
                    // A person sees the call before dispatch when the grant
                    // asks for one — the same gate the loop applies, and a
                    // refusal fails the run because there is no model turn to
                    // report it to.
                    if grant.requires_approval {
                        let Some(spec) = oversight.as_ref() else {
                            return Err(SkillError::Other(
                                "a tool grant requires approval but the agent declares no \
                                 oversight policy — there is nobody to ask"
                                    .into(),
                            ));
                        };
                        cx.deadline(spec.deadline.name.clone(), &spec.deadline.spec(), None)
                            .await?;
                        let decision = cx
                            .task(&spec.approve_call(&reference, assembled.peek()))
                            .await?;
                        if !decision.approved {
                            return Ok(Outcome::fail(format!(
                                "{} refused the call to {reference}: {}",
                                decision.actor, decision.reason
                            )));
                        }
                    }

                    // Dispatch takes the same two paths the loop takes, and
                    // errors leave the same way — the executor reaches its own
                    // verdict, exactly as for a hand-written skill.
                    let out = if id.server == crate::tools::AGENT_SERVER {
                        cx.commission(&id.tool, assembled).await?
                    } else {
                        cx.sink_with(&assembled, |value| {
                            crate::tools::ToolCall::prepare(catalog, Arc::clone(client), id, value)
                                .map_err(|e| {
                                    crate::core::StepError::Effect(
                                        crate::core::EffectError::Rejected(e.to_string()),
                                    )
                                })
                        })
                        .await?
                    };
                    outputs.push(out);
                }

                // ── A parse: the quarantined model, a bounded schema ───────
                (None, Some(parse)) => {
                    // `args` belongs to a tool step, and a parse ignores it —
                    // so accepting one here would be a field that parses and
                    // is never read, manufacturing confidence in arguments
                    // nothing executes. Refused for the same reason the
                    // manifest refuses `routed`: what is accepted must be
                    // what runs.
                    if step.args.is_some() {
                        return Ok(Outcome::fail(format!(
                            "plan step {index} is a parse and carries `args` — a parse takes \
                             `from` and `schema`, and arguments nothing executes would be \
                             accepted prose"
                        )));
                    }
                    let source = match resolve_reference(&parse.from, &input, &outputs) {
                        Ok(source) => source,
                        Err(why) => {
                            return Ok(Outcome::fail(format!("plan step {index}: {why}")));
                        }
                    };
                    let Some(schema) = bounded_parse_schema(&parse.schema) else {
                        return Ok(Outcome::fail(format!(
                            "plan step {index}: a parse schema must be an object schema"
                        )));
                    };
                    // The whole role, ceilings included. A parse is the one
                    // call in a plan that reads hostile content, so the token
                    // ceiling and reasoning depth its declaration carries are
                    // the ones that apply here — and when no quarantined role
                    // is declared, the privileged role's own declaration
                    // governs its fallback rather than the driver default.
                    let parse_role = match cx.manifest() {
                        Some(m) => untrusted_contact_model(m, &role),
                        None => role.clone(),
                    };
                    let prompt = Tainted::object([
                        (
                            "system".to_owned(),
                            Tainted::trusted(json!(PARSE_INSTRUCTION)),
                        ),
                        ("source".to_owned(), source.clone()),
                    ]);
                    // As at the planning call: the floor derives from the
                    // egress ceiling, so nothing restates it per site.
                    let completion = cx
                        .sink_with(&prompt, |value| {
                            let mut call = ModelCall::new(
                                Arc::clone(&self.provider),
                                parse_role.model.clone(),
                                value,
                            )
                            .expecting(schema);
                            call = parse_role.applied_to(call);
                            if let Some(ceiling) = egress {
                                call = call.with_max_sensitivity(ceiling);
                            }
                            call
                        })
                        .await?;
                    let label = completion.label().join(prompt.label()).clone();
                    let Some(mut value) = completion.peek().structured.clone() else {
                        return Ok(Outcome::fail(format!(
                            "plan step {index}: the parse returned nothing structured"
                        )));
                    };
                    // The one thing a parse may say out of band, and it fails
                    // the step: a parser short of information that answers
                    // anyway produces wrong data nothing downstream can
                    // detect, which is why the escape is a bit and not a
                    // message — a message would be untrusted text steering
                    // the plan.
                    let enough = value
                        .get("have_enough_information")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if !enough {
                        return Ok(Outcome::fail(format!(
                            "plan step {index}: the parse declared the source does not \
                             contain enough information — the plan must hand it more of \
                             the source, not let a guess stand"
                        )));
                    }
                    if let Some(map) = value.as_object_mut() {
                        map.remove("have_enough_information");
                    }
                    // Schema-shaped is not trusted. The output joins the
                    // source's label with the completion's, so it stays as
                    // untrusted as the text it came from.
                    outputs.push(Tainted::with_label(value, label));
                }

                _ => {
                    return Ok(Outcome::fail(format!(
                        "plan step {index} must name exactly one of `tool` or `parse`"
                    )));
                }
            }
        }

        let answer = match plan.answer.as_deref() {
            Some(reference) => match resolve_reference(reference, &input, &outputs) {
                Ok(answer) => answer,
                Err(why) => return Ok(Outcome::fail(format!("plan answer: {why}"))),
            },
            None => match outputs.last() {
                Some(last) => last.clone(),
                None => return Ok(Outcome::fail("the plan produced nothing to answer with")),
            },
        };
        if let Some(schema) = output_schema
            && let Err(detail) = crate::model::validate_schema(&schema, answer.peek())
        {
            return Ok(Outcome::fail(format!(
                "the answer does not satisfy the declared output shape: {detail}"
            )));
        }

        let formed_source = answer.clone();
        self.settle(
            cx,
            answer,
            formed_source,
            &input,
            oversight,
            formation.as_ref(),
            &role,
        )
        .await
    }
}

#[allow(clippy::too_many_lines)]
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
        let (system, role, schema, egress, oversight, granted, memory) = {
            let m = cx.manifest().ok_or_else(|| {
                // Unreachable through the builder, which only registers this
                // skill when a manifest declared it. Stated rather than
                // unwrapped: a panic here would be a runtime crash for a wiring
                // mistake, and this is a library.
                SkillError::Other(
                    "a declarative agent ran without a manifest — it has nothing to be".into(),
                )
            })?;
            let role = privileged(m).ok_or_else(|| {
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
                role,
                m.output_schema().cloned(),
                m.spec.security.max_sensitivity_egress,
                m.spec.oversight.as_ref().map(Proposal::from_manifest),
                m.spec.tools.clone(),
                m.spec.memory.clone(),
            )
        };
        let formation = memory.as_ref().and_then(|m| m.formation.clone());
        // Before the prompt is assembled, because that is what a recall is
        // *for*: the memories are part of what the model is asked, not
        // something it is told afterwards.
        //
        // Not attempted under `planned`, rather than attempted and discarded:
        // a recall is a journaled store read. The refusal itself lives at
        // parse, where a reviewer meets it.
        let remembered = match self.kind {
            ExecutionKind::Planned => None,
            _ => self.recall_into(cx, memory.as_ref(), &input).await?,
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
                // See `tool_loop`: a subject binding resolves against the run's
                // own input, not against the prompt object it is folded into.
                let bindable_input = input.clone();
                let prompt = prompt_object(&system, input, remembered);
                // The completion's floor derives from the egress ceiling
                // applied below; see the tool loop's model call for why
                // nothing restates it here.
                let completion = cx
                    .sink_with(&prompt, |value| {
                        let mut call =
                            ModelCall::new(Arc::clone(&self.provider), role.model.clone(), value);
                        call = role.applied_to(call);
                        if let Some(schema) = schema {
                            call = call.expecting(schema);
                        }
                        // The declared egress ceiling, applied to the one sink
                        // a declarative agent has. Without it the call keeps
                        // `ModelCall`'s conservative default of `Public`, so a
                        // declarative agent could only ever handle public data
                        // — and an agent commissioned with a *specialist's*
                        // answer is handling untrusted data by definition,
                        // which is `Internal` at least.
                        //
                        // A manifest that declares no ceiling keeps the
                        // default: a deployment that never said what may leave
                        // does not get to send internal data because it was
                        // convenient.
                        if let Some(ceiling) = egress {
                            call = call.with_max_sensitivity(ceiling);
                        }
                        call
                    })
                    .await?;
                let label = completion.label().join(prompt.label());
                let completion = Tainted::with_label(completion.into_unlabelled(), label);
                let formed_source = Tainted::with_label(
                    completion
                        .peek()
                        .structured
                        .clone()
                        .unwrap_or_else(|| json!({ "text": completion.peek().text.clone() })),
                    completion.label().clone(),
                );
                // wanted — the manifest already said.
                let answer =
                    completion.map(|c| c.structured.unwrap_or_else(|| json!({ "text": c.text })));

                self.settle(
                    cx,
                    answer,
                    formed_source,
                    &bindable_input,
                    oversight,
                    formation.as_ref(),
                    &role,
                )
                .await
            }

            ExecutionKind::ToolCalling => {
                self.tool_loop(
                    cx, input, remembered, system, role, egress, granted, oversight, formation,
                    schema,
                )
                .await
            }

            ExecutionKind::Planned => {
                self.planned(
                    cx, input, system, role, egress, granted, oversight, formation, schema,
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
    approval: crate::manifest::Approval,
    approvers: Vec<String>,
    deadline: crate::manifest::OversightDeadline,
    on_expiry: crate::core::OnExpiry,
    allow_unattended: bool,
    /// Rules that open a task *beside* the answer rather than in front of it.
    triage: Vec<crate::manifest::TriageRule>,
}

impl Proposal {
    fn from_manifest(o: &crate::manifest::Oversight) -> Self {
        use crate::manifest::Expiry;
        Self {
            approval: o.approval,
            approvers: o.approvers.clone(),
            deadline: o.deadline.clone(),
            on_expiry: match o.on_expiry {
                Expiry::Deny => crate::core::OnExpiry::Deny,
                Expiry::Escalate => crate::core::OnExpiry::Escalate,
                Expiry::Proceed => crate::core::OnExpiry::Proceed,
            },
            allow_unattended: o.allow_unattended,
            triage: o.triage.clone(),
        }
    }

    /// Whether the final answer waits, as opposed to only the calls that ask.
    const fn gates_the_answer(&self) -> bool {
        matches!(self.approval, crate::manifest::Approval::Required)
    }

    /// The task shown when a reviewer must approve the agent's **answer**.
    fn approve_answer(&self, answer: Value) -> crate::core::TaskSpec {
        self.task("agent.approve", "approve this agent's answer", answer)
    }

    /// The task shown when a reviewer must approve a **tool call**.
    ///
    /// A separate summary, and separate because the two are different
    /// questions: one asks *may this reply go out*, the other *may this call
    /// happen*. A reviewer told "approve this agent's answer" while the thing
    /// in front of them moves money is being asked to vet the wrong artifact —
    /// the exact conflation `oversight.approval: tools-only` exists to
    /// prevent, reintroduced in the sentence the reviewer actually reads.
    fn approve_call(&self, reference: &str, arguments: &Value) -> crate::core::TaskSpec {
        self.task(
            "agent.approve_call",
            format!("approve this agent's call to {reference}"),
            json!({ "tool": reference, "arguments": arguments }),
        )
    }

    fn task(&self, kind: &str, summary: impl Into<String>, action: Value) -> crate::core::TaskSpec {
        let mut spec = crate::core::TaskSpec::new(
            kind,
            crate::core::Justification::new(summary, action),
            self.deadline.name.clone(),
        );
        spec.candidate_roles.clone_from(&self.approvers);
        spec.on_expiry = self.on_expiry;
        spec.allow_unattended = self.allow_unattended;
        spec
    }
}

/// The fixed instruction a `parse` step's model receives.
///
/// A constant, never planner text: a planner's output is a model completion
/// and therefore untrusted, and `/system` is the trusted slot — so the one
/// instruction a parse runs under is written here, exactly as `CaMeL`'s
/// reference implementation fixes its quarantined model's prompt as a
/// constant. Anti-fabrication is the load-bearing sentence: a parser that
/// guesses an address produces wrong data nothing downstream can detect.
const PARSE_INSTRUCTION: &str = "Extract the requested fields from the source. Record only \
     what the source literally states: do not infer or invent email addresses, dates, \
     identifiers, names or amounts that are not present. If the source does not contain \
     enough information, set `have_enough_information` to false and every other field to \
     an empty or zero value.";

/// The shape a planner must answer in.
///
/// The plan format lives here, in the response schema, rather than in prompt
/// text — so the instruction slot stays exactly the reviewed identity, and the
/// format is versioned in code where changing it is a diff. The step bound is
/// the manifest's `max_turns`, the same ceiling the loop spends per turn.
fn plan_schema(max_steps: u32) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["steps"],
        "properties": {
            "steps": {
                "type": "array",
                "minItems": 1,
                "maxItems": max_steps,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "tool": {
                            "type": "string",
                            "description": "a granted tool to call, named exactly as offered"
                        },
                        "args": {
                            "type": "object",
                            "description": "the tool's arguments. A string beginning with '$' \
                                 is a reference to earlier data, not a literal: '$input' is \
                                 the run's input and '$step0' is the first step's output, \
                                 and a JSON Pointer may follow the head, e.g. \
                                 '$step1/customer/email'. Escape a literal leading '$' as \
                                 '$$'. Prefer references over copying values: a reference \
                                 carries the data's provenance, a copy does not"
                        },
                        "parse": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["from", "schema"],
                            "properties": {
                                "from": {
                                    "type": "string",
                                    "description": "reference to the value to extract from, \
                                         e.g. '$step0/body'"
                                },
                                "schema": {
                                    "type": "object",
                                    "description": "a JSON Schema with type 'object' naming \
                                         the fields to extract"
                                }
                            },
                            "description": "extract structured fields from a prior output \
                                 instead of calling a tool"
                        }
                    }
                }
            },
            "answer": {
                "type": "string",
                "description": "reference selecting the run's answer, e.g. '$step1/summary'; \
                     omitted means the last step's output"
            }
        }
    })
}

/// A plan as the planner wrote it, deserialised strictly.
///
/// `deny_unknown_fields` beside the schema validation, because two layers of
/// refusal cost nothing and a field that parses but is never read is the
/// defect class this crate keeps finding in other people's formats.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanDoc {
    steps: Vec<PlanStep>,
    #[serde(default)]
    answer: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanStep {
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    args: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    parse: Option<ParseStep>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ParseStep {
    from: String,
    schema: Value,
}

/// Resolve a `$input` / `$stepN` reference, labels intact.
///
/// The pointer after the head is RFC 6901, the same spelling the label
/// machinery uses, so the projected value arrives with the label of exactly
/// the field it names — which is the entire point of a reference: a value
/// that travelled by name keeps the provenance a model's retyping would have
/// stripped.
fn resolve_reference(
    reference: &str,
    input: &Tainted<Value>,
    outputs: &[Tainted<Value>],
) -> Result<Tainted<Value>, String> {
    let (head, pointer) = match reference.find('/') {
        Some(split) => (&reference[..split], &reference[split..]),
        None => (reference, ""),
    };
    let base = if head == "$input" {
        input
    } else {
        let step = head
            .strip_prefix("$step")
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| {
                format!(
                    "'{reference}' is not a reference this plan can hold — use $input \
                     or $step<N>"
                )
            })?;
        outputs
            .get(step)
            .ok_or_else(|| format!("'{reference}' points at a step that has not run yet"))?
    };
    base.project_pointer(pointer)
        .ok_or_else(|| format!("'{reference}' selects nothing in the value it points at"))
}

/// Assemble a step's arguments, resolving references wherever they appear.
///
/// Literals carry the **plan's** label — they are model output, and arrive at
/// every gate as exactly that. References carry the label of the value they
/// name. Objects and arrays are rebuilt with [`Tainted::object`] /
/// [`Tainted::array`], so the distinction survives per field all the way to
/// the sink binding.
fn assemble_arguments(
    value: &Value,
    plan_label: &crate::core::Label,
    input: &Tainted<Value>,
    outputs: &[Tainted<Value>],
) -> Result<Tainted<Value>, String> {
    match value {
        Value::String(s) if s.starts_with("$$") => Ok(Tainted::with_label(
            Value::String(s[1..].to_owned()),
            plan_label.clone(),
        )),
        Value::String(s) if s.starts_with('$') => resolve_reference(s, input, outputs),
        Value::Object(map) => {
            let mut fields = Vec::with_capacity(map.len());
            for (name, nested) in map {
                fields.push((
                    name.clone(),
                    assemble_arguments(nested, plan_label, input, outputs)?,
                ));
            }
            Ok(Tainted::object(fields))
        }
        Value::Array(items) => {
            let mut elements = Vec::with_capacity(items.len());
            for nested in items {
                elements.push(assemble_arguments(nested, plan_label, input, outputs)?);
            }
            Ok(Tainted::array(elements))
        }
        other => Ok(Tainted::with_label(other.clone(), plan_label.clone())),
    }
}

/// A parse schema with the runtime's escape bit injected, or `None` if the
/// planner's schema is not an object schema.
///
/// `have_enough_information` is added by the runtime, never by the planner,
/// and `additionalProperties` is forced closed — a parse is bounded or it is
/// not a parse. Mirrors `CaMeL`'s reference implementation, which injects the
/// same field with `create_model` for the same reason: a model short of
/// information that answers anyway produces wrong data nothing can detect.
fn bounded_parse_schema(declared: &Value) -> Option<Value> {
    if declared.get("type") != Some(&json!("object")) {
        return None;
    }
    let mut schema = declared.clone();
    let map = schema.as_object_mut()?;
    map.insert("additionalProperties".to_owned(), json!(false));
    let properties = map
        .entry("properties")
        .or_insert_with(|| json!({}))
        .as_object_mut()?;
    properties.insert(
        "have_enough_information".to_owned(),
        json!({
            "type": "boolean",
            "description": "Whether the source provided enough information. Set false \
                 rather than inventing any value."
        }),
    );
    let required = map.entry("required").or_insert_with(|| json!([]));
    let required = required.as_array_mut()?;
    if !required.contains(&json!("have_enough_information")) {
        required.push(json!("have_enough_information"));
    }
    Some(schema)
}

/// The object a declarative agent's model call is given.
///
/// `Tainted::object`, not `input.map(..)`. The instruction comes from the
/// manifest — reviewed, and inside the digest — so it is trusted; the input
/// stays whatever it arrived as; each recalled memory keeps the label it was
/// written with. `map` cannot prove how a closure reshaped a value, so it
/// taints the whole result and the declared instruction becomes
/// indistinguishable from the caller's data. `/system` is a protected field
/// precisely so that conflation is refused rather than obeyed.
///
/// A memory subject binding resolves against the run's **own** input, never
/// against this object — a pointer in a reviewed file must not be wrong by one
/// level because the runtime folded the input under a key.
fn prompt_object(
    system: &str,
    input: Tainted<Value>,
    remembered: Option<Tainted<Value>>,
) -> Tainted<Value> {
    let mut parts = vec![
        ("system".to_owned(), Tainted::trusted(json!(system))),
        ("input".to_owned(), input),
    ];
    if let Some(remembered) = remembered {
        parts.push(("memory".to_owned(), remembered));
    }
    Tainted::object(parts)
}

/// Resolve a declared memory subject for this run, for the field that declared
/// it.
///
/// # Every refusal here is the same refusal
///
/// A subject decides which pile a durable fact lands in, and the pile is the
/// unit an erasure request names. Resolving one wrongly does not fail loudly at
/// the time — it files a customer's facts under somebody else's key, where they
/// are recalled into that person's next run and survive their own erasure. So
/// every case this cannot answer exactly is a run that fails, and none is
/// answered with a fallback.
///
/// The trust rule is the one worth stating twice. `$input/…` is refused unless
/// the field it names is **trusted**, because a subject taken from untrusted
/// input is the attacker choosing whose file to write into — a strictly worse
/// outcome than the pooling a binding exists to fix. Correlation keys and the
/// case id need no such check: correlation is a deterministic lookup performed
/// at admission from keys an operator's edge supplied, and the case id is the
/// runtime's own.
fn resolve_subject(
    cx: &StepCtx<'_>,
    field: &str,
    subject: &crate::manifest::MemorySubject,
    input: &Tainted<Value>,
) -> Result<String, SkillError> {
    use crate::manifest::MemorySubject;

    let refuse = SkillError::Other;
    match subject {
        MemorySubject::Literal(literal) => Ok(literal.clone()),
        MemorySubject::Case => cx.case_id().map(|id| id.to_string()).ok_or_else(|| {
            refuse(format!(
                "`{field}.subject: $case` needs the run to belong to a case, and \
                 this run has none. Admit it with `run_correlated(..)` or `run_in_case(..)` \
                 — filing the memory under a constant instead would pool every matter's \
                 facts under one key"
            ))
        }),
        MemorySubject::Correlation(namespace) => cx
            .correlation_value(namespace)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                let held: Vec<&str> = cx
                    .correlation()
                    .iter()
                    .map(|key| key.namespace.as_str())
                    .collect();
                refuse(format!(
                    "`{field}.subject: $correlation/{namespace}` found no key in \
                     that namespace; this run's case is keyed by {held:?}. A memory filed \
                     under the wrong scope is recalled into another subject's run and \
                     survives that subject's erasure, so the run fails rather than \
                     guessing"
                ))
            }),
        MemorySubject::Input(pointer) => {
            let selected = input.project_pointer(pointer).ok_or_else(|| {
                refuse(format!(
                    "`{field}.subject: $input{pointer}` selects nothing in this \
                     run's input"
                ))
            })?;
            if selected.label().trust != crate::core::Trust::Trusted {
                return Err(refuse(format!(
                    "`{field}.subject: $input{pointer}` names an **untrusted** \
                     field, and a subject taken from untrusted input lets whoever supplied \
                     it choose whose memories this run writes into. Bind the subject to a \
                     correlation key instead — those are settled at admission by a \
                     deterministic lookup — or release the field explicitly if it really is \
                     the plane's own"
                )));
            }
            match selected.peek() {
                Value::String(value) if !value.trim().is_empty() => Ok(value.clone()),
                Value::Number(value) => Ok(value.to_string()),
                other => Err(refuse(format!(
                    "`{field}.subject: $input{pointer}` selects {}, and a subject \
                     is a scope name — it must be a non-empty string or a number",
                    match other {
                        Value::String(_) => "an empty string",
                        Value::Null => "null",
                        Value::Bool(_) => "a boolean",
                        Value::Array(_) => "an array",
                        Value::Object(_) => "an object",
                        Value::Number(_) => unreachable!("numbers are accepted above"),
                    }
                ))),
            }
        }
    }
}

/// The role for untrusted contact: the quarantined role when one is declared,
/// the given fallback otherwise.
///
/// One implementation, consulted by memory formation and by a plan's `parse`
/// steps — the two places the declarative tier itself points a model at
/// untrusted-derived content.
///
/// The **whole** role, not only its model id. `max_tokens` and
/// `reasoning_effort` are declared per role for a reason a quarantined model
/// makes concrete: the role that reads hostile content is the one whose output
/// most needs a ceiling somebody reviewed. Returning the id alone parsed those
/// two fields into the digest and then dropped them — a declared control the
/// runtime silently did not apply (I12), found the way that shape always is,
/// by following the value rather than the field. The fallback is a role too,
/// so a manifest with no quarantined model keeps the privileged declaration's
/// own ceilings instead of quietly reverting to the driver default.
fn untrusted_contact_model(m: &Manifest, fallback: &ModelRole) -> ModelRole {
    m.quarantined_role().unwrap_or_else(|| fallback.clone())
}

/// The tool surface a declarative agent offers a model: exactly the manifest's
/// grants, resolved through the operator's catalogue, with the declared
/// descriptions and argument shapes.
///
/// A tool granted by a manifest but absent from the catalogue is not offered:
/// the model would choose it, and the call would be refused after the tokens
/// were paid for. Offered with the manifest's own words and argument shape —
/// a bare name makes the model guess, and a guess is refused at the field
/// check after it has been paid for, so the declaration is where the
/// description belongs, reviewable and covered by the digest. One
/// implementation for the loop and the planner, because two copies of the
/// offer rule would agree everywhere except the grant nobody probed.
fn offered_tools<'g>(
    catalog: &crate::tools::ToolCatalog,
    granted: &'g [crate::manifest::ToolGrant],
) -> (
    Vec<(crate::tools::ToolId, &'g crate::manifest::ToolGrant)>,
    Vec<crate::model::ToolDeclaration>,
) {
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
    (offered, declared)
}

fn privileged(m: &Manifest) -> Option<ModelRole> {
    m.privileged_role()
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
