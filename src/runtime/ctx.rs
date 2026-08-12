//! [`StepCtx`] — the only door out of a skill.
//!
//! Everything non-deterministic or externally visible passes through here, and
//! that is what makes replay sound. A skill holds no clock, no socket, and no
//! RNG of its own; it holds a context that journals.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde_json::Value;

use crate::case::{CaseStore, EventStore, TaskStore, TimerStore};
use crate::core::{
    AwaitSpec, Calendar, CaseId, CaseStatus, CaseVersion, CorrelationKey, Deadline, DeadlineSpec,
    DeadlineState, Decision, Effect, EffectDescriptor, EffectKey, Epoch, Ledger, OnExpiry, Phase,
    PolicyError, RunId, StepError, StepId, Subscription, Tainted, Task, TaskId, TaskSpec,
    TaskState, Timestamp, canon,
};

/// The event kind a decision arrives as.
///
/// Human tasks reuse the durable-wait machinery wholesale: completing a task
/// delivers an event of this kind correlated to the task id, and the waiting run
/// resumes exactly as it would for any other message.
pub(crate) const TASK_DECIDED: &str = "agentplane.task.decided";
use crate::journal::{Append, EffectReplay, JournalStore, RecordKind, StepCursor};

use super::effects::{Clock, ResolveDeadline};
use super::metrics;
use super::telemetry;
use tracing::Instrument;

/// The case-facing services a step may reach, when the runtime has them.
#[derive(Clone)]
pub(crate) struct CaseContext {
    pub cases: Arc<dyn CaseStore>,
    /// Only human tasks need this.
    pub tasks: Option<Arc<dyn TaskStore>>,
    /// Only durable waits need this. Correlation, state, and obligations work
    /// without it, so a runtime that never waits is not made to configure one.
    pub events: Option<Arc<dyn EventStore>>,
    pub calendar: Arc<dyn Calendar>,
    pub case_id: CaseId,
    /// The case's business keys as recorded at binding.
    ///
    /// Carried on the context rather than fetched on demand because a fetch is
    /// a store read, and a store read inside the deterministic zone is exactly
    /// the non-determinism the effect protocol exists to forbid — a key added
    /// to the case next month would change what a replayed run resolves. The
    /// journal's `CaseBound` record is the source on both the live and the
    /// resumed path.
    pub correlation: Vec<crate::core::CorrelationKey>,
}

impl CaseContext {
    pub(crate) fn id(&self) -> CaseId {
        self.case_id
    }
}

impl std::fmt::Debug for CaseContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaseContext")
            .field("case_id", &self.case_id)
            .finish_non_exhaustive()
    }
}

/// How a step is being executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Normal execution: effects are performed and journaled.
    Live,
    /// Re-execution from history. Effects are read back, never performed.
    ///
    /// When the cursor runs out, execution continues live — which is exactly
    /// how a crashed run resumes mid-flight instead of starting over.
    ///
    /// **Resume is for crashes, not for code changes.** It requires the journal
    /// to be a *prefix* of what the current code does. A journal written by a
    /// different program is divergence, and the run is quarantined rather than
    /// continued — which is the desired outcome, not a limitation. Continuing
    /// would graft new behaviour onto a history that never produced it, and the
    /// resulting audit trail would be a plausible lie.
    ///
    /// To run changed code against recorded inputs, use [`Mode::Strict`] as a
    /// regression check and start a fresh run for real work.
    Resume,
    /// Verification. Reaching the end of history is itself a failure, because it
    /// means this build does more than the recorded one did.
    Strict,
}

impl Mode {
    #[must_use]
    pub fn is_replaying(self) -> bool {
        matches!(self, Self::Resume | Self::Strict)
    }
}

/// What a step needs to know about itself.
///
/// Gathered into a struct because the alternative was eight positional
/// arguments, several of them the same shape — an ordering mistake waiting to
/// compile cleanly.
#[derive(Debug)]
pub(crate) struct Frame {
    pub run: RunId,
    pub epoch: Epoch,
    pub step: StepId,
    /// Whether this frame is doing the work or undoing it.
    pub phase: Phase,
    pub mode: Mode,
    pub case: Option<CaseContext>,
    /// Durable wake-ups. Deliberately *not* inside `CaseContext`: a timer has
    /// nothing to correlate and no business horizon to bound it, so requiring a
    /// case would deny durable sleep to exactly the plain runs that most want
    /// it — including a retry backing off past the point where holding a worker
    /// is reasonable.
    pub timers: Option<Arc<dyn TimerStore>>,
    pub blobs: Option<Arc<dyn crate::blob::BlobStore>>,
    pub memories: Option<Arc<dyn crate::memory::MemoryStore>>,
    pub authorities: Option<Arc<dyn crate::authority::AuthorityStore>>,
    /// The plane's checked catalogue and transport, for [`StepCtx::call_tool`].
    #[cfg(feature = "manifest")]
    pub tools: Option<(
        Arc<crate::tools::ToolCatalog>,
        Arc<dyn crate::tools::ToolClient>,
    )>,
    pub meter: crate::runtime::metrics::Meter,
    #[cfg(feature = "keyring")]
    pub keyring: Option<Arc<dyn crate::keyring::KeyRing>>,
    pub tenant: crate::core::TenantId,
    pub ledger: Arc<Mutex<Ledger>>,
    /// The authorization engine, if this plane has one.
    ///
    /// `None` means no policy layer — which is the same behaviour as a
    /// permissive engine, and deliberately the only way to spell it. See
    /// `core::policy` on why there is no `AllowAll`.
    pub policy: Option<Arc<dyn crate::core::PolicyEngine>>,
    /// The chain this run acts under, for the policy context.
    pub identity: Option<crate::core::Delegation>,
    /// Who is acting, for the policy principal.
    pub agent: String,
    /// The plane this step runs on, so it can commission other agents on it.
    pub plane: std::sync::Weak<super::Runtime>,
    /// The declaration this agent runs under, if it has one.
    ///
    /// Held by the *runtime* and handed down, never held by a skill. An agent
    /// has skills, not the other way round — a skill separately configured with
    /// a copy of the agent's own declaration would be able to disagree with the
    /// agent about what the agent is.
    #[cfg(feature = "manifest")]
    pub manifest: Option<Arc<crate::manifest::Manifest>>,
    /// The plane's workload identity, for signing what it tells a callee.
    ///
    /// Separate from the store's signer even though a deployment should give
    /// both the same one: the store signs *records*, this signs *outward
    /// claims*, and a plane can legitimately have one without the other.
    pub signer: Option<Arc<dyn crate::core::Signer>>,
}

/// Per-step execution context.
#[derive(Debug)]
pub struct StepCtx<'a> {
    store: &'a Arc<dyn JournalStore>,
    run: RunId,
    epoch: Epoch,
    step: StepId,
    phase: Phase,
    ordinal: u32,
    mode: Mode,
    cursor: StepCursor,
    rng: ChaCha8Rng,
    case: Option<CaseContext>,
    timers: Option<Arc<dyn TimerStore>>,
    blobs: Option<Arc<dyn crate::blob::BlobStore>>,
    memories: Option<Arc<dyn crate::memory::MemoryStore>>,
    authorities: Option<Arc<dyn crate::authority::AuthorityStore>>,
    #[cfg(feature = "manifest")]
    tools: Option<(
        Arc<crate::tools::ToolCatalog>,
        Arc<dyn crate::tools::ToolClient>,
    )>,
    meter: crate::runtime::metrics::Meter,
    #[cfg(feature = "keyring")]
    keyring: Option<Arc<dyn crate::keyring::KeyRing>>,
    tenant: crate::core::TenantId,
    /// The run's budget. Shared because it spans steps; a step never gets its
    /// own allowance to blow.
    ledger: Arc<Mutex<Ledger>>,
    policy: Option<Arc<dyn crate::core::PolicyEngine>>,
    identity: Option<crate::core::Delegation>,
    agent: String,
    plane: std::sync::Weak<super::Runtime>,
    #[cfg(feature = "manifest")]
    manifest: Option<Arc<crate::manifest::Manifest>>,
    signer: Option<Arc<dyn crate::core::Signer>>,
    /// Whether this context is currently taking a group back.
    ///
    /// A reversal runs in the step's **forward** phase — same step, same cursor
    /// — so the phase cannot say what it is. Without this flag a reversal is
    /// gated like a forward call, and a run that reached its ceiling mid-group
    /// could not undo the hold it had already placed. That is the exact outcome
    /// the compensation exemption exists to prevent, reached by a different
    /// road.
    reversing: bool,
    /// The effect group this step is inside, if any.
    ///
    /// Here rather than in the `EffectGroup` handle because a skill that fails
    /// with `?` drops the handle without settling, and `Drop` cannot run an
    /// async reversal. The executor settles what the handle abandoned.
    open_group: Option<super::group::OpenGroup>,
    /// Whether the effect being dispatched right now *is* a group member.
    ///
    /// A group's `Aborted` settlement claims the world was taken back whole.
    /// An ordinary mutating effect performed while a group is open falsifies
    /// that claim: it is journaled, gated and metered like any other, but it
    /// registers no reversal and survives the unwind. So an open group refuses
    /// them — and the runtime has to tell a member's own dispatch apart from
    /// an ambient one, because members reach the world through the same two
    /// methods everything else does.
    member_dispatch: bool,
}

impl<'a> StepCtx<'a> {
    pub(crate) fn new(store: &'a Arc<dyn JournalStore>, cursor: StepCursor, frame: Frame) -> Self {
        let Frame {
            run,
            epoch,
            step,
            phase,
            mode,
            case,
            timers,
            blobs,
            memories,
            authorities,
            #[cfg(feature = "manifest")]
            tools,
            meter,
            #[cfg(feature = "keyring")]
            keyring,
            tenant,
            ledger,
            policy,
            identity,
            agent,
            plane,
            #[cfg(feature = "manifest")]
            manifest,
            signer,
        } = frame;
        Self {
            store,
            run,
            epoch,
            step,
            phase,
            ordinal: 0,
            mode,
            cursor,
            rng: seeded_rng(run, step),
            case,
            timers,
            blobs,
            memories,
            authorities,
            #[cfg(feature = "manifest")]
            tools,
            meter,
            #[cfg(feature = "keyring")]
            keyring,
            tenant,
            ledger,
            policy,
            identity,
            agent,
            plane,
            #[cfg(feature = "manifest")]
            manifest,
            signer,
            reversing: false,
            open_group: None,
            member_dispatch: false,
        }
    }

    /// Run something with the gate exempted, because it is taking work back.
    pub(crate) fn set_reversing(&mut self, reversing: bool) {
        self.reversing = reversing;
    }

    /// Derive the next effect key at this step and consume its ordinal, in one
    /// call so the two can never be done out of step.
    ///
    /// Advancing the ordinal is the bookkeeping a hand-rolled effect path can
    /// forget, and a forgotten advance collides the next effect's key — a replay
    /// divergence with nothing on the record to explain it. This bundles the two,
    /// so every single-attempt effect (a group member, a timer, a release) gets
    /// a fresh key by construction rather than by the author remembering.
    ///
    /// The *retried* forward path (`effect_unlabelled`) cannot use this: it
    /// re-derives per attempt with the attempt number in the key, so its ordinal
    /// is taken once, before the retry loop, and the derivation lives there.
    pub(crate) fn next_effect_key(&mut self, descriptor: &EffectDescriptor) -> EffectKey {
        let ordinal = self.ordinal;
        self.ordinal += 1;
        EffectKey::derive(
            self.step,
            self.phase,
            ordinal,
            1,
            &descriptor.kind,
            &canon::value_bytes(&descriptor.args),
        )
    }

    pub(crate) fn replaying(&self) -> bool {
        self.mode.is_replaying()
    }

    pub(crate) const fn is_strict(&self) -> bool {
        matches!(self.mode, Mode::Strict)
    }

    pub(crate) fn cursor_next(
        &mut self,
        key: EffectKey,
    ) -> Result<Option<crate::journal::EffectReplay>, StepError> {
        self.cursor.next(key)
    }

    pub(crate) const fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub(crate) const fn phase_of(&self) -> Phase {
        self.phase
    }

    pub(crate) fn bound_case(&self) -> Option<crate::core::CaseId> {
        self.case.as_ref().map(CaseContext::id)
    }

    pub(crate) fn journal(&self) -> &Arc<dyn JournalStore> {
        self.store
    }

    pub(crate) fn open_group(&self) -> Option<&super::group::OpenGroup> {
        self.open_group.as_ref()
    }

    pub(crate) fn open_group_mut(&mut self) -> Option<&mut super::group::OpenGroup> {
        self.open_group.as_mut()
    }

    pub(crate) fn set_open_group(&mut self, group: super::group::OpenGroup) {
        self.open_group = Some(group);
    }

    pub(crate) fn take_open_group(&mut self) -> Option<super::group::OpenGroup> {
        self.open_group.take()
    }

    /// Dispatch an effect **as a group member**, exempt from the ambient
    /// refusal above.
    ///
    /// Scoped rather than sticky: the flag is cleared on the way out whatever
    /// the effect did, so a member that fails cannot leave the group open to
    /// ambient mutations for the rest of the step.
    pub(crate) async fn effect_as_member<E: Effect>(
        &mut self,
        effect: E,
    ) -> Result<Tainted<E::Output>, StepError> {
        self.member_dispatch = true;
        let out = self.effect(effect).await;
        self.member_dispatch = false;
        out
    }

    /// Commission another agent on this plane, and journal that you did.
    ///
    /// The hand-off, done properly. A skill cannot hold an `Arc<Runtime>` —
    /// the runtime needs the skill before the skill can have the runtime — so
    /// commissioning belongs to the runtime and is reached through here.
    ///
    /// Three properties, none of them optional:
    ///
    /// * **Journaled**, so a strict replay reads the answer back instead of
    ///   commissioning the work a second time. A skill that called another
    ///   runtime inline would be doing non-deterministic work outside the
    ///   journal, and replay would re-run the whole room.
    /// * **The label travels.** A specialist's answer is untrusted — it came
    ///   from a model — and the next agent is commissioned with that label
    ///   intact, so the receiving run's taint gates judge what they were
    ///   actually given.
    /// * **The cost comes back**, and is billed to the commissioning run, so an
    ///   orchestrator's ceiling bounds the work it ordered rather than its own
    ///   idling.
    ///
    /// The answer is untrusted whatever the org chart says: another agent's
    /// output is somebody else's data.
    ///
    /// # Errors
    ///
    /// [`StepError`] if the sub-run fails. Reported as *in doubt* rather than
    /// *did not happen*: the commissioned agent may have performed effects
    /// before failing, and its own journal is where that is answered.
    pub async fn commission(
        &mut self,
        capability: &str,
        input: Tainted<Value>,
    ) -> Result<Tainted<Value>, StepError> {
        let plane = self.plane.clone();
        let depth = self
            .identity
            .as_ref()
            .map_or(0, crate::core::Delegation::depth);
        let commissioned = self
            .effect(Commission {
                capability: capability.to_owned(),
                input: input.peek().clone(),
                label: input.label().clone(),
                plane,
                depth,
            })
            .await?;
        // Raised, never lowered — the same rule the effect layer applies to a
        // declared sensitivity, applied here because only now is the figure
        // known. A specialist that handled `Confidential` data must not have
        // its answer arrive as `Internal` merely because it crossed a
        // delegation boundary.
        let sensitivity = commissioned.peek().sensitivity;
        let label = commissioned
            .label()
            .clone()
            .with_sensitivity(commissioned.label().sensitivity.max(sensitivity));
        Ok(Tainted::with_label(
            commissioned.into_unlabelled().answer,
            label,
        ))
    }

    /// The declaration this agent runs under.
    ///
    /// `None` when the runtime was wired by builder calls instead. A skill asks
    /// its context which agent it is part of — it does not hold a manifest of
    /// its own, because **an agent has skills**, and a skill carrying a separate
    /// copy of the agent's declaration could disagree with the agent about what
    /// the agent is.
    ///
    /// What a skill typically wants from it: the system prompt
    /// ([`Identity::system_prompt`](crate::manifest::Identity::system_prompt)),
    /// the model role to call, and
    /// [`output_schema`](crate::manifest::Manifest::output_schema).
    #[cfg(feature = "manifest")]
    #[must_use]
    pub fn manifest(&self) -> Option<&crate::manifest::Manifest> {
        self.manifest.as_deref()
    }

    /// Call a tool through the **plane's own** catalogue.
    ///
    /// # Why this exists, and why the obvious alternative is a hole
    ///
    /// A declarative agent gets its [`ToolCatalog`] from the runtime. A
    /// hand-written skill had to construct and carry one:
    ///
    /// ```ignore
    /// ToolCall::prepare(&self.catalog, Arc::clone(&self.client), id, args)?
    /// ```
    ///
    /// and nothing bound `self.catalog` to the manifest governing that skill.
    /// [`ToolCatalog::from_manifest`] is the right primitive and it is one call
    /// away — but the *obvious* thing, hand-building a catalogue with the tools
    /// you know you call, compiles, runs, and grants the skill reach its
    /// declaration never described. Worse, it can be **laxer**: a
    /// [`ToolSafety::read_only`] entry for a tool the manifest calls mutating
    /// exempts it from the whole-value taint gate and carries
    /// [`Recovery::Retry`](crate::core::Recovery::Retry), so a timed-out
    /// money-moving call is sent a second time.
    ///
    /// [`RuntimeBuilder::try_build`](crate::runtime::RuntimeBuilder::try_build)
    /// refuses exactly that divergence — for the *plane's* catalogue. A
    /// catalogue built inside a skill never passed under that check. So this is
    /// the same dispatch a declarative agent performs, over the same checked
    /// catalogue, and the drift is unrepresentable rather than merely
    /// discouraged.
    ///
    /// # Everything else is unchanged
    ///
    /// The manifest gate still refuses a tool this agent's declaration does not
    /// grant, the protected-field rules still have to match, the egress ceiling
    /// still applies, and the result still comes back
    /// [`Tainted`] and untrusted. This narrows what a skill can reach; it grants
    /// nothing.
    ///
    /// ```ignore
    /// let overdue = cx
    ///     .call_tool(ToolId::new("obsd", "list_overdue_processes"), args)
    ///     .await?;
    /// ```
    ///
    /// [`ToolCatalog`]: crate::tools::ToolCatalog
    /// [`ToolCatalog::from_manifest`]: crate::tools::ToolCatalog::from_manifest
    /// [`ToolSafety::read_only`]: crate::tools::ToolSafety::read_only
    ///
    /// # Errors
    ///
    /// [`StepError`] when this plane has no tool catalogue, when the tool is not
    /// in it, when this agent's manifest does not grant it, or when the
    /// arguments' label is refused at the sink.
    #[cfg(feature = "manifest")]
    pub async fn call_tool(
        &mut self,
        tool: crate::tools::ToolId,
        arguments: Tainted<Value>,
    ) -> Result<Tainted<Value>, StepError> {
        let (catalog, client) = self.tools.clone().ok_or_else(|| {
            StepError::Effect(crate::core::EffectError::Other(
                "this plane has no tool catalogue — `RuntimeBuilder::toolbox(..)` derives \
                 one from the agents' declarations, and `.tools(catalog, client)` states \
                 it explicitly"
                    .into(),
            ))
        })?;
        let prepared =
            crate::tools::ToolCall::prepare(&catalog, client, tool, arguments.peek().clone())
                .map_err(|e| {
                    StepError::Effect(crate::core::EffectError::Rejected(e.to_string()))
                })?;
        self.sink(prepared, &arguments).await
    }

    /// What this run tells a callee about itself, sealed for one call.
    ///
    /// Unsigned when the plane has no workload identity, which is honest: a
    /// self-signed block would look attested and prove nothing, the same
    /// reasoning that leaves unsigned journal records unsigned.
    fn provenance(
        &self,
        key: EffectKey,
        ordinal: u32,
        descriptor: &EffectDescriptor,
    ) -> crate::core::Provenance {
        // The same key with the attempt pinned to zero: one identity for the
        // logical dispatch, however many times it is attempted. A callee
        // deduplicates on this, because "have I already done this work?" must
        // answer *yes* for a retry — while the effect key must differ per
        // attempt so replay reads back the retry rather than the failure before
        // it. Two questions, two identifiers.
        let dispatch = EffectKey::derive(
            self.step,
            self.phase,
            ordinal,
            0,
            &descriptor.kind,
            &canon::value_bytes(&descriptor.args),
        );
        let block = crate::core::Provenance::new(self.run, key, self.agent.clone())
            .dispatching(dispatch)
            .in_case(self.case.as_ref().map(|c| c.case_id));
        match &self.signer {
            Some(signer) => block.seal(signer.as_ref(), &descriptor.kind, &descriptor.args),
            None => block,
        }
    }

    /// Hand the step's history back once it has finished with it.
    pub(crate) fn into_cursor(self) -> StepCursor {
        self.cursor
    }

    #[must_use]
    pub fn run_id(&self) -> RunId {
        self.run
    }

    #[must_use]
    pub fn step_id(&self) -> StepId {
        self.step
    }

    /// What this run has consumed so far, and against what limits.
    #[must_use]
    pub fn budget(&self) -> crate::core::Consumed {
        self.ledger.lock().expect("budget mutex").consumed()
    }

    /// Count one dispatched effect and add what it consumed.
    ///
    /// Called for failures as well as successes, with a zero spend, because a
    /// call that failed still *happened*: it took a slot against `max_effects`,
    /// and a budget that only counted successes could never bound a call that
    /// fails every time. Replay bills the same way from the same records, so the
    /// two paths reach the same verdict at the same point.
    ///
    /// A separate function so the guard's scope is a single statement and cannot
    /// accidentally span an await.
    fn bill(&self, spend: crate::core::Spend) {
        self.ledger
            .lock()
            .expect("budget mutex")
            .record_effect(spend);
    }

    /// A deterministic random source.
    ///
    /// Seeded from `(run_id, step)` rather than journaled per draw: the sequence
    /// is reproducible by construction, so replay reproduces it for free and the
    /// journal carries no entropy records at all. Cheaper *and* stronger than
    /// recording each value — there is no way for the recorded and recomputed
    /// streams to disagree.
    pub fn rng(&mut self) -> &mut impl rand::Rng {
        &mut self.rng
    }

    /// The current instant, as a journaled effect.
    ///
    /// On replay this returns the instant the original run saw, not the instant
    /// now — which is why a replayed run makes the same time-dependent decisions
    /// as the run it is reproducing.
    pub async fn now(&mut self) -> Result<Timestamp, StepError> {
        Ok(self.effect(Clock).await?.into_unlabelled())
    }

    /// Record structured reasoning in the journal, adjacent to the effects it
    /// explains.
    ///
    /// Adjacency is the point: a note next to the action it claims to justify
    /// makes reasoning-versus-action mismatch detectable after the fact and
    /// testable under replay. A summary written at the end of a run cannot do
    /// that, because by then the ordering evidence is gone.
    pub async fn note(&mut self, text: impl Into<String>) -> Result<(), StepError> {
        self.append(RecordKind::Note { text: text.into() }).await
    }

    /// Perform (or replay) an effect, repeating it if it fails and repeating is
    /// safe.
    ///
    /// The whole determinism boundary is this function.
    ///
    /// # Why one loop covers both replay and live execution
    ///
    /// A retry sequence is history like any other. Each attempt has its own
    /// effect key (the attempt number is hashed in), so the journal holds
    /// attempts 1..N as ordinary consecutive effects, and replay walks them the
    /// same way it walks anything else. There is no separate "replay the
    /// retries" path to drift out of sync with the live one.
    ///
    /// # History outranks policy
    ///
    /// While history has attempts left, they are consumed regardless of what
    /// the current [`RetryPolicy`](crate::core::RetryPolicy) says. A run that made four attempts under
    /// yesterday's policy still made four attempts, and a replay under a
    /// two-attempt policy that stopped early would leave unconsumed records and
    /// report divergence for a run that did nothing wrong. The policy governs
    /// only what happens *after* history runs out.
    /// # The result is labelled
    ///
    /// An effect is how the deterministic zone reaches the outside world, so
    /// what comes back *is* the outside world's data. It arrives as
    /// [`Tainted`], labelled from the effect's own [`Effect::trust`]
    /// declaration — which defaults to untrusted.
    ///
    /// That is what makes the architecture hold rather than merely be
    /// described. A tool result flowing into a downstream step's input is
    /// labelled automatically, so the replan refusal and the taint gate see it
    /// without the skill author having to remember; and a skill that wants to
    /// treat a tool response as trusted has to say so, in a call that leaves a
    /// record.
    pub async fn effect<E: Effect>(&mut self, effect: E) -> Result<Tainted<E::Output>, StepError> {
        if effect.sink_arguments().is_some() {
            return Err(PolicyError::SinkGateRequired {
                sink: effect.descriptor().kind,
            }
            .into());
        }
        self.effect_after_sink_gate(effect, None).await
    }

    /// Dispatch an effect once any required information-flow checks have run.
    async fn effect_after_sink_gate<E: Effect>(
        &mut self,
        effect: E,
        outbound: Option<&crate::core::Label>,
    ) -> Result<Tainted<E::Output>, StepError> {
        let trust = effect.trust();
        let declared = effect.output_sensitivity();
        let kind = effect.descriptor().kind;
        // A mutation beside an open group, rather than inside it. Refused:
        // the group's `Aborted` outcome says *taken back whole*, and this
        // write would still be standing when it was written. Reads are
        // untouched — a read changes nothing there is to take back — and a
        // member's own dispatch sets `member_dispatch` on the way through.
        if let Some(open) = self.open_group.as_ref()
            && !self.member_dispatch
            && effect.mutates()
        {
            return Err(StepError::GroupFootprint {
                group: open.name.clone(),
                detail: format!(
                    "'{kind}' mutates and is not a member of the open group — it \
                     would survive an abort that claims the world was taken back \
                     whole. Register it with the group, or perform it before the \
                     group opens or after it settles"
                ),
            });
        }
        let output = self.effect_unlabelled(effect, outbound).await?;

        let labelled = match trust {
            crate::core::Trust::Trusted => Tainted::trusted(output),
            crate::core::Trust::Untrusted => {
                Tainted::from_source(output, crate::core::SourceId::new(format!("effect:{kind}")))
            }
        };
        // Raised, never lowered: an untrusted result is already `Internal`, and
        // an effect that could declare its output *less* sensitive than its
        // provenance implies would be a laundering primitive.
        let sensitivity = labelled.label().sensitivity.max(declared);
        let label = labelled.label().clone().with_sensitivity(sensitivity);
        Ok(Tainted::with_label(labelled.into_unlabelled(), label))
    }

    /// The effect protocol itself, before the result is labelled.
    ///
    /// Split out so the label is applied at exactly one place: a second exit
    /// from this function that forgot to wrap would be an unlabelled tool
    /// result, which is the hole the labelling exists to close.
    async fn effect_unlabelled<E: Effect>(
        &mut self,
        mut effect: E,
        outbound: Option<&crate::core::Label>,
    ) -> Result<E::Output, StepError> {
        // Checked once, on the path *both* `effect` and `sink` take, and before
        // the retry loop because a depth violation is not attempt-dependent.
        //
        // It lived in `sink` alone, which meant the ceiling governed the A2A
        // peer call and not `cx.commission` — the rule held across a network
        // boundary and not across a function call, which is the wrong way
        // round. The loop a `specialist` role exists to prevent is the in-plane
        // one: A commissions B commissions C commissions A, inside one process,
        // with no peer boundary to cross and no allowlist to notice.
        self.check_delegation_depth(&effect)?;

        let descriptor = effect.descriptor();
        let policy = effect.retry();
        let recovery = effect.recovery();
        let ordinal = self.ordinal;
        self.ordinal += 1;

        let mut attempt: u32 = 1;
        loop {
            let key = EffectKey::derive(
                self.step,
                self.phase,
                ordinal,
                attempt,
                &descriptor.kind,
                &canon::value_bytes(&descriptor.args),
            );

            // Hand the effect what it needs to identify itself to a callee.
            // After the key is derived and before anything is announced: the key
            // is part of the block, and the block is signed for *this* call.
            effect.attach(&self.provenance(key, ordinal, &descriptor));

            // ── Replay: is this attempt already in history? ────────────────
            if self.mode.is_replaying() {
                match self.cursor.next(key)? {
                    Some(EffectReplay::Done { output, spend, .. }) => {
                        self.replayed_done(&descriptor.kind, attempt, spend);
                        return Ok(serde_json::from_value(output)?);
                    }
                    Some(
                        refusal @ (EffectReplay::Refused { .. } | EffectReplay::Denied { .. }),
                    ) => {
                        return Err(recorded_refusal(refusal));
                    }
                    Some(EffectReplay::Failed {
                        error,
                        disposition,
                        spend,
                        permanent,
                    }) => {
                        attempt = self.replay_recorded_failure(
                            &descriptor,
                            ordinal,
                            attempt,
                            key,
                            &recovery,
                            &policy,
                            &error,
                            disposition,
                            spend,
                            permanent,
                        )?;
                        continue;
                    }
                    Some(EffectReplay::Orphan { recovery, .. }) => {
                        return self.resolve_orphan(&effect, key, attempt, &recovery).await;
                    }
                    // History exhausted: this attempt runs live, unless a
                    // strict pass is verifying — where reaching the end is
                    // itself the finding.
                    None if self.mode == Mode::Strict => {
                        return Err(StepError::ReplayOverrun { actual: key });
                    }
                    None => {}
                }
            }

            // ── Live ───────────────────────────────────────────────────────
            //
            // Admission is checked per attempt, not once per effect. A retry is
            // a real call that costs real money, and a budget that only counted
            // the first one would be a ceiling a retry storm walks straight
            // through.
            //
            // Checked *before* dispatch: the point of a budget is to stop the
            // spending, not to notice it. Only live execution is gated —
            // replay must reproduce whatever the original run did, or history
            // would change shape with the limit in force when you replayed it.
            //
            // Compensation is exempt. Refusing to undo because the ceiling was
            // reached is how a run ends with a charged card and no order — the
            // ceiling exists to bound work, not to strand it half-done. The
            // spend is still billed and journaled, so the overshoot is visible
            // rather than silent.
            self.gate(key, &descriptor, effect.mutates(), outbound)
                .await?;

            let backoff = policy.backoff(self.run, key, attempt);
            if !backoff.is_zero() {
                tokio::time::sleep(backoff).await;
            }
            let waited = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);

            let failure = match self
                .traced_attempt(&effect, key, attempt, waited, outbound)
                .await?
            {
                Ok(output) => return Ok(output),
                Err(e) => e,
            };

            // An in-doubt failure on a reconcilable effect is a question, not a
            // verdict. Ask before deciding.
            let mut disposition = failure.disposition();
            if disposition == crate::core::Disposition::InDoubt
                && matches!(recovery, crate::core::Recovery::Reconcile)
            {
                match self.reconcile_and_record(&effect, key).await? {
                    crate::core::Reconciliation::Landed(output) => return Ok(output),
                    resolved => disposition = resolved.disposition(),
                }
            }

            if let Some(stop) = Self::stop_reason(
                disposition,
                &recovery,
                key,
                attempt,
                &policy,
                &failure.to_string(),
                matches!(failure, crate::core::EffectError::Refused(_)),
            ) {
                return Err(stop);
            }
            attempt += 1;
        }
    }

    /// An `EffectStarted` with no terminal record: a crash landed between
    /// "sent the request" and "recorded the answer".
    ///
    /// Whether the call landed is undecidable from the journal, so the declared
    /// recovery mode decides. This is the same question an
    /// [`InDoubt`](crate::core::Disposition::InDoubt) failure asks — a crash and
    /// a timeout leave the runtime knowing exactly as much — and it is answered
    /// the same way, by declaration rather than by guessing.
    async fn resolve_orphan<E: Effect>(
        &mut self,
        effect: &E,
        key: EffectKey,
        attempt: u32,
        recovery: &crate::core::Recovery,
    ) -> Result<E::Output, StepError> {
        use crate::core::{Reconciliation, Recovery};

        // Strict replay is a pure read, and resolving an orphan is not reading —
        // every branch below either performs an effect or probes a provider, and
        // both write to the journal being verified.
        //
        // An earlier version fell straight through to the `Retry` arm here, so
        // verifying a crashed run re-performed its interrupted effect for real
        // and appended to the history it was meant to be checking.
        if self.mode == Mode::Strict {
            return Err(StepError::Undecidable {
                key,
                recovery: recovery.clone(),
                detail: "the journal ends mid-effect; strict replay verifies history and will \
                         not perform or probe to complete it"
                    .into(),
            });
        }

        match recovery {
            // Re-performed under the *same* key, and without a second
            // `EffectStarted`: the announcement already in the journal covers
            // this call, and writing another would report two attempts where
            // one interrupted attempt was resumed.
            Recovery::Retry | Recovery::Idempotent { .. } => {
                match self
                    .perform_once(effect, key, attempt, 0, false, None)
                    .await?
                {
                    Ok(output) => Ok(output),
                    Err(e) => Err(StepError::Effect(e)),
                }
            }
            // Ask, rather than assume. This is the only branch that turns an
            // undecidable outcome into a decided one without betting on it.
            Recovery::Reconcile => match self.reconcile_and_record(effect, key).await? {
                Reconciliation::Landed(output) => Ok(output),
                Reconciliation::DidNotHappen => {
                    match self
                        .perform_once(effect, key, attempt, 0, false, None)
                        .await?
                    {
                        Ok(output) => Ok(output),
                        Err(e) => Err(StepError::Effect(e)),
                    }
                }
                Reconciliation::Inconclusive => Err(StepError::Undecidable {
                    key,
                    recovery: recovery.clone(),
                    detail: "started before a crash, and the reconciliation probe could not \
                             establish whether it landed"
                        .into(),
                }),
            },
            Recovery::RequiresOperator => Err(StepError::Undecidable {
                key,
                recovery: recovery.clone(),
                detail: "started before a crash and never completed".into(),
            }),
        }
    }

    /// Ask the provider whether a call landed, and journal the answer.
    ///
    /// The verdict goes in the journal — including an inconclusive one, because
    /// "we did not know, we asked, and we still do not know" is exactly what an
    /// operator picking up the escalation needs to see. Omitting it would make
    /// the escalation look like nobody tried.
    ///
    /// Journaling also makes the probe replayable: it is a network call like any
    /// other, and replay reads its verdict back rather than asking again.
    async fn reconcile_and_record<E: Effect>(
        &mut self,
        effect: &E,
        key: EffectKey,
    ) -> Result<crate::core::Reconciliation<E::Output>, StepError> {
        use crate::core::Reconciliation;

        // A probe that fails tells us nothing new, so the doubt stands. It is
        // recorded rather than retried: a probe worth repeating is a probe the
        // driver should be repeating internally, and stacking a retry loop on
        // top of one is a multiplication nobody asked for.
        let (outcome, detail) = match effect.reconcile().await {
            Ok(r) => (r, None),
            Err(e) => (Reconciliation::Inconclusive, Some(e.to_string())),
        };

        let (output, spend) = match &outcome {
            Reconciliation::Landed(value) => {
                let spend = effect.spend(value);
                self.bill(spend);
                (Some(serde_json::to_value(value)?), spend)
            }
            _ => (None, crate::core::Spend::default()),
        };

        tracing::info!(
            target: telemetry::RECONCILED,
            run = %self.run,
            step = %self.step,
            verdict = ?outcome.disposition(),
        );
        self.meter
            .count(metrics::RECONCILIATIONS, outcome.disposition().as_str());
        self.append_effect(
            key,
            RecordKind::EffectReconciled {
                disposition: outcome.disposition(),
                output,
                spend,
                detail,
            },
        )
        .await?;

        Ok(outcome)
    }

    /// What history says about a wait, if anything.
    ///
    /// `Ok(None)` means the journal has nothing here and the wait must be
    /// registered live. Every other arm is a decision the recorded run already
    /// made, reproduced rather than re-derived.
    async fn replayed_wait(
        &mut self,
        key: EffectKey,
        spec: &AwaitSpec,
        cx: &CaseContext,
    ) -> Result<Option<Tainted<Value>>, StepError> {
        match self.cursor.next(key)? {
            Some(EffectReplay::Done {
                output,
                source,
                spend,
            }) => {
                self.bill(spend);
                Ok(Some(Self::label_inbound(
                    output,
                    &spec.kind,
                    source.as_deref(),
                )))
            }
            Some(EffectReplay::Refused { limit, used }) => {
                Err(StepError::Budget(crate::core::BudgetExceeded::Recorded {
                    limit,
                    used,
                }))
            }
            Some(EffectReplay::Denied {
                reason,
                action,
                resource,
            }) => Err(StepError::Denied {
                action,
                resource,
                reason,
            }),
            Some(EffectReplay::Failed { error, .. }) => {
                Err(StepError::Effect(crate::core::EffectError::Rejected(error)))
            }
            // A subscription with no delivery: the run is still waiting.
            // Suspend again rather than re-registering.
            Some(EffectReplay::Orphan { .. }) => {
                Err(StepError::Suspended(self.suspend_reason(spec, cx).await?))
            }
            None if self.mode == Mode::Strict => Err(StepError::ReplayOverrun { actual: key }),
            None => Ok(None),
        }
    }

    /// Account for an effect served from the journal rather than performed.
    ///
    /// Marked replayed so metrics like "effect latency by driver" do not average
    /// real calls with journal reads, and billed at the figure that was
    /// *recorded* — so a replayed run reaches the same budget verdict at the
    /// same point as the original.
    fn replayed_done(&mut self, kind: &str, attempt: u32, spend: crate::core::Spend) {
        tracing::debug!(
            target: telemetry::EFFECT_SPAN,
            kind = %kind,
            attempt,
            replayed = true,
            outcome = "done",
        );
        self.meter.count(metrics::EFFECTS_REPLAYED, kind);
        self.bill(spend);
    }

    /// The reviewed grant for an effect, if the manifest names one.
    ///
    /// The bridge between a declaration and a dispatch. Without it
    /// `ToolGrant::mutates` and `ToolGrant::max_sensitivity` are fields a
    /// reviewer approves and nothing consults — the "manufactures confidence"
    /// failure the binding rule exists to prevent.
    #[cfg(feature = "manifest")]
    fn tool_grant_for(&self, descriptor: &EffectDescriptor) -> Option<&crate::manifest::ToolGrant> {
        if descriptor.kind != "tool.call" {
            return None;
        }
        let server = descriptor.args["server"].as_str()?;
        let tool = descriptor.args["tool"].as_str()?;
        self.manifest
            .as_ref()?
            .tool_grant(&crate::tools::ToolId::new(server, tool).reference())
    }

    /// Everything that can refuse an attempt before it is dispatched.
    ///
    /// Authorization before accounting: both refuse before dispatch, but an
    /// unauthorized call should not first consume the run's allowance —
    /// otherwise a denied agent can still exhaust a budget by asking.
    ///
    /// Compensation is exempt from both, for the same reason: refusing to undo
    /// is how a run ends with a charged card and no order.
    pub(crate) async fn gate(
        &mut self,
        key: EffectKey,
        descriptor: &EffectDescriptor,
        mutates: bool,
        outbound: Option<&crate::core::Label>,
    ) -> Result<(), StepError> {
        // A compensating phase, or a group being taken back inside a forward
        // one. Both are undo, and both are exempt for the same reason: refusing
        // to undo is how a run ends with a charged card and no order.
        if !self.phase.is_forward() || self.reversing {
            return Ok(());
        }
        // First, because it is the cheapest and the most fundamental: an effect
        // the agent's own declaration never mentioned should not reach the
        // deployment's policy engine, let alone the world.
        #[cfg(feature = "manifest")]
        self.declared(key, descriptor).await?;
        // The reviewed grant may only tighten. A tool the operator declared
        // mutating gets the cautious treatment even if the catalogue advertises
        // otherwise, because a server's own description of itself is an
        // advertisement and the grant is the operator's decision about it.
        #[cfg(feature = "manifest")]
        let mutates = mutates || self.tool_grant_for(descriptor).is_some_and(|g| g.mutates);
        self.authorize(key, descriptor, mutates, outbound).await?;
        self.admit(key, &descriptor.kind).await
    }

    /// Check an effect against the agent's **own manifest**, journalling any
    /// refusal.
    ///
    /// This is what makes a manifest a control rather than a comment. Without
    /// it, `spec.models` and `spec.tools` describe what the code is *supposed*
    /// to do: a reviewer approves `model: haiku`, the code calls opus, and
    /// nothing anywhere disagrees. The declaration and the behaviour are then
    /// two independent copies of one decision, which is the failure mode a
    /// single reviewable file exists to remove.
    ///
    /// Only the fields a descriptor can be checked against are enforced here —
    /// the model and the tool reference. An effect kind this does not recognise
    /// passes, because inventing a constraint for it would be worse than saying
    /// nothing.
    ///
    /// Runs on live dispatch only, like every other gate: a replayed effect
    /// reads its result from the journal, so editing a manifest cannot re-judge
    /// a run that already happened.
    #[cfg(feature = "manifest")]
    #[allow(clippy::too_many_lines)]
    async fn declared(
        &mut self,
        key: EffectKey,
        descriptor: &EffectDescriptor,
    ) -> Result<(), StepError> {
        let Some(manifest) = self.manifest.as_ref() else {
            return Ok(());
        };

        let refusal = match descriptor.kind.as_str() {
            "model.complete" => {
                let provider = descriptor.args["provider"].as_str().unwrap_or_default();
                let model = descriptor.args["model"].as_str().unwrap_or_default();
                (!manifest.permits_model(provider, model)).then(|| {
                    format!(
                        "manifest '{}' does not declare the model '{provider}/{model}' —                          a model this agent's declaration never named is a behaviour                          change nobody reviewed",
                        manifest.metadata.name
                    )
                })
            }
            "tool.call" => {
                let server = descriptor.args["server"].as_str().unwrap_or_default();
                let tool = descriptor.args["tool"].as_str().unwrap_or_default();
                let reference = crate::tools::ToolId::new(server, tool).reference();
                match manifest.tool_grant(&reference) {
                    None => Some(format!(
                        "manifest '{}' does not grant '{reference}' — a tool the                          agent's declaration never listed is authority nobody granted",
                        manifest.metadata.name
                    )),
                    // Compared canonically. The descriptor sorts on the way
                    // out, so the grant must be sorted too or a manifest whose
                    // fields were listed in another order is refused for a
                    // difference that means nothing.
                    Some(grant)
                        if serde_json::to_value(crate::tools::sorted_fields(
                            &grant.protected_fields,
                        ))
                        .ok()
                            != descriptor.args.get("protected_fields").cloned() =>
                    {
                        Some(format!(
                            "manifest '{}' and the live catalogue disagree about protected fields for '{reference}' — authority-bearing argument policy must be digest-covered and exact",
                            manifest.metadata.name
                        ))
                    }
                    Some(_) => None,
                }
            }
            "mcp.prompt/get" => {
                let server = descriptor.args["server"].as_str().unwrap_or_default();
                let name = descriptor.args["name"].as_str().unwrap_or_default();
                match manifest.prompt_grant(server, name) {
                    None => Some(format!(
                        "manifest '{}' does not grant MCP prompt '{server}/{name}'",
                        manifest.metadata.name
                    )),
                    Some(grant)
                        if descriptor.args.get("max_input_sensitivity")
                            != serde_json::to_value(grant.max_input_sensitivity)
                                .ok()
                                .as_ref()
                            || descriptor.args.get("output_sensitivity")
                                != serde_json::to_value(grant.output_sensitivity).ok().as_ref() =>
                    {
                        Some(format!(
                            "manifest '{}' and the MCP prompt catalogue disagree about sensitivity for '{server}/{name}'",
                            manifest.metadata.name
                        ))
                    }
                    Some(_) => None,
                }
            }
            "mcp.resource/read" => {
                let server = descriptor.args["server"].as_str().unwrap_or_default();
                let uri = descriptor.args["uri"].as_str().unwrap_or_default();
                match manifest.resource_grant(server, uri) {
                    None => Some(format!(
                        "manifest '{}' does not grant MCP resource '{server}/{uri}'",
                        manifest.metadata.name
                    )),
                    Some(grant)
                        if descriptor.args.get("output_sensitivity")
                            != serde_json::to_value(grant.output_sensitivity).ok().as_ref() =>
                    {
                        Some(format!(
                            "manifest '{}' and the MCP resource catalogue disagree about sensitivity for '{server}/{uri}'",
                            manifest.metadata.name
                        ))
                    }
                    Some(_) => None,
                }
            }
            _ => None,
        };

        let Some(reason) = refusal else {
            return Ok(());
        };

        tracing::error!(
            target: telemetry::POLICY_DENIED,
            run = %self.run,
            step = %self.step,
            action = crate::core::ACTION_DECLARED,
            resource = %descriptor.kind,
            %reason,
        );
        self.meter
            .count(metrics::POLICY_DENIALS, crate::core::ACTION_DECLARED);

        // Journaled under the refused effect's key, for the same reason a budget
        // refusal is: a replay that found no history here would report that the
        // *build* performs more effects than the record, sending an operator to
        // look for a code change that does not exist.
        self.append_effect(
            key,
            RecordKind::PolicyDenied {
                reason: reason.clone(),
                action: crate::core::ACTION_DECLARED.to_owned(),
                resource: descriptor.kind.clone(),
            },
        )
        .await?;

        Err(StepError::Denied {
            action: crate::core::ACTION_DECLARED.to_owned(),
            resource: descriptor.kind.clone(),
            reason,
        })
    }

    /// Check an effect against the policy in force, journalling any denial.
    ///
    /// Runs **only on live dispatch**. A replayed effect never reaches here,
    /// because its result comes back from the journal rather than from the
    /// world — which is what keeps a policy edit from re-judging a run that
    /// already happened. See `core::policy`.
    ///
    /// A permit is not recorded. The effect's own `EffectStarted` is already
    /// evidence it was allowed, and journaling "yes" beside every call doubles
    /// the log to say nothing.
    async fn authorize(
        &mut self,
        key: EffectKey,
        descriptor: &EffectDescriptor,
        mutates: bool,
        outbound: Option<&crate::core::Label>,
    ) -> Result<(), StepError> {
        let Some(engine) = self.policy.as_ref() else {
            return Ok(());
        };

        let mut context = serde_json::json!({
            "run": self.run.to_string(),
            "step": self.step.0,
            // Every authorization request carries the tenant, not only
            // admission. A gate that knows which tenant is acting at the door
            // and forgets by the time an effect reaches the world is a gate
            // that cannot express "this tenant may not call that tool".
            "tenant": self.tenant.as_str(),
            "mutates": mutates,
            "args": descriptor.args,
        });
        // **Where the value came from**, not only what it is.
        //
        // Provenance and authorization are two graphs, and an attack lives in
        // the gap between them: an agent is permitted to call a tool in general,
        // and that permission never accounts for the provenance of the
        // particular value it is called with. This crate closes the gap with
        // checks written *here* — the taint gate and per-field source rules —
        // but without the label in the request a **deployment** cannot express
        // the alignment at all. It could say "amounts over 5000 need approval";
        // it could not say "not with data that passed through that peer".
        //
        // Present only for `sink`, which is the only call that has a labelled
        // value to bind. Absent is not "trusted": a rule that requires a source
        // simply does not match, so it fails closed.
        if let Some(label) = outbound {
            context["label"] = serde_json::to_value(label).unwrap_or(Value::Null);
        }
        merge_identity(&mut context, self.identity.as_ref());
        let request = crate::core::PolicyRequest {
            principal: &self.agent,
            action: crate::core::ACTION_PERFORM,
            resource: &descriptor.kind,
            context: &context,
        };

        // Before the policy is consulted, not after. A refusal is journaled as
        // it happens, so a ceiling applied afterwards bounds nothing an
        // observer can see — the record is already written and the bit is
        // already out. Refusing here means the attempt produces neither.
        if let Err(exceeded) = self
            .ledger
            .lock()
            .expect("budget mutex")
            .admit_policy_check()
        {
            return Err(StepError::Budget(exceeded));
        }

        let crate::core::PolicyDecision::Deny { reason } = engine.authorize(&request) else {
            return Ok(());
        };

        tracing::error!(
            target: telemetry::POLICY_DENIED,
            run = %self.run,
            step = %self.step,
            action = crate::core::ACTION_PERFORM,
            resource = %descriptor.kind,
            %reason,
        );
        self.meter
            .count(metrics::POLICY_DENIALS, crate::core::ACTION_PERFORM);
        self.append_effect(
            key,
            RecordKind::PolicyDenied {
                reason: reason.clone(),
                action: crate::core::ACTION_PERFORM.to_owned(),
                resource: descriptor.kind.clone(),
            },
        )
        .await?;

        // Counted after the record, and the ordering matters: the refusal has
        // already happened and belongs in the journal whatever the ceiling says.
        // What the ceiling stops is the *next* attempt, which is the one that
        // would learn something the last one did not.
        if let Err(exceeded) = self.ledger.lock().expect("budget mutex").record_denial() {
            return Err(StepError::Budget(exceeded));
        }

        Err(StepError::Denied {
            action: crate::core::ACTION_PERFORM.to_owned(),
            resource: descriptor.kind.clone(),
            reason,
        })
    }

    /// Check an effect against the run's ceilings, journalling any refusal.
    ///
    /// The refusal goes in the journal under the key of the effect it refused.
    /// Without it a replayed run reaches this point, finds no history, and
    /// reports that the *build* performs more effects than the record — sending
    /// an operator to look for a code change that does not exist.
    async fn admit(&mut self, key: EffectKey, kind: &str) -> Result<(), StepError> {
        // Scoped so the guard is gone before any await below.
        let verdict = self.ledger.lock().expect("budget mutex").admit_effect();
        let Err(exceeded) = verdict else {
            return Ok(());
        };

        tracing::warn!(
            target: telemetry::BUDGET_REFUSED,
            run = %self.run,
            step = %self.step,
            %kind,
            limit = %exceeded,
        );
        self.meter
            .count(metrics::BUDGET_REFUSALS, exceeded.as_str());
        self.append_effect(
            key,
            RecordKind::BudgetRefused {
                limit: exceeded.to_string(),
                used: format!("{:?}", self.budget()),
            },
        )
        .await?;
        Err(StepError::Budget(exceeded))
    }

    /// Perform one attempt inside its own span.
    ///
    /// One span per *attempt*, not per effect, so a retried call shows as
    /// several — which is what makes "how often does this driver need a second
    /// try" answerable at all.
    async fn traced_attempt<E: Effect>(
        &mut self,
        effect: &E,
        key: EffectKey,
        attempt: u32,
        waited_ms: u64,
        outbound: Option<&crate::core::Label>,
    ) -> Result<Result<E::Output, crate::core::EffectError>, StepError> {
        let span = tracing::info_span!(
            telemetry::EFFECT_SPAN,
            { telemetry::EFFECT_KIND } = tracing::field::display(&effect.descriptor().kind),
            { telemetry::EFFECT_ATTEMPT } = attempt,
            { telemetry::EFFECT_MUTATES } = effect.mutates(),
            { telemetry::EFFECT_REPLAYED } = false,
            { telemetry::OUTCOME } = tracing::field::Empty,
            // Present only on the effects that *are* GenAI operations. Recorded
            // rather than declared with a value so a clock read does not carry
            // an empty `gen_ai.operation.name`, which would make the attribute
            // useless for the tooling that keys on it.
            { telemetry::GEN_AI_OPERATION } = tracing::field::Empty,
        );
        if let Some(op) = effect.gen_ai_operation() {
            span.record(telemetry::GEN_AI_OPERATION, op);
        }
        // `Instrument`, never `enter()`. An `Entered` guard held across an
        // `.await` stays entered on the *thread*, so when the future yields,
        // whatever runs next is attributed to this span. With concurrent step
        // dispatch that silently reparents a sibling's work.
        // Counted per *attempt*, matching the span: a driver that needs two
        // tries has performed two effects against the world, and a count that
        // collapsed them would hide exactly the retry rate an operator is
        // looking for.
        self.meter
            .count(metrics::EFFECTS, &effect.descriptor().kind);
        let outcome = self
            .perform_once(effect, key, attempt, waited_ms, true, outbound)
            .instrument(span.clone())
            .await?;
        span.record(
            telemetry::OUTCOME,
            if outcome.is_ok() { "done" } else { "failed" },
        );
        Ok(outcome)
    }

    /// What to do about a failure the journal already holds.
    ///
    /// Returns the next attempt number to try. Errors if the recorded run
    /// stopped here — which is the faithful outcome, not a fault.
    #[allow(clippy::too_many_arguments)]
    fn recorded_failure(
        &mut self,
        descriptor: &EffectDescriptor,
        ordinal: u32,
        attempt: u32,
        key: EffectKey,
        recovery: &crate::core::Recovery,
        policy: &crate::core::RetryPolicy,
        error: &str,
        disposition: crate::core::Disposition,
        permanent: bool,
    ) -> Result<u32, StepError> {
        // Billed on replay exactly as it was live, or a run that exhausted its
        // budget on failures would replay as healthy under the same limit.
        self.bill(crate::core::Spend::default());

        // Did the recorded run go on to retry? Ask history rather than infer:
        // if the next journaled effect is this one's attempt + 1, it retried.
        let next = EffectKey::derive(
            self.step,
            self.phase,
            ordinal,
            attempt + 1,
            &descriptor.kind,
            &canon::value_bytes(&descriptor.args),
        );
        if self.cursor.peek_is(next) {
            // Follow history, whatever the current policy says.
            return Ok(attempt + 1);
        }

        // History ends here. Recompute what the recorded run would have done
        // next — a pure function of the disposition, the recovery mode, and the
        // policy. If it would have stopped, this failure was final.
        if let Some(stop) = Self::stop_reason(
            disposition,
            recovery,
            key,
            attempt,
            policy,
            error,
            permanent,
        ) {
            return Err(stop);
        }

        // It would have retried, so it died between recording this failure and
        // starting the next attempt. A strict pass reports that rather than
        // performing anything; a resume carries on live.
        if self.mode == Mode::Strict {
            return Err(StepError::ReplayOverrun { actual: next });
        }
        Ok(attempt + 1)
    }

    /// Whether to stop after a failed attempt, and with what.
    ///
    /// Three gates in order, and a policy can only ever narrow what the first
    /// two allow:
    ///
    /// 1. [`Landed`](crate::core::Disposition::Landed) — the call took effect.
    ///    Repeating it would be a second real performance, so it never happens.
    /// 2. [`InDoubt`](crate::core::Disposition::InDoubt) — the same
    ///    undecidability a crash produces, resolved the same way: by the
    ///    declared [`Recovery`], never by guessing.
    /// 3. The policy's attempt count, which governs only failures the first two
    ///    have already cleared.
    ///
    /// Returns `None` when another attempt is permitted.
    #[allow(clippy::too_many_arguments)]
    fn stop_reason(
        disposition: crate::core::Disposition,
        recovery: &crate::core::Recovery,
        key: EffectKey,
        attempt: u32,
        policy: &crate::core::RetryPolicy,
        message: &str,
        permanent: bool,
    ) -> Option<StepError> {
        use crate::core::{Disposition, Recovery};

        match disposition {
            Disposition::Landed => {
                return Some(StepError::Effect(crate::core::EffectError::Final {
                    detail: format!(
                        "effect {key} took effect and its response could not be used \
                         ({message}); repeating it would perform it a second time"
                    ),
                    disposition,
                }));
            }
            Disposition::InDoubt => match recovery {
                // Safe to repeat by declaration: either genuinely idempotent,
                // or carrying an idempotency key the provider honours.
                Recovery::Retry | Recovery::Idempotent { .. } => {}
                Recovery::Reconcile => {
                    // Reached only once the probe has already run and come back
                    // inconclusive — the caller resolves what it can before
                    // asking this. The doubt survived being asked about.
                    return Some(StepError::Undecidable {
                        key,
                        recovery: recovery.clone(),
                        detail: format!(
                            "{message} — the reconciliation probe could not establish whether \
                             it landed"
                        ),
                    });
                }
                Recovery::RequiresOperator => {
                    return Some(StepError::Undecidable {
                        key,
                        recovery: recovery.clone(),
                        detail: format!("{message} — it may well have been applied"),
                    });
                }
            },
            Disposition::DidNotHappen => {
                // An answer, not a fault. The peer understood the request and
                // said no, so a second attempt asks the same rule the same
                // question — every further attempt would be spent teaching the
                // operator that retries are noise. The bit comes from the
                // failure itself live and from the record on replay, so both
                // stop at the same attempt.
                if permanent {
                    return Some(StepError::Effect(crate::core::EffectError::Final {
                        detail: format!(
                            "effect {key} was refused on attempt {attempt}, and the refusal                              is an answer rather than a fault ({message}); no retry would                              change it"
                        ),
                        disposition,
                    }));
                }
            }
        }

        // The disposition travels with the failure. Flattening it to `Other`
        // here — which reads as `InDoubt` — would tell every caller that a call
        // the driver explicitly *refused* might have happened, and the callers
        // that act on doubt are exactly the ones that must not be misled.
        (!policy.permits(attempt)).then(|| {
            StepError::Effect(crate::core::EffectError::Final {
                detail: format!(
                    "effect {key} failed on attempt {attempt} of {}: {message}",
                    policy.max_attempts
                ),
                disposition,
            })
        })
    }

    /// Suspend until an instant, durably.
    ///
    /// The run's frame is persisted and the task is dropped: a sleeping run
    /// costs a row, not a thread. A sweep wakes it when the instant arrives, so
    /// a plane can hold as many sleeping runs as it has disk and a restart loses
    /// none of them.
    ///
    /// The instant is recorded under an effect key, so replay reads it back
    /// rather than sleeping again — and a run that slept until Tuesday still
    /// says Tuesday when it is audited next year.
    pub async fn sleep_until(&mut self, until: Timestamp) -> Result<(), StepError> {
        let timers = self.timers.clone().ok_or_else(|| {
            StepError::Effect(crate::core::EffectError::Other(
                "durable timers need a timer store — build the runtime with `.timers(store)`"
                    .into(),
            ))
        })?;

        // Whole seconds, matching the store's precision. Two records of one
        // wake-up that disagree by a fraction of a second give "when does this
        // fire?" two answers.
        let until = until.replace_nanosecond(0).map_err(|e| {
            StepError::Effect(crate::core::EffectError::Other(format!(
                "unrepresentable wake instant: {e}"
            )))
        })?;

        // The sleep is an effect: its output is the instant it woke at. Replay
        // reads that back like any other recorded result, so none of the
        // suspension machinery exists twice.
        let descriptor = EffectDescriptor::new(
            "timer.sleep",
            serde_json::json!({ "until": until.unix_timestamp() }),
        );
        let key = self.next_effect_key(&descriptor);

        // ── Replay: the timer already fired ────────────────────────────────
        if self.mode.is_replaying() {
            match self.cursor.next(key)? {
                Some(EffectReplay::Done { spend, .. }) => {
                    self.bill(spend);
                    return Ok(());
                }
                Some(EffectReplay::Refused { limit, used }) => {
                    return Err(StepError::Budget(crate::core::BudgetExceeded::Recorded {
                        limit,
                        used,
                    }));
                }
                Some(EffectReplay::Denied {
                    reason,
                    action,
                    resource,
                }) => {
                    return Err(StepError::Denied {
                        action,
                        resource,
                        reason,
                    });
                }
                Some(EffectReplay::Failed { error, .. }) => {
                    return Err(StepError::Effect(crate::core::EffectError::Rejected(error)));
                }
                // Armed but not yet fired: still asleep. Suspend again rather
                // than re-arming, which would reset the clock every replay.
                Some(EffectReplay::Orphan { .. }) => {
                    return Err(StepError::Suspended(
                        crate::core::SuspendReason::AwaitingTime { until },
                    ));
                }
                None if self.mode == Mode::Strict => {
                    return Err(StepError::ReplayOverrun { actual: key });
                }
                None => {}
            }
        }

        // Announce before arming, so a crash between the two leaves an orphan
        // the resumed run recognises rather than a timer nobody is waiting on.
        self.append_effect(
            key,
            RecordKind::EffectStarted {
                descriptor,
                recovery: crate::core::Recovery::Retry,
                mutates: false,
                attempt: 1,
                backoff_ms: 0,
                // A durable wait binds no outbound value.
                outbound_label: None,
            },
        )
        .await?;

        timers
            .arm(&crate::core::Timer {
                run: self.run,
                case: self.case.as_ref().map(CaseContext::id),
                effect: key,
                step: self.step,
                phase: self.phase,
                fire_at: until,
            })
            .await?;

        Err(StepError::Suspended(
            crate::core::SuspendReason::AwaitingTime { until },
        ))
    }

    /// Suspend for a duration.
    ///
    /// The duration is resolved to an instant through the journaled clock, so
    /// the wake time is a recorded fact rather than a formula re-evaluated on
    /// every replay.
    pub async fn sleep(&mut self, how_long: std::time::Duration) -> Result<(), StepError> {
        let now = self.now().await?;
        let until = now
            .checked_add(time::Duration::try_from(how_long).map_err(|e| {
                StepError::Effect(crate::core::EffectError::Other(format!(
                    "unrepresentable sleep duration: {e}"
                )))
            })?)
            .ok_or_else(|| {
                StepError::Effect(crate::core::EffectError::Other(
                    "sleep duration overflows the representable range".into(),
                ))
            })?;
        self.sleep_until(until).await
    }

    /// Send a labeled value into a sink, enforcing the information-flow gates.
    ///
    /// Two checks, both of which are the reason labels exist at all:
    ///
    /// * **Egress ceiling** — a value's sensitivity may not exceed what the sink
    ///   is allowed to receive. This is the exfiltration path that actually
    ///   matters: not the network, but a legitimate-looking call carrying a
    ///   secret that was read three steps ago.
    /// * **Authority-bearing fields** — a mutating sink either refuses all
    ///   untrusted arguments or declares protected JSON fields with explicit
    ///   trust, source, and sensitivity constraints.
    pub async fn sink<E: Effect>(
        &mut self,
        effect: E,
        args: &Tainted<Value>,
    ) -> Result<Tainted<E::Output>, StepError> {
        let sink_name = effect.descriptor().kind;
        let label = args.label();

        let Some(bound) = effect.sink_arguments() else {
            return Err(PolicyError::UnboundSinkArguments { sink: sink_name }.into());
        };
        if canon::value_bytes(bound) != canon::value_bytes(args.peek()) {
            return Err(PolicyError::SinkArgumentsMismatch { sink: sink_name }.into());
        }

        // Manifest-derived ceilings apply to **live dispatch only**.
        //
        // A replay re-executes the deterministic zone and reads every effect
        // back from the journal; if today's manifest were consulted here, a
        // tightened ceiling would refuse an effect that already happened and a
        // loosened one would bless an effect that was refused. Either way the
        // replay stops reproducing the run and starts re-judging it under rules
        // that did not exist at the time — which this design rejects for policy
        // and must reject for declarations too, since a manifest is policy a
        // reviewer wrote.
        //
        // The sink's *own* ceiling still applies: that is code, and a code
        // change that alters an outcome is divergence, which quarantine exists
        // to catch.
        #[cfg(feature = "manifest")]
        let manifest_gates = !self.mode.is_replaying();

        let ceiling = {
            let effect_ceiling = effect.max_sensitivity();
            #[cfg(feature = "manifest")]
            {
                // Three ceilings, and the strictest wins: the sink's own, the
                // agent-wide egress ceiling, and the ceiling on *this tool's*
                // reviewed grant. The last is the finest-grained of the three —
                // "this tool may see internal data, that one may not" — and
                // omitting it made a per-tool declaration decorative.
                let effect_ceiling = self
                    .tool_grant_for(&effect.descriptor())
                    .and_then(|g| g.max_sensitivity)
                    .filter(|_| manifest_gates)
                    .map_or(effect_ceiling, |grant| effect_ceiling.min(grant));
                self.manifest
                    .as_ref()
                    .filter(|_| manifest_gates)
                    .and_then(|m| m.spec.security.max_sensitivity_egress)
                    .map_or(effect_ceiling, |manifest_ceiling| {
                        effect_ceiling.min(manifest_ceiling)
                    })
            }
            #[cfg(not(feature = "manifest"))]
            effect_ceiling
        };
        if label.sensitivity > ceiling {
            return Err(PolicyError::EgressCeiling {
                sink: sink_name,
                actual: label.sensitivity,
                ceiling,
            }
            .into());
        }

        // What may be *written down* is a different question from what may
        // leave, and it is the one that decides whether a run's personal data
        // can ever be erased: this effect's canonical arguments are about to
        // enter an append-only chain, where no record is ever removed. This is
        // the *refuse it* half; `RuntimeBuilder::keyring` is the *seal it* half,
        // and they compose — a sealed record is still a record, and a key ring
        // is still an operational dependency, so a deployment may want both.
        // Checked here, before the announcement, so the refusal costs nothing —
        // and absent by default, because every deployment before this field had
        // no ceiling and silence must not start refusing their traffic.
        #[cfg(feature = "manifest")]
        if let Some(journal_ceiling) = self
            .manifest
            .as_ref()
            .filter(|_| manifest_gates)
            .and_then(|m| m.spec.security.max_sensitivity_journaled)
            && label.sensitivity > journal_ceiling
        {
            return Err(PolicyError::JournalCeiling {
                sink: sink_name,
                actual: label.sensitivity,
                ceiling: journal_ceiling,
            }
            .into());
        }

        // The reviewed grant may only tighten — here as at the authorization
        // gate, which has ORed the manifest's `mutates` in since it existed.
        //
        // `Effect::mutates` on a tool call reports what the **catalogue** says.
        // A manifest declaring the same tool mutating is the deployment's own
        // statement about it, and the whole-value taint gate below is precisely
        // the control that statement buys. Without this line an operator
        // catalogue calling a reviewed-mutating tool read-only exempts it from
        // that gate, so model-chosen arguments reach something that changes the
        // world — the one direction `ToolBox::check_against` says nobody can be
        // right about, reached by the path that check cannot see.
        //
        // Live dispatch only, for the same reason the ceiling above is: a
        // tightened manifest must not re-judge an effect that already happened.
        #[cfg(feature = "manifest")]
        let mutates = effect.mutates()
            || (manifest_gates
                && self
                    .tool_grant_for(&effect.descriptor())
                    .is_some_and(|g| g.mutates));
        #[cfg(not(feature = "manifest"))]
        let mutates = effect.mutates();

        Self::enforce_protected_fields(&effect, args, sink_name, mutates)?;

        // The same label the gates above enforced, handed to the deployment's
        // own rules. See `authorize` for why it belongs there too.
        self.effect_after_sink_gate(effect, Some(label)).await
    }

    fn enforce_protected_fields<E: Effect>(
        effect: &E,
        args: &Tainted<Value>,
        sink_name: String,
        mutates: bool,
    ) -> Result<(), StepError> {
        let label = args.label();
        let protected = effect.protected_fields();
        if protected.is_empty() {
            if mutates && label.is_untrusted() {
                return Err(PolicyError::TaintGate { sink: sink_name }.into());
            }
            return Ok(());
        }

        for field in protected {
            let path = field.path();
            let Some(field_label) = args.label_at(path) else {
                return Err(PolicyError::ProtectedFieldMissing {
                    sink: sink_name,
                    path: path.to_owned(),
                }
                .into());
            };
            if field.requires_trusted() && field_label.is_untrusted() {
                return Err(PolicyError::ProtectedFieldTaint {
                    sink: sink_name,
                    path: path.to_owned(),
                }
                .into());
            }
            if !field.allowed_sources().is_empty() {
                let source = field_label
                    .provenance
                    .iter()
                    .find(|source| !field.allowed_sources().contains(*source));
                if let Some(source) = source {
                    return Err(PolicyError::ProtectedFieldSource {
                        sink: sink_name,
                        path: path.to_owned(),
                        actual_source: source.to_string(),
                    }
                    .into());
                }
                if field_label.provenance.is_empty() {
                    return Err(PolicyError::ProtectedFieldSource {
                        sink: sink_name,
                        path: path.to_owned(),
                        actual_source: "<no provenance>".to_owned(),
                    }
                    .into());
                }
            }
            if let Some(field_ceiling) = field.sensitivity_ceiling()
                && field_label.sensitivity > field_ceiling
            {
                return Err(PolicyError::ProtectedFieldSensitivity {
                    sink: sink_name,
                    path: path.to_owned(),
                    actual: field_label.sensitivity,
                    ceiling: field_ceiling,
                }
                .into());
            }
        }
        Ok(())
    }

    /// Improve a whole value's label, or selected structured field labels.
    ///
    /// The release is policy-authorized and permanently records the releaser,
    /// basis, field scope, destination, evidence, and prior label. A selected
    /// field release is accepted only when the value was assembled with
    /// [`Tainted::object`](crate::core::Tainted::object) or
    /// [`Tainted::array`](crate::core::Tainted::array), so precision can never
    /// be invented after provenance was flattened.
    pub async fn release(
        &mut self,
        value: Tainted<Value>,
        release: crate::core::Release,
    ) -> Result<Tainted<Value>, StepError> {
        release
            .validate()
            .map_err(|detail| PolicyError::InvalidRelease {
                detail: detail.to_owned(),
            })?;
        let label = value.label().clone();
        let field_labels = value
            .field_labels()
            .map(|(path, label)| (path.to_owned(), label.clone()))
            .collect::<BTreeMap<_, _>>();
        let value_bytes = canon::value_bytes(value.peek());
        let value_digest = crate::core::Digest::of(&value_bytes);
        let released = value
            .apply_release(&release)
            .ok_or(PolicyError::UntrackedReleaseField)?;
        let result_label = released.label().clone();
        let result_field_labels = released
            .field_labels()
            .map(|(path, label)| (path.to_owned(), label.clone()))
            .collect::<BTreeMap<_, _>>();
        let descriptor = EffectDescriptor::new(
            crate::core::ACTION_RELEASE,
            serde_json::json!({
                "release": &release,
                "label": &label,
                "field_labels": &field_labels,
                "result_label": &result_label,
                "result_field_labels": &result_field_labels,
                "value": value_digest,
            }),
        );
        let key = self.next_effect_key(&descriptor);

        if self.mode.is_replaying() {
            match self.cursor.next(key)? {
                Some(EffectReplay::Done { .. }) => return Ok(released),
                Some(EffectReplay::Denied {
                    reason,
                    action,
                    resource,
                }) => {
                    return Err(StepError::Denied {
                        action,
                        resource,
                        reason,
                    });
                }
                Some(_) => {
                    return Err(StepError::ReplayOverrun { actual: key });
                }
                None if self.mode == Mode::Strict => {
                    return Err(StepError::ReplayOverrun { actual: key });
                }
                None => {}
            }
        }

        self.authorize_release(key, &release, &label).await?;
        self.append_effect(
            key,
            RecordKind::Released {
                releaser: self.agent.clone(),
                release,
                label,
                field_labels,
                result_label,
                result_field_labels,
                value: value_digest,
            },
        )
        .await?;
        Ok(released)
    }

    /// Authorize a live release from the information-flow lattice.
    ///
    /// Historical releases are facts and are never re-judged during replay,
    /// matching the effect authorization rule. A denial is still journaled:
    /// otherwise a run would stop at a policy decision with no durable account
    /// of why it stopped.
    async fn authorize_release(
        &mut self,
        key: EffectKey,
        release: &crate::core::Release,
        label: &crate::core::Label,
    ) -> Result<(), StepError> {
        let Some(engine) = self.policy.clone() else {
            return Ok(());
        };

        let mut context = serde_json::json!({
            "run": self.run.to_string(),
            "step": self.step.0,
            "release": release,
            "label": label,
        });
        merge_identity(&mut context, self.identity.as_ref());
        let request = crate::core::PolicyRequest {
            principal: &self.agent,
            action: crate::core::ACTION_RELEASE,
            resource: "information_flow.label",
            context: &context,
        };

        self.ledger
            .lock()
            .expect("budget mutex")
            .admit_policy_check()
            .map_err(StepError::Budget)?;

        let crate::core::PolicyDecision::Deny { reason } = engine.authorize(&request) else {
            return Ok(());
        };

        tracing::error!(
            target: telemetry::POLICY_DENIED,
            run = %self.run,
            step = %self.step,
            action = crate::core::ACTION_RELEASE,
            resource = "information_flow.label",
            %reason,
        );
        self.meter
            .count(metrics::POLICY_DENIALS, crate::core::ACTION_RELEASE);
        self.append_effect(
            key,
            RecordKind::PolicyDenied {
                reason: reason.clone(),
                action: crate::core::ACTION_RELEASE.to_owned(),
                resource: "information_flow.label".to_owned(),
            },
        )
        .await?;

        Err(StepError::Denied {
            action: crate::core::ACTION_RELEASE.to_owned(),
            resource: "information_flow.label".to_owned(),
            reason,
        })
    }

    /// Whether non-effect records should be written right now.
    ///
    /// Effects carry keys and are matched against history individually, so they
    /// look after themselves. Bookkeeping records — notes, releases —
    /// have no key, so they need this rule instead:
    ///
    /// * `Live` — always write.
    /// * `Resume` — write only once history is exhausted. Inside the replayed
    ///   prefix these records already exist; re-appending them would duplicate
    ///   history rather than reconstruct it.
    /// * `Strict` — never write. Verification is a pure read, and a
    ///   verification pass that mutates the journal would corrupt the very
    ///   history it is checking, moving the chain head every time someone ran a
    ///   regression test.
    fn writes_enabled(&self) -> bool {
        match self.mode {
            Mode::Live => true,
            Mode::Resume => self.cursor.exhausted(),
            Mode::Strict => false,
        }
    }

    /// Consume a recorded failure and decide what the run did next.
    ///
    /// Billed on the way past, exactly as the live path bills it: a replayed run
    /// must reach the same budget verdict at the same point, and a metered
    /// failure is part of what the original run spent.
    #[allow(clippy::too_many_arguments)]
    fn replay_recorded_failure(
        &mut self,
        descriptor: &EffectDescriptor,
        ordinal: u32,
        attempt: u32,
        key: EffectKey,
        recovery: &crate::core::Recovery,
        policy: &crate::core::RetryPolicy,
        error: &str,
        disposition: crate::core::Disposition,
        spend: crate::core::Spend,
        permanent: bool,
    ) -> Result<u32, StepError> {
        self.bill(spend);
        self.recorded_failure(
            descriptor,
            ordinal,
            attempt,
            key,
            recovery,
            policy,
            error,
            disposition,
            permanent,
        )
    }

    /// Refuse an effect that would delegate deeper than the declaration allows.
    ///
    /// Live dispatch only, like every other manifest gate: a replay reads its
    /// effects back, so a tightened ceiling must not retroactively refuse an
    /// effect that already happened.
    // `self` and `effect` are both unused without `manifest`, and the ceiling
    // lives on the manifest — so a build with no manifest support has nothing to
    // check rather than a different rule.
    #[allow(
        unused_variables,
        clippy::unnecessary_wraps,
        clippy::unused_self,
        clippy::needless_pass_by_ref_mut
    )]
    fn check_delegation_depth<E: Effect>(&self, effect: &E) -> Result<(), StepError> {
        #[cfg(feature = "manifest")]
        let ceiling = self
            .manifest
            .as_ref()
            .filter(|_| !self.mode.is_replaying())
            .and_then(|manifest| {
                // Role is authority, not prose. A specialist means zero
                // delegation even when the duplicate numeric ceiling is
                // omitted; otherwise omission restores exactly the handoff
                // power the role claims not to have.
                manifest
                    .spec
                    .topology
                    .as_ref()
                    .is_some_and(|topology| topology.role == crate::manifest::Role::Specialist)
                    .then_some(0)
                    .or(manifest.spec.security.max_delegation_depth)
            });
        #[cfg(feature = "manifest")]
        if let (Some(actual), Some(ceiling)) = (effect.delegation_depth(), ceiling)
            && actual > usize::from(ceiling)
        {
            return Err(PolicyError::DelegationDepth {
                sink: effect.descriptor().kind,
                actual,
                ceiling: usize::from(ceiling),
            }
            .into());
        }
        Ok(())
    }

    /// One attempt: announce, act, record.
    ///
    /// The nested result separates two failures that must not be confused. The
    /// outer `StepError` is the runtime itself failing — the journal would not
    /// accept a write, the output would not encode — and is never retryable,
    /// because a runtime that cannot record what it did must not go on doing
    /// things. The inner `EffectError` is the *effect* failing, which is
    /// ordinary, journaled, and what the retry decision is made from.
    async fn perform_once<E: Effect>(
        &mut self,
        effect: &E,
        key: EffectKey,
        attempt: u32,
        backoff_ms: u64,
        write_start: bool,
        outbound: Option<&crate::core::Label>,
    ) -> Result<Result<E::Output, crate::core::EffectError>, StepError> {
        // `EffectStarted` goes down *before* the call. If the process dies
        // between here and the terminal record, replay sees an orphan and the
        // declared recovery mode decides — which is only possible because the
        // start was durable first.
        if write_start {
            self.append_effect(
                key,
                RecordKind::EffectStarted {
                    descriptor: effect.descriptor(),
                    recovery: effect.recovery(),
                    mutates: effect.mutates(),
                    attempt,
                    backoff_ms,
                    outbound_label: outbound.cloned(),
                },
            )
            .await?;
        }

        match effect.perform().await {
            Ok(output) => {
                let json = serde_json::to_value(&output)?;
                let spend = effect.spend(&output);
                self.bill(spend);
                self.append_effect(
                    key,
                    RecordKind::EffectDone {
                        output: json,
                        // Not an inbound event: only an awaited delivery has a
                        // sender to record.
                        source: None,
                        spend,
                    },
                )
                .await?;
                Ok(Ok(output))
            }
            Err(e) => {
                // A failed call still occupied a call, which is what lets
                // `max_effects` bound an effect that never succeeds — and it may
                // also have spent real money before dying. A stream cut off
                // after five hundred tokens is billed for five hundred tokens.
                let spend = e.spend();
                self.bill(spend);
                // The disposition is recorded alongside the message because it
                // is what every later decision reads — the retry taken now, and
                // an operator's judgement afterwards. Messages get reworded;
                // this is a fact about the run.
                self.append_effect(
                    key,
                    RecordKind::EffectFailed {
                        error: e.to_string(),
                        spend,
                        disposition: e.disposition(),
                        // An answer, not a fault — recorded so the replayed
                        // retry decision stops where the live one did.
                        permanent: matches!(e, crate::core::EffectError::Refused(_)),
                    },
                )
                .await?;
                Ok(Err(e))
            }
        }
    }

    async fn append_effect(&self, key: EffectKey, kind: RecordKind) -> Result<(), StepError> {
        self.store
            .append(self.epoch, vec![self.stamp(kind).effect(key)])
            .await?;
        Ok(())
    }

    pub(crate) async fn append(&self, kind: RecordKind) -> Result<(), StepError> {
        if !self.writes_enabled() {
            return Ok(());
        }
        self.store
            .append(self.epoch, vec![self.stamp(kind)])
            .await?;
        Ok(())
    }

    /// Tag a record with this step's run, step, and case.
    ///
    /// Every record of a case-bound run carries its case, which is what
    /// `JournalStore::case_history` scans. Without it, "show me everything
    /// about this matter" is a join over the case's runs — and one that misses
    /// every record written by a run the case does not own, which is exactly
    /// what a sweep is.
    fn stamp(&self, kind: RecordKind) -> Append {
        let mut a = Append::new(self.run, kind)
            .step(self.step)
            .phase(self.phase);
        if let Some(c) = &self.case {
            a = a.case(c.case_id);
        }
        a
    }
}

/// A refusal the recorded run met, as the error this one meets.
///
/// The verdict is history: a run refused by a ceiling or a rule was refused
/// then, whatever the ceiling or the rule says now. Re-deriving either would
/// re-judge last year's run under this year's configuration, which is the one
/// thing replay must never do.
fn recorded_refusal(replay: EffectReplay) -> StepError {
    match replay {
        EffectReplay::Refused { limit, used } => {
            StepError::Budget(crate::core::BudgetExceeded::Recorded { limit, used })
        }
        EffectReplay::Denied {
            reason,
            action,
            resource,
        } => StepError::Denied {
            action,
            resource,
            reason,
        },
        // The caller matches only these two.
        other => StepError::Effect(crate::core::EffectError::Other(format!(
            "not a recorded refusal: {other:?}"
        ))),
    }
}

/// Wall-clock read for subscription bookkeeping.
///
/// Infrastructure metadata, not run-visible state: it never enters the journal
/// and therefore cannot affect replay. Run-visible time goes through
/// `StepCtx::now`, which journals the instant.
#[allow(clippy::disallowed_methods)]
fn subscription_clock() -> Timestamp {
    Timestamp::now_utc()
}

/// Derive a reproducible RNG stream for one step.
fn seeded_rng(run: RunId, step: StepId) -> ChaCha8Rng {
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(&run.0.to_bytes());
    seed[16..20].copy_from_slice(&step.0.to_be_bytes());
    ChaCha8Rng::from_seed(seed)
}

/// Case-scoped operations.
///
/// Available only when the runtime was built with a case store and the run was
/// admitted with correlation keys. A run without a case is a perfectly ordinary
/// run — it simply has no long-lived state to reach.
impl StepCtx<'_> {
    /// The case this run belongs to, if any.
    #[must_use]
    pub fn case_id(&self) -> Option<CaseId> {
        self.case.as_ref().map(|c| c.case_id)
    }

    /// The business keys this run's case is identified by.
    ///
    /// Empty when the run has no case. These are the keys **as recorded when the
    /// run bound to the case**, not as the case stands now: a case accumulates
    /// keys over months, and reading the store here would make a resumed run see
    /// a set the live run never did.
    ///
    /// The intended use is scoping durable state to the party a run is about —
    /// `Recall::about(cx.correlation_value("meter")?)` reads back exactly what a
    /// declarative agent's `subject: "$correlation/meter"` wrote.
    #[must_use]
    pub fn correlation(&self) -> &[CorrelationKey] {
        self.case.as_ref().map_or(&[], |c| c.correlation.as_slice())
    }

    /// One correlation value by namespace.
    ///
    /// `None` for a run with no case, and for a namespace the case is not keyed
    /// by. Two keys sharing a namespace is a correlation the deployment set up,
    /// not something to arbitrate here, so the first in canonical order wins and
    /// the choice is stable across runs rather than dependent on store order.
    #[must_use]
    pub fn correlation_value(&self, namespace: &str) -> Option<&str> {
        self.correlation()
            .iter()
            .find(|key| key.namespace == namespace)
            .map(|key| key.value.as_str())
    }

    fn case_ctx(&self) -> Result<&CaseContext, StepError> {
        self.case.as_ref().ok_or_else(|| {
            StepError::Effect(crate::core::EffectError::Other(
                "this run has no case: build the runtime with a case store and admit the run \
                 with correlation keys"
                    .into(),
            ))
        })
    }

    /// Read the case's opaque state, and the revision it was read at.
    ///
    /// **A journaled effect**, so a replay reads back what the live run saw
    /// rather than whatever the case holds now. Case state is mutable storage
    /// shared by every run on the case; reading it is as non-deterministic as
    /// reading a clock, and treating it as free was a hole in exactly the
    /// property this crate exists to provide.
    ///
    /// The version comes back with the value because [`put_case_state`] needs
    /// it. Returning the value alone is what makes a lost update easy to write.
    ///
    /// [`put_case_state`]: Self::put_case_state
    ///
    /// # Errors
    ///
    /// [`StepError`] if this run has no case, or the read fails.
    pub async fn case_state(&mut self) -> Result<(Tainted<Value>, CaseVersion), StepError> {
        let cx = self.case_ctx()?.clone();
        let snapshot = self
            .effect(crate::runtime::effects::ReadCaseState {
                cases: Arc::clone(&cx.cases),
                case: cx.case_id,
            })
            .await?;
        let snapshot = snapshot.into_unlabelled();
        // **Untrusted, always.** Case state is shared mutable state: several
        // runs write it over a process that may last months, and the engine
        // never interprets a byte of it. So a read is only as trustworthy as
        // the least trustworthy thing anybody ever wrote — and nothing here
        // knows what that was.
        //
        // Returning `trusted()` made this an exit from the lattice. A skill
        // holding a model completion could `peek` it into case state and read
        // it back clean in a later step, or a later *run*, having passed none of
        // `cx.release`'s policy check and leaving no record that a
        // declassification happened. Every taint gate downstream then had
        // nothing to act on, which is the failure the labels exist to prevent.
        //
        // Storing the writer's label instead would be no better: it would
        // describe one write of many and read as authoritative. The join of
        // every writer is the only honest label, it decays to untrusted the
        // moment anything untrusted lands, and it never recovers on its own —
        // so this *is* that answer, without the machinery to arrive at it.
        //
        // A caller who genuinely needs it trusted asks for a release, which is
        // journaled, policy-checked, and names who decided.
        let label = crate::core::Label::untrusted(crate::core::SourceId::new(format!(
            "case:{}",
            cx.case_id
        )));
        Ok((Tainted::with_label(snapshot.state, label), snapshot.version))
    }

    /// Draw on a standing authority, or be refused.
    ///
    /// The ceiling that outlives a run: a customer's approved spend, a purchase
    /// order, a subscription mandate. A [`Budget`](crate::core::Budget) bounds
    /// this run and a [`TenantQuota`](crate::quota::TenantQuota) bounds a billing
    /// period; neither can express an authorization somebody granted once and may
    /// take back.
    ///
    /// Journaled, so a replay reads the receipt rather than consuming again, and
    /// idempotent across retries of the same call — see
    /// [`DrawOnAuthority`](crate::runtime::effects::DrawOnAuthority) for why the
    /// deduplication key is the dispatch rather than the effect.
    ///
    /// Expiry is evaluated against this run's journaled clock, so a replay
    /// reaches the verdict the live run did rather than today's.
    ///
    /// # Errors
    ///
    /// [`StepError::Store`] when no authority store is wired, and the effect's
    /// own error carrying whichever of the five refusals applies — unknown,
    /// exhausted, out of draws, revoked, or expired.
    pub async fn draw(
        &mut self,
        id: &crate::authority::AuthorityId,
        amount: crate::core::Spend,
    ) -> Result<crate::authority::Drawn, StepError> {
        let authorities = self.authorities.clone().ok_or_else(|| {
            StepError::Store(crate::core::StoreError::Backend(
                "no standing-authority store is configured; \
                 `Runtime::builder(..).authorities(..)` is what gives an agent a \
                 ceiling that outlives one run"
                    .to_owned(),
            ))
        })?;

        let at = self.now().await?;
        Ok(self
            .effect(crate::runtime::effects::DrawOnAuthority {
                authorities,
                id: id.clone(),
                amount,
                at,
                key: None,
            })
            .await?
            .into_unlabelled())
    }

    /// Recall what this agent remembers about a subject.
    ///
    /// # Every item comes back labelled from its **provenance**
    ///
    /// Never from its content. Text asserting its own reliability is the
    /// cheapest thing an attacker can write, so a memory derived from a model,
    /// a peer or an inbound message stays untrusted however many times it is
    /// re-read — and reaching a mutating sink with it takes the same journaled
    /// release as any other untrusted value.
    ///
    /// That is the defence against the attack this whole module is shaped by: a
    /// poisoned write becomes a standing instruction only if something later
    /// treats it as one.
    ///
    /// # Journaled, and replayed by version
    ///
    /// The **selection** is recorded — ids, versions, content digests — and a
    /// replay re-materialises exactly those versions rather than re-running the
    /// search. So a run replayed after the corpus changed reads what it read,
    /// not what a fresh ranking would return now.
    ///
    /// # Errors
    ///
    /// [`StepError`] if this plane has no memory store, if the recall fails, or
    /// if a version this run read can no longer be reproduced — which is a
    /// deliberate loud failure, not an empty result: a memory that was forgotten
    /// makes the history that used it unreplayable, and saying so beats
    /// replaying a different memory.
    pub async fn recall(
        &mut self,
        mut query: crate::memory::Recall,
    ) -> Result<Vec<Tainted<crate::memory::MemoryItem>>, StepError> {
        let memories = self.memories.clone().ok_or_else(|| {
            StepError::Store(crate::core::StoreError::Backend(
                "no memory store is configured; `Runtime::builder(..).memory(..)` is what \
                 gives an agent something to remember"
                    .to_owned(),
            ))
        })?;

        if query.as_of.is_none() {
            query.as_of = Some(self.now().await?);
        }
        let recall_at = query.as_of.expect("recall cutoff set above");
        let refresh_access = query.refresh_access;
        let selected = self
            .effect(crate::runtime::effects::RecallMemory {
                memories: Arc::clone(&memories),
                query,
            })
            .await?
            .into_unlabelled();

        if refresh_access && !selected.is_empty() {
            self.effect(crate::runtime::effects::TouchMemory {
                memories: Arc::clone(&memories),
                ids: selected.iter().map(|pick| pick.id.clone()).collect(),
                at: recall_at,
            })
            .await?;
        }

        let mut out = Vec::with_capacity(selected.len());
        for pick in selected {
            let item = memories
                .version(&pick.id, pick.version)
                .await
                .map_err(StepError::Store)?
                .ok_or_else(|| {
                    StepError::Store(crate::core::StoreError::Backend(
                        crate::memory::MemoryError::Forgotten {
                            id: pick.id.clone(),
                            version: pick.version,
                        }
                        .to_string(),
                    ))
                })?;

            // A version is supposed to be immutable. If content or label inputs
            // moved under one, the store cannot reproduce its own history — and
            // a replay that quietly used the new value would be a different run
            // wearing the old one's journal.
            if item.selection_digest() != pick.digest {
                return Err(StepError::Store(crate::core::StoreError::Backend(
                    crate::memory::MemoryError::Rewritten {
                        id: pick.id,
                        version: pick.version,
                    }
                    .to_string(),
                )));
            }

            let label = item.label();
            out.push(Tainted::with_label(item, label));
        }
        Ok(out)
    }

    /// Turn text into a vector, on the record.
    ///
    /// The vector this returns is what [`SemanticQuery::embedding`] wants, and
    /// going through here rather than calling an embedding client directly is
    /// what makes semantic retrieval replayable at all: the query vector is in
    /// the retrieval effect's key, and an embedding service is under no
    /// obligation to return the same floats twice. Journaled, so a strict replay
    /// reads the vector back instead of asking again — and so the call is
    /// metered and the model revision that produced it is on the record beside
    /// the numbers.
    ///
    /// The text carries its own label, and the returned vector carries it too: a
    /// vector derived from an untrusted document is untrusted, and sending
    /// confidential text to an embedding service is an egress like any other.
    ///
    /// [`SemanticQuery::embedding`]: crate::memory::SemanticQuery::embedding
    ///
    /// # Errors
    ///
    /// Whatever the effect protocol reports — a refused sink, an exhausted
    /// budget, or the embedder's own failure.
    pub async fn embed(
        &mut self,
        embedder: Arc<dyn crate::memory::Embedder>,
        text: Tainted<String>,
    ) -> Result<Tainted<Vec<f32>>, StepError> {
        let plain = text.peek().clone();
        let arguments = text.map(serde_json::Value::String);
        self.sink(
            crate::runtime::effects::Embed {
                embedder,
                text: plain,
                arguments: arguments.peek().clone(),
            },
            &arguments,
        )
        .await
    }

    /// Rank governed memories through a derived semantic index.
    ///
    /// The retriever returns only immutable `(id, version, digest)` commitments
    /// and scores. The selection is journaled; live execution and replay then
    /// materialize exact versions from the authoritative memory store and
    /// verify scope and digest before exposing content.
    pub async fn semantic_recall(
        &mut self,
        retriever: Arc<dyn crate::memory::SemanticRetriever>,
        query: Tainted<crate::memory::SemanticQuery>,
    ) -> Result<Vec<(Tainted<crate::memory::MemoryItem>, f32)>, StepError> {
        let memories = self.memories.clone().ok_or_else(|| {
            StepError::Store(crate::core::StoreError::Backend(
                "no memory store is configured; semantic retrieval needs authoritative memory"
                    .to_owned(),
            ))
        })?;
        let plain = query.peek().clone();
        let arguments = query.map(|query| {
            serde_json::to_value(query).expect("SemanticQuery serialization is infallible")
        });
        let hits = self
            .sink(
                crate::runtime::effects::SemanticRecall {
                    retriever,
                    query: plain.clone(),
                    arguments: arguments.peek().clone(),
                },
                &arguments,
            )
            .await?
            .into_unlabelled();
        let mut out = Vec::with_capacity(hits.len());
        for hit in hits {
            if !hit.score.is_finite() {
                return Err(StepError::Store(crate::core::StoreError::Backend(
                    "semantic retriever returned a non-finite score".to_owned(),
                )));
            }
            let item = memories
                .version(&hit.selected.id, hit.selected.version)
                .await
                .map_err(StepError::Store)?
                .ok_or_else(|| {
                    StepError::Store(crate::core::StoreError::Backend(
                        crate::memory::MemoryError::Forgotten {
                            id: hit.selected.id.clone(),
                            version: hit.selected.version,
                        }
                        .to_string(),
                    ))
                })?;
            if item.selection_digest() != hit.selected.digest
                || item.subject != plain.subject
                || plain
                    .purpose
                    .as_ref()
                    .is_some_and(|purpose| purpose != &item.purpose)
            {
                return Err(StepError::Store(crate::core::StoreError::Backend(
                    "semantic retriever returned an out-of-scope or changed memory commitment"
                        .to_owned(),
                )));
            }
            let label = item.label();
            out.push((Tainted::with_label(item, label), hit.score));
        }
        Ok(out)
    }

    /// Remember something, as a new version.
    ///
    /// Journaled: a replay that wrote again would append a second version of a
    /// memory this run wrote once, and the version number the run went on to use
    /// would be wrong.
    ///
    /// Trust, provenance and sensitivity are derived from `content`. They are
    /// not fields the caller can declare: allowing a skill to store untrusted
    /// model output with `trust: Trusted` would be an unjournaled release and a
    /// cross-session laundering primitive.
    ///
    /// # Errors
    ///
    /// [`StepError`] if this plane has no memory store, or the write fails.
    pub async fn remember(
        &mut self,
        write: crate::memory::MemoryWrite,
        content: Tainted<Value>,
    ) -> Result<u64, StepError> {
        let at = self.now().await?;
        self.remember_at(write, content, at, Vec::new()).await
    }

    async fn remember_at(
        &mut self,
        write: crate::memory::MemoryWrite,
        content: Tainted<Value>,
        at: crate::core::Timestamp,
        derived_from: Vec<crate::memory::Selected>,
    ) -> Result<u64, StepError> {
        let memories = self.memories.clone().ok_or_else(|| {
            StepError::Store(crate::core::StoreError::Backend(
                "no memory store is configured; `Runtime::builder(..).memory(..)` is what \
                 gives an agent something to remember"
                    .to_owned(),
            ))
        })?;
        let label = content.label().clone();
        let mut provenance: Vec<_> = label.provenance.iter().cloned().collect();
        provenance.sort();
        provenance.dedup();
        let item = crate::memory::MemoryItem {
            id: write.id,
            subject: write.subject,
            purpose: write.purpose,
            content: content.into_unlabelled(),
            provenance,
            sensitivity: label.sensitivity,
            trust: label.trust,
            written_by: self.run.to_string(),
            version: 0,
            created_at: at,
            expires_at: write.expires_at,
            access_retention_seconds: write.access_retention_seconds,
            superseded_at: None,
            derived_from,
        };
        Ok(self
            .effect(crate::runtime::effects::RememberMemory { memories, item })
            .await?
            .into_unlabelled())
    }

    /// Atomically erase memories expired at the run's journaled clock.
    ///
    /// Legal holds remain authoritative in the backend. The cutoff and removed
    /// count are journaled, so strict replay reports the historical decision
    /// without mutating memory a second time.
    pub async fn sweep_expired_memories(&mut self) -> Result<usize, StepError> {
        let memories = self.memories.clone().ok_or_else(|| {
            StepError::Store(crate::core::StoreError::Backend(
                "no memory store is configured; there is nothing to sweep".to_owned(),
            ))
        })?;
        let at = self.now().await?;
        Ok(self
            .effect(crate::runtime::effects::SweepExpiredMemory { memories, at })
            .await?
            .into_unlabelled())
    }

    /// Summarise memories into a new, derived memory.
    ///
    /// # The label is derived, never declared
    ///
    /// This is the difference between `compact` and
    /// [`remember`](Self::remember). A writer declares where ordinary content
    /// came from; a summary's provenance is not a matter of opinion — it is the
    /// **join of what was summarised**, plus the model that wrote it. Letting a
    /// caller declare it would make compaction the laundering step: read three
    /// untrusted memories, summarise, call the result trusted, and every gate
    /// downstream has nothing to act on.
    ///
    /// So the summary is untrusted whenever any input is, carries every input's
    /// sources, and takes the highest sensitivity of any of them.
    ///
    /// # It records what it was made from
    ///
    /// Sources are recorded with the exact versions read. That is what makes a
    /// summary **repairable**: a poisoned memory does not stop being a problem
    /// when it is forgotten, because its content keeps arriving in every summary
    /// that absorbed it. `MemoryStore::derivatives` walks that edge, and
    /// `forget_cascading` is the form an erasure request needs.
    ///
    /// # Compaction is an egress decision
    ///
    /// It sends the memories to a model. So [`Compaction::max_sensitivity`](crate::memory::Compaction::max_sensitivity)
    /// bounds what that model may be shown, and it defaults to `Public` —
    /// summarising is otherwise the way to move confidential content past a
    /// ceiling that stops every other path, while looking like housekeeping.
    ///
    /// # The originals stay
    ///
    /// Compaction adds; it does not delete. What a summary is *for* — fitting a
    /// context window — is a reason to stop reading the originals, not a reason
    /// to destroy the only record of what the summary claims to represent.
    ///
    /// # Errors
    ///
    /// [`StepError`] if this plane has no memory store, if the model call fails,
    /// or if the write fails.
    pub async fn compact(
        &mut self,
        into: crate::memory::Compaction,
        sources: &[Tainted<crate::memory::MemoryItem>],
        provider: Arc<dyn crate::model::ModelProvider>,
        model: crate::model::ModelId,
    ) -> Result<u64, StepError> {
        // The prompt is **built here**, from the sources, rather than accepted
        // from the caller. `cx.sink` refuses an effect whose outbound arguments
        // differ from the labelled value it checked, and a caller passing a
        // pre-built call would have to reproduce this assembly exactly to get
        // past that gate — an obligation nobody would meet twice.
        //
        // Labelled by the join of the sources, so the model call is checked like
        // any other outbound value rather than around it.
        let prompt = Tainted::object([
            (
                "instruction".to_owned(),
                Tainted::trusted(serde_json::Value::String(into.instruction.clone())),
            ),
            (
                "memories".to_owned(),
                Tainted::array(sources.iter().map(|s| {
                    let label = s.label().clone();
                    Tainted::with_label(s.peek().content.clone(), label)
                })),
            ),
        ]);

        let call = crate::model::ModelCall::new(provider, model, prompt.peek().clone())
            .with_max_sensitivity(into.max_sensitivity);
        let completion = self.sink(call, &prompt).await?;
        let label = completion.label().clone();
        let summary = completion.map(|c| c.structured.unwrap_or(serde_json::Value::String(c.text)));

        let mut provenance: Vec<crate::core::SourceId> = label.provenance.iter().cloned().collect();
        let mut sensitivity = label.sensitivity;
        let mut trust = label.trust;
        let mut derived_from = Vec::with_capacity(sources.len());
        for source in sources {
            let item = source.peek();
            derived_from.push(crate::memory::Selected {
                id: item.id.clone(),
                version: item.version,
                digest: item.selection_digest(),
            });
            let l = source.label();
            provenance.extend(l.provenance.iter().cloned());
            sensitivity = sensitivity.max(l.sensitivity);
            // Doubled on purpose, and no test can distinguish the two halves.
            // A summary is already untrusted because a model wrote it —
            // `ModelCall` declares `Trust::Untrusted` unconditionally — so this
            // line changes no outcome today. It is here for the day a
            // deterministic local summariser is declared trusted, at which point
            // the model half stops carrying it and this half is the only thing
            // between an untrusted memory and a trusted summary.
            //
            // Sensitivity and provenance above are *not* doubled: each is the
            // only thing computing its own field, and both are mutation-tested.
            if l.trust == crate::core::Trust::Untrusted {
                trust = crate::core::Trust::Untrusted;
            }
        }
        provenance.sort();
        provenance.dedup();

        // The explicit joins above protect a future trusted local summariser.
        // Bind them back onto the value before the common write path derives
        // storage metadata; no parallel metadata channel remains.
        let mut summary_label = label;
        summary_label.provenance = provenance.into_iter().collect();
        summary_label.sensitivity = sensitivity;
        summary_label.trust = trust;
        self.remember_at(
            crate::memory::MemoryWrite::new(into.id, into.subject, into.purpose),
            Tainted::with_label(summary.into_unlabelled(), summary_label),
            into.at,
            derived_from,
        )
        .await
    }

    /// Extract a bounded set of durable facts from labelled source material.
    ///
    /// Formation is not an ambient hook. The reviewed declaration supplies the
    /// destination and instruction; the model proposes only stable keys and
    /// content. Every proposal remains labelled from the model and source and
    /// is written through [`remember`](Self::remember).
    pub async fn form_memories(
        &mut self,
        formation: crate::memory::Formation,
        source: Tainted<Value>,
        provider: Arc<dyn crate::model::ModelProvider>,
        model: crate::model::ModelId,
    ) -> Result<Vec<(String, u64)>, StepError> {
        let source_label = source.label().clone();
        let prompt = Tainted::object([
            (
                "system".to_owned(),
                Tainted::trusted(serde_json::Value::String(formation.instruction.clone())),
            ),
            ("source".to_owned(), source),
        ]);
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "memories": {
                    "type": "array",
                    "maxItems": formation.max_items,
                    "items": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string", "minLength": 1},
                            "content": {}
                        },
                        "required": ["key", "content"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["memories"],
            "additionalProperties": false
        });
        let call = crate::model::ModelCall::new(provider, model, prompt.peek().clone())
            .with_max_sensitivity(formation.max_sensitivity)
            .with_output_sensitivity(source_label.sensitivity)
            .expecting(schema);
        let completion = self.sink(call, &prompt).await?;
        let label = completion.label().join(&source_label);

        // The schema above is enforced at the effect boundary, so a well-formed
        // answer is the only one that reaches here. It is still read defensively
        // rather than unwrapped: the boundary's *shape* check runs in every
        // build but its full JSON Schema validation needs `jsonschema`, which a
        // bare `testkit` build does not have. A model's answer is untrusted
        // data, and untrusted data must never be able to abort the process —
        // a panic here would unwind a run that has already announced effects,
        // leaving exactly the terminal-record-less outcome I2 exists to prevent.
        let unusable = |detail: &str| {
            StepError::Effect(crate::core::EffectError::Rejected(format!(
                "memory formation for subject `{}` could not read the model's answer: {detail}",
                formation.subject
            )))
        };
        let value = completion
            .peek()
            .structured
            .as_ref()
            .ok_or_else(|| unusable("it carried no structured value"))?;
        let proposals = value["memories"]
            .as_array()
            .ok_or_else(|| unusable("`memories` is not an array"))?
            .clone();
        let mut written = Vec::with_capacity(proposals.len());
        for proposal in proposals {
            let key = proposal["key"]
                .as_str()
                .ok_or_else(|| unusable("a proposal carries no string `key`"))?;
            let id = format!(
                "formed-{}",
                crate::core::Digest::of(&crate::core::canon::value_bytes(&serde_json::json!({
                    "subject": formation.subject,
                    "purpose": formation.purpose,
                    "key": key,
                })))
                .to_hex()
            );
            let mut destination = crate::memory::MemoryWrite::new(
                id.clone(),
                formation.subject.clone(),
                formation.purpose.clone(),
            );
            destination.expires_at = formation.expires_at;
            destination.access_retention_seconds = formation.access_retention_seconds;
            let version = self
                .remember(
                    destination,
                    Tainted::with_label(proposal["content"].clone(), label.clone()),
                )
                .await?;
            written.push((id, version));
        }
        Ok(written)
    }

    /// The blob store for this run, sealed to its case.
    ///
    /// **Use this rather than a store held from the builder.** With a key ring
    /// configured, bytes written here are encrypted under the case's data key,
    /// and a store obtained any other way writes them in the clear — the two
    /// would disagree about what erasing the case actually erased. It is also
    /// what a skill passes to
    /// [`ModelCall::with_media`](crate::model::ModelCall::with_media), so
    /// materialization reads through the same envelope that sealed the bytes.
    ///
    /// # Errors
    ///
    /// If no blob store is configured, or the run belongs to no case while a
    /// key ring is — there would be no erasure unit to scope the key to, and
    /// falling back to storing in the clear would silently drop the guarantee.
    pub fn blobs(&self) -> Result<Arc<dyn crate::blob::BlobStore>, StepError> {
        self.blobs_scoped(None)
    }

    /// The blob store, sealed to whichever unit owns erasure for these bytes.
    ///
    /// `scope` overrides the case, for bytes whose lifecycle another controller
    /// owns — named external media retention is the only such caller. Sealing
    /// those under a case they do not belong to would put them in an erasure
    /// unit that does not own them; not sealing them would leave a hole in a
    /// deployment that asked for none.
    fn blobs_scoped(
        &self,
        scope: Option<&str>,
    ) -> Result<Arc<dyn crate::blob::BlobStore>, StepError> {
        let blobs = self.blobs.clone().ok_or_else(|| {
            StepError::Store(crate::core::StoreError::Backend(
                "no blob store is configured; `Runtime::builder(..).blobs(..)` is what lets \
                 bytes live outside the journal"
                    .to_owned(),
            ))
        })?;

        #[cfg(feature = "keyring")]
        if let Some(keys) = self.keyring.clone() {
            // The tenant prefixes every scope. Without it two tenants sharing a
            // key ring collide the moment they use the same case or retention
            // name — and the collision is invisible until one tenant's erasure
            // destroys the other's key. `TenantId` refuses `/` for exactly this
            // reason, so the prefix cannot be forged by naming a tenant
            // `acme/prod`.
            let unit = match scope {
                Some(s) => s.to_owned(),
                None => self
                    .case
                    .as_ref()
                    .ok_or_else(|| {
                        StepError::Store(crate::core::StoreError::Backend(
                            "a key ring is configured but this run belongs to no case and no \
                             other erasure unit was named, so there is nothing to scope its data \
                             key to. Bind the run to a case, name an external retention policy, \
                             or drop the key ring — storing these bytes in the clear would leave \
                             an erasure that silently does not reach them"
                                .to_owned(),
                        ))
                    })?
                    .case_id
                    .to_string(),
            };
            let scope = crate::keyring::scope(&self.tenant, &unit);
            return Ok(Arc::new(crate::keyring::EncryptedBlobs::new(
                blobs, keys, scope,
            )));
        }
        let _ = scope;
        Ok(blobs)
    }

    /// Store bytes in the blob store and record that this case produced them.
    ///
    /// The reason this lives on the context rather than on the blob store: the
    /// runtime knows which case is running and the blob store deliberately does
    /// not — it is content-addressed, and a digest cannot be reversed to find
    /// the matter it belonged to. Writing through here means the association is
    /// made at the only moment it is knowable, so an erasure request can later
    /// be answered by case, which is the only unit anybody actually asks about.
    /// The association is made before the blob write: a crash can leave a
    /// harmless dangling link, repaired by retry, but never durable bytes that
    /// case erasure cannot discover.
    ///
    /// Deliberately **not** a journaled effect. The digest is a pure function of
    /// the bytes, so a replay that re-derives it gets the same answer without
    /// re-performing anything, and writing content-addressed bytes twice is the
    /// same write. What *is* journaled is whatever the skill does with the
    /// digest next — a tool call carrying it, a case-state write recording it.
    ///
    /// # Errors
    ///
    /// If no blob store is configured, if the write fails, or if this step is
    /// not running inside a case.
    pub async fn store_blob(&mut self, bytes: &[u8]) -> Result<crate::core::Digest, StepError> {
        let cx = self.case_ctx()?.clone();
        let digest = crate::core::Digest::of(bytes);
        // Through `blobs()`, so a sealed deployment seals these too rather than
        // having one write path that encrypts and another that does not.
        let blobs = if self.mode == Mode::Strict {
            None
        } else {
            Some(self.blobs()?)
        };
        let at = self.now().await?;
        let Some(blobs) = blobs else {
            return Ok(digest);
        };
        // Link before put: a crash may leave a dangling, erasable reference,
        // but can never leave durable bytes unreachable from case erasure.
        cx.cases
            .link_blob(cx.case_id, digest, at)
            .await
            .map_err(StepError::Store)?;
        let stored = blobs
            .put(bytes)
            .await
            .map_err(|e| StepError::Store(crate::core::StoreError::Backend(e.to_string())))?;
        debug_assert_eq!(stored, digest, "blob stores compute the content digest");
        Ok(digest)
    }

    /// Fetch remote media through the governed, replayable ingestion boundary.
    ///
    /// The URL stays labelled and is bound byte-for-byte to the fetch effect.
    /// The fetcher checks and pins DNS, validates every redirect, caps time and
    /// bytes, refuses content coding and ungranted media types, runs configured
    /// validators, and writes the bytes to content-addressed blob storage. The
    /// journal receives only [`FetchedMedia`](crate::media::FetchedMedia).
    ///
    /// When the run belongs to a case, the digest is linked before blob storage
    /// so [`erase_case`](crate::blob::erase_case) can enforce retention even
    /// across crashes. Strict replay consumes the same clock record but never
    /// rewrites that link.
    ///
    /// # Errors
    ///
    /// If no blob store is configured, any fetch control refuses the URL or
    /// response, validation fails, or blob/case storage fails.
    #[cfg(feature = "media")]
    pub async fn fetch_media(
        &mut self,
        fetcher: &crate::media::GovernedMedia,
        url: Tainted<String>,
    ) -> Result<Tainted<crate::media::FetchedMedia>, StepError> {
        if fetcher.requires_case() && self.case.is_none() {
            return Err(StepError::Store(crate::core::StoreError::Backend(
                "governed media requires a case for retention; configure a named external retention policy only when another lifecycle controller owns erasure"
                    .to_owned(),
            )));
        }
        // Through the sealed accessor: media bytes are payload bytes, and a
        // fetch path that wrote them in the clear would leave exactly the hole
        // this deployment configured a key ring to close.
        // Propagated rather than replaced. Mapping every failure onto "no blob
        // store is configured" would report a missing *erasure unit* as a
        // missing store, and send whoever reads it to fix the wrong thing.
        let blobs = self.blobs_scoped(fetcher.external_scope())?;
        let raw = url.peek().clone();
        let arguments = Tainted::object([("url".to_owned(), url.map(Value::String))]);
        let case_link = if let Some(cx) = self.case.clone() {
            let at = self.now().await?;
            (self.mode != Mode::Strict).then_some(crate::media::MediaCaseLink {
                cases: cx.cases,
                case: cx.case_id,
                at,
            })
        } else {
            None
        };
        self.sink(fetcher.effect(blobs, &raw, case_link), &arguments)
            .await
    }

    /// Replace the case's opaque state, if it is still at `at`.
    ///
    /// **A journaled effect**, so a replay does not write again.
    ///
    /// # Why you have to pass the version
    ///
    /// A case is shared by every run correlated to it, and the window between
    /// reading its state and writing it back contains a model call — which is
    /// unbounded. Two runs on one case overlap as a matter of course, and a
    /// blind write in that window silently discards whichever one lost, with
    /// nothing in the record to show it happened.
    ///
    /// Passing the version you read makes that unexpressible: the store rejects
    /// a write against a revision the case has moved past. The remedy is to
    /// re-read and decide again — **not** to retry the same write, which is the
    /// lost update this exists to prevent.
    ///
    /// # Errors
    ///
    /// [`StepError`] if this run has no case, or if the case has moved on since
    /// `at` — see [`StoreError::CaseConflict`](crate::core::StoreError::CaseConflict).
    pub async fn put_case_state(
        &mut self,
        at: CaseVersion,
        state: Value,
    ) -> Result<CaseVersion, StepError> {
        let cx = self.case_ctx()?.clone();
        let version = self
            .effect(crate::runtime::effects::WriteCaseState {
                cases: Arc::clone(&cx.cases),
                case: cx.case_id,
                expected: at,
                state,
            })
            .await?;
        Ok(version.into_unlabelled())
    }

    /// Move the case to a new status.
    pub async fn set_case_status(&mut self, status: CaseStatus) -> Result<(), StepError> {
        let cx = self.case_ctx()?.clone();
        self.effect(crate::runtime::effects::SetCaseStatus {
            cases: Arc::clone(&cx.cases),
            case: cx.case_id,
            status,
        })
        .await?;
        Ok(())
    }

    /// Register a durable obligation on the case.
    ///
    /// Resolution goes through the configured [`Calendar`] as a journaled
    /// effect, so replay reads back the instant the original run registered
    /// rather than recomputing it against whatever the calendar says today.
    /// That is what keeps a corrected holiday table from retroactively moving a
    /// deadline that has already been relied upon.
    ///
    /// # Why `warn_before` is a `std::time::Duration`
    ///
    /// Two reasons, and the second is the one that bites. It used to be
    /// `time::Duration`, which is **signed** — so a negative warning offset
    /// parsed, compiled, and put `warn_at` *after* the instant it warns about:
    /// a warning that can only fire once the obligation is already breached.
    /// A quantity that only makes sense non-negative is an unsigned type here,
    /// as it is for [`Spend`](crate::core::Spend).
    ///
    /// And it is the `Duration` a caller already has.
    /// [`sleep`](Self::sleep) takes the standard one, so the public surface had
    /// two types spelled `Duration`, only one of which came from a crate this
    /// one re-exports — a reader with the obvious `use std::time::Duration`
    /// met a type error naming a dependency the guides never mentioned.
    pub async fn deadline(
        &mut self,
        name: impl Into<String>,
        spec: &DeadlineSpec,
        warn_before: Option<std::time::Duration>,
    ) -> Result<Deadline, StepError> {
        let name = name.into();
        let cx = self.case_ctx()?.clone();

        let from = self.now().await?;
        let resolved = self
            .effect(ResolveDeadline {
                calendar: Arc::clone(&cx.calendar),
                name: name.clone(),
                from,
                spec: spec.clone(),
            })
            .await?
            .into_unlabelled();

        let deadline = Deadline {
            case: cx.case_id,
            name: name.clone(),
            resolved_at: resolved.at,
            calendar_digest: resolved.calendar_digest,
            warn_at: warn_before
                .and_then(|d| time::Duration::try_from(d).ok())
                .and_then(|d| resolved.at.checked_sub(d)),
            state: DeadlineState::Pending,
        };

        // Idempotent by primary key, so a resumed run re-registering the same
        // obligation is a no-op rather than a duplicate.
        cx.cases.register_deadline(&deadline).await?;

        self.append(RecordKind::DeadlineRegistered {
            name,
            resolved_at: resolved.at,
            calendar_digest: resolved.calendar_digest,
        })
        .await?;

        Ok(deadline)
    }

    /// Mark an obligation satisfied.
    ///
    /// A case cannot be closed while any obligation is still open, so this is
    /// what turns "we did the thing" into "the case may now be concluded".
    pub async fn meet_deadline(&mut self, name: &str) -> Result<(), StepError> {
        self.transition_deadline(name, DeadlineState::Met).await
    }

    /// Withdraw an obligation that no longer applies.
    pub async fn cancel_deadline(&mut self, name: &str) -> Result<(), StepError> {
        self.transition_deadline(name, DeadlineState::Cancelled)
            .await
    }

    async fn transition_deadline(
        &mut self,
        name: &str,
        to: DeadlineState,
    ) -> Result<(), StepError> {
        let cx = self.case_ctx()?.clone();
        // The read of `from` happens *inside* the effect, so it is journaled
        // with the write it describes rather than beside it. Reading here would
        // put a store lookup in the deterministic zone, and a replay would
        // report whatever the deadline says now as the state it moved from.
        let before = self
            .effect(crate::runtime::effects::TransitionDeadline {
                cases: Arc::clone(&cx.cases),
                case: cx.case_id,
                name: name.to_owned(),
                to,
            })
            .await?
            .into_unlabelled();

        // A readable summary beside the effect record, for the same reason
        // `StepCompensated` exists: "met" and "cancelled" mean very different
        // things to whoever reads this in six months, and reconstructing them
        // from an effect descriptor is work nobody does.
        self.append(RecordKind::DeadlineTransition {
            name: name.to_owned(),
            from: before,
            to,
        })
        .await?;
        Ok(())
    }
}

/// Durable waits.
impl StepCtx<'_> {
    /// Wait for an inbound event correlated by business key.
    ///
    /// On replay this returns the event that was recorded; on first execution it
    /// either finds one already buffered, or suspends the run.
    ///
    /// # The ordering that makes this safe
    ///
    /// An event can arrive *before* the run reaches this call — a fast
    /// counterparty, a slow earlier step, a retry that overtakes. So this looks
    /// in the durable buffer **first**, and only registers a subscription and
    /// suspends if nothing is there. Delivery and waiting meet in the store
    /// rather than in time, which is the only way to close the race.
    ///
    /// # Errors
    ///
    /// Returns [`StepError::Suspended`] when the event has not arrived. That is
    /// **not a failure** — propagate it with `?`. Catching it turns a durable
    /// wait into a silent hang: the subscription stays live, the event arrives
    /// later, and it resumes a run that already decided it was finished.
    pub async fn await_event(&mut self, spec: &AwaitSpec) -> Result<Tainted<Value>, StepError> {
        let correlation = spec.correlation.clone();
        self.wait_on(
            &spec.kind,
            move |_| correlation,
            &spec.deadline,
            |_| async { Ok(()) },
        )
        .await
    }

    /// Ask a human, and wait for the answer.
    ///
    /// The task is created, the run suspends, and a decision resumes it. Because
    /// the task id is derived from the awaiting effect rather than minted, a
    /// resumed run addresses the same task instead of opening a second one for
    /// the same decision.
    ///
    /// # Errors
    ///
    /// Returns [`StepError::Suspended`] until somebody decides. Propagate it —
    /// see [`Self::await_event`].
    pub async fn task(&mut self, spec: &TaskSpec) -> Result<Decision, StepError> {
        let cx = self.case_ctx()?.clone();
        let tasks = cx.tasks.clone().ok_or_else(|| {
            StepError::Effect(crate::core::EffectError::Other(
                "human tasks need a task store — build the runtime with `.tasks(store)`".into(),
            ))
        })?;

        // Acting unattended must be chosen deliberately, not picked off a list.
        if spec.on_expiry == OnExpiry::Proceed && !spec.allow_unattended {
            return Err(StepError::Effect(crate::core::EffectError::Other(
                "OnExpiry::Proceed requires `allow_unattended()`: acting without a human \
                 when the window closes must be an explicit decision, not a default"
                    .into(),
            )));
        }

        let due_at = self.deadline_instant(&cx, &spec.deadline).await?;
        // The run's journaled clock, not the obligation's instant.
        //
        // `created_at` was the deadline. Both fields then said *when this is
        // due*, so a worklist reported every row as created in the future and
        // "oldest first" silently meant "soonest due" — a reasonable ordering
        // under a field name that denies it, which is the worst combination for
        // an operator trying to explain a backlog.
        let created_at = self.now().await?;
        let run = self.run;
        let case_id = cx.case_id;
        let spec = spec.clone();

        let answer = self
            .wait_on(
                TASK_DECIDED,
                |key| {
                    vec![CorrelationKey::new(
                        "task",
                        TaskId::derive(run, key).to_hex(),
                    )]
                },
                &spec.deadline.clone(),
                move |key| {
                    let tasks = Arc::clone(&tasks);
                    let spec = spec.clone();
                    async move {
                        let id = TaskId::derive(run, key);
                        tasks
                            .open(&Task {
                                id,
                                run,
                                case: Some(case_id),
                                kind: spec.kind.clone(),
                                justification: spec.justification.clone(),
                                candidate_roles: spec.candidate_roles.clone(),
                                excluded_actors: spec.excluded_actors.clone(),
                                assignee: None,
                                priority: spec.priority,
                                state: TaskState::Open,
                                on_expiry: spec.on_expiry,
                                created_at,
                                due_at: Some(due_at),
                            })
                            .await?;
                        Ok(())
                    }
                },
            )
            .await?;

        // A decision is a human's assertion, not a fact the engine verified.
        let decision: Decision = serde_json::from_value(answer.peek().clone())?;
        Ok(decision)
    }

    /// Put something in front of a person **without waiting for them**.
    ///
    /// # The control an advisory agent needs
    ///
    /// [`task`](Self::task) asks and blocks. That is the right shape when the
    /// answer decides what happens next, and the wrong one when nothing does: an
    /// agent that has finished, whose finding a compliance desk must see, does
    /// not need its run suspended — it needs a row in a worklist. Gating the
    /// *answer* to achieve that is a worklist that blocks, and it costs one
    /// suspended run per finding at whatever rate the world produces them.
    ///
    /// So this opens the row and returns its id. The run continues, and nothing
    /// resumes on the decision because nothing is waiting on it.
    ///
    /// # Journaled, and the id is derived
    ///
    /// It is an ordinary mutating effect: replay reads the id back rather than
    /// opening a second row, and the id is derived from the effect key so a
    /// *resume* addresses the row it already opened. `TaskStore::open` is
    /// idempotent on that id, which is what makes an interrupted attempt safe to
    /// repeat.
    ///
    /// # The justification is untrusted, deliberately
    ///
    /// What a reviewer is shown usually came from a model, and this does **not**
    /// route it through the sink gate — the same arrangement [`task`](Self::task)
    /// has always had. Refusing untrusted content at a worklist would mean a
    /// task could only ever carry content nobody needs to review. See
    /// [`OpenTask`](crate::runtime::effects::OpenTask) for the whole argument.
    ///
    /// # Errors
    ///
    /// [`StepError`] if this run has no case, if no task store is wired, or if
    /// the named obligation is not registered on the case.
    pub async fn open_task(&mut self, spec: &TaskSpec) -> Result<TaskId, StepError> {
        let cx = self.case_ctx()?.clone();
        let tasks = cx.tasks.clone().ok_or_else(|| {
            StepError::Effect(crate::core::EffectError::Other(
                "human tasks need a task store — build the runtime with `.tasks(store)`".into(),
            ))
        })?;
        // A notification is not a decision, so `OnExpiry::Proceed` has nothing
        // to proceed *past* and the unattended consent it demands would be
        // consent to nothing. Refused rather than accepted-and-ignored.
        if spec.on_expiry == OnExpiry::Proceed {
            return Err(StepError::Effect(crate::core::EffectError::Other(
                "a task opened beside an answer has no decision to wait for, so \
                 `OnExpiry::Proceed` describes nothing — the run has already proceeded. \
                 Use `Deny` to let the window close, or `Escalate` to widen the audience"
                    .into(),
            )));
        }
        let due_at = self.deadline_instant(&cx, &spec.deadline).await?;
        let at = self.now().await?;
        let run = self.run;
        Ok(self
            .effect(crate::runtime::effects::OpenTask {
                tasks,
                run,
                case: cx.case_id,
                spec: spec.clone(),
                at,
                due_at,
                key: None,
            })
            .await?
            .into_unlabelled())
    }

    /// The shared machinery behind [`Self::await_event`] and [`Self::task`].
    ///
    /// `before_suspend` runs once, after the effect key is known and the
    /// subscription is registered, but before the buffer is consulted — the
    /// window in which a task row must exist so that a decision arriving
    /// immediately has something to attach to.
    async fn wait_on<C, F, Fut>(
        &mut self,
        kind: &str,
        correlate: C,
        deadline: &str,
        before_suspend: F,
    ) -> Result<Tainted<Value>, StepError>
    where
        C: FnOnce(EffectKey) -> Vec<CorrelationKey> + Send,
        F: FnOnce(EffectKey) -> Fut + Send,
        Fut: std::future::Future<Output = Result<(), StepError>> + Send,
    {
        // Correlation is computed from the key rather than passed in, because a
        // human task's correlation key *is* its id, and that id is derived from
        // the key. Taking a closure resolves the circularity without a second
        // identifier that could drift from the first.
        let key_preview = self.preview_key(kind, &[]);
        let spec = &AwaitSpec {
            kind: kind.to_owned(),
            correlation: correlate(key_preview),
            deadline: deadline.to_owned(),
        };
        let cx = self.case_ctx()?.clone();
        let events = cx.events.clone().ok_or_else(|| {
            StepError::Effect(crate::core::EffectError::Other(
                "durable waits need an event store — build the runtime with `.events(store)`"
                    .into(),
            ))
        })?;

        // The wait is an effect: its output is the event. That means replay
        // reads the event back like any other recorded result, and none of the
        // suspension machinery has to exist twice.
        let descriptor =
            EffectDescriptor::new("event.await", serde_json::json!({ "kind": spec.kind }));
        let key = self.preview_key(kind, &[]);
        debug_assert_eq!(
            key,
            EffectKey::derive(
                self.step,
                self.phase,
                self.ordinal,
                1,
                &descriptor.kind,
                &canon::value_bytes(&descriptor.args),
            ),
            "the previewed key must match the one the effect is recorded under"
        );
        self.ordinal += 1;

        // ── Replay: the event is already in history ────────────────────────
        if self.mode.is_replaying()
            && let Some(recorded) = self.replayed_wait(key, spec, &cx).await?
        {
            return Ok(recorded);
        }

        let subscription = Subscription {
            run: self.run,
            case: Some(cx.case_id),
            effect: key,
            step: self.step,
            phase: self.phase,
            kind: spec.kind.clone(),
            correlation: spec.correlation.clone(),
        };

        // NOTE: deliberately not `self.now()`. That is itself an effect, and
        // taking it here would give the clock a later ordinal but an earlier
        // journal position — replay verifies journal order, so the two must
        // agree. The subscription's timestamp is store metadata anyway, like a
        // lease: it never enters the journal and cannot affect replay.
        let now = subscription_clock();

        // Announce the wait before releasing the frame, so an event arriving in
        // the same instant finds a durable subscription rather than a gap.
        self.append_effect(
            key,
            RecordKind::EffectStarted {
                descriptor,
                recovery: crate::core::Recovery::Retry,
                mutates: false,
                attempt: 1,
                backoff_ms: 0,
                // An awaited inbound event binds no outbound value.
                outbound_label: None,
            },
        )
        .await?;
        events.subscribe(&subscription, now).await?;

        // Whatever must exist for a decision to attach to — a task row, say —
        // is created here: after the subscription is durable, before the buffer
        // is consulted. An answer arriving in this window finds both.
        before_suspend(key).await?;

        // Look in the buffer: the event may already be here.
        if let Some(buffered) = events.claim_for(&subscription, now).await? {
            events.unsubscribe(self.run, key).await?;
            self.append_effect(
                key,
                RecordKind::EffectDone {
                    output: buffered.event.payload.clone(),
                    source: Some(buffered.event.source.clone()),
                    spend: crate::core::Spend::default(),
                },
            )
            .await?;
            return Ok(Self::label_inbound(
                buffered.event.payload,
                &spec.kind,
                Some(&buffered.event.source),
            ));
        }

        Err(StepError::Suspended(self.suspend_reason(spec, &cx).await?))
    }

    /// The key this wait will be recorded under, computed without advancing the
    /// ordinal.
    ///
    /// Needed because a human task's correlation key is derived from its own
    /// effect key, so the key must be known before the subscription is built.
    fn preview_key(&self, kind: &str, _unused: &[CorrelationKey]) -> EffectKey {
        // Attempt 1, always: a wait that times out suspends or dead-letters,
        // it never repeats, so there is no second attempt to distinguish.
        EffectKey::derive(
            self.step,
            self.phase,
            self.ordinal,
            1,
            "event.await",
            &canon::value_bytes(&serde_json::json!({ "kind": kind })),
        )
    }

    /// An inbound message is external data by definition, and is labeled as
    /// such — including when it comes from a first-party system.
    ///
    /// The label names the *kind*, not the sender, and that is a limitation
    /// rather than a choice. A replayed run rebuilds this from the recorded
    /// await, which carries the payload and not the source — so deriving the
    /// label from `InboundEvent::source` would give a live run and its replay
    /// two different labels, which is divergence. Naming the sender in
    /// provenance needs the source journaled with the await first.
    fn label_inbound(payload: Value, kind: &str, source: Option<&str>) -> Tainted<Value> {
        let mut label =
            crate::core::Label::untrusted(crate::core::SourceId::new(format!("event:{kind}")));
        // Provenance accumulates, so the kind and the sender are both there: a
        // sink may allow an authority-bearing field from `event:ack` generally,
        // or from one counterparty in particular.
        if let Some(source) = source {
            label
                .provenance
                .insert(crate::core::SourceId::new(format!("sender:{source}")));
        }
        Tainted::with_label(payload, label)
    }

    /// The instant an obligation falls due.
    ///
    /// A wait's horizon is the obligation that bounds it, and the reviewer's
    /// deadline is the same fact — so both read it from one place rather than
    /// each computing their own.
    async fn deadline_instant(&self, cx: &CaseContext, name: &str) -> Result<Timestamp, StepError> {
        cx.cases
            .deadlines(cx.case_id)
            .await?
            .into_iter()
            .find(|d| d.name == name)
            .map(|d| d.resolved_at)
            .ok_or_else(|| {
                StepError::Effect(crate::core::EffectError::Other(format!(
                    "wait references deadline '{name}', which is not registered on this case \
                     — register it before waiting, or the run has no horizon"
                )))
            })
    }

    async fn suspend_reason(
        &self,
        spec: &AwaitSpec,
        cx: &CaseContext,
    ) -> Result<crate::core::SuspendReason, StepError> {
        let until = self.deadline_instant(cx, &spec.deadline).await?;

        Ok(crate::core::SuspendReason::AwaitingEvent {
            kind: spec.kind.clone(),
            correlation: spec.correlation.clone(),
            until,
        })
    }
}

/// Fold a delegation chain into a policy context object.
///
/// Merged rather than nested under a key so a rule reads `context.owner` and
/// `context.delegation_depth` directly — which is the shape the Cedar
/// examples assume, and a rule that has to reach through an extra level is a
/// rule somebody writes wrong once.
pub(crate) fn merge_identity(
    context: &mut serde_json::Value,
    identity: Option<&crate::core::Delegation>,
) {
    let (Some(chain), Some(obj)) = (identity, context.as_object_mut()) else {
        return;
    };
    if let Some(extra) = chain.as_context().as_object() {
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng as _;

    #[test]
    fn rng_is_reproducible_for_the_same_run_and_step() {
        let run = RunId::generate();
        let mut a = seeded_rng(run, StepId(0));
        let mut b = seeded_rng(run, StepId(0));
        let xs: Vec<u64> = (0..8).map(|_| a.random()).collect();
        let ys: Vec<u64> = (0..8).map(|_| b.random()).collect();
        assert_eq!(xs, ys, "replay must reproduce the entropy stream exactly");
    }

    #[test]
    fn rng_differs_across_steps_and_runs() {
        let run = RunId::generate();
        let other = RunId::generate();
        let a: u64 = seeded_rng(run, StepId(0)).random();
        let b: u64 = seeded_rng(run, StepId(1)).random();
        let c: u64 = seeded_rng(other, StepId(0)).random();
        assert_ne!(a, b, "steps must not share a stream");
        assert_ne!(a, c, "runs must not share a stream");
    }
}

/// One agent commissioning another on the same plane.
///
/// An effect rather than a direct call, so the sub-run's answer is journaled
/// under a key and a replay reads it back. Its arguments carry the label, so
/// commissioning the same work with a *differently trusted* brief is a different
/// effect rather than a cache hit on this one.
#[derive(Debug)]
struct Commission {
    capability: String,
    input: Value,
    label: crate::core::Label,
    plane: std::sync::Weak<super::Runtime>,
    /// How deep the commissioning run already is.
    depth: usize,
}

/// What a commission produced, and what it cost.
///
/// The cost travels with the answer because [`Effect::spend`] is handed the
/// output and nothing else — a commission whose output were the bare answer
/// could not report what the sub-run spent.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Commissioned {
    answer: Value,
    tokens: u64,
    minor_units: u64,
    /// How sensitive the sub-run said its answer was.
    ///
    /// Journaled with the answer rather than re-read afterwards, because the
    /// label a replay applies has to come from history — asking the specialist
    /// again would make the same run label the same value differently.
    ///
    /// It exists because [`Effect::output_sensitivity`] is a *static*
    /// declaration, evaluated before the effect performs, so a commission
    /// cannot declare what it does not yet know. Without it every commissioned
    /// answer arrived at the default `Internal` floor, which silently
    /// downgrades a specialist that handled anything above it — delegation as
    /// a laundering primitive, reached without anyone writing a release.
    /// Absent in history written before this field existed, which reads back
    /// as the floor an untrusted effect output already carries — the old
    /// behaviour exactly, rather than a guess that could raise a ceiling.
    #[serde(default = "internal_floor")]
    sensitivity: crate::core::Sensitivity,
}

const fn internal_floor() -> crate::core::Sensitivity {
    crate::core::Sensitivity::Internal
}

#[async_trait::async_trait]
impl Effect for Commission {
    type Output = Commissioned;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "agent.commission",
            serde_json::json!({
                "capability": self.capability,
                "input": self.input,
                "label": self.label,
            }),
        )
    }

    /// Commissioning is not itself a mutation of the world: whatever the
    /// sub-run does is journaled in the sub-run, where it belongs.
    fn mutates(&self) -> bool {
        false
    }

    /// Another agent's answer is somebody else's data.
    fn trust(&self) -> crate::core::Trust {
        crate::core::Trust::Untrusted
    }

    /// Handing work to another agent **is** delegation, and the depth ceiling
    /// has to see it.
    ///
    /// This is the in-plane hand-off, and it is the one that matters for the
    /// loop a `specialist` role exists to prevent: A commissions B commissions C
    /// commissions A, inside one process, with no peer boundary to cross and no
    /// egress allowlist to notice. Declaring nothing here meant the ceiling
    /// governed only the A2A path — so the rule held across the network and not
    /// across a function call, which is the wrong way round.
    ///
    /// One deeper than the chain this run already carries, or the first link
    /// when there is none.
    fn delegation_depth(&self) -> Option<usize> {
        Some(self.depth + 1)
    }

    /// Bill the commissioning run for what the sub-run spent, so a delegating
    /// agent's ceiling bounds the work it ordered.
    fn spend(&self, output: &Self::Output) -> crate::core::Spend {
        crate::core::Spend {
            tokens: output.tokens,
            minor_units: output.minor_units,
        }
    }

    async fn perform(&self) -> Result<Self::Output, crate::core::EffectError> {
        let plane = self
            .plane
            .upgrade()
            .ok_or_else(|| crate::core::EffectError::Other("the plane is gone".into()))?;

        // `Interrupted`, not `Rejected`: this caller cannot know whether the
        // commissioned agent performed effects before it failed, and asserting
        // that nothing was applied would be a claim it has no basis for.
        let out = plane
            .run(
                &self.capability,
                Tainted::with_label(self.input.clone(), self.label.clone()),
            )
            .await
            .map_err(|e| crate::core::EffectError::Interrupted {
                driver: self.capability.clone(),
                detail: e.to_string(),
            })?;

        let answer = out
            .output
            .ok_or_else(|| crate::core::EffectError::Interrupted {
                driver: self.capability.clone(),
                detail: format!("'{}' finished without producing output", self.capability),
            })?;
        Ok(Commissioned {
            sensitivity: answer.label().sensitivity,
            answer: answer.into_unlabelled(),
            tokens: out.spend.tokens,
            minor_units: out.spend.minor_units,
        })
    }
}
