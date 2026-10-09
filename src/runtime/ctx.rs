//! [`StepCtx`] — the only door out of a skill.
//!
//! Everything non-deterministic or externally visible passes through here, and
//! that is what makes replay sound. A skill holds no clock, no socket, and no
//! RNG of its own; it holds a context that journals.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use rand::SeedableRng;
use rand::rngs::ChaCha8Rng;
use serde_json::Value;

use crate::case::{CaseStore, EventStore, TaskStore, TimerStore};
use crate::core::{
    AwaitSpec, Calendar, CaseId, CaseStatus, CaseVersion, CorrelationKey, Deadline, DeadlineSpec,
    DeadlineState, Decision, Effect, EffectDescriptor, EffectKey, Epoch, Expiry, Ledger, Phase,
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

/// The label an effect's output carries, from its declaration and source.
///
/// Raised, never lowered: an untrusted result is already `Internal`, and an
/// effect that could declare its output *less* sensitive than its provenance
/// implies would be a laundering primitive.
fn output_label(
    declared: crate::core::DeclaredOutput,
    source: &crate::core::SourceId,
) -> crate::core::Label {
    let base = match declared.trust {
        crate::core::Trust::Trusted => crate::core::Label::trusted(),
        crate::core::Trust::Untrusted => crate::core::Label::untrusted(source.clone()),
    };
    let sensitivity = base.sensitivity.max(declared.sensitivity);
    base.with_sensitivity(sensitivity)
}

/// What the wiring declares about an effect's data ceilings, carried to the
/// manifest gate beside the descriptor.
///
/// A separate value because the descriptor cannot carry it: the descriptor is
/// the effect key, and a reviewed allowance is not part of what a call asks
/// for — a catalogue edit re-keying history is the failure that rule prevents.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "manifest"), allow(dead_code))]
pub(crate) struct DeclaredCeilings {
    pub max_input: crate::core::Sensitivity,
    pub output: crate::core::Sensitivity,
}

impl DeclaredCeilings {
    pub(crate) fn of<E: Effect + ?Sized>(effect: &E) -> Self {
        Self {
            max_input: effect.max_sensitivity(),
            output: effect.output_sensitivity(),
        }
    }
}

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

/// What the journal says about a durable wait a replay just met.
///
/// Internal to the wait machinery: `Recorded` carries the delivered value, and
/// `Repair` says the wait was announced but its registration may not have
/// survived — the caller re-registers idempotently under the same key.
enum ReplayedWait {
    Recorded(Box<Arrival>),
    Repair,
}

/// What a durable wait received: the value, and who the delivery named.
///
/// The value's label already carries the sender as provenance; the two fields
/// beside it are for a wait that must hold an answer to its origin rather than
/// merely label it — a human task, whose answer counts only from the worklist.
struct Arrival {
    value: Tainted<Value>,
    /// The sender, as the delivery recorded it.
    source: Option<String>,
    /// The operator this plane minted the event for, when it minted one.
    by: Option<crate::core::Operator>,
}

/// What the journal says about an effect attempt a replay just met.
///
/// The dispatch loop's two halves meet here: `Live` is the only arm that lets
/// an attempt reach the world, and it is reached only when history is used up.
enum Replayed<T> {
    /// History answers the effect: this output, under this declaration.
    Answered(T, crate::core::DeclaredOutput),
    /// History says the run went on. Loop again at this attempt number — the
    /// same one for a refusal a raise re-admitted, the next for a retry.
    Continue(u32),
    /// History ends here, so this attempt dispatches.
    Live,
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
    /// The plane's embedder and index, paired because a query vector is only
    /// meaningful against the index it was built for.
    pub semantic: Option<Arc<super::SemanticMemory>>,
    pub authorities: Option<Arc<dyn crate::authority::AuthorityStore>>,
    /// The plane's peer registry and transport, for [`StepCtx::call_peer`].
    pub peers: Option<Arc<super::executor::PeerWiring>>,
    /// The plane's checked catalogue and transport, for [`StepCtx::call_tool`].
    #[cfg(feature = "manifest")]
    pub tools: Option<(
        Arc<crate::tools::ToolCatalog>,
        Arc<dyn crate::tools::ToolClient>,
    )>,
    /// Where the plane's tool transports may connect, for the same gate a
    /// model driver applies to its base URL.
    ///
    /// Behind `manifest` because the tool path is: a plane with no catalogue
    /// dispatches no tool call for an allowlist to judge.
    #[cfg(feature = "manifest")]
    pub egress: Option<Arc<crate::core::Egress>>,
    /// The content checkers registered on the plane, by name.
    #[cfg(feature = "manifest")]
    pub checkers: crate::content::Checkers,
    /// Where the plane forwards live model output, when anything listens.
    pub streams: Option<Arc<dyn super::RunStreamObserver>>,
    /// The plane's rate ceilings and the store that counts them.
    #[cfg(feature = "manifest")]
    pub rates: Option<Arc<Rates>>,
    /// The highest sensitivity this plane will write into a record, when it
    /// says. The plane-level twin of `spec.security.max_sensitivity_journaled`.
    pub journal_ceiling: Option<crate::core::Sensitivity>,
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
    pub subjects: BTreeSet<crate::core::SubjectRef>,
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
    /// The declaration's identity, as every gate reports it.
    ///
    /// Carried rather than derived at the gate so that the *same* revision is
    /// named at admission and at every effect. Computed once where the manifest
    /// is wired, because the publisher arrives beside the document from a
    /// verified registry resolution and a manifest alone cannot state it.
    #[cfg(feature = "manifest")]
    pub declaration: Option<crate::journal::AgentIdentity>,
    /// The plane's workload identity, for signing what it tells a callee.
    ///
    /// Separate from the store's signer even though a deployment should give
    /// both the same one: the store signs *records*, this signs *outward
    /// claims*, and a plane can legitimately have one without the other.
    pub signer: Option<Arc<dyn crate::core::Signer>>,
    /// Group records this step and phase already wrote, with how many opens
    /// and settlements each name has. Always empty on a live run. Group
    /// records are not effects, so the cursor cannot dedup them; without this
    /// a resumed step re-opening or re-settling its group at the frontier
    /// would report one group as two. Counts rather than a set, because a
    /// step may legitimately open and settle the same name twice — a set
    /// would swallow the second pair of a pass that recorded only the first.
    pub recorded_groups: std::collections::BTreeMap<String, RecordedGroup>,
}

/// How often a group name already appears on one step-and-phase's record.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RecordedGroup {
    pub(crate) opened: usize,
    pub(crate) settled: usize,
}

/// The first attempt of every dispatch; attempts are 1-based.
const FIRST_ATTEMPT: u32 = 1;

/// A rate counter that could not answer, as the step error it becomes.
///
/// Fails **closed**: a ceiling that yields when its store is unreachable is one
/// an attacker removes by making the store unreachable. Not journaled — nothing
/// was decided, and a resume asks again.
#[cfg(feature = "manifest")]
fn rate_counter_unreachable(error: &crate::quota::QuotaError) -> StepError {
    StepError::Store(crate::core::StoreError::Backend(error.to_string()))
}

/// The rate ceilings a plane's declarations state, and where they are counted.
///
/// Plane-wide rather than per declaration: the count is per tool reference, so
/// every ceiling any agent on the plane states for a tool binds every dispatch
/// of it, whoever makes it.
#[cfg(feature = "manifest")]
#[derive(Debug)]
pub(crate) struct Rates {
    pub(crate) store: Arc<dyn crate::quota::QuotaStore>,
    /// Every distinct ceiling stated per tool reference, tightest count first.
    pub(crate) ceilings: BTreeMap<String, Vec<crate::quota::RateCeiling>>,
}

/// Per-step execution context.
// Each flag is an independent fact about this step; no combination is invalid,
// so an enum over them would satisfy the lint at the reader's expense.
#[allow(clippy::struct_excessive_bools)]
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
    semantic: Option<Arc<super::SemanticMemory>>,
    authorities: Option<Arc<dyn crate::authority::AuthorityStore>>,
    peers: Option<Arc<super::executor::PeerWiring>>,
    #[cfg(feature = "manifest")]
    tools: Option<(
        Arc<crate::tools::ToolCatalog>,
        Arc<dyn crate::tools::ToolClient>,
    )>,
    /// Where the plane's tool transports may connect, when it says so.
    #[cfg(feature = "manifest")]
    egress: Option<Arc<crate::core::Egress>>,
    #[cfg(feature = "manifest")]
    checkers: crate::content::Checkers,
    streams: Option<Arc<dyn super::RunStreamObserver>>,
    #[cfg(feature = "manifest")]
    rates: Option<Arc<Rates>>,
    /// The highest sensitivity this plane will write into a record.
    journal_ceiling: Option<crate::core::Sensitivity>,
    meter: crate::runtime::metrics::Meter,
    #[cfg(feature = "keyring")]
    keyring: Option<Arc<dyn crate::keyring::KeyRing>>,
    tenant: crate::core::TenantId,
    /// The run's budget. Shared because it spans steps; a step never gets its
    /// own allowance to blow.
    ledger: Arc<Mutex<Ledger>>,
    policy: Option<Arc<dyn crate::core::PolicyEngine>>,
    identity: Option<crate::core::Delegation>,
    /// The run's data-subject references, which its inbound events and case
    /// state reads carry.
    subjects: BTreeSet<crate::core::SubjectRef>,
    agent: String,
    plane: std::sync::Weak<super::Runtime>,
    #[cfg(feature = "manifest")]
    manifest: Option<Arc<crate::manifest::Manifest>>,
    #[cfg(feature = "manifest")]
    declaration: Option<crate::journal::AgentIdentity>,
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
    /// The label the last failed effect's output would have carried.
    ///
    /// A failure's text is written by the far side as much as its answer is —
    /// an MCP tool's `isError` content, a peer's error message — so it
    /// carries the same class of data. A caller relaying that text onward
    /// (the declarative loop hands it to the model) must join this label
    /// first, or a confidential tool can reach a public model by failing.
    failed_output: Option<crate::core::Label>,
    /// The classification the content rules raised the last live output to,
    /// between the record that holds it and the label built from it.
    source_raise: Option<crate::core::Sensitivity>,
    /// Whether this step has appended anything to the journal.
    ///
    /// The executor's "did this step do new work" bit: a resumed step that
    /// merely re-read its own history appends nothing here, and its ending is
    /// already on the record — writing a second `StepFinished` for it reports
    /// one piece of work as two and grows the chain on every resume.
    wrote: bool,
    /// Group records this step and phase already wrote — see
    /// [`Frame::recorded_groups`].
    pub(crate) recorded_groups: std::collections::BTreeMap<String, RecordedGroup>,
    /// Whether this step runs only to abandon a group a pause left open: the
    /// run was cancelled while paused, so the pause that ends this pass
    /// aborts the group instead of leaving it open again.
    pub(crate) abandoning: bool,
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
            semantic,
            authorities,
            peers,
            #[cfg(feature = "manifest")]
            tools,
            #[cfg(feature = "manifest")]
            egress,
            #[cfg(feature = "manifest")]
            checkers,
            streams,
            #[cfg(feature = "manifest")]
            rates,
            journal_ceiling,
            meter,
            #[cfg(feature = "keyring")]
            keyring,
            tenant,
            ledger,
            policy,
            identity,
            subjects,
            agent,
            plane,
            #[cfg(feature = "manifest")]
            manifest,
            #[cfg(feature = "manifest")]
            declaration,
            signer,
            recorded_groups,
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
            semantic,
            authorities,
            peers,
            #[cfg(feature = "manifest")]
            tools,
            #[cfg(feature = "manifest")]
            egress,
            #[cfg(feature = "manifest")]
            checkers,
            streams,
            #[cfg(feature = "manifest")]
            rates,
            journal_ceiling,
            meter,
            #[cfg(feature = "keyring")]
            keyring,
            tenant,
            ledger,
            policy,
            identity,
            subjects,
            agent,
            plane,
            #[cfg(feature = "manifest")]
            manifest,
            #[cfg(feature = "manifest")]
            declaration,
            signer,
            recorded_groups,
            abandoning: false,
            reversing: false,
            open_group: None,
            member_dispatch: false,
            failed_output: None,
            source_raise: None,
            wrote: false,
        }
    }

    /// Take the label the last failed effect's output would have carried.
    ///
    /// Set whenever an effect fails with an [`EffectError`], from the same
    /// declaration a success is labelled with. `None` when the last failure
    /// was not the effect's own — a policy refusal, whose text this plane
    /// wrote.
    #[cfg(feature = "manifest")]
    pub(crate) fn take_failed_output_label(&mut self) -> Option<crate::core::Label> {
        self.failed_output.take()
    }

    /// Whether this step appended anything — the executor's "did new work" bit.
    pub(crate) const fn wrote_records(&self) -> bool {
        self.wrote
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
        asked: &EffectDescriptor,
    ) -> Result<Option<crate::journal::EffectReplay>, StepError> {
        self.cursor.next(key, asked, 1)
    }

    /// Whether the next recorded entry is at `key`, without consuming it.
    pub(crate) fn cursor_peek_is(&self, key: EffectKey) -> bool {
        self.cursor.peek_is(key)
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
    /// * **The chain travels, one link longer.** The sub-run acts under this
    ///   run's chain extended by a link naming the commissioned agent — the
    ///   in-plane twin of what a peer call sends outward — so its journal
    ///   answers "on whose behalf" with the same owner, and its expiry and
    ///   audience are this run's. A sub-run admitted under the plane's chain
    ///   instead would act as the operator for a caller who never held that,
    ///   and a chain with no room for another hop refuses here rather than
    ///   one journal down.
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
        self.commission_with(capability, input, None).await
    }

    /// Commission another agent, but only the revision an approval covered.
    ///
    /// `digest` is the declaration a reviewer was shown — a
    /// [`reach`](Self::reach)'s `DeclaredReach::digest`. When another
    /// revision answers the capability by the time the consultation is
    /// dispatched, it is refused before any sub-run is admitted, naming both,
    /// as a refusal no retry repeats — never in doubt, since nothing ran.
    ///
    /// # Errors
    ///
    /// As [`commission`](Self::commission), plus that refusal.
    pub async fn commission_pinned(
        &mut self,
        capability: &str,
        input: Tainted<Value>,
        digest: crate::core::Digest,
    ) -> Result<Tainted<Value>, StepError> {
        self.commission_with(capability, input, Some(digest)).await
    }

    async fn commission_with(
        &mut self,
        capability: &str,
        input: Tainted<Value>,
        pin: Option<crate::core::Digest>,
    ) -> Result<Tainted<Value>, StepError> {
        let plane = self.plane.clone();
        // A run acting under no chain starts from the plane's depth: it is
        // bounded by that chain, so it is no closer to the owner.
        let depth = self.identity.as_ref().map_or_else(
            || plane.upgrade().map_or(0, |p| p.own_depth()),
            crate::core::Delegation::depth,
        );
        // The link carries this run's effective scope unchanged: what the
        // commissioned agent may do is its own manifest's business, and the
        // chain's job is to say for whom and how far from the owner.
        let chain = self
            .identity
            .as_ref()
            .map(|parent| {
                parent.delegate(crate::core::Principal::new(
                    format!("agent/{capability}"),
                    parent.effective_scope().clone(),
                ))
            })
            .transpose()
            .map_err(|e| {
                StepError::Effect(crate::core::EffectError::Refused(format!(
                    "commissioning '{capability}' refused: {e}"
                )))
            })?;
        let initiator = self.initiator().await?;
        let served_unchained = self.served_unchained().await?;
        let plane_chain = self.plane_chain().await?;
        let commissioned = self
            .effect(Commission {
                plane_chain,
                capability: capability.to_owned(),
                input: input.peek().clone(),
                label: input.label().clone(),
                plane,
                depth,
                chain,
                initiator,
                served_unchained,
                pin,
            })
            .await?;
        // What the sub-run spent counts against **this** run's ceilings, so a
        // delegating agent's budget bounds the work it ordered — but not
        // against this pass's live spend. The sub-run is a run of its own: it
        // held its own reservation and settled its own spend into the tenant's
        // period, and settling it again from here would charge the period
        // twice. Billed here rather than as the effect's spend so the journal,
        // the live pass and a replay reach one figure by one path.
        self.bill_delegated(crate::core::Spend {
            tokens: commissioned.peek().tokens,
            minor_units: commissioned.peek().minor_units,
        });
        // Billed first: a sub-run that gave no answer still spent.
        if let Some(failed) = commissioned.peek().failed.clone() {
            return Err(StepError::Effect(crate::core::EffectError::Performed(
                failed,
            )));
        }
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
        let Commissioned {
            answer,
            data_subjects,
            ..
        } = commissioned.into_unlabelled();
        Ok(Tainted::with_label(answer, label).attributed(&data_subjects))
    }

    /// What the agent answering `capability` may do, as its registered
    /// declaration says — the section to put in front of whoever approves a
    /// consultation of it.
    ///
    /// Journaled, so a replay reads back the reach the reviewer was shown
    /// rather than the plane's current one: a redeployed callee changes what
    /// a new approval shows, never the digest of one already given. `None`
    /// when nothing on this plane answers the capability.
    ///
    /// Offered, never attached: a skill that writes its own approval task puts
    /// it in the justification (`Justification::reach`) and pins the
    /// consultation that follows with [`commission_pinned`](Self::commission_pinned).
    ///
    /// # Errors
    ///
    /// As any journaled effect.
    #[cfg(feature = "manifest")]
    pub async fn reach(
        &mut self,
        capability: &str,
    ) -> Result<Option<crate::core::Reach>, StepError> {
        let read = self
            .effect(ReachRead {
                capability: capability.to_owned(),
                plane: self.plane.clone(),
            })
            .await?;
        Ok(read.peek().clone())
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

    /// Complete a prompt on the **manifest's own** model, through the
    /// **plane's own** driver.
    ///
    /// The model-call counterpart to [`call_tool`](Self::call_tool), and it
    /// closes the same gap. A declarative agent resolves its model from the
    /// declaration and its driver from the plane's registry; a hand-written
    /// skill had to carry an `Arc<dyn ModelProvider>` field and name a model
    /// in code — so the skill held wiring its manifest never described, and
    /// the file's `models.privileged` governed the declarative tier while the
    /// coded tier read it or did not. This is the path where it cannot be
    /// ignored: the privileged role supplies the model and its reviewed
    /// ceilings, the plane supplies the driver registered under the role's
    /// provider name, and the manifest's egress ceiling rides the call.
    ///
    /// ```ignore
    /// let completion = cx.complete(&prompt).await?;
    /// ```
    ///
    /// An explicit `(provider, model)` remains one construction away —
    /// `cx.sink_with(&prompt, |value| ModelCall::new(provider, model, value))`
    /// — which is the honest spelling for a call the manifest does not govern.
    ///
    /// # Errors
    ///
    /// [`StepError`] when this skill runs under no manifest, when the manifest
    /// declares no privileged model, when no driver is registered under the
    /// role's provider name, or whatever the dispatch itself refuses.
    #[cfg(feature = "manifest")]
    pub async fn complete(
        &mut self,
        prompt: &Tainted<Value>,
    ) -> Result<Tainted<crate::model::Completion>, StepError> {
        self.complete_with(prompt, |call| call).await
    }

    /// [`complete`](Self::complete), with the call adjusted before dispatch.
    ///
    /// The closure receives the fully-resolved call — model, role ceilings and
    /// egress ceiling already applied — and may add what only the skill knows:
    ///
    /// ```ignore
    /// let completion = cx
    ///     .complete_with(&prompt, |call| call.expecting(schema.clone()))
    ///     .await?;
    /// ```
    ///
    /// It runs *after* the manifest's declarations are applied, so a skill can
    /// tighten or reshape the call; what it cannot do is dodge the `declared`
    /// gate, which still refuses a model the manifest never named.
    ///
    /// # Errors
    ///
    /// As [`complete`](Self::complete).
    #[cfg(feature = "manifest")]
    pub async fn complete_with<F>(
        &mut self,
        prompt: &Tainted<Value>,
        tune: F,
    ) -> Result<Tainted<crate::model::Completion>, StepError>
    where
        F: FnOnce(crate::model::ModelCall) -> crate::model::ModelCall,
    {
        let stream = self.model_stream();
        let refuse = |detail: String| StepError::NotWired(detail);
        let manifest = self.manifest.clone().ok_or_else(|| {
            refuse(
                "this skill runs under no manifest, so `cx.complete` has no declared \
                 model to call — register it with `Agent::new(&manifest).skill(..)`, or \
                 construct a `ModelCall` and dispatch it with `cx.sink_with`"
                    .into(),
            )
        })?;
        let role = manifest.privileged_role().ok_or_else(|| {
            refuse(format!(
                "manifest '{}' declares no privileged model — `spec.models.privileged` \
                 is what `cx.complete` calls",
                manifest.metadata.name
            ))
        })?;
        let provider = self
            .plane
            .upgrade()
            .and_then(|plane| plane.model_provider(&role.model.provider))
            .ok_or_else(|| {
                refuse(format!(
                    "no driver is registered for provider '{}' — \
                     `RuntimeBuilder::provider(\"{}\", ..)` is what maps the manifest's \
                     name to one",
                    role.model.provider, role.model.provider
                ))
            })?;
        let egress = manifest.spec.security.max_sensitivity_egress;
        self.sink_with(prompt, |value| {
            let mut call = role.applied_to(
                crate::model::ModelCall::new(provider, role.model.clone(), value)
                    .observed_by(stream.clone()),
            );
            if let Some(ceiling) = egress {
                call = call.with_max_sensitivity(ceiling);
            }
            tune(call)
        })
        .await
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
            StepError::NotWired(
                "this plane has no tool catalogue — `RuntimeBuilder::toolbox(..)` derives \
                 one from the agents' declarations, and `.tools(catalog, client)` states \
                 it explicitly"
                    .into(),
            )
        })?;
        let egress = self.tool_egress();
        self.sink_with(&arguments, |value| {
            crate::tools::ToolCall::prepare(&catalog, client, tool, value, egress.as_deref())
                .map_err(|e| StepError::Effect(crate::core::EffectError::Rejected(e.to_string())))
        })
        .await
    }

    /// Where this plane's tool transports may connect, when it says so.
    ///
    /// [`call_tool`](Self::call_tool) applies it already. This is for a skill
    /// assembling its own catalogue and calling
    /// [`ToolCall::prepare`](crate::tools::ToolCall::prepare) directly: that
    /// path bypasses the plane's checked catalogue, and it would silently
    /// bypass the plane's destination allowlist too unless the skill can reach
    /// it. Hand it straight through:
    ///
    /// ```ignore
    /// let egress = cx.tool_egress();   // before the closure: it cannot borrow cx
    /// cx.sink_with(&args, |value| {
    ///     ToolCall::prepare(&catalog, client, tool, value, egress.as_deref())
    /// }).await?
    /// ```
    ///
    /// Captured before a `sink_with` closure rather than read inside one: the
    /// closure cannot borrow the context it is being handed to.
    #[cfg(feature = "manifest")]
    #[must_use]
    pub fn tool_egress(&self) -> Option<Arc<crate::core::Egress>> {
        self.egress.clone()
    }

    /// Call another plane's agent, under this run's chain.
    ///
    /// Reached through the plane's own wiring ([`RuntimeBuilder::peers`]),
    /// never a registry or client the skill carries, which is what makes
    /// three things hold:
    ///
    /// * the peer receives [`acting_as`](Self::acting_as) plus one link
    ///   naming it — the caller's chain on a served plane — and a run
    ///   admitted without a chain is refused rather than sent out as nobody;
    /// * the manifest grant `tool://<peer>/<capability>` admits the call, and
    ///   its protected fields and ceiling are checked at the sink as for a
    ///   tool;
    /// * it is an effect: journaled, policy-gated, counted against the
    ///   delegation ceiling, metered, read back on replay.
    ///
    /// The answer is untrusted, labelled `tool://<peer>/<capability>` so a
    /// source rule can name this peer.
    ///
    /// # Errors
    ///
    /// [`StepError`] when no peers are wired, when this run acts under no
    /// chain, when the peer is unknown or the capability outside its grant,
    /// when the payload's label is refused at the sink, and whatever the peer
    /// answers with — classified by [`PeerError::disposition`].
    ///
    /// [`RuntimeBuilder::peers`]: crate::runtime::RuntimeBuilder::peers
    /// [`PeerError::disposition`]: crate::peers::PeerError::disposition
    pub async fn call_peer(
        &mut self,
        peer: &crate::peers::PeerId,
        capability: &str,
        payload: &Tainted<Value>,
    ) -> Result<Tainted<Value>, StepError> {
        let wiring = self.peers.clone().ok_or_else(|| {
            StepError::NotWired(
                "this plane reaches no peers — `RuntimeBuilder::peers(registry, client)` \
                 is what wires them"
                    .into(),
            )
        })?;
        let chain = self.identity.clone().ok_or_else(|| {
            StepError::NotWired(
                "a peer call is made on somebody's behalf, and this run acts under no \
                 chain — admit it with `RunTerms::acting_as`, or build the plane with \
                 `RuntimeBuilder::acting_as`"
                    .into(),
            )
        })?;
        // The grant that governs this call: the governing manifest's own,
        // read directly — it is the reviewed document, and a plane whose
        // only tools are agents and peers derives no catalogue to look it up
        // in. A stated catalogue answers for a skill no manifest governs.
        #[cfg(feature = "manifest")]
        let safety = {
            let id = crate::tools::ToolId::new(peer.to_string(), capability);
            self.manifest
                .as_ref()
                .and_then(|m| m.tool_grant(&id.reference()))
                .map(crate::tools::ToolSafety::from_grant)
                .or_else(|| {
                    self.tools
                        .as_ref()
                        .and_then(|(catalog, _)| catalog.safety(&id).cloned())
                })
        };
        let peer = peer.clone();
        let capability = capability.to_owned();
        // A run admitted as the plane is the plane asking: a peer told who
        // asked is shown the plane's own credential, never one naming the
        // plane's owner as if a person had asked.
        let prepare = if self.plane_chain().await? {
            crate::peers::PeerCall::prepare_as_plane
        } else {
            crate::peers::PeerCall::prepare
        };
        self.sink_with(payload, |value| {
            let call = prepare(
                &wiring.registry,
                Arc::clone(&wiring.client),
                &chain,
                peer,
                capability,
                value,
            )
            .map_err(|e| StepError::Effect(crate::core::EffectError::Rejected(e.to_string())))?;
            #[cfg(feature = "manifest")]
            let call = match safety.as_ref() {
                Some(safety) => call.governed_by(safety),
                None => call,
            };
            Ok::<_, StepError>(call)
        })
        .await
    }

    /// Read a task a peer accepted earlier — the journaled, idempotent poll.
    ///
    /// # Errors
    ///
    /// [`StepError`] when no peers are wired or the task's peer is unknown,
    /// and whatever the read answers with.
    pub async fn peer_task(
        &mut self,
        task: crate::peers::PeerTask,
    ) -> Result<Tainted<crate::peers::PeerTaskSnapshot>, StepError> {
        let wiring = self.peer_wiring()?;
        let call = crate::peers::PeerTaskCall::prepare(
            &wiring.registry,
            Arc::clone(&wiring.client),
            task,
            self.asker().await?,
        )
        .map_err(|e| StepError::Effect(crate::core::EffectError::Rejected(e.to_string())))?;
        self.effect(call).await
    }

    /// Ask a peer to stop a task it accepted earlier.
    ///
    /// Cooperative, and safe to retry: a repeat meets the peer's own
    /// *not cancelable* refusal rather than a second act.
    ///
    /// # Errors
    ///
    /// As [`peer_task`](Self::peer_task).
    pub async fn cancel_peer_task(
        &mut self,
        task: crate::peers::PeerTask,
    ) -> Result<Tainted<crate::peers::PeerTaskSnapshot>, StepError> {
        let wiring = self.peer_wiring()?;
        let call = crate::peers::PeerTaskCancel::prepare(
            &wiring.registry,
            Arc::clone(&wiring.client),
            task,
            self.asker().await?,
        )
        .map_err(|e| StepError::Effect(crate::core::EffectError::Rejected(e.to_string())))?;
        self.effect(call).await
    }

    /// Refuse a hop that would present a credential naming a withdrawn
    /// subject.
    ///
    /// The step boundary reads the halts too, but a step begun before a halt
    /// would otherwise go on presenting the withdrawn owner's credential —
    /// a fresh one, or one a source still holds — until it ends. So each live
    /// subject-bound hop asks the same predicate the boundary does; on a match
    /// every source drops what it holds for the subject, the withholding is
    /// recorded at this hop's key, and the run pauses as the boundary pauses
    /// it. An unreachable halt store refuses the hop.
    ///
    /// An undo is exempt, as it is from the budget's verdict: refusing to
    /// take back work because its owner was withdrawn strands the half-done
    /// act the withdrawal was meant to stop.
    async fn withdrawal_at_hop(&mut self, key: EffectKey) -> Result<(), StepError> {
        if self.undoing() {
            return Ok(());
        }
        let plane = self.plane.upgrade().ok_or_else(|| {
            StepError::Effect(crate::core::EffectError::Other(
                "the plane this run belongs to is gone, so its halts cannot be read".into(),
            ))
        })?;
        let Some(withdrawal) = plane.withdrawal_against(self.identity.as_ref()).await? else {
            return Ok(());
        };
        if let Some(wiring) = self.peers.as_ref() {
            wiring.registry.forget(&withdrawal.subject);
        }
        self.append_effect(
            key,
            RecordKind::AuthorityWithheld {
                subject: withdrawal.subject.clone(),
                reason: withdrawal.reason.clone(),
                by: withdrawal.by,
            },
        )
        .await?;
        Err(StepError::Withheld {
            subject: withdrawal.subject,
            reason: withdrawal.reason,
        })
    }

    /// On whose behalf this run's hops present their credential: the chain's
    /// owner, the plane for a run admitted as the plane, or nobody.
    async fn asker(&self) -> Result<crate::peers::Asker<'_>, StepError> {
        Ok(match &self.identity {
            None => crate::peers::Asker::Nobody,
            Some(_) if self.plane_chain().await? => crate::peers::Asker::Plane,
            Some(chain) => crate::peers::Asker::Owner(chain),
        })
    }

    /// Where this run's model calls forward their live output: the plane's
    /// observer, bound to this run. `None` when nothing listens.
    pub(crate) fn model_stream(&self) -> Option<Arc<dyn crate::model::ModelStreamObserver>> {
        let inner = self.streams.clone()?;
        Some(Arc::new(RunBound {
            run: self.run,
            inner,
        }))
    }

    fn peer_wiring(&self) -> Result<Arc<super::executor::PeerWiring>, StepError> {
        self.peers.clone().ok_or_else(|| {
            StepError::NotWired(
                "this plane reaches no peers — `RuntimeBuilder::peers(registry, client)` \
                 is what wires them"
                    .into(),
            )
        })
    }

    /// The registered peer a grant's server component names, if any.
    #[cfg(feature = "manifest")]
    pub(crate) fn peer_named(&self, server: &str) -> Option<crate::peers::PeerId> {
        let id = crate::peers::PeerId::new(server);
        self.peers
            .as_ref()
            .and_then(|wiring| wiring.registry.grant(&id).is_some().then_some(id))
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

    /// The chain this run acts under, if it was admitted with one.
    ///
    /// The one to hand a `PeerCall` or anything else that extends a chain
    /// outward: it is the caller's on a served plane and the plane's for a run
    /// the embedder started, and on replay it is read back from the journal
    /// rather than from whatever the plane is configured with now. A skill
    /// that carries a chain of its own instead is spending one owner's
    /// authority for every caller.
    #[must_use]
    pub fn acting_as(&self) -> Option<&crate::core::Delegation> {
        self.identity.as_ref()
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

    /// Bill one announced attempt read back from the journal: its slot against
    /// `max_effects`, and everything its records say it cost.
    ///
    /// Called for failures as well as successes, because a call that failed
    /// still *happened*: it took a slot, and a budget that only counted
    /// successes could never bound a call that fails every time. The live path
    /// takes the same slot at admission and adds the cost when the call
    /// returns, so the two reach the same verdict at the same point — the
    /// property this whole seam exists for, and the one that breaks the moment
    /// one announcement costs two slots on one path and one on the other.
    ///
    /// A separate function so the guard's scope is a single statement and cannot
    /// accidentally span an await.
    pub(crate) fn bill_replayed(&self, spend: crate::core::Spend, outbound: u64) {
        self.ledger
            .lock()
            .expect("budget mutex")
            .replay_effect(spend, outbound);
    }

    /// How many bytes this effect would hand its sink.
    ///
    /// One implementation, read by three callers that must agree: the ceiling
    /// that refuses before dispatch, the `EffectStarted` record that states what
    /// crossed, and the replayed billing that has to reach the same tally. Two
    /// spellings of "how big is this" would agree until one of them learned to
    /// measure something else.
    ///
    /// The effect's own [`Effect::outbound_bytes`]: an effect binding no
    /// outbound value is zero rather than absent, so a read does not consume
    /// an egress ceiling, and an effect whose request carries more than its
    /// bound value counts all of it.
    pub(crate) fn outbound_size<E: crate::core::Effect>(effect: &E) -> u64 {
        effect.outbound_bytes()
    }

    /// Take an effect's slot for an announcement no ceiling gates.
    ///
    /// A compensating call and a durable wait are both exempt from admission
    /// and neither is exempt from having happened: the journal holds an
    /// announcement, so every later pass bills one, and a live pass that
    /// billed none would exhaust later than its own replay.
    pub(crate) fn count_unadmitted(&self, outbound: u64) {
        self.ledger
            .lock()
            .expect("budget mutex")
            .count_effect(outbound);
    }

    /// Add what a commissioned sub-run spent to this run's consumption, and
    /// not to this pass's live spend: the sub-run settles it into the
    /// tenant's period itself. Called on every pass alike, from the recorded
    /// answer, so a replay reaches the verdict the live pass did.
    fn bill_delegated(&self, spend: crate::core::Spend) {
        self.ledger
            .lock()
            .expect("budget mutex")
            .record_spend(spend);
    }

    /// Add what a **freshly dispatched** attempt cost. Its slot was taken at
    /// admission; only the figure was unknown until now.
    ///
    /// The live/replayed distinction feeds the tenant's period ledger:
    /// replayed spend is billed to the run's own budget so a resume exhausts
    /// where the original did, but only live spend accrues at settlement —
    /// otherwise every suspend/resume cycle re-accrues the prefix and every
    /// strict pass bills history into today's period.
    fn bill_live(&self, spend: crate::core::Spend) {
        self.ledger
            .lock()
            .expect("budget mutex")
            .record_live_spend(spend);
    }

    /// A deterministic random source.
    ///
    /// Seeded from `(run_id, step)` rather than journaled per draw: the sequence
    /// is reproducible by construction, so replay reproduces it for free and the
    /// journal carries no entropy records at all. Cheaper *and* stronger than
    /// recording each value — there is no way for the recorded and recomputed
    /// streams to disagree.
    ///
    /// **The stream is part of the replay contract** — nothing in the journal
    /// records which generator wrote a history — so it is pinned by a golden
    /// vector rather than left to a dependency's discretion.
    ///
    /// The traits are re-exported as [`agentplane::rand`](crate::rand), so
    /// drawing from this does not begin with matching a `rand` version in your
    /// own manifest:
    ///
    /// ```
    /// # use agentplane::runtime::StepCtx;
    /// use agentplane::rand::RngExt as _;
    /// # fn draw(cx: &mut StepCtx<'_>) -> u32 {
    /// cx.rng().random_range(0..100)
    /// # }
    /// ```
    pub fn rng(&mut self) -> &mut impl rand::RngExt {
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
        outbound: Option<Outbound<'_>>,
    ) -> Result<Tainted<E::Output>, StepError> {
        // Captured before dispatch consumes the effect. This is the name a
        // `ProtectedField::from_sources` rule matches, so it is per *effect* —
        // `tool://crm/lookup`, `model:openai/gpt-4o` — not per family: a rule
        // that can only say `effect:tool.call` admits whichever granted tool an
        // injected prompt reached first, which is no rule at all.
        let source = effect.source();
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
        // A failure's text came from the same far side a result would have,
        // so it carries the label a result would have carried.
        let failure_label = output_label(crate::core::DeclaredOutput::of(&effect), &source);
        self.failed_output = None;
        // The declaration comes back with the value, because for a replayed
        // effect it is **history** rather than a fresh reading of the
        // catalogue. See `DeclaredOutput` for what re-reading would cost.
        let (output, declared) = match self.effect_unlabelled(effect, outbound).await {
            Ok(answered) => answered,
            Err(error) => {
                if matches!(error, StepError::Effect(_)) {
                    self.failed_output = Some(failure_label);
                }
                return Err(error);
            }
        };
        let label = output_label(declared, &source);
        #[cfg(feature = "manifest")]
        let label = self.checked_arrival(&kind, &output, label).await?;
        Ok(Tainted::with_label(output, label))
    }

    /// The effect protocol itself, before the result is labelled.
    ///
    /// Split out so the label is applied at exactly one place: a second exit
    /// from this function that forgot to wrap would be an unlabelled tool
    /// result, which is the hole the labelling exists to close.
    ///
    /// Returns the [`DeclaredOutput`](crate::core::DeclaredOutput) that applies
    /// to the value beside it, which is **not** always the one the effect would
    /// answer now: a value read back from history carries the declaration that
    /// was recorded with it, so a catalogue edited since cannot relabel it.
    async fn effect_unlabelled<E: Effect>(
        &mut self,
        mut effect: E,
        outbound: Option<Outbound<'_>>,
    ) -> Result<(E::Output, crate::core::DeclaredOutput), StepError> {
        // Checked once, on the path *both* `effect` and `sink` take, and before
        // the retry loop because a depth violation is not attempt-dependent.
        //
        // It lived in `sink` alone, which meant the ceiling governed the A2A
        // peer call and not `cx.commission` — the rule held across a network
        // boundary and not across a function call, which is the wrong way
        // round. The loop a `specialist` role exists to prevent is the in-plane
        // one: A commissions B commissions C commissions A, inside one process,
        // with no peer boundary to cross and no allowlist to notice.
        //
        // A refusal is journaled like the sink gates': it fires before any key
        // exists, so the record takes the dispatch's position, and replay
        // consumes the verdict instead of re-deciding it.
        let descriptor = effect.descriptor();
        self.refuse_excess_delegation(&effect, &descriptor).await?;
        let policy = effect.retry();
        let recovery = effect.recovery();
        let ordinal = self.ordinal;
        self.ordinal += 1;

        let mut attempt: u32 = 1;
        // What the last failure's peer said about when to come back. The wait
        // belongs to the *next* attempt, so it crosses the iteration boundary;
        // a replayed pass never waits, because the wait already happened and
        // its outcome is the record being read back.
        let mut advice: Option<std::time::Duration> = None;
        loop {
            let key = EffectKey::derive(
                self.step,
                self.phase,
                ordinal,
                attempt,
                &descriptor.kind,
                &canon::value_bytes(&descriptor.args),
            );

            // The dispatch's identity across its attempts: the first attempt's
            // key, which a retry, a recovered re-dispatch and a resumed pass
            // all derive again. A rate ceiling counts under it, so a retry
            // spends once.
            let dispatch = EffectKey::derive(
                self.step,
                self.phase,
                ordinal,
                FIRST_ATTEMPT,
                &descriptor.kind,
                &canon::value_bytes(&descriptor.args),
            );

            // Hand the effect what it needs to identify itself to a callee.
            // After the key is derived and before anything is announced: the key
            // is part of the block, and the block is signed for *this* call.
            effect.attach(&self.provenance(key, ordinal, &descriptor));

            // ── Replay: is this attempt already in history? ────────────────
            if self.mode.is_replaying() {
                match self
                    .replayed_attempt(
                        &effect,
                        &descriptor,
                        ordinal,
                        attempt,
                        key,
                        &recovery,
                        &policy,
                    )
                    .await?
                {
                    Replayed::Answered(output, declared) => return Ok((output, declared)),
                    Replayed::Continue(next) => {
                        attempt = next;
                        continue;
                    }
                    Replayed::Live => {}
                }
            }

            self.starts_no_work_when_abandoning(&descriptor)?;

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
            // Compensation is exempt from the *verdict*, never from the
            // accounting. Refusing to undo because the ceiling was reached is
            // how a run ends with a charged card and no order — the ceiling
            // exists to bound work, not to strand it half-done — but the undo
            // still takes its slot and reports its spend, so the overshoot is
            // visible rather than silent, and a pass replaying the
            // announcement bills the same one.
            if let Some(crate::core::CredentialBinding::Subject { .. }) =
                effect.credential_binding()
            {
                self.withdrawal_at_hop(key).await?;
            }
            let ceilings = Some(DeclaredCeilings::of(&effect));
            let outbound_bytes = Self::outbound_size(&effect);
            self.gate(
                key,
                dispatch,
                &descriptor,
                effect.mutates(),
                outbound,
                ceilings,
                outbound_bytes,
            )
            .await?;

            let backoff = policy.wait_before(self.run, key, attempt, advice.take());
            if !backoff.is_zero() {
                tokio::time::sleep(backoff).await;
            }
            let waited = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);

            let failure = match self
                .traced_attempt(&effect, key, attempt, waited, outbound)
                .await?
            {
                // Dispatched live, so the effect's own answer is both what the
                // value carries and what the `EffectDone` record just stored.
                Ok(output) => {
                    let mut declared = crate::core::DeclaredOutput::of(&effect);
                    declared.sensitivity =
                        crate::core::content_joined(declared.sensitivity, self.source_raise.take());
                    return Ok((output, declared));
                }
                Err(e) => e,
            };

            if let Some(output) = self
                .failed_attempt_verdict(&effect, key, attempt, &recovery, &policy, &failure)
                .await?
            {
                return Ok((output, crate::core::DeclaredOutput::of(&effect)));
            }
            advice = failure.retry_after();
            attempt += 1;
        }
    }

    /// Decide what a failed attempt means: a reconciled answer, a stop, or a
    /// retry.
    ///
    /// One implementation for the live path and the resolved-orphan path,
    /// because they are one rule: an in-doubt failure on a reconcilable
    /// effect is a question asked before deciding, and everything else goes
    /// to the stop machinery. `Ok(Some(output))` is an answer reconciliation
    /// recovered; `Ok(None)` tells the attempt loop to retry.
    async fn failed_attempt_verdict<E: Effect>(
        &mut self,
        effect: &E,
        key: EffectKey,
        attempt: u32,
        recovery: &crate::core::Recovery,
        policy: &crate::core::RetryPolicy,
        failure: &crate::core::EffectError,
    ) -> Result<Option<E::Output>, StepError> {
        let mut disposition = failure.disposition();
        if disposition == crate::core::Disposition::InDoubt
            && matches!(recovery, crate::core::Recovery::Reconcile)
        {
            match self.reconcile_and_record(effect, key).await? {
                crate::core::Reconciliation::Landed(output) => return Ok(Some(output)),
                resolved => disposition = resolved.disposition(),
            }
        }
        if let Some(stop) = Self::stop_reason(
            disposition,
            recovery,
            key,
            attempt,
            policy,
            &failure.to_string(),
            permanent_failure(effect, failure),
            effect.mutates(),
        ) {
            return Err(stop);
        }
        Ok(None)
    }

    /// Resolve an orphan and classify what came of it.
    ///
    /// A resolved orphan that *fails* is a live failure and takes the live
    /// failure's path — disposition, reconciliation, stop machinery — rather
    /// than a verdict of its own. The re-performance already wrote its
    /// terminal record inside `resolve_orphan`; what is decided here is only
    /// what the failure means, and deciding it anywhere else is how a
    /// mutating in-doubt outcome once unwound as a plain failure.
    ///
    /// `Ok(Some(output))` is a landed answer; `Ok(None)` tells the attempt
    /// loop to retry under the recomputed policy.
    #[allow(clippy::too_many_arguments)]
    async fn orphan_verdict<E: Effect>(
        &mut self,
        effect: &E,
        key: EffectKey,
        attempt: u32,
        recorded: &crate::core::Recovery,
        recovery: &crate::core::Recovery,
        policy: &crate::core::RetryPolicy,
    ) -> Result<Option<E::Output>, StepError> {
        match self.resolve_orphan(effect, key, attempt, recorded).await? {
            Ok(output) => Ok(Some(output)),
            Err(failure) => {
                self.failed_attempt_verdict(effect, key, attempt, recovery, policy, &failure)
                    .await
            }
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
    ///
    /// The nested result is the point of the signature: the inner `Err` is a
    /// re-performance that **failed**, handed back to the ordinary attempt
    /// loop so the same disposition, reconciliation and stop machinery decides
    /// what it means. Collapsing it to a step failure here would skip the
    /// classifier — a resumed orphan whose re-performance timed out `InDoubt`
    /// on a mutating effect would read as a plain failure, and the failure
    /// unwind would compensate completed steps around a call that may have
    /// landed. The outer `Err` carries only the verdicts this
    /// function can reach alone: strict refuses to probe, an operator-recovery
    /// effect stays undecidable, and an inconclusive probe stays undecidable.
    async fn resolve_orphan<E: Effect>(
        &mut self,
        effect: &E,
        key: EffectKey,
        attempt: u32,
        recovery: &crate::core::Recovery,
    ) -> Result<Result<E::Output, crate::core::EffectError>, StepError> {
        use crate::core::{Reconciliation, Recovery};

        // Strict replay is a pure read, and resolving an orphan is not reading —
        // every branch below either performs an effect or probes a provider, and
        // both write to the journal being verified. Falling through to the
        // `Retry` arm would make verifying a crashed run re-perform its
        // interrupted effect for real and append to the history under check.
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
            // one interrupted attempt was resumed. A failure is handed back to
            // the attempt loop, not decided here.
            Recovery::Retry | Recovery::Idempotent { .. } => {
                self.perform_once(effect, key, attempt, 0, false, None)
                    .await
            }
            // Ask, rather than assume. This is the only branch that turns an
            // undecidable outcome into a decided one without betting on it.
            Recovery::Reconcile => match self.reconcile_and_record(effect, key).await? {
                Reconciliation::Landed(output) => Ok(Ok(output)),
                Reconciliation::DidNotHappen => {
                    self.perform_once(effect, key, attempt, 0, false, None)
                        .await
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

    /// Decide what a replayed refusal means in this pass.
    ///
    /// `Err` re-raises the recorded verdict; `Ok(())` means a budget refusal
    /// was superseded by a re-admission this pass just journaled, and the
    /// caller dispatches the same key live. One implementation for the
    /// ordinary dispatch loop and the atomic-member path, because it is one
    /// rule — and the step-level twin lives in `admit_ready`, so the two
    /// tiers must move together: an effect tier that replayed its refusal
    /// verbatim would leave a run exhausted by `max_effects` paused forever
    /// under a ceiling that now admits it, while its step-limited sibling
    /// resumes.
    ///
    /// The asymmetry between the two refusal kinds is deliberate. A budget is
    /// raised, so a resume re-asks the ledger now in force — still refused
    /// consumes the standing record and re-concludes without stacking a
    /// second, admitted journals `BudgetReadmitted` beside the refusal it
    /// supersedes. A policy denial is argued with, not raised: resume already
    /// requires the exact bundle recorded at admission, so the verdict is
    /// consumed rather than re-decided — a gate must not re-decide a dispatch
    /// history already settled.
    ///
    /// A tool's rate ceiling is re-asked beside the ledger, without taking
    /// room: a window still full stands the refusal as a ledger that still
    /// refuses does, rather than re-admitting a dispatch the gate would refuse
    /// again under a second record.
    pub(crate) async fn replayed_refusal(
        &mut self,
        key: EffectKey,
        descriptor: &EffectDescriptor,
        refusal: EffectReplay,
        outbound_bytes: u64,
    ) -> Result<(), StepError> {
        let EffectReplay::Refused { limit, used } = refusal else {
            return Err(self.replayed_denial(refusal));
        };
        // Re-askable only at the history frontier, and the condition is
        // deliberately `writes_enabled`: a re-admission is a write, and
        // bookkeeping writes begin where history ends. Strict is covered by
        // the same condition: verification writes nothing and consults no
        // ledger. A cancelling pass re-admits nothing either — it exists to
        // take work back, not to continue it.
        if !self.writes_enabled() || self.abandoning {
            return Err(recorded_refusal(EffectReplay::Refused { limit, used }));
        }
        // Asked without taking the slot: this is the question "does the
        // ceiling now in force still refuse", and the dispatch that follows a
        // yes goes through the ordinary gate, which is what takes the slot.
        // Taking one here as well would charge the re-admitted effect twice.
        let verdict = self
            .ledger
            .lock()
            .expect("budget mutex")
            .can_admit_effect(outbound_bytes);
        #[cfg(feature = "manifest")]
        let verdict = match (verdict, self.rate_ceilings(descriptor), self.rates.as_ref()) {
            (Ok(()), Some((grant, ceilings)), Some(rates)) => {
                match rates
                    .store
                    .rate_room(&grant, &ceilings, super::executor::now_for_admission())
                    .await
                {
                    Ok(()) => Ok(()),
                    Err(crate::quota::QuotaError::RateLimited { .. }) => Err(()),
                    Err(other) => return Err(rate_counter_unreachable(&other)),
                }
            }
            (verdict, _, _) => verdict.map_err(|_| ()),
        };
        #[cfg(not(feature = "manifest"))]
        let _ = descriptor;
        if verdict.is_err() {
            // The ceiling now in force still refuses: the run concludes
            // exhausted again, and the standing refusal already says so — no
            // second record.
            return Err(StepError::Budget(crate::core::BudgetExceeded::Recorded {
                limit,
                used,
            }));
        }
        self.append_effect(key, RecordKind::BudgetReadmitted { limit })
            .await?;
        Ok(())
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
                // Spend without a slot. A probe asks about the attempt that
                // was already admitted and already counted; charging a second
                // slot for the same call would make one announcement cost two
                // — and the journal holds one announcement, so every replay
                // bills one.
                let spend = effect.spend(value);
                self.bill_live(spend);
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
                // Present exactly when the probe recovered a value, so the two
                // are derived from one match rather than from two.
                declared: output
                    .is_some()
                    .then(|| crate::core::DeclaredOutput::of(effect)),
                output,
                spend,
                detail,
                // The effect asked its own provider. Nobody asserted anything,
                // and naming the run here would attribute a machine's answer to
                // a person — so neither the name nor the note a person would
                // have written.
                note: None,
                asserted_by: None,
            },
        )
        .await?;

        Ok(outcome)
    }

    /// What history says about a wait, if anything.
    ///
    /// `Ok(None)` means the journal has nothing here and the wait must be
    /// registered live. `Ok(Some(ReplayedWait::Repair))` means the wait was announced and
    /// its registration may not have survived — the caller re-registers
    /// idempotently under the same key, without a second announcement. Every
    /// other arm is a decision the recorded run already made, reproduced
    /// rather than re-derived.
    async fn replayed_wait(
        &mut self,
        key: EffectKey,
        descriptor: &EffectDescriptor,
        spec: &AwaitSpec,
        cx: &CaseContext,
    ) -> Result<Option<ReplayedWait>, StepError> {
        match self.cursor.next(key, descriptor, 1)? {
            Some(EffectReplay::Done {
                output,
                source,
                by,
                spend,
                // An inbound payload's label is rebuilt from `source` and the
                // wait's own kind, which `label_inbound` holds together.
                declared: _,
                content,
            }) => {
                // A wait hands nothing to a sink: what arrives is inbound.
                self.bill_replayed(spend, 0);
                self.arrival_refusal(content.as_ref())?;
                Ok(Some(ReplayedWait::Recorded(Box::new(Arrival {
                    value: self.label_inbound(
                        output,
                        &spec.kind,
                        source.as_deref(),
                        content.as_ref(),
                    ),
                    source,
                    by,
                }))))
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
            Some(EffectReplay::Withheld { subject, reason }) => {
                Err(StepError::Withheld { subject, reason })
            }
            Some(EffectReplay::Failed { error, spend, .. }) => {
                self.bill_replayed(spend, 0);
                Err(StepError::Effect(crate::core::EffectError::Rejected(error)))
            }
            // Announced, and *possibly* registered: a crash — or a transient
            // store error — between the announcement and the subscription
            // leaves exactly this record, and suspending without repairing
            // would strand the run forever: later events buffer until they
            // dead-letter while the run sleeps with nothing in the system
            // naming it. A resume re-walks the registration path, which is
            // idempotent end to end (the subscription keeps its first row,
            // the task row derives its id from this same key), skipping only
            // the announcement that already exists. A strict pass dispatches
            // nothing and suspends as the record reads.
            Some(EffectReplay::Orphan { .. }) => {
                // The announcement is on the record, so this pass bills it —
                // including on the repair path, which re-enters the
                // registration below with the announcement skipped and would
                // otherwise be the one pass that waits for free.
                self.bill_replayed(crate::core::Spend::default(), 0);
                if self.mode == Mode::Resume {
                    Ok(Some(ReplayedWait::Repair))
                } else {
                    Err(StepError::Suspended(self.suspend_reason(spec, cx).await?))
                }
            }
            None if self.mode == Mode::Strict => Err(StepError::ReplayOverrun {
                actual: key,
                kind: descriptor.kind.clone(),
            }),
            None => Ok(None),
        }
    }

    /// Account for an effect served from the journal rather than performed.
    ///
    /// Marked replayed so metrics like "effect latency by driver" do not average
    /// real calls with journal reads, and billed at the figure that was
    /// *recorded* — so a replayed run reaches the same budget verdict at the
    /// same point as the original.
    fn replayed_done(
        &self,
        kind: &str,
        attempt: u32,
        spend: crate::core::Spend,
        outbound_bytes: u64,
    ) {
        tracing::debug!(
            target: telemetry::EFFECT_SPAN,
            kind = %kind,
            attempt,
            replayed = true,
            outcome = "done",
        );
        self.meter.count(metrics::EFFECTS_REPLAYED, kind);
        self.bill_replayed(spend, outbound_bytes);
    }

    /// [`judged`] under this step's declaration.
    #[cfg(feature = "manifest")]
    fn content_at(
        &self,
        at: crate::content::At<'_>,
        value: &Value,
    ) -> Result<crate::content::Outcome, PolicyError> {
        judged(
            self.manifest
                .as_ref()
                .and_then(|m| m.spec.security.content.as_ref()),
            at,
            value,
        )
    }

    /// The bytes an effect bound are the bytes the gates are shown, or the
    /// refusal that says where they differ.
    fn bound_as_sent<E: Effect>(
        effect: &E,
        args: &Tainted<Value>,
        sink_name: String,
    ) -> Result<(), StepError> {
        let Some(bound) = effect.sink_arguments() else {
            return Err(PolicyError::UnboundSinkArguments { sink: sink_name }.into());
        };
        let bound_bytes = canon::value_bytes(bound);
        let sent_bytes = canon::value_bytes(args.peek());
        if bound_bytes != sent_bytes {
            // Where, not only that. The rule is exact equality and the verdict
            // needs nothing more, but the reader does: without a path this is
            // two documents and a diff by eye, and the commonest case — a
            // bound payload still at its `null` default beside a labelled
            // object — is the one a bare "they differ" hides worst. Neither
            // value is printed: the labelled one is precisely the data these
            // gates exist to keep out of a log, so the digests identify it to
            // whoever already holds it and disclose nothing to anyone else.
            return Err(PolicyError::SinkArgumentsMismatch {
                sink: sink_name,
                at: canon::first_difference(bound, args.peek()).unwrap_or_default(),
                bound: crate::core::Digest::of(&bound_bytes),
                sent: crate::core::Digest::of(&sent_bytes),
            }
            .into());
        }
        Ok(())
    }

    /// The declared content rules and checks at a sink: the value as it will
    /// be sent, when they changed it, and the ids that judged it.
    ///
    /// A refusal is a sink gate like the label gates: live only, and judged
    /// over the value as the step handed it. A redaction is not a verdict but
    /// a change to what is sent, so it is applied in every mode — the effect
    /// key, the record and every replay are over the redacted bytes, and a
    /// replay under a declaration that redacts differently diverges at this
    /// effect. Each check is its own journaled effect over the value as it
    /// will be sent. A classification, a rule's or a check's, raises the label
    /// the gates after this one judge.
    #[cfg(feature = "manifest")]
    async fn content_at_sink<E: Effect>(
        &mut self,
        effect: &mut E,
        args: &Tainted<Value>,
    ) -> Result<(Option<Tainted<Value>>, Vec<String>), StepError> {
        let kind = effect.descriptor().kind;
        let outcome = match self.content_at(crate::content::At::Sink(&kind), args.peek()) {
            Err(denial) if self.writes_enabled() => {
                return Err(self
                    .refuse_sink(&effect.descriptor(), crate::core::ACTION_CONTENT, denial)
                    .await);
            }
            Err(_) => crate::content::Outcome::default(),
            Ok(outcome) => outcome,
        };
        let refused = outcome.refused.first().cloned();
        let redaction = outcome.redactions.first().cloned();
        let rebound = match &outcome.redacted {
            Some(value) => effect.rebind(value.clone()),
            None => true,
        };
        // An effect whose arguments cannot be rebound would send the value
        // whole, so a redaction it needs refuses it instead.
        if let Some(hit) = refused.or_else(|| redaction.filter(|_| !rebound))
            && self.writes_enabled()
        {
            let denial = PolicyError::Content {
                rule: hit.rule,
                pointer: hit.pointer,
            };
            return Err(self
                .refuse_sink(&effect.descriptor(), crate::core::ACTION_CONTENT, denial)
                .await);
        }
        let redacted = outcome
            .redacted
            .filter(|_| rebound)
            .map(|v| args.redacted(v));
        let sent = redacted.as_ref().unwrap_or(args);

        let (checks, verdict) = self
            .run_checks(crate::content::At::Sink(&kind), sent)
            .await?;
        if let Some(refused) = verdict.refused.clone()
            && self.writes_enabled()
        {
            let denial = PolicyError::Content {
                rule: refused.rule,
                pointer: refused.pointer,
            };
            return Err(self
                .refuse_sink(&effect.descriptor(), crate::core::ACTION_CONTENT, denial)
                .await);
        }
        let classified = [outcome.sensitivity, verdict.sensitivity]
            .into_iter()
            .fold(sent.label().sensitivity, crate::core::content_joined);
        let judged = if classified > sent.label().sensitivity {
            Some(sent.raised_to(classified))
        } else {
            redacted
        };
        let ids = outcome.evaluated.into_iter().chain(checks).collect();
        Ok((judged, ids))
    }

    /// Run the declared checks that apply at `at` over `value`, each as its
    /// own journaled `content.check` effect, in declaration order. Answers
    /// the ids that ran and their joined verdict: the first refusal, and
    /// every classification joined.
    ///
    /// A checker that failed, or a check its own gates refused, refuses the
    /// value — there is no fallback setting. A ceiling, a store fault or an
    /// authorization denial is the run's, and goes up unchanged.
    #[cfg(feature = "manifest")]
    async fn run_checks(
        &mut self,
        at: crate::content::At<'_>,
        value: &Tainted<Value>,
    ) -> Result<(Vec<String>, crate::core::ContentVerdict), StepError> {
        let mut verdict = crate::core::ContentVerdict {
            rules: Vec::new(),
            sensitivity: None,
            refused: None,
        };
        let checks: Vec<crate::content::ContentCheck> = self
            .manifest
            .as_ref()
            .and_then(|m| m.spec.security.content.as_ref())
            .map(|c| c.checks_at(at).cloned().collect())
            .unwrap_or_default();
        let mut ran = Vec::with_capacity(checks.len());
        for check in checks {
            let Some(checker) = self.checkers.get(&check.checker).cloned() else {
                // The build refuses a check naming no registered checker, so
                // this is a plane wired around that check: refuse, never pass.
                verdict
                    .refused
                    .get_or_insert_with(|| crate::core::ContentRefusal {
                        rule: check.id.clone(),
                        pointer: String::new(),
                    });
                ran.push(check.id);
                continue;
            };
            let id = check.id.clone();
            let effect = crate::content::CheckEffect {
                checker,
                check,
                arguments: value.peek().clone(),
            };
            let found = match Box::pin(self.sink(effect, value)).await {
                Ok(answer) => answer.into_unlabelled().verdict,
                Err(StepError::Effect(_) | StepError::Policy(_)) => {
                    Some(crate::core::ContentVerdict {
                        rules: vec![id.clone()],
                        sensitivity: None,
                        refused: Some(crate::core::ContentRefusal {
                            rule: id.clone(),
                            pointer: String::new(),
                        }),
                    })
                }
                Err(other) => return Err(other),
            };
            if let Some(found) = found {
                if verdict.refused.is_none() {
                    verdict.refused = found.refused;
                }
                verdict.sensitivity = found
                    .sensitivity
                    .map(|s| crate::core::content_joined(s, verdict.sensitivity));
                verdict.rules.extend(found.rules);
            }
            ran.push(id);
        }
        Ok((ran, verdict))
    }

    /// The label an output arriving from `kind` carries once the declared
    /// checks have judged it, or the refusal they reached — on the pass that
    /// ran them and, from their records, on every replay.
    #[cfg(feature = "manifest")]
    async fn checked_arrival<T: serde::Serialize>(
        &mut self,
        kind: &str,
        output: &T,
        label: crate::core::Label,
    ) -> Result<crate::core::Label, StepError> {
        let applies = self
            .manifest
            .as_ref()
            .and_then(|m| m.spec.security.content.as_ref())
            .is_some_and(|c| {
                c.checks_at(crate::content::At::Source(kind))
                    .next()
                    .is_some()
            });
        if !applies {
            return Ok(label);
        }
        let value = Tainted::with_label(serde_json::to_value(output)?, label.clone());
        let (_, verdict) = self
            .run_checks(crate::content::At::Source(kind), &value)
            .await?;
        self.arrival_refusal(Some(&verdict))?;
        let raised = crate::core::ContentVerdict::raise(Some(&verdict), label.sensitivity);
        Ok(label.with_sensitivity(raised))
    }

    /// The content rules' verdict on an output arriving from `kind`, for its
    /// record; `None` where no rule matched.
    #[cfg(feature = "manifest")]
    fn source_verdict(&self, kind: &str, output: &Value) -> Option<crate::core::ContentVerdict> {
        verdict(self.content_at(crate::content::At::Source(kind), output))
    }

    #[cfg(not(feature = "manifest"))]
    #[allow(clippy::unused_self)]
    fn source_verdict(&self, _kind: &str, _output: &Value) -> Option<crate::core::ContentVerdict> {
        None
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
    /// `ceilings` is what the wiring declares about the effect's data limits,
    /// carried beside the descriptor because the descriptor cannot hold it:
    /// the descriptor is the effect key, and a reviewed allowance is not part
    /// of what a call asks for — keying history on a catalogue edit is the
    /// failure that rule exists to prevent. `None` marks a dispatch path that
    /// has no ceilings to state (an atomic group member); the manifest arms
    /// that need them refuse on `None` rather than assume.
    ///
    /// Authorization before accounting: both refuse before dispatch, but an
    /// unauthorized call should not first consume the run's allowance —
    /// otherwise a denied agent can still exhaust a budget by asking.
    ///
    /// Undo — a compensating phase, or a group taken back inside a forward
    /// one — is judged by the declaration and the policy like any other
    /// dispatch, and exempt from the budget: refusing to undo for cost is how
    /// a run ends with a charged card and no order, while an undo the
    /// declaration or policy refuses fails its compensation, which quarantines
    /// the run for a person to decide.
    ///
    /// `dispatch` is the dispatch's first attempt's key, which a tool's rate
    /// ceiling counts under: a retry derives the same one and spends nothing.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn gate(
        &mut self,
        key: EffectKey,
        dispatch: EffectKey,
        descriptor: &EffectDescriptor,
        mutates: bool,
        outbound: Option<Outbound<'_>>,
        ceilings: Option<DeclaredCeilings>,
        outbound_bytes: u64,
    ) -> Result<(), StepError> {
        // First, because it is the cheapest and the most fundamental: an effect
        // the agent's own declaration never mentioned should not reach the
        // deployment's policy engine, let alone the world.
        #[cfg(feature = "manifest")]
        self.declared(key, descriptor, ceilings).await?;
        #[cfg(not(feature = "manifest"))]
        let _ = ceilings;
        let mutates = self.gated_mutates(descriptor, mutates);
        self.authorize(key, descriptor, mutates, outbound.map(|o| o.label))
            .await?;
        // Undo is exempt from the budget's *verdict*, not from its count: the
        // undo still announces an effect, so a replay of this history bills
        // one and a live pass that billed none would exhaust later than its
        // own replay. A rate ceiling counts it the same way.
        if self.undoing() {
            self.count_unadmitted(outbound_bytes);
            #[cfg(feature = "manifest")]
            self.count_undo(dispatch, descriptor).await;
            return Ok(());
        }
        // A tool's rate ceiling after the run's own budget, which is asked
        // first **without** taking its slot: a rate refusal must cost the run
        // nothing, because replay bills slots from announcements and a refusal
        // has none — a live pass billed for it would exhaust before its own
        // replay does.
        #[cfg(feature = "manifest")]
        if let Some(rated) = self.rate_ceilings(descriptor) {
            self.admit(key, &descriptor.kind, outbound_bytes, false)
                .await?;
            self.reserve_rate(key, dispatch, rated).await?;
        }
        #[cfg(not(feature = "manifest"))]
        let _ = dispatch;
        self.admit(key, &descriptor.kind, outbound_bytes, true)
            .await
    }

    /// Refuse a forward dispatch on the pass that abandons a cancelled run.
    ///
    /// That pass re-walks the paused step only so its open group can abort, so
    /// past the frontier it takes work back and starts none: whatever was
    /// raised, lifted or decided since the pause, a forward dispatch here would
    /// perform — and could commit — what the operator asked to stop.
    fn starts_no_work_when_abandoning(
        &self,
        descriptor: &EffectDescriptor,
    ) -> Result<(), StepError> {
        if self.abandoning && !self.undoing() {
            return Err(StepError::Effect(crate::core::EffectError::Rejected(
                format!(
                    "{} was not dispatched: the run is being cancelled, and cancelling \
                 starts no new work",
                    descriptor.kind
                ),
            )));
        }
        Ok(())
    }

    /// Whether this dispatch takes work back: a compensating phase, or a group
    /// reversing inside a forward one.
    const fn undoing(&self) -> bool {
        !self.phase.is_forward() || self.reversing
    }

    /// Whether the gate treats this dispatch as mutating: the effect's own
    /// claim, widened by the reviewed grant.
    ///
    /// The grant may only tighten. A tool the operator declared mutating gets
    /// the cautious treatment even if the catalogue advertises otherwise,
    /// because a server's own description of itself is an advertisement and
    /// the grant is the operator's decision about it.
    ///
    /// One function for the gate and for `EffectStarted.mutates`, so the
    /// record states the request the gate was asked rather than the effect's
    /// claim — an offline re-derivation reads it back from there.
    #[cfg_attr(not(feature = "manifest"), allow(clippy::unused_self))]
    fn gated_mutates(&self, descriptor: &EffectDescriptor, claimed: bool) -> bool {
        #[cfg(feature = "manifest")]
        let widened = self.tool_grant_for(descriptor).is_some_and(|g| g.mutates);
        #[cfg(not(feature = "manifest"))]
        let widened = {
            let _ = descriptor;
            false
        };
        claimed || widened
    }

    /// The tool reference a dispatch is counted under and every ceiling the
    /// plane states for it, or `None` when nothing limits its rate.
    ///
    /// A tool call and a peer call are both granted as `tool://server/name`;
    /// an agent consultation is never here, because it dispatches through
    /// commission and a manifest refuses a ceiling on one.
    #[cfg(feature = "manifest")]
    fn rate_ceilings(
        &self,
        descriptor: &EffectDescriptor,
    ) -> Option<(String, Vec<crate::quota::RateCeiling>)> {
        let rates = self.rates.as_ref()?;
        let (server, name) = match descriptor.kind.as_str() {
            "tool.call" => ("server", "tool"),
            "a2a.peer/call" => ("peer", "capability"),
            _ => return None,
        };
        let reference = crate::tools::ToolId::new(
            descriptor.args[server].as_str()?,
            descriptor.args[name].as_str()?,
        )
        .reference();
        let ceilings = rates.ceilings.get(&reference)?.clone();
        Some((reference, ceilings))
    }

    /// Take room for this dispatch under its tool's rate ceilings, journalling
    /// a refusal.
    ///
    /// Refused as a budget is — `BudgetRefused` under the refused effect's key,
    /// before the error returns — so the run stops `exhausted` and a resume
    /// once the window has room re-admits it beside the refusal. The count is
    /// never asked on replay: this runs on live dispatch only, and a replayed
    /// refusal is read back.
    #[cfg(feature = "manifest")]
    async fn reserve_rate(
        &mut self,
        key: EffectKey,
        dispatch: EffectKey,
        (grant, ceilings): (String, Vec<crate::quota::RateCeiling>),
    ) -> Result<(), StepError> {
        let Some(rates) = self.rates.clone() else {
            return Ok(());
        };
        let reservation = crate::quota::RateReservation {
            grant,
            run: self.run,
            dispatch,
            ceilings,
            at: super::executor::now_for_admission(),
            exempt: false,
        };
        let refused = match rates.store.reserve_rate(&reservation).await {
            Ok(()) => return Ok(()),
            Err(crate::quota::QuotaError::RateLimited {
                grant,
                ceiling,
                reached,
                ..
            }) => crate::core::BudgetExceeded::Rate {
                grant,
                allowed: ceiling.count,
                window_seconds: ceiling.window_seconds,
                reached,
            },
            Err(other) => return Err(rate_counter_unreachable(&other)),
        };
        tracing::warn!(
            target: telemetry::BUDGET_REFUSED,
            run = %self.run,
            step = %self.step,
            kind = %reservation.grant,
            limit = %refused,
        );
        self.meter.count(metrics::BUDGET_REFUSALS, refused.as_str());
        let rate_refusal = RecordKind::BudgetRefused {
            limit: refused.to_string(),
            used: format!("{:?}", self.budget()),
        };
        self.append_effect(key, rate_refusal).await?;
        Err(StepError::Budget(refused))
    }

    /// Count an undo under its tool's rate ceilings, never refusing it.
    ///
    /// An unreachable counter does not stop the undo either: refusing to undo
    /// is the outcome the exemption exists to prevent, so the miss is logged
    /// and the undo goes out uncounted.
    #[cfg(feature = "manifest")]
    async fn count_undo(&self, dispatch: EffectKey, descriptor: &EffectDescriptor) {
        let (Some(rates), Some((grant, ceilings))) =
            (self.rates.as_ref(), self.rate_ceilings(descriptor))
        else {
            return;
        };
        let reservation = crate::quota::RateReservation {
            grant,
            run: self.run,
            dispatch,
            ceilings,
            at: super::executor::now_for_admission(),
            exempt: true,
        };
        if let Err(error) = rates.store.reserve_rate(&reservation).await {
            tracing::warn!(
                target: telemetry::BUDGET_REFUSED,
                run = %self.run,
                step = %self.step,
                kind = %reservation.grant,
                %error,
                "an undo went out uncounted by its rate ceiling",
            );
        }
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
        ceilings: Option<DeclaredCeilings>,
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
                        "manifest '{}' does not declare the model '{provider}/{model}' — a model this agent's declaration never named is a behaviour change nobody reviewed",
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
                        "manifest '{}' does not grant '{reference}' — a tool the agent's declaration never listed is authority nobody granted",
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
            // A peer call is granted like a tool, under the peer's registry
            // name: `tool://<peer>/<capability>`. Its ceilings and fields
            // arrive on the effect from that same grant (`PeerCall::governed_by`),
            // so presence is the whole question here.
            "a2a.peer/call" => {
                let peer = descriptor.args["peer"].as_str().unwrap_or_default();
                let capability = descriptor.args["capability"].as_str().unwrap_or_default();
                let reference = crate::tools::ToolId::new(peer, capability).reference();
                manifest.tool_grant(&reference).is_none().then(|| {
                    format!(
                        "manifest '{}' does not grant '{reference}' — a peer the agent's declaration never listed is authority nobody granted",
                        manifest.metadata.name
                    )
                })
            }
            // Reading or cancelling a task at a peer is authority at that
            // peer, granted only by a capability there: a task handle names a
            // peer, and a skill may build one for any peer the plane can reach.
            "a2a.task/get" | "a2a.task/cancel" => {
                let peer = descriptor.args["peer"].as_str().unwrap_or_default();
                let prefix = format!("tool://{peer}/");
                (!manifest
                    .spec
                    .tools
                    .iter()
                    .any(|grant| grant.reference.starts_with(&prefix)))
                .then(|| {
                    format!(
                        "manifest '{}' grants nothing at peer '{peer}' — a task at a peer the agent's declaration never listed is authority nobody granted",
                        manifest.metadata.name
                    )
                })
            }
            // The grant's ceilings are compared against what the *effect*
            // declares, never against the descriptor: the descriptor is the
            // effect key, and a reviewed allowance is not part of what a call
            // asks for. The wiring's ceilings arrive beside the descriptor,
            // and a dispatch that did not supply them is refused rather than
            // waved through — an MCP context effect with unstated ceilings is
            // exactly the case this check exists for.
            "mcp.prompt/get" => {
                let server = descriptor.args["server"].as_str().unwrap_or_default();
                let name = descriptor.args["name"].as_str().unwrap_or_default();
                match (manifest.prompt_grant(server, name), ceilings) {
                    (None, _) => Some(format!(
                        "manifest '{}' does not grant MCP prompt '{server}/{name}'",
                        manifest.metadata.name
                    )),
                    (Some(_), None) => Some(format!(
                        "MCP prompt '{server}/{name}' was dispatched without declared ceilings, so the manifest grant cannot be checked",
                    )),
                    (Some(grant), Some(wired))
                        if wired.max_input != grant.max_input_sensitivity
                            || wired.output != grant.output_sensitivity =>
                    {
                        Some(format!(
                            "manifest '{}' grants MCP prompt '{server}/{name}' at input {:?} / output {:?}, but the wiring declares input {:?} / output {:?} — the reviewed artifact and the code disagree about a data ceiling",
                            manifest.metadata.name,
                            grant.max_input_sensitivity,
                            grant.output_sensitivity,
                            wired.max_input,
                            wired.output,
                        ))
                    }
                    (Some(_), Some(_)) => None,
                }
            }
            "mcp.resource/read" => {
                let server = descriptor.args["server"].as_str().unwrap_or_default();
                let uri = descriptor.args["uri"].as_str().unwrap_or_default();
                match (manifest.resource_grant(server, uri), ceilings) {
                    (None, _) => Some(format!(
                        "manifest '{}' does not grant MCP resource '{server}/{uri}'",
                        manifest.metadata.name
                    )),
                    (Some(_), None) => Some(format!(
                        "MCP resource '{server}/{uri}' was dispatched without declared ceilings, so the manifest grant cannot be checked",
                    )),
                    (Some(grant), Some(wired)) if wired.output != grant.output_sensitivity => {
                        Some(format!(
                            "manifest '{}' grants MCP resource '{server}/{uri}' at output {:?}, but the wiring declares output {:?} — the reviewed artifact and the code disagree about a data ceiling",
                            manifest.metadata.name, grant.output_sensitivity, wired.output,
                        ))
                    }
                    (Some(_), Some(_)) => None,
                }
            }
            "mcp.task/update" => {
                let server = descriptor.args["server"].as_str().unwrap_or_default();
                match (manifest.task_input_grant(server), ceilings) {
                    (None, _) => Some(format!(
                        "manifest '{}' does not grant task input responses to MCP server '{server}' — an elicitation is a server asking this plane for data, and the manifest never said it may have an answer",
                        manifest.metadata.name
                    )),
                    (Some(_), None) => Some(format!(
                        "task input for MCP server '{server}' was dispatched without declared ceilings, so the manifest grant cannot be checked",
                    )),
                    (Some(grant), Some(wired))
                        if wired.max_input != grant.max_input_sensitivity =>
                    {
                        Some(format!(
                            "manifest '{}' grants task input to MCP server '{server}' at input {:?}, but the wiring declares input {:?} — the reviewed artifact and the code disagree about a data ceiling",
                            manifest.metadata.name, grant.max_input_sensitivity, wired.max_input,
                        ))
                    }
                    (Some(_), Some(_)) => None,
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

    /// Who is asking, as every policy question inside this run states it.
    ///
    /// The same answer admission gave: the chain's subject when this run acts
    /// under one, and otherwise the capability the run was admitted for, which
    /// claims nothing. One answer at every gate, so `principal == X` means the
    /// same thing wherever a rule is evaluated.
    ///
    /// The agent block is the declaration governing **this step's skill**. It
    /// equals `RunAdmitted.governed_by` whenever the step runs the skill the
    /// run was admitted to; a plan whose steps run other skills presents their
    /// declarations, which no record names.
    fn acting(&self) -> crate::policy::requests::Acting<'_> {
        crate::policy::requests::Acting {
            tenant: self.tenant.as_str(),
            capability: self.agent.as_str(),
            #[cfg(feature = "manifest")]
            agent: self.declaration.as_ref(),
            #[cfg(not(feature = "manifest"))]
            agent: None,
            chain: self.identity.as_ref(),
        }
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

        // Built by the one function an offline re-derivation over an export
        // also calls, and handed to the engine untouched: every input is on
        // the record or named by the checker (the tenant), so `policy check`
        // reaches this verdict again or reports the request as not evaluable.
        // A key added here, after the builder, is a question nobody can ask
        // again.
        let request = crate::policy::requests::effect(
            &self.acting(),
            self.run,
            self.step,
            &descriptor.kind,
            &descriptor.args,
            mutates,
            outbound,
        );

        // Before the policy is consulted, not after. A refusal is journaled as
        // it happens, so a ceiling applied afterwards bounds nothing an
        // observer can see — the record is already written and the bit is
        // already out. Refusing here means the attempt produces neither.
        //
        // Undo is exempt from this ceiling and the one below, as it is from
        // every budget verdict.
        let undoing = self.undoing();
        if let Err(exceeded) = self
            .ledger
            .lock()
            .expect("budget mutex")
            .admit_policy_check()
            && !undoing
        {
            return Err(StepError::Budget(exceeded));
        }

        // Both refusals, one path. `let … else` over `Deny` alone would send
        // every other variant to the permit branch, so a decision this gate
        // does not know about becomes an allow — a gate that fails open the
        // moment the vocabulary grows. `Malformed` is refused like a denial
        // and journaled like one; what differs is the operator's telemetry,
        // because the fix is the policy set rather than the request.
        let decision = engine.authorize(&request.as_request());
        let malformed = decision.is_malformed();
        let Some(reason) = decision.reason().map(ToOwned::to_owned) else {
            return Ok(());
        };

        tracing::error!(
            target: telemetry::POLICY_DENIED,
            run = %self.run,
            step = %self.step,
            action = crate::core::ACTION_PERFORM,
            resource = %descriptor.kind,
            policy_error = malformed,
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
        if let Err(exceeded) = self.ledger.lock().expect("budget mutex").record_denial()
            && !undoing
        {
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
    ///
    /// `take` is whether an admitted effect takes its slot now. A caller that
    /// asks first and dispatches later — the rate ceiling sits between — asks
    /// without, and takes it on the second call.
    async fn admit(
        &mut self,
        key: EffectKey,
        kind: &str,
        outbound_bytes: u64,
        take: bool,
    ) -> Result<(), StepError> {
        // Scoped so the guard is gone before any await below.
        let verdict = {
            let mut ledger = self.ledger.lock().expect("budget mutex");
            if take {
                ledger.admit_effect(outbound_bytes)
            } else {
                ledger.can_admit_effect(outbound_bytes)
            }
        };
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

    /// Put a completion's own report on its span.
    ///
    /// Every value here is a fact the provider stated about its own answer, which is
    /// why absence is preserved rather than defaulted: an attribute this plane fills
    /// in from the request would report that a substitution had been ruled out when
    /// nothing looked.
    fn record_gen_ai_response(span: &tracing::Span, reply: &crate::core::GenAiResponse) {
        if let Some(model) = &reply.model {
            span.record(telemetry::GEN_AI_RESPONSE_MODEL, model.as_str());
        }
        if let Some(reason) = &reply.finish_reason {
            span.record(telemetry::GEN_AI_FINISH_REASON, reason.as_str());
        }
        span.record(telemetry::GEN_AI_INPUT_TOKENS, reply.input_tokens);
        span.record(telemetry::GEN_AI_OUTPUT_TOKENS, reply.output_tokens);
        span.record(telemetry::GEN_AI_CACHE_READ_TOKENS, reply.cache_read_tokens);
        span.record(
            telemetry::GEN_AI_CACHE_WRITE_TOKENS,
            reply.cache_write_tokens,
        );
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
        outbound: Option<Outbound<'_>>,
    ) -> Result<Result<E::Output, crate::core::EffectError>, StepError> {
        let span = tracing::info_span!(
            telemetry::EFFECT_SPAN,
            { telemetry::EFFECT_KIND } = tracing::field::display(&effect.descriptor().kind),
            { telemetry::EFFECT_KEY } = tracing::field::display(&key),
            { telemetry::EFFECT_ATTEMPT } = attempt,
            { telemetry::EFFECT_MUTATES } = effect.mutates(),
            { telemetry::EFFECT_REPLAYED } = false,
            { telemetry::MODE } = telemetry::mode_str(self.mode),
            { telemetry::OUTCOME } = tracing::field::Empty,
            { telemetry::ERROR_TYPE } = tracing::field::Empty,
            // Present only on the effects that *are* GenAI operations. Recorded
            // rather than declared with a value so a clock read does not carry
            // an empty `gen_ai.operation.name`, which would make the attribute
            // useless for the tooling that keys on it.
            { telemetry::GEN_AI_OPERATION } = tracing::field::Empty,
            { telemetry::GEN_AI_PROVIDER } = tracing::field::Empty,
            { telemetry::GEN_AI_REQUEST_MODEL } = tracing::field::Empty,
            { telemetry::GEN_AI_TOOL_NAME } = tracing::field::Empty,
            { telemetry::GEN_AI_RESPONSE_MODEL } = tracing::field::Empty,
            { telemetry::GEN_AI_FINISH_REASON } = tracing::field::Empty,
            { telemetry::GEN_AI_INPUT_TOKENS } = tracing::field::Empty,
            { telemetry::GEN_AI_OUTPUT_TOKENS } = tracing::field::Empty,
            { telemetry::GEN_AI_CACHE_READ_TOKENS } = tracing::field::Empty,
            { telemetry::GEN_AI_CACHE_WRITE_TOKENS } = tracing::field::Empty,
        );
        if let Some(op) = effect.gen_ai_operation() {
            span.record(telemetry::GEN_AI_OPERATION, op);
            // The convention splits the name by operation: a completion names
            // a model, a tool call names a tool, and neither key means the
            // other. Read from the effect rather than guessed from the kind.
            if let Some(request) = effect.gen_ai_request() {
                if let Some(provider) = &request.provider {
                    span.record(telemetry::GEN_AI_PROVIDER, provider.as_str());
                    span.record(telemetry::GEN_AI_REQUEST_MODEL, request.name.as_str());
                } else {
                    span.record(telemetry::GEN_AI_TOOL_NAME, request.name.as_str());
                }
            }
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
        // After the call, because that is when either exists. A failure records
        // no figures rather than zeroes: *this call reported no usage* and *this
        // call used none* are different facts, and a panel that cannot tell them
        // apart reads a metered refusal as free.
        match &outcome {
            Ok(answer) => {
                if let Some(reply) = effect.gen_ai_response(answer) {
                    Self::record_gen_ai_response(&span, &reply);
                }
            }
            // The convention asks for this on any operation that ends in error,
            // and without it every `GenAI` panel reports a plane with no
            // failures at all — which is the one claim this runtime exists not
            // to make.
            Err(failure) => {
                span.record(telemetry::ERROR_TYPE, failure.class());
            }
        }
        Ok(outcome)
    }

    /// Consume one attempt's history, if the journal holds it.
    ///
    /// Split out of the dispatch loop because that loop is the determinism
    /// boundary and reads better as two halves — *what does history say*, then
    /// *what does a live attempt do* — and because the replay half is where
    /// every billing arm lives, which is the arithmetic a replayed run's verdict
    /// depends on.
    #[allow(clippy::too_many_arguments)]
    async fn replayed_attempt<E: Effect>(
        &mut self,
        effect: &E,
        descriptor: &EffectDescriptor,
        ordinal: u32,
        attempt: u32,
        key: EffectKey,
        recovery: &crate::core::Recovery,
        policy: &crate::core::RetryPolicy,
    ) -> Result<Replayed<E::Output>, StepError> {
        match self.cursor.next(key, descriptor, attempt)? {
            Some(EffectReplay::Done {
                output,
                spend,
                mut declared,
                content,
                ..
            }) => {
                self.replayed_done(
                    &descriptor.kind,
                    attempt,
                    spend,
                    Self::outbound_size(effect),
                );
                self.arrival_refusal(content.as_ref())?;
                declared.sensitivity =
                    crate::core::ContentVerdict::raise(content.as_ref(), declared.sensitivity);
                Ok(Replayed::Answered(
                    serde_json::from_value(output)?,
                    declared,
                ))
            }
            // A hop the run was withheld at. Re-raised inside the replayed
            // prefix and on a strict pass; at the frontier the boundary has
            // already decided the withdrawal is lifted — it would have paused
            // the run before this step otherwise — so the same key is
            // dispatched live, through the hop's own fresh read of the halts.
            Some(EffectReplay::Withheld { subject, reason }) => {
                if !self.writes_enabled() {
                    return Err(StepError::Withheld { subject, reason });
                }
                Ok(Replayed::Continue(attempt))
            }
            Some(refusal @ (EffectReplay::Refused { .. } | EffectReplay::Denied { .. })) => {
                // Re-admitted refusals fall through to a live dispatch of the
                // same key; everything else re-raises inside.
                self.replayed_refusal(key, descriptor, refusal, Self::outbound_size(effect))
                    .await?;
                Ok(Replayed::Continue(attempt))
            }
            Some(EffectReplay::Failed {
                error,
                disposition,
                spend,
                permanent,
            }) => Ok(Replayed::Continue(self.replay_recorded_failure(
                descriptor,
                ordinal,
                attempt,
                key,
                recovery,
                policy,
                &error,
                disposition,
                spend,
                permanent,
                // Recomputed from the code, like the recovery and the policy:
                // replay assumes the same program, and the record's own
                // `mutates` lives on the start record the cursor has already
                // collapsed.
                effect.mutates(),
                Self::outbound_size(effect),
            )?)),
            Some(EffectReplay::Orphan {
                recovery: recorded, ..
            }) => {
                // An announcement with no terminal record is still an attempt
                // this run made against the world, and every pass that reads it
                // bills the one slot the live pass took when it admitted the
                // attempt.
                self.bill_replayed(crate::core::Spend::default(), Self::outbound_size(effect));
                if let Some(output) = self
                    .orphan_verdict(effect, key, attempt, &recorded, recovery, policy)
                    .await?
                {
                    // Recovered by a probe this pass ran, so the declaration
                    // this pass reads is the one its own `EffectReconciled`
                    // record just carried.
                    return Ok(Replayed::Answered(
                        output,
                        crate::core::DeclaredOutput::of(effect),
                    ));
                }
                Ok(Replayed::Continue(attempt + 1))
            }
            // History exhausted: this attempt runs live, unless a strict pass
            // is verifying — where reaching the end is itself the finding.
            None if self.mode == Mode::Strict => Err(StepError::ReplayOverrun {
                actual: key,
                kind: descriptor.kind.clone(),
            }),
            None => Ok(Replayed::Live),
        }
    }

    /// What to do about a failure the journal already holds.
    ///
    /// Returns the next attempt number to try. Errors if the recorded run
    /// stopped here — which is the faithful outcome, not a fault.
    #[allow(clippy::too_many_arguments)]
    fn recorded_failure(
        &self,
        descriptor: &EffectDescriptor,
        ordinal: u32,
        attempt: u32,
        key: EffectKey,
        recovery: &crate::core::Recovery,
        policy: &crate::core::RetryPolicy,
        error: &str,
        disposition: crate::core::Disposition,
        permanent: bool,
        mutates: bool,
    ) -> Result<u32, StepError> {
        // Deliberately bills nothing. The recorded failure was billed by the
        // caller, at the figure the record carries; a second billing here
        // would charge one announced attempt two slots against `max_effects`,
        // so a resumed run would exhaust a ceiling its live pass had room
        // under — the exact divergence journaled spend exists to prevent.

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
            mutates,
        ) {
            return Err(stop);
        }

        // It would have retried, so it died between recording this failure and
        // starting the next attempt. A strict pass reports that rather than
        // performing anything; a resume carries on live.
        if self.mode == Mode::Strict {
            return Err(StepError::ReplayOverrun {
                actual: next,
                kind: descriptor.kind.clone(),
            });
        }
        Ok(attempt + 1)
    }

    /// Whether to stop after a failed attempt, and with what.
    ///
    /// Three gates in order, and a policy can only ever narrow what the first
    /// two allow:
    ///
    /// 1. [`Landed`](crate::core::Disposition::Landed) — the call took effect.
    ///    For a mutating effect, repeating it would be a second real
    ///    performance, so it never happens; a non-mutating one falls through
    ///    to the policy, since asking again changes nothing but the bill —
    ///    unless the failure is permanent, the far side's answer rather than a
    ///    fault.
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
        mutates: bool,
    ) -> Option<StepError> {
        use crate::core::{Disposition, Recovery};

        match disposition {
            // A call that changed nothing may be asked again: what landed was
            // a read, or a completion — a bill, which the failure already
            // carried to the budget — and the policy decides whether another
            // attempt is worth its cost. A model stream that died after
            // generating is the common case. A permanent landed failure is an
            // answer — a tool that ran and reported failure — and asking again
            // repeats the work for the same answer.
            Disposition::Landed if !mutates && !permanent => {}
            Disposition::Landed if !mutates => {
                return Some(StepError::Effect(crate::core::EffectError::Final {
                    detail: format!(
                        "effect {key} ran and failed on attempt {attempt}, and the failure is \
                         its answer rather than a fault ({message}); no retry would change it"
                    ),
                    disposition,
                }));
            }
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
                // or carrying an idempotency key the provider honours — while
                // attempts remain. Once they run out the doubt is *final*,
                // and for a mutating effect a final unknown is an operator's
                // question, not a `Failed` (I5): a failure unwinds, and the
                // unwind would compensate every step around a call that may
                // have landed — the refund for money nobody took, issued by
                // the retry policy having merely given up.
                Recovery::Retry | Recovery::Idempotent { .. } => {
                    if mutates && !policy.permits(attempt) {
                        return Some(StepError::Undecidable {
                            key,
                            recovery: recovery.clone(),
                            detail: format!(
                                "{message} — attempts exhausted with the outcome still \
                                 unknown, and the effect mutates; whether the last call \
                                 landed is a question for an operator, not for an unwind"
                            ),
                        });
                    }
                }
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
                            "effect {key} was refused on attempt {attempt}, and the refusal is an answer rather than a fault ({message}); no retry would change it"
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
            StepError::NotWired(
                "durable timers need a timer store — build the runtime with `.timers(store)`"
                    .into(),
            )
        })?;

        // Whole seconds, matching the store's precision. Two records of one
        // wake-up that disagree by a fraction of a second give "when does this
        // fire?" two answers.
        let until = until.replace_nanosecond(0).map_err(|e| {
            StepError::Effect(crate::core::EffectError::Refused(format!(
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
            match self.cursor.next(key, &descriptor, 1)? {
                Some(EffectReplay::Done { spend, .. }) => {
                    // A durable sleep sends nothing; it is registered.
                    self.bill_replayed(spend, 0);
                    return Ok(());
                }
                Some(
                    refusal @ (EffectReplay::Refused { .. }
                    | EffectReplay::Withheld { .. }
                    | EffectReplay::Denied { .. }),
                ) => return Err(recorded_refusal(refusal)),
                Some(EffectReplay::Failed { error, spend, .. }) => {
                    self.bill_replayed(spend, 0);
                    return Err(StepError::Effect(crate::core::EffectError::Rejected(error)));
                }
                // Announced, and *possibly* armed: whether the arm landed is
                // unknowable from the journal, because a crash — or a
                // transient store error — between the announcement and the
                // registration leaves exactly this record. Suspending without
                // repairing would strand the run forever: no timer, no
                // subscription, a released lease — nothing in the system ever
                // names it again, and it looks precisely like work in
                // progress. Re-arming is safe because `until` derives from
                // journaled reads (the same instant on every pass) and `arm`
                // keeps the first registration (a timer somebody may have
                // claimed is never moved). A strict pass dispatches nothing,
                // so only a resume repairs — strict still suspends here, which
                // is the honest reading of a journal that ends mid-wait.
                Some(EffectReplay::Orphan { .. }) => {
                    // Announced on the record, so this pass bills the wait —
                    // the re-arm below writes no second announcement.
                    self.bill_replayed(crate::core::Spend::default(), 0);
                    if self.mode == Mode::Resume {
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
                    }
                    return Err(StepError::Suspended(
                        crate::core::SuspendReason::AwaitingTime { until },
                    ));
                }
                None if self.mode == Mode::Strict => {
                    return Err(StepError::ReplayOverrun {
                        actual: key,
                        kind: descriptor.kind.clone(),
                    });
                }
                None => {}
            }
        }

        // A wait is announced rather than dispatched, so no ceiling gates it —
        // refusing one would strand a run mid-plan rather than stop work. It
        // is still an operation the journal holds, so it takes its slot, and
        // every pass that replays the announcement bills the same one.
        self.count_unadmitted(0);

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
                outbound_bytes: None,
                content_rules: None,
                credential: None,
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
                StepError::Effect(crate::core::EffectError::Refused(format!(
                    "unrepresentable sleep duration: {e}"
                )))
            })?)
            .ok_or_else(|| {
                StepError::Effect(crate::core::EffectError::Refused(
                    "sleep duration overflows the representable range".into(),
                ))
            })?;
        self.sleep_until(until).await
    }

    /// Record a sink-gate refusal under the key the refused dispatch would
    /// have carried, then hand it back as the error to raise.
    ///
    /// The refusal occupies the dispatch's position: the ordinal is consumed
    /// and the record keyed exactly as the effect would have been (attempt 1 —
    /// nothing was attempted), for the same reason a budget refusal and a
    /// policy denial are keyed. Without a record the refusal is invisible one
    /// mode later: a strict pass over the refused run finds nothing to consume
    /// and reports history left over.
    ///
    /// Reached only where the dispatch would be **live**, because that is the
    /// only place a sink gate runs at all. A replayed prefix does not re-decide
    /// these verdicts; it reads the record this wrote, through the same cursor
    /// arm that replays a policy denial.
    ///
    /// # It stays a [`StepError::Policy`], and the record says so
    ///
    /// A sink gate refusing one call is something a tool-calling loop can act
    /// on: the model is told `REFUSED` and may try another route. An
    /// authorization denial is not — it ends the run. Both are journaled as
    /// `PolicyDenied`, so the record carries
    /// [`ACTION_EGRESS`](crate::core::ACTION_EGRESS) to keep the two
    /// distinguishable, and `recorded_refusal` rebuilds this shape from it. A
    /// replay that turned a sink refusal into a denial would end a run the
    /// original completed.
    async fn refuse_sink(
        &mut self,
        descriptor: &EffectDescriptor,
        action: &str,
        denial: PolicyError,
    ) -> StepError {
        let key = self.next_effect_key(descriptor);
        if let Err(e) = self
            .append_effect(
                key,
                RecordKind::PolicyDenied {
                    reason: denial.to_string(),
                    action: action.to_owned(),
                    resource: descriptor.kind.clone(),
                },
            )
            .await
        {
            // A runtime that cannot record what it refused must not report
            // the tidier error instead.
            return e;
        }

        // **Counted, because this is the refusal a model can actually probe.**
        //
        // The engine gate counts its own denials, and in a tool-calling loop
        // one of those is not model-facing and ends the run — so nothing there
        // accumulates. What does accumulate is here: a sink refusal comes back
        // as `REFUSED`, the loop continues, and the model may try again. That
        // is the channel `REFUSED`'s own documentation says `max_denials`
        // bounds, and it was the one path not counted.
        //
        // After the record, for the reason the engine gate gives: the refusal
        // has happened and belongs in the journal whatever the ceiling says.
        // What the ceiling stops is the next attempt.
        self.counted_refusal(denial)
    }

    /// The refusal a recorded content verdict hands the step, if it refused —
    /// on the pass that recorded it and on every replay of it alike.
    fn arrival_refusal(
        &self,
        content: Option<&crate::core::ContentVerdict>,
    ) -> Result<(), StepError> {
        match content.and_then(|c| c.refused.as_ref()) {
            Some(refused) => Err(self.counted_refusal(PolicyError::Content {
                rule: refused.rule.clone(),
                pointer: refused.pointer.clone(),
            })),
            None => Ok(()),
        }
    }

    /// A recorded refusal read back, counted toward `max_denials` exactly as
    /// the pass that recorded it counted it — so a replay reaches the ceiling
    /// at the same refusal the original did, and a resume does not start the
    /// count again. A sink or content refusal always counts; an engine denial
    /// stops an undo no more than it did live.
    fn replayed_denial(&self, refusal: EffectReplay) -> StepError {
        if let EffectReplay::Denied { action, .. } = &refusal {
            let sink =
                action == crate::core::ACTION_EGRESS || action == crate::core::ACTION_CONTENT;
            if let Err(exceeded) = self.ledger.lock().expect("budget mutex").record_denial()
                && (sink || !self.undoing())
            {
                return StepError::Budget(exceeded);
            }
        }
        recorded_refusal(refusal)
    }

    /// A refusal a step is handed, counted toward `max_denials` first: past
    /// the ceiling the step is handed the ceiling instead.
    fn counted_refusal(&self, denial: PolicyError) -> StepError {
        if let Err(exceeded) = self.ledger.lock().expect("budget mutex").record_denial() {
            return StepError::Budget(exceeded);
        }
        denial.into()
    }

    /// Send a labeled value into a sink, handing the value to the effect and
    /// the gate in one motion.
    ///
    /// The closure receives the inner value and builds the effect from it, so
    /// the bytes the gates check and the bytes the effect sends are one
    /// argument rather than two the caller must keep in agreement:
    ///
    /// ```ignore
    /// let completion = cx
    ///     .sink_with(&prompt, |value| ModelCall::new(provider, model, value))
    ///     .await?;
    /// ```
    ///
    /// The two-pass spelling — `ModelCall::new(.., prompt.peek().clone())`
    /// beside `cx.sink(call, &prompt)` — writes the same data twice and
    /// leaves a runtime check to catch the versions drifting apart. Passing it
    /// once removes the drift at the API instead of detecting it afterwards;
    /// the byte-for-byte binding check still runs underneath, because a custom
    /// effect could bind something other than what its constructor was
    /// handed, and that is a driver bug worth a loud refusal.
    ///
    /// Fallible construction composes: the closure may return
    /// `Result<E, impl Into<StepError>>` — see [`BuildsEffect`] — which is
    /// what `ToolCall::prepare` needs.
    ///
    /// # Errors
    ///
    /// Whatever the closure refuses with, and everything [`sink`](Self::sink)
    /// refuses: the egress ceiling, the journal ceiling, the whole-value taint
    /// gate, and the per-field provenance rules.
    pub async fn sink_with<E, B, F>(
        &mut self,
        args: &Tainted<Value>,
        build: F,
    ) -> Result<Tainted<E::Output>, StepError>
    where
        E: Effect,
        B: BuildsEffect<E>,
        F: FnOnce(Value) -> B,
    {
        let effect = build(args.peek().clone()).into_effect()?;
        self.sink(effect, args).await
    }

    /// Send a labeled value into a sink, enforcing the information-flow gates.
    ///
    /// Prefer [`sink_with`](Self::sink_with), which hands the value to the
    /// effect and the gate in one motion. This form remains for effects that
    /// bind their outbound value internally — a governed media fetch derives
    /// its bound arguments from the URL it was constructed over — and for
    /// callers holding an effect built elsewhere.
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
    ///
    /// Both are judged over the *effective label at this sink*: the base label
    /// improved by exactly the release marks whose destination names this
    /// sink's identity. A release for `tool://ledger/transfer` moves nothing
    /// at `tool://mail/send`.
    pub async fn sink<E: Effect>(
        &mut self,
        #[cfg_attr(not(feature = "manifest"), allow(unused_mut))] mut effect: E,
        args: &Tainted<Value>,
    ) -> Result<Tainted<E::Output>, StepError> {
        let sink_name = effect.descriptor().kind;
        // The identity a destination-scoped release must name: the sink's
        // provenance identity — `tool://server/name`, `model:provider/model` —
        // the same exact name a `ProtectedField::from_sources` rule grants.
        // One chokepoint, so a release cannot be "for the ledger" at one gate
        // and "for tools generally" at another.
        let sink_id = effect.source().to_string();

        Self::bound_as_sent(&effect, args, sink_name.clone())?;

        #[cfg(feature = "manifest")]
        let (judged, content_rules) = self.content_at_sink(&mut effect, args).await?;
        #[cfg(feature = "manifest")]
        let args = judged.as_ref().unwrap_or(args);
        #[cfg(not(feature = "manifest"))]
        let content_rules: Vec<String> = Vec::new();

        // The label these gates judge is the **effective label at this sink**:
        // the base label improved by exactly the release marks granted for
        // this destination. Everywhere outside a sink gate the base label
        // speaks — a release is for a destination, not for storage — and this
        // effective label is also what policy is asked over and what the
        // dispatch journals as its outbound label, because it is the label the
        // verdict was reached over.
        let label = args.effective_label(&sink_id);
        let label = &label;

        // **Every sink gate applies to live dispatch only**, and "live
        // dispatch" is a property of the *cursor*, not of the mode.
        //
        // A replayed effect reads its result back from the journal, and the
        // verdict these gates reached the first time is already in that
        // journal — a pass as the `EffectDone` beside it, a refusal as its own
        // record the cursor hands back. So there is nothing here for a replay
        // to decide, and deciding anyway is how a replay stops reproducing the
        // run and starts re-judging it: a tightened ceiling refuses an effect
        // that already happened, a loosened one blesses an effect that was
        // refused.
        //
        // This covers the effect's own declarations as well as the manifest's,
        // because for every effect that reaches a sink the "code" reading is
        // wrong. A tool's ceiling and protected fields come from the operator's
        // `ToolSafety`, an MCP prompt's from a reviewed grant, a peer's from
        // its `PeerGrant` — configuration, all of it, editable without
        // recompiling and absent from the effect key. Judging a replayed
        // effect against today's copy makes an operator's catalogue edit
        // retroactively change what a finished run was allowed to do.
        //
        // But `Resume` is only *replaying* until its history runs out, and
        // then it dispatches **live** — new calls, against the real world,
        // for the rest of the run. Keying these gates on the mode instead of
        // on cursor exhaustion switches them off for that entire live tail:
        // a run refused by the egress ceiling, resumed, sails the same value
        // past the same ceiling — an enforcement whose second attempt is a
        // bypass is not an enforcement. `writes_enabled` is precisely "will
        // this effect dispatch live": always in `Live`, past the frontier in
        // `Resume`, never in `Strict` (which cannot dispatch at all — an
        // exhausted cursor there is `ReplayOverrun`, not permission).
        let live_dispatch = self.writes_enabled();
        #[cfg(feature = "manifest")]
        let manifest_gates = live_dispatch;

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
        if live_dispatch && label.sensitivity > ceiling {
            let denial = PolicyError::EgressCeiling {
                sink: sink_name,
                actual: label.sensitivity,
                ceiling,
            };
            return Err(self
                .refuse_sink(&effect.descriptor(), crate::core::ACTION_EGRESS, denial)
                .await);
        }

        // What may be *written down* is a different question from what may
        // leave, and it is the one that decides whether a run's personal data
        // can ever be erased: this effect's canonical arguments are about to
        // enter an append-only chain, where no record is ever removed. This is
        // the *refuse it* half; `RuntimeBuilder::keyring` is the *seal it* half,
        // and they compose — a sealed record is still a record, and a key ring
        // is still an operational dependency, so a deployment may want both.
        // Checked here, before the announcement, so the refusal costs nothing —
        // and absent by default, because silence is not a ceiling: a
        // deployment that never declared one must not have its traffic refused
        // by an option it did not ask for.
        //
        // Judged over the **base** label, not the effective one: what may be
        // written down is a storage question, and a release is for a
        // destination, not for storage. A sensitivity release toward this sink
        // does not make the bytes en route to the append-only chain any more
        // erasable.
        //
        // Two sources, and **the stricter wins** — exactly as a reviewed tool
        // grant may only tighten the operator's catalogue. The plane's ceiling
        // is how a hand-written skill, running under no manifest, states it.
        let stored = args.label().sensitivity;
        #[cfg(feature = "manifest")]
        let declared = self
            .manifest
            .as_ref()
            .filter(|_| manifest_gates)
            .and_then(|m| m.spec.security.max_sensitivity_journaled);
        #[cfg(not(feature = "manifest"))]
        let declared: Option<crate::core::Sensitivity> = None;
        let journal_ceiling = match (self.journal_ceiling, declared) {
            (Some(plane), Some(manifest)) => Some(plane.min(manifest)),
            (only, None) | (None, only) => only,
        };
        // Live dispatch only, like every other sink gate: on replay the record
        // already says what this ceiling decided, and judging it again would
        // write a second refusal in strict mode and re-judge history under
        // today's ceiling.
        if live_dispatch
            && let Some(journal_ceiling) = journal_ceiling
            && stored > journal_ceiling
        {
            let denial = PolicyError::JournalCeiling {
                sink: sink_name,
                actual: stored,
                ceiling: journal_ceiling,
            };
            return Err(self
                .refuse_sink(&effect.descriptor(), crate::core::ACTION_EGRESS, denial)
                .await);
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

        if live_dispatch
            && let Err(refusal) =
                Self::enforce_protected_fields(&effect, args, sink_name, &sink_id, mutates)
        {
            // The whole-value taint gate and the per-field rules are sink
            // gates like the ceilings above, and their refusals are recorded
            // for the same reason.
            return Err(match refusal {
                StepError::Policy(denial) => {
                    self.refuse_sink(&effect.descriptor(), crate::core::ACTION_EGRESS, denial)
                        .await
                }
                other => other,
            });
        }

        // The same label the gates above enforced, handed to the deployment's
        // own rules. See `authorize` for why it belongs there too.
        self.effect_after_sink_gate(
            effect,
            Some(Outbound {
                label,
                content_rules: &content_rules,
            }),
        )
        .await
    }

    /// The whole-object taint gate and the per-field rules, judged over the
    /// **effective label at this sink**: the base label improved by exactly
    /// the release marks whose destination is `sink_id`, field-scoped marks
    /// applying only to their fields. A mark granted toward a different sink
    /// changes nothing here except the refusal's wording — the operator is
    /// told the release exists and where it points, never its basis or
    /// evidence.
    fn enforce_protected_fields<E: Effect>(
        effect: &E,
        args: &Tainted<Value>,
        sink_name: String,
        sink_id: &str,
        mutates: bool,
    ) -> Result<(), StepError> {
        let protected = effect.protected_fields();
        if protected.is_empty() {
            if mutates && args.effective_label(sink_id).is_untrusted() {
                if let Some(mark) = misdirected_release(args, sink_id, "") {
                    return Err(PolicyError::ReleaseDestination {
                        sink: sink_name,
                        granted: mark.destination().to_owned(),
                        actual: sink_id.to_owned(),
                    }
                    .into());
                }
                return Err(PolicyError::TaintGate { sink: sink_name }.into());
            }
            return Ok(());
        }

        for field in protected {
            let path = field.path();
            let Some(field_label) = args.effective_label_at(sink_id, path) else {
                return Err(PolicyError::ProtectedFieldMissing {
                    sink: sink_name,
                    path: path.to_owned(),
                }
                .into());
            };
            if field.requires_trusted() && field_label.is_untrusted() {
                if let Some(mark) = misdirected_release(args, sink_id, path) {
                    return Err(PolicyError::ProtectedFieldReleaseDestination {
                        sink: sink_name,
                        path: path.to_owned(),
                        granted: mark.destination().to_owned(),
                        actual: sink_id.to_owned(),
                    }
                    .into());
                }
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
            // The content discipline: the value itself must be one of the
            // declared set, whatever its labels say. Exact structural
            // equality — a near miss is a refusal, never a correction — and
            // conjoined with the label rules above rather than substituting
            // for them, so a source-bound field with a value set refuses an
            // allowed source answering something nobody enumerated.
            if !field.allowed_values().is_empty()
                && !args
                    .peek()
                    .pointer(path)
                    .is_some_and(|actual| field.allowed_values().contains(actual))
            {
                return Err(PolicyError::ProtectedFieldValue {
                    sink: sink_name,
                    path: path.to_owned(),
                }
                .into());
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

    /// Grant a destination-scoped release over a whole value or selected
    /// structured fields.
    ///
    /// The release is policy-authorized and permanently records the releaser,
    /// basis, field scope, destination, evidence, and prior label. It does
    /// **not** relabel the value: it attaches release marks, and only the
    /// sink whose identity equals the release's `destination` — the
    /// provenance-style name, `tool://server/name`, `model:provider/model` —
    /// computes an improved effective label from them. Everywhere else the
    /// value keeps its base label: joined into other values, written to
    /// memory, read as `label().trust`, it is still what it was. A selected
    /// field release is accepted only when the value was assembled with
    /// [`Tainted::object`](crate::core::Tainted::object) or
    /// [`Tainted::array`](crate::core::Tainted::array), so precision can never
    /// be invented after provenance was flattened.
    ///
    /// Refused on a plane with no policy engine: a release is the one call
    /// that lowers a label, and without a rule permitting `data:release` there
    /// is nobody to have decided it.
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
        // The record carries the decision and the prior labels only; the
        // marks it attaches are determined by `release` — see
        // `RecordKind::Released` for why they are not restated.
        let descriptor = EffectDescriptor::new(
            crate::core::ACTION_RELEASE,
            serde_json::json!({
                "release": &release,
                "label": &label,
                "field_labels": &field_labels,
                "value": value_digest,
            }),
        );
        let key = self.next_effect_key(&descriptor);

        if self.mode.is_replaying() {
            match self.cursor.next(key, &descriptor, 1)? {
                Some(EffectReplay::Done { .. }) => return Ok(released),
                Some(denied @ EffectReplay::Denied { .. }) => {
                    return Err(self.replayed_denial(denied));
                }
                Some(_) => {
                    return Err(StepError::ReplayOverrun {
                        actual: key,
                        kind: descriptor.kind.clone(),
                    });
                }
                None if self.mode == Mode::Strict => {
                    return Err(StepError::ReplayOverrun {
                        actual: key,
                        kind: descriptor.kind.clone(),
                    });
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
        // The builder the effect gate and `policy check` share, for the same
        // reason: `Released` records the release and label asked about.
        let request =
            crate::policy::requests::release(&self.acting(), self.run, self.step, release, label);

        self.ledger
            .lock()
            .expect("budget mutex")
            .admit_policy_check()
            .map_err(StepError::Budget)?;

        // Both refusals, one path. `let … else` over `Deny` alone would send
        // every other variant to the permit branch, so a decision this gate
        // does not know about becomes an allow — a gate that fails open the
        // moment the vocabulary grows. `Malformed` is refused like a denial
        // and journaled like one; what differs is the operator's telemetry,
        // because the fix is the policy set rather than the request.
        //
        // **No engine is a refusal here**, unlike at the effect gate. A plane
        // with no policy performs what its code asks, and the structural gates
        // — the taint gate, protected fields, sink and journal ceilings — hold
        // regardless. A release is the one call that switches those off for a
        // value, so an ungoverned release would let any skill lower a label
        // below a ceiling nobody agreed to lift.
        let decision = self.policy.as_ref().map_or_else(
            || {
                crate::core::PolicyDecision::deny(
                    "this plane has no policy engine, and a release lowers a label \
                     only when a rule permits it — wire one that permits `data:release`",
                )
            },
            |engine| engine.authorize(&request.as_request()),
        );
        let malformed = decision.is_malformed();
        let Some(reason) = decision.reason().map(ToOwned::to_owned) else {
            return Ok(());
        };

        tracing::error!(
            target: telemetry::POLICY_DENIED,
            run = %self.run,
            step = %self.step,
            action = crate::core::ACTION_RELEASE,
            resource = "information_flow.label",
            policy_error = malformed,
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
        &self,
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
        mutates: bool,
        outbound_bytes: u64,
    ) -> Result<u32, StepError> {
        self.bill_replayed(spend, outbound_bytes);
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
            mutates,
        )
    }

    /// The delegation-depth gate, with its refusal journaled.
    async fn refuse_excess_delegation<E: Effect>(
        &mut self,
        effect: &E,
        descriptor: &EffectDescriptor,
    ) -> Result<(), StepError> {
        if let Err(refusal) = self.check_delegation_depth(effect) {
            return Err(match refusal {
                StepError::Policy(denial) => {
                    self.refuse_sink(descriptor, crate::core::ACTION_EGRESS, denial)
                        .await
                }
                other => other,
            });
        }
        Ok(())
    }

    /// Refuse an effect that would delegate deeper than the declaration allows.
    ///
    /// Live dispatch only, like every other manifest gate — where "live" is
    /// cursor exhaustion, not mode: a replayed effect reads its result back,
    /// so a tightened ceiling must not retroactively refuse it, but a resumed
    /// run past its frontier is dispatching *new* delegations against the
    /// real world, and the loop a `specialist` role exists to prevent does
    /// not pause because the run once crashed.
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
            .filter(|_| self.writes_enabled())
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
        outbound: Option<Outbound<'_>>,
    ) -> Result<Result<E::Output, crate::core::EffectError>, StepError> {
        // `EffectStarted` goes down *before* the call. If the process dies
        // between here and the terminal record, replay sees an orphan and the
        // declared recovery mode decides — which is only possible because the
        // start was durable first.
        if write_start {
            let descriptor = effect.descriptor();
            // The value the gate was asked with, not the effect's own claim:
            // see `gated_mutates`.
            let mutates = self.gated_mutates(&descriptor, effect.mutates());
            self.append_effect(
                key,
                RecordKind::EffectStarted {
                    descriptor,
                    recovery: effect.recovery(),
                    mutates,
                    attempt,
                    backoff_ms,
                    outbound_label: outbound.map(|o| o.label.clone()),
                    // Measured from what the sink was handed, so the figure is
                    // the payload rather than the descriptor around it. `None`
                    // where nothing crossed, so the ordinary record is
                    // unchanged — the ceiling reads the same measurement with
                    // absence flattened to zero.
                    outbound_bytes: effect.sink_arguments().map(|_| Self::outbound_size(effect)),
                    content_rules: outbound
                        .filter(|o| !o.content_rules.is_empty())
                        .map(|o| o.content_rules.to_vec()),
                    credential: effect.credential_binding(),
                },
            )
            .await?;
        }

        // Past this point the call has returned, so a failure to *record* what
        // it did is not a store error like any other: the announcement is
        // durable, the terminal record is not, and this process — unlike the
        // resume that will find the orphan — knows what actually happened.
        // That knowledge travels as `StepError::Unrecorded` rather than being
        // flattened into `Store`, because a consumer deciding what the failure
        // permits (an effect group's cheap abort claims *taken back whole*)
        // branches on whether the call reached the world.
        let began = stopwatch();
        let performed = effect.perform().await;
        let elapsed_ms = Some(u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX));
        match performed {
            Ok(output) => {
                let unrecorded = |key, detail: String| StepError::Unrecorded {
                    key,
                    disposition: crate::core::Disposition::Landed,
                    detail,
                };
                let json = match serde_json::to_value(&output) {
                    Ok(json) => json,
                    Err(e) => return Err(unrecorded(key, e.to_string())),
                };
                let spend = effect.spend(&output);
                self.bill_live(spend);
                let content = self.source_verdict(&effect.descriptor().kind, &json);
                if let Err(e) = self
                    .append_effect(
                        key,
                        RecordKind::EffectDone {
                            output: json,
                            // Not an inbound event: only an awaited delivery has
                            // a sender to record, and only an operator-minted
                            // one has somebody to name.
                            source: None,
                            by: None,
                            spend,
                            declared: crate::core::DeclaredOutput::of(effect),
                            content: content.clone(),
                            elapsed_ms,
                        },
                    )
                    .await
                {
                    return Err(unrecorded(key, e.to_string()));
                }
                // The effect happened and its output is on the record; a
                // refusal keeps it from the step, not from the journal.
                self.arrival_refusal(content.as_ref())?;
                self.source_raise = content.and_then(|c| c.sensitivity);
                Ok(Ok(output))
            }
            Err(e) => {
                // A failed call still occupied a call, which is what lets
                // `max_effects` bound an effect that never succeeds — and it may
                // also have spent real money before dying. A stream cut off
                // after five hundred tokens is billed for five hundred tokens.
                let spend = e.spend();
                self.bill_live(spend);
                // The disposition is recorded alongside the message because it
                // is what every later decision reads — the retry taken now, and
                // an operator's judgement afterwards. Messages get reworded;
                // this is a fact about the run.
                if let Err(append_failed) = self
                    .append_effect(
                        key,
                        RecordKind::EffectFailed {
                            error: e.to_string(),
                            spend,
                            disposition: e.disposition(),
                            // An answer, not a fault — recorded so the replayed
                            // retry decision stops where the live one did.
                            permanent: permanent_failure(effect, &e),
                            elapsed_ms,
                        },
                    )
                    .await
                {
                    return Err(StepError::Unrecorded {
                        key,
                        disposition: e.disposition(),
                        detail: format!("{e}; and recording that failure failed: {append_failed}"),
                    });
                }
                Ok(Err(e))
            }
        }
    }

    async fn append_effect(&mut self, key: EffectKey, kind: RecordKind) -> Result<(), StepError> {
        self.store
            .append(self.epoch, vec![self.stamp(kind).effect(key)])
            .await?;
        self.wrote = true;
        Ok(())
    }

    pub(crate) async fn append(&mut self, kind: RecordKind) -> Result<(), StepError> {
        if !self.writes_enabled() {
            return Ok(());
        }
        self.store
            .append(self.epoch, vec![self.stamp(kind)])
            .await?;
        self.wrote = true;
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

/// The escalation declaration must describe something the store can do.
///
/// One implementation serving [`StepCtx::task`] and [`StepCtx::open_task`],
/// mirroring the manifest parser's rules for `spec.oversight` — the coded tier
/// and the declared tier must refuse the same shapes, or which tier an agent
/// was written in decides whether its oversight declaration is checked.
///
/// Roles beside a policy that never escalates cannot be written — they live
/// inside [`Expiry::Escalate`] — so two shapes are left to refuse:
///
/// * `Escalate` naming nobody — "widen the audience" with no audience to add
///   is a state flag wearing a control's name;
/// * `Escalate` over an empty `candidate_roles` — empty already means
///   *anyone*, and `Task::escalate` deliberately will not narrow it, so the
///   declared widening would do nothing.
fn escalation_names_its_audience(spec: &TaskSpec) -> Result<(), StepError> {
    let refuse = |detail: &str| Err(StepError::NotWired(detail.into()));
    if let Expiry::Escalate { to } = &spec.on_expiry {
        if to.is_empty() {
            return refuse(
                "Expiry::Escalate names no role: widening the audience is escalation's \
                 one enforceable meaning, so the declaration must say who is added — \
                 `Expiry::escalate_to([\"role\"])`",
            );
        }
        if spec.candidate_roles.is_empty() {
            return refuse(
                "Expiry::Escalate needs a bounded audience: an empty `candidate_roles` \
                 already means anyone, and there is no wider audience than that — \
                 name the initial reviewers with `role(..)`, or use `Deny`",
            );
        }
    }
    Ok(())
}

/// The first release mark that covers `path`, would confer trust, and names a
/// destination other than the sink at hand — the evidence for a refusal that
/// can say "released, but not for here".
///
/// Only the two destinations reach the message; the release's basis and
/// evidence stay in the journal, where an operator reads them and a probing
/// model cannot.
fn misdirected_release<'a>(
    args: &'a Tainted<Value>,
    sink_id: &str,
    path: &str,
) -> Option<&'a crate::core::ReleaseMark> {
    args.release_marks().iter().find(|mark| {
        mark.destination() != sink_id && mark.covers(path) && mark.scope().improves_trust()
    })
}

/// A refusal the recorded run met, as the error this one meets.
///
/// The verdict is history: a run refused by a ceiling or a rule was refused
/// then, whatever the ceiling or the rule says now. Re-deriving either would
/// re-judge last year's run under this year's configuration, which is the one
/// thing replay must never do.
/// The declared content rules' verdict on `value` at one boundary; empty
/// where none are declared. A declaration that does not compile refuses,
/// naming the block, rather than letting every value through.
#[cfg(feature = "manifest")]
pub(crate) fn judged(
    content: Option<&crate::content::Content>,
    at: crate::content::At<'_>,
    value: &Value,
) -> Result<crate::content::Outcome, PolicyError> {
    let Some(content) = content else {
        return Ok(crate::content::Outcome::default());
    };
    content
        .rules()
        .map(|rules| rules.at(at, value))
        .map_err(|_| PolicyError::Content {
            rule: "spec.security.content".to_owned(),
            pointer: String::new(),
        })
}

/// What the content rules decided, as a record carries it: `None` where no
/// rule matched. A declaration that does not compile refuses.
#[cfg(feature = "manifest")]
pub(crate) fn verdict(
    outcome: Result<crate::content::Outcome, PolicyError>,
) -> Option<crate::core::ContentVerdict> {
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(denial) => {
            let (rule, pointer) = match denial {
                PolicyError::Content { rule, pointer } => (rule, pointer),
                other => (other.to_string(), String::new()),
            };
            return Some(crate::core::ContentVerdict {
                rules: vec![rule.clone()],
                sensitivity: None,
                refused: Some(crate::core::ContentRefusal { rule, pointer }),
            });
        }
    };
    let mut rules: Vec<String> = outcome.refused.iter().map(|h| h.rule.clone()).collect();
    for id in &outcome.classified {
        if !rules.contains(id) {
            rules.push(id.clone());
        }
    }
    if rules.is_empty() {
        return None;
    }
    Some(crate::core::ContentVerdict {
        rules,
        sensitivity: outcome.sensitivity,
        refused: outcome
            .refused
            .first()
            .map(|h| crate::core::ContentRefusal {
                rule: h.rule.clone(),
                pointer: h.pointer.clone(),
            }),
    })
}

/// The effect kind of an awaited inbound event.
pub(crate) const AWAIT_KIND: &str = "event.await";

/// What a sink gate hands the dispatch: the label its verdict was reached
/// over, and the content rules it judged the value by.
#[derive(Clone, Copy)]
pub(crate) struct Outbound<'a> {
    pub(crate) label: &'a crate::core::Label,
    pub(crate) content_rules: &'a [String],
}

/// A case's blob store, readable and closed to writes: see [`StepCtx::blobs`].
#[derive(Debug)]
struct CaseBlobsReadOnly(Arc<dyn crate::blob::BlobStore>);

impl CaseBlobsReadOnly {
    fn refused() -> crate::blob::BlobError {
        crate::blob::BlobError::Backend(
            "this handle reads a case's blobs; write them with `StepCtx::store_blob`, which \
             records that the case produced them so erasing the case reaches them"
                .to_owned(),
        )
    }
}

#[async_trait::async_trait]
impl crate::blob::BlobStore for CaseBlobsReadOnly {
    fn tenant(&self) -> &str {
        self.0.tenant()
    }
    async fn put(&self, _bytes: &[u8]) -> Result<crate::core::Digest, crate::blob::BlobError> {
        Err(Self::refused())
    }
    async fn put_at(
        &self,
        _digest: crate::core::Digest,
        _bytes: &[u8],
    ) -> Result<(), crate::blob::BlobError> {
        Err(Self::refused())
    }
    async fn get_raw(
        &self,
        digest: crate::core::Digest,
    ) -> Result<Vec<u8>, crate::blob::BlobError> {
        self.0.get_raw(digest).await
    }
    async fn get(&self, digest: crate::core::Digest) -> Result<Vec<u8>, crate::blob::BlobError> {
        self.0.get(digest).await
    }
    async fn expire(
        &self,
        _digest: crate::core::Digest,
        _at: Timestamp,
        _reason: &str,
    ) -> Result<(), crate::blob::BlobError> {
        Err(Self::refused())
    }
    async fn has(&self, digest: crate::core::Digest) -> Result<bool, crate::blob::BlobError> {
        self.0.has(digest).await
    }
}

fn recorded_refusal(replay: EffectReplay) -> StepError {
    match replay {
        EffectReplay::Refused { limit, used } => {
            StepError::Budget(crate::core::BudgetExceeded::Recorded { limit, used })
        }
        // Which gate refused is recorded in `action`, and rebuilding the right
        // shape from it is what keeps a replay from ending a run the original
        // finished: a sink refusal is one call the model may route around, an
        // authorization denial is the run.
        EffectReplay::Denied { reason, action, .. }
            if action == crate::core::ACTION_EGRESS || action == crate::core::ACTION_CONTENT =>
        {
            StepError::Policy(PolicyError::Recorded { reason })
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
        EffectReplay::Withheld { subject, reason } => StepError::Withheld { subject, reason },
        // The callers match only these.
        other => StepError::Effect(crate::core::EffectError::Other(format!(
            "not a recorded refusal: {other:?}"
        ))),
    }
}

/// The instant an effect's call begins, for the `elapsed_ms` its outcome
/// record carries.
///
/// An observation, never an input: the figure is written beside the outcome,
/// read back by replay and by readers, and consulted by nothing a run decides.
#[allow(clippy::disallowed_methods)]
fn stopwatch() -> std::time::Instant {
    std::time::Instant::now()
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
///
/// Both halves — the seed layout and the generator — are a durable contract,
/// because replay recomputes the stream instead of reading it back.
/// `rng_stream_is_pinned` holds them to literal bytes.
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
            StepError::NotWired(
                "this run has no case: build the runtime with a case store and admit the run \
                 with correlation keys"
                    .into(),
            )
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
        // Attributed to the reading run's subjects: shared state is traced
        // through whoever reads it.
        let state = Tainted::with_label(snapshot.state, label).attributed(&self.subjects);
        Ok((state, snapshot.version))
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
    /// # Which authority, and whose
    ///
    /// The id is a labelled value, and an untrusted one is refused: which
    /// mandate to spend is an authority-bearing choice, and one a model or a
    /// peer made is a choice this run did not. The authority must also be held
    /// by the principal this run acts for — its chain's owner, or its tenant
    /// for a run the plane started with no chain, and nobody for a served
    /// caller that presented none ([`holder_of`](crate::authority::holder_of))
    /// — so knowing an id is not enough to spend it.
    ///
    /// # Errors
    ///
    /// [`StepError::Store`] when no authority store is wired, a policy refusal
    /// for an untrusted id, and the effect's own error carrying whichever
    /// refusal applies — unknown, not this run's holder, exhausted, out of
    /// draws, revoked, or expired.
    pub async fn draw(
        &mut self,
        id: &Tainted<crate::authority::AuthorityId>,
        amount: crate::core::Spend,
    ) -> Result<crate::authority::Drawn, StepError> {
        if id.label().is_untrusted() {
            return Err(PolicyError::ProtectedFieldTaint {
                sink: "authority.draw".to_owned(),
                path: "/authority".to_owned(),
            }
            .into());
        }
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
                id: id.peek().clone(),
                holder: crate::authority::holder_of(
                    self.identity.as_ref(),
                    self.served_unchained().await?,
                ),
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

        // The cutoff is never earlier than now: a caller-chosen past instant
        // would read memories whose retention has already lapsed.
        let now = self.now().await?;
        query.as_of = Some(query.as_of.map_or(now, |cutoff| cutoff.max(now)));
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
                at: now,
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
                return Err(StepError::Unreproducible {
                    what: format!("memory '{}' version {}", pick.id, pick.version),
                    detail: crate::memory::MemoryError::Rewritten {
                        id: pick.id,
                        version: pick.version,
                    }
                    .to_string(),
                });
            }

            let label = item.label();
            out.push(Tainted::with_label(item, label));
        }
        Ok(out)
    }

    /// Turn text into a vector, on the record, through the plane's embedder.
    ///
    /// Going through here rather than calling an embedding client directly is
    /// what makes semantic retrieval replayable at all: the query vector is in
    /// the retrieval effect's key, and an embedding service is under no
    /// obligation to return the same floats twice. Journaled, so a strict replay
    /// reads the vector back instead of asking again — and so the call is
    /// metered and the revision that produced it is on the record beside the
    /// numbers.
    ///
    /// The embedder is the one [`RuntimeBuilder::semantic_memory`] wired, which
    /// is what makes [`Embedding::revision`] a fact rather than a claim.
    ///
    /// The text carries its own label, and the returned vector carries it too: a
    /// vector derived from an untrusted document is untrusted, and sending
    /// confidential text to an embedding service is an egress like any other.
    ///
    /// `max_sensitivity` is that egress decision, and it is a parameter because
    /// there is no answer this crate could pick for every deployment. Note what
    /// it has to admit for the call to be useful at all: a query worth embedding
    /// has almost always crossed a trust boundary — a user's question, a model's
    /// paraphrase, a recalled memory — and anything that has is already
    /// [`Internal`].
    ///
    /// [`Internal`]: crate::core::Sensitivity::Internal
    /// [`Embedding::revision`]: crate::memory::Embedding::revision
    /// [`RuntimeBuilder::semantic_memory`]: crate::runtime::RuntimeBuilder::semantic_memory
    ///
    /// # Errors
    ///
    /// [`StepError`] if this plane wired no semantic memory, or whatever the
    /// effect protocol reports — a refused sink, an exhausted budget, or the
    /// embedder's own failure.
    pub async fn embed(
        &mut self,
        text: Tainted<String>,
        max_sensitivity: crate::core::Sensitivity,
    ) -> Result<Tainted<crate::memory::Embedding>, StepError> {
        let embedder = Arc::clone(&self.semantic_index()?.embedder);
        let plain = text.peek().clone();
        let arguments = text.map(serde_json::Value::String);
        self.sink_with(&arguments, |value| crate::runtime::effects::Embed {
            embedder,
            text: plain,
            arguments: value,
            max_sensitivity,
        })
        .await
    }

    fn semantic_index(&self) -> Result<&Arc<crate::runtime::SemanticMemory>, StepError> {
        self.semantic.as_ref().ok_or_else(|| {
            StepError::Store(crate::core::StoreError::Backend(
                "this plane wired no semantic memory; \
                 `Runtime::builder(..).semantic_memory(embedder, retriever)` is what \
                 gives an agent an index to search"
                    .to_owned(),
            ))
        })
    }

    /// Rank governed memories by meaning, through the plane's semantic index.
    ///
    /// Two journaled effects: the text is embedded, then the vector is ranked.
    /// The retriever returns only immutable `(id, version, digest)` commitments
    /// and scores, and the selection is recorded already screened — a hit
    /// naming a superseded, expired, or erased version leaves it, for the
    /// reasons on [`SemanticRecall`](crate::runtime::effects::SemanticRecall).
    /// Live execution and replay then both materialise the surviving versions
    /// and re-check scope and digest before any content is exposed, so an
    /// index that *contradicts* durable truth — rather than merely trailing
    /// it — is a refusal, never a plausible answer.
    ///
    /// The [`SemanticSearch`] states the question; the space it is asked in
    /// comes from the wired embedder and index, which `build` already held to
    /// each other ([`IndexIdentity`]).
    ///
    /// # The selected set is untrusted-influenced, whatever the items say
    ///
    /// Similarity is computed over item content, so anything able to write a
    /// memory is a ranking signal: an attacker who cannot taint a value can
    /// still choose *which* clean values a model is shown, and no label shows
    /// it. Every item still arrives labelled from its own provenance — but a
    /// caller needing a selection nobody can steer wants
    /// [`recall`](Self::recall), whose order is a fixed rule no stored item can
    /// move.
    ///
    /// [`MemoryStore`]: crate::memory::MemoryStore
    /// [`SemanticSearch`]: crate::memory::SemanticSearch
    /// [`IndexIdentity`]: crate::memory::IndexIdentity
    ///
    /// # Errors
    ///
    /// [`StepError`] if this plane wired no semantic memory or no memory store,
    /// if either effect fails, or if the index returned a commitment the
    /// authoritative store cannot honour.
    pub async fn semantic_recall(
        &mut self,
        search: crate::memory::SemanticSearch,
        text: Tainted<String>,
    ) -> Result<Vec<(Tainted<crate::memory::MemoryItem>, f32)>, StepError> {
        let memories = self.memories.clone().ok_or_else(|| {
            StepError::Store(crate::core::StoreError::Backend(
                "no memory store is configured; semantic retrieval needs authoritative memory"
                    .to_owned(),
            ))
        })?;
        let retriever = Arc::clone(&self.semantic_index()?.retriever);
        let as_of = self.now().await?;
        let written = text.peek().clone();
        let label = text.label().clone();
        let embedding = self.embed(text, search.max_sensitivity).await?;
        let label = label.join(embedding.label());
        let query = crate::memory::SemanticQuery {
            subject: search.subject.clone(),
            purpose: search.purpose.clone(),
            text: written,
            index: crate::memory::IndexIdentity {
                snapshot: retriever.index().snapshot,
                query_revision: embedding.peek().revision.clone(),
            },
            embedding: embedding.into_unlabelled().vector,
            limit: search.limit,
            max_sensitivity: search.max_sensitivity,
            as_of,
        };
        let searched = query.clone();
        let screen = Arc::clone(&memories);
        let arguments = Tainted::with_label(
            serde_json::to_value(&query).expect("SemanticQuery serialization is infallible"),
            label,
        );
        let hits = self
            .sink_with(&arguments, |value| {
                crate::runtime::effects::SemanticRecall {
                    retriever,
                    memories: screen,
                    query: searched,
                    arguments: value,
                }
            })
            .await?
            .into_unlabelled();
        // The retriever's misconduct refusals — an answer past the declared
        // limit, a non-finite score — live in the effect's `perform`, before
        // the selection is journaled: a record is written once, and one that
        // held either could not honestly be read back. What runs here is what
        // must hold on **replay too**: the journaled selection materialises
        // against durable truth, digest and scope re-checked.
        let mut out = Vec::with_capacity(hits.len());
        for hit in hits {
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
            // Two failures, two systems to go look in. A digest that moved is
            // the authoritative store contradicting itself; a hit outside the
            // query's scope is the retriever misbehaving while durable truth is
            // intact.
            if item.selection_digest() != hit.selected.digest {
                return Err(StepError::Unreproducible {
                    what: format!(
                        "memory '{}' version {}",
                        hit.selected.id, hit.selected.version
                    ),
                    detail: crate::memory::MemoryError::Rewritten {
                        id: hit.selected.id,
                        version: hit.selected.version,
                    }
                    .to_string(),
                });
            }
            if item.subject != query.subject
                || query
                    .purpose
                    .as_ref()
                    .is_some_and(|purpose| purpose != &item.purpose)
            {
                return Err(StepError::Store(crate::core::StoreError::Backend(format!(
                    "semantic retriever returned memory '{}', which is outside the \
                     scope the query asked for",
                    hit.selected.id
                ))));
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
        let stream = self.model_stream();
        // The prompt is **built here**, from the sources, rather than accepted
        // from the caller. The sink binds an effect's outbound arguments to the
        // labelled value it checks, and a caller passing a pre-built call would
        // have to reproduce this assembly exactly to satisfy that binding — an
        // obligation nobody would meet twice.
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

        let max_sensitivity = into.max_sensitivity;
        let completion = self
            .sink_with(&prompt, |value| {
                crate::model::ModelCall::new(provider, model, value)
                    .observed_by(stream.clone())
                    .with_max_sensitivity(max_sensitivity)
            })
            .await?;
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
            // Sensitivity is doubled the same way, and the claim that it was
            // not is what let its mutation look verified: the prompt is built
            // from these very sources, so the completion's own label already
            // carries their joined sensitivity, and deleting this line changed
            // no outcome any test could see. It stays for the same future the
            // trust half is kept for — a summariser whose output label does
            // not inherit its input's sensitivity — and the mutation that
            // proves the guarantee now targets the assignment below, which is
            // the one place the written summary's sensitivity is decided.
            //
            // Provenance is the exception that is genuinely undoubled: nothing
            // else unions the sources' provenance into the summary.
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
    ///
    /// # It takes the whole role, not a model id
    ///
    /// Formation is untrusted contact — the source material derives from
    /// whatever the run handled — so a manifest that declares a quarantined
    /// role declares `max_tokens` and `reasoning_effort` beside the model for
    /// exactly this call. Taking the id alone was how those two ceilings got
    /// parsed into the digest and then dropped at this seam: a declared
    /// control the runtime silently did not apply. The role's ceilings now
    /// ride the formation call itself.
    pub async fn form_memories(
        &mut self,
        formation: crate::memory::Formation,
        source: Tainted<Value>,
        provider: Arc<dyn crate::model::ModelProvider>,
        role: crate::model::ModelRole,
    ) -> Result<Vec<(String, u64)>, StepError> {
        let stream = self.model_stream();
        let source_label = source.label().clone();
        let prompt = Tainted::object([
            (
                "system".to_owned(),
                Tainted::trusted(serde_json::Value::String(formation.instruction.clone())),
            ),
            ("source".to_owned(), source),
        ]);
        let schema = formation_schema(formation.max_items);
        let completion = self
            .sink_with(&prompt, |value| {
                role.applied_to(
                    crate::model::ModelCall::new(provider, role.model.clone(), value)
                        .observed_by(stream.clone())
                        .with_max_sensitivity(formation.max_sensitivity)
                        .with_output_sensitivity(source_label.sensitivity)
                        .expecting(schema),
                )
            })
            .await?;
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
        // The declared bound, enforced by the runtime rather than by the
        // schema alone: `maxItems` above holds only where the `jsonschema`
        // validator is in the build, and a declared ceiling that depends on a
        // feature flag is a control that yields where nobody is looking. The
        // truncation is silent toward the model on purpose — an over-long
        // answer is not worth failing a run that has already paid for it, and
        // which proposals survive is the declaration's order, first wins.
        let mut written = Vec::with_capacity(proposals.len().min(formation.max_items));
        let mut seen = std::collections::BTreeSet::new();
        for proposal in proposals {
            if written.len() == formation.max_items {
                break;
            }
            let key = proposal["key"]
                .as_str()
                .ok_or_else(|| unusable("a proposal carries no string `key`"))?;
            // The same first-wins rule the ceiling applies. A key proposed
            // twice in one answer would otherwise write two versions back to
            // back, with the *later* proposal silently superseding the one the
            // declaration's order preferred — and a duplicate is not a
            // distinct fact, so it does not spend a `max_items` slot either.
            if !seen.insert(key.to_owned()) {
                continue;
            }
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

    /// The blob store `fetcher` files its bytes in.
    ///
    /// [`blobs`](Self::blobs) for case-linked retention; the policy's own
    /// erasure unit for a named external one, whose bytes a case-scoped handle
    /// cannot address. Hand this to
    /// [`ModelCall::with_media`](crate::model::ModelCall::with_media) to
    /// materialize what [`fetch_media`](Self::fetch_media) stored.
    ///
    /// # Errors
    ///
    /// As [`blobs`](Self::blobs).
    #[cfg(feature = "media")]
    pub fn media_blobs(
        &self,
        fetcher: &crate::media::GovernedMedia,
    ) -> Result<Arc<dyn crate::blob::BlobStore>, StepError> {
        self.blobs_scoped(fetcher.external_scope().as_deref())
    }

    /// The blob store for this run, sealed to its case.
    ///
    /// **Use this rather than a store held from the builder.** With a key ring
    /// configured, it reads through the case's data key — the envelope
    /// [`store_blob`](Self::store_blob) sealed the bytes in — where a store
    /// obtained any other way sees only ciphertext. It is also what a skill
    /// passes to [`ModelCall::with_media`](crate::model::ModelCall::with_media),
    /// so materialization reads through the same envelope.
    ///
    /// **Read-only for a run bound to a case**: bytes a case produces are
    /// written with [`store_blob`](Self::store_blob), which records that the
    /// case produced them, so erasing the case reaches them. A write through
    /// this handle would land in the case's address space with no record, and
    /// an erasure would report success over bytes it never touched.
    ///
    /// # Errors
    ///
    /// If no blob store is configured, or the run belongs to no case while a
    /// key ring is — there would be no erasure unit to scope the key to, and
    /// falling back to storing in the clear would silently drop the guarantee.
    pub fn blobs(&self) -> Result<Arc<dyn crate::blob::BlobStore>, StepError> {
        let blobs = self.blobs_scoped(None)?;
        Ok(if self.case.is_some() {
            Arc::new(CaseBlobsReadOnly(blobs))
        } else {
            blobs
        })
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

        // The tenant prefixes every scope. Without it two tenants sharing a
        // key ring or a bucket collide the moment they use the same case or
        // retention name — and the collision is invisible until one tenant's
        // erasure destroys the other's key. `TenantId` refuses `/` for exactly
        // this reason, so the prefix cannot be forged by naming a tenant
        // `acme/prod`.
        let unit = match scope {
            Some(s) => Some(s.to_owned()),
            None => self.case.as_ref().map(|c| c.case_id.to_string()),
        };

        // The erasure unit leads the storage address, sealed or not — the
        // same bytes in two units are two objects, so one unit's erasure
        // reaches only its own copies. `blob::ScopedBlobs` carries the
        // argument.
        let scoped = |u: &str| -> Arc<dyn crate::blob::BlobStore> {
            Arc::new(crate::blob::ScopedBlobs::new(
                blobs.clone(),
                crate::core::erasure_scope(&self.tenant, u),
            ))
        };

        #[cfg(feature = "keyring")]
        if let Some(keys) = self.keyring.clone() {
            let unit = unit.ok_or_else(|| {
                StepError::Store(crate::core::StoreError::Backend(
                    "a key ring is configured but this run belongs to no case and no \
                     other erasure unit was named, so there is nothing to scope its data \
                     key to. Bind the run to a case, name an external retention policy, \
                     or drop the key ring — storing these bytes in the clear would leave \
                     an erasure that silently does not reach them"
                        .to_owned(),
                ))
            })?;
            let scope = crate::core::erasure_scope(&self.tenant, &unit);
            return Ok(Arc::new(crate::keyring::EncryptedBlobs::new(
                scoped(&unit),
                keys,
                scope,
            )));
        }
        // Unsealed: address by unit when the run has one. A caseless run with
        // no named scope keeps the bare handle — it links no blobs through the
        // case layer, so there is no erasure unit for an address to belong to.
        Ok(match unit {
            Some(u) => scoped(&u),
            None => blobs,
        })
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
            Some(self.blobs_scoped(None)?)
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
        // An erased address refuses as itself rather than as a backend string:
        // a run re-producing bytes an operator had removed is a rule this
        // runtime enforces, not a store that is having a bad day.
        let stored = blobs
            .put(bytes)
            .await
            .map_err(|e| StepError::Store(crate::blob::refusal(e)))?;
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
    /// Under case-linked retention the digest is linked to the run's case
    /// before blob storage, so [`erase_case`](crate::blob::erase_case) can
    /// enforce retention even across crashes. Strict replay consumes the same
    /// clock record but never rewrites that link. Under a named external
    /// retention policy the bytes belong to that policy's erasure unit, not the
    /// case, so nothing is linked and a case erasure does not reach them; read
    /// them back through [`media_blobs`](Self::media_blobs).
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
        let blobs = self.blobs_scoped(fetcher.external_scope().as_deref())?;
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
    /// Two reasons, and the first is the one that bites. `time::Duration` is
    /// **signed**, so a negative warning offset would parse, compile, and put
    /// `warn_at` *after* the instant it warns about: a warning that can only
    /// fire once the obligation is already breached. A quantity that only makes
    /// sense non-negative is an unsigned type here, as it is for
    /// [`Spend`](crate::core::Spend).
    ///
    /// And it is the `Duration` a caller already has.
    /// [`sleep`](Self::sleep) takes the standard one, so the alternative is a
    /// public surface with two types spelled `Duration`, only one of which
    /// comes from a crate this
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

        let mut deadline = Deadline {
            case: cx.case_id,
            name: name.clone(),
            resolved_at: resolved.at,
            calendar_digest: resolved.calendar_digest,
            warn_at: warn_before
                .and_then(|d| time::Duration::try_from(d).ok())
                .and_then(|d| resolved.at.checked_sub(d)),
            state: DeadlineState::Pending,
            acknowledged: None,
        };

        // Idempotent by primary key, so a resumed run re-registering the same
        // obligation is a no-op rather than a duplicate — and on Resume that
        // re-registration is deliberate even for a replayed effect, because it
        // is what heals a crash between the resolution record and the case
        // store's row. Strict never writes it, matching `store_blob`: a
        // verification pass is a pure read, and one that re-registered
        // obligations would mutate the case layer every time someone ran a
        // regression check — including re-arming a deadline an operator had
        // since cancelled.
        if self.mode != Mode::Strict {
            match cx.cases.register_deadline(&deadline).await {
                Ok(()) => {}
                // Another run on this matter registered the name first. The
                // obligation is the matter's, so this run shares it on the
                // terms it was registered with, and journals those.
                Err(crate::core::StoreError::DeadlineExists { .. }) => {
                    if let Some(standing) = cx
                        .cases
                        .deadlines(cx.case_id)
                        .await?
                        .into_iter()
                        .find(|d| d.name == deadline.name)
                    {
                        deadline = standing;
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }

        self.append(RecordKind::DeadlineRegistered {
            name,
            resolved_at: deadline.resolved_at,
            calendar_digest: deadline.calendar_digest,
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

/// What a forming model may answer with.
///
/// A free function so a test can hold it to the rule the drivers apply: an
/// untyped subschema is valid JSON Schema and is refused by constrained
/// decoding, so a schema built inline here is one nothing checks.
fn formation_schema(max_items: usize) -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "memories": {
                "type": "array",
                "maxItems": max_items,
                "items": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string", "minLength": 1},
                        // A memory is a durable fact stated plainly, so the
                        // permissive spelling was never buying what it cost.
                        "content": {"type": "string"}
                    },
                    "required": ["key", "content"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["memories"],
        "additionalProperties": false
    })
}

/// Hold a task's answer to the one door that may give it.
///
/// Every external intake refuses the kind a task waits on, so this is the
/// second of two locks rather than the only one: an answer that reached the run
/// from anywhere but the worklist — an embedder's store, a door added later
/// that forgot the refusal — is not a decision, and neither is one whose
/// decider is not the operator it was delivered under. Checked on replay as
/// live, from the same record, so a run cannot pass it once and fail it later.
fn answered_by_the_worklist(answer: &Arrival, decision: &Decision) -> Result<(), StepError> {
    let from_worklist = answer.source.as_deref() == Some(super::sweeper::SOURCE_WORKLIST);
    if !from_worklist || decision.decided.operator() != answer.by.as_ref() {
        return Err(StepError::Effect(crate::core::EffectError::Other(format!(
            "a task's answer arrived from {} for decider '{}' — only this plane's worklist \
             decides a task, under the operator who decided it",
            answer.source.as_deref().unwrap_or("no sender"),
            decision.decided,
        ))));
    }
    Ok(())
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
        // A wait may carry no correlation key: **targeted** delivery
        // (`Runtime::deliver_to`, which is how A2A task input arrives) finds
        // the subscription by run id and needs none. What such a wait cannot
        // be woken by is *broadcast* delivery — `POST /events` matches by
        // key — so a run waiting on an event from a bus must `.correlate(...)`
        // with the business key the event will carry, or, for a CloudEvent,
        // with `("subject", <id>)`.
        let correlation = spec.correlation.clone();
        self.wait_on(
            &spec.kind,
            move |_| correlation,
            spec.from.clone(),
            &spec.deadline,
            |_| async { Ok(()) },
        )
        .await
        .map(|arrival| arrival.value)
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
            StepError::NotWired(
                "human tasks need a task store — build the runtime with `.tasks(store)`".into(),
            )
        })?;

        escalation_names_its_audience(spec)?;

        let due_at = self.deadline_instant(&cx, &spec.deadline).await?;
        // The run's journaled clock, not the obligation's instant.
        //
        // Were `created_at` the deadline, both fields would say *when this is
        // due*: a worklist would show every row as created in the future and
        // "oldest first" would silently mean "soonest due".
        let created_at = self.now().await?;
        let run = self.run;
        let case_id = cx.case_id;
        let spec = self.four_eyes(spec).await?;
        let spec_digest = spec.justification.digest();
        let answer = self
            .wait_on(
                TASK_DECIDED,
                |key| {
                    vec![CorrelationKey::new(
                        "task",
                        TaskId::derive(run, key).to_hex(),
                    )]
                },
                None,
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
                                escalate_to: spec.on_expiry.escalate_roles().to_vec(),
                                excluded_actors: spec.excluded_actors.clone(),
                                assignee: None,
                                priority: spec.priority,
                                state: TaskState::Open,
                                on_expiry: spec.on_expiry.policy(),
                                created_at,
                                due_at: Some(due_at),
                                withheld: None,
                            })
                            .await?;
                        Ok(())
                    }
                },
            )
            .await?;

        // A decision is a human's assertion, not a fact the engine verified.
        let decision: Decision = serde_json::from_value(answer.value.peek().clone())?;
        answered_by_the_worklist(&answer, &decision)?;
        // A person's approval holds only for the task this run proposed. The
        // digest is what the store held when they decided; any other value —
        // or none — is an approval of something else, and acting on it would
        // dispatch arguments nobody reviewed.
        if decision.approved
            && decision.decided.operator().is_some()
            && decision.reviewed != Some(spec_digest)
        {
            return Err(StepError::Effect(crate::core::EffectError::Refused(
                "the approval does not name the task this run proposed — the task was \
                 changed between proposal and decision, so what was approved is not \
                 what would be dispatched"
                    .into(),
            )));
        }
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
            StepError::NotWired(
                "human tasks need a task store — build the runtime with `.tasks(store)`".into(),
            )
        })?;
        // A notification is not a decision, so `Expiry::ProceedUnattended` has nothing
        // to proceed *past* and the unattended consent it demands would be
        // consent to nothing. Refused rather than accepted-and-ignored.
        if spec.on_expiry == Expiry::ProceedUnattended {
            return Err(StepError::NotWired(
                "a task opened beside an answer has no decision to wait for, so \
                 `Expiry::ProceedUnattended` describes nothing — the run has already proceeded. \
                 Use `Deny` to let the window close, or `Escalate` to widen the audience"
                    .into(),
            ));
        }
        escalation_names_its_audience(spec)?;
        let due_at = self.deadline_instant(&cx, &spec.deadline).await?;
        let at = self.now().await?;
        let run = self.run;
        let spec = self.four_eyes(spec).await?;
        Ok(self
            .effect(crate::runtime::effects::OpenTask {
                tasks,
                run,
                case: cx.case_id,
                spec,
                at,
                due_at,
                key: None,
            })
            .await?
            .into_unlabelled())
    }

    /// Who asked for this run, when admission named them.
    ///
    /// Read from the run's `RunAdmitted` record, which is immutable — so a
    /// replay reads what the live run read. `None` when nobody was named.
    ///
    /// # Errors
    ///
    /// [`StepError::Store`] if the journal cannot be read.
    pub async fn initiator(&self) -> Result<Option<String>, StepError> {
        let first = self.store.read_page(self.run, 1, 1).await?;
        Ok(first.into_iter().find_map(|record| match record.kind() {
            RecordKind::RunAdmitted { admitted_by, .. } => admitted_by.clone(),
            _ => None,
        }))
    }

    /// Whether this run was admitted for a served caller that presented no
    /// chain — read from the journal, so a replay draws as the holder the
    /// live run did.
    async fn served_unchained(&self) -> Result<bool, StepError> {
        let first = self.store.read_page(self.run, 1, 1).await?;
        Ok(first.into_iter().any(|record| {
            matches!(
                record.kind(),
                RecordKind::RunAdmitted {
                    served_unchained: true,
                    ..
                }
            )
        }))
    }

    /// Whether this run was admitted as the plane, under its own chain.
    async fn plane_chain(&self) -> Result<bool, StepError> {
        let first = self.store.read_page(self.run, 1, 1).await?;
        Ok(first.into_iter().any(|record| {
            matches!(
                record.kind(),
                RecordKind::RunAdmitted {
                    plane_chain: true,
                    ..
                }
            )
        }))
    }

    /// `spec`, with every party the run acts for barred from deciding it.
    ///
    /// Applied to every task a run opens, coded or declarative: the parties
    /// whose request produced the action are the reviewers four-eyes exists
    /// to exclude, and a declarative agent has no code in which to say so.
    /// They are the admitting caller, and — when the run acts under a
    /// caller's chain — the person at its root and the workload acting for
    /// them: a served caller admits as a peer service, so the admitter alone
    /// is not who asked. A run under the plane's own chain was asked for by
    /// the embedder, not by the plane's principals, so they may still decide.
    async fn four_eyes(&self, spec: &TaskSpec) -> Result<TaskSpec, StepError> {
        let mut spec = spec.clone();
        let chain = match &self.identity {
            Some(c) if !self.plane_chain().await? => {
                Some([c.owner().id.clone(), c.subject().id.clone()])
            }
            _ => None,
        };
        let parties = self
            .initiator()
            .await?
            .into_iter()
            .chain(chain.into_iter().flatten());
        for party in parties {
            if !spec.excluded_actors.contains(&party) {
                spec.excluded_actors.push(party);
            }
        }
        Ok(spec)
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
        from: Option<String>,
        deadline: &str,
        before_suspend: F,
    ) -> Result<Arrival, StepError>
    where
        C: FnOnce(EffectKey) -> Vec<CorrelationKey> + Send,
        F: FnOnce(EffectKey) -> Fut + Send,
        Fut: std::future::Future<Output = Result<(), StepError>> + Send,
    {
        // Correlation is computed from the key rather than passed in, because a
        // human task's correlation key *is* its id, and that id is derived from
        // the key. Taking a closure resolves the circularity without a second
        // identifier that could drift from the first.
        let key_preview = self.preview_key(kind);
        let spec = &AwaitSpec {
            kind: kind.to_owned(),
            correlation: correlate(key_preview),
            deadline: deadline.to_owned(),
            from,
        };
        let cx = self.case_ctx()?.clone();
        let events = cx.events.clone().ok_or_else(|| {
            StepError::NotWired(
                "durable waits need an event store — build the runtime with `.events(store)`"
                    .into(),
            )
        })?;

        // The wait is an effect: its output is the event. That means replay
        // reads the event back like any other recorded result, and none of the
        // suspension machinery has to exist twice.
        let descriptor =
            EffectDescriptor::new(AWAIT_KIND, serde_json::json!({ "kind": spec.kind }));
        let key = self.preview_key(kind);
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
        // `repair` re-enters the registration below with the announcement
        // skipped: the wait was announced and its registration may not have
        // survived the crash that followed.
        let mut repair = false;
        if self.mode.is_replaying() {
            match self.replayed_wait(key, &descriptor, spec, &cx).await? {
                Some(ReplayedWait::Recorded(recorded)) => return Ok(*recorded),
                Some(ReplayedWait::Repair) => repair = true,
                None => {}
            }
        }

        let subscription = Subscription {
            run: self.run,
            case: Some(cx.case_id),
            effect: key,
            step: self.step,
            phase: self.phase,
            kind: spec.kind.clone(),
            correlation: spec.correlation.clone(),
            from: spec.from.clone(),
        };

        // NOTE: deliberately not `self.now()`. That is itself an effect, and
        // taking it here would give the clock a later ordinal but an earlier
        // journal position — replay verifies journal order, so the two must
        // agree. The subscription's timestamp is store metadata anyway, like a
        // lease: it never enters the journal and cannot affect replay.
        let now = subscription_clock();

        // Announce the wait before releasing the frame, so an event arriving in
        // the same instant finds a durable subscription rather than a gap. On
        // a repair pass the announcement is the one record that provably
        // survived — writing it again would report one wait as two.
        if !repair {
            // Its slot, for the same reason a timer takes one: ungated because
            // refusing a wait strands a run, counted because the journal holds
            // the announcement and every replay of it bills one. A repair pass
            // already billed it off the orphan record.
            self.count_unadmitted(0);
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
                    outbound_bytes: None,
                    content_rules: None,
                    credential: None,
                },
            )
            .await?;
        }
        events.subscribe(&subscription, now).await?;

        // Whatever must exist for a decision to attach to — a task row, say —
        // is created here: after the subscription is durable, before the buffer
        // is consulted. An answer arriving in this window finds both.
        before_suspend(key).await?;

        // Look in the buffer: the event may already be here. The journal
        // write comes **before** the unsubscribe, because unsubscribing sheds
        // the claimed row's payload — the journal holds the delivered copy
        // from then on — and the reverse order leaves a crash window in which
        // the payload exists nowhere: claimed and stripped in the buffer,
        // never journaled. The delivery worker orders these two the same way.
        if let Some(buffered) = events.claim_for(&subscription, now).await? {
            let content = self.source_verdict(AWAIT_KIND, &buffered.event.payload);
            self.append_effect(
                key,
                RecordKind::EffectDone {
                    output: buffered.event.payload.clone(),
                    source: Some(buffered.event.source.clone()),
                    by: buffered.event.by.clone(),
                    spend: crate::core::Spend::default(),
                    // What `label_inbound` builds, stated rather than derived:
                    // an inbound payload is another party's data, and the
                    // provenance half of its label comes from `source` beside
                    // this and the wait's own kind.
                    declared: crate::core::DeclaredOutput::untrusted(),
                    content: content.clone(),
                    elapsed_ms: None,
                },
            )
            .await?;
            events.unsubscribe(self.run, key).await?;
            self.arrival_refusal(content.as_ref())?;
            return Ok(Arrival {
                value: self.label_inbound(
                    buffered.event.payload,
                    &spec.kind,
                    Some(&buffered.event.source),
                    content.as_ref(),
                ),
                source: Some(buffered.event.source),
                by: buffered.event.by,
            });
        }

        Err(StepError::Suspended(self.suspend_reason(spec, &cx).await?))
    }

    /// The key this wait will be recorded under, computed without advancing the
    /// ordinal.
    ///
    /// Needed because a human task's correlation key is derived from its own
    /// effect key, so the key must be known before the subscription is built.
    fn preview_key(&self, kind: &str) -> EffectKey {
        // Attempt 1, always: a wait that times out suspends or dead-letters,
        // it never repeats, so there is no second attempt to distinguish.
        EffectKey::derive(
            self.step,
            self.phase,
            self.ordinal,
            1,
            AWAIT_KIND,
            &canon::value_bytes(&serde_json::json!({ "kind": kind })),
        )
    }

    /// An inbound message is external data by definition, and is labeled as
    /// such — including when it comes from a first-party system.
    ///
    /// Every input is journaled: the kind from the await's spec, the sender
    /// from the recorded arrival, and the run's data-subject references from
    /// its `DataSubjectBound` — so a replay labels exactly as the live run did.
    /// An event reaches a run only through that run's correlation, so it is
    /// attributed to the run's subjects.
    fn label_inbound(
        &self,
        payload: Value,
        kind: &str,
        source: Option<&str>,
        content: Option<&crate::core::ContentVerdict>,
    ) -> Tainted<Value> {
        let mut label =
            crate::core::Label::untrusted(crate::core::SourceId::new(format!("event:{kind}")));
        label.sensitivity = crate::core::ContentVerdict::raise(content, label.sensitivity);
        // Provenance accumulates, so the kind and the sender are both there: a
        // sink may allow an authority-bearing field from `event:ack` generally,
        // or from one counterparty in particular.
        if let Some(source) = source {
            label
                .provenance
                .insert(crate::core::SourceId::new(format!("sender:{source}")));
        }
        Tainted::with_label(payload, label).attributed(&self.subjects)
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
                StepError::NotWired(format!(
                    "wait references deadline '{name}', which is not registered on this case \
                     — register it before waiting, or the run has no horizon"
                ))
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

/// What a [`StepCtx::sink_with`] closure may hand back: the effect itself, or
/// a refusal to build one.
///
/// Two implementations and no third: an effect whose construction cannot fail
/// is returned bare, and one whose construction can — `ToolCall::prepare`,
/// which refuses a tool the catalogue does not hold — returns the `Result` it
/// already produces. Without this the infallible majority would write `Ok(..)`
/// at every call site to satisfy the fallible minority.
pub trait BuildsEffect<E: Effect> {
    /// The effect, or the error that stops the step instead.
    ///
    /// # Errors
    ///
    /// Whatever the construction refused with, converted to a [`StepError`].
    fn into_effect(self) -> Result<E, StepError>;
}

impl<E: Effect> BuildsEffect<E> for E {
    fn into_effect(self) -> Result<E, StepError> {
        Ok(self)
    }
}

impl<T: Effect, Er: Into<StepError>> BuildsEffect<T> for Result<T, Er> {
    fn into_effect(self) -> Result<T, StepError> {
        self.map_err(Into::into)
    }
}

/// Whether a failure is an answer no retry would change.
///
/// A refusal is one by definition. A landed failure is one where the effect
/// says its landed failures are not retried — a tool that ran and reported
/// failure, unless its operator declared otherwise. Recorded on the failure,
/// so a replay stops where the live run stopped.
fn permanent_failure<E: Effect + ?Sized>(effect: &E, failure: &crate::core::EffectError) -> bool {
    matches!(failure, crate::core::EffectError::Refused(_))
        || (failure.disposition() == crate::core::Disposition::Landed && !effect.retries_landed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng as _, RngExt as _};

    /// Memory formation has to be askable of a real provider.
    ///
    /// It was not: `"content": {}` is valid JSON Schema, and constrained
    /// decoding refuses an untyped subschema — so every run declaring
    /// `spec.memory.formation` failed at the forming call against `OpenAI`,
    /// while every test against `FakeProvider` passed.
    #[test]
    #[cfg(feature = "providers")]
    fn the_formation_schema_survives_constrained_decoding() {
        assert_eq!(
            crate::model::strict_schema_problem(&formation_schema(3)),
            None
        );
    }

    /// The entropy stream is a durable contract, and this is the only test that
    /// can tell when it breaks.
    ///
    /// The two tests below compare one build against itself, so they hold for
    /// *any* generator: they would pass unchanged the day a dependency swapped
    /// `ChaCha8` for something else, whereupon every run that had ever drawn a
    /// number re-derives different effect arguments and is quarantined as
    /// non-determinism — with nothing in the journal to name the cause.
    ///
    /// Literal words for a literal seed, therefore, for the reason the
    /// canonicalization goldens exist. If this fails after a dependency bump,
    /// the bump changed every replay in the world — that is the finding, not
    /// the vector.
    #[test]
    fn rng_stream_is_pinned() {
        let run = RunId(ulid::Ulid(0x018F_2A3B_4C5D_6E7F_8091_A2B3_C4D5_E6F7));
        let mut r = seeded_rng(run, StepId(7));
        let drawn: Vec<u64> = (0..4).map(|_| r.next_u64()).collect();
        assert_eq!(
            drawn,
            vec![
                0x5dc1_d7b7_0c89_cfc8,
                0xd538_d4d4_ce78_3876,
                0xe2d6_bb02_860a_b9c7,
                0x91e7_553e_9e7d_bdc3,
            ],
            "the ChaCha8 stream behind StepCtx::rng moved; every replay that \
             ever drew a number now diverges"
        );
    }

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
    /// The chain the sub-run is admitted under: this run's, plus one link.
    /// Not in the descriptor — the parent's `IdentityBound` already records
    /// it, and the sub-run's records its own.
    chain: Option<crate::core::Delegation>,
    /// Who asked for the commissioning run, carried to the sub-run so its
    /// tasks bar the same person. Not in the descriptor, for the reason the
    /// chain is not: both runs' `RunAdmitted` records it.
    initiator: Option<String>,
    /// Whether the commissioning run acts as the plane. Its sub-run does too,
    /// one link down, so the credential a peer is shown is still the plane's.
    plane_chain: bool,
    /// Whether the commissioning run acts for a served caller that presented
    /// no chain. Read from its `RunAdmitted`, and the one fact that tells a
    /// chainless served run from the plane's own chainless run.
    served_unchained: bool,
    /// The declaration an approval covered, when the consultation is pinned
    /// to it. Handed to the sub-run's admission, which refuses another
    /// revision before the sub-run exists. Not in the descriptor: the key is
    /// what was asked, and the sub-run's `RunAdmitted` records which revision
    /// answered.
    pin: Option<crate::core::Digest>,
}

/// Reading what a consulted agent's declaration permits.
#[cfg(feature = "manifest")]
#[derive(Debug)]
struct ReachRead {
    capability: String,
    plane: std::sync::Weak<super::Runtime>,
}

#[cfg(feature = "manifest")]
#[async_trait::async_trait]
impl Effect for ReachRead {
    type Output = Option<crate::core::Reach>;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "agent.reach",
            serde_json::json!({ "capability": self.capability }),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn recovery(&self) -> crate::core::Recovery {
        crate::core::Recovery::Retry
    }

    async fn perform(&self) -> Result<Self::Output, crate::core::EffectError> {
        let plane = self
            .plane
            .upgrade()
            .ok_or_else(|| crate::core::EffectError::Other("the plane is gone".into()))?;
        Ok(plane.reach_of(&self.capability))
    }
}

/// The plane's stream observer, bound to one run.
#[derive(Debug)]
struct RunBound {
    run: RunId,
    inner: Arc<dyn super::RunStreamObserver>,
}

impl crate::model::ModelStreamObserver for RunBound {
    fn event(&self, event: Tainted<crate::model::ModelStreamEvent>) {
        self.inner.event(self.run, event);
    }
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
    /// Absent in a record that does not carry it, which reads back as the
    /// floor an untrusted effect output already carries, rather than a guess
    /// that could raise a ceiling.
    #[serde(default = "internal_floor")]
    sensitivity: crate::core::Sensitivity,
    /// The data-subject references the sub-run's answer carried: its own
    /// bindings and whatever of this run's it was handed. Journaled for the
    /// reason `sensitivity` is, so a replay attributes the answer as the live
    /// run did, and a subject the specialist bound is traced past the
    /// delegation boundary.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    data_subjects: BTreeSet<crate::core::SubjectRef>,
    /// The sub-run that answered, so a reader of this run's journal can
    /// follow the delegation into the run that did the work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run: Option<String>,
    /// Why the sub-run gave no answer, when it concluded without one.
    ///
    /// Recorded as the commission's outcome rather than raised as an effect
    /// failure: the sub-run ran, may have acted, and spent — so its spend is
    /// billed to this run like an answer's, and a replay reads the same
    /// verdict back instead of asking the specialist again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failed: Option<String>,
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
                // The effect gate reads these arguments, and no gate reads a
                // subject reference; the sub-run still receives them through
                // its input's label.
                "label": self.label.for_policy(),
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

    /// Which agent answered, so a source rule can name the specialist rather
    /// than the act of delegating.
    fn source(&self) -> crate::core::SourceId {
        crate::core::SourceId::new(format!("agent/{}", self.capability))
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

    /// Nothing, as an effect: what the sub-run spent is its own run's to
    /// settle. [`StepCtx::commission`] bills it to this run's ceilings
    /// without settling it into the tenant's period a second time.
    fn spend(&self, _output: &Self::Output) -> crate::core::Spend {
        crate::core::Spend::ZERO
    }

    /// Never asked twice. Each dispatch admits a sub-run of its own, so a
    /// retry is a second specialist doing the work again beside the first.
    fn retry(&self) -> crate::core::RetryPolicy {
        crate::core::RetryPolicy::never()
    }

    /// A commission announced and never recorded may have admitted a sub-run
    /// that is still working — the recovery sweep resumes that run — so
    /// re-performing it would commission a second. Only a person can say.
    fn recovery(&self) -> crate::core::Recovery {
        crate::core::Recovery::RequiresOperator
    }

    async fn perform(&self) -> Result<Self::Output, crate::core::EffectError> {
        let plane = self
            .plane
            .upgrade()
            .ok_or_else(|| crate::core::EffectError::Other("the plane is gone".into()))?;

        // The sub-run acts as the commissioning run does. Under its chain
        // when it has one; under none when it serves a caller that presented
        // none, so the plane's authority is not picked up on the way down; and
        // as the plane when it is the plane's own run, which on a plane with
        // no chain of its own is what holds the tenant's mandates.
        let mut terms = match (&self.chain, self.served_unchained) {
            (Some(chain), _) if self.plane_chain => {
                super::RunTerms::default().acting_as_plane(chain.clone())
            }
            (Some(chain), _) => super::RunTerms::default().acting_as(chain.clone()),
            (None, true) => super::RunTerms::default().served(None),
            (None, false) => super::RunTerms::default(),
        };
        if let Some(initiator) = self.initiator.as_deref() {
            terms = terms.admitted_by(initiator);
        }
        if let Some(pin) = self.pin {
            terms = terms.expect_declaration(pin);
        }
        // `Interrupted`, not `Rejected`: this caller cannot know whether the
        // commissioned agent performed effects before it failed, and asserting
        // that nothing was applied would be a claim it has no basis for.
        //
        // An outcome rather than an `Admission`, because a commission carries no
        // idempotency key: there is no in-flight answer for a caller to have to
        // handle, and the key is the run's own effect key on the parent's chain.
        let out = plane
            .commission_run(
                &self.capability,
                Tainted::with_label(self.input.clone(), self.label.clone()),
                terms,
            )
            .await
            .map_err(|e| match e {
                // The store could not say whether the sub-run was admitted.
                crate::core::RuntimeError::Store(_) => crate::core::EffectError::Interrupted {
                    driver: self.capability.clone(),
                    detail: e.to_string(),
                },
                // Refused at admission — unknown capability, scope, policy,
                // quota, a halt, a pinned revision that moved: no sub-run
                // exists and nothing ran.
                e => crate::core::EffectError::Refused(e.to_string()),
            })?;

        let spend = out.spend();
        let run = Some(out.run_id.to_string());
        let Some(answer) = out.output else {
            return Ok(Commissioned {
                answer: Value::Null,
                tokens: spend.tokens,
                minor_units: spend.minor_units,
                sensitivity: internal_floor(),
                data_subjects: BTreeSet::new(),
                run,
                failed: Some(format!(
                    "'{}' concluded {:?} without an answer; its run is {}",
                    self.capability, out.status, out.run_id
                )),
            });
        };
        Ok(Commissioned {
            run,
            sensitivity: answer.label().sensitivity,
            data_subjects: answer.label().data_subjects.clone(),
            answer: answer.into_unlabelled(),
            tokens: spend.tokens,
            minor_units: spend.minor_units,
            failed: None,
        })
    }
}
