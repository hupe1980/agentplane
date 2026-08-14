//! The executor: admission, step dispatch, sealing, and replay.
//!
//! M0 executes a single step. The DAG scheduler, plan contract, and topology
//! checks slot in above this without changing the effect protocol below it —
//! which is the point of putting the determinism boundary at the effect rather
//! than at the plan.

#[cfg(feature = "manifest")]
use std::collections::HashSet;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::case::{CaseStore, EventStore, TaskStore, TimerStore};
use crate::core::{
    ArgSource, Budget, Calendar, Capability, CorrelationKey, Delivery, Digest, EffectDescriptor,
    InboundEvent, Ledger, Outcome, Phase, PlanIR, PlanNode, PolicyBundleIdentity, RunId,
    RuntimeError, Skill, SkillDescriptor, Spend, StepId, Tainted, WallClock,
};
use crate::journal::{Append, JournalStore, Record, RecordKind, ReplayCursor, StepCursor};
use crate::runtime::BuildError;

use super::ctx::{CaseContext, Mode, StepCtx};
use super::metrics;
use super::telemetry;
use tracing::Instrument;

#[derive(Debug, Clone)]
pub(crate) enum CaseBinding {
    Correlate {
        kind: String,
        keys: Vec<CorrelationKey>,
    },
    Existing(crate::core::CaseId),
}

/// Default lease duration. A crashed owner's runs become claimable this long
/// after its last heartbeat.
///
/// This bounds how long a *dead* owner's runs are stranded, not how long a run
/// may take: a live run renews while it executes. Set per plane with
/// [`RuntimeBuilder::lease_ttl`].
pub const LEASE_TTL: Duration = Duration::from_secs(30);

/// The shortest lease a live run can actually hold.
///
/// Both stores keep expiry in whole seconds and lapse on `expires_at <= now`, so
/// a one-second lease is expired for part of every second it exists. Two is the
/// smallest value a renewal can stay ahead of.
pub const MIN_LEASE_TTL: Duration = Duration::from_secs(2);

/// What a run produced.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub run_id: RunId,
    pub status: RunStatus,
    /// What this run consumed.
    ///
    /// Reported rather than left in the ledger because "what did the settlement
    /// run cost" has to be answerable per item, and a batch sums its items. A
    /// figure that only exists inside a dropped `Ledger` is a figure nobody can
    /// bill against.
    pub spend: Spend,
    /// Terminal hash of the run's chain — what a signature would cover.
    pub chain_head: Digest,
    /// What the run produced, **with its label**.
    ///
    /// Labelled rather than bare, and the difference is not cosmetic: a
    /// caller acting on a run's answer needs to know whether a model, a peer
    /// or a person wrote it. The label was stripped here until an A2A reply
    /// projection read a marker key out of an untrusted answer and let a
    /// remote peer choose the envelope its own reply arrived in — a
    /// confused-deputy reachable because the one fact that would have refused
    /// it had been dropped at the boundary.
    pub output: Option<Tainted<Value>>,
}

impl RunOutcome {
    /// The output if the run succeeded, or a [`RunFailure`] saying why not.
    ///
    /// Every caller that acts on a run's answer asks the same two questions —
    /// did it work, and what did it say — and pattern-matching
    /// [`status`](Self::status) to learn the first is how the second gets read
    /// off a run that quarantined. This folds the pair into one `?`:
    ///
    /// ```ignore
    /// let answer = runtime.run("greet", input).await?.success()?;
    /// ```
    ///
    /// `status` stays public for the callers whose branches genuinely differ —
    /// a suspended run is not a failed one, and an operator surface treats
    /// them differently. This is for the caller to whom anything short of an
    /// answer is an error.
    ///
    /// # Errors
    ///
    /// [`RunFailure`] for every non-succeeded status, carrying the run id and
    /// the status itself.
    pub fn success(self) -> Result<Tainted<Value>, RunFailure> {
        match self.status {
            // A succeeded run's answer; `Null` for the degenerate run that
            // finished without producing one, which is still a success.
            RunStatus::Succeeded => {
                Ok(self.output.unwrap_or_else(|| Tainted::trusted(Value::Null)))
            }
            status => Err(RunFailure {
                run_id: self.run_id,
                status,
            }),
        }
    }
}

/// A run that stopped short of an answer, as an error a caller can `?`.
///
/// Carries the [`RunStatus`] whole rather than a flattened string, so a caller
/// that started with [`RunOutcome::success`] and later needs to tell a
/// suspension from a quarantine can match on [`status`](Self::status) without
/// re-plumbing the call site.
#[derive(Debug, Clone)]
pub struct RunFailure {
    pub run_id: RunId,
    pub status: RunStatus,
}

impl std::fmt::Display for RunFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "run {} did not succeed: ", self.run_id)?;
        match &self.status {
            RunStatus::Succeeded => unreachable!("a success is not a failure"),
            RunStatus::Failed(reason) => write!(f, "it failed — {reason}"),
            RunStatus::Suspended(reason) => write!(f, "it is suspended — {reason:?}"),
            RunStatus::Exhausted(limit) => write!(f, "a budget stopped it — {limit}"),
            RunStatus::Quarantined(reason) => write!(f, "it is quarantined — {reason}"),
            RunStatus::Replanning(reason) => write!(f, "it asked to replan — {reason}"),
            RunStatus::Cancelled { actor, reason } => {
                write!(f, "{actor} cancelled it — {reason}")
            }
        }
    }
}

impl std::error::Error for RunFailure {}

#[derive(Debug, Clone, PartialEq)]
pub enum RunStatus {
    /// All terminal work completed.
    ///
    /// Structural, never self-reported: a skill saying "done" is not what makes
    /// a run succeed. Agents confidently announce success on unmet objectives,
    /// so completion is determined by the runtime, not claimed by the workload.
    Succeeded,
    Failed(String),
    /// Waiting for something that has not happened. The frame is persisted and
    /// the task is gone: a suspended run costs disk, not a thread.
    Suspended(crate::core::SuspendReason),
    /// A limit stopped it. Not a fault — the run did what it was told, and what
    /// it was told included a ceiling.
    Exhausted(crate::core::BudgetExceeded),
    /// Needs human resolution before anything else may happen to it.
    Quarantined(String),
    /// A step asked for a different plan.
    ///
    /// Never observed by a caller: the executor either produces a successor and
    /// keeps going, or turns this into a failure with the reason it refused.
    /// It exists as a status so a step's request travels the same path every
    /// other outcome does.
    Replanning(String),
    /// An operator stopped it.
    ///
    /// Distinct from `Failed` on purpose. A failure is the run discovering it
    /// cannot proceed; a cancellation is a human deciding it should not. They
    /// call for different responses — one is investigated, the other was
    /// intended — and an operator scanning for failures should not have to
    /// mentally subtract their own interventions.
    ///
    /// Completed steps are unwound exactly as they are for a failure: stopping a
    /// run that has moved money and leaving the movement in place is not
    /// stopping it.
    Cancelled {
        actor: String,
        reason: String,
    },
}

impl RunStatus {
    /// Whether the run stopped without reaching a conclusion.
    #[must_use]
    pub fn is_suspended(&self) -> bool {
        matches!(self, Self::Suspended(_))
    }

    /// Whether the recorded history can no longer be trusted to describe this
    /// code, so a human must look before anything else happens.
    #[must_use]
    pub fn is_quarantined(&self) -> bool {
        matches!(self, Self::Quarantined(_))
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed(_) => "failed",
            Self::Suspended(_) => "suspended",
            Self::Exhausted(_) => "exhausted",
            Self::Quarantined(_) => "quarantined",
            Self::Replanning(_) => "replanning",
            Self::Cancelled { .. } => "cancelled",
        }
    }

    /// Whether an operator stopped this run.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }

    /// Whether this conclusion freezes the journal and enters the Merkle log.
    ///
    /// Only conclusions that nothing may resume seal. A failed run may be
    /// resumed — its completed effects are read back from history rather than
    /// performed again, which is the point of having a journal — and an
    /// exhausted run may continue once somebody raises the ceiling. Sealing
    /// either would commit the Merkle log to a leaf its own resume is then
    /// permitted to grow past: the checkpoint would attest a prefix of a
    /// history that kept moving, and the store's refusal of appends after a
    /// seal would turn every legitimate resume into an error.
    ///
    /// This is the **one** implementation of that rule. `resume_is_closed`
    /// refuses exactly the outcomes this method seals — a test pins the
    /// agreement — because two copies of one rule agree everywhere except the
    /// boundary nobody probed.
    #[must_use]
    pub fn seals(&self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Quarantined(_) | Self::Cancelled { .. }
        )
    }
}

/// Every outcome a sealed run can carry, as the outcome index spells them.
///
/// The store indexes runs *by* outcome and deliberately has no "all runs"
/// query — a backlog listing is a range read rather than a table scan — so any
/// caller that wants every sealed run has to name the outcomes one by one. This
/// is the list to name them from, and it lives beside [`RunStatus::seals`]
/// because it is the same rule in its other spelling: the statuses that seal,
/// plus the two sealed conclusions that are not run statuses at all — a sweep
/// (`swept`) and a break-glass crossing (`broke-glass`), each sealed at birth
/// with no goal to have succeeded or failed at.
///
/// It lived in the CLI first, as string literals — two implementations of one
/// rule, where a new sealing outcome would have been exported by nobody and
/// the export that silently omitted it would have dropped exactly the runs an
/// auditor came for. A test holds this list to `RunStatus::seals` variant by
/// variant, which the literals in a binary could never be held to.
pub const SEALED_OUTCOMES: &[&str] = &[
    "succeeded",
    "quarantined",
    "cancelled",
    super::sweeper::SWEEP_OUTCOME,
    BREAK_GLASS_OUTCOME,
];

/// A run that exists but has not run.
///
/// Produced by admission and consumed by execution, so the two can happen in
/// different places — the same request for a blocking call, and a background
/// task for a non-blocking one.
struct Admitted {
    run: RunId,
    epoch: crate::core::Epoch,
    budget: Budget,
    agent: String,
    plan: PlanIR,
    input: Tainted<Value>,
    case: Option<CaseContext>,
}

/// Keeps a run's lease alive for as long as it is executing.
///
/// A lease answers one question — *is this owner dead?* — and it answers by
/// expiry. Without renewal it also answers a question it was never asked: a
/// healthy run that outlives its TTL looks exactly like a crashed one, and agent
/// runs routinely outlive a lease because a single model call can. Another
/// instance then takes the run over, bumps the epoch, and the original is fenced
/// on its next append: killed mid-flight, having already done real work.
///
/// Renewing while executing separates the two. The TTL then bounds how long a
/// *crashed* owner strands its runs, which is what it is for, and stops bounding
/// how long a run may take, which it should never have bounded.
///
/// Aborted on drop, so the renewal stops the moment execution returns — by any
/// path, including a panic unwinding through it. A heartbeat that outlived its
/// run would hold a lease nobody is using and strand it for a full TTL after a
/// crash, which is the failure this exists to prevent, arriving late.
struct Heartbeat(tokio::task::JoinHandle<()>);

impl Drop for Heartbeat {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The runtime.
#[derive(Debug, Clone)]
pub struct Runtime {
    store: Arc<dyn JournalStore>,
    skills: HashMap<String, Arc<dyn Skill>>,
    by_capability: HashMap<Capability, String>,
    /// A handle to this plane, for steps that commission other agents on it.
    ///
    /// Weak, and that is not an optimisation: a strong self-reference would
    /// leak every runtime ever built. It exists because commissioning belongs to
    /// the *runtime* — a skill holding an `Arc<Runtime>` cannot work, since the
    /// runtime needs the skill before the skill can have the runtime.
    self_ref: std::sync::Weak<Runtime>,
    /// The declaration governing each skill, by skill name.
    ///
    /// Per skill rather than per runtime, because a plane runs several agents
    /// and a step must be judged against *its own* agent's manifest.
    #[cfg(feature = "manifest")]
    governed_by: HashMap<String, Arc<crate::manifest::Manifest>>,
    /// Which tenant this plane runs as.
    ///
    /// One plane serves one tenant; a **process** may run several and serve
    /// them all, because `api::Planes` resolves a plane from the authenticated
    /// caller's tenant. That is what the composite keys on both backends bought:
    /// the tenant leads every key, lease, correlation and blob path, so a query
    /// that forgets it misses rather than returning somebody else's rows.
    tenant: crate::core::TenantId,
    /// Who vouched for each declaration, by agent name.
    ///
    /// Separate from the manifest because it is *not* in it: a document cannot
    /// state who signed it. It arrives beside the manifest from a verified
    /// registry resolution, and an absent entry means nobody vouched.
    #[cfg(feature = "manifest")]
    published_by: HashMap<String, crate::core::KeyId>,
    /// Model drivers by the name a manifest calls them.
    ///
    /// Kept after build — not only consumed by it — so a *hand-written* skill
    /// can reach the driver its manifest's model role names through
    /// [`StepCtx::complete`], instead of smuggling an `Arc<dyn ModelProvider>`
    /// field past the declaration.
    #[cfg(feature = "manifest")]
    providers: HashMap<String, Arc<dyn crate::model::ModelProvider>>,
    owner: String,
    /// How long a run's lease lasts, and how long a crashed owner's runs stay
    /// unclaimable.
    lease_ttl: Duration,
    /// Where this plane's agents remember things, when a deployment wires one.
    memories: Option<Arc<dyn crate::memory::MemoryStore>>,
    authorities: Option<Arc<dyn crate::authority::AuthorityStore>>,
    /// The catalogue and transport a **skill** reaches tools through.
    ///
    /// Held by the plane rather than handed to each skill, and that is the
    /// point. A skill that built its own [`ToolCatalog`] could declare a tool
    /// read-only that its manifest calls mutating — and `ToolSafety::read_only`
    /// carries `Recovery::Retry`, so a timed-out money-moving call gets sent
    /// again. `check_catalogue_not_laxer_than_grants` refuses exactly that for
    /// the plane's catalogue at build; a hand-built one never passed under it.
    /// `StepCtx::call_tool` is the path that cannot.
    #[cfg(feature = "manifest")]
    tools: Option<(
        Arc<crate::tools::ToolCatalog>,
        Arc<dyn crate::tools::ToolClient>,
    )>,
    /// How this plane attributes its metrics.
    meter: super::metrics::Meter,
    /// Durable per-tenant ceilings, when a deployment wires them.
    quotas: Option<Arc<dyn crate::quota::QuotaStore>>,
    quota: crate::quota::TenantQuota,
    budget: Budget,

    cases: Option<Arc<dyn CaseStore>>,
    events: Option<Arc<dyn EventStore>>,
    tasks: Option<Arc<dyn TaskStore>>,
    timers: Option<Arc<dyn TimerStore>>,
    blobs: Option<Arc<dyn crate::blob::BlobStore>>,
    /// Where data keys live, when payload bytes are sealed.
    #[cfg(feature = "keyring")]
    keyring: Option<Arc<dyn crate::keyring::KeyRing>>,
    batches: Option<Arc<dyn crate::batch::BatchStore>>,
    policy: Option<Arc<dyn crate::core::PolicyEngine>>,
    identity: Option<crate::core::Delegation>,
    replanner: Option<Arc<dyn crate::plan::Replanner>>,
    calendar: Arc<dyn Calendar>,
    signer: Option<Arc<dyn crate::core::Signer>>,
    /// Where this plane sends its own events, when a deployment configures it.
    ///
    /// Registered per run **at admission**: a destination attached after the
    /// first record would silently miss it, and "the journal is the outbox" only
    /// holds if the cursor starts at sequence one.
    #[cfg(feature = "push")]
    outbox: Option<Arc<crate::push::Outbox>>,
}

/// A backend that implements every store a full plane runs on.
///
/// Blanket-implemented, so it is a *description* rather than an obligation:
/// any type providing the six store traits — journal, cases, tasks, events,
/// timers, memory — is a `FullBackend` without saying so, and both shipped
/// backends are. What it buys is [`Runtime::builder_on`], where the
/// alternative was six casts of one `Arc` that every deployment spelled out
/// and none could get differently.
pub trait FullBackend:
    JournalStore + CaseStore + TaskStore + EventStore + TimerStore + crate::memory::MemoryStore
{
}

impl<B> FullBackend for B where
    B: JournalStore + CaseStore + TaskStore + EventStore + TimerStore + crate::memory::MemoryStore
{
}

impl Runtime {
    /// A builder with the whole case layer wired to one backend.
    ///
    /// The one-call form of the six-cast litany: journal, cases, tasks,
    /// events, timers and memory all backed by `store`, which is what a
    /// deployment on a single `RedbStore` or `PostgresStore` means anyway. The
    /// à-la-carte methods remain — [`cases`](RuntimeBuilder::cases) and
    /// friends override an individual store afterwards, and
    /// [`builder`](Self::builder) still starts from the journal alone for a
    /// plane that wants nothing else.
    ///
    /// Blob storage is deliberately not included: bytes routinely live in a
    /// different system than rows, so [`blobs`](RuntimeBuilder::blobs) stays
    /// an explicit decision.
    #[must_use]
    pub fn builder_on<B: FullBackend + 'static>(store: Arc<B>) -> RuntimeBuilder {
        Self::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
            .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
            .tasks(Arc::clone(&store) as Arc<dyn TaskStore>)
            .events(Arc::clone(&store) as Arc<dyn EventStore>)
            .timers(Arc::clone(&store) as Arc<dyn TimerStore>)
            .memory(store as Arc<dyn crate::memory::MemoryStore>)
    }

    #[must_use]
    pub fn builder(store: Arc<dyn JournalStore>) -> RuntimeBuilder {
        RuntimeBuilder {
            store,
            signer: None,
            skills: Vec::new(),
            owner: None,
            lease_ttl: LEASE_TTL,
            memories: None,
            authorities: None,
            metric_tenant: super::metrics::TenantLabel::default(),
            quotas: None,
            quota: crate::quota::TenantQuota::default(),
            budget: Budget::unlimited(),
            cases: None,
            events: None,
            tasks: None,
            timers: None,
            blobs: None,
            #[cfg(feature = "keyring")]
            keyring: None,
            #[cfg(feature = "manifest")]
            tools: None,
            tenant: crate::core::TenantId::default(),
            batches: None,
            policy: None,
            identity: None,
            replanner: None,
            calendar: None,
            #[cfg(feature = "manifest")]
            toolbox: None,
            #[cfg(feature = "manifest")]
            tool_servers: Vec::new(),
            #[cfg(feature = "manifest")]
            agents: Vec::new(),
            #[cfg(feature = "manifest")]
            providers: HashMap::new(),
            #[cfg(feature = "push")]
            outbox: None,
        }
    }

    /// The driver registered under a manifest's name for it, if any.
    #[cfg(feature = "manifest")]
    pub(crate) fn model_provider(
        &self,
        name: &str,
    ) -> Option<Arc<dyn crate::model::ModelProvider>> {
        self.providers.get(name).map(Arc::clone)
    }

    /// The case store, if this runtime has one.
    #[must_use]
    pub fn cases(&self) -> Option<&Arc<dyn CaseStore>> {
        self.cases.as_ref()
    }

    /// The worklist, if this runtime has one.
    #[must_use]
    pub fn tasks(&self) -> Option<&Arc<dyn TaskStore>> {
        self.tasks.as_ref()
    }

    /// The inbound-event store, if this runtime has one.
    #[must_use]
    pub fn events(&self) -> Option<&Arc<dyn EventStore>> {
        self.events.as_ref()
    }

    /// The ceilings every run under this runtime starts with.
    ///
    /// Readable because "what is this plane allowed to spend" is a question an
    /// operator asks of a running system, and answering it by re-reading the
    /// config that *should* have been applied is how a misapplied budget stays
    /// invisible.
    #[must_use]
    pub const fn budget(&self) -> &Budget {
        &self.budget
    }

    /// The blob store, if this runtime has one.
    #[must_use]
    pub fn blobs(&self) -> Option<&Arc<dyn crate::blob::BlobStore>> {
        self.blobs.as_ref()
    }

    /// Run the live half of the case-layer drill with this plane's own stores.
    ///
    /// The wiring is the point of this method existing: the drill's value is
    /// holding each case's references against the stores the plane *actually
    /// runs with*, and an embedder assembling `drill::Stores` by hand could
    /// hand it a different blob store than the one their runs write to —
    /// a drill that passes over the wrong bucket. Stores this runtime does
    /// not have are reported as unchecked by the drill itself, which is a
    /// different and better answer than an error: a plane with no blob store
    /// has no bytes to lose.
    ///
    /// # Errors
    ///
    /// If this runtime has no case store — the drill walks cases, so there is
    /// nothing to drill — or if the case layer cannot be enumerated.
    pub async fn drill(&self) -> Result<crate::drill::DrillReport, RuntimeError> {
        let cases = self.cases().ok_or_else(|| {
            RuntimeError::PlanContract(
                "this runtime has no case store — the drill walks cases, so there is \
                 nothing to drill; build it with `.cases(store)`"
                    .into(),
            )
        })?;
        let stores = crate::drill::Stores {
            cases,
            blobs: self.blobs(),
            #[cfg(feature = "keyring")]
            keys: self.keyring.as_ref(),
        };
        crate::drill::drill(&stores)
            .await
            .map_err(RuntimeError::from_store)
    }

    /// The timer store, if this runtime has one.
    #[must_use]
    pub fn timers(&self) -> Option<&Arc<dyn TimerStore>> {
        self.timers.as_ref()
    }

    #[must_use]
    pub fn batches(&self) -> Option<&Arc<dyn crate::batch::BatchStore>> {
        self.batches.as_ref()
    }

    /// Ask a run to stop, and drive the stop if nothing else will.
    ///
    /// The request is durable before this returns, so an operator who gets an
    /// acknowledgement has one whether or not the run was reachable. What
    /// happens next depends on where the run is:
    ///
    /// * **Suspended** — nothing is executing, so this resumes the run itself.
    ///   It observes the request at its first step boundary and unwinds.
    /// * **Running here or elsewhere** — the owner observes the request at its
    ///   next step boundary. Nothing is interrupted mid-effect, deliberately:
    ///   stopping between "announced" and "recorded" manufactures the in-doubt
    ///   case the effect protocol exists to avoid.
    /// * **Already concluded** — the request is recorded and does nothing. A
    ///   sealed run is not reopened by an operator changing their mind.
    ///
    /// Returns whether *this* call recorded the request. A second caller gets
    /// `false`: the first asker stays on the record, because "who intervened"
    /// must not be rewritten by a retry.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] if the store is unreachable, or if resuming a suspended
    /// run fails.
    pub async fn request_cancel(
        &self,
        run: RunId,
        actor: &str,
        reason: &str,
    ) -> Result<bool, RuntimeError> {
        // Checked before recording. Writing first and failing afterwards leaves a
        // request standing against an id that does not exist, and the operator's
        // retry then comes back "somebody else already asked" — which is a
        // confusing way to say "you mistyped".
        if self
            .store
            .head(run)
            .await
            .map_err(RuntimeError::from_store)?
            .seq
            == 0
        {
            return Err(RuntimeError::Store(crate::core::StoreError::NotFound(
                run.to_string(),
            )));
        }

        let fresh = self
            .store
            .request_cancel(run, actor, reason)
            .await
            .map_err(RuntimeError::from_store)?;

        // Drive it. A suspended run has no thread to notice anything, so an
        // operator's stop would sit unobserved until the deadline swept it —
        // which for a run waiting on a six-week obligation is not a stop.
        //
        // Resuming a run that has already concluded is a no-op inside `replay`,
        // which reads the recorded status back rather than re-executing — so
        // there is no "is it finished?" check to race with here.
        //
        // Driven **only when the run is genuinely idle**: `replay` claims the
        // lease before it reads, and a `LeaseHeld` refusal means somebody is
        // executing the run right now — here or on another instance. That is
        // not a failure of this call. The request is already durable, and the
        // live owner checks for it at every step boundary (the cancellation
        // read at the top of the executor's ready-set loop), so the stop
        // arrives without a second executor ever touching the run. Resuming
        // anyway is what this used to do, and on the owner's own instance the
        // old lease semantics handed the resume the *same epoch* the live
        // execution was writing under — two executors on one chain that
        // fencing, by construction, could not tell apart.
        if fresh {
            match self.replay(run, Mode::Resume).await {
                Ok(_) | Err(RuntimeError::LeaseHeld { .. }) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(fresh)
    }

    /// The stop request standing against a run, if any.
    ///
    /// Stop this tenant from starting new work, or let it start again.
    ///
    /// The emergency stop. `Some(reason)` halts, `None` lifts, and the reason is
    /// required because the next person to look will be somebody else, possibly
    /// at three in the morning, and *why* is the whole question.
    ///
    /// **What it stops, precisely.** New admissions, across every instance,
    /// because the flag is in the store rather than in this process — a switch
    /// that stops only the instance it was thrown on is the in-process-counter
    /// failure arriving during an incident. Refusals are their own error, not a
    /// ceiling: a ceiling means *not right now* and invites a retry, which is
    /// exactly what somebody pulling this switch is trying to stop.
    ///
    /// **What it does not stop, deliberately.** Runs already executing, and
    /// suspended runs resuming. Those are existing work, and refusing to let
    /// them continue would strand them mid-saga with reversals unrun — turning
    /// an incident into a second one. To stop work in flight, cancel it: that
    /// unwinds what it did and records who asked. This is the front door, not a
    /// power cut, and saying so is the difference between a control an operator
    /// can reason about and one they discover the shape of during an outage.
    ///
    /// Requires a quota store; without one there is nowhere durable to keep the
    /// flag, and an emergency stop that a restart forgets is not one.
    ///
    /// # Errors
    ///
    /// If no quota store is wired, or the store is unreachable.
    pub async fn set_halt(&self, reason: Option<&str>) -> Result<(), RuntimeError> {
        let quotas = self.quotas.as_ref().ok_or_else(|| {
            RuntimeError::Store(crate::core::StoreError::Backend(
                "an emergency stop needs a quota store to keep the flag in — an \
                 in-process one is forgotten by a restart and never seen by a \
                 second instance"
                    .to_owned(),
            ))
        })?;
        quotas.set_halt(reason).await.map_err(RuntimeError::Store)
    }

    /// Why this tenant is halted, if it is.
    ///
    /// # Errors
    ///
    /// If no quota store is wired, or the store is unreachable.
    pub async fn halted(&self) -> Result<Option<String>, RuntimeError> {
        let quotas = self.quotas.as_ref().ok_or_else(|| {
            RuntimeError::Store(crate::core::StoreError::Backend(
                "no quota store is wired, so no emergency stop can be set or read".to_owned(),
            ))
        })?;
        quotas.halted().await.map_err(RuntimeError::Store)
    }

    /// # Errors
    ///
    /// If the store is unreachable.
    pub async fn cancellation(
        &self,
        run: RunId,
    ) -> Result<Option<crate::journal::Cancellation>, RuntimeError> {
        self.store
            .cancellation(run)
            .await
            .map_err(RuntimeError::from_store)
    }

    /// The policy engine, if this runtime has one.
    ///
    /// Exposed because a surface that faces strangers has to be able to ask
    /// whether one exists at all. Inside the process the caller is the
    /// embedder's own code and an absent engine is a choice; on a socket it is
    /// a hole, and the HTTP surface refuses to start without one.
    #[must_use]
    pub fn policy(&self) -> Option<&Arc<dyn crate::core::PolicyEngine>> {
        self.policy.as_ref()
    }

    /// Which tenant this plane runs as.
    #[must_use]
    pub fn tenant(&self) -> &crate::core::TenantId {
        &self.tenant
    }

    /// The journal, under the name the batch driver reads it by.
    #[must_use]
    pub(crate) fn meter(&self) -> &super::metrics::Meter {
        &self.meter
    }

    /// Record an operator deliberately crossing into this tenant, and return
    /// the run that holds the record.
    ///
    /// Every other tenancy control keeps a cross-tenant read from being reached
    /// by accident. This is the designed exception, and the rule for it is that an
    /// exception without a record is indistinguishable from the breach it is
    /// meant to be. So the access is written into **this** tenant's journal —
    /// the one whose data is about to be reached — in a sealed run of its own,
    /// exactly as a sweep writes its decisions. It therefore inherits the hash
    /// chain, the per-record signature and the Merkle inclusion, and the
    /// offline audit tool reports it without being taught that break-glass
    /// exists.
    ///
    /// **The record is written before any data is served, and a failure to
    /// write it is a failure to access.** That direction is the whole control:
    /// the alternative — serve first, record best-effort — is a break-glass
    /// that works exactly as well when its own evidence is lost.
    ///
    /// # Errors
    ///
    /// If `reason` is blank, or if the record cannot be written. An
    /// unexplained exception is the thing this record exists to prevent, so it
    /// is refused rather than stored empty.
    pub async fn record_break_glass(
        &self,
        actor: &str,
        roles: &[String],
        reason: &str,
    ) -> Result<RunId, RuntimeError> {
        if reason.trim().is_empty() {
            return Err(RuntimeError::PlanContract(
                "break-glass needs a reason: an unexplained crossing of the tenant \
                 boundary is what this record exists to prevent"
                    .to_owned(),
            ));
        }
        let run = RunId::generate();
        let epoch = BREAK_GLASS_EPOCH;
        self.store
            .append(
                epoch,
                vec![Append::new(
                    run,
                    RecordKind::BreakGlass {
                        actor: actor.to_owned(),
                        roles: roles.to_vec(),
                        reason: reason.to_owned(),
                    },
                )],
            )
            .await
            .map_err(RuntimeError::from_store)?;
        // Concluded and closed like any other terminal run, so the outcome is
        // in the chain and the run enters the Merkle log. `broke-glass` rather
        // than a run status: it neither succeeded nor failed at a goal, which
        // is the same reason a sweep seals as `swept`.
        let head = self
            .store
            .head(run)
            .await
            .map_err(RuntimeError::from_store)?;
        self.store
            .append(
                epoch,
                vec![Append::new(
                    run,
                    RecordKind::RunSealed {
                        outcome: BREAK_GLASS_OUTCOME.to_owned(),
                        chain_head: head.hash,
                    },
                )],
            )
            .await
            .map_err(RuntimeError::from_store)?;
        self.store
            .seal(run, epoch, BREAK_GLASS_OUTCOME)
            .await
            .map_err(RuntimeError::from_store)?;
        tracing::warn!(
            tenant = %self.tenant(),
            %actor,
            %run,
            reason,
            "break-glass: an operator crossed the tenant boundary"
        );
        Ok(run)
    }

    /// The journal, for reads the runtime does not mediate.
    ///
    /// This is also the embedder's **resumable output stream**:
    /// [`JournalStore::read`] is a seq-cursored read over a run's records, so
    /// polling from the last sequence seen is a durable, reconnect-safe
    /// progress feed that any instance can serve — the exact mechanism the
    /// A2A streaming surface is built on. There is deliberately no curated
    /// event type between an embedder and the records: a third vocabulary
    /// beside the journal's and the wire's would be a second truth wearing
    /// ergonomics, and the records are already the history the stream must
    /// agree with.
    pub fn journal(&self) -> &Arc<dyn JournalStore> {
        &self.store
    }

    /// Which case a run belongs to, or `None` if it belongs to none.
    ///
    /// Read from the **journal**, not from a column beside it. The binding is
    /// stamped on the run's own records at admission, so answering from there
    /// is answering from the plan of record — a case-store column saying the
    /// same thing would be a second copy of one fact, and the two could
    /// disagree about a run the case layer never saw.
    ///
    /// It is the first question an operator surface asks, which is why it is a
    /// method rather than a documented one-liner: every caller was otherwise
    /// going to reach for the first record and read `body.case` off it, and a
    /// caller who reached for the *last* one instead would still be right today
    /// and wrong the moment a run is admitted before its case is known.
    ///
    /// # Errors
    ///
    /// If the journal cannot be read. An unknown run is `Ok(None)` rather than
    /// an error: *no such run* and *a run in no case* are both honest answers
    /// to this question, and neither is a fault.
    pub async fn case_of(&self, run: RunId) -> Result<Option<crate::core::CaseId>, RuntimeError> {
        Ok(self
            .store
            .read(run, 1)
            .await
            .map_err(RuntimeError::from_store)?
            .first()
            .and_then(|record| record.body.case))
    }

    #[must_use]
    pub fn store(&self) -> &Arc<dyn JournalStore> {
        &self.store
    }

    /// This **process instance's** identity, as it appears in run leases.
    ///
    /// Not the agent's name. Several instances of one agent are normal, and a
    /// lease is renewed without a fencing bump only when the holder is the same
    /// owner — so two instances sharing this string would each renew the other's
    /// lease and both write to one run. See
    /// [`RuntimeBuilder::owner`](RuntimeBuilder::owner).
    ///
    /// Public because "which instance holds this run" is a question an operator
    /// asks of a stuck system, and the answer is otherwise only in a store row.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner
    }

    /// The declaration governing a skill, if its agent has one.
    ///
    /// Per skill, not per plane: a runtime runs several agents, and a step must
    /// be judged against the manifest of the agent whose skill it is. Looking up
    /// one plane-wide manifest would apply another agent's ceilings.
    #[cfg(feature = "manifest")]
    fn governing(&self, skill: &dyn Skill) -> Option<Arc<crate::manifest::Manifest>> {
        self.governed_by.get(&skill.descriptor().name).cloned()
    }

    /// Renew this run's lease until the returned guard is dropped.
    ///
    /// Requires a Tokio runtime, as the rest of this crate's timing does.
    fn heartbeat(&self, run: RunId, epoch: crate::core::Epoch) -> Heartbeat {
        let store = Arc::clone(&self.store);
        let owner = self.owner.clone();
        let ttl = self.lease_ttl;
        // A third of the TTL, so two renewals can be lost to a slow store before
        // the lease lapses. Renewing *at* the TTL would mean any hesitation
        // leaves it expired, and an expired lease is one anybody may take —
        // including, per `acquire`, this caller, which would fence the run with
        // its own heartbeat.
        let period = ttl / 3;
        Heartbeat(tokio::spawn(async move {
            loop {
                tokio::time::sleep(period).await;
                // `renew`, never `acquire`. A renewal extends only a lease
                // still held by exactly this `(owner, epoch)`; it cannot
                // claim. That distinction is load-bearing here: this task
                // races the run's own conclusion, and an acquire arriving
                // just after `conclude` released the lease would re-take it —
                // a live, never-released lease over a concluded run, which
                // the recovery sweep then "recovers" forever.
                //
                // A failed renewal means the lease was lost — released by the
                // conclusion, lapsed and reclaimed, or taken over. Stop
                // either way: the run's next append will be fenced, which is
                // the correct outcome, and claiming now would only resurrect
                // ownership this instance no longer has.
                if store.renew(run, &owner, epoch, ttl).await.is_err() {
                    return;
                }
            }
        }))
    }

    /// Refuse a run whose tenant is at a ceiling.
    ///
    /// Fails **closed**: an unreachable quota store refuses rather than admits,
    /// because a ceiling that yields when its accounting is down is a ceiling an
    /// attacker removes by taking the accounting down.
    ///
    /// Live admission only. Replay and resume never come through here, which is
    /// deliberate — re-checking a quota during replay would let a run that
    /// happened produce a different history when it is re-read, and a ceiling
    /// crossed since admission would rewrite the past into a refusal.
    async fn check_quota(&self, run: RunId) -> Result<(), RuntimeError> {
        let Some(quotas) = self.quotas.as_ref() else {
            return Ok(());
        };

        // The halt is checked **before** the unlimited shortcut, because an
        // emergency stop is not a ceiling and a tenant with no ceilings is
        // exactly the one an operator is most likely to need to stop. Reading it
        // fails closed for the same reason the ceilings do: a switch that yields
        // when its store is unreachable is a switch an attacker throws by taking
        // the store down.
        match quotas.halted().await {
            Ok(Some(reason)) => {
                return Err(RuntimeError::QuotaExceeded(
                    crate::quota::QuotaError::Halted {
                        tenant: self.tenant.as_str().to_owned(),
                        reason,
                    },
                ));
            }
            Ok(None) => {}
            Err(e) => {
                return Err(RuntimeError::QuotaExceeded(
                    crate::quota::QuotaError::Unavailable(e.to_string()),
                ));
            }
        }

        if self.quota.is_unlimited() {
            return Ok(());
        }

        if self.quota.bounds_spend() {
            let period = self.quota.period.key_for(now_for_admission());
            let spent = quotas.spent(&period).await.map_err(|e| {
                RuntimeError::QuotaExceeded(crate::quota::QuotaError::Unavailable(e.to_string()))
            })?;
            crate::quota::check_spend(self.tenant.as_str(), &period, &self.quota, spent)
                .map_err(RuntimeError::QuotaExceeded)?;
        }

        quotas
            .reserve(run, self.quota.max_concurrent_runs, now_for_admission())
            .await
            .map_err(RuntimeError::QuotaExceeded)
    }

    /// Give back the slot and record what the run spent.
    ///
    /// Best-effort, and deliberately so: the work is done and journaled by the
    /// time this runs, and turning a bookkeeping failure into a run failure
    /// would convert a tidiness problem into a correctness one. A slot that is
    /// not released is attributable — the table names the run — so an operator
    /// can see a stranded one rather than a counter that has silently drifted.
    async fn settle_quota(&self, run: RunId, spend: Spend) {
        let Some(quotas) = self.quotas.as_ref() else {
            return;
        };
        if let Err(e) = quotas.release(run).await {
            tracing::debug!(%run, error = %e, "could not release the quota slot");
        }
        if self.quota.bounds_spend() {
            let period = self.quota.period.key_for(now_for_admission());
            if let Err(e) = quotas.accrue(&period, spend).await {
                tracing::warn!(
                    %run, error = %e,
                    "could not record this run's spend against the tenant ceiling — \
                     the period will under-count"
                );
            }
        }
    }

    /// The ceilings a run gets: its agent's, or the plane's if it has no agent.
    ///
    /// Per agent, because that is who declared them. A plane-wide budget would
    /// let one agent's generosity bound another's runs, which is the whole
    /// reason a declaration belongs to an identity rather than to a process.
    fn budget_for(&self, target: &str) -> Budget {
        #[cfg(feature = "manifest")]
        if let Ok(skill) = self.resolve(target)
            && let Some(m) = self.governing(skill.as_ref())
        {
            return m.budget();
        }
        let _ = target;
        self.budget
    }

    /// Which declaration governs runs of this capability, if a declared agent
    /// does.
    ///
    /// Resolved the same way the budget is, and for the same reason: a run is
    /// governed by the agent that answers its entry capability. A commissioned
    /// sub-run opens its own run and records its own governor, so every run in a
    /// room has exactly one — there is no case where this has to pick.
    ///
    /// The digest is computed here rather than stored on the agent because it is
    /// only needed at admission, and a manifest that cannot produce one is a
    /// manifest that could not have been published; recording `None` in that
    /// case would claim the run was ungoverned, so the failure is surfaced as an
    /// absent identity rather than a false one.
    #[cfg(feature = "manifest")]
    fn identity_for(&self, target: &str) -> Option<crate::journal::AgentIdentity> {
        let skill = self.resolve(target).ok()?;
        let m = self.governing(skill.as_ref())?;
        Some(crate::journal::AgentIdentity {
            name: m.metadata.name.clone(),
            version: m.metadata.version.clone(),
            digest: m.digest().ok()?,
            publisher: self.published_by.get(&m.metadata.name).cloned(),
        })
    }

    fn resolve(&self, target: &str) -> Result<Arc<dyn Skill>, RuntimeError> {
        if let Some(s) = self.skills.get(target) {
            return Ok(Arc::clone(s));
        }
        let cap = Capability::new(target);
        if let Some(name) = self.by_capability.get(&cap)
            && let Some(s) = self.skills.get(name)
        {
            return Ok(Arc::clone(s));
        }
        // Capabilities rather than skill names: `run` is documented to take the
        // capability, and listing the names would answer a question nobody
        // asked with vocabulary that does not work in the call that failed.
        let mut available: Vec<String> = self
            .by_capability
            .keys()
            .map(std::string::ToString::to_string)
            .collect();
        available.sort();
        Err(RuntimeError::NoProvider {
            target: target.to_owned(),
            available,
        })
    }

    /// Execute a fresh run with no case attached.
    ///
    /// The input arrives **labelled**, and that is the whole of the decision.
    /// [`Tainted::trusted`](crate::core::Tainted::trusted) is what an operator
    /// writes for a literal, a constant or a configuration value they vouch for;
    /// anything that came from outside — an inbound event, a queue message, a
    /// counterparty's payload — keeps the label it arrived with.
    ///
    /// This took a bare `Value` and admitted it as `Trusted` by default. A
    /// deployment whose runs are started by inbound events passed counterparty
    /// data straight in, and three controls went quiet at once: `require_trusted`
    /// protected fields were satisfied by attacker-chosen values, the egress
    /// ceiling had nothing untrusted to join with, and the journal recorded no
    /// contact with outside data. Nothing failed and the suite stayed green,
    /// which is the profile of every other default this crate declines to offer.
    ///
    /// A `run_trusted`/`run_tainted` pair was tried first and is worse: it
    /// doubles every shape, puts `run_trusted_in_case` one word away from
    /// `run_tainted_in_case`, and still lets `run_trusted(cap, payload)` compile
    /// over data nobody vouched for. A label is a **value** — it can be
    /// computed, threaded through an adapter, or derived from where a message
    /// arrived, none of which a method name can do. [`spawn`](Self::spawn)
    /// already worked this way; `run` was the outlier.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::NoProvider`] when no skill provides `target`, and
    /// whatever admission refuses — policy, quota, a halted tenant, a lease.
    pub async fn run(
        &self,
        target: &str,
        input: Tainted<Value>,
    ) -> Result<RunOutcome, RuntimeError> {
        self.admit(target, input, None).await
    }

    /// Admit a run and let it proceed in the background, returning its id.
    ///
    /// The asynchronous counterpart to [`run`](Self::run), for
    /// callers that want a handle rather than an answer — A2A's
    /// `return_immediately`, a queue worker, an operator kicking something off.
    ///
    /// **Admission happens before this returns.** The policy gate, the lease and
    /// the admission records are all written first, so a refusal is an error
    /// here and not a task that never appears, and the id handed back can be
    /// read immediately. What continues in the background is the *work*.
    ///
    /// The run is durable, so a process that dies mid-flight leaves a journal
    /// another instance resumes; the background task is where the work happens,
    /// not where it is kept.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime, as the rest of this crate's timing does.
    ///
    /// # Errors
    ///
    /// As [`run`](Self::run) — anything admission itself refuses.
    pub async fn spawn(
        self: &Arc<Self>,
        target: &str,
        input: Tainted<Value>,
    ) -> Result<RunId, RuntimeError> {
        self.spawn_bound(target, input, None).await
    }

    async fn spawn_bound(
        self: &Arc<Self>,
        target: &str,
        input: Tainted<Value>,
        case: Option<CaseBinding>,
    ) -> Result<RunId, RuntimeError> {
        // Resolved before the id is minted: an unknown capability is the
        // caller's mistake and must be an error, not a run that exists and
        // immediately fails.
        let skill = self.resolve(target)?;
        let capability = first_capability(&skill.descriptor());

        let run = RunId::generate();
        let admitted = self
            .admit_only(run, PlanIR::single(capability), input, case)
            .await?;

        let plane = Arc::clone(self);
        tokio::spawn(async move { plane.execute_admitted(admitted).await });
        Ok(run)
    }

    pub async fn spawn_in_case(
        self: &Arc<Self>,
        target: &str,
        input: Tainted<Value>,
        case: crate::core::CaseId,
    ) -> Result<RunId, RuntimeError> {
        self.spawn_bound(target, input, Some(CaseBinding::Existing(case)))
            .await
    }

    pub async fn spawn_correlated(
        self: &Arc<Self>,
        target: &str,
        input: Tainted<Value>,
        case_kind: &str,
        keys: &[CorrelationKey],
    ) -> Result<RunId, RuntimeError> {
        self.spawn_bound(
            target,
            input,
            Some(CaseBinding::Correlate {
                kind: case_kind.to_owned(),
                keys: keys.to_vec(),
            }),
        )
        .await
    }

    /// Start a new immutable run inside a case that already exists.
    pub async fn run_in_case(
        &self,
        target: &str,
        input: Tainted<Value>,
        case: crate::core::CaseId,
    ) -> Result<RunOutcome, RuntimeError> {
        self.admit(target, input, Some(CaseBinding::Existing(case)))
            .await
    }

    /// Join or open a case by business key, then run.
    ///
    /// Correlation happens **before planning**, because which case a message
    /// belongs to is a question of fact, not of judgement: it is a deterministic
    /// lookup on business keys, never a model call. If an open case matches any
    /// key the run joins it; otherwise a case is opened.
    pub async fn run_correlated(
        &self,
        target: &str,
        input: Tainted<Value>,
        case_kind: &str,
        keys: &[CorrelationKey],
    ) -> Result<RunOutcome, RuntimeError> {
        self.admit(
            target,
            input,
            Some(CaseBinding::Correlate {
                kind: case_kind.to_owned(),
                keys: keys.to_vec(),
            }),
        )
        .await
    }

    /// Execute an explicit multi-step plan.
    ///
    /// The plan is validated and frozen *before the first step runs*: one that
    /// would fail at step seven must not begin at step one.
    pub async fn run_plan(
        &self,
        plan: PlanIR,
        input: Tainted<Value>,
    ) -> Result<RunOutcome, RuntimeError> {
        self.admit_plan(plan, input, None).await
    }

    /// Execute an explicit plan inside a long-lived case.
    pub async fn run_plan_correlated(
        &self,
        plan: PlanIR,
        input: Tainted<Value>,
        case_kind: &str,
        keys: &[CorrelationKey],
    ) -> Result<RunOutcome, RuntimeError> {
        self.admit_plan(
            plan,
            input,
            Some(CaseBinding::Correlate {
                kind: case_kind.to_owned(),
                keys: keys.to_vec(),
            }),
        )
        .await
    }

    /// Rebuild a run's case binding **from its history**, never by re-deriving.
    ///
    /// Two facts are read back rather than recomputed, and each has its own
    /// failure if it is not.
    ///
    /// The **case id**, because re-correlating could land on a different case if
    /// the keys were since released — silently rewriting which business fact the
    /// run belongs to.
    ///
    /// The **business keys**, because a case accumulates them over months. A run
    /// that resolved `memory_formation.subject: $correlation/meter` would
    /// otherwise resolve it against a set the live run never saw, write a second
    /// memory under a second subject, and produce a history that disagrees with
    /// itself with nothing on the record explaining why.
    fn recorded_case(&self, records: &[Record]) -> Option<CaseContext> {
        let (case_id, correlation) = records.iter().find_map(|r| match r.kind() {
            RecordKind::CaseBound { correlation, .. } => {
                r.body.case.map(|case_id| (case_id, correlation.clone()))
            }
            _ => None,
        })?;
        self.cases.as_ref().map(|cases| CaseContext {
            cases: Arc::clone(cases),
            tasks: self.tasks.clone(),
            events: self.events.clone(),
            calendar: Arc::clone(&self.calendar),
            case_id,
            correlation,
        })
    }

    /// The contract this runtime enforces on every plan.
    pub(crate) fn contract(&self) -> crate::plan::Contract {
        crate::plan::Contract::new(self.by_capability.keys().cloned())
    }

    async fn admit(
        &self,
        target: &str,
        input: Tainted<Value>,
        case: Option<CaseBinding>,
    ) -> Result<RunOutcome, RuntimeError> {
        // A bare target is the degenerate plan: one node, terminal.
        let skill = self.resolve(target)?;
        let capability = first_capability(&skill.descriptor());
        self.admit_plan(PlanIR::single(capability), input, case)
            .await
    }

    async fn admit_plan(
        &self,
        plan: PlanIR,
        input: Tainted<Value>,
        case: Option<CaseBinding>,
    ) -> Result<RunOutcome, RuntimeError> {
        self.admit_plan_as(RunId::generate(), plan, input, case)
            .await
    }

    /// Record the chain this run acts under, beside the plan it authorizes.
    ///
    /// The two are read back together: a chain without its plan says nothing
    /// about what it was allowed to do, and a plan without its chain says
    /// nothing about who was allowed to run it.
    fn bind_identity(&self, run: RunId, records: &mut Vec<Append>) {
        if let Some(chain) = self.identity.as_ref() {
            records.push(Append::new(
                run,
                RecordKind::IdentityBound {
                    chain: chain.links().cloned().collect(),
                },
            ));
        }
    }

    /// Check the plan against the delegation chain's authority.
    ///
    /// The plan is the authorization graph, so this is where authority belongs:
    /// a plan that names a capability outside the chain's scope must never
    /// start, rather than failing at whichever step happens to reach it first.
    /// Checking here also makes the refusal deterministic — it depends only on
    /// the frozen plan and the chain, both of which are recorded.
    fn authorize_scope(&self, plan: &PlanIR) -> Result<(), RuntimeError> {
        let Some(chain) = self.identity.as_ref() else {
            return Ok(());
        };
        let scope = chain.effective_scope();
        for node in &plan.nodes {
            if !scope.permits(&node.capability) {
                return Err(RuntimeError::PolicyDenied(
                    crate::core::PolicyError::Denied {
                        principal: chain.subject().id.clone(),
                        action: crate::core::ACTION_ADMIT.to_owned(),
                        resource: node.capability.to_string(),
                    },
                ));
            }
        }
        Ok(())
    }

    /// Authorize starting a run, before the run exists.
    ///
    /// A denial here leaves no journal at all, which is correct: nothing
    /// happened, and a run record for something that was never allowed to start
    /// would be a run nobody can explain.
    fn authorize_admission(
        &self,
        capability: &str,
        governed_by: Option<&crate::journal::AgentIdentity>,
        input: &Value,
    ) -> Result<(), RuntimeError> {
        let Some(engine) = self.policy.as_ref() else {
            return Ok(());
        };
        let mut context = serde_json::json!({ "input": input, "tenant": self.tenant.as_str() });
        // The declaration, so a rule can bind to the **digest** rather than to a
        // name anyone can reuse: "this exact declaration may admit, and an
        // edited one may not" is otherwise inexpressible, and a name-only rule
        // keeps permitting an agent whose prompt and grants have since changed.
        if let Some(id) = governed_by {
            let mut agent = serde_json::json!({
                "name": id.name,
                "version": id.version,
                "digest": id.digest.to_hex(),
            });
            // The grouping a real rule binds to. `name` is beside it for
            // readability and must not be authorized on: a file claims a name,
            // but only the holder of a key can claim a publisher.
            //
            // **Absent, never `null`.** An `Option` serialized straight into the
            // context put a JSON `null` there for every unpublished manifest —
            // which is most of them, since publisher attestation is opt-in — and
            // Cedar refuses a context containing one: not the field, the whole
            // record. So the request never reached a rule, came back
            // `malformed`, and **every run on a Cedar plane with an unsigned
            // manifest was denied**, with the caller told only that it was
            // declined, because naming the reason to an external caller is
            // precisely what this crate refuses to do. The adapter's own module
            // documentation already said *"or absent"*; only the code disagreed.
            //
            // A policy asks `context.agent has publisher` and then reads it,
            // which is Cedar's idiom for an optional attribute and is what the
            // absent form supports.
            if let Some(publisher) = id.publisher.as_ref() {
                agent["publisher"] = serde_json::to_value(publisher)?;
            }
            context["agent"] = agent;
        }
        super::ctx::merge_identity(&mut context, self.identity.as_ref());
        // Who is acting, and what is being asked for. Passing one string as both
        // made every admission rule a tautology — `principal == resource` cannot
        // express "this agent may not run that capability", which is the whole
        // question at admission on a plane hosting several agents.
        //
        // The principal is an **authenticated** identity or it is nothing. The
        // scope check a few lines above already denies under the delegation
        // subject, so anything else here would give one refused run two answers
        // to "who was refused" in the same error type.
        //
        // The agent's `metadata.name` is deliberately *not* used, tempting as it
        // is. A name is self-asserted — a manifest is a file, and its name is
        // whatever the author typed — so a rule granting authority to a name
        // grants it to any file claiming that name. A name is only as good as
        // the resolution path that produced it, and at admission the runtime
        // cannot know whether it came from a verified registry lookup or a
        // string literal. Worse, a fallback would be *silent*: `principal == X`
        // would mean an authenticated identity in a deployment with a delegation
        // chain and a self-asserted label in one without, so the same rule would
        // change meaning with the wiring.
        //
        // Rules that need to bind to the agent bind to `context.agent.digest`,
        // which is content-addressed and pins what the declaration actually
        // said. The capability is the fallback because it claims nothing: it is
        // what was asked for, not who asked.
        let principal = self
            .identity
            .as_ref()
            .map_or(capability, |chain| chain.subject().id.as_str());
        let request = crate::core::PolicyRequest {
            principal,
            action: crate::core::ACTION_ADMIT,
            resource: capability,
            context: &context,
        };
        let crate::core::PolicyDecision::Deny { reason } = engine.authorize(&request) else {
            return Ok(());
        };

        tracing::error!(
            target: telemetry::POLICY_DENIED,
            action = crate::core::ACTION_ADMIT,
            resource = %capability,
            %reason,
        );
        self.meter
            .count(metrics::POLICY_DENIALS, crate::core::ACTION_ADMIT);
        Err(RuntimeError::PolicyDenied(
            crate::core::PolicyError::Denied {
                principal: principal.to_owned(),
                action: crate::core::ACTION_ADMIT.to_owned(),
                resource: capability.to_owned(),
            },
        ))
    }

    /// The record that opens a run.
    ///
    /// Its own function because the label matters: journaled rather than
    /// recomputed, so a replay reaches the same verdict at every taint gate as
    /// the run it reproduces.
    fn admission(
        &self,
        capability: &str,
        governed_by: Option<crate::journal::AgentIdentity>,
        input: &Tainted<Value>,
    ) -> RecordKind {
        RecordKind::RunAdmitted {
            capability: capability.to_owned(),
            governed_by,
            input: input.peek().clone(),
            input_label: input.label().clone(),
            policy_bundle: self.policy.as_ref().map(|p| p.bundle()),
            canon: crate::core::canon::VERSION,
        }
    }

    /// Everything up to and including the admission records, and no work.
    ///
    /// The seam a non-blocking submit needs. Admission is what makes a run
    /// *exist*: the policy gate, the lease, and the records that say what is
    /// about to happen. Splitting there means a caller can be told the run was
    /// accepted — or refused — before any of it runs, and a refusal stays an
    /// immediate answer rather than becoming a task that silently never appears.
    #[allow(clippy::too_many_lines)]
    async fn admit_only(
        &self,
        run: RunId,
        plan: PlanIR,
        input: Tainted<Value>,
        case: Option<CaseBinding>,
    ) -> Result<Admitted, RuntimeError> {
        crate::plan::validate(&plan, &self.contract())
            .map_err(|e| RuntimeError::PlanContract(e.to_string()))?;

        let agent = plan
            .nodes
            .first()
            .map_or_else(|| "plan".to_owned(), |n| n.capability.to_string());

        // Resolved once: the gate and the record must agree about which
        // declaration governs this run, and computing it twice is how they
        // start disagreeing.
        #[cfg(feature = "manifest")]
        let governed_by = self.identity_for(&agent);
        #[cfg(not(feature = "manifest"))]
        let governed_by: Option<crate::journal::AgentIdentity> = None;

        self.authorize_scope(&plan)?;
        self.authorize_admission(&agent, governed_by.as_ref(), input.peek())?;

        // Before the lease and before any record: a run refused on quota must
        // leave nothing behind, or a throttled tenant accumulates half-open runs
        // that its next request has to step over.
        self.check_quota(run).await?;

        // From here a concurrency slot is reserved, and every error path below
        // must give it back. `check_quota`'s own refusals reserve nothing; an
        // error *after* the reservation — a lease that cannot be taken, a case
        // store that refuses, an append that fails — used to leak the slot
        // permanently, so a tenant whose admissions failed transiently was
        // throttled down to zero by its own error handling, one failure at a
        // time. Best-effort, like `settle_quota`: the slot row names the run,
        // so one that survives an unreachable store is attributable rather
        // than a counter that silently drifted.
        let out = self
            .admit_reserved(run, plan, input, case, agent, governed_by)
            .await;
        if out.is_err()
            && let Some(quotas) = self.quotas.as_ref()
            && let Err(e) = quotas.release(run).await
        {
            tracing::debug!(%run, error = %e, "could not release the quota slot of a failed admission");
        }
        out
    }

    /// Admission past the quota reservation: the lease, the records, the case
    /// binding, the outbox.
    ///
    /// Every error path hands the lease back. A lease left standing over a
    /// failed admission is not idle bookkeeping: it expires unreleased, which
    /// is the exact signature the recovery sweep reads as "an instance died
    /// holding this run" — so a half-admitted run (records appended, outbox
    /// registration failed) would be *executed* by the sweeper a TTL later,
    /// having never been admitted. The one error that concludes rather than
    /// merely unwinding is the post-append one, where records already exist:
    /// the run is concluded `failed` in its own chain first, so nothing later
    /// reads an open journal as work in progress.
    async fn admit_reserved(
        &self,
        run: RunId,
        plan: PlanIR,
        input: Tainted<Value>,
        case: Option<CaseBinding>,
        agent: String,
        governed_by: Option<crate::journal::AgentIdentity>,
    ) -> Result<Admitted, RuntimeError> {
        // Admission: take ownership, then record what we are about to do —
        // before doing any of it.
        let lease = self
            .store
            .acquire(run, &self.owner, self.lease_ttl)
            .await
            .map_err(RuntimeError::from_store)?;

        let out = self
            .admit_under_lease(run, &lease, plan, input, case, &agent, governed_by)
            .await;
        if out.is_err()
            && let Err(e) = self.store.release_lease(run, lease.epoch).await
        {
            tracing::debug!(
                %run,
                error = %e,
                "could not release the lease of a failed admission; it will expire on its own"
            );
        }
        out
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn admit_under_lease(
        &self,
        run: RunId,
        lease: &crate::journal::Lease,
        plan: PlanIR,
        input: Tainted<Value>,
        case: Option<CaseBinding>,
        agent: &str,
        governed_by: Option<crate::journal::AgentIdentity>,
    ) -> Result<Admitted, RuntimeError> {
        let mut records = vec![
            Append::new(run, self.admission(agent, governed_by, &input)),
            // From here the plan is an authorization graph: compiled from
            // trusted input, frozen before anything untrusted was read, and
            // recorded so the journal that follows can be checked against it.
            Append::new(
                run,
                RecordKind::PlanFrozen {
                    steps: plan
                        .nodes
                        .iter()
                        .map(|n| n.capability.to_string())
                        .collect(),
                    plan: serde_json::to_value(&plan)?,
                },
            ),
        ];

        self.bind_identity(run, &mut records);

        // Correlation is deterministic and runs before planning: which case a
        // message belongs to is a matter of fact, settled by a lookup.
        let case_ctx = match (case, self.cases.as_ref()) {
            (Some(CaseBinding::Correlate { kind, keys }), Some(cases)) => {
                let correlation = cases
                    .correlate_or_open(&kind, &keys, now_for_admission())
                    .await
                    .map_err(RuntimeError::from_store)?;
                let case_id = correlation.case_id();
                cases
                    .attach_run(case_id, run)
                    .await
                    .map_err(RuntimeError::from_store)?;
                // The case's own keys, not the ones this message carried. A run
                // that *joined* an existing case may have been admitted with one
                // key while the case holds three, and a binding naming any of
                // them must resolve — which is the difference between "the keys
                // in this request" and "the business facts this matter is
                // identified by".
                let bound_keys = case_correlation(cases.as_ref(), case_id, &keys).await?;
                // Stamp the case on the records already queued as well: every
                // record of a case-bound run carries its case, which is what
                // makes "show me everything about this matter" one range scan.
                for r in &mut records {
                    r.case = Some(case_id);
                }
                records.push(
                    Append::new(
                        run,
                        RecordKind::CaseBound {
                            case_kind: kind,
                            opened: correlation.is_new(),
                            correlation: bound_keys.clone(),
                        },
                    )
                    .case(case_id),
                );
                Some(CaseContext {
                    cases: Arc::clone(cases),
                    tasks: self.tasks.clone(),
                    events: self.events.clone(),
                    calendar: Arc::clone(&self.calendar),
                    case_id,
                    correlation: bound_keys,
                })
            }
            (Some(CaseBinding::Existing(case_id)), Some(cases)) => {
                let existing = cases
                    .case(case_id)
                    .await
                    .map_err(RuntimeError::from_store)?
                    .ok_or_else(|| {
                        RuntimeError::PlanContract(format!("no such case: {case_id}"))
                    })?;
                if existing.status.is_closed() {
                    return Err(RuntimeError::PlanContract(format!(
                        "case '{case_id}' is closed and cannot accept another run"
                    )));
                }
                cases
                    .attach_run(case_id, run)
                    .await
                    .map_err(RuntimeError::from_store)?;
                for record in &mut records {
                    record.case = Some(case_id);
                }
                records.push(
                    Append::new(
                        run,
                        RecordKind::CaseBound {
                            case_kind: existing.kind,
                            opened: false,
                            correlation: existing.correlation.clone(),
                        },
                    )
                    .case(case_id),
                );
                Some(CaseContext {
                    cases: Arc::clone(cases),
                    tasks: self.tasks.clone(),
                    events: self.events.clone(),
                    calendar: Arc::clone(&self.calendar),
                    case_id,
                    correlation: existing.correlation,
                })
            }
            (Some(_), None) => {
                return Err(RuntimeError::PlanContract(
                    "this run was admitted with correlation keys but the runtime has no case \
                     store — build it with `.cases(store)`"
                        .into(),
                ));
            }
            (None, _) => None,
        };

        self.store
            .append(lease.epoch, records)
            .await
            .map_err(RuntimeError::from_store)?;

        // Registered before the run is handed back, and its failure fails
        // admission. A run that started with its destinations unregistered would
        // produce a history nothing is watching, and the events it missed are
        // unrecoverable without a scan nobody schedules — which is the exact
        // failure a durable outbox exists to remove, arriving one layer up.
        //
        // After the append rather than before: the cursor starts at sequence
        // one, so a registration written for a run whose admission then failed
        // would sit against an empty journal forever. The price of that order
        // is paid here instead: the admission records above are already
        // durable, so a registration failure must **conclude** the run rather
        // than merely return — an open journal under a lease that then lapses
        // is exactly what the recovery sweep reads as a crashed run, and it
        // would execute a run whose admission failed. Concluded `failed`, in
        // the chain, with the reason beside it; the caller's cleanup then
        // releases the lease.
        #[cfg(feature = "push")]
        if let Some(outbox) = &self.outbox
            && let Err(open_failed) = outbox.open(run).await
        {
            let head = self
                .store
                .head(run)
                .await
                .map_err(RuntimeError::from_store)?;
            self.store
                .append(
                    lease.epoch,
                    vec![
                        Append::new(
                            run,
                            RecordKind::Note {
                                text: format!(
                                    "admission failed after its records were written: the \
                                     outbox registration was refused ({open_failed}) — the \
                                     run is concluded failed and was never executed"
                                ),
                            },
                        ),
                        Append::new(
                            run,
                            RecordKind::RunSealed {
                                outcome: RunStatus::Failed(String::new()).as_str().to_owned(),
                                chain_head: head.hash,
                            },
                        ),
                    ],
                )
                .await
                .map_err(RuntimeError::from_store)?;
            return Err(RuntimeError::from_store(open_failed));
        }

        Ok(Admitted {
            run,
            epoch: lease.epoch,
            budget: self.budget_for(agent),
            agent: agent.to_owned(),
            plan,
            input,
            case: case_ctx,
        })
    }

    /// Execute a run that has already been admitted.
    async fn execute_admitted(&self, a: Admitted) -> Result<RunOutcome, RuntimeError> {
        let mut cursor = ReplayCursor::default();
        // Named, not `_`: `let _ = ` drops immediately, which would renew
        // nothing at all while looking exactly like this.
        let _heartbeat = self.heartbeat(a.run, a.epoch);
        self.execute(
            Execution {
                run: a.run,
                epoch: a.epoch,
                plan: &a.plan,
                input: a.input,
                mode: Mode::Live,
                case: a.case,
                budget: a.budget,
                agent: a.agent,
                refusal: None,
                successors: Vec::new(),
                started: BTreeSet::new(),
                finished: BTreeSet::new(),
            },
            &mut cursor,
        )
        .await
    }

    /// Admit and execute, which is what every blocking entry point does.
    ///
    /// The run id is the caller's rather than minted here, for batches: an
    /// item's run id is written to the batch store *before* the run starts, so
    /// that a crash leaves a reservation pointing at a journal that can be
    /// replayed rather than an item that must be guessed about.
    pub(crate) async fn admit_plan_as(
        &self,
        run: RunId,
        plan: PlanIR,
        input: Tainted<Value>,
        case: Option<CaseBinding>,
    ) -> Result<RunOutcome, RuntimeError> {
        let admitted = self.admit_only(run, plan, input, case).await?;
        self.execute_admitted(admitted).await
    }

    /// Ensure an open run cannot cross its history frontier under different
    /// authorization semantics than those recorded at admission.
    fn ensure_resume_policy_bundle(&self, records: &[Record]) -> Result<(), RuntimeError> {
        let recorded = records
            .iter()
            .find_map(|record| match record.kind() {
                RecordKind::RunAdmitted { policy_bundle, .. } => Some(policy_bundle.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                RuntimeError::PlanContract("journal has no RunAdmitted record".into())
            })?;
        let configured = self.policy.as_ref().map(|policy| policy.bundle());
        if recorded != configured {
            return Err(RuntimeError::PolicyBundleChanged {
                recorded: recorded.as_ref().map(PolicyBundleIdentity::digest),
                configured: configured.as_ref().map(PolicyBundleIdentity::digest),
            });
        }
        Ok(())
    }

    /// Re-execute a recorded run from its journal.
    ///
    /// * [`Mode::Strict`] verifies determinism: every effect must match, and the
    ///   run must not want any effect the journal lacks.
    /// * [`Mode::Resume`] recovers a crashed run: history is replayed, then
    ///   execution continues live from wherever the record ends.
    ///
    /// Either way no external effect is performed for anything already in the
    /// journal. That is the whole point — a resumed run does not re-issue the
    /// invoice it already issued.
    pub async fn replay(&self, run: RunId, mode: Mode) -> Result<RunOutcome, RuntimeError> {
        // ── Ownership before observation ───────────────────────────────────
        //
        // Resume writes, so it takes the lease *before* it reads. The old
        // order — snapshot the records, then acquire — left a window in which
        // a live owner could append past the snapshot; the resume then
        // replayed a prefix of the true history and continued live from a
        // frontier that was not the frontier, re-deriving keys the owner had
        // already written. Claiming first means the snapshot below is taken
        // under this instance's own fence. Strict verifies and never writes,
        // so it needs no lease — and must not take one, or every regression
        // check would fence a run somebody may be legitimately running.
        let lease = if mode == Mode::Resume {
            Some(
                self.store
                    .acquire(run, &self.owner, self.lease_ttl)
                    .await
                    .map_err(RuntimeError::from_store)?,
            )
        } else {
            None
        };

        let outcome = self.replay_under(run, mode, lease.as_ref()).await;

        // Idempotent: a resume that reached execution already handed its lease
        // back in `conclude`, and re-releasing the same epoch changes nothing.
        // What this covers is every path that returns *before* executing — a
        // closed run's no-op, a refused resume, an unverifiable chain — which
        // would otherwise strand the freshly claimed lease until it expired
        // and the recovery sweep "recovered" a run nobody was running.
        if let Some(lease) = &lease
            && let Err(e) = self.store.release_lease(run, lease.epoch).await
        {
            tracing::debug!(
                %run,
                error = %e,
                "could not hand back the resume lease; it will expire on its own"
            );
        }
        outcome
    }

    async fn replay_under(
        &self,
        run: RunId,
        mode: Mode,
        lease: Option<&crate::journal::Lease>,
    ) -> Result<RunOutcome, RuntimeError> {
        let records = self
            .store
            .read(run, 1)
            .await
            .map_err(RuntimeError::from_store)?;
        if records.is_empty() {
            return Err(RuntimeError::Store(crate::core::StoreError::NotFound(
                run.to_string(),
            )));
        }

        // Never trust a journal that does not verify. A tampered or truncated
        // history would let replay "confirm" something that never happened.
        //
        // Per-record hashes are already checked on read, so a single altered
        // record fails before we get here; this catches the structural attacks
        // that survive individually-valid records — deletion, reordering, and
        // splicing history from another run.
        Record::verify_chain(&records, Digest::ZERO).map_err(RuntimeError::from_store)?;

        ensure_replayable_canon(&records)?;

        let input = records.iter().find_map(recorded_input).ok_or_else(|| {
            RuntimeError::PlanContract("journal has no RunAdmitted record".into())
        })?;

        // The plan is read back from history rather than recompiled. Recompiling
        // could produce a different graph — a changed manifest, a different
        // router — and replay would then verify a run against a plan that never
        // governed it.
        let plan: PlanIR = records
            .iter()
            .find_map(|r| match r.kind() {
                RecordKind::PlanFrozen { plan, .. } => Some(plan.clone()),
                _ => None,
            })
            .ok_or_else(|| RuntimeError::PlanContract("journal has no PlanFrozen record".into()))
            .and_then(|v| serde_json::from_value(v).map_err(RuntimeError::Encoding))?;

        // A succeeded or quarantined run must not be resumed — see
        // `resume_is_closed`. Strict mode still re-executes, because
        // verification is the point there and it writes nothing.
        if mode == Mode::Resume
            && let Some(recorded) = resume_is_closed(&records)
        {
            let head = self
                .store
                .head(run)
                .await
                .map_err(RuntimeError::from_store)?;
            return Ok(RunOutcome {
                run_id: run,
                status: recorded,
                chain_head: head.hash,
                output: None,
                // Re-reading a closed run performs nothing, so it consumes
                // nothing. The spend belongs to the pass that did the work and
                // is on that run's records, not re-attributed on every read.
                spend: Spend::default(),
            });
        }

        // A run whose journal holds compensation-phase records is not
        // resumable once it stands concluded. The unwind *reversed* work — a
        // hold released, a refund issued — and a resume that replays the
        // forward history and continues would conclude success over a world
        // where the work was undone: the journal would say "done" about
        // effects its own later records say were taken back. Scoped to runs
        // with a standing conclusion, deliberately: a run that is mid-unwind
        // (a compensation suspended for four eyes, a crash between reversals)
        // has concluded nothing, and resuming it is how the unwind finishes.
        if mode == Mode::Resume
            && let Some(outcome) = recorded_conclusion(&records)
            && records
                .iter()
                .any(|r| matches!(r.kind(), RecordKind::StepCompensated { .. }))
        {
            return Err(RuntimeError::PlanContract(format!(
                "run {run} concluded '{outcome}' after compensating completed steps — \
                 the work was reversed, and resuming over undone work would report \
                 success about a world where it no longer stands. Start a fresh run"
            )));
        }

        // Resume can dispatch new effects after it reaches the end of history.
        // They must be judged by the same complete bundle recorded at
        // admission, or one run would claim one policy while later effects were
        // authorized by another. Strict replay performs no effects and remains
        // usable as an offline verifier without loading the historical engine.
        if mode == Mode::Resume {
            self.ensure_resume_policy_bundle(&records)?;
        }

        let case_ctx = self.recorded_case(&records);

        let mut cursor = ReplayCursor::from_records(&records);

        // Strict verification must not write, and it does not: it holds no
        // lease, and appends happen only past the end of history, which
        // Strict mode refuses to reach. Resume writes under the lease it
        // claimed before reading.
        let epoch = lease.map_or_else(|| records.last().map_or(1, |r| r.body.epoch), |l| l.epoch);

        // Strict verification never writes, so it holds no lease to renew.
        let _heartbeat = lease.map(|l| self.heartbeat(run, l.epoch));
        self.execute(
            Execution {
                run,
                epoch,
                plan: &plan,
                input,
                mode,
                case: case_ctx,
                budget: {
                    // The agent recorded at admission, so a replay is bounded by
                    // the ceilings the run actually had.
                    let recorded = recorded_agent(&records);
                    self.budget_for(&recorded)
                },
                agent: recorded_agent(&records),
                // A step-level refusal has no effect key, so it cannot ride the
                // replay cursor like an effect's does. It is lifted here from
                // the records `replay` has already read.
                refusal: recorded_step_refusal(&records),
                // Every `PlanFrozen` after the first is a successor this run
                // produced. Replay walks them in the order they were made.
                successors: records
                    .iter()
                    .filter_map(|r| match r.kind() {
                        RecordKind::PlanFrozen { plan, .. } => {
                            serde_json::from_value::<PlanIR>(plan.clone()).ok()
                        }
                        _ => None,
                    })
                    .skip(1)
                    .collect(),
                started: recorded_started_steps(&records),
                finished: recorded_finished_steps(&records),
            },
            &mut cursor,
        )
        .await
    }

    /// The trace root. Every span below is a child, so "what did this run do"
    /// is one query rather than a correlation exercise across logs.
    ///
    /// Instrumented rather than entered: an `Entered` guard held across an
    /// `.await` belongs to the thread, and with concurrent dispatch that
    /// reparents whatever runs next onto this span.
    async fn execute(
        &self,
        plan: Execution<'_>,
        cursor: &mut ReplayCursor,
    ) -> Result<RunOutcome, RuntimeError> {
        let span = tracing::info_span!(
            telemetry::RUN_SPAN,
            { telemetry::GEN_AI_OPERATION } = telemetry::GEN_AI_INVOKE_AGENT,
            { telemetry::RUN_ID } = tracing::field::display(plan.run),
            { telemetry::MODE } = telemetry::mode_str(plan.mode),
            { telemetry::CASE_ID } = plan
                .case
                .as_ref()
                .map(|c| super::ctx::CaseContext::id(c).to_string()),
            { telemetry::OUTCOME } = tracing::field::Empty,
            semconv = telemetry::SEMCONV_VERSION,
        );
        self.execute_inner(plan, cursor).instrument(span).await
    }

    /// The driver loop: ready set, admit, dispatch, apply, repeat.
    ///
    /// Long by line count and deliberately not split further. Every *step* is
    /// already its own method — `admit_ready`, `dispatch`, `collect`, `apply`,
    /// `adopt_successor`, `stop`. What is left is the order they happen in, and
    /// that order is the algorithm. Breaking it up again would scatter one
    /// readable sequence across functions that exist only to satisfy a line
    /// count, which is the opposite of the thing the lint is protecting.
    #[allow(clippy::too_many_lines)]
    async fn execute_inner(
        &self,
        plan: Execution<'_>,
        cursor: &mut ReplayCursor,
    ) -> Result<RunOutcome, RuntimeError> {
        let Execution {
            run,
            epoch,
            plan: ir,
            input,
            mode,
            case,
            budget,
            agent,
            refusal: recorded_refusal,
            successors,
            started,
            finished,
        } = plan;
        let writing = !matches!(mode, Mode::Strict);
        let case_id = case.as_ref().map(super::ctx::CaseContext::id);
        let stamp = |a: Append| match case_id {
            Some(c) => a.case(c),
            None => a,
        };

        // The plan in force. Owned rather than borrowed, because a replan
        // replaces it and a reference into the version list could not
        // survive that. `recorded_successors` is empty on a live run and seeded
        // from the journal on a replay, so a successor is read back rather than
        // re-synthesised.
        let mut current: PlanIR = ir.clone();
        let mut replans: u32 = 0;
        let recorded_successors = successors;

        // One ledger for the run. A step never gets its own allowance to blow.
        let ledger = Arc::new(std::sync::Mutex::new(Ledger::new(budget)));

        // Steps already completed, and what they produced. Rebuilt from the
        // journal on replay so a resumed run knows where it got to.
        let mut done: BTreeSet<StepId> = BTreeSet::new();

        // The same steps as `done`, in the order they finished, **with the
        // capability that actually ran**. Unwinding needs both: a set has no
        // order to reverse, and after a replan the current plan may have
        // different work — or nothing at all — at a completed step's id.
        // Resolving the compensation from the live plan then undoes something
        // that never ran, which is a refund for a charge nobody made.
        let mut completed: Vec<(StepId, Capability)> = Vec::new();
        let mut outputs: BTreeMap<StepId, Tainted<Value>> = BTreeMap::new();

        // ── Ready-set scheduling ───────────────────────────────────────────
        //
        // Dispatch order is a deterministic total order (topological rank, then
        // id), so replay reproduces it exactly. A plan with parallelism that
        // dispatched in completion order would replay differently every time.
        loop {
            // ── The stop check, at a step boundary and nowhere else ────────
            //
            // Between boundaries an effect may be announced and not yet
            // recorded, and interrupting there manufactures the in-doubt case
            // the whole protocol exists to avoid. Checking here costs one
            // store read per ready set and buys a cancellation that can never
            // strand an effect.
            //
            // Skipped while replaying: a recorded run's history already
            // contains whatever stop it received, and re-reading the live
            // request would let a cancellation arriving *today* rewrite what a
            // run did last year.
            if writing
                && let Some(c) = self
                    .store
                    .cancellation(run)
                    .await
                    .map_err(RuntimeError::from_store)?
            {
                let status = RunStatus::Cancelled {
                    actor: c.actor.clone(),
                    reason: c.reason.clone(),
                };
                // Journaled *before* unwinding, so the reason the run stopped is
                // in the chain even if compensation then fails and quarantines
                // it. An operator reading a half-unwound run must be able to see
                // that somebody asked for this.
                self.store
                    .append(
                        epoch,
                        vec![stamp(Append::new(
                            run,
                            RecordKind::RunCancelled {
                                actor: c.actor,
                                reason: c.reason,
                            },
                        ))],
                    )
                    .await
                    .map_err(RuntimeError::from_store)?;
                return self
                    .stop(
                        Unwind {
                            agent: &agent,
                            run,
                            epoch,
                            ir: &current,
                            mode,
                            case: case.clone(),
                            ledger: &ledger,
                            writing,
                            stamp: &stamp,
                        },
                        status,
                        &completed,
                        &outputs,
                        cursor,
                        case_id,
                    )
                    .await;
            }

            let ready = current.ready(&done);
            if ready.is_empty() {
                break;
            }

            // Admission first, and deliberately not concurrent: which step a
            // ceiling refuses must be a property of the plan, not of which
            // future happened to poll first.
            let (admitted, refused) = self
                .admit_ready(
                    &ready,
                    &ledger,
                    mode,
                    recorded_refusal.as_ref(),
                    cursor,
                    Journalling {
                        run,
                        epoch,
                        writing,
                        stamp: &stamp,
                    },
                )
                .await?;

            let dispatched = self
                .dispatch(
                    &admitted,
                    cursor,
                    Batch {
                        agent: &agent,
                        run,
                        epoch,
                        ir: &current,
                        mode,
                        case: &case,
                        ledger: &ledger,
                        writing,
                        stamp: &stamp,
                        input: &input,
                        outputs: &outputs,
                        started: &started,
                        finished: &finished,
                    },
                )
                .await;
            let outcomes = collect(dispatched, &ready, cursor)?;

            // ── Strict verification consumes everything, per step ──────────
            //
            // Divergence has two directions, and the ordered key comparison
            // only sees one of them. A build that asks for a *different*
            // effect fails at the mismatch; a build that asks for **fewer**
            // effects than the record sails past the remainder and would
            // report the step verified — a false confirmation about exactly
            // the history a verification pass exists to check. So a step that
            // finished with journaled effects still unread is the same
            // quarantine-grade finding as a key mismatch, named by the first
            // effect nothing requested.
            if mode == Mode::Strict {
                for &(step, ref status, _) in &outcomes {
                    // A step that stopped — suspended, failed, refused — ended
                    // where its history says it ended, and the stop itself is
                    // the verified finding. Only a step that claims to have
                    // *finished* owes a fully consumed slice.
                    if !matches!(status, RunStatus::Succeeded) {
                        continue;
                    }
                    if let Some(key) = cursor.unconsumed_in(step, Phase::Forward) {
                        self.meter.count(metrics::DIVERGENCES, "");
                        tracing::error!(
                            target: telemetry::NONDETERMINISM,
                            %step, %key, unconsumed = true,
                        );
                        return self
                            .conclude(
                                run,
                                epoch,
                                RunStatus::Quarantined(format!(
                                    "strict replay verified less than the run recorded: \
                                     step {step} finished with journaled effect {key} never \
                                     requested — this build performs fewer effects than the \
                                     recorded one"
                                )),
                                None,
                                writing,
                                case_id,
                                Spend::default(),
                            )
                            .await;
                    }
                }
            }

            // A step that stops for any reason stops the run: whatever remains
            // either depended on it, or will be dispatched when it resumes.
            // Anything already done may need undoing first.
            let mut stopped = apply(&current, outcomes, &mut done, &mut completed, &mut outputs)
                .or(refused.map(RunStatus::Exhausted));

            if let Some(RunStatus::Replanning(reason)) = &stopped {
                let recorded = recorded_successors.get(replans as usize);
                let journal = Journalling {
                    run,
                    epoch,
                    writing: writing && recorded.is_none(),
                    stamp: &stamp,
                };
                let cx = Replan {
                    current: &current,
                    reason,
                    already_replanned: replans,
                    max_replans: budget.max_replans,
                    recorded,
                };
                match self
                    .adopt_successor(cx, journal, &outputs, &completed)
                    .await?
                {
                    Ok(next) => {
                        replans += 1;
                        current = next;
                        continue;
                    }
                    Err(refusal) => stopped = Some(refusal),
                }
            }

            if let Some(status) = stopped {
                return self
                    .stop(
                        Unwind {
                            agent: &agent,
                            run,
                            epoch,
                            ir: &current,
                            mode,
                            case: case.clone(),
                            ledger: &ledger,
                            writing,
                            stamp: &stamp,
                        },
                        status,
                        &completed,
                        &outputs,
                        cursor,
                        case_id,
                    )
                    .await;
            }
        }

        // ── Strict verification consumes everything, at the end ────────────
        //
        // The per-batch check above covers steps this build dispatched; this
        // covers the ones it never asked for at all — a step a changed guard
        // now skips, a compensation slice nothing requested. Either way the
        // record holds work this build cannot account for, and "verified" must
        // not be the answer.
        if mode == Mode::Strict
            && let Some((step, phase, key)) = cursor.first_unconsumed()
        {
            self.meter.count(metrics::DIVERGENCES, "");
            tracing::error!(
                target: telemetry::NONDETERMINISM,
                %step, %key, unconsumed = true,
            );
            return self
                .conclude(
                    run,
                    epoch,
                    RunStatus::Quarantined(format!(
                        "strict replay verified less than the run recorded: journaled \
                         effect {key} (step {step}, {phase:?} phase) was never requested \
                         — this build performs fewer effects than the recorded one"
                    )),
                    None,
                    writing,
                    case_id,
                    Spend::default(),
                )
                .await;
        }

        // Read into a value first. A `MutexGuard` built inline as an argument
        // lives until the end of the full expression — which here is *after*
        // the await — so the lock would be held across a suspension. That is
        // the same shape as the `Span::enter()` bug: a guard whose
        // scope is wider than it looks, and invisible until something else
        // needs the lock.
        let spend = ledger.lock().expect("budget mutex").consumed().spend;
        self.conclude(
            run,
            epoch,
            completion(&current, &done),
            run_output(&current, &outputs),
            writing,
            case_id,
            spend,
        )
        .await
    }

    /// Run a ready set concurrently.
    ///
    /// The ready set is every node whose predecessors are done and whose guards
    /// hold, so nothing in it depends on anything else in it — running them one
    /// at a time is a choice, and the wrong one when steps are waiting on models
    /// and networks.
    ///
    /// Each step takes its own slice of history, which is what makes this sound:
    /// a step touches only its own effects, so no shared mutable state is left
    /// between them, and the per-step replay cursor verifies each one's order
    /// independently of how the journal happened to interleave them.
    async fn dispatch(
        &self,
        admitted: &[StepId],
        cursor: &mut ReplayCursor,
        batch: Batch<'_>,
    ) -> Vec<Dispatched> {
        let slices: Vec<(StepId, StepCursor)> = admitted
            .iter()
            .map(|&s| (s, cursor.take(s, Phase::Forward)))
            .collect();

        futures_util::future::join_all(slices.into_iter().map(|(step, slice)| async move {
            let node = batch
                .ir
                .node(step)
                .ok_or_else(|| RuntimeError::PlanContract(format!("no node {step}")))?;
            let (status, out, slice) = self
                .run_step(
                    StepRun {
                        agent: batch.agent,
                        run: batch.run,
                        epoch: batch.epoch,
                        node,
                        phase: Phase::Forward,
                        mode: batch.mode,
                        case: batch.case.clone(),
                        ledger: batch.ledger,
                        writing: batch.writing,
                        stamp: batch.stamp,
                        already_started: batch.started.contains(&step),
                        already_finished: batch.finished.contains(&step),
                    },
                    batch.input,
                    batch.outputs,
                    slice,
                )
                .await?;
            Ok((step, status, out, slice))
        }))
        .await
    }

    /// Take the successor a step asked for: check it, record it, announce it.
    ///
    /// The nested result separates two failures. The outer `RuntimeError` is the
    /// runtime itself failing — the journal would not accept the plan — and is
    /// never recoverable. The inner `RunStatus` is the *request* being refused,
    /// which is an ordinary outcome the run reports.
    async fn adopt_successor(
        &self,
        cx: Replan<'_>,
        journal: Journalling<'_>,
        outputs: &BTreeMap<StepId, Tainted<Value>>,
        completed: &[(StepId, Capability)],
    ) -> Result<Result<PlanIR, RunStatus>, RuntimeError> {
        let next = match self.successor(cx, outputs, completed).await {
            Ok(next) => next,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if journal.writing {
            self.freeze(journal.run, journal.epoch, &next, journal.stamp)
                .await?;
        }
        announce_replan(
            &self.meter,
            journal.run,
            &next,
            next.reason.as_deref().unwrap_or(""),
        );
        Ok(Ok(next))
    }

    /// Record a plan version in the journal.
    ///
    /// A successor is frozen exactly as a first plan is, so replay reads it back
    /// rather than asking a planner that may since have changed its mind.
    async fn freeze(
        &self,
        run: RunId,
        epoch: u64,
        plan: &PlanIR,
        stamp: &(dyn Fn(Append) -> Append + Send + Sync),
    ) -> Result<(), RuntimeError> {
        self.store
            .append(
                epoch,
                vec![stamp(Append::new(
                    run,
                    RecordKind::PlanFrozen {
                        steps: plan.nodes.iter().map(|n| n.capability.0.clone()).collect(),
                        plan: serde_json::to_value(plan)?,
                    },
                ))],
            )
            .await
            .map_err(RuntimeError::from_store)?;
        Ok(())
    }

    /// Produce the successor plan a step asked for, or say why not.
    ///
    /// Three gates, and the first is not negotiable.
    ///
    /// **Provenance.** The frozen plan is an authorization graph compiled from
    /// trusted input only. A replan *changes that graph*, so once any
    /// untrusted value has reached working memory, anything shaping the new plan
    /// may be attacker-chosen — and choosing the authorization graph is the
    /// whole game. `plan-then-execute` is enforced here, structurally. A run
    /// that wants a different plan after reading untrusted input is describing
    /// exactly the attack.
    ///
    /// **Budget.** A run that replans without bound has stopped making progress
    /// and started thrashing.
    ///
    /// **On replay, the successor is read back, never re-synthesised.** A
    /// planner asked twice can answer differently — a changed router, a
    /// different model — and replay would then verify the run against a plan
    /// that never governed it. Same rule as the first plan, for the same
    /// reason.
    async fn successor(
        &self,
        cx: Replan<'_>,
        outputs: &BTreeMap<StepId, Tainted<Value>>,
        completed: &[(StepId, Capability)],
    ) -> Result<PlanIR, RunStatus> {
        if let Some(source) = untrusted_in(outputs) {
            return Err(RunStatus::Failed(format!(
                "replanning refused: untrusted data from {source} is already in                  working memory, and the plan is an authorization graph —                  letting it change now would let that data choose what runs                  next ({})",
                cx.reason
            )));
        }

        let spent = cx.already_replanned;
        if let Some(max) = cx.max_replans
            && spent >= max
        {
            return Err(RunStatus::Exhausted(crate::core::BudgetExceeded::Replans {
                allowed: max,
            }));
        }

        // Replay: the successor is in the journal, at the position this replan
        // reached. Reading it back is what keeps a re-planned run replayable.
        if let Some(recorded) = cx.recorded {
            return Ok(recorded.clone());
        }

        let replanner = self.replanner.as_ref().ok_or_else(|| {
            RunStatus::Failed(format!(
                "a step asked to replan and this runtime has no planner — build                  it with `.replanner(..)` ({})",
                cx.reason
            ))
        })?;

        let next = replanner
            .replan(cx.current, cx.reason, completed)
            .await
            .map_err(|e| RunStatus::Failed(format!("replanning failed: {e}")))?;

        // A successor faces the same contract a first plan does. One that fails
        // validation stops the run rather than half-applying.
        crate::plan::validate(&next, &self.contract())
            .map_err(|e| RunStatus::Failed(format!("the successor plan is invalid: {e}")))?;

        // A completed step's id may not be reused for different work. Effect
        // keys are derived from the step id, so new work at a used id makes the
        // run unreplayable — and the saga, which undoes what `completed` says
        // ran, would compensate something that never happened.
        for (step, ran) in completed {
            if let Some(node) = next.node(*step)
                && node.capability != *ran
            {
                return Err(RunStatus::Failed(format!(
                    "the successor plan reuses step {step} — which already ran \
                     as '{}' — for '{}'. Keep a completed step's capability or \
                     leave the step out; effect keys are derived from the step \
                     id, so new work at a used id cannot be replayed",
                    ran.0, node.capability.0
                )));
            }
        }

        if next.derived_from != Some(cx.current.digest()) {
            return Err(RunStatus::Failed(
                "the successor plan does not name its predecessor — use                  `PlanIR::succeed_with`, or the audit trail has a hole where the                  lineage should be"
                    .into(),
            ));
        }

        Ok(next)
    }

    /// Decide which of a ready set may start, in ready order.
    ///
    /// Three regimes, one per mode, and the middle one is the subtle case:
    ///
    /// * **Strict** consumes recorded verdicts and recomputes none. A run
    ///   replayed under a larger budget stopped where it stopped; recomputing
    ///   made a step-limited run replay as *succeeded* — a false audit result.
    /// * **Resume** takes each verdict from wherever the truth lives. A step
    ///   with unconsumed history was admitted by the run that recorded it,
    ///   and the history *is* the verdict. A step at the frontier is about to
    ///   run **live**, and every live step is metered — keying this on "is
    ///   the mode a replay" instead of "will this step dispatch live" let a
    ///   resumed run cross `max_steps` unmetered for as long as it kept
    ///   running. A *recorded refusal* is re-evaluated against the ledger now
    ///   in force: exhaustion is a pause, and raising the ceiling and
    ///   resuming is how it un-pauses.
    /// * **Live** asks the ledger, which is the ordinary case.
    async fn admit_ready(
        &self,
        ready: &[StepId],
        ledger: &Arc<std::sync::Mutex<Ledger>>,
        mode: Mode,
        recorded: Option<&(StepId, String, String)>,
        cursor: &ReplayCursor,
        journal: Journalling<'_>,
    ) -> Result<(Vec<StepId>, Option<crate::core::BudgetExceeded>), RuntimeError> {
        let mut admitted = Vec::new();

        for &step in ready {
            // ── A recorded step refusal at this step ───────────────────────
            if let Some((at, limit, used)) = recorded
                && *at == step
            {
                if mode == Mode::Strict {
                    // Verbatim: the recorded run stopped here, and a
                    // verification pass reaches the same conclusion without
                    // consulting today's ledger.
                    return Ok((
                        admitted,
                        Some(crate::core::BudgetExceeded::Recorded {
                            limit: limit.clone(),
                            used: used.clone(),
                        }),
                    ));
                }
                // Resume: the replayed prefix has already billed the journaled
                // historical usage into this ledger, so the question is "does
                // the budget now in force admit one more step over what the
                // run already spent". Still no → the run concludes exhausted
                // again, and the standing refusal already says so — no second
                // record. Yes → the re-admission is its own record, beside
                // the refusal it supersedes, so a strict replay of this
                // history reads refusal-then-continuation as a decision
                // somebody made rather than as divergence.
                if let Err(exceeded) = ledger.lock().expect("budget mutex").admit_step() {
                    return Ok((admitted, Some(exceeded)));
                }
                if journal.writing {
                    self.store
                        .append(
                            journal.epoch,
                            vec![(journal.stamp)(
                                Append::new(
                                    journal.run,
                                    RecordKind::BudgetReadmitted {
                                        limit: limit.clone(),
                                    },
                                )
                                .step(step),
                            )],
                        )
                        .await
                        .map_err(RuntimeError::from_store)?;
                }
                admitted.push(step);
                continue;
            }

            let verdict = match mode {
                Mode::Strict => Ok(()),
                Mode::Resume if !cursor.exhausted(step, Phase::Forward) => Ok(()),
                Mode::Live | Mode::Resume => ledger.lock().expect("budget mutex").admit_step(),
            };

            let Err(exceeded) = verdict else {
                admitted.push(step);
                continue;
            };

            if journal.writing {
                // The refusal goes in the journal under the step it refused, so
                // replay reads the verdict rather than recomputing it.
                let used = format!("{:?}", ledger.lock().expect("budget mutex").consumed());
                self.store
                    .append(
                        journal.epoch,
                        vec![(journal.stamp)(
                            Append::new(
                                journal.run,
                                RecordKind::BudgetRefused {
                                    limit: exceeded.to_string(),
                                    used,
                                },
                            )
                            .step(step),
                        )],
                    )
                    .await
                    .map_err(RuntimeError::from_store)?;
            }
            return Ok((admitted, Some(exceeded)));
        }

        Ok((admitted, None))
    }

    /// End a run that stopped early: undo what warrants undoing, then seal.
    ///
    /// Both places a run can stop short go through here, so the unwind can never
    /// be attached to one of them and forgotten on the other.
    #[allow(clippy::too_many_arguments)]
    async fn stop(
        &self,
        cx: Unwind<'_>,
        status: RunStatus,
        completed: &[(StepId, Capability)],
        outputs: &BTreeMap<StepId, Tainted<Value>>,
        cursor: &mut ReplayCursor,
        case_id: Option<crate::core::CaseId>,
    ) -> Result<RunOutcome, RuntimeError> {
        let (run, epoch, writing, ir) = (cx.run, cx.epoch, cx.writing, cx.ir);
        let output = run_output(ir, outputs);
        // Cloned before `maybe_unwind` consumes `cx`; read *after* it, because an
        // item's cost is what the whole attempt consumed, compensation included.
        let ledger = cx.ledger.clone();
        let unwound = self
            .maybe_unwind(cx, status, completed, outputs, cursor)
            .await?;
        // Scoped before the await — see `execute_inner` on why an inline guard
        // outlives the call it is passed to.
        let spend = ledger.lock().expect("budget mutex").consumed().spend;
        self.conclude(run, epoch, unwound, output, writing, case_id, spend)
            .await
    }

    /// Undo the completed steps, if the way the run stopped calls for it.
    ///
    /// # When a run does *not* unwind
    ///
    /// * **Quarantined.** The run holds an effect whose outcome is unknown, and
    ///   you cannot safely undo around one: compensating a payment that may
    ///   never have gone out creates a refund for money nobody took. Everything
    ///   stays exactly where it is until a human decides. This is the rule that
    ///   separates a saga that is honest about distributed systems from one that
    ///   tidies up and hopes.
    /// * **Suspended.** The run is healthy and waiting. Nothing has failed.
    ///
    /// A failure *after the pivot* also stops the unwind at the pivot: once the
    /// business has committed, reversing the decisions leading up to it would
    /// contradict something the outside world has already acted on.
    ///
    /// # Two rules that apply only to a stop
    ///
    /// **It must not unwind around an unknown outcome.** The same rule quarantine
    /// already enforces, applied to the door cancellation opened. Scoped to
    /// cancellation deliberately: an ordinary failure that leaves an orphan is
    /// not stuck — the announcement is journaled, the effect declared a
    /// `Recovery`, and resuming resolves it. Quarantining there would turn every
    /// recoverable orphan into a permanent operator obligation. A cancelled run
    /// gets no second pass, so an unresolved outcome stays unresolved.
    ///
    /// **It must undo the step it interrupted.** Compensation walks *completed*
    /// steps, which is right for a failure. A stop arrives from outside while a
    /// step is typically suspended — holding effects it performed and never
    /// completing — so unwinding only completed steps would leave exactly the
    /// work the operator was stopping: a run that posted to a ledger and then
    /// suspended for approval would "stop" with the posting still standing.
    async fn maybe_unwind(
        &self,
        cx: Unwind<'_>,
        status: RunStatus,
        completed: &[(StepId, Capability)],
        outputs: &BTreeMap<StepId, Tainted<Value>>,
        cursor: &mut ReplayCursor,
    ) -> Result<RunStatus, RuntimeError> {
        match status {
            // A cancelled run unwinds exactly as a failed one does. Stopping a
            // run that has already moved money and leaving the movement in
            // place is not stopping it — and the operator who asked is entitled
            // to assume "stop" means the world is put back, not that the
            // process merely exited.
            //
            // **Exhausted is deliberately not here.** Exhaustion is a pause,
            // not a fault: the run did what it was told, and what it was told
            // included a ceiling. Its mutations stand, because the operator's
            // two honest options both need them standing — raise the ceiling
            // and resume (which continues *over* the completed work), or
            // cancel (which unwinds through this same function under a status
            // that does). Unwinding on exhaustion made the three ends of an
            // exhausted run contradict each other: the work was reversed, the
            // run stayed resumable, and the resume then reported success over
            // a world where the work no longer stood.
            RunStatus::Failed(_) | RunStatus::Cancelled { .. } => {}
            other => return Ok(other),
        }

        // Which steps actually changed something outside. Read from the journal
        // rather than tracked in memory: it is the same evidence live and on
        // replay, and it is what lets an *undeclared* step be judged on what it
        // did instead of on what nobody said about it.
        let (mutated, already_undone) = self.unwind_evidence(cx.run).await?;

        // Both stop-only rules, in one place — see the doc comment.
        let extended;
        let completed = if status.is_cancelled() {
            match self
                .stop_list(cx.run, completed, cx.ir, &mutated, &already_undone)
                .await?
            {
                Ok(list) => {
                    extended = list;
                    &extended[..]
                }
                Err(quarantine) => return Ok(quarantine),
            }
        } else {
            completed
        };

        for (step, capability) in completed.iter().rev().cloned() {
            // Resolved from what ran, not from the plan in force. After a replan
            // the two can differ, and undoing whatever now occupies that slot is
            // how a saga compensates work that never happened.
            let skill = self.resolve(&capability.0)?;
            let declared = skill.compensation();

            match declared {
                // The point of no return. Everything from here back stays.
                crate::core::Compensation::Pivot => break,
                crate::core::Compensation::Unnecessary => continue,
                crate::core::Compensation::Undeclared => {
                    if !mutated.contains(&step) {
                        // Nothing to undo, and the journal proves it.
                        continue;
                    }
                    return Ok(RunStatus::Quarantined(format!(
                        "step {step} ('{}') changed external state and declares no \
                         compensation, so the run cannot be safely unwound — \
                         declare Compensation on it, or resolve this by hand",
                        capability.0
                    )));
                }
                crate::core::Compensation::Compensatable => {}
            }

            let result = self
                .run_compensation(&cx, step, skill.as_ref(), outputs, cursor)
                .await;

            // A compensation may legitimately need to wait — a refund that needs
            // four eyes is still a refund. Suspension is not failure: the run is
            // healthy, its frame is durable, and it will finish unwinding when
            // the answer arrives.
            //
            // Reported as a failure in an earlier version, which quarantined a
            // run that was doing exactly the right thing and told the operator
            // the compensation had broken.
            if let Err(crate::core::SkillError::Step(crate::core::StepError::Suspended(reason))) =
                &result
            {
                return Ok(RunStatus::Suspended(reason.clone()));
            }

            let outcome = match &result {
                Ok(()) => "compensated".to_owned(),
                Err(e) => e.to_string(),
            };

            // Re-run but do not re-record. On resume the compensation executes
            // again with every effect served from the journal, which is what
            // keeps strict verification meaningful — but a second
            // `StepCompensated` would report one compensation as two.
            if result.is_ok() {
                tracing::info!(target: telemetry::COMPENSATED, run = %cx.run, %step);
                self.meter.count(metrics::COMPENSATIONS, "done");
            }
            if cx.writing && !already_undone.contains(&step) {
                self.store
                    .append(
                        cx.epoch,
                        vec![(cx.stamp)(
                            Append::new(
                                cx.run,
                                RecordKind::StepCompensated {
                                    compensation: declared,
                                    outcome: outcome.clone(),
                                },
                            )
                            .step(step)
                            .phase(Phase::Compensating),
                        )],
                    )
                    .await
                    .map_err(RuntimeError::from_store)?;
            }

            if result.is_err() {
                tracing::error!(
                    target: telemetry::COMPENSATION_FAILED,
                    run = %cx.run,
                    %step,
                    detail = %outcome,
                );
                self.meter.count(metrics::COMPENSATIONS, "failed");
                // Not a problem more compensation solves. Unwinding further
                // would undo steps *before* one that is now in an unknown
                // state, which is strictly worse than stopping and saying so.
                return Ok(RunStatus::Quarantined(format!(
                    "compensation failed for step {step} ('{}'): {outcome} — the run is \
                     partially unwound and needs an operator",
                    capability.0
                )));
            }
        }

        Ok(status)
    }

    /// What the journal knows about an unwind before it starts:
    /// `(steps that changed something, steps already compensated)`.
    ///
    /// Evidence, not bookkeeping. The journal already knows both, it knows the
    /// same thing on replay, and nothing has to be threaded through the executor
    /// to keep a parallel copy honest.
    async fn unwind_evidence(
        &self,
        run: RunId,
    ) -> Result<(BTreeSet<StepId>, BTreeSet<StepId>), RuntimeError> {
        let records = self
            .store
            .read(run, 1)
            .await
            .map_err(RuntimeError::from_store)?;

        let mut mutated = BTreeSet::new();
        let mut undone = BTreeSet::new();
        for r in &records {
            let Some(step) = r.body.step else { continue };
            match r.kind() {
                RecordKind::EffectStarted { mutates: true, .. } if r.body.phase.is_forward() => {
                    mutated.insert(step);
                }
                RecordKind::StepCompensated { .. } => {
                    undone.insert(step);
                }
                _ => {}
            }
        }
        Ok((mutated, undone))
    }

    /// Run one step's `compensate`, in its own phase and cursor slice.
    ///
    /// Split out so the unwind reads as the policy it is. The step gets a full
    /// `StepCtx` on purpose: compensating effects are journaled, retried,
    /// reconciled and replayed exactly like forward ones, and may suspend for a
    /// human — a refund that needs four eyes is still a refund.
    async fn run_compensation(
        &self,
        cx: &Unwind<'_>,
        step: StepId,
        skill: &dyn Skill,
        outputs: &BTreeMap<StepId, Tainted<Value>>,
        cursor: &mut ReplayCursor,
    ) -> Result<(), crate::core::SkillError> {
        // A step with no recorded output still gets compensated: the absence of
        // a result says nothing about whether it changed anything, and the
        // compensation is what knows.
        let output = outputs
            .get(&step)
            .cloned()
            .unwrap_or_else(|| Tainted::trusted(Value::Null));

        let mut ctx = StepCtx::new(
            &self.store,
            cursor.take(step, Phase::Compensating),
            super::ctx::Frame {
                run: cx.run,
                epoch: cx.epoch,
                step,
                phase: Phase::Compensating,
                mode: cx.mode,
                case: cx.case.clone(),
                timers: self.timers.clone(),
                blobs: self.blobs.clone(),
                memories: self.memories.clone(),
                authorities: self.authorities.clone(),
                #[cfg(feature = "manifest")]
                tools: self.tools.clone(),
                meter: self.meter.clone(),
                #[cfg(feature = "keyring")]
                keyring: self.keyring.clone(),
                tenant: self.tenant.clone(),
                ledger: Arc::clone(cx.ledger),
                policy: self.policy.clone(),
                identity: self.identity.clone(),
                agent: cx.agent.to_owned(),
                plane: self.self_ref.clone(),
                #[cfg(feature = "manifest")]
                manifest: self.governing(skill),
                signer: self.signer.clone(),
            },
        );

        let result = skill.compensate(&mut ctx, &output).await;
        cursor.restore(step, Phase::Compensating, ctx.into_cursor());
        result
    }

    /// The unwind list for a stop, or the quarantine that replaces it.
    ///
    /// Both rules in `maybe_unwind`'s doc comment, applied in order: refuse
    /// outright if an outcome is unknown, otherwise extend the list with the
    /// step the stop interrupted.
    async fn stop_list(
        &self,
        run: RunId,
        completed: &[(StepId, Capability)],
        ir: &PlanIR,
        mutated: &BTreeSet<StepId>,
        undone: &BTreeSet<StepId>,
    ) -> Result<Result<Vec<(StepId, Capability)>, RunStatus>, RuntimeError> {
        if let Some(step) = self.undecided_effect(run).await? {
            return Ok(Err(RunStatus::Quarantined(format!(
                "step {step} holds a mutating effect whose outcome is unknown — it \
                 was announced and never concluded, or concluded in doubt with no \
                 reconciliation — so the run cannot be unwound: compensating around \
                 it would undo everything except the one thing nobody can account for"
            ))));
        }
        Ok(Ok(Self::with_interrupted_steps(
            completed, ir, mutated, undone,
        )))
    }

    /// The unwind list for a cancelled run: completed steps, plus the one it was
    /// stopped in.
    ///
    /// Only reachable through cancellation. An ordinary failure ends *at* the step
    /// that failed; a stop arrives from outside while a step is typically suspended
    /// — holding effects it already performed and never completing. The interrupted
    /// steps go last, so the caller's reverse walk undoes them first.
    fn with_interrupted_steps(
        completed: &[(StepId, Capability)],
        ir: &PlanIR,
        mutated: &BTreeSet<StepId>,
        undone: &BTreeSet<StepId>,
    ) -> Vec<(StepId, Capability)> {
        let mut out = completed.to_vec();
        let done: BTreeSet<StepId> = out.iter().map(|(s, _)| *s).collect();
        for step in mutated
            .iter()
            .filter(|s| !done.contains(s) && !undone.contains(s))
        {
            if let Some(node) = ir.node(*step) {
                out.push((*step, node.capability.clone()));
            }
        }
        out
    }

    /// A mutating effect that was announced and never concluded, if there is one.
    ///
    /// An `EffectStarted` with no terminal record is the undecidable case: the
    /// call may have landed, may not have, and the journal cannot say. Ordinarily
    /// the run is already `Quarantined` when this is true, and a quarantined run
    /// never unwinds.
    ///
    /// Cancellation opens a second door into the unwind, and it has to be shut
    /// the same way. Otherwise an operator's stop compensates every step
    /// *around* the one nobody can account for — which is precisely the refund
    /// for money nobody took that `NoUnwindUnderDoubt` exists to forbid, arriving
    /// through a control that was added to make things safer.
    async fn undecided_effect(&self, run: RunId) -> Result<Option<StepId>, RuntimeError> {
        let records = self
            .store
            .read(run, 1)
            .await
            .map_err(RuntimeError::from_store)?;

        // Two shapes of doubt, and both must stop an unwind.
        //
        // An **orphan**: a mutating `EffectStarted` with no terminal record —
        // the crash shape. And a **terminal `InDoubt`**: the call *concluded*,
        // with a record saying the runtime does not know whether it reached
        // the world. The second was invisible here for as long as only orphans
        // were tracked, and the consequence was concrete: a run whose last
        // attempt failed in doubt was cancelled, and the unwind compensated
        // every step around a call that may have landed — the refund for money
        // nobody took, issued through the control added to prevent it.
        //
        // A doubt is resolved by evidence, not by time: a later
        // `EffectReconciled` that lands or clears it, or — for an effect whose
        // declaration made repeating safe — a later attempt of the same
        // dispatch (same step, same descriptor) that completed, which under
        // that declaration is the same single performance finally landing.
        let mut open: BTreeMap<crate::core::EffectKey, (StepId, EffectDescriptor)> =
            BTreeMap::new();
        let mut doubts: BTreeMap<crate::core::EffectKey, (StepId, EffectDescriptor)> =
            BTreeMap::new();
        for r in &records {
            let Some(key) = r.effect_key() else { continue };
            match r.kind() {
                RecordKind::EffectStarted {
                    mutates: true,
                    descriptor,
                    ..
                } => {
                    if let Some(step) = r.body.step {
                        open.insert(key, (step, descriptor.clone()));
                    }
                }
                RecordKind::EffectDone { .. } => {
                    if let Some((step, descriptor)) = open.remove(&key) {
                        // A completed attempt settles any doubted earlier
                        // attempt of the same dispatch: the effect declared
                        // repetition safe (or it would never have been
                        // retried through doubt), so the landing is the one
                        // performance resolving.
                        doubts.retain(|_, (s, d)| !(*s == step && *d == descriptor));
                    }
                }
                RecordKind::EffectFailed { disposition, .. } => {
                    if let Some((step, descriptor)) = open.remove(&key)
                        && *disposition == crate::core::Disposition::InDoubt
                    {
                        doubts.insert(key, (step, descriptor));
                    }
                }
                RecordKind::EffectReconciled { disposition, .. } => {
                    let settled = open.remove(&key);
                    match disposition {
                        // The probe answered: it landed, or it never happened.
                        // Either way the doubt is resolved.
                        crate::core::Disposition::Landed
                        | crate::core::Disposition::DidNotHappen => {
                            doubts.remove(&key);
                        }
                        // Asked, and still unknown.
                        crate::core::Disposition::InDoubt => {
                            if let Some(entry) = settled {
                                doubts.insert(key, entry);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(open
            .values()
            .map(|(step, _)| *step)
            .chain(doubts.values().map(|(step, _)| *step))
            .min())
    }

    /// Execute one plan node.
    async fn run_step(
        &self,
        ctx: StepRun<'_>,
        run_input: &Tainted<Value>,
        outputs: &BTreeMap<StepId, Tainted<Value>>,
        cursor: crate::journal::StepCursor,
    ) -> Result<
        (
            RunStatus,
            Option<Tainted<Value>>,
            crate::journal::StepCursor,
        ),
        RuntimeError,
    > {
        let span = tracing::info_span!(
            telemetry::STEP_SPAN,
            { telemetry::STEP } = tracing::field::display(ctx.node.id),
            { telemetry::CAPABILITY } = tracing::field::display(&ctx.node.capability.0),
            { telemetry::PHASE } = if ctx.phase.is_forward() {
                "forward"
            } else {
                "compensating"
            },
            { telemetry::MODE } = telemetry::mode_str(ctx.mode),
            { telemetry::OUTCOME } = tracing::field::Empty,
        );
        self.run_step_inner(ctx, run_input, outputs, cursor)
            .instrument(span)
            .await
    }

    async fn run_step_inner(
        &self,
        ctx: StepRun<'_>,
        run_input: &Tainted<Value>,
        outputs: &BTreeMap<StepId, Tainted<Value>>,
        cursor: crate::journal::StepCursor,
    ) -> Result<
        (
            RunStatus,
            Option<Tainted<Value>>,
            crate::journal::StepCursor,
        ),
        RuntimeError,
    > {
        let StepRun {
            run,
            epoch,
            node,
            phase,
            mode,
            case,
            ledger,
            writing,
            stamp,
            agent,
            already_started,
            already_finished,
        } = ctx;
        let step = node.id;
        let skill = self.resolve(&node.capability.0)?;

        // Assemble this step's input from its declared sources. Labels join, so
        // provenance flows through the graph without anyone threading it by hand.
        let step_input = assemble(node, run_input, outputs)?;

        // Announce a step doing new work, once: always in `Live`, and on a
        // resume only for a step the journal never announced — a frontier
        // step running for the first time. Keying this on the mode alone got
        // both directions wrong: resumed frontier steps went unannounced, and
        // the `!Strict` finish gate below duplicated `StepFinished` for every
        // fully replayed step on every resume.
        let announce = writes_step_record(mode, !already_started);
        if announce {
            self.store
                .append(
                    epoch,
                    vec![stamp(
                        Append::new(
                            run,
                            RecordKind::StepStarted {
                                skill: skill.descriptor().name,
                            },
                        )
                        .step(step),
                    )],
                )
                .await
                .map_err(RuntimeError::from_store)?;
        }

        let mut cx = StepCtx::new(
            &self.store,
            cursor,
            super::ctx::Frame {
                run,
                epoch,
                step,
                phase,
                mode,
                case,
                timers: self.timers.clone(),
                blobs: self.blobs.clone(),
                memories: self.memories.clone(),
                authorities: self.authorities.clone(),
                #[cfg(feature = "manifest")]
                tools: self.tools.clone(),
                meter: self.meter.clone(),
                #[cfg(feature = "keyring")]
                keyring: self.keyring.clone(),
                tenant: self.tenant.clone(),
                ledger: Arc::clone(ledger),
                policy: self.policy.clone(),
                identity: self.identity.clone(),
                agent: agent.to_owned(),
                plane: self.self_ref.clone(),
                #[cfg(feature = "manifest")]
                manifest: self.governing(skill.as_ref()),
                signer: self.signer.clone(),
            },
        );
        let result = skill.invoke(&mut cx, step_input).await;
        let result = settle_abandoned_group(&mut cx, result).await;
        let wrote = cx.wrote_records();
        let cursor = cx.into_cursor();
        ledger.lock().expect("budget mutex").record_step();

        let (status, output) = classify(&self.meter, result);
        tracing::Span::current().record(telemetry::OUTCOME, status.as_str());
        if let RunStatus::Quarantined(why) = &status {
            tracing::error!(target: telemetry::QUARANTINED, %step, reason = %why);
        }

        // Record the ending only where the journal does not already hold it:
        // every live step; a resumed step that did new work; and a resumed
        // step reaching an ending the record never captured — how a suspended
        // step that finishes purely from replayed history (its awaited event
        // recorded by the delivery) still gets its one `StepFinished`. What
        // this rules out is a duplicate ending for every fully replayed
        // completed step, appended on every resume of a run doing nothing new.
        let record_ending = writes_step_record(mode, announce || wrote || !already_finished);
        if writing && record_ending {
            // A suspended step has not finished, so it records why it stopped
            // rather than claiming an outcome.
            let record = match &status {
                RunStatus::Suspended(reason) => RecordKind::RunSuspended {
                    reason: reason.clone(),
                },
                other => RecordKind::StepFinished {
                    outcome: other.as_str().to_owned(),
                },
            };
            self.store
                .append(epoch, vec![stamp(Append::new(run, record).step(step))])
                .await
                .map_err(RuntimeError::from_store)?;
        }

        Ok((status, output, cursor))
    }

    /// Seal the run and report.
    /// Eight arguments, and each is a distinct fact about how the run ended
    /// that the caller already holds. Bundling them into a struct would move the
    /// same fields one indirection away without removing a single one.
    #[allow(clippy::too_many_arguments)]
    async fn conclude(
        &self,
        run: RunId,
        epoch: u64,
        status: RunStatus,
        output: Option<Tainted<Value>>,
        writing: bool,
        case: Option<crate::core::CaseId>,
        spend: Spend,
    ) -> Result<RunOutcome, RuntimeError> {
        // Loud toward the operator, ordinary toward the caller. A failed run is
        // a conclusion a resume can honestly answer, so it is not an incident —
        // but until this, nothing said why one failed except the journal and an
        // index that needs the HTTP surface mounted, so `agentplane serve`
        // reported "failed" to a peer and gave its own operator nothing.
        if let RunStatus::Failed(reason) = &status {
            tracing::warn!(target: telemetry::RUN_FAILED, %run, reason = %reason);
        }

        // A suspended run is not sealed: its chain is going to be extended the
        // moment whatever it waits for arrives.
        let chain_head = if writing && !status.is_suspended() {
            // The conclusion goes *in* the chain — before the chain is closed
            // over it, where the conclusion is one that closes it. Two things
            // follow, and both were missing while the outcome lived only in a
            // side table: tamper detection covers how the run ended, and a
            // resumed run can read that fact from the same history it verifies
            // rather than inferring it from the last step that happened to
            // finish. The stores also derive the outcome index from this
            // record, last conclusion wins — which is what keeps a
            // failed-then-resumed-then-succeeded run from being listed as
            // failed forever.
            let before = self
                .store
                .head(run)
                .await
                .map_err(RuntimeError::from_store)?;
            let mut sealed = Append::new(
                run,
                RecordKind::RunSealed {
                    outcome: status.as_str().to_owned(),
                    chain_head: before.hash,
                },
            );
            if let Some(c) = case {
                sealed = sealed.case(c);
            }
            let concluded = self
                .store
                .append(epoch, vec![sealed])
                .await
                .map_err(RuntimeError::from_store)?;

            // Only a conclusion nothing may resume freezes the journal and
            // enters the Merkle log. A failed or exhausted run stays open: its
            // conclusion is in the chain — indexed, findable, tamper-covered —
            // but a leaf published for it would be a checkpoint attesting a
            // history its own resume is permitted to grow past.
            if status.seals() {
                self.store
                    .seal(run, epoch, status.as_str())
                    .await
                    .map_err(RuntimeError::from_store)?
            } else {
                concluded.last().map_or(before.hash, |r| r.hash)
            }
        } else {
            self.store
                .head(run)
                .await
                .map_err(RuntimeError::from_store)?
                .hash
        };

        // Hand the lease back rather than letting it time out.
        //
        // Whatever the outcome — sealed, suspended, exhausted — this instance is
        // finished with the run. Holding the lease until expiry would make every
        // failover wait out the TTL for nothing, and that wait is precisely the
        // pressure that tempts a deployment into giving all its replicas one
        // owner string, which silently disables fencing.
        //
        // Best-effort on purpose. A release that fails costs a TTL of patience;
        // turning it into a run failure would convert a tidiness problem into a
        // correctness one, after the work is already done and journaled.
        if let Err(e) = self.store.release_lease(run, epoch).await {
            tracing::debug!(
                %run,
                error = %e,
                "could not hand back the lease; it will expire on its own"
            );
        }

        // Beside the lease, and for the same reason: this instance is finished
        // with the run whatever the outcome. A **suspended** run gives its slot
        // back too — it costs a row, not a thread, and holding the slot would
        // mean a tenant waiting on a hundred approvals could start nothing.
        self.settle_quota(run, spend).await;

        announce(&self.meter, run, &status);

        Ok(RunOutcome {
            run_id: run,
            status,
            chain_head,
            spend,
            // The caller is outside the lattice, so the label is dropped at the
            // boundary rather than inside the graph.
            output,
        })
    }
}

/// The run's result: the terminal step's output.
///
/// Not "whichever step finished last". That coincides with the terminal step
/// only while dispatch is sequential, and stops being well-defined the moment
/// two steps run at once. Lowest id wins when a plan has several terminals, so
/// the answer is a property of the plan rather than of the schedule.
fn run_output(ir: &PlanIR, outputs: &BTreeMap<StepId, Tainted<Value>>) -> Option<Tainted<Value>> {
    ir.nodes
        .iter()
        .filter(|n| n.terminal)
        .map(|n| n.id)
        .min()
        .and_then(|id| outputs.get(&id).cloned())
        // A run that stopped before any terminal step still has something to
        // report: the furthest output it did produce.
        .or_else(|| outputs.iter().next_back().map(|(_, v)| v.clone()))
}

/// Whether the plan actually finished.
///
/// Structural, never self-reported: a workload asserting it is done is not
/// evidence, so the runtime checks that every terminal node ran.
fn completion(ir: &PlanIR, done: &BTreeSet<StepId>) -> RunStatus {
    if ir.is_complete(done) {
        return RunStatus::Succeeded;
    }
    let missing: Vec<String> = ir
        .nodes
        .iter()
        .filter(|n| n.terminal && !done.contains(&n.id))
        .map(|n| n.id.to_string())
        .collect();
    RunStatus::Failed(format!(
        "plan did not complete: terminal step(s) {} never ran",
        missing.join(", ")
    ))
}

/// Say that a run changed its plan, and what it changed from.
fn announce_replan(meter: &super::metrics::Meter, run: RunId, next: &PlanIR, reason: &str) {
    tracing::info!(
        target: telemetry::REPLANNED,
        %run,
        from = next.derived_from.map(Digest::to_hex),
        version = next.version,
        %reason,
    );
    meter.count(metrics::REPLANS, "");
}

/// Say how a run ended, on the run span and — for the loud ones — as an event.
fn announce(meter: &super::metrics::Meter, run: RunId, status: &RunStatus) {
    // Counted here and nowhere else. A step that quarantines also fails its run,
    // so counting at both levels would report one incident as two — and the
    // terminal status is the fact an operator is counting.
    meter.count(metrics::RUNS, status.as_str());
    match status {
        RunStatus::Quarantined(why) => {
            tracing::error!(target: telemetry::QUARANTINED, %run, reason = %why);
            meter.count(metrics::QUARANTINES, "");
        }
        RunStatus::Exhausted(limit) => {
            tracing::warn!(target: telemetry::BUDGET_REFUSED, %run, %limit);
        }
        _ => {}
    }
    tracing::Span::current().record(telemetry::OUTCOME, status.as_str());
}

/// Record a batch's successes, then report the first step that stopped.
///
/// **Every** success is recorded, including those of siblings dispatched
/// alongside the one that stopped. Returning early on the first failure loses
/// them — and a sibling that already performed a mutating effect would then
/// never be compensated, because `completed` is what the unwind reverses. The
/// work happened; the saga has to know about it.
///
/// When siblings stop for different reasons, **severity wins over ready order**.
/// A suspension is the run working; a failure is the run over. Letting one
/// sibling's wait mask another's failure would defer the unwind until an event
/// that may never arrive — leaving the failed sibling's mutations in place
/// indefinitely. Within one severity, ready order decides, so the choice stays a
/// property of the plan rather than of the schedule.
fn apply(
    plan: &PlanIR,
    outcomes: Vec<StepOutcome>,
    done: &mut BTreeSet<StepId>,
    completed: &mut Vec<(StepId, Capability)>,
    outputs: &mut BTreeMap<StepId, Tainted<Value>>,
) -> Option<RunStatus> {
    let mut stopped: Option<RunStatus> = None;
    for (step, status, output) in outcomes {
        let RunStatus::Succeeded = status else {
            if stopped
                .as_ref()
                .is_none_or(|held| severity(&status) > severity(held))
            {
                stopped = Some(status);
            }
            continue;
        };
        if let Some(v) = output {
            outputs.insert(step, v);
        }
        done.insert(step);
        if let Some(node) = plan.node(step) {
            completed.push((step, node.capability.clone()));
        }
    }
    stopped
}

/// How much a stop reason dominates a competing one.
///
/// `Quarantined` is highest because it is the only one that must *not* unwind:
/// something is undecidable, and compensating around it can make the damage
/// worse. `Suspended` is lowest because it is not a stop at all — the run is
/// healthy and waiting.
fn severity(status: &RunStatus) -> u8 {
    match status {
        RunStatus::Quarantined(_) => 3,
        // A stop ranks with a failure, not above it: both end the run, both
        // unwind, and when they arrive together the run is over either way.
        RunStatus::Cancelled { .. } | RunStatus::Failed(_) => 2,
        RunStatus::Exhausted(_) => 1,
        // A replan request is the weakest signal in a batch: a sibling that
        // failed outright has already decided the run, and re-planning around a
        // failure is not what the requesting step was asking for.
        RunStatus::Replanning(_) | RunStatus::Suspended(_) | RunStatus::Succeeded => 0,
    }
}

/// Gather a dispatched batch back into ready order.
///
/// Not completion order. `completed` is what the unwind reverses, and a saga
/// whose compensation order depended on which future finished first would undo
/// a plan differently on every run.
type Dispatched = Result<(StepId, RunStatus, Option<Tainted<Value>>, StepCursor), RuntimeError>;

/// One step's result, once its history has been handed back.
type StepOutcome = (StepId, RunStatus, Option<Tainted<Value>>);

fn collect(
    dispatched: Vec<Dispatched>,
    ready: &[StepId],
    cursor: &mut ReplayCursor,
) -> Result<Vec<StepOutcome>, RuntimeError> {
    let mut outcomes = Vec::with_capacity(dispatched.len());
    for result in dispatched {
        let (step, status, out, slice) = result?;
        cursor.restore(step, Phase::Forward, slice);
        outcomes.push((step, status, out));
    }
    outcomes.sort_by_key(|(step, _, _)| ready.iter().position(|r| r == step));
    Ok(outcomes)
}

/// What one ready set's dispatch needs.
struct Batch<'a> {
    agent: &'a str,
    run: RunId,
    epoch: u64,
    ir: &'a PlanIR,
    mode: Mode,
    case: &'a Option<CaseContext>,
    ledger: &'a Arc<std::sync::Mutex<Ledger>>,
    writing: bool,
    stamp: &'a (dyn Fn(Append) -> Append + Send + Sync),
    input: &'a Tainted<Value>,
    outputs: &'a BTreeMap<StepId, Tainted<Value>>,
    /// Steps whose `StepStarted` the journal already holds. Empty on a live
    /// run.
    started: &'a BTreeSet<StepId>,
    /// Steps whose `StepFinished` the journal already holds. Empty on a live
    /// run.
    finished: &'a BTreeSet<StepId>,
}

/// What producing a successor plan needs.
struct Replan<'a> {
    current: &'a PlanIR,
    reason: &'a str,
    already_replanned: u32,
    max_replans: Option<u32>,
    /// The successor this run produced when it first ran, if this is a replay.
    recorded: Option<&'a PlanIR>,
}

/// The first untrusted value in working memory, if any.
///
/// Returns the source so the refusal can name it: "replanning refused" without
/// saying *what* made it unsafe sends an operator looking through the whole run.
fn untrusted_in(outputs: &BTreeMap<StepId, Tainted<Value>>) -> Option<String> {
    outputs.values().find_map(|v| {
        let label = v.label();
        label.is_untrusted().then(|| {
            label
                .provenance
                .first()
                .map_or_else(|| "an untrusted source".to_owned(), ToString::to_string)
        })
    })
}

/// Where a refusal is recorded, when one is.
struct Journalling<'a> {
    run: RunId,
    epoch: u64,
    writing: bool,
    stamp: &'a (dyn Fn(Append) -> Append + Send + Sync),
}

/// What unwinding a run needs.
struct Unwind<'a> {
    run: RunId,
    epoch: u64,
    ir: &'a PlanIR,
    mode: Mode,
    case: Option<CaseContext>,
    ledger: &'a Arc<std::sync::Mutex<Ledger>>,
    writing: bool,
    stamp: &'a (dyn Fn(Append) -> Append + Send + Sync),
    agent: &'a str,
}

/// What one step's execution needs.
struct StepRun<'a> {
    run: RunId,
    epoch: u64,
    node: &'a PlanNode,
    phase: Phase,
    mode: Mode,
    case: Option<CaseContext>,
    ledger: &'a Arc<std::sync::Mutex<Ledger>>,
    writing: bool,
    stamp: &'a (dyn Fn(Append) -> Append + Send + Sync),
    agent: &'a str,
    /// Whether the journal already announced this step. Always `false` live.
    already_started: bool,
    /// Whether the journal already records this step finishing. Always
    /// `false` live.
    already_finished: bool,
}

/// Where the recorded run was refused by a *step* limit, if the refusal still
/// stands.
///
/// A step-level refusal has no effect key, so it cannot ride the replay cursor
/// the way an effect's does; it is lifted from the records instead.
///
/// **The last word wins.** An exhausted run may be resumed under a raised
/// ceiling; when the resume re-admits the refused step it journals a
/// `BudgetReadmitted` beside the old refusal, and from then on the refusal is
/// history that was *superseded*, not a verdict to re-serve. Without this, a
/// strict replay of the resumed history would stop at the old refusal and
/// report `Exhausted` about a run whose own later records show it finishing —
/// the refusal followed by the continuation would read as divergence.
fn recorded_step_refusal(records: &[Record]) -> Option<(StepId, String, String)> {
    let mut standing: Option<(StepId, String, String)> = None;
    for r in records {
        match r.kind() {
            RecordKind::BudgetRefused { limit, used } if r.effect_key().is_none() => {
                if let Some(step) = r.body.step {
                    standing = Some((step, limit.clone(), used.clone()));
                }
            }
            RecordKind::BudgetReadmitted { .. }
                if standing
                    .as_ref()
                    .is_some_and(|(s, _, _)| Some(*s) == r.body.step) =>
            {
                standing = None;
            }
            _ => {}
        }
    }
    standing
}

/// The run's most recent recorded conclusion, if it has one.
///
/// `None` for a run that has only ever suspended — a suspension is not a
/// conclusion, and `conclude` writes no `RunSealed` for it.
fn recorded_conclusion(records: &[Record]) -> Option<String> {
    records.iter().rev().find_map(|r| match r.kind() {
        RecordKind::RunSealed { outcome, .. } => Some(outcome.clone()),
        _ => None,
    })
}

/// Whether this pass writes a step-level record: always live, never under
/// strict verification, and on a resume only when `new_fact` — the record is
/// not already in the journal, or the step did new work.
const fn writes_step_record(mode: Mode, new_fact: bool) -> bool {
    match mode {
        Mode::Live => true,
        Mode::Resume => new_fact,
        Mode::Strict => false,
    }
}

/// The steps whose start is already on the record.
///
/// Read back so a resume neither re-announces a step history already announced
/// nor forgets to announce one it is starting for the first time.
fn recorded_started_steps(records: &[Record]) -> BTreeSet<StepId> {
    records
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::StepStarted { .. } => r.body.step,
            _ => None,
        })
        .collect()
}

/// The steps whose ending is already on the record.
///
/// Read back so a resume records a `StepFinished` exactly for the steps that
/// reach an ending the journal does not yet hold: a fully replayed completed
/// step keeps its one record, and a suspended step that finally finishes —
/// even purely from replayed history, its awaited event having been recorded
/// by the delivery — gets the one it never had.
fn recorded_finished_steps(records: &[Record]) -> BTreeSet<StepId> {
    records
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::StepFinished { .. } => r.body.step,
            _ => None,
        })
        .collect()
}

/// Every capability an agent advertises is provided by one of **its own**
/// skills.
///
/// An agent advertising a capability none of its skills provide is a card that
/// lies, and the caller who believed it finds out at dispatch — in production —
/// rather than here at startup.
///
/// This checked a plane-wide map, and the difference is not pedantry. A skill
/// registered on the *builder* rather than on the agent — `.agent(Agent::new(&m))`
/// followed by `.skill(s)` — satisfied a plane-wide check while being
/// **ungoverned**: `governed_by` is keyed from the agent's own skills, so that
/// skill gets no manifest. It runs under the plane's default budget instead of
/// the declared one, and `StepCtx::gate` never refuses a model or tool the file
/// did not list, because there is no file.
///
/// The plane built cleanly and the assertion's own message said "its skills",
/// so the only signal was a `None` from `cx.manifest()` that a skill has no
/// reason to check. That is a declaration reading as a control while governing
/// nothing, which is the one shape this codebase refuses everywhere.
#[cfg(feature = "manifest")]
fn check_advertises_what_it_provides(
    m: &crate::manifest::Manifest,
    mine: &HashSet<Capability>,
) -> Result<(), BuildError> {
    let missing: Vec<String> = m
        .spec
        .capabilities
        .provides
        .iter()
        .filter(|c| !mine.contains(&Capability::new(c.as_str())))
        .cloned()
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(BuildError::AdvertisesWhatItCannotProvide {
        agent: m.metadata.name.clone(),
        missing,
    })
}

/// Add one skill to the plane's two lookup tables, refusing a collision.
///
/// Both maps are plane-wide, and a bare `insert` would take a second
/// registration silently. That was tolerable when a plane was one agent and is
/// not now: dispatch resolves a capability to a skill *and to the manifest
/// governing it*, so a silent overwrite does not merely shadow the loser — it
/// moves work the loser still advertises out from under the loser's budget,
/// model grants and egress ceiling. Nothing in the journal would show it,
/// because the winner looks like the only claimant that ever existed.
///
/// Returns the skill's name, which is the key governance is recorded under.
///
/// # Errors
///
/// If another skill already holds this name, or another skill already claims one
/// of its capabilities.
fn register_skill(
    skill: Arc<dyn Skill>,
    caps: &mut HashMap<Capability, String>,
    skills: &mut HashMap<String, Arc<dyn Skill>>,
) -> Result<String, BuildError> {
    let d = skill.descriptor();
    if let Some(existing) = skills.get(&d.name)
        // Registering the *same* `Arc` twice is idempotent rather than a
        // mistake; two distinct skills under one name is the collision.
        && !Arc::ptr_eq(existing, &skill)
    {
        return Err(BuildError::DuplicateSkillName { name: d.name });
    }
    // `capabilities()`, not the raw field: a descriptor that declared nothing
    // answers its own name, and registering that here is what makes
    // `run("greet")` and an `agent/greet` grant resolve without a hello-world
    // program inventing a second name for its one skill.
    for cap in d.capabilities() {
        if let Some(first) = caps.get(&cap)
            && first != &d.name
        {
            return Err(BuildError::CapabilityClaimedTwice {
                capability: cap.0,
                first: first.clone(),
                second: d.name,
            });
        }
        caps.insert(cap, d.name.clone());
    }
    skills.insert(d.name.clone(), skill);
    Ok(d.name)
}

/// The capability a bare `run(target, ..)` admits: the first declared, or the
/// skill's own name — [`SkillDescriptor::capabilities`] is never empty.
fn first_capability(descriptor: &SkillDescriptor) -> Capability {
    descriptor
        .capabilities()
        .into_iter()
        .next()
        .unwrap_or_else(|| Capability::new(descriptor.name.clone()))
}

/// The business keys a case is identified by, for the binding record.
///
/// Read from the case rather than taken from the request, because a run joining
/// an existing case is admitted with whichever key its message carried while the
/// case may be identified by several — and a manifest binding naming any of them
/// must resolve.
///
/// Falls back to the admitted keys if the case cannot be read back. That is not
/// defensive padding: `correlate_or_open` has already committed the binding, so
/// a failure here is a read that lost a race with nothing, and the keys the run
/// was admitted with are a true subset of the case's. Recording them is strictly
/// better than recording none, and *nothing* is what would silently make a
/// binding unresolvable for a run whose case is perfectly well identified.
async fn case_correlation(
    cases: &dyn CaseStore,
    case_id: crate::core::CaseId,
    admitted: &[CorrelationKey],
) -> Result<Vec<CorrelationKey>, RuntimeError> {
    let stored = cases
        .case(case_id)
        .await
        .map_err(RuntimeError::from_store)?
        .map(|case| case.correlation)
        .unwrap_or_default();
    let mut keys = if stored.is_empty() {
        admitted.to_vec()
    } else {
        stored
    };
    // Canonical order, so the record is byte-stable for a given set and two
    // stores that answer in different orders produce the same journal.
    keys.sort();
    keys.dedup();
    Ok(keys)
}

/// A lease owner that no other process will accidentally share.
///
/// The previous default was the constant `"agentplane"`, which every replica and
/// every restart used. Two consequences, both silent:
///
/// * Two replicas each saw the other's lease as their own and renewed it
///   without bumping the epoch — two writers on one run, which is the exact
///   situation fencing exists to make impossible.
/// * A process restarting after a crash "renewed" the dead process's lease
///   instead of waiting for expiry and fencing it, so a zombie still holding a
///   socket could keep writing under the same epoch as its replacement.
///
/// A per-process random identity turns both into the correct behaviour: a
/// different owner cannot renew, so it waits for expiry and takes over with
/// `epoch + 1`.
///
/// Not derived from a hostname or PID: containers reuse both. Randomness is the
/// property that matters; readability is what the `owner` override is for, and a
/// deployment with a real instance identity — a pod name — should pass it.
fn default_owner() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};

    // OS entropy, and deliberately *not* the clock: this crate forbids reading
    // the wall clock outside a journaled effect, and rightly — a lease owner is
    // a poor reason to make an exception to a rule that keeps replay honest.
    // `RandomState` is seeded by the operating system, so two processes differ
    // even where a container has reused a PID.
    static SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    // A counter beside it, so two runtimes built in one process — which tests do
    // constantly — never alias each other either.
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let seed = *SEED.get_or_init(|| RandomState::new().build_hasher().finish());
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("agentplane-{seed:016x}-{n}")
}

/// The admitted input, label and all.
///
/// Read back rather than recomputed: a replay that re-labelled would reach a
/// different verdict at every taint gate than the run it reproduces.
fn recorded_input(r: &Record) -> Option<Tainted<Value>> {
    match r.kind() {
        RecordKind::RunAdmitted {
            input, input_label, ..
        } => Some(Tainted::with_label(input.clone(), input_label.clone())),
        _ => None,
    }
}

/// Refuse a history this build cannot re-derive.
///
/// Before recomputing anything, because every effect key a replay derives comes
/// out of the canonicalizer: a run written under another rule recomputes
/// different keys and would be quarantined as *non-determinism* — the most
/// serious conclusion this runtime reaches, reported for a healthy run because
/// the rule moved underneath it.
///
/// The chain itself is fine and always was: it hashes the bytes it stored rather
/// than re-canonicalizing them. What moved is everything *derived*, which is
/// exactly the class replay compares.
fn ensure_replayable_canon(records: &[Record]) -> Result<(), RuntimeError> {
    if let Some(recorded) = records.iter().find_map(recorded_canon)
        && recorded != crate::core::canon::VERSION
    {
        return Err(RuntimeError::CanonicalizationChanged {
            recorded,
            implemented: crate::core::canon::VERSION,
        });
    }
    Ok(())
}

/// Which canonicalization rule wrote this run's derived digests.
fn recorded_canon(r: &Record) -> Option<u16> {
    match r.kind() {
        RecordKind::RunAdmitted { canon, .. } => Some(*canon),
        _ => None,
    }
}

/// The principal a run was admitted as.
///
/// Read back rather than recomputed, for the same reason the plan is: the
/// principal a run was authorized as is a fact *about that run*, and deriving it
/// again from a plan that may since have been edited would silently re-attribute
/// history.
fn recorded_agent(records: &[Record]) -> String {
    records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::RunAdmitted { capability, .. } => Some(capability.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Build a step's input from its declared argument sources.
///
/// Labels join across sources, so a step reading anything untrusted produces an
/// untrusted input without the plan author having to say so.
fn assemble(
    node: &PlanNode,
    run_input: &Tainted<Value>,
    outputs: &BTreeMap<StepId, Tainted<Value>>,
) -> Result<Tainted<Value>, RuntimeError> {
    // The common case — a single argument — passes the value through rather than
    // wrapping it in a one-key object, so simple plans stay legible.
    if node.args.len() == 1
        && let Some((_, only)) = node.args.iter().next()
    {
        return resolve_arg(node, only, run_input, outputs);
    }

    let mut fields = Vec::with_capacity(node.args.len());
    for (name, source) in &node.args {
        let v = resolve_arg(node, source, run_input, outputs)?;
        fields.push((name.clone(), v));
    }
    Ok(Tainted::object(fields))
}

fn resolve_arg(
    node: &PlanNode,
    source: &ArgSource,
    run_input: &Tainted<Value>,
    outputs: &BTreeMap<StepId, Tainted<Value>>,
) -> Result<Tainted<Value>, RuntimeError> {
    let pick = |v: &Value, field: &Option<String>| match field {
        Some(f) => v.get(f).cloned().unwrap_or(Value::Null),
        None => v.clone(),
    };

    Ok(match source {
        // Picking a field inherits the whole value's label: the parts of an
        // untrusted document are untrusted.
        ArgSource::RunInput { field } => {
            Tainted::with_label(pick(run_input.peek(), field), run_input.label().clone())
        }
        ArgSource::Const { value } => Tainted::trusted(value.clone()),
        ArgSource::Node { step, field } => {
            // The contract already proved this is upstream, so a miss here means
            // the scheduler dispatched out of order — a bug worth naming rather
            // than papering over with a null.
            let upstream = outputs.get(step).ok_or_else(|| {
                RuntimeError::PlanContract(format!(
                    "step {} read step {step}, which has not produced a value",
                    node.id
                ))
            })?;
            match field {
                Some(field) => upstream
                    .project_field(field)
                    .unwrap_or_else(|| Tainted::with_label(Value::Null, upstream.label().clone())),
                None => upstream.clone(),
            }
        }
    })
}

/// Settle a group the skill left open, because `Drop` cannot.
///
/// A skill that fails with `?` never reaches `commit` or `abort`, so the handle
/// is dropped with members standing. Reversing them is async and `Drop` is not,
/// which is why the group lives on the context and the executor finishes what
/// the handle abandoned — the same relationship the executor already has with a
/// step's compensation.
///
/// Three situations, and they are not the same:
///
/// * **suspended** — the step has not ended. Its frame is persisted and it will
///   re-run from the top, rebuilding the group from the journal as it replays
///   the members. Reversing here would undo a run that is merely waiting.
/// * **failed** — abort, unless the failure leaves the world in doubt. Doubt is
///   the one condition under which nothing may be reversed.
/// * **succeeded with a group still open** — an author bug, and the safe
///   reading is that the group was never meant to take. It is reversed and the
///   step fails loudly, because a group that commits by being forgotten is
///   worse than one that does not commit at all.
async fn settle_abandoned_group(
    cx: &mut StepCtx<'_>,
    result: Result<Outcome, crate::core::SkillError>,
) -> Result<Outcome, crate::core::SkillError> {
    use crate::core::{SkillError, StepError};

    let Some(name) = cx.open_group().map(|g| g.name.clone()) else {
        return result;
    };
    if matches!(&result, Err(SkillError::Step(StepError::Suspended(_)))) {
        return result;
    }

    // A member whose failure may have reached the world travels no further.
    // Reversing around a call that may have — or did — happen leaves the world
    // holding a write no `Aborted` settlement can honestly claim to have undone.
    let doubt = match &result {
        Err(SkillError::Step(e)) => crate::runtime::group::may_have_externalised(e),
        _ => false,
    };
    if doubt {
        let detail = match &result {
            Err(e) => e.to_string(),
            Ok(_) => String::new(),
        };
        let settled = cx
            .settle_open_group(crate::core::GroupOutcome::Quarantined, Some(&detail))
            .await;
        return match settled {
            Ok(()) => result,
            Err(e) => Err(SkillError::Step(e)),
        };
    }

    match cx
        .abort_open_group("the step ended without settling the group")
        .await
    {
        // The abort itself could not be completed. That outranks whatever the
        // step was reporting: a partly unwound group is the more dangerous fact.
        Err(e) => Err(SkillError::Step(e)),
        Ok(()) => match result {
            // A reported failure keeps its own reason. `Outcome::Fail` is an
            // `Ok` at the type level and a failure in fact: leaving the group
            // to the runtime is the ordinary path there, not an author bug, and
            // overwriting the reason would tell an operator the step "returned
            // successfully" while hiding why it actually stopped.
            Err(e) => Err(e),
            failed @ Ok(Outcome::Fail { .. }) => failed,
            // Anything else claimed to make progress while leaving a group
            // unsettled.
            Ok(_) => Err(SkillError::Step(StepError::GroupAborted {
                what: format!(
                    "step made progress with group '{name}' still open — it was \
                     reversed, because a group that commits by being forgotten is worse \
                     than one that does not commit at all"
                ),
            })),
        },
    }
}

/// Turn a step's result into a run status.
///
/// The distinction that matters is between an ordinary failure and a run whose
/// *history can no longer be trusted*. Divergence and orphaned effects are the
/// latter: they mean the journal no longer describes what this code does, so a
/// human has to look before anything else happens. Folding them into `Failed`
/// would put them in the same bucket as "the invoice was rejected", and they
/// would be retried like one.
fn classify(
    meter: &super::metrics::Meter,
    result: Result<Outcome, crate::core::SkillError>,
) -> (RunStatus, Option<Tainted<Value>>) {
    use crate::core::{SkillError, StepError};

    match result {
        // The label travels with the value. Stripping it here would silently
        // launder provenance at every step boundary: a downstream step reading
        // an untrusted upstream output would receive it marked trusted, and the
        // taint gates further on would have nothing to act on.
        Ok(Outcome::Done(v)) => (RunStatus::Succeeded, Some(v)),
        Ok(Outcome::Fail { reason }) => (RunStatus::Failed(reason), None),
        // Not a failure: the executor decides whether a new plan is allowed,
        // because the answer depends on the run's provenance and budget, which
        // a step cannot see.
        Ok(Outcome::Replan { reason }) => (RunStatus::Replanning(reason), None),
        // Suspension is not a failure: the run is healthy and waiting. It
        // reaches here as an error only because that is how control leaves a
        // skill.
        Err(SkillError::Step(StepError::Suspended(reason))) => (RunStatus::Suspended(reason), None),
        // The ceiling did its job. Reporting this as a failure would have
        // operators debugging a system that behaved exactly as instructed.
        Err(SkillError::Step(StepError::Budget(exceeded))) => {
            (RunStatus::Exhausted(exceeded), None)
        }
        Err(e) => {
            let msg = e.to_string();
            // Matched structurally. An earlier version tested the *message* for
            // the word "quarantined", which meant rewording an error silently
            // downgraded a run to `Failed` — the run kept its history and lost
            // the flag that said not to trust it.
            // Each of these is a failure P7 exists to make loud, and each gets
            // its own event so "did this happen" is a query rather than a grep.
            match &e {
                SkillError::Step(StepError::NonDeterminism {
                    seq,
                    expected,
                    actual,
                }) => {
                    tracing::error!(
                        target: telemetry::NONDETERMINISM,
                        %seq, %expected, %actual,
                    );
                    meter.count(metrics::DIVERGENCES, "");
                }
                SkillError::Step(StepError::ReplayOverrun { actual }) => {
                    tracing::error!(target: telemetry::NONDETERMINISM, %actual, overrun = true);
                    meter.count(metrics::DIVERGENCES, "");
                }
                SkillError::Step(StepError::Undecidable { key, detail, .. }) => {
                    tracing::error!(target: telemetry::UNDECIDABLE, %key, %detail);
                    meter.count(metrics::UNDECIDABLE, "");
                }
                _ => {}
            }

            let untrustworthy = matches!(
                e,
                SkillError::Step(
                    StepError::NonDeterminism { .. }
                        | StepError::ReplayOverrun { .. }
                        | StepError::Undecidable { .. }
                        | StepError::GroupUnsettled { .. }
                )
            );
            if untrustworthy {
                (RunStatus::Quarantined(msg), None)
            } else {
                (RunStatus::Failed(msg), None)
            }
        }
    }
}

/// Everything one execution needs, gathered so the executor is not called with
/// eight positional arguments — two of which are `u64`-shaped and would swap
/// silently.
struct Execution<'a> {
    /// Where the recorded run was refused by a step limit, if it was. `None`
    /// for a live run, which has no history to consult.
    refusal: Option<(StepId, String, String)>,
    /// Successor plans the recorded run produced, oldest first. Empty on a live
    /// run. Read back rather than re-synthesised, because a planner asked twice
    /// can answer differently.
    successors: Vec<PlanIR>,
    /// Steps whose `StepStarted` is already on the record. Empty on a live
    /// run. Read back so a resume neither re-announces a step nor forgets to
    /// announce one it starts for the first time.
    started: BTreeSet<StepId>,
    /// Steps whose `StepFinished` is already on the record. Empty on a live
    /// run.
    finished: BTreeSet<StepId>,
    run: RunId,
    epoch: u64,
    plan: &'a PlanIR,
    input: Tainted<Value>,
    mode: Mode,
    case: Option<CaseContext>,
    budget: Budget,
    /// Who is acting, for the policy principal. Read back from `RunAdmitted` on
    /// a replay rather than recomputed, for the same reason the plan is: the
    /// principal a run was authorized as is a fact about that run.
    agent: String,
}

/// The recorded status of a run that must not be resumed.
///
/// Only two outcomes close a run to recovery:
///
/// * **Succeeded** — there is nothing outstanding. Re-executing would repeat
///   work that is not an effect (a case-state write, say), which is the same
///   class of bug the effect protocol prevents, arriving through a side door.
/// * **Quarantined** — a human has to look first. Resuming would re-hit
///   whatever could not be decided, and burying that in a retry loop is exactly
///   how an undecidable situation becomes an unnoticed one.
///
/// A **failed** run is deliberately *not* terminal here: a process that died
/// mid-flight records a failure, and recovering it is the entire point.
///
/// # Why the seal, and not the last step
///
/// This used to scan backwards for a `StepFinished` and read its outcome. Two
/// things were wrong with that, and the second is severe:
///
/// * A step's outcome is not the run's. They coincide only in a one-step plan.
/// * `find_map` **skips** a record it does not recognise and keeps looking. A
///   run whose last step failed after earlier steps succeeded therefore matched
///   an *earlier* `StepFinished { outcome: "succeeded" }` and was reported
///   closed-and-succeeded. Every multi-step run that suspended after a failure
///   — every saga waiting on an approval to finish unwinding — could never be
///   resumed, and reported success while doing it.
///
/// `RunSealed` is written by `conclude` for exactly the runs that reached a
/// conclusion, and never for a suspended one. That is the fact this needs, so
/// it is the fact it reads.
fn resume_is_closed(records: &[Record]) -> Option<RunStatus> {
    let outcome = records.iter().rev().find_map(|r| match r.kind() {
        RecordKind::RunSealed { outcome, .. } => Some(outcome.as_str()),
        _ => None,
    })?;

    match outcome {
        "succeeded" => Some(RunStatus::Succeeded),
        "quarantined" => Some(RunStatus::Quarantined(
            "recorded as quarantined; a human must resolve it before it can run again".into(),
        )),
        // A stopped run stays stopped. Otherwise the next inbound event resumes
        // it and it carries on doing the thing somebody intervened to prevent —
        // and the intervention would look, from the journal, like it worked.
        "cancelled" => Some(RunStatus::Cancelled {
            actor: recorded_canceller(records).unwrap_or_else(|| "unknown".into()),
            reason: "recorded as cancelled; an operator stopped this run".into(),
        }),
        // The two conclusions that deliberately do not close a run: a failed
        // run resumes with its completed effects read back from history, and an
        // exhausted one continues once somebody raises the ceiling.
        //
        // Their relationship to [`RunStatus::seals`] is the load-bearing part
        // and is pinned by `a_sealing_conclusion_is_never_resumable`. The
        // direction that matters is *no sealing status may be resumable*: a
        // status that seals froze the journal and published a Merkle leaf, so
        // resuming it would grow the history past the leaf every later
        // checkpoint attests. The reverse direction is deliberately **not** an
        // equality — `Suspended` and `Replanning` also do not seal, and never
        // reach here at all, because neither is ever a recorded conclusion.
        // Stating that as "the two that do not seal" was wrong; there are four,
        // and only two of them can be a `RunSealed` outcome.
        "failed" | "exhausted" => None,
        // Fail closed. An outcome this build does not recognise — a sweep's
        // `swept`, a future variant, a corrupted string — is not permission to
        // resume; it is a run whose recorded ending this code cannot interpret,
        // and continuing it would graft new behaviour onto a history that says
        // it ended.
        other => Some(RunStatus::Quarantined(format!(
            "recorded as '{other}', which this build does not recognise as resumable"
        ))),
    }
}

/// Who asked for the stop, read back from the chain.
///
/// Read rather than remembered, for the same reason every other fact about a run
/// is: the journal gives the same answer on every subsequent read, and an
/// operator asking "who stopped this?" six weeks later is asking history.
fn recorded_canceller(records: &[Record]) -> Option<String> {
    records.iter().rev().find_map(|r| match r.kind() {
        RecordKind::RunCancelled { actor, .. } => Some(actor.clone()),
        _ => None,
    })
}

/// Wall-clock read for the case's `opened_at` stamp.
///
/// Admission happens before any step exists, so there is no `StepCtx` to
/// journal through. The value is descriptive metadata on the case row and never
/// participates in replay — run-visible time still goes through
/// `StepCtx::now`, which journals it.
#[allow(clippy::disallowed_methods)]
fn now_for_admission() -> crate::core::Timestamp {
    crate::core::Timestamp::now_utc()
}

/// The epoch a break-glass record is written under.
///
/// A break-glass run has no competing writer to fence against — it is created,
/// written and sealed in one call — so a constant is honest here for the same
/// reason it is in the sweeper.
const BREAK_GLASS_EPOCH: crate::core::Epoch = 1;

/// How a break-glass run ends. Not a run status: it neither succeeded nor
/// failed at a goal, which is why a sweep seals as `swept` rather than
/// borrowing one.
const BREAK_GLASS_OUTCOME: &str = "broke-glass";

/// One governed identity: a declaration and the skills that serve it.
///
/// A runtime **runs** agents; it is not one. It owns the journal, the stores,
/// the model drivers and the policy engine — infrastructure, shared. An agent
/// owns a manifest and its skills — governance, per-identity. Several agents on
/// one plane share a journal and are still separately declared, separately
/// bounded, and separately answerable.
///
/// Conflating the two forced a runtime per agent, which meant a lease owner per
/// agent for what is one process, a model driver registered once per agent, and
/// nowhere in the journal to record *which* agent governed a run.
#[cfg(feature = "manifest")]
#[derive(Debug, Default)]
pub struct Agent {
    manifest: Option<Arc<crate::manifest::Manifest>>,
    /// Who vouched for the declaration, when it came from a verified resolution.
    publisher: Option<crate::core::KeyId>,
    skills: Vec<Arc<dyn Skill>>,
}

#[cfg(feature = "manifest")]
impl Agent {
    /// An agent governed by this declaration.
    ///
    /// Nobody has vouched for it. Prefer [`Agent::published_by`] where the
    /// manifest came from a verified registry resolution.
    #[must_use]
    pub fn new(manifest: &crate::manifest::Manifest) -> Self {
        Self {
            manifest: Some(Arc::new(manifest.clone())),
            publisher: None,
            skills: Vec::new(),
        }
    }

    /// Record who vouched for this declaration.
    ///
    /// Takes the [`KeyId`](crate::core::KeyId) that
    /// [`Registry::resolve_verified`](crate::manifest::Registry::resolve_verified)
    /// returned beside the manifest — which is otherwise dropped on the floor,
    /// so a verified resolution and a parsed file become indistinguishable the
    /// moment they reach the runtime.
    ///
    /// # Why this is the grouping a policy wants
    ///
    /// A rule has to name *a set of agents*, and the obvious candidates do not
    /// survive contact with a deployment:
    ///
    /// * the **workload identity** is per-instance, so a rule naming one is a
    ///   rule rewritten on every deploy;
    /// * the agent **name**, its **role**, or any group label in the manifest is
    ///   self-asserted — a file claims it, so a rule granting authority to one
    ///   grants it to any file that types the same string;
    /// * the **digest** is unforgeable but names exactly one revision, so every
    ///   edit is a policy change.
    ///
    /// A publisher key is the only one that is both a group — many agents, many
    /// versions — and impossible to claim without holding the key. Bind the rule
    /// to the publisher, keep the digest for "this exact revision", and leave
    /// the name for humans reading logs.
    #[must_use]
    pub fn published_by(mut self, key_id: impl Into<crate::core::KeyId>) -> Self {
        self.publisher = Some(key_id.into());
        self
    }

    /// Give it a skill.
    #[must_use]
    pub fn skill(mut self, skill: impl Skill + 'static) -> Self {
        self.skills.push(Arc::new(skill));
        self
    }
}

/// Assembles a [`Runtime`].
#[derive(Debug)]
pub struct RuntimeBuilder {
    store: Arc<dyn JournalStore>,
    signer: Option<Arc<dyn crate::core::Signer>>,
    skills: Vec<Arc<dyn Skill>>,
    #[cfg(feature = "manifest")]
    tools: Option<(
        Arc<crate::tools::ToolCatalog>,
        Arc<dyn crate::tools::ToolClient>,
    )>,
    tenant: crate::core::TenantId,
    owner: Option<String>,
    lease_ttl: Duration,
    memories: Option<Arc<dyn crate::memory::MemoryStore>>,
    authorities: Option<Arc<dyn crate::authority::AuthorityStore>>,
    metric_tenant: super::metrics::TenantLabel,
    quotas: Option<Arc<dyn crate::quota::QuotaStore>>,
    quota: crate::quota::TenantQuota,
    budget: Budget,
    /// Typed tools whose coherence with every agent is checked at `build`.
    #[cfg(feature = "manifest")]
    toolbox: Option<crate::tools::ToolBox>,
    /// Tool servers reached by some transport other than the box, by name.
    #[cfg(feature = "manifest")]
    tool_servers: Vec<(String, Arc<dyn crate::tools::ToolClient>)>,
    /// Agents registered on this plane, each with its own declaration.
    #[cfg(feature = "manifest")]
    agents: Vec<Agent>,
    /// Drivers by the name a manifest calls them.
    #[cfg(feature = "manifest")]
    providers: HashMap<String, Arc<dyn crate::model::ModelProvider>>,
    cases: Option<Arc<dyn CaseStore>>,
    events: Option<Arc<dyn EventStore>>,
    tasks: Option<Arc<dyn TaskStore>>,
    timers: Option<Arc<dyn TimerStore>>,
    blobs: Option<Arc<dyn crate::blob::BlobStore>>,
    #[cfg(feature = "keyring")]
    keyring: Option<Arc<dyn crate::keyring::KeyRing>>,
    batches: Option<Arc<dyn crate::batch::BatchStore>>,
    policy: Option<Arc<dyn crate::core::PolicyEngine>>,
    identity: Option<crate::core::Delegation>,
    replanner: Option<Arc<dyn crate::plan::Replanner>>,
    calendar: Option<Arc<dyn Calendar>>,
    /// Destinations this deployment sends its own run events to.
    #[cfg(feature = "push")]
    outbox: Option<Arc<crate::push::Outbox>>,
}

impl RuntimeBuilder {
    #[must_use]
    pub fn skill(mut self, s: impl Skill) -> Self {
        self.skills.push(Arc::new(s));
        self
    }

    /// The workload identity this plane signs its outward claims with.
    ///
    /// What it buys is that a tool or peer can *check* who called it. Without a
    /// signer the provenance block still travels — a server can correlate on it
    /// — but it is an assertion any intermediary could have written, and a
    /// callee must not authorize on it.
    ///
    /// Give the store the same signer ([`signing_as`] there) so records and
    /// outward claims carry one identity. They are separate settings because a
    /// plane can legitimately have one without the other.
    ///
    /// [`signing_as`]: crate::store::RedbStore::signing_as
    #[must_use]
    pub fn signing_as(mut self, signer: Arc<dyn crate::core::Signer>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// How long this plane's run leases last.
    ///
    /// The trade is recovery speed against tolerance for a slow instance: a
    /// crashed owner's runs stay unclaimable for this long, and a live owner
    /// must renew within it. The runtime heartbeats while a run executes, so
    /// this bounds *crash* detection rather than how long a run may take.
    ///
    /// # Panics
    ///
    /// Below [`MIN_LEASE_TTL`]. Both stores keep lease expiry in **whole
    /// seconds** and treat `expires_at <= now` as lapsed, so a one-second lease
    /// expires the moment the clock ticks past the second it was written in — no
    /// matter how often it is renewed. Such a lease cannot be held by a live
    /// run, and a run that cannot hold its lease is one any instance may take
    /// away mid-flight. Refused here rather than left as a footgun that only
    /// shows up under load.
    #[must_use]
    pub fn lease_ttl(mut self, ttl: Duration) -> Self {
        assert!(
            ttl >= MIN_LEASE_TTL,
            "a lease of {ttl:?} cannot be renewed: the store keeps expiry in \
             whole seconds and treats `expires_at <= now` as lapsed, so anything \
             under {MIN_LEASE_TTL:?} expires between renewals however often they \
             run — and a run that cannot hold its lease can be taken over while \
             it is still working"
        );
        self.lease_ttl = ttl;
        self
    }

    /// Put this plane's tenant on its metrics.
    ///
    /// Off by default. Read [`metrics::TenantLabel`](super::metrics::TenantLabel)
    /// before turning it on: a tenant name is often a customer name, and a
    /// metrics backend is usually the least protected system in a deployment.
    ///
    /// Cardinality is bounded by construction — the label is *this plane's*
    /// tenant, so the number of streams is the number of planes configured, and
    /// no request can grow it.
    #[must_use]
    pub const fn metric_tenant(mut self, label: super::metrics::TenantLabel) -> Self {
        self.metric_tenant = label;
        self
    }

    /// Give this plane's agents a memory.
    ///
    /// Optional, and absent by default: an agent with no memory is a normal
    /// agent, and one that quietly gained persistent state because a store was
    /// wired for something else would be a surprise.
    ///
    /// Read [`crate::memory`] before wiring one. Writable memory is delayed
    /// code: what is written today is read into a context window tomorrow, where
    /// a model treats it as established fact.
    #[must_use]
    pub fn memory(mut self, memories: Arc<dyn crate::memory::MemoryStore>) -> Self {
        self.memories = Some(memories);
        self
    }

    /// Attach durable standing-authority accounting.
    ///
    /// The ceiling neither of the other two can express. A budget bounds one
    /// run; a quota bounds a tenant over a billing period. A standing authority
    /// bounds *an authorization* — what one customer approved, spanning as many
    /// runs as it takes, revocable when they change their mind.
    ///
    /// Without one, [`StepCtx::draw`](crate::runtime::StepCtx::draw) refuses
    /// rather than falling back to an in-process counter. That fallback would
    /// fail **open** the moment a second instance started, which is exactly when
    /// a shared ceiling was needed.
    #[must_use]
    pub fn authorities(mut self, authorities: Arc<dyn crate::authority::AuthorityStore>) -> Self {
        self.authorities = Some(authorities);
        self
    }

    /// Bound what this tenant may consume, durably.
    ///
    /// Budgets bound one run; this bounds the tenant. Both are needed: a caller
    /// that can start runs can start a thousand, each within its own ceiling.
    ///
    /// The accounting lives in the store, so the ceiling survives a second
    /// instance — an in-process counter would silently double the moment
    /// somebody scales out, which is exactly when it was needed.
    ///
    /// Read [`crate::quota`] for what each ceiling does and does not bound; a
    /// limit believed to bound something it does not is worse than none.
    #[must_use]
    pub fn quota(
        mut self,
        quotas: Arc<dyn crate::quota::QuotaStore>,
        quota: crate::quota::TenantQuota,
    ) -> Self {
        self.quotas = Some(quotas);
        self.quota = quota;
        self
    }

    /// This **process instance's** identity, as it appears in run leases.
    ///
    /// Not the agent's name, and the distinction is load-bearing. A lease is
    /// renewed without bumping the epoch when the holder is *the same owner*, so
    /// two processes sharing an owner string each read the other's lease as
    /// their own: no fencing, no epoch bump, and two writers on one run. That is
    /// precisely the failure the epoch exists to prevent.
    ///
    /// So it must be unique per running process, which is what the default is —
    /// override it only if you have a better instance identity than a random
    /// one, such as a pod name. An agent's *name* is
    /// [`Manifest::metadata`](crate::manifest::Metadata::name); several
    /// instances of one agent are normal and must not share this.
    ///
    /// The owner lives in the lease table and never in the chain, so it has no
    /// bearing on replay.
    #[must_use]
    pub fn owner(mut self, o: impl Into<String>) -> Self {
        self.owner = Some(o.into());
        self
    }

    /// Cap what a run may consume.
    ///
    /// Defaults to [`Budget::unlimited`], which is right for a runtime whose
    /// effects are all free and local, and wrong the moment one of them calls a
    /// metered API.
    #[must_use]
    pub fn budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    /// Attach long-lived case storage, enabling correlation and deadlines.
    #[must_use]
    pub fn cases(mut self, cases: Arc<dyn CaseStore>) -> Self {
        self.cases = Some(cases);
        self
    }

    /// Send this plane's own events to destinations the deployment configured.
    ///
    /// Every run registers each destination **at admission**, so there is no
    /// window in which a run exists and nothing is watching it. Delivery is a
    /// separate, operator-scheduled sweep — see
    /// [`DeliveryWorker`](crate::push::DeliveryWorker) — reading each run's
    /// journal past a cursor that advances only on 2xx.
    ///
    /// This is the mirror image of A2A push, and the mirror is the point: there
    /// the *caller* names a URL and three controls exist because of it. Here the
    /// deployment names it, and the run's own history is the outbox rather than
    /// a queue that can fall out of sync with it.
    #[cfg(feature = "push")]
    #[must_use]
    pub fn outbox(mut self, outbox: Arc<crate::push::Outbox>) -> Self {
        self.outbox = Some(outbox);
        self
    }

    /// Attach inbound-event storage, enabling durable waits.
    #[must_use]
    pub fn events(mut self, events: Arc<dyn EventStore>) -> Self {
        self.events = Some(events);
        self
    }

    /// Attach a worklist, enabling human tasks.
    #[must_use]
    pub fn tasks(mut self, tasks: Arc<dyn TaskStore>) -> Self {
        self.tasks = Some(tasks);
        self
    }

    /// Supply the planner that produces successor plans.
    ///
    /// Without one, a step asking to replan fails with that as the reason —
    /// which is the honest outcome, not a silent no-op.
    #[must_use]
    pub fn replanner(mut self, r: Arc<dyn crate::plan::Replanner>) -> Self {
        self.replanner = Some(r);
        self
    }

    /// Supply the durable-timer store.
    ///
    /// Needed by `StepCtx::sleep` and `sleep_until`, and by the sweep that wakes
    /// them. A runtime without one refuses to sleep rather than falling back to
    /// an in-process wait that a restart would forget.
    #[must_use]
    pub fn timers(mut self, timers: Arc<dyn TimerStore>) -> Self {
        self.timers = Some(timers);
        self
    }

    /// Register an agent on this plane.
    ///
    /// A runtime runs agents; it is not one. This is where a declaration and
    /// its skills arrive together, so several agents can share one journal, one
    /// set of drivers and one process identity while each stays separately
    /// governed.
    ///
    /// The declaration **binds** for that agent's steps: an effect naming a
    /// model or tool its manifest never listed is refused before dispatch and
    /// journaled, and the egress and delegation ceilings combine with the sink's
    /// own — the stricter wins. Its budget bounds its runs. Architectural
    /// injection patterns are deliberately absent from the schema, because this
    /// runtime cannot prove that arbitrary skill code follows one.
    ///
    /// An agent declaring `spec.execution` needs no skill: the runtime supplies
    /// the behaviour. See [`provider`](Self::provider) for the driver mapping it
    /// needs.
    ///
    /// It does **not** set the lease owner. That identifies a *process*, and one
    /// plane running four agents is still one process — see
    /// [`owner`](Self::owner).
    ///
    /// # This call never fails
    ///
    /// It records the agent and returns. Every refusal an agent can cause — a
    /// capability none of its skills provide, a provider no driver is registered
    /// for, oversight with nowhere to put a decision — is raised at
    /// [`build`](Self::build), which panics, or returned by
    /// [`try_build`](Self::try_build), which does not.
    ///
    /// That split matters for a daemon assembling a plane from files it did not
    /// write: a bad manifest is an *input* there, and a panic takes down every
    /// other tenant in the process to report it. This method's documentation
    /// used to carry a `# Panics` section describing `build`'s refusals, which
    /// sent readers looking for a fallible variant of the wrong call.
    #[cfg(feature = "manifest")]
    #[must_use]
    pub fn agent(mut self, agent: Agent) -> Self {
        self.agents.push(agent);
        self
    }

    /// Register a model driver under the name a manifest uses for it.
    ///
    /// The seam a declarative agent needs. A manifest says `provider: anthropic`
    /// — a string a reviewer can read — and something has to map that to a
    /// driver holding a credential. That mapping is deployment wiring, not a
    /// property of the agent, which is exactly why it lives here and not in the
    /// file: an agent's declaration should not change when its API key does.
    ///
    /// Required only for [`ExecutionKind::Completion`] and the other declarative
    /// kinds. A hand-written skill constructs its own `ModelCall` and never
    /// consults this.
    ///
    /// [`ExecutionKind::Completion`]: crate::manifest::ExecutionKind::Completion
    #[cfg(feature = "manifest")]
    #[must_use]
    pub fn provider(
        mut self,
        name: impl Into<String>,
        provider: Arc<dyn crate::model::ModelProvider>,
    ) -> Self {
        self.providers.insert(name.into(), provider);
        self
    }

    /// Supply content-addressed blob storage.
    ///
    /// Needed by `StepCtx::store_blob`, which is how bytes too large for a
    /// journal record get somewhere durable while the chain keeps only their
    /// digest. A runtime without one refuses rather than silently inlining
    /// megabytes into an append-only chain that can never take them back.
    #[must_use]
    pub fn blobs(mut self, blobs: Arc<dyn crate::blob::BlobStore>) -> Self {
        self.blobs = Some(blobs);
        self
    }

    /// The operator's tool catalogue, and the client that reaches those tools.
    ///
    /// Required by a `tool-calling` agent and by nothing else: a skill that
    /// calls tools builds its own [`ToolCall`](crate::tools::ToolCall), because
    /// it knows which client it means. A declarative agent has no code to make
    /// that choice, so the plane makes it once.
    ///
    /// The catalogue is the authority. A manifest grants a subset of it, the
    /// model is offered exactly that subset, and a name the model returns is
    /// matched against it byte for byte.
    #[cfg(feature = "manifest")]
    #[must_use]
    pub fn tools(
        mut self,
        catalog: Arc<crate::tools::ToolCatalog>,
        client: Arc<dyn crate::tools::ToolClient>,
    ) -> Self {
        self.tools = Some((catalog, client));
        self
    }

    /// Typed tools, with their catalogue derived and their coherence enforced.
    ///
    /// The one-call form, and the reason it exists is not brevity. Deriving the
    /// catalogue and checking it against every agent's manifest were both
    /// possible before and both **optional**, and a control a caller may forget
    /// is not a control — it is advice that reads like one.
    ///
    /// So this does three things that were three things:
    ///
    /// * derives the catalogue from each agent's declaration, so a grant, its
    ///   ceiling and its protected fields are stated once;
    /// * refuses to build if the tools this binary implements and the manifests
    ///   a reviewer approved have drifted apart;
    /// * wires the box as the client.
    ///
    /// The work happens in [`build`](Self::build) rather than here, and that is
    /// the whole reason it is trustworthy: checking on this call would check
    /// against the agents registered *so far*, so `.toolbox(..).agent(..)` would
    /// pass by having nothing to disagree with. An enforcement that depends on
    /// the order a builder was written is not one.
    #[cfg(feature = "manifest")]
    #[must_use]
    pub fn toolbox(mut self, tools: crate::tools::ToolBox) -> Self {
        self.toolbox = Some(tools);
        self
    }

    /// A tool server this plane reaches over some transport of its own.
    ///
    /// An MCP connection is the usual one. Registering it does three things that
    /// were previously impossible together:
    ///
    /// * a plane may reach **several** servers, because the router resolves the
    ///   `tool://server/name` a grant carries rather than handing every id to one
    ///   client;
    /// * typed in-process tools and remote servers can be used by the *same*
    ///   agent, which is the ordinary shape and used to be unrepresentable;
    /// * a grant naming a server nobody wired is refused at build, in the same
    ///   breath as a grant nothing implements — both mean the model would be
    ///   offered a tool that fails when chosen.
    ///
    /// Composes with [`toolbox`](Self::toolbox); the box answers for the servers
    /// its own tools name and these answer for theirs. A server claimed twice is
    /// a panic, because registration order deciding which transport carries a
    /// call is the defect [`ToolRouter`](crate::tools::ToolRouter) exists to
    /// remove.
    #[cfg(feature = "manifest")]
    #[must_use]
    pub fn tool_server(
        mut self,
        name: impl Into<String>,
        client: Arc<dyn crate::tools::ToolClient>,
    ) -> Self {
        self.tool_servers.push((name.into(), client));
        self
    }

    /// Which tenant this plane runs as.
    ///
    /// **One plane, one tenant — but one process, many planes.** A plane is the
    /// unit that is bound to a tenant; serving several is
    /// [`Planes`](crate::api::Planes)' job, and it resolves the plane from the
    /// authenticated caller's tenant rather than from the request, so a handler
    /// cannot reach a store it did not resolve. An unregistered tenant is
    /// refused rather than defaulted.
    ///
    /// The name scopes **data keys**, so one tenant's cryptographic erasure
    /// cannot reach another's bytes, and it reaches the **policy request**, so a
    /// rule can be written per tenant.
    ///
    /// It does **not** scope the store — that is a separate handle, scoped by
    /// `RedbStore::for_tenant` or `PostgresStore::for_tenant`. Two tenants may
    /// share one store, because the tenant is a key component of every row on
    /// both backends rather than a filter. Setting one and not the other is
    /// refused at [`build`](Self::build) rather than discovered later: a plane
    /// whose store is scoped elsewhere works perfectly and writes its runs into
    /// somebody else's keyspace.
    ///
    /// Defaults to `default`, which is a real tenant rather than an absence: the
    /// single-tenant path is then the same code as the multi-tenant one, and a
    /// special "no tenant" case is a second path that would not get tested.
    #[must_use]
    pub fn tenant(mut self, tenant: crate::core::TenantId) -> Self {
        self.tenant = tenant;
        self
    }

    /// Seal payload bytes, and make erasure reach copies deletion cannot.
    ///
    /// With a key ring configured, everything written through
    /// [`StepCtx::blobs`](crate::runtime::StepCtx::blobs) — including
    /// [`store_blob`](crate::runtime::StepCtx::store_blob) and governed media —
    /// is encrypted under a data key belonging to the run's **case**. Erasing
    /// that case destroys the key, so every copy of those bytes becomes
    /// unreadable at once: the live store, the replicas, and every backup ever
    /// taken. Expiring blobs only reaches the first of those.
    ///
    /// The case is the erasure unit because it is already the retention unit —
    /// bytes are linked to their case at write time, and a second, differently
    /// shaped unit for keys would let the two disagree about what an erasure
    /// covered.
    ///
    /// It also seals the stores the plane holds — the journal's payloads, case
    /// state, task proposals and buffered event payloads — at
    /// [`build`](Self::build), so the order they were registered in cannot lose
    /// the guarantee — a store registered after this call is sealed just the
    /// same.
    ///
    /// **Governed memory is the one store this does not reach.**
    /// [`EncryptedMemoryStore`](crate::keyring::EncryptedMemoryStore)
    /// serialises subject erasure against writes and legal-hold changes with a
    /// process-local mutex, so it holds its contract on a single-writer
    /// deployment and nowhere else; wrapping it here would hand that adapter to
    /// an active-active `PostgreSQL` plane, where the mutex coordinates nothing
    /// and the hold race it exists to prevent is the result. Its erasure unit
    /// is `tenant/memory/<subject>` and outlives every case, so `erase_case`
    /// was never the act that reaches it either. Wrap it yourself, where the
    /// deployment's topology is visible:
    ///
    /// ```ignore
    /// let memories = EncryptedMemoryStore::new(inner, keys.clone(), tenant.clone());
    /// Runtime::builder(store).memory(Arc::new(memories)).keyring(keys).build()
    /// ```
    ///
    /// Without one, bytes are stored as given and erasure remains deletion.
    #[cfg(feature = "keyring")]
    #[must_use]
    pub fn keyring(mut self, keyring: Arc<dyn crate::keyring::KeyRing>) -> Self {
        self.keyring = Some(keyring);
        self
    }

    /// Wrap every store a key ring can seal, at **build** time.
    ///
    /// One call, one guarantee. Before this, `keyring` sealed blob payloads
    /// and nothing else — which was honest when blobs were the only sealable
    /// surface and became a trap the moment they were not: a deployer who
    /// configured a key ring would reasonably read it as *this plane is
    /// encrypted* while the journal, the case store, the worklist and the
    /// event buffer stayed in the clear. Five independent wrapping calls is a
    /// control that can be forgotten four times, and forgetting looks exactly
    /// like remembering.
    ///
    /// Wrapped here rather than inside `keyring()` for the reason the tool
    /// catalogue is checked here: a wrap applied when the ring is supplied
    /// would cover only the stores registered so far, so `keyring(..)` before
    /// `cases(..)` would silently seal less than `keyring(..)` after it. An
    /// enforcement a reordering can lose is one a reformatter can delete.
    ///
    /// Every decorator is handed `self.tenant` rather than reading a name back
    /// out of the store it wraps, so all four derive the erasure scope from one
    /// value. `keyring()`'s own documentation names the one store deliberately
    /// left out, and why.
    #[cfg(feature = "keyring")]
    fn seal_stores(&mut self) {
        let Some(keys) = self.keyring.clone() else {
            return;
        };
        let tenant = self.tenant.clone();
        self.store = crate::keyring::SealedJournal::wrap(
            Arc::clone(&self.store),
            Arc::clone(&keys),
            tenant.clone(),
        );
        if let Some(cases) = self.cases.take() {
            self.cases = Some(crate::keyring::SealedCases::wrap(
                cases,
                Arc::clone(&keys),
                tenant.clone(),
            ));
        }
        if let Some(events) = self.events.take() {
            self.events = Some(crate::keyring::SealedEvents::wrap(
                events,
                Arc::clone(&keys),
                tenant.clone(),
            ));
        }
        // The outbox's store keeps the operator destinations' bearer tokens —
        // credentials like any caller's, and the one store here reached through
        // a handle the embedder built rather than registered. Sealing it in the
        // same sweep is what keeps `keyring()` one decision rather than five
        // and a sixth.
        #[cfg(feature = "push")]
        if let Some(outbox) = self.outbox.take() {
            self.outbox = Some(Arc::new(
                outbox
                    .as_ref()
                    .clone()
                    .sealed(Arc::clone(&keys), tenant.clone()),
            ));
        }
        if let Some(tasks) = self.tasks.take() {
            self.tasks = Some(crate::keyring::SealedTasks::wrap(tasks, keys, tenant));
        }
    }

    /// Without the `keyring` feature there is nothing to seal.
    #[cfg(not(feature = "keyring"))]
    #[allow(clippy::unused_self)]
    fn seal_stores(&mut self) {}

    /// Supply the store that tracks batch items.
    ///
    /// Only needed for [`Runtime::run_batch`]; a plane that runs no batches does
    /// not need one, and asking for it unconditionally would make the common
    /// case carry the uncommon one's setup.
    #[must_use]
    pub fn batches(mut self, batches: Arc<dyn crate::batch::BatchStore>) -> Self {
        self.batches = Some(batches);
        self
    }

    /// Supply the authorization engine.
    ///
    /// Without one there is no policy layer — the information-flow gates still
    /// apply, but nothing asks whether the principal was allowed. That is a
    /// deliberate absence rather than a permissive default: see `core::policy`
    /// on why there is no `AllowAll` to configure by mistake.
    ///
    /// The engine's complete immutable bundle identity is recorded at admission,
    /// so both whether policy was on and exactly which executable semantics
    /// governed the run are answerable from the journal. An open run may resume
    /// only under that same identity.
    #[must_use]
    pub fn policy(mut self, policy: Arc<dyn crate::core::PolicyEngine>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Act under a verified delegation chain.
    ///
    /// The chain is checked against the plan at admission — the plan is the
    /// authorization graph, so a plan that exceeds the chain's authority never
    /// starts — and journaled, so "on whose behalf" is answerable from history
    /// rather than reconstructed from timestamps.
    ///
    /// Verification of the *credential* belongs to a
    /// [`DelegationScheme`](crate::core::DelegationScheme); what arrives here is
    /// already a chain, and its attenuation is guaranteed by its own
    /// constructors however it was obtained.
    #[must_use]
    pub fn acting_as(mut self, chain: crate::core::Delegation) -> Self {
        self.identity = Some(chain);
        self
    }

    /// Supply the calendar that resolves deadline descriptions to instants.
    ///
    /// Defaults to [`WallClock`], which understands plain offsets and refuses
    /// anything it does not know rather than approximating it. Domain calendars
    /// — working days, holidays, cut-off hours — are the adapter's job.
    #[must_use]
    pub fn calendar(mut self, calendar: Arc<dyn Calendar>) -> Self {
        self.calendar = Some(calendar);
        self
    }

    /// Derive the tool catalogue from the agents and refuse a disagreement.
    ///
    /// Every agent, not the first: a plane may host several, and a tool granted
    /// to none of them is still a tool this binary can be asked for.
    ///
    /// # Errors
    ///
    /// If the box and any agent's manifest disagree. A build-time
    /// misconfiguration has a fix and no recovery, and it is refused the way the
    /// tenant mismatch beside it is: before anything runs.
    #[cfg(feature = "manifest")]
    fn settle_toolbox(&mut self) -> Result<(), BuildError> {
        let servers = std::mem::take(&mut self.tool_servers);
        let tools = self.toolbox.take();
        if tools.is_none() && servers.is_empty() {
            return Ok(());
        }
        let tools = tools.unwrap_or_default();
        let remote_servers: std::collections::BTreeSet<String> =
            servers.iter().map(|(name, _)| name.clone()).collect();
        // `agent` names agents on this plane, and only them. A transport or a
        // typed tool under that name would let a deployment decide whether a
        // reviewed grant means "an agent here" or "somebody's server".
        if remote_servers.contains(crate::tools::AGENT_SERVER)
            || tools
                .servers()
                .any(|server| server == crate::tools::AGENT_SERVER)
        {
            return Err(BuildError::ReservedToolServer);
        }
        if remote_servers.len() != servers.len() {
            // The set lost an entry, so some name appears twice. Naming it beats
            // reporting a count a reader then has to go and diff by hand.
            let mut seen = std::collections::BTreeSet::new();
            let duplicate = servers
                .iter()
                .map(|(name, _)| name)
                .find(|name| !seen.insert((*name).clone()))
                .cloned()
                .unwrap_or_default();
            return Err(BuildError::DuplicateToolServer { server: duplicate });
        }
        // Both forms wired is not a merge and must not silently be one. The
        // hand-built catalogue is the operator saying something deliberate; the
        // derived one is the agent's declaration. Overwriting either with the
        // other would run a plane under grants nobody chose.
        if self.tools.is_some() {
            return Err(BuildError::ToolsWiredTwice);
        }
        let mut catalog = crate::tools::ToolCatalog::new();
        let mut declared = 0usize;
        // Which agent's declaration a tool's catalogue entry came from, so a
        // second agent declaring the same tool *differently* is a build-time
        // refusal rather than a silent overwrite.
        //
        // A plane has one catalogue and its agents have one manifest each, so
        // two agents granting `tool://ledger/read` with different protected
        // fields cannot both be satisfied. Merging by last-writer would resolve
        // it by **registration order** — the one thing this builder already
        // says an enforcement must never depend on — and it fails at a
        // distance: `declared` compares each agent's manifest against the
        // catalogue-derived descriptor exactly, so the agent that lost the race
        // is refused *every* call to that tool, in production, with a message
        // blaming a code-versus-manifest drift that neither file exhibits.
        let mut source: BTreeMap<crate::tools::ToolId, (String, crate::tools::ToolSafety)> =
            BTreeMap::new();
        for agent in &self.agents {
            let Some(manifest) = agent.manifest.as_ref() else {
                continue;
            };
            declared += 1;
            tools
                .check_against(manifest, &remote_servers)
                .map_err(|problems| BuildError::ToolDrift {
                    agent: manifest.metadata.name.clone(),
                    problems,
                })?;
            for (id, safety) in crate::tools::ToolCatalog::from_manifest(manifest).entries() {
                if let Some((first, existing)) = source.get(&id) {
                    if existing != &safety {
                        return Err(BuildError::ToolDeclaredTwoWays {
                            tool: id.reference(),
                            first: first.clone(),
                            second: manifest.metadata.name.clone(),
                        });
                    }
                    continue;
                }
                source.insert(id.clone(), (manifest.metadata.name.clone(), safety.clone()));
                catalog = catalog.allow(id, safety);
            }
        }
        // A box with nothing to be coherent *with* is the same defect one step
        // earlier: tools wired to a plane where no declaration admits them, so
        // nothing a reviewer reads describes what this binary can reach.
        if declared == 0 {
            return Err(BuildError::ToolsWithoutDeclaration);
        }
        // The typed argument type is the schema source. Overlay its
        // presentation only after every manifest has been checked, so the
        // model sees exactly what the body will deserialize rather than the
        // old permissive `{ type: object }` fallback.
        for id in tools.ids() {
            let (description, schema, _) = tools
                .declared(id)
                .expect("every registered typed tool has a declaration");
            let reviewed_description = catalog
                .declaration(id)
                .map_or_else(|| description.to_owned(), |(text, _)| text.to_owned());
            catalog = catalog.declare(id.clone(), reviewed_description, schema.clone());
        }
        // One client per server, resolved by the name a grant carries. A single
        // client handed every id could not tell `tool://ledger/read` from
        // `tool://tickets/read`, and a transport that never reads the server
        // component answers both — from whichever server it happens to hold.
        let router = servers.into_iter().fold(
            crate::tools::ToolRouter::new().toolbox(&Arc::new(tools)),
            |router, (name, client)| router.server(name, client),
        );
        self.tools = Some((
            Arc::new(catalog),
            Arc::new(router) as Arc<dyn crate::tools::ToolClient>,
        ));
        Ok(())
    }

    /// Settle the tool catalogue: derive it if asked, then hold it to the
    /// declarations.
    ///
    /// One call because the two halves are one decision seen from either side.
    /// [`settle_toolbox`](Self::settle_toolbox) covers the derived catalogue,
    /// where code and manifest could disagree; the check after it covers the
    /// stated one, where operator and manifest could. Whichever way the
    /// catalogue arrived, it is checked before anything runs.
    #[cfg(feature = "manifest")]
    fn settle_tools(&mut self) -> Result<(), BuildError> {
        self.settle_toolbox()?;
        self.check_catalogue_not_laxer_than_grants()
    }

    /// Refuse a stated catalogue that is **laxer** than a reviewed grant.
    ///
    /// `toolbox(..)` derives the catalogue from the manifests, so the two
    /// cannot drift. `tools(..)` states it by hand, and there the operator's
    /// entry and the agent's declaration are two copies of one decision — with
    /// nothing, until this, that noticed them disagreeing.
    ///
    /// Only one direction is a defect, the same one
    /// [`ToolBox::check_against`](crate::tools::ToolBox::check_against) refuses.
    /// An operator being **more** cautious than the declaration is fine and
    /// often right. An operator being **less** cautious is not, and it changes
    /// two things at once:
    ///
    /// * the whole-value taint gate stops firing, so model-chosen arguments
    ///   reach something that changes the world;
    /// * `ToolSafety::read_only` carries `Recovery::Retry`, so a timed-out call
    ///   to a money-moving tool is sent a second time.
    ///
    /// The dispatch gates already take the stricter `mutates` of the two, so
    /// the first is contained at runtime. The second is not — recovery is read
    /// from the catalogue alone — and neither should have to be, because this
    /// is a wiring mistake with a fix and no recovery. It is refused here,
    /// beside the rest of them.
    #[cfg(feature = "manifest")]
    fn check_catalogue_not_laxer_than_grants(&self) -> Result<(), BuildError> {
        let Some((catalog, _)) = self.tools.as_ref() else {
            return Ok(());
        };
        let mut problems = Vec::new();
        for agent in &self.agents {
            let Some(manifest) = agent.manifest.as_ref() else {
                continue;
            };
            for grant in &manifest.spec.tools {
                if !grant.mutates {
                    continue;
                }
                let Some(id) = crate::tools::ToolId::parse(&grant.reference) else {
                    continue;
                };
                if catalog.safety(&id).is_some_and(|s| !s.mutates) {
                    problems.push(format!(
                        "agent '{}' grants '{}' as mutating and the stated catalogue \
                         calls it read-only",
                        manifest.metadata.name, grant.reference
                    ));
                }
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(BuildError::CatalogueLaxerThanGrant { problems })
        }
    }

    /// Assemble the runtime, or panic naming the wiring mistake.
    ///
    /// The ordinary entry point. Every refusal below is a bug in code the author
    /// is looking at, so propagating it through `?` to a `main` that prints it
    /// is ceremony around an abort — and each is caught here at startup rather
    /// than at dispatch, in production, where the cost is a run that has already
    /// begun.
    ///
    /// Use [`try_build`](Self::try_build) where a manifest arrives at *runtime*
    /// — read from disk, pinned by a registry, or supplied per tenant. There a
    /// bad declaration is an input rather than a bug, and a panic would take
    /// every other tenant in the process down to report it.
    ///
    /// # Panics
    ///
    /// On any [`BuildError`]:
    ///
    /// * A manifest declares a capability in `spec.capabilities.provides` that
    ///   no registered skill provides. **An agent has skills**, so a declaration
    ///   advertising one it cannot perform is a card that lies.
    /// * Two agents claim the same capability. Dispatch resolves a capability to
    ///   one skill *and to the manifest governing it*, so a second claim would
    ///   silently take the first's work out from under the first's budget,
    ///   model grants and egress ceiling.
    /// * Two skills share a name. A name is what a capability resolves to and
    ///   what governance is keyed on; two of them make both lookups arbitrary.
    /// * A stated catalogue calls a tool read-only that a reviewed manifest
    ///   grants as mutating. That exemption drops the whole-value taint gate
    ///   and makes a timed-out money-moving call retryable — the one direction
    ///   an operator cannot be right about.
    /// * A declarative agent names a provider no driver is registered for, or
    ///   declares `spec.execution` without a privileged model to call.
    /// * A plane and its store — or its blob store — are scoped to different
    ///   tenants. The two are set
    ///   separately — this builder's tenant scopes data keys and the policy
    ///   request, `for_tenant` scopes the store's keys — and the mismatch does
    ///   not show up at runtime. It *works*, and writes this tenant's runs into
    ///   another's keyspace while every erasure and every policy request names
    ///   the right one.
    ///
    /// # Long-running services want [`try_build`](Self::try_build)
    ///
    /// This panics, which is the honest answer for a binary wiring its own
    /// skills: every variant above is a bug in code the author is looking at,
    /// and aborting reports it at the moment it can be fixed. A daemon is a
    /// different case — it wants to exit with a diagnostic, and a plane
    /// assembled from a manifest that arrived at runtime is handling an *input*,
    /// where a panic reports one tenant's typo by killing every other tenant's
    /// in-flight run. `try_build` returns the same `BuildError` instead. One
    /// implementation underneath both, so they cannot disagree about what is
    /// refused.
    #[must_use]
    pub fn build(self) -> Arc<Runtime> {
        // Not `expect`. That formats the error with `Debug`, which would print
        // `AdvertisesWhatItCannotProvide { agent: "…", missing: [...] }` — the
        // variant's *shape* — while the sentence explaining what to do about it
        // lives in `Display`. Panicking with `{error}` keeps the two entry
        // points telling one story, which is the whole point of `build` being
        // `try_build` underneath.
        match self.try_build() {
            Ok(runtime) => runtime,
            Err(error) => panic!("{error}"),
        }
    }

    /// Assemble the runtime, or say why it cannot be.
    ///
    /// The same checks as [`build`](Self::build), returned rather than raised.
    /// One implementation behind both, so they cannot come to disagree about
    /// what is refused.
    ///
    /// # Errors
    ///
    /// Any [`BuildError`] — see [`build`](Self::build) for what each means.
    // `mut` is for `settle_toolbox`, which only exists when manifests do.
    #[cfg_attr(not(feature = "manifest"), allow(unused_mut))]
    #[allow(clippy::too_many_lines)]
    pub fn try_build(mut self) -> Result<Arc<Runtime>, BuildError> {
        check_same_tenant(
            self.store.as_ref(),
            self.blobs.as_ref(),
            self.memories.as_ref(),
            &self.tenant,
        )?;
        self.seal_stores();
        #[cfg(feature = "manifest")]
        self.settle_tools()?;

        let mut skills = HashMap::new();
        let mut by_capability = HashMap::new();
        #[cfg(feature = "manifest")]
        let mut governed_by: HashMap<String, Arc<crate::manifest::Manifest>> = HashMap::new();
        #[cfg(feature = "manifest")]
        let mut published_by: HashMap<String, crate::core::KeyId> = HashMap::new();

        // Skills registered directly belong to the plane's anonymous agent: no
        // declaration, so nothing to enforce against them beyond the runtime's
        // own budget. That is a legitimate shape — not every agent needs a
        // manifest — and it is why `skill()` still exists beside `agent()`.
        for s in self.skills {
            register_skill(s, &mut by_capability, &mut skills)?;
        }

        #[cfg(feature = "manifest")]
        for agent in self.agents {
            if let (Some(m), Some(key)) = (agent.manifest.as_ref(), agent.publisher.clone()) {
                published_by.insert(m.metadata.name.clone(), key);
            }
            let Some(m) = agent.manifest.clone() else {
                for s in agent.skills {
                    register_skill(s, &mut by_capability, &mut skills)?;
                }
                continue;
            };

            // The capabilities this agent's *own* skills provide, which is what
            // its declaration is checked against below.
            let mut mine: HashSet<Capability> = HashSet::new();
            for s in agent.skills {
                mine.extend(s.descriptor().capabilities());
                let name = register_skill(s, &mut by_capability, &mut skills)?;
                governed_by.insert(name, Arc::clone(&m));
            }

            // A declarative agent needs no skill: the runtime supplies the
            // behaviour its manifest asked for.
            if let Some(execution) = &m.spec.execution {
                let model = m
                    .spec
                    .models
                    .as_ref()
                    .and_then(|x| x.privileged.as_ref())
                    .ok_or_else(|| BuildError::DeclarativeWithoutModel {
                        agent: m.metadata.name.clone(),
                    })?;
                // Named rather than defaulted. Falling back to some other
                // registered driver would run the agent on a model its own
                // declaration does not name.
                let provider = self
                    .providers
                    .get(&model.provider)
                    .map(Arc::clone)
                    .ok_or_else(|| BuildError::UnknownProvider {
                        agent: m.metadata.name.clone(),
                        provider: model.provider.clone(),
                    })?;
                if m.spec.capabilities.provides.is_empty() {
                    return Err(BuildError::DeclarativeProvidesNothing {
                        agent: m.metadata.name.clone(),
                    });
                }
                // A plane whose only tools are agents needs no toolbox and no
                // transport: the catalogue is derived from the declaration and
                // dispatch is `commission`. The empty router is deliberate —
                // an agent-server call never reaches it, and anything else
                // arriving there is refused as unreachable rather than
                // silently absorbed.
                let tools = self.tools.clone().or_else(|| {
                    let all_agent = !m.spec.tools.is_empty()
                        && m.spec.tools.iter().all(|g| {
                            crate::tools::ToolId::parse(&g.reference)
                                .is_some_and(|id| id.server == crate::tools::AGENT_SERVER)
                        });
                    all_agent.then(|| {
                        (
                            Arc::new(crate::tools::ToolCatalog::from_manifest(&m)),
                            Arc::new(crate::tools::ToolRouter::new())
                                as Arc<dyn crate::tools::ToolClient>,
                        )
                    })
                });
                // A tool loop with nothing to reach fails on every run with the
                // same sentence, and the manifest that says so was read at
                // build. `planned` only needs a catalogue when it has grants;
                // `tool-calling` needs one to exist at all, since offering a
                // model no tools is not a tool loop.
                if tools.is_none() {
                    let needs = match execution.kind {
                        crate::manifest::ExecutionKind::ToolCalling => {
                            Some(if m.spec.tools.is_empty() {
                                "no tool grants".to_owned()
                            } else {
                                format!("{} tool grant(s)", m.spec.tools.len())
                            })
                        }
                        crate::manifest::ExecutionKind::Planned if !m.spec.tools.is_empty() => {
                            Some(format!("{} tool grant(s)", m.spec.tools.len()))
                        }
                        _ => None,
                    };
                    if let Some(grants) = needs {
                        return Err(BuildError::DeclarativeToolsUnreachable {
                            agent: m.metadata.name.clone(),
                            kind: execution.kind.as_str(),
                            grants,
                        });
                    }
                }

                // Oversight needs somewhere to put the decision, and both
                // halves are known here. Left to run time it surfaces at the
                // first real approval — a person already waiting, on the code
                // path a test suite is least likely to reach.
                let declared = if m.spec.oversight.is_some() {
                    Some("`spec.oversight`".to_owned())
                } else if m.spec.tools.iter().any(|g| g.requires_approval) {
                    Some("a grant with `requires_approval: true`".to_owned())
                } else {
                    None
                };
                if let Some(declared) = declared {
                    // Ordered by what a reader fixes first: without a case
                    // there is nothing for a task to hang off.
                    //
                    // Timers are deliberately **not** required, and the test
                    // suite is why: four approval tests wire a case store and a
                    // worklist, no timers, and run an approval end to end. A
                    // task is opened, the run suspends, a person decides. What
                    // a timer store adds is the sweeper firing `on_expiry`, and
                    // refusing a configuration that works would be this check
                    // asserting more than it knows — the failure mode it exists
                    // to prevent, arriving from the other side.
                    let missing = if self.cases.is_none() {
                        Some(("case store", "cases"))
                    } else if self.tasks.is_none() {
                        Some(("worklist", "tasks"))
                    } else {
                        None
                    };
                    if let Some((missing, remedy)) = missing {
                        return Err(BuildError::OversightUnreachable {
                            agent: m.metadata.name.clone(),
                            declared,
                            missing,
                            remedy,
                        });
                    }
                }

                // Formation writes after the answer, so a missing store is a
                // failure the run pays for in full before reaching. Both facts
                // are here: the file says memories are written, the plane says
                // there is nowhere to write them.
                if let Some(formation) = &m.spec.memory_formation {
                    if self.memories.is_none() {
                        return Err(BuildError::FormationWithoutMemory {
                            agent: m.metadata.name.clone(),
                        });
                    }
                    if formation.subject.needs_case() && self.cases.is_none() {
                        return Err(BuildError::MemorySubjectUnbindable {
                            agent: m.metadata.name.clone(),
                            subject: formation.subject.as_written(),
                        });
                    }
                }

                for cap in &m.spec.capabilities.provides {
                    let skill: Arc<dyn Skill> = Arc::new(super::declarative::Declarative::new(
                        execution.kind,
                        cap.clone(),
                        m.metadata.name.clone(),
                        Arc::clone(&provider),
                        tools.clone(),
                        execution.max_turns,
                    ));
                    mine.insert(Capability::new(cap.as_str()));
                    let name = register_skill(skill, &mut by_capability, &mut skills)?;
                    governed_by.insert(name, Arc::clone(&m));
                }
            }

            check_advertises_what_it_provides(&m, &mine)?;
        }

        // Agent grants are validated against the finished plane, because the
        // capability they name may belong to an agent registered *later* — a
        // check inside the loop would pass or fail on registration order.
        #[cfg(feature = "manifest")]
        {
            let mut checked = std::collections::BTreeSet::new();
            for m in governed_by.values() {
                if !checked.insert(m.metadata.name.clone()) {
                    continue;
                }
                for grant in &m.spec.tools {
                    let Some(id) = crate::tools::ToolId::parse(&grant.reference) else {
                        continue;
                    };
                    if id.server != crate::tools::AGENT_SERVER {
                        continue;
                    }
                    if m.spec.capabilities.provides.contains(&id.tool) {
                        return Err(BuildError::AgentToolSelfReference {
                            agent: m.metadata.name.clone(),
                            capability: id.tool,
                        });
                    }
                    if !by_capability.contains_key(&Capability::new(id.tool.as_str())) {
                        return Err(BuildError::AgentToolUnknownCapability {
                            agent: m.metadata.name.clone(),
                            capability: id.tool,
                        });
                    }
                }
            }
        }

        Ok(Arc::new_cyclic(|self_ref| Runtime {
            self_ref: self_ref.clone(),
            signer: self.signer,
            store: self.store,
            skills,
            by_capability,
            #[cfg(feature = "manifest")]
            published_by,
            #[cfg(feature = "manifest")]
            providers: self.providers,
            meter: super::metrics::Meter::new(self.metric_tenant, &self.tenant),
            tenant: self.tenant,
            owner: self.owner.unwrap_or_else(default_owner),
            lease_ttl: self.lease_ttl,
            memories: self.memories,
            authorities: self.authorities,
            #[cfg(feature = "manifest")]
            tools: self.tools,
            quotas: self.quotas,
            quota: self.quota,
            budget: self.budget,
            cases: self.cases,
            events: self.events,
            tasks: self.tasks,
            timers: self.timers,
            blobs: self.blobs,
            #[cfg(feature = "keyring")]
            keyring: self.keyring,
            batches: self.batches,
            policy: self.policy,
            identity: self.identity,
            replanner: self.replanner,
            calendar: self.calendar.unwrap_or_else(|| Arc::new(WallClock)),
            #[cfg(feature = "push")]
            outbox: self.outbox,
            #[cfg(feature = "manifest")]
            governed_by,
        }))
    }
}

/// Refuse a plane whose store serves a different tenant.
///
/// Not a misconfiguration that shows up at runtime — it *works*, and writes this
/// tenant's runs into another's keyspace while every key-scoped erasure and
/// every policy request names the right one. The two are set separately, so the
/// mismatch is easy to make and invisible once made.
fn check_same_tenant(
    store: &dyn JournalStore,
    blobs: Option<&Arc<dyn crate::blob::BlobStore>>,
    memories: Option<&Arc<dyn crate::memory::MemoryStore>>,
    tenant: &crate::core::TenantId,
) -> Result<(), BuildError> {
    if let Some(blobs) = blobs
        && blobs.tenant() != tenant.as_str()
    {
        return Err(BuildError::BlobStoreTenant {
            plane: tenant.to_string(),
            store: blobs.tenant().to_owned(),
        });
    }
    if store.tenant() != tenant.as_str() {
        return Err(BuildError::JournalStoreTenant {
            plane: tenant.to_string(),
            store: store.tenant().to_owned(),
        });
    }

    // After the tenant checks, deliberately: a store scoped to the wrong tenant
    // is the more basic fault, and reporting the erasure lock first would send
    // an operator to fix the second-most-wrong thing.
    //
    // A process-local erasure lock beside a store two instances can write is a
    // control that reads as present and is not. The window it fails to close is
    // between an erasure's legal-hold check and its key destruction: the other
    // instance writes an item, that item is sealed under a scope about to stop
    // existing, and the erasure reports success. Both facts are here, so the
    // refusal is here.
    if store.is_shared() && memories.is_some_and(|m| m.erasure_is_distributed() == Some(false)) {
        return Err(BuildError::ErasureCoordinatorNotShared);
    }
    Ok(())
}

/// Inbound event delivery.
impl Runtime {
    /// Deliver an inbound event, resuming whichever run was waiting for it.
    ///
    /// # Ordering
    ///
    /// The event is **stored before** anyone looks for a waiter. That ordering
    /// is the whole reason this works: a message can arrive before its run
    /// reaches the wait, and one that is matched-then-discarded leaves that run
    /// waiting forever for something that already happened.
    ///
    /// A [`Delivery::Buffered`] result is therefore normal and not an error —
    /// it means "held until someone asks". Only the sweep
    /// ([`EventStore::sweep_unclaimed`](crate::case::EventStore::sweep_unclaimed))
    /// decides an event is genuinely unroutable, because that is a claim about
    /// the future rather than about this instant.
    pub async fn deliver(&self, event: &InboundEvent) -> Result<Delivery, RuntimeError> {
        let events = self.events.as_ref().ok_or_else(|| {
            RuntimeError::PlanContract(
                "this runtime has no event store — build it with `.events(store)`".into(),
            )
        })?;

        let now = now_for_admission();

        // Durable first. Deduplication by event id makes a counterparty's retry
        // — and they all retry — harmless.
        if !events
            .buffer(event, now)
            .await
            .map_err(RuntimeError::from_store)?
        {
            return Ok(Delivery::Duplicate);
        }

        let Some(sub) = events
            .match_waiter(event, now)
            .await
            .map_err(RuntimeError::from_store)?
        else {
            return Ok(Delivery::Buffered);
        };

        self.resume_subscription(events, sub, event).await
    }

    /// Deliver an inbound event to exactly `run`.
    ///
    /// This is the task-addressed counterpart to [`Runtime::deliver`]. It is
    /// used by protocols such as A2A where a follow-up carries a concrete task
    /// id. Correlation alone is insufficient there: two tasks may wait on the
    /// same business key, and resuming the oldest would violate the request.
    ///
    /// The event store atomically inserts and claims the event for this run. A
    /// run that is not waiting leaves no buffered event behind for another run.
    pub async fn deliver_to(
        &self,
        run: RunId,
        event: &InboundEvent,
    ) -> Result<Delivery, RuntimeError> {
        let events = self.events.as_ref().ok_or_else(|| {
            RuntimeError::PlanContract(
                "this runtime has no event store — build it with `.events(store)`".into(),
            )
        })?;
        match events
            .deliver_to(run, event, now_for_admission())
            .await
            .map_err(RuntimeError::from_store)?
        {
            crate::case::TargetedDelivery::Duplicate => Ok(Delivery::Duplicate),
            crate::case::TargetedDelivery::NotWaiting => Err(RuntimeError::PlanContract(format!(
                "run {run} is not waiting for this input"
            ))),
            crate::case::TargetedDelivery::Matched(sub) => {
                self.resume_subscription(events, sub, event).await
            }
        }
    }

    async fn resume_subscription(
        &self,
        events: &Arc<dyn crate::case::EventStore>,
        sub: crate::core::Subscription,
        event: &InboundEvent,
    ) -> Result<Delivery, RuntimeError> {
        // Record the event as the awaited effect's result, then let replay do
        // the rest: the resumed run reads it back like any other completed
        // effect, and none of the suspension machinery exists twice.
        //
        // The lease may be briefly held: an event can arrive in the window
        // between the run registering its subscription and its owner finishing
        // the suspension bookkeeping — the owner is *concluding*, and will
        // release within milliseconds. That race used to be fatal in the
        // quietest possible way: the delivery failed `LeaseHeld` **after** the
        // event was durably claimed for this run, the counterparty's retry
        // deduplicated against the claimed event, and nothing ever resumed the
        // run — a message that arrived in time, parked forever. So the claim
        // is retried under a bounded backoff; if the owner is genuinely
        // stalled past the bound, the event is *left claimed* for this run
        // and reported as buffered — the sweep's redelivery pass finds a
        // waiting subscription with a claimed event and finishes the job on a
        // later tick, so the bound bounds latency, never delivery.
        let mut backoff = Duration::from_millis(25);
        let lease = loop {
            match self
                .store
                .acquire(sub.run, &self.owner, self.lease_ttl)
                .await
            {
                Ok(lease) => break lease,
                Err(crate::core::StoreError::LeaseHeld { .. })
                    if backoff < Duration::from_secs(1) =>
                {
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                Err(crate::core::StoreError::LeaseHeld { .. }) => {
                    // The claim retired the subscription, so nothing lists
                    // this run as waiting any more — and the claimed event
                    // blocks every dedup'd retry of itself. Re-registering
                    // the subscription is what keeps the pair findable: the
                    // sweep's redelivery pass walks waiting subscriptions,
                    // re-claims (a claim by the same run is returned, not
                    // filtered), and finishes the delivery once the owner
                    // concludes.
                    events
                        .subscribe(&sub, now_for_admission())
                        .await
                        .map_err(RuntimeError::from_store)?;
                    tracing::warn!(
                        run = %sub.run,
                        event = %event.id,
                        "an event was claimed for a run whose owner did not conclude \
                         within the retry window; the sweep will deliver it"
                    );
                    return Ok(Delivery::Buffered);
                }
                Err(e) => return Err(RuntimeError::from_store(e)),
            }
        };

        let already_recorded = self
            .store
            .read(sub.run, 1)
            .await
            .map_err(RuntimeError::from_store)?
            .iter()
            .any(|record| {
                record.effect_key() == Some(sub.effect)
                    && matches!(record.kind(), RecordKind::EffectDone { .. })
            });
        if !already_recorded {
            self.store
                .append(
                    lease.epoch,
                    vec![{
                        let mut a = Append::new(
                            sub.run,
                            RecordKind::EffectDone {
                                output: event.payload.clone(),
                                // The sender, so a replayed run rebuilds the same
                                // provenance this delivery gave the value.
                                source: Some(event.source.clone()),
                                spend: crate::core::Spend::default(),
                            },
                        )
                        .effect(sub.effect)
                        .step(sub.step)
                        .phase(sub.phase);
                        // Every record of a case-bound run carries its case, and a
                        // record written from outside the run is no exception.
                        if let Some(c) = sub.case {
                            a = a.case(c);
                        }
                        a
                    }],
                )
                .await
                .map_err(RuntimeError::from_store)?;
        }

        events
            .unsubscribe(sub.run, sub.effect)
            .await
            .map_err(RuntimeError::from_store)?;

        // The bookkeeping lease has done its work — the event is recorded as
        // the awaited effect's result. `replay` claims its own lease before it
        // reads (which fences this epoch, under which nothing is left to
        // write), so this one is handed back first rather than deadlocking
        // the resume against its own delivery.
        if let Err(e) = self.store.release_lease(sub.run, lease.epoch).await {
            tracing::debug!(run = %sub.run, error = %e, "could not hand back the delivery lease");
        }
        match self.replay(sub.run, Mode::Resume).await {
            // A `LeaseHeld` means somebody claimed the run in the gap — a
            // concurrent delivery, a recovery sweep. The event is durably
            // recorded, so whoever holds the lease replays it; this delivery
            // still delivered.
            Ok(_) | Err(RuntimeError::LeaseHeld { .. }) => {}
            Err(e) => return Err(e),
        }
        Ok(Delivery::Resumed { run: sub.run })
    }

    /// Finish deliveries that died between the claim and the resume.
    ///
    /// A delivery that raced a live owner leaves an event durably claimed for
    /// a run nothing resumed, and the counterparty's retries deduplicate
    /// against that claim — so no future delivery drives the run, and a
    /// message that arrived in time is parked forever. The giving-up delivery
    /// re-registers the subscription precisely so the pair stays findable;
    /// this pass walks the waiting subscriptions, re-claims (idempotently —
    /// a claim by the same run is returned, not filtered), and finishes the
    /// delivery. Runs whose owner is *still* live are skipped and found again
    /// next tick, so the delivery's retry bound bounds latency, never
    /// delivery.
    ///
    /// What this does **not** cover, honestly: a crash inside the store
    /// commit between an event's claim and the resume retires the
    /// subscription with nothing left to re-register it, and that window
    /// stays what it always was — recorded rather than closed, with later
    /// events for the same correlation dead-lettering as its symptom.
    pub(crate) async fn redeliver_claimed(&self, limit: usize) -> Result<usize, RuntimeError> {
        let Some(events) = self.events.as_ref() else {
            return Ok(0);
        };
        let waiting = events
            .waiting(limit)
            .await
            .map_err(RuntimeError::from_store)?;
        let mut delivered = 0usize;
        for sub in waiting {
            let Some(buffered) = events
                .claim_for(&sub, now_for_admission())
                .await
                .map_err(RuntimeError::from_store)?
            else {
                continue;
            };
            match self
                .resume_subscription(events, sub.clone(), &buffered.event)
                .await
            {
                Ok(Delivery::Resumed { .. }) => delivered += 1,
                // Still held live: the owner is working, and will either
                // consume the claim itself or conclude and be found next tick.
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(
                        run = %sub.run,
                        %error,
                        "a claimed event's redelivery failed; retried next tick",
                    );
                }
            }
        }
        Ok(delivered)
    }

    /// Retire events that nobody claimed within `grace`.
    ///
    /// A non-empty dead-letter list means a correlation key is wrong somewhere:
    /// the message arrived, was held, and no run ever asked for it. That is the
    /// failure which otherwise presents as a process silently never completing,
    /// so it is worth alerting on rather than logging.
    /// `grace` is a `std::time::Duration` for the reason
    /// [`StepCtx::deadline`](crate::runtime::StepCtx::deadline)'s `warn_before`
    /// is: a negative grace window is meaningless, and the signed type could
    /// express it — a cutoff moved *forward* of now, retiring events that had
    /// not yet had their chance. It is also the `Duration` the caller has.
    pub async fn sweep_events(&self, grace: std::time::Duration) -> Result<usize, RuntimeError> {
        let events = self
            .events
            .as_ref()
            .ok_or_else(|| RuntimeError::PlanContract("this runtime has no event store".into()))?;
        // Saturating rather than fallible: a grace window beyond what the
        // calendar type can hold means "retire nothing", which is what
        // `Duration::MAX` gives, and refusing the call would be a worse answer
        // to a caller asking for a longer hold.
        let grace = time::Duration::try_from(grace).unwrap_or(time::Duration::MAX);
        let cutoff = now_for_admission() - grace;
        let retired = events
            .sweep_unclaimed(cutoff, "no run claimed this event within the grace window")
            .await
            .map_err(RuntimeError::from_store)?;

        if retired > 0 {
            // A non-empty dead-letter list means a correlation key is wrong
            // somewhere: the message arrived, was held, and no run ever asked
            // for it. That is the failure which otherwise presents as a process
            // silently never completing.
            tracing::error!(target: telemetry::DEAD_LETTERED, count = retired, %cutoff);
            self.meter
                .count_by(metrics::DEAD_LETTERS, "", retired as u64);
        }
        Ok(retired)
    }
}

/// Every `RunStatus`, so adding one forces a decision everywhere one is owed.
///
/// Written out rather than derived, because Rust cannot enumerate a
/// data-carrying enum — and a list is honest about that: the count assertion in
/// each consumer fails the day a variant is added, which is exactly when
/// somebody must decide whether it seals, whether it may resume, and which A2A
/// state it surfaces as.
///
/// Crate-visible so those consumers share **one** list. Two copies would be two
/// places to remember, and the second would be the one that went stale — which
/// is the same failure the tests using it exist to catch.
#[cfg(test)]
pub(crate) fn every_status() -> Vec<RunStatus> {
    use crate::core::{BudgetExceeded, CorrelationKey, SuspendReason, Timestamp};
    vec![
        RunStatus::Succeeded,
        RunStatus::Failed("because".into()),
        RunStatus::Suspended(SuspendReason::AwaitingEvent {
            kind: "reply".into(),
            correlation: vec![CorrelationKey::new("claim", "CLM-1")],
            until: Timestamp::from_unix_timestamp(1_760_000_000).expect("time"),
        }),
        RunStatus::Exhausted(BudgetExceeded::Steps { allowed: 1 }),
        RunStatus::Quarantined("unknown outcome".into()),
        RunStatus::Replanning("try again".into()),
        RunStatus::Cancelled {
            actor: "ops".into(),
            reason: "stop".into(),
        },
    ]
}

#[cfg(test)]
mod resume_agreement_tests {
    use super::{RunStatus, resume_is_closed};
    use crate::journal::RecordKind;

    // Through the crate re-export rather than `super::`, so the one path both
    // consumers use is exercised in every build. Reaching it directly here
    // would leave the re-export unused whenever `a2a-server` is off — which is
    // a lint failure in exactly the feature configuration nobody runs locally.
    use crate::runtime::every_status;

    /// **A conclusion that sealed the journal may never be resumed.**
    ///
    /// `RunStatus::seals` decides whether a conclusion freezes the run and
    /// publishes a Merkle leaf; `resume_is_closed` decides whether a recorded
    /// conclusion may be continued. A status that did the first and permits the
    /// second would grow the history past the leaf every later checkpoint
    /// attests — the failure the "a conclusion is not a closure" work removed
    /// for `failed`, reachable again the moment the two disagree.
    ///
    /// The executor's own comment claimed "a test pins the agreement" while no
    /// such test existed, which is the unfalsifiable-guarantee shape this
    /// project treats as a defect in itself: the rule was real, checked by
    /// nobody, and deletable in silence.
    #[test]
    fn a_sealing_conclusion_is_never_resumable() {
        let statuses = every_status();
        assert_eq!(
            statuses.len(),
            7,
            "a RunStatus variant was added or removed — decide whether it seals \
             and whether a resume may continue from it, then update this list"
        );

        for status in &statuses {
            let records = sealed_as(status.as_str());
            let verdict = resume_is_closed(&records);
            if status.seals() {
                assert!(
                    verdict.is_some(),
                    "'{}' seals the journal and enters the Merkle log, yet a resume \
                     is permitted from it — the resume would grow the history past \
                     the leaf every later checkpoint attests",
                    status.as_str()
                );
            }
        }
    }

    /// The availability half: the two conclusions that stay open really do.
    ///
    /// Asserted separately and by name rather than as the converse of the rule
    /// above, because the converse is false — `Suspended` and `Replanning` do
    /// not seal either, and neither is ever a recorded conclusion.
    #[test]
    fn a_failed_or_exhausted_run_may_still_be_resumed() {
        for outcome in ["failed", "exhausted"] {
            assert!(
                resume_is_closed(&sealed_as(outcome)).is_none(),
                "'{outcome}' is a conclusion a resume must be able to continue \
                 from — its completed effects are read back from history, which \
                 is the point of having a journal"
            );
        }
    }

    /// `SEALED_OUTCOMES` and `RunStatus::seals` are one rule in two spellings,
    /// and this holds them together variant by variant.
    ///
    /// The list exists so a caller wanting every sealed run — the export CLI —
    /// does not restate the rule as string literals in a binary, which is where
    /// a new sealing outcome would have been silently dropped from exactly the
    /// artifact an auditor asks for. Both directions matter: a sealing status
    /// missing from the list loses runs, and a non-sealing status present in it
    /// makes the export ask the outcome index about a backlog that drains.
    #[test]
    fn the_sealed_outcome_list_agrees_with_the_sealing_rule() {
        for status in super::every_status() {
            assert_eq!(
                super::SEALED_OUTCOMES.contains(&status.as_str()),
                status.seals(),
                "'{}' disagrees between RunStatus::seals and SEALED_OUTCOMES — \
                 one rule, two spellings, and the export reads the list",
                status.as_str()
            );
        }
        for special in ["swept", "broke-glass"] {
            assert!(
                super::SEALED_OUTCOMES.contains(&special),
                "'{special}' is sealed at birth by the sweeper or a break-glass \
                 crossing and must be exportable"
            );
        }
    }

    /// An outcome this build cannot interpret is never permission to resume.
    #[test]
    fn an_unrecognised_conclusion_fails_closed() {
        let verdict = resume_is_closed(&sealed_as("swept"));
        assert!(
            matches!(verdict, Some(RunStatus::Quarantined(_))),
            "an unrecognised conclusion must quarantine rather than resume: {verdict:?}"
        );
    }

    /// A chain whose only record is a seal with this outcome.
    fn sealed_as(outcome: &str) -> Vec<crate::journal::Record> {
        use crate::core::{Digest, Epoch};
        use crate::journal::{Record, RecordBody};

        let body = RecordBody {
            seq: 1,
            run: crate::core::RunId::generate(),
            case: None,
            step: None,
            phase: super::Phase::Forward,
            epoch: Epoch::default(),
            v: 1,
            effect_key: None,
            kind: RecordKind::RunSealed {
                outcome: outcome.to_owned(),
                chain_head: Digest::of(b""),
            },
        };
        vec![Record::seal(body, Digest::of(b"")).expect("a sealed record")]
    }
}
