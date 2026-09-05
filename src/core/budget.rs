//! Budgets — bounded cost, enforced deterministically.
//!
//! # Why spend is journaled
//!
//! A budget decision is control flow: "may this effect run?" changes what the
//! run does. So it has to live in the deterministic zone, and everything it
//! reads has to be reproducible.
//!
//! That rules out asking a provider what something cost at replay time — the
//! answer moves. Instead each effect reports its consumption when it completes,
//! the number goes into the `EffectDone` record, and replay adds up the same
//! figures the original run did. A replayed run therefore reaches the same
//! budget verdict at the same point, which is the only way an exhausted budget
//! can be part of a faithful history rather than an artefact of when you looked.
//!
//! # A metered budget stops *after* the limit, not before it
//!
//! A token or cost limit cannot be a hard ceiling, because an operation's cost
//! is not known until it has run. What is enforced is: *once consumption has
//! reached the limit, no further operation starts.* A run therefore overshoots
//! a metered ceiling by at most one operation's cost **per step it has in
//! flight** — a plan's ready set is dispatched concurrently, and every step in
//! it may be holding a call the ledger has admitted and not yet billed.
//! `max_parallel_steps` is what bounds that number; without it the bound is the
//! plan's own width.
//!
//! That is stated rather than hidden because the alternative — pretending to a
//! hard cap — is how somebody sizes a limit at exactly their ceiling and is
//! surprised. Where a true ceiling matters, set `max_effects` too: a count is
//! known in advance, so admission takes the slot as it checks it and that limit
//! is exact however wide the plan runs.
//!
//! # One announcement, one slot, on every pass
//!
//! The ledger is the same on both sides of a replay, and that is arithmetic
//! rather than intent. An attempt takes its slot when it is admitted and adds
//! its cost when the call returns; the pass that reads that attempt back out of
//! the journal takes one slot and adds everything the attempt's records report
//! — including a figure a later record superseded, which the live pass had
//! already added.
//!
//! An arm that bills twice, or one that drops a superseded figure, moves where
//! a resumed run stops without changing anything a status assertion can see:
//! the run concludes `Exhausted` against a ceiling its own history never
//! reached, at a point no record contains. So the arms are held to one rule,
//! and the rule is asserted as a tally rather than as an outcome.
//!
//! # Why wall-clock limits are opt-in
//!
//! Elapsed time cannot be checked without reading a clock, and a clock read is
//! an effect. A wall-clock budget therefore costs one journaled effect per step
//! boundary. That is cheap but not free, so it is only paid when asked for.
//!
//! The reading has to be journaled rather than ambient, and that is the whole
//! reason it costs anything: a verdict taken from the wall would be a different
//! verdict every time the run was looked at, and an exhausted run would replay
//! as healthy. What follows from the opt-in is worth stating plainly — the
//! step's first effect is this reading when a wall-clock ceiling is declared
//! and the skill's own when it is not, so that history replays under a *raised*
//! ceiling and not under a build that removed it.
//!
//! Elapsed time is the distance between the extremes of what the run has read,
//! never between the first and last *arrival*: a ready set is dispatched
//! concurrently, so arrival order belongs to the scheduler, and a ceiling that
//! depended on it would fire on some passes over one history and not on others.
//!
//! The limit that follows from reading at *boundaries* is stated rather than
//! implied: the ceiling stops the next step, so a single step that overruns it
//! is not interrupted. Nothing here cancels work in flight — that would abort
//! an effect mid-call and manufacture the unknown outcome the protocol exists
//! to refuse. What bounds one call is the driver's own timeout; this bounds how
//! long a *run* goes on making new ones.

use serde::{Deserialize, Serialize};

use crate::core::Timestamp;

/// What one effect consumed.
///
/// Deliberately unit-agnostic: the engine never learns what a token is or which
/// currency `minor_units` is in. It adds them up and compares them to a limit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spend {
    /// Model tokens, or any other metered unit the deployment counts.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub tokens: u64,
    /// Money in minor units — cents, pence, whatever the deployment uses.
    ///
    /// Integer rather than float: money that rounds differently on two machines
    /// is money that produces two different budget verdicts.
    ///
    /// **Unsigned, and that is a security property rather than tidiness.** Every
    /// ceiling in this crate — a [`Budget`], a [`TenantQuota`], a
    /// [`StandingAuthority`] — is enforced by comparing an accumulated `Spend`
    /// against a limit. A *negative* amount reverses the accumulation, so a
    /// single one un-spends everything before it and the ceiling stops being
    /// one. That was reachable while this was an `i64`: a €500 standing
    /// authority could be drawn to zero, drawn again for −€400, and then drawn
    /// for a further €400 — €900 against a €500 mandate, with every check
    /// passing. Refusing negatives in each of the three enforcement paths would
    /// have been three places to remember; making the state unrepresentable is
    /// none.
    ///
    /// A refund or a credit is therefore not a `Spend`. It is a new
    /// authorization, which is what leaves both decisions on the record.
    ///
    /// [`TenantQuota`]: crate::quota::TenantQuota
    /// [`StandingAuthority`]: crate::authority::StandingAuthority
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub minor_units: u64,
}

// By-reference because `skip_serializing_if` requires it.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

impl Spend {
    /// Nothing consumed.
    pub const ZERO: Self = Self {
        tokens: 0,
        minor_units: 0,
    };

    #[must_use]
    pub const fn tokens(n: u64) -> Self {
        Self {
            tokens: n,
            minor_units: 0,
        }
    }

    #[must_use]
    pub const fn money(minor_units: u64) -> Self {
        Self {
            tokens: 0,
            minor_units,
        }
    }

    /// By-reference form, for `skip_serializing_if`.
    ///
    /// One predicate under one name. Two spellings of "did this cost
    /// anything" is two places for the answer to drift, and the by-reference
    /// form exists only because `skip_serializing_if` hands out a reference.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[must_use]
    pub const fn is_free_ref(v: &Self) -> bool {
        v.is_free()
    }

    /// Whether this cost nothing at all.
    #[must_use]
    pub const fn is_free(self) -> bool {
        self.tokens == 0 && self.minor_units == 0
    }

    /// Saturating so a runaway meter cannot wrap into a smaller number and
    /// silently re-open a budget that was already blown.
    #[must_use]
    pub fn plus(self, other: Self) -> Self {
        Self {
            tokens: self.tokens.saturating_add(other.tokens),
            minor_units: self.minor_units.saturating_add(other.minor_units),
        }
    }
}

impl std::ops::AddAssign for Spend {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.plus(rhs);
    }
}

/// What a run is allowed to consume.
///
/// Every limit is optional; `Budget::unlimited()` is a legitimate choice for a
/// run that only touches free, local effects. It is not the default, because
/// "nobody set a limit" and "somebody decided no limit was needed" should not
/// look the same in a config file.
///
/// # A ceiling gates every effect, not only the metered ones
///
/// Worth stating once, because the field names invite the opposite reading:
/// [`admit_effect`](Ledger::admit_effect) evaluates *all* of these limits before
/// *every* effect, whatever kind it is. A run holding a token ceiling passes it
/// on the way to a read-only tool call, and a run that has reached any one
/// ceiling performs no further operation of any kind. So `max_tokens` is not
/// "what the model may spend" — it is a gate the whole run walks through.
///
/// The corollary is that zero is not a useful value for any ceiling here except
/// [`max_replans`](Self::max_replans) and [`max_denials`](Self::max_denials): at
/// zero the limit is reached before the run starts, and the agent can never do
/// anything at all. Refused on both paths that can carry one — the manifest at
/// parse, and [`RuntimeBuilder::budget`] at build — from the single rule in
/// [`bricked_ceiling`](Self::bricked_ceiling).
///
/// [`RuntimeBuilder::budget`]: crate::runtime::RuntimeBuilder::budget
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Plan nodes this run may execute, checked before each one starts.
    ///
    /// Zero permits no step at all, so a run carrying it cannot begin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_steps: Option<usize>,
    /// Externally visible operations, of every kind.
    ///
    /// The blunt instrument that stops a loop nobody predicted, independent of
    /// what each operation happens to cost — a free local read costs one here
    /// exactly as a model completion does. Zero permits no effect at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_effects: Option<usize>,
    /// Metered units the run may consume in total.
    ///
    /// Compared before **every** effect, including the effects that consume no
    /// tokens, so this bounds when the run stops rather than only what the model
    /// costs. Zero refuses the first effect of any kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    /// Money in minor units the run may spend in total.
    ///
    /// Gates **every** effect, exactly like [`max_tokens`](Self::max_tokens):
    /// a free effect still has to pass it. Zero refuses the first one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_minor_units: Option<u64>,
    /// How many times a run may change its plan.
    ///
    /// A run that replans without bound is a run that has stopped making
    /// progress and started thrashing, and the ceiling is what turns that from
    /// an unbounded spend into a reported fault.
    ///
    /// Zero is meaningful here, unlike the ceilings above: it says the plan the
    /// run started with is the plan it finishes with, and a run that never
    /// replans is unaffected by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_replans: Option<u32>,
    /// Wall-clock ceiling.
    ///
    /// Costs one journaled clock read per step boundary when set — see the
    /// module docs. Checked against elapsed time, which starts at zero, so a
    /// zero ceiling refuses the first step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wallclock_secs: Option<u64>,
    /// How many of a plan's ready steps may run at once.
    ///
    /// A ready set is every node whose predecessors are done, so nothing in it
    /// depends on anything else in it and running them concurrently is the
    /// point of writing a graph rather than a list. What that width costs is
    /// paid outside this process — connections, provider rate limits, and the
    /// metered ceilings above, which are checked before an operation and
    /// billed after it, so each step in flight may be holding one operation's
    /// worth of unbilled spend.
    ///
    /// Absent means the plan's own width is the bound, which is the right
    /// default for a graph the embedder wrote and the wrong one for a graph
    /// anything else may widen. Zero permits no step at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_parallel_steps: Option<usize>,
    /// How many times the policy may refuse this run before it is stopped.
    ///
    /// **A run that keeps hitting the policy is probing it.** Refusals carry a
    /// uniform message precisely so a model cannot tell one from another
    /// ([`REFUSED`](crate::core::REFUSED)), but the refused/allowed bit itself
    /// still leaks one bit per attempt, and nothing short of fabricating success
    /// removes that. What bounds the channel is bounding the attempts.
    ///
    /// It is an operational ceiling as much as a security one: a run stuck in a
    /// denial loop has stopped making progress, exactly like one that replans
    /// without bound.
    ///
    /// Zero is meaningful here too, and for a different reason than
    /// [`max_replans`](Self::max_replans): this one is counted *after* the
    /// refusal and compared with `>`, so zero says the first refusal ends the
    /// run. A run nothing refuses never notices it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_denials: Option<u32>,
}

impl Budget {
    /// The first ceiling set to zero, if any — the field name, for a message.
    ///
    /// Zero is not a small limit here; it is a limit already reached. Every
    /// ceiling this reports is compared **before** the work and against every
    /// effect of every kind, so at zero the run is refused its first operation:
    /// a read-only tool call, a local lookup, an agent that declares no models
    /// at all. Such a plane does not run once and stop — it fails identically
    /// on every run it will ever make, which makes it a wiring mistake rather
    /// than a budget.
    ///
    /// [`max_replans`](Self::max_replans) and [`max_denials`](Self::max_denials)
    /// are excluded, because zero is meaningful for both: it says *do not
    /// replan* and *the first refusal ends the run*, and a run that never
    /// replans or is never refused is unaffected by either.
    #[must_use]
    pub const fn bricked_ceiling(&self) -> Option<&'static str> {
        // `matches!` rather than `== Some(0)` so this stays `const`.
        if matches!(self.max_steps, Some(0)) {
            return Some("max_steps");
        }
        if matches!(self.max_effects, Some(0)) {
            return Some("max_effects");
        }
        if matches!(self.max_tokens, Some(0)) {
            return Some("max_tokens");
        }
        if matches!(self.max_minor_units, Some(0)) {
            return Some("max_minor_units");
        }
        if matches!(self.max_wallclock_secs, Some(0)) {
            return Some("max_wallclock_secs");
        }
        if matches!(self.max_parallel_steps, Some(0)) {
            return Some("max_parallel_steps");
        }
        None
    }

    /// No limits. An explicit choice, not an absence of one.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_steps: None,
            max_effects: None,
            max_tokens: None,
            max_minor_units: None,
            max_replans: None,
            max_wallclock_secs: None,
            max_denials: None,
            max_parallel_steps: None,
        }
    }

    #[must_use]
    pub const fn steps(mut self, n: usize) -> Self {
        self.max_steps = Some(n);
        self
    }

    #[must_use]
    pub const fn effects(mut self, n: usize) -> Self {
        self.max_effects = Some(n);
        self
    }

    #[must_use]
    pub const fn tokens(mut self, n: u64) -> Self {
        self.max_tokens = Some(n);
        self
    }

    #[must_use]
    pub const fn minor_units(mut self, n: u64) -> Self {
        self.max_minor_units = Some(n);
        self
    }

    #[must_use]
    pub const fn replans(mut self, n: u32) -> Self {
        self.max_replans = Some(n);
        self
    }

    /// How many policy refusals this run may accrue.
    #[must_use]
    pub const fn denials(mut self, n: u32) -> Self {
        self.max_denials = Some(n);
        self
    }

    #[must_use]
    pub const fn wallclock_secs(mut self, n: u64) -> Self {
        self.max_wallclock_secs = Some(n);
        self
    }

    /// Bound the width of a ready set. See
    /// [`max_parallel_steps`](Self::max_parallel_steps).
    #[must_use]
    pub const fn parallel_steps(mut self, n: usize) -> Self {
        self.max_parallel_steps = Some(n);
        self
    }

    /// How many ready steps may be dispatched at once — the plan's own width
    /// when nothing narrows it.
    #[must_use]
    pub const fn parallelism(&self) -> usize {
        match self.max_parallel_steps {
            Some(n) => n,
            None => usize::MAX,
        }
    }

    #[must_use]
    pub const fn tracks_wallclock(&self) -> bool {
        self.max_wallclock_secs.is_some()
    }
}

/// Running totals for one run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Consumed {
    pub steps: usize,
    /// Effects **dispatched**, not effects that succeeded.
    ///
    /// A call that fails still consumed a call — it occupied a connection, hit
    /// a rate limit, and may have cost money on the way to failing. Counting
    /// only successes leaves the one loop a ceiling most needs to stop, a
    /// failing call retried forever, costing nothing on paper.
    pub effects: usize,
    pub spend: Spend,
    pub elapsed_secs: u64,
    /// Policy refusals this run has accrued.
    #[serde(default)]
    pub denials: u32,
}

/// Which limit stopped the run, and where it stood.
///
/// Carries the numbers rather than a message: an operator raising a limit needs
/// to know what it actually reached, and "budget exhausted" does not say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[non_exhaustive]
#[serde(tag = "limit", rename_all = "snake_case")]
pub enum BudgetExceeded {
    #[error("step budget exhausted: {allowed} step(s) permitted")]
    Steps { allowed: usize },

    #[error("effect budget exhausted: {allowed} operation(s) permitted, {used} performed")]
    Effects { allowed: usize, used: usize },

    #[error("replan budget exhausted: {allowed} replan(s) permitted")]
    Replans { allowed: u32 },

    /// The run was refused by the policy more often than it is allowed to be.
    ///
    /// Not a policy failure — a *probing* ceiling. See
    /// [`Budget::max_denials`].
    #[error("denial budget exhausted: {allowed} refusal(s) permitted")]
    Denials { allowed: u32 },

    /// A refusal read back from the journal.
    ///
    /// Carries the recorded limit rather than the one in force now, because a
    /// run replayed under a larger budget still stopped where it stopped.
    #[error("{limit} (recorded: {used})")]
    Recorded {
        #[serde(rename = "recorded_limit")]
        limit: String,
        used: String,
    },

    #[error("token budget exhausted: {allowed} permitted, {used} consumed")]
    Tokens { allowed: u64, used: u64 },

    #[error("cost budget exhausted: {allowed} minor units permitted, {used} spent")]
    Money { allowed: u64, used: u64 },

    #[error("time budget exhausted: {allowed}s permitted, {used}s elapsed")]
    Wallclock { allowed: u64, used: u64 },
}

impl BudgetExceeded {
    /// Which limit was hit, for a metric label.
    ///
    /// The variant only — never the rendered message. `Display` here embeds the
    /// allowed and used figures, and a label carrying those is a new time series
    /// per distinct budget, which is how a metrics backend falls over. See
    /// `runtime::metrics`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Steps { .. } => "steps",
            Self::Effects { .. } => "effects",
            Self::Replans { .. } => "replans",
            Self::Denials { .. } => "denials",
            Self::Recorded { .. } => "recorded",
            Self::Tokens { .. } => "tokens",
            Self::Money { .. } => "money",
            Self::Wallclock { .. } => "wallclock",
        }
    }
}

/// Tracks a run's consumption against its budget.
///
/// Lives entirely in the deterministic zone: it reads only numbers that came
/// out of the journal, so a replayed run reaches the same verdict at the same
/// point as the original.
///
/// Every ceiling it holds gates *every* effect: [`admit_effect`](Self::admit_effect)
/// evaluates the effect count, the token total, the money total and the clock
/// before each operation, whatever kind that operation is. A token ceiling is
/// therefore not a model-spend ceiling — a run that has reached it stops making
/// free local calls too, which is exactly what makes a zero one uninhabitable.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    budget: Budget,
    consumed: Consumed,
    /// The extremes of every instant this run has read, when it reads any.
    ///
    /// `None` on a run with no wall-clock ceiling: the readings that would fill
    /// these cost a journaled effect apiece, and a ceiling nobody declared is
    /// not worth one per step.
    first: Option<Timestamp>,
    last: Option<Timestamp>,
    /// What *this pass* dispatched, as opposed to what it read back.
    ///
    /// The budget verdict runs on `consumed`, which bills replayed history
    /// exactly as it was billed live so a resumed run reaches the same
    /// exhaustion at the same point. The tenant's quota ledger must not: a run
    /// that suspends and resumes N times would accrue its prefix N times, and
    /// a strict verification would bill a historical run's whole spend into
    /// the current period on every look. This figure carries only the effects
    /// the current pass actually performed, and it is what settlement accrues.
    live: Spend,
}

impl Ledger {
    #[must_use]
    pub const fn new(budget: Budget) -> Self {
        Self {
            budget,
            consumed: Consumed {
                steps: 0,
                effects: 0,
                spend: Spend {
                    tokens: 0,
                    minor_units: 0,
                },
                elapsed_secs: 0,
                denials: 0,
            },
            live: Spend {
                tokens: 0,
                minor_units: 0,
            },
            first: None,
            last: None,
        }
    }

    #[must_use]
    pub const fn budget(&self) -> Budget {
        self.budget
    }

    /// What the current pass dispatched, excluding everything read from
    /// history. This is the figure a tenant's period ledger accrues; the run's
    /// own budget verdict uses [`consumed`](Self::consumed), which includes
    /// the replayed prefix.
    #[must_use]
    pub const fn live_spend(&self) -> Spend {
        self.live
    }

    #[must_use]
    pub const fn consumed(&self) -> Consumed {
        self.consumed
    }

    /// Whether elapsed time needs measuring at all.
    #[must_use]
    pub const fn tracks_wallclock(&self) -> bool {
        self.budget.tracks_wallclock()
    }

    /// Fold in a journaled clock reading.
    ///
    /// Elapsed time is the distance between the earliest and the latest instant
    /// this run has read, and both are taken as extremes rather than as *first*
    /// and *last seen* — a ready set is dispatched concurrently, so "the one
    /// that arrived first" is a property of the scheduler, and a ceiling whose
    /// verdict depends on that is a ceiling that fires on some runs of the same
    /// history and not on others. Extremes are order-independent, so every pass
    /// over the same readings computes the same elapsed figure.
    ///
    /// Saturating rather than signed: a clock that steps backwards between two
    /// reads must not un-spend the time already elapsed.
    pub fn observe_clock(&mut self, at: Timestamp) {
        self.first = Some(match self.first {
            Some(f) if f <= at => f,
            _ => at,
        });
        self.last = Some(match self.last {
            Some(l) if l >= at => l,
            _ => at,
        });
        if let (Some(f), Some(l)) = (self.first, self.last) {
            self.consumed.elapsed_secs =
                u64::try_from((l.unix_timestamp() - f.unix_timestamp()).max(0)).unwrap_or(u64::MAX);
        }
    }

    /// Check whether another step may start, given `pending` already admitted
    /// and not yet finished.
    ///
    /// Checked *before* dispatch: a step that would exceed the budget must not
    /// half-run and then be stopped.
    ///
    /// `pending` is what makes this hold for a plan with any width. A step is
    /// counted when it finishes, so a whole ready set admitted against the
    /// same figure is a whole ready set that passes — three branches admitted
    /// under a ceiling of two, each check truthfully reporting nothing spent
    /// yet. The caller admits a ready set one at a time and says how many of
    /// them it has already taken, so the ceiling bounds the plan rather than
    /// the sequential prefix of it.
    pub fn admit_step(&self, pending: usize) -> Result<(), BudgetExceeded> {
        if let Some(max) = self.budget.max_steps
            && self.consumed.steps + pending >= max
        {
            return Err(BudgetExceeded::Steps { allowed: max });
        }
        self.check_denials()?;
        self.check_time()
    }

    pub const fn record_step(&mut self) {
        self.consumed.steps += 1;
    }

    /// Check whether another effect may be performed, **and take its slot**.
    ///
    /// Before dispatch — after is too late, since the point of a budget is to
    /// stop the money leaving. Note the semantics for metered limits: an
    /// operation's cost is unknown until it runs, so this refuses once
    /// consumption has *reached* the limit. A run overshoots those by at most
    /// one operation per step dispatched in parallel, which is what
    /// [`Budget::max_parallel_steps`] bounds.
    ///
    /// `max_effects` is exact, and taking the slot here is what makes it so.
    /// Checking without counting leaves a window between the verdict and the
    /// announcement, and steps in one ready set run concurrently: at the last
    /// remaining slot every one of them is told yes. Counting under the same
    /// lock that checked means the second caller sees the first one's slot.
    ///
    /// # Errors
    ///
    /// The first ceiling this effect would cross. Nothing is counted when the
    /// answer is a refusal.
    pub fn admit_effect(&mut self) -> Result<(), BudgetExceeded> {
        self.can_admit_effect()?;
        self.consumed.effects += 1;
        Ok(())
    }

    /// Whether another effect would be admitted, without taking its slot.
    ///
    /// For the one caller that asks the question early and dispatches through
    /// [`admit_effect`](Self::admit_effect) afterwards: a resume re-asking
    /// whether a journaled refusal still stands.
    ///
    /// # Errors
    ///
    /// The first ceiling the next effect would cross.
    pub fn can_admit_effect(&self) -> Result<(), BudgetExceeded> {
        // Checked here as well as at the denial itself, and that is the half
        // that actually binds: a probing loop swallows the error it gets back,
        // so refusing the *next* attempt is what stops the probing rather than
        // merely reporting it.
        self.check_denials()?;
        if let Some(max) = self.budget.max_effects
            && self.consumed.effects >= max
        {
            return Err(BudgetExceeded::Effects {
                allowed: max,
                used: self.consumed.effects,
            });
        }
        if let Some(max) = self.budget.max_tokens
            && self.consumed.spend.tokens >= max
        {
            return Err(BudgetExceeded::Tokens {
                allowed: max,
                used: self.consumed.spend.tokens,
            });
        }
        if let Some(max) = self.budget.max_minor_units
            && self.consumed.spend.minor_units >= max
        {
            return Err(BudgetExceeded::Money {
                allowed: max,
                used: self.consumed.spend.minor_units,
            });
        }
        self.check_time()
    }

    /// Take an effect's slot without checking a ceiling.
    ///
    /// For the announcements no ceiling gates: a compensating call, which is
    /// exempt because refusing to undo is how a run ends with a charged card
    /// and no order, and a durable wait, which is registered rather than
    /// dispatched. Both still happened, so both still count — the alternative
    /// is a ceiling a run walks through by phrasing its work as an undo.
    pub const fn count_effect(&mut self) {
        self.consumed.effects += 1;
    }

    /// Add what an announced attempt cost, without taking a slot.
    ///
    /// The slot was taken when the attempt was admitted, so this is the second
    /// half of one billing: the cost is not known until the call returns, and
    /// the count was.
    pub fn record_spend(&mut self, spend: Spend) {
        self.consumed.spend += spend;
    }

    /// [`record_spend`](Self::record_spend) for an attempt this pass actually
    /// dispatched.
    ///
    /// The distinction feeds the tenant's period ledger: replayed spend is
    /// billed to the run's own budget so a resume exhausts where the original
    /// did, but only live spend accrues at settlement — otherwise every
    /// suspend/resume cycle re-accrues the prefix and every strict pass bills
    /// history into today's period.
    pub fn record_live_spend(&mut self, spend: Spend) {
        self.record_spend(spend);
        self.live += spend;
    }

    /// Bill an announced attempt read back from the journal: one slot, and
    /// everything its records say it cost.
    ///
    /// The mirror of [`admit_effect`](Self::admit_effect) plus
    /// [`record_spend`](Self::record_spend), which is the pair the live path
    /// performs — a replayed run must reach the same verdict at the same
    /// point, and it can only do that if one announcement costs one slot on
    /// both paths.
    pub fn replay_effect(&mut self, spend: Spend) {
        self.consumed.effects += 1;
        self.consumed.spend += spend;
    }

    /// Count a policy refusal, and report if that was one too many.
    ///
    /// Counted *after* the refusal rather than checked before it: the run is not
    /// asking permission to be denied, and a refusal that has already been
    /// journaled has already happened. What the ceiling stops is the *next*
    /// attempt — which is the one that would learn something.
    ///
    /// # Errors
    ///
    /// [`BudgetExceeded::Denials`] once the run has been refused more often than
    /// its budget allows.
    pub fn record_denial(&mut self) -> Result<(), BudgetExceeded> {
        self.consumed.denials += 1;
        if let Some(max) = self.budget.max_denials
            && self.consumed.denials > max
        {
            return Err(BudgetExceeded::Denials { allowed: max });
        }
        Ok(())
    }

    /// Whether this run may be put in front of the policy again.
    ///
    /// Checked *before* the policy is consulted, which is the only placement
    /// that works: a refusal is journaled as it happens, so a ceiling applied
    /// afterwards bounds nothing an observer can see. Refusing here means the
    /// attempt produces no new record and no new bit.
    ///
    /// # Errors
    ///
    /// [`BudgetExceeded::Denials`] once the run has spent its refusals.
    pub fn admit_policy_check(&self) -> Result<(), BudgetExceeded> {
        self.check_denials()
    }

    fn check_denials(&self) -> Result<(), BudgetExceeded> {
        if let Some(max) = self.budget.max_denials
            && self.consumed.denials > max
        {
            return Err(BudgetExceeded::Denials { allowed: max });
        }
        Ok(())
    }

    fn check_time(&self) -> Result<(), BudgetExceeded> {
        if let Some(max) = self.budget.max_wallclock_secs
            && self.consumed.elapsed_secs >= max
        {
            return Err(BudgetExceeded::Wallclock {
                allowed: max,
                used: self.consumed.elapsed_secs,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unlimited_budget_admits_everything() {
        let mut l = Ledger::new(Budget::unlimited());
        for _ in 0..1000 {
            l.admit_effect().unwrap();
            l.record_spend(Spend::tokens(10_000));
        }
        l.admit_step(0).unwrap();
    }

    #[test]
    fn the_step_limit_stops_the_next_step() {
        let mut l = Ledger::new(Budget::default().steps(2));
        l.admit_step(0).unwrap();
        l.record_step();
        l.admit_step(0).unwrap();
        l.record_step();
        assert!(matches!(
            l.admit_step(0).unwrap_err(),
            BudgetExceeded::Steps { allowed: 2 }
        ));
    }

    /// The blunt instrument: a loop nobody predicted is stopped by count, even
    /// when every individual operation is free.
    #[test]
    fn the_effect_limit_stops_a_runaway_loop_of_free_operations() {
        let mut l = Ledger::new(Budget::default().effects(3));
        for _ in 0..3 {
            l.admit_effect().unwrap();
            l.record_spend(Spend::default());
        }
        assert!(matches!(
            l.admit_effect().unwrap_err(),
            BudgetExceeded::Effects {
                allowed: 3,
                used: 3
            }
        ));
    }

    #[test]
    fn the_token_limit_reports_where_it_stood() {
        let mut l = Ledger::new(Budget::default().tokens(100));
        l.admit_effect().unwrap();
        l.record_spend(Spend::tokens(150));
        match l.admit_effect().unwrap_err() {
            BudgetExceeded::Tokens { allowed, used } => {
                assert_eq!(
                    (allowed, used),
                    (100, 150),
                    "raise-the-limit needs the numbers"
                );
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn the_cost_limit_uses_integers() {
        let mut l = Ledger::new(Budget::default().minor_units(500));
        l.admit_effect().unwrap();
        l.record_spend(Spend::money(499));
        l.admit_effect().expect("still under");
        l.record_spend(Spend::money(2));
        assert!(matches!(
            l.admit_effect().unwrap_err(),
            BudgetExceeded::Money {
                allowed: 500,
                used: 501
            }
        ));
    }

    #[test]
    fn elapsed_time_is_only_checked_when_asked_for() {
        let base = Timestamp::from_unix_timestamp(1_700_000_000).expect("a valid instant");
        let plus = |secs: i64| {
            Timestamp::from_unix_timestamp(base.unix_timestamp() + secs).expect("a valid instant")
        };

        let mut unbounded = Ledger::new(Budget::default().steps(10));
        assert!(!unbounded.tracks_wallclock());
        unbounded.observe_clock(base);
        unbounded.observe_clock(plus(99_999));
        unbounded
            .admit_step(0)
            .expect("no wall-clock limit was set");

        let mut bounded = Ledger::new(Budget::default().wallclock_secs(60));
        assert!(bounded.tracks_wallclock());
        // Deliberately out of order: a concurrent wave reads the clock in
        // whatever order it happens to run, and the ceiling must not depend on
        // which reading arrived first.
        bounded.observe_clock(plus(61));
        bounded.observe_clock(base);
        assert!(matches!(
            bounded.admit_step(0).unwrap_err(),
            BudgetExceeded::Wallclock {
                allowed: 60,
                used: 61
            }
        ));
    }

    /// A negative amount must not be *representable*, not merely refused.
    ///
    /// Every ceiling in this crate is an accumulate-and-compare, so one negative
    /// figure un-spends everything before it. When `minor_units` was an `i64`
    /// that was reachable and demonstrated: a €500 standing authority drawn to
    /// zero, drawn again for −€400, then drawn for a further €400 — €900 against
    /// a €500 mandate, with the ceiling check passing at every step.
    ///
    /// The fix was the type, so the compiler covers every caller and the three
    /// enforcement paths need no rule of their own. What the compiler does *not*
    /// cover is the deserialization boundary — a journal record, a stored row, a
    /// manifest — and that is what this pins. Flip the field back to a signed
    /// integer and these parse successfully instead of failing, which is the
    /// only externally visible difference the change makes.
    #[test]
    fn a_negative_amount_does_not_deserialize() {
        serde_json::from_str::<Spend>(r#"{"minor_units":-1}"#)
            .expect_err("a negative spend un-spends every ceiling comparing against it");
        serde_json::from_str::<Budget>(r#"{"max_minor_units":-1}"#)
            .expect_err("a negative ceiling is not a ceiling");

        // The positive half, so a refuse-everything change cannot pass: the
        // ordinary forms still parse, and to the value they name.
        assert_eq!(
            serde_json::from_str::<Spend>(r#"{"minor_units":250}"#).expect("an ordinary spend"),
            Spend::money(250)
        );
        assert_eq!(
            serde_json::from_str::<Budget>(r#"{"max_minor_units":250}"#)
                .expect("an ordinary ceiling")
                .max_minor_units,
            Some(250)
        );
    }

    /// A wrapping meter would silently re-open a budget that was already blown.
    #[test]
    fn spend_saturates_rather_than_wrapping() {
        let huge = Spend {
            tokens: u64::MAX,
            minor_units: u64::MAX,
        };
        let sum = huge.plus(Spend::tokens(10)).plus(Spend::money(10));
        assert_eq!(sum.tokens, u64::MAX);
        assert_eq!(sum.minor_units, u64::MAX);
    }

    /// The same journaled figures produce the same verdict — the property that
    /// makes an exhausted budget part of history rather than an artefact.
    #[test]
    fn the_same_figures_produce_the_same_verdict() {
        let replay = |spends: &[Spend]| {
            let mut l = Ledger::new(Budget::default().tokens(100));
            let mut stopped_at = None;
            for (i, s) in spends.iter().enumerate() {
                if l.admit_effect().is_err() {
                    stopped_at = Some(i);
                    break;
                }
                l.record_spend(*s);
            }
            stopped_at
        };
        let spends = [Spend::tokens(40); 5];
        assert_eq!(
            replay(&spends),
            replay(&spends),
            "same figures, same verdict"
        );
        // 0, 40, 80 all admit; at 120 consumption has reached the 100 limit.
        assert_eq!(replay(&spends), Some(3));
    }

    /// Literal vectors because this enum is now part of the durable conclusion
    /// format. A serialize-then-deserialize test proves only that two copies of
    /// the same mistake agree.
    #[test]
    fn exhaustion_has_a_stable_tagged_format() {
        let vectors = [
            (
                BudgetExceeded::Steps { allowed: 2 },
                r#"{"limit":"steps","allowed":2}"#,
            ),
            (
                BudgetExceeded::Effects {
                    allowed: 3,
                    used: 4,
                },
                r#"{"limit":"effects","allowed":3,"used":4}"#,
            ),
            (
                BudgetExceeded::Replans { allowed: 5 },
                r#"{"limit":"replans","allowed":5}"#,
            ),
            (
                BudgetExceeded::Denials { allowed: 6 },
                r#"{"limit":"denials","allowed":6}"#,
            ),
            (
                BudgetExceeded::Recorded {
                    limit: "effect budget exhausted".to_owned(),
                    used: "3 performed".to_owned(),
                },
                r#"{"limit":"recorded","recorded_limit":"effect budget exhausted","used":"3 performed"}"#,
            ),
            (
                BudgetExceeded::Tokens {
                    allowed: 7,
                    used: 8,
                },
                r#"{"limit":"tokens","allowed":7,"used":8}"#,
            ),
            (
                BudgetExceeded::Money {
                    allowed: 9,
                    used: 10,
                },
                r#"{"limit":"money","allowed":9,"used":10}"#,
            ),
            (
                BudgetExceeded::Wallclock {
                    allowed: 11,
                    used: 12,
                },
                r#"{"limit":"wallclock","allowed":11,"used":12}"#,
            ),
        ];

        for (value, literal) in vectors {
            assert_eq!(serde_json::to_string(&value).unwrap(), literal);
            assert_eq!(
                serde_json::from_str::<BudgetExceeded>(literal).unwrap(),
                value
            );
        }
    }

    /// A metered budget is overshot by at most one operation, because an
    /// operation's cost is not known until it has run.
    ///
    /// Stated as a test so nobody has to discover it by sizing a limit at their
    /// actual ceiling.
    #[test]
    fn a_metered_budget_overshoots_by_at_most_one_operation() {
        let mut l = Ledger::new(Budget::default().tokens(100));
        l.admit_effect().unwrap();
        l.record_spend(Spend::tokens(99));
        l.admit_effect().expect("99 has not reached 100");
        l.record_spend(Spend::tokens(1_000_000));

        assert!(l.admit_effect().is_err(), "but nothing further starts");
        assert_eq!(l.consumed().spend.tokens, 1_000_099);
    }

    /// An effect *count* limit is exact, because counts are known in advance.
    #[test]
    fn an_effect_count_budget_is_exact() {
        let mut l = Ledger::new(Budget::default().effects(2));
        l.admit_effect().unwrap();
        l.record_spend(Spend::tokens(1));
        l.admit_effect().unwrap();
        l.record_spend(Spend::tokens(1));
        assert!(l.admit_effect().is_err());
        assert_eq!(l.consumed().effects, 2, "never more than asked for");
    }
}

#[cfg(test)]
mod denial_tests {
    use super::*;

    /// The ceiling admits exactly as many refusals as it names.
    #[test]
    fn the_denial_ceiling_admits_what_it_says_and_no_more() {
        let mut ledger = Ledger::new(Budget::unlimited().denials(3));
        for i in 1..=3 {
            assert!(
                ledger.record_denial().is_ok(),
                "refusal {i} is within a ceiling of 3"
            );
        }
        assert!(matches!(
            ledger.record_denial(),
            Err(BudgetExceeded::Denials { allowed: 3 })
        ));
    }

    /// Past the ceiling, nothing further is admitted.
    ///
    /// The half that actually binds: a probing loop swallows the error it gets
    /// back, so what stops the probing is refusing the *next* attempt rather
    /// than reporting the last one.
    #[test]
    fn past_the_ceiling_no_further_effect_is_admitted() {
        let mut ledger = Ledger::new(Budget::unlimited().denials(1));
        assert!(ledger.admit_effect().is_ok());
        let _ = ledger.record_denial();
        assert!(
            ledger.admit_effect().is_ok(),
            "one refusal is within a ceiling of one"
        );
        let _ = ledger.record_denial();
        assert!(
            matches!(
                ledger.admit_effect(),
                Err(BudgetExceeded::Denials { allowed: 1 })
            ),
            "past the ceiling the next attempt must be refused before it is \
             performed, or the loop keeps learning"
        );
        assert!(
            matches!(
                ledger.admit_step(0),
                Err(BudgetExceeded::Denials { allowed: 1 })
            ),
            "and the run must not be admitted to a further step"
        );
    }

    /// No ceiling set means no ceiling applied.
    #[test]
    fn an_unset_denial_ceiling_does_not_bind() {
        let mut ledger = Ledger::new(Budget::unlimited());
        for _ in 0..1_000 {
            assert!(ledger.record_denial().is_ok());
        }
        assert!(ledger.admit_effect().is_ok());
    }
}
