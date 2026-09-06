+++
title = "Plans, cases and time"
description = "Frozen authorization graphs, month-long cases, durable waits and timers, budgets that bind, human tasks and batch runs."
weight = 11

[extra]
group = "How it works"
+++

A run is minutes; a business process is months. This page covers the graph a
run executes, the case that outlives it, the ways a run waits, the ceilings that
bound it, and the humans it waits on.

## Plans

A plan is compiled — from a manifest, from capability routing, or from a model —
into one validated `PlanIR`, then frozen and content-addressed **before anything
runs**.

```
        ┌── s0 fetch ──┐
input ──┤              ├── s2 post (terminal)
        └── s1 check ──┘
```

### The plan is an authorization graph

Because the plan is built from *trusted* input and frozen before any untrusted
data is read, it is more than a schedule: it states what this run is permitted
to do, decided before anything could have influenced it. The journal that
follows can be checked against it.

That check goes past "which capabilities may run". Every argument declares its
source — an upstream node, the run input, or a constant — so provenance is part
of the plan rather than an emergent property of execution:

```rust
PlanNode::new(1, "meter.validate")
    .arg("reading", ArgSource::node(StepId(0)))   // must come from s0
    .arg("threshold", ArgSource::constant(json!(4000)))
```

Labels say *how much to trust* a value; source bindings say *where it came
from*. Both are needed — a label alone permits substituting one untrusted value
for another.

**Labels join as arguments are assembled**, so a step downstream of anything
untrusted receives untrusted input without the plan author saying so. Losing the
label at a step boundary would silently launder provenance and leave the taint
gates further on with nothing to act on.

### The contract

Validation is total, side-effect free, and runs before the first step. Each
check corresponds to a *measured* failure mode — roughly four fifths of observed
multi-agent failures are specification and coordination problems, which is to
say things a graph checker can see.

| Check | What it prevents |
|---|---|
| Acyclic | A run that can never finish while looking busy |
| Has a terminal node | Nothing declaring the plan complete |
| No unreachable steps | Work whose result is silently discarded |
| Dependencies exist | A graph describing something that is not there |
| Capabilities provided | Asking for what the runtime cannot do |
| Arguments bound, and upstream | Reading a value that may not exist yet |
| Verifier has a subject | A verifier that cannot have seen what it checks |
| Verifier present (optional) | Nothing checking the work |
| Topology justified | Paying for coordination that buys nothing |

Rejections name the step and the reason, because a planner — human or otherwise
— can only correct a fault it can see. "Invalid plan" is not a diagnosis.

### Ready-set scheduling

The ready set — every node whose predecessors are done and whose guards hold —
**runs concurrently**. Nothing in it depends on anything else in it, so running
them one at a time is a choice, and the wrong one when steps wait on models and
networks.

Three things make it sound:

- **Each step owns its slice of history.** The replay cursor is per-step, so a
  step touches only its own effects and no shared mutable state is left between
  siblings. Their records interleave in the journal; each step's own order is
  what replay verifies.
- **Admission is sequential, in ready order.** Which step a ceiling refuses must
  be a property of the plan, not of which future polled first.
- **Results are applied in ready order, not completion order.** `completed` is
  what a saga's unwind reverses, and a compensation order set by scheduling would
  undo a plan differently on every run.

The run's output is the **terminal node's** — lowest id if a plan has several —
not the last step to finish. Those coincide only while dispatch is sequential.

`sibling_steps_in_the_ready_set_run_concurrently` proves this by rendezvous
rather than by timing: two siblings each wait on the other's barrier, so
sequential dispatch deadlocks and the test cannot pass by accident on a fast
machine.

`plan.ready(&done)` returns every node whose dependencies are satisfied, in a
**deterministic total order** (topological rank, then id). That ordering is what
admission and result-application follow, so a plan's stopping point does not
depend on its schedule.

This is the useful part of Pregel — a bulk-synchronous ready set with parallel
work and deterministic state application — without importing cyclic mutable
channels. A cycle would execute one step id more than once, collide with its
effect-key/journal slice, and make authorization depend on data observed after
the plan was frozen. Dynamic control flow therefore remains an explicit,
versioned replan with lineage. A graph algorithm that is itself deterministic
can still live inside one skill; it does not redefine the runtime protocol.

**Completion is structural**: every terminal node must have run. A workload
asserting it finished is not evidence.

### Topology

| Topology | Inter-agent failure surface | Cost |
|---|---|---|
| `Single` | None — structurally absent | 1× |
| `Collaborative(reason)` | Full | ~15× tokens |

Routing one trigger to one specialist is a deployment dispatch table, not an
agent topology. It deliberately has no manifest variant: the runtime does not
execute that routing decision, so accepting a `routed` declaration would make a
reviewer believe behavior was digest-covered when it was not.

`Collaborative` requires a reason the contract checks:

- `ParallelDisjoint` — sub-tasks must read genuinely disjoint sources.
  Overlapping ones are **false parallelism**: coordination cost paid, no
  parallelism obtained.
- `DistinctAuthority` — sub-tasks need strictly different capabilities. The best
  reason to split agents and the least often named: it buys least privilege
  rather than hypothetical speed.

### Replanning

A step may return `Outcome::Replan { reason }`. The runtime decides whether it
gets one; a `Replanner` seam decides what it is, because where a new plan comes
from — a router, a rules table, a model call — is a deployment decision.

**Versioned, never mutative.** The successor is `PlanIR v2` carrying
`derived_from: v1`, and both stay in the journal. What the run *intended* before
it changed its mind is usually the interesting part of an incident, and it is
structurally absent from any system that edits a plan in place. A successor that
does not name its predecessor is rejected, and so is one that carries no
`reason`: a plan frozen as having replaced another with nothing on the record
saying why is an audit trail with a hole where the lineage should be.
`PlanIR::succeed_with` sets all three legs — version, parent, reason —
together.

**Refused once untrusted data is in working memory.** This is the sharp one. The
frozen plan is an authorization graph compiled from trusted input only. A replan
*changes that graph*, so if untrusted data has already been read, anything
shaping the new plan may be attacker-chosen — and choosing the authorization
graph is the whole game. The refusal names the source, because "replanning
refused" without saying what made it unsafe sends an operator through the whole
run. A run that wants a different plan after reading untrusted input is
describing exactly the attack.

**Bounded.** `Budget::max_replans` caps it. A run that replans without bound has
stopped making progress and started thrashing.

**A completed step's id may not be reused for other work.** Effect keys are
derived from the step id, so new work at a used id cannot be replayed — and the
unwind, which undoes what actually ran, would compensate whatever now occupies
that slot. The runtime rejects such a successor and names both capabilities. The
successor may keep a completed step, or leave it out; it may not repurpose it.

**The unwind resolves from what ran, not from the plan in force.** `completed`
records the capability alongside the step id, because a successor may drop a
completed step entirely — and resolving the compensation from the live plan then
finds nothing and silently skips it, leaving the mutation in place.

**Read back on replay, never re-synthesised.** A planner asked twice can answer
differently — a changed router, a different model — and replay would then verify
the run against a plan that never governed it. Same rule the first plan follows.

## Cases

A run is one goal, one lifetime. A business process is not: a supplier switch
spans days, and each inbound message arrives as a *separate trigger* knowing
nothing but a document number.

```
Case ──┬── run (day 0: request sent, obligation registered)
       ├── run (day 1: acknowledgement received, obligation met)
       └── run (day 12: invoice disputed)
     correlation: document=DOC-4711, meter=51238696781
```

**Correlation happens at admission, before planning**, because which case a
message belongs to is a question of fact, not judgement — a deterministic lookup
on business keys, never a model call.

Two schema constraints carry the correctness:

- **Open cases are keyed by `(namespace, value)`**, so "concurrent messages for
  one new case produce one case" is a store invariant. Without it, two inbound
  messages racing at admission fragment a process across two cases and its
  obligations are tracked in neither.
- **Every sweep has its own index, keyed by the instant it looks for.**
  Obligations by when they first need attention, inbound events by arrival while
  unclaimed, tasks by their closing window, the worklist backlog by membership.
  Each keeps its sweep a bounded range scan at a hundred thousand open items,
  rather than a table scan that quietly stops finishing on time — and on redb
  each index is written in the same transaction as the row it describes, so it
  cannot be left describing something that was never committed.

Every record of a case-bound run carries its case id, so "show me everything
about this matter" is one indexed range scan instead of a join across runs.

**Closing is guarded, in both directions.** A case with an unmet obligation
refuses to close — as the typed `ObligationsOutstanding` refusal, never a
backend fault, so a store that is merely unreachable cannot read as the rule
firing. That is the check that stops a missed regulatory window from vanishing
behind a tidy status.

On its own it would only be a check. *A closed case owes nothing* is a property
of the store rather than of the order two callers happened to run in, so the
write that could break it afterwards refuses too: registering an obligation on
a closed case is `CaseClosed`. Without that half the sweep breaches the late
obligation and escalates, and a matter audited as settled acquires a duty and
misses it with no run and no operator involved. The two decide one at a time —
redb by its single write transaction, PostgreSQL by taking the case row's lock
before it counts.

Closing releases the correlation keys, so a genuinely new matter about the same
entity opens a fresh case rather than reanimating a concluded one. **Leaving
`Closed` takes the free ones back**, which is the same rule read backwards: a
case reopened by any route — a run's `set_case_status`, the sweep escalating
over an expired task — would otherwise come back live-looking and unreachable,
a matter no inbound message can correlate to. A key another case has since
claimed stays where it is; the identifier belongs to whichever matter is open
for it now.

**How an obligation ended is not editable.** Met, breached and withdrawn are
terminal. `cx.meet_deadline` is a `set_deadline_state` write like any other, so
without that rule a run answering after the window closed would move a breached
obligation to met — erasing the only record that it closed unmet and taking the
miss off the obligation listing in one call. Re-applying the state already held
still succeeds, because a sweep repeating its own last write is a retry rather
than an edit. A late answer is recorded as an account of the breach.

Every half holds on the agent path too: `set_status(Closed)` routes through the
same closure, and the conformance battery pins each refusal's type on every
backend.

### Why a case rather than one long-lived run

Durable-execution engines usually model this as a workflow that lives for weeks.
That is a versioning trap: a six-week workflow pins your code version for six
weeks, and every deploy needs a migration story for in-flight instances.

Inverting it — short runs, long cases — makes deploys free. The cost is that
continuity must be explicit (case state, not local variables), which is the
right trade when the alternative is an auditor asking about a process whose code
no longer exists.

That explicit state carries two obligations, and both were learned the hard way.

**It is read through the effect protocol, not directly.** Case state is mutable
storage shared by every run on the case, so reading it is exactly as
non-deterministic as reading a clock. Read directly, a strict replay sees
whatever the case holds *now* and the run reaches a different answer from the
same journal — and writes to the store on the way through, against a runtime
whose replay is supposed to perform nothing. `cx.case_state()` and
`cx.put_case_state()` are journaled effects for the same reason `cx.now()` is.

**A case-state read comes back untrusted.** Case state is shared mutable state:
several runs write it over a process that may last months, and the engine never
interprets a byte of it, so a read is only as trustworthy as the least
trustworthy thing anybody ever wrote — and nothing in the runtime knows what that
was. Handing it back trusted made it an exit from the lattice: a skill holding a
model completion could put it into case state and read it back clean in a later
step, or a later *run*, having passed none of `cx.release`'s policy check and
leaving no record that a declassification happened.

Storing the writing step's label instead would be no better, because it describes
one write out of many while reading as authoritative. The join of every writer is
the only honest label; it decays to untrusted the moment anything untrusted lands
and never recovers on its own — so untrusted *is* that answer, without the
machinery needed to arrive at it. A caller who genuinely needs it trusted asks
for a release, which is journaled, policy-checked, and names who decided.

**A write names the version it read.** A run is owned — one writer per journal,
arbitrated by the lease. A case is the opposite: it is what several runs share,
and the shared-store topology exists precisely so several plane instances write
at once. The window between reading case state and writing it back contains a
model call, which is unbounded, so two runs on one case overlap as a matter of
course. A blind `UPDATE cases SET state = ?` in that window discards whichever
write lost, silently. The version check is a predicate on the `UPDATE` — not a
read followed by a write — for the same reason exactly-once is a unique index.

## Deadlines and the calendar seam

Regulatory deadlines are rarely "now plus 24 hours". A realistic one reads: *five
working days, at 17:00 in a named timezone, excluding weekends and public
holidays — where a holiday observed in any single federal state counts
nationwide.* An off-by-one-hour error at a daylight-saving transition is a
compliance violation, not a rounding issue.

None of that belongs in a domain-agnostic engine. All of it must be reachable
from one:

| Core owns | Adapter owns |
|---|---|
| Durable registration, firing, cancellation | What "5 working days" resolves to |
| Warning thresholds, escalation | Holiday tables, timezone, cut-off hour |
| Breach recording, closure rules | Calendar versioning |

```rust
pub trait Calendar: Send + Sync + Debug {
    fn resolve(&self, from: Timestamp, spec: &DeadlineSpec)
        -> Result<Timestamp, CalendarError>;
    fn digest(&self) -> Digest;
}
```

**The resolved instant is journaled — not the rule that produced it.** Resolution
goes through the calendar as an *effect*, so replay reads back the instant the
original run registered rather than recomputing it against whatever the calendar
says today. A corrected holiday table cannot retroactively move an obligation
someone already relied on, and the `calendar_digest` beside the instant says
which ruleset produced it, making a changed rule visible instead of silent.

The built-in `WallClock` understands plain offsets and **refuses** anything it
does not know rather than approximating. A wrong working-day answer is worse
than no answer, because it looks right.

## Durable waits

A run sends a request and waits for a reply that may take days. The waiting is
not the hard part — the arrival ordering is.

```
        ┌─────────────────────────────────────────────────────┐
        │  deliver(event)                                     │
        │    1. store it durably          ← always, first     │
        │    2. look for a waiter                             │
        │       found  → journal EffectDone, resume the run   │
        │       none   → Buffered (held, not dropped)         │
        └─────────────────────────────────────────────────────┘
        ┌─────────────────────────────────────────────────────┐
        │  await_event(spec)                                  │
        │    1. journal the subscription  ← before suspending │
        │    2. look in the buffer                            │
        │       found  → consume it, continue immediately     │
        │       none   → suspend; the frame is a row on disk  │
        └─────────────────────────────────────────────────────┘
```

**Both directions exist because either side can be first.** A design that only
matches subscriptions on arrival drops any reply that beats its run to the wait,
and that run then waits forever for something that already happened. Delivery
and waiting meet in the store, not in time.

The wait is modelled as an **effect** whose output is the event. Delivery
journals an `EffectDone` under the wait's key and then resumes the run in
`Resume` mode, where the awaited event is read back like any other recorded
result. None of the suspension machinery exists twice, and a resumed run replays
strictly.

Three consequences worth naming:

- **A suspended run costs a row.** No thread, no task, no held connection. The
  frame is journaled and dropped; `RunSuspended` records why.
- **A suspended run is not sealed.** Its chain is going to be extended the
  moment the event arrives.
- **Every wait names a deadline.** An unbounded wait is a run that can hang
  forever with nothing to notice it — the failure that presents as "the process
  just stalled". A wait referencing an unregistered obligation is refused.

### Dead letters

Dead-lettering happens on a **sweep** of the buffer, never on arrival. "Nobody
is waiting for this yet" and "nobody will ever want this" are different claims,
and only the second is safe to act on.

A non-empty dead-letter list means a correlation key is wrong somewhere: the
message arrived, was held, and no run ever asked for it. That is worth paging
on — it is the failure that otherwise presents as a process silently never
completing. `GET /dead-letters` is what the page leads to: it names each message
and the keys it was filed under, so the mismatch is visible beside what the run
subscribed to. The body is deliberately not there — the diagnosis is in the
keys, and the payload is the counterparty's.

Delivery is deduplicated by event id, so a counterparty that retries — and they
all retry — does not deliver twice. Claiming happens inside the transaction that
selects, so two runs waiting on one key cannot both consume a single message.

## Durable timers

A wait whose event is the clock.

```rust
cx.sleep(Duration::from_secs(86400)).await?;      // or sleep_until(instant)
```

The run suspends, the frame is persisted, and a sweep wakes it when the instant
arrives — so a process waiting five Werktage is a row, not a held task, and a
restart loses none of them.

**The instant is journaled, not recomputed.** Recomputing `now + duration` on
replay would move the wake time every time, exactly as recomputing a calendar
deadline would. A run that slept until Tuesday still says Tuesday when replayed
next year.

**The wake-up is single-delivery.** A sweep claims a due timer atomically before
firing it, so two sweepers over one store cannot both resume the same run.

**A claim is a lease, not a mark.** A sweeper that dies between claiming and
journaling the wake-up would otherwise strand the run forever: the row stays
claimed, no later sweep looks at it, and the run waits for an instant that has
passed. The claim lapses after a grace period, and re-firing is safe because the
wake-up is recorded under a fixed effect key — a second write is the same write.

**The recorded wake is the instant it was *due*,** not the instant a late sweep
noticed. Otherwise a sweep that ran an hour behind would make the run believe it
slept an hour longer than it was told to, and a replay would compute different
downstream deadlines than the original.

A timer needs no case: there is nothing to correlate and no horizon to bound it,
because the instant *is* the horizon. Durable sleep is available to any run.

### This is not a retry backoff

A retry's backoff waits in-process, bounded by `RetryPolicy::max_backoff`, and
that is deliberate. Waking a suspended run replays it from the beginning — a run
fifty steps deep should not pay fifty steps of replay to avoid a five-second
sleep.

The boundary is drawn by purpose, not duration:

| | |
|---|---|
| Retrying a flaky call | `RetryPolicy` — in-process, bounded by `max_backoff` |
| Waiting for the world — a settlement date, five Werktage | `cx.sleep()` — suspends, costs a row |

### When the peer names the window

A computed backoff is a **guess about when a service recovers**, and it is the
right shape for a failure nobody can time. It is the wrong shape for a throttle:
a schedule capped at ten seconds meets a sixty-second rate-limit window three
times inside a second, exhausts its attempts, and reports the provider as down.
Correct by the policy, and a false outage.

So a failure that carries a `Retry-After` schedules the next attempt from the
number the peer gave. Every HTTP driver reads the header, `EffectError::RateLimited`
carries it, and `RetryPolicy::wait_before` is the one place that chooses between
the two schedules.

```rust
// A provider that says "come back in 30s" is waited out, not hammered.
let policy = RetryPolicy::attempts(4).wait_at_most(Duration::from_secs(45));
```

Two ceilings, not one, because obeying a stranger and guessing for oneself are
different risks:

| | Bounds | Default |
|---|---|---|
| `max_backoff` | the **guess** — nobody knows when the service recovers, so waiting long is waste | 10 s |
| `max_advice` | **somebody else's word** — from the one party with an interest in never being called again | 60 s |

Advice past `max_advice` is clamped rather than discarded: waiting part of a
window is closer to right than ignoring it, and if the window really was longer
the next refusal names what is left. Advice this runtime cannot act on is *no
advice*, which is the same answer as an absent header — an HTTP-date, because
acting on it means trusting the peer's clock against ours, and zero, because it
would replace a backoff with no wait at all.

The wait is still in-process, so `max_advice` is also a bound on worker
occupancy. A rate limit measured in more than minutes is not a retry; that is
`cx.sleep()`.

## Budgets

A budget decision is control flow — "may this effect run?" changes what the run
does — so it lives in the deterministic zone, and everything it reads has to be
reproducible.

That rules out asking a provider what something cost at replay time; the answer
moves. Instead:

```
effect completes → Effect::spend(&output) → journaled in EffectDone
                                              ↓
replay reads the recorded figure ────────────→ same verdict, same point
```

A run that exhausted its budget **verifies** as exhausted even under a larger
limit — a strict replay's stopping point is recorded, not recomputed. A
**resume** is the path a raised ceiling changes, and it changes it at both
tiers: a run refused at the step ceiling and one refused at an effect ceiling
are each re-asked against the ledger now in force, journaled as
`BudgetReadmitted` beside the refusal it supersedes (see
[Exhaustion is not failure](#exhaustion-is-not-failure)). Only a refusal at
the **history frontier** is re-asked — one the run itself already answered,
such as a group member's refusal followed by the abort's reversals, replays
verbatim, because re-admitting it would dispatch into recorded history.

### What can be limited

| Limit | Exact? |
|---|---|
| `max_steps` | Yes — admission counts what it has already handed out in the wave |
| `max_effects` | Yes — admission takes the slot in the same lock that checked it |
| `max_tokens` | No — see below |
| `max_minor_units` | No — see below |
| `max_replans` | Yes — each plan change is counted |
| `max_denials` | Yes — each policy refusal is counted |
| `max_parallel_steps` | Yes — the ready set is dispatched no wider |
| `max_wallclock_secs` | Opt-in; costs one journaled clock read per step boundary, and the reading has to be journaled or the verdict changes every time you look |

A ready set runs concurrently, which is what the two "counted in advance"
answers have to survive. A step is counted when it finishes and a whole wave is
admitted before any of it runs, so admission counts the branches it has already
taken; and an effect's slot is taken by the same lock that checked for it,
because a verdict acted on later is a verdict every concurrent caller passes.

The last two counters bound faults rather than work. A run that replans without
bound has stopped making progress and started thrashing, and the ceiling turns
that from an unbounded spend into a reported fault. A run that keeps hitting
the policy is probing it: refusals carry a uniform message precisely so a model
cannot tell one from another, but the refused/allowed bit itself still leaks
one bit per attempt, and nothing short of fabricating success removes that —
what bounds the channel is bounding the attempts. It is an operational ceiling
as much as a security one, because a denial loop is thrashing by another name.

### A metered budget overshoots by one operation per step in flight

An operation's cost is not known until it has run, so a token or money limit
cannot be a hard ceiling. What is enforced is: *once consumption has reached the
limit, nothing further starts.* A run therefore overshoots by at most one
operation's cost **per step it has in flight** — every step in a ready set may
be holding a call the ledger admitted and has not yet been told the price of.

So the width is a declared bound rather than whatever the plan happens to be:
`spec.budgets.max_parallel_steps` caps how many of a ready set are dispatched at
once, and dispatch stays ordered so narrowing the wave never reorders it. Absent,
the plan's own width is the bound — right for a graph you wrote, wrong for one
anything else may widen.

This is stated rather than hidden, because the alternative — implying a hard cap
— is how somebody sizes a limit at exactly their ceiling and is surprised. Where
a true ceiling matters, set `max_effects` as well: a count is known in advance,
so that one is exact however wide the plan runs.

Money is tracked in **integer minor units**. Money that rounds differently on
two machines is money that produces two different budget verdicts.

### A wall-clock ceiling is measured from the journal

Elapsed time cannot be checked without reading a clock, and a clock read is an
effect. So a run that declares `max_wallclock_secs` takes one **journaled**
reading at each step boundary, and a run that does not takes none — the reading
is not free, and neither is a ceiling nobody asked for.

Journaled rather than ambient is the load-bearing half: a verdict read off the
wall is a different verdict every time you look at the run, and an exhausted run
would replay as healthy. Elapsed time is then the distance between the
**extremes** of what the run read, never between the first and last *arrival* —
a ready set is dispatched concurrently, so arrival order belongs to the
scheduler, and a ceiling that depended on it would fire on some passes over one
history and not on others.

Reading at boundaries has a limit, and it is stated rather than implied: the
ceiling stops the *next* step, so a single step that overruns it is not
interrupted. Nothing cancels work in flight — that would abort an effect
mid-call and manufacture the unknown outcome the effect protocol exists to
refuse. What bounds one call is the driver's own timeout; this bounds how long a
run goes on making new ones.

One consequence, because it is the only asymmetry among the ceilings: the step's
first effect is that reading when a wall-clock ceiling is declared and the
skill's own when it is not, so such a history replays under a **raised** ceiling
and not under a build that removed it. Every other ceiling can be changed in
either direction between passes.

### One announcement, one slot, on every pass

The tally is the same on both sides of a replay, and that is arithmetic rather
than intent. An attempt takes its slot when it is admitted and adds its cost
when the call returns. The pass that reads that attempt back out of the journal
takes **one** slot and adds **every** figure the attempt's records carry —
including one a later record superseded, which the live pass had already added.
A reconciled call is the sharp case: an announcement, a failure carrying what
died mid-flight, and a probe's verdict carrying what the recovered call
reports, all under one effect key and all part of one attempt's cost.

An arm that bills twice, or one that drops a superseded figure, moves where a
resumed run stops without changing anything a status assertion can see: the run
concludes `Exhausted` against a ceiling its own history never reached, at a
point no record contains. So the property is asserted as a *tally* —
`RunOutcome::consumed` after a strict replay must equal the live run's — rather
than as an outcome.

### Exhaustion is not failure

`RunStatus::Exhausted` is distinct from `Failed`. The run did what it was told,
and what it was told included a ceiling. Conflating the two has operators
debugging a system that behaved exactly as instructed. It is also a **pause**
rather than an end: completed work stands, and resuming after the ceiling was
raised re-evaluates the recorded refusal against the current ledger, journaled
as `BudgetReadmitted` so the chain says who raised what to let it continue. The
one exception is a run that has already compensated — that one is closed to
resume, because continuing over reversed work would report success about a
world where it no longer stands.

## Human tasks

A worklist is a durable wait with an operational surface — and it reuses the
wait machinery wholesale. `cx.task(spec)` registers a subscription, creates a
queue row, and suspends; a decision is delivered as an ordinary inbound event
correlated to the task id, so it travels the same buffered, deduplicated,
single-consumer path as any other message.

Task ids are **derived from the awaiting effect's key**, not minted, so they are
stable across replay: a resumed run addresses the same task rather than opening a
second one for the same decision.

### What a task carries, and why

Oversight fails through *approval fatigue*, not refusal. A queue of proposals
nobody can evaluate becomes a queue of rubber stamps — worse than no oversight,
because it launders the decision. So a task carries what a reviewer needs in
order to **disagree**:

| Field | Why it is there |
|---|---|
| `proposed_action` | The action itself, so the reviewer sees what will happen rather than a description of it |
| `confidence` | A confident-sounding proposal is not evidence that it is right |
| `cost` | What acting will cost |
| `evidence` | The trail behind the proposal |
| `due_at` | Taken from the case's obligation, so reviewer and case share one deadline |

### Four eyes

`TaskSpec::excluding(actor)` bars whoever proposed an action from approving it,
checked inside the same transaction that reserves the task. Without an enforced
exclusion, dual control is a naming convention.

Claiming is also atomic: two reviewers opening one queue must not both believe
they hold a task, and a check followed by a separate write has exactly that
window.

### A task's state answers three different questions

`GET /tasks`, the backlog gauge and the expiry sweep read three different sets,
and a backend that treats them as one shows a held decision to a second
reviewer or stops applying an expiry policy plane-wide.

| State | In the queue | In the backlog | Owed to the expiry sweep |
|---|---|---|---|
| `open` | ✅ | ✅ | ✅ |
| `claimed` | — | ✅ | ✅ |
| `escalated` | ✅ | ✅ | — |
| `completed`, `expired` | — | — | — |

A claimed task leaves the queue because it is nobody else's to take, and stays
in the backlog because it is still a decision the plane is waiting on. An
escalated one is queued again — escalation releases the claim and widens the
audience, which is only a remedy if somebody can then see it — and is owed
nothing further by the sweep, because its expiry policy has already fired. The
three predicates are `TaskState::is_queued`, `is_pending` and `awaits_expiry`;
an implementation of `TaskStore` should call them rather than re-deciding.

### Expiry is declared, never decided in the moment

| `OnExpiry` | Behaviour |
|---|---|
| `Deny` | Refuse the proposed action. The default. |
| `Escalate` | Widen the audience and keep waiting. Idempotent, so the sweep is safe on a timer. |
| `Proceed` | Act unattended — **requires `allow_unattended()`** |

The separate opt-in exists so that acting without a human is an explicit,
greppable decision rather than an enum variant somebody picked off a list.
"The human did not answer, so we did it anyway" must be something signed in
advance.

## Batch runs

A batch is one business act made of many independent ones — a Jahresabrechnung
over 10⁵ meters. It is modelled as neither one run nor N unrelated ones, because
both lose something: one run gives 10⁵ settlements a single failure and a single
budget, and N unrelated runs leave nobody able to answer "did it finish".

So a batch owns N runs sharing one frozen plan. Each item gets its own journal,
its own budget, and its own outcome; the batch holds the cursor, the census, and
the terminal state.

"One frozen plan" is the store's to enforce, not a convention: the batch row
records the plan digest it was opened with, and a resume offering a different
one is refused naming both digests. By the time the runner executes an item,
that row is the only witness to what the batch was opened as — accepted, items
from the resume onward would settle under a plan the batch's record does not
name. The row also answers existence: a report on an unknown batch id is a
refusal, never an empty `Running` — a census cannot tell a mistyped id from a
batch with no items yet, and an operator watching a batch that will never
exist is the quieter of the two mistakes.

### Partial failure is enforced by the type

`BatchStatus` has no `Succeeded`. A finished batch is `Completed { succeeded,
failed, quarantined }`, so there is no way to spell "it worked" that skips the
counts. This is deliberate: "mostly worked" is reported as success everywhere it
is not explicitly handled, and the items that failed are the ones a human needed
to hear about.

### An item is processed the way an effect is performed

Announce, act, record. The item's run id is written to the batch store *before*
the run starts, so a crash in between leaves an item marked started with a known
run id — and resume **replays that run** rather than starting a new one. Its
effects come back from its journal instead of happening twice.

Two consequences:

* Reserving an item twice must return the *original* run id. Overwriting it would
  orphan the first journal and re-perform its effects.
* **The cursor is an optimisation, not a correctness mechanism.** Lose it and
  re-processing every item is safe — slow, but not wrong. Preserve that property
  when changing anything here.

### Two distinctions that are easy to get wrong

The cursor is the **contiguous terminal prefix**, not the highest finished key: an
item suspended at 400 holds the cursor at 399 even if 401–500 have finished, or a
resume steps over it and the batch reports complete with work outstanding.

And "every stored item is terminal" is **not** "the batch is finished" — a batch
halted after 10,000 of 100,000 items has no unfinished item anywhere in its
store. Whether the source was read to the end is recorded durably, because a
resumed batch has to know whether it ever reached the end.
