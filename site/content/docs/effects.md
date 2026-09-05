+++
title = "The effect protocol"
description = "At-most-once outward calls: intent before action, unknown outcomes that stay unknown, sagas, transactional effect groups, and what stopping a run does."
weight = 7
+++

Every outward call — a model completion, a tool call, a clock read, a payment —
crosses one protocol. This page is that protocol, the saga rules built on it, the
transactional group that sits between an effect and a step, and what an operator
stopping a run does to work already done.

## The effect protocol

<figure class="diagram">
<svg viewBox="0 0 640 200" role="img" aria-labelledby="ep-t ep-d" xmlns="http://www.w3.org/2000/svg">
  <title id="ep-t">The effect protocol and its two crash points</title>
  <desc id="ep-d">An effect is announced to the journal, then performed against the
    world, then its outcome is recorded. A crash between announce and act means the
    call did not happen. A crash between act and record means the outcome is
    unknown — the in-doubt case.</desc>

  <rect class="box" x="8"   y="60" width="150" height="52" rx="9"/>
  <rect class="box" x="245" y="60" width="150" height="52" rx="9"/>
  <rect class="box" x="482" y="60" width="150" height="52" rx="9"/>

  <text class="lbl" x="83"  y="82"  text-anchor="middle">1 · Announce</text>
  <text class="sub" x="83"  y="99"  text-anchor="middle">EffectStarted</text>
  <text class="lbl" x="320" y="82"  text-anchor="middle">2 · Act</text>
  <text class="sub" x="320" y="99"  text-anchor="middle">the outward call</text>
  <text class="lbl" x="557" y="82"  text-anchor="middle">3 · Record</text>
  <text class="sub" x="557" y="99"  text-anchor="middle">EffectDone</text>

  <path class="arrow" d="M158 86 H239" marker-end="url(#ah)"/>
  <path class="arrow" d="M395 86 H476" marker-end="url(#ah)"/>

  <path class="danger" d="M201 60 V26"/>
  <text class="danger-lbl" x="201" y="18" text-anchor="middle">crash → DidNotHappen</text>
  <path class="danger" d="M438 112 V150"/>
  <text class="danger-lbl" x="438" y="166" text-anchor="middle">crash → InDoubt</text>

  <defs>
    <marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L10 5 L0 10 z" fill="currentColor" class="arrow"/>
    </marker>
  </defs>
</svg>
<figcaption>The order is the guarantee. Announcing <em>before</em> acting is what makes
the second gap survivable: a record exists naming a call whose outcome nobody knows,
so the run can be quarantined rather than retried blindly or unwound as if it never
happened.</figcaption>
</figure>

```
    announce            act              record
  EffectStarted  ──►  perform()  ──►  EffectDone
       │                                   │
       └── durable before anything         └── durable after
           externally visible happens          it happened
```

Three rules:

1. Announce intent durably **before** acting.
2. Record the outcome durably **after** acting.
3. On restart, an announcement with no outcome is **undecidable**.

Rule 3 is the one that is tempting to get wrong. A crash between "sent the
request" and "recorded the answer" leaves no way to know whether the action
landed. Retrying looks helpful and is exactly how a duplicate invoice gets
issued. So every effect declares its recovery semantics:

| `Recovery` | Meaning |
|---|---|
| `Retry` | Pure read or idempotent write — safe to re-run |
| `Idempotent { key }` | Provider honors a key; replay reuses it |
| `Reconcile` | Ask the provider whether it landed — see below |
| `RequiresOperator` | Undecidable. Escalate. Never guess. |

`RequiresOperator` is the **default**, so an effect that forgets to declare
itself gets the conservative treatment rather than the convenient one.

### Retries, and the failures that must not be retried

Rule 3 above is about a *crash* leaving the outcome unknown. A call that fails
on its own leaves exactly the same unknown, reached from the other direction —
and the runtime knows exactly as much in both cases, which is nothing.

The distinction that makes repeating safe is **not** whether the error looked
transient. A refused connection and a timed-out request are both transient; only
one of them provably never reached the peer. So every `EffectError` declares a
`Disposition`:

| `Disposition` | Meaning | Repeatable? |
|---|---|---|
| `DidNotHappen` | Refused before dispatch, or rejected with the request intact | Always — even for a mutation |
| `InDoubt` | Timed out, or the connection died mid-flight | Only if `Recovery` says so |
| `Landed` | It took effect and the response would not decode | Never |

The vocabulary is borrowed from distributed transactions, where a participant
whose outcome is unknown after a failure has been called **in-doubt** since the
XA specification. The situation is identical, and so is the resolution: an
in-doubt mutation is escalated, never guessed at.

Three gates decide, in order:

1. The **disposition** — did the call reach the outside world?
2. The **recovery mode** — for an in-doubt failure, is guessing permitted?
3. The **retry policy** — and only then, how many times and how far apart.

A policy can narrow what the first two allow and can never widen it. Raising
`max_attempts` does not make a mutating in-doubt call retryable, which is
pinned down by `raising_max_attempts_does_not_make_an_in_doubt_call_retryable`
in `tests/engine/retries.rs` and by the `RetryInDoubtBlindly` mutant in `spec/`.

#### Asking beats guessing

`Recovery::Reconcile` is the branch that turns an undecidable outcome into a
decided one. Instead of assuming the call is safe to repeat, the runtime asks the
provider what happened — retrieve the payment intent by id, query the transfer by
reference. Every serious provider supports it, and it is the only route out of
doubt that is not a bet.

```rust
async fn reconcile(&self) -> Result<Reconciliation<Self::Output>, EffectError> {
    match self.provider.retrieve(&self.client_ref).await? {
        Some(done) => Ok(Reconciliation::Landed(done)),   // completes the effect
        None       => Ok(Reconciliation::DidNotHappen),   // safe to send now
    }
}
```

| Verdict | What happens |
|---|---|
| `Landed(output)` | The effect completes with the **recovered** result. Nothing is re-performed. |
| `DidNotHappen` | An escalation becomes an ordinary retry — safe because it was *established*, not assumed. |
| `Inconclusive` | Nothing changes. The doubt survived being asked about, and the run escalates. |

The probe must identify the call by something stable across attempts — an
idempotency key, a client reference, an order id in the request. A probe that
matches on a timestamp or on "most recent" is not a probe; it is a guess with
extra steps, and the guess authorises a real repeat. That exact failure is the
`ProbeMatchesTooLoosely` mutant, and it trips `ExactlyOnce`.

The verdict is journaled **even when inconclusive**, along with the probe's own
error if it failed. Leaving that out would make an escalation look like nobody
tried, and the operator would repeat the probe by hand. Journaling also makes the
probe replayable: it is a network call like any other, so replay reads the
verdict back rather than asking again.

The default implementation returns `Inconclusive`, so declaring `Reconcile`
without writing a probe escalates rather than silently deciding either way.

#### Backoff

Backoff is exponential with an integer multiplier and a ceiling. Jitter is
*derived*, not drawn: the runtime forbids ambient randomness, so the spread
comes from `H(run ‖ key ‖ attempt)` mapped into `[0.5, 1.0]` of the computed
delay. Including the run id is what decorrelates two runs of the same plan
retrying the same effect — without it, identical keys would produce identical
schedules and reconverge into exactly the thundering herd jitter exists to
prevent.

Every attempt is journaled with its number, its backoff, and — on failure — its
disposition. An operator asking "why did this call the endpoint three times"
reads the answer instead of correlating logs.

**A retry is billed.** Admission is checked per attempt, because a ceiling that
only counted first attempts is a ceiling a retry storm walks straight through.

### Effect keys

`key = H(step ‖ ordinal ‖ attempt ‖ kind ‖ canonical(args))`

Skills never construct these. An effect declares *what it does*
(`EffectDescriptor`) and the runtime derives the key from that plus the effect's
position. If effects chose their own keys, a buggy or hostile one could collide
with another's and read back someone else's journaled output.

`attempt` is in the key so a retry is a *new* effect in the journal rather than
a second record under an existing one. Without it, attempt 2 would collide with
attempt 1's recorded failure — replay would read back the failure instead of the
retry that followed, and the store's uniqueness constraint would reject the
second attempt outright.

Two properties follow:

- **Exactly-once** — the store keys effect starts by `(run_id, effect_key)`, so
  a second start for one effect is a store invariant rather than a code path
  someone might forget to call. On redb the key *is* the table's identity, so a
  duplicate is inexpressible; on Postgres it is a partial unique index, which
  says the same thing in that engine's terms.
- **Divergence detection** — the key is position-sensitive, so a build that
  performs different effects, or the same effects in a different order, cannot
  quietly reuse a recorded run's history.

## Sagas: undoing a run forward

A plan that touches real systems cannot be a transaction — there is nothing to
roll back across a payment provider and a warehouse. So when a step fails, the
completed steps are compensated in **reverse order of completion**. That order is
not stylistic: a later step may depend on what an earlier one set up, so undoing
the earlier one first can leave the later compensation with nothing to work
against.

Each step declares its place:

| `Compensation` | Meaning |
|---|---|
| `Compensatable` | `Skill::compensate` undoes it |
| `Pivot` | The point of no return. Nothing at or before it is reversed. |
| `Unnecessary` | Nothing to undo, and someone said so |
| `Undeclared` *(default)* | Resolved from the journal — see below |

### Undeclared is judged on evidence

The default is not "assume it is fine". At unwind time the runtime reads the
journal for `EffectStarted { mutates: true }` in the step's forward phase:

- **No mutating effect?** There is nothing to undo, and the journal proves it.
  The step is skipped and the unwind continues.
- **A mutating effect?** The unwind **stops and escalates**, naming the step.

Silently skipping a charge while reversing everything around it is precisely the
outcome this mechanism exists to prevent, so forgetting to declare is loud rather
than convenient. Evidence rather than bookkeeping also means the answer is the
same live and on replay, with no parallel state to keep honest.

### A run in doubt is never unwound

This is the rule that separates a saga honest about distributed systems from one
that tidies up and hopes.

A quarantined run holds an effect whose outcome is unknown. Compensating a
payment that may never have gone out creates a refund for money nobody took, and
undoing everything *except* the one thing nobody can account for leaves a worse
mess than stopping. So a quarantined run compensates nothing. A suspended run
does not unwind either — it is healthy and waiting. Cancellation obeys the same
rule from the other direction: a cancel refuses to unwind through recorded
doubt, because "stop" must not manufacture a reversal for work nobody can
account for.

What *does* unwind: `Failed`, and `Cancelled`. **Exhaustion does not** — it is
a pause, not a fault. The run did what it was told, and what it was told
included a ceiling; its mutations stand, because the operator's two honest
options both need them standing. Raise the ceiling and resume — the resume
re-evaluates the recorded budget refusal against the current ledger and
journals a `BudgetReadmitted` record — or cancel, which unwinds through the
ordinary path.

### Compensation is exempt from the budget

Refusing to undo because the ceiling was reached is how a run ends with a charged
card and no order. The ceiling exists to bound work, not to strand it half-done.
Exempt from the *verdict*, not from the count: a compensating effect still takes
its slot and still reports its spend, so the overshoot is visible rather than
silent — and a pass replaying that announcement bills the same one it did live.

A **group reversal** carries the same exemption, and needs it stated separately
because it cannot be inferred: a reversal runs in the step's *forward* phase, so
the phase — which is what exempts a compensating effect — says nothing about it.
Without the exemption a run that reached its ceiling mid-group could not release
the hold it had already placed, which is the outcome above reached by a different
road.

### A compensation may wait for a human

A refund that needs four eyes is still a refund. `compensate()` may suspend like
any other step — on an approval, a settlement window, a counterparty
confirmation — and that is **not** a failed compensation. The run is healthy, its
frame is durable, and it finishes unwinding when the answer arrives.

When it resumes, the unwind re-walks from the top rather than remembering a
position, skipping steps the journal already records as compensated. Re-running a
compensation is safe — its effects come back from the journal — but re-*recording*
one would report a single compensation as two, so the `StepCompensated` record is
written only when there is not already one for that step.

### Concurrency and the unwind

Two rules govern what a batch of concurrently-dispatched siblings does when one
of them stops.

**Every success is recorded before the stop is reported.** A sibling that
completed and mutated must be compensated, and `completed` is exactly what the
unwind reverses. Returning on the first non-success in ready order would discard
later siblings' completions — effects performed and never undone.

**Severity beats ready order.** A suspension is the run working; a failure is the
run over. If one sibling suspends on an approval and another fails after
mutating, reporting the suspension would defer the unwind until an event that may
never arrive. So `Quarantined` > `Failed` > `Exhausted` > `Suspended`, with two
peers folded into the ranks: `Cancelled` sits with `Failed`, because a stop
ranks with a failure rather than above it — both end the run and both unwind —
and `Replanning` sits with `Suspended`, the weakest signal in a batch, since a
sibling that failed outright has already decided the run and re-planning around
a failure is not what the requesting step was asking for. Ready order decides
only within a severity — keeping the choice a property of the plan rather than
of the schedule.

`Quarantined` sits highest because it is the only one that must *not* unwind.

<figure class="diagram">
<svg viewBox="0 0 640 190" role="img" aria-labelledby="st-t st-d" xmlns="http://www.w3.org/2000/svg">
  <title id="st-t">Terminal run statuses, ordered by severity</title>
  <desc id="st-d">When concurrently dispatched siblings disagree about how a run
    ended, severity decides, not the order they happened to be scheduled in.
    Quarantined outranks Failed, which outranks Exhausted, which outranks
    Suspended. Cancelled ranks with Failed; Replanning ranks with Suspended.
    Only Quarantined refuses to unwind.</desc>

  <rect class="box" x="14"  y="58" width="132" height="52" rx="9"/>
  <rect class="box" x="176" y="58" width="132" height="52" rx="9"/>
  <rect class="box" x="338" y="58" width="132" height="52" rx="9"/>
  <rect class="box" x="500" y="58" width="126" height="52" rx="9"/>

  <text class="lbl" x="80"  y="80"  text-anchor="middle">Quarantined</text>
  <text class="sub" x="80"  y="97"  text-anchor="middle">must NOT unwind</text>
  <text class="lbl" x="242" y="80"  text-anchor="middle">Failed</text>
  <text class="sub" x="242" y="97"  text-anchor="middle">unwinds</text>
  <text class="lbl" x="404" y="80"  text-anchor="middle">Exhausted</text>
  <text class="sub" x="404" y="97"  text-anchor="middle">unwinds</text>
  <text class="lbl" x="563" y="80"  text-anchor="middle">Suspended</text>
  <text class="sub" x="563" y="97"  text-anchor="middle">still working</text>

  <path class="arrow" d="M146 84 H170" marker-end="url(#sh)"/>
  <path class="arrow" d="M308 84 H332" marker-end="url(#sh)"/>
  <path class="arrow" d="M470 84 H494" marker-end="url(#sh)"/>

  <text class="sub" x="14"  y="34">outranks →</text>
  <text class="danger-lbl" x="80" y="140" text-anchor="middle">an outcome nobody can account for</text>
  <text class="sub" x="242" y="140" text-anchor="middle">Cancelled ranks here</text>
  <text class="sub" x="563" y="130" text-anchor="middle">Replanning ranks here</text>
  <text class="sub" x="563" y="146" text-anchor="middle">a wait, not an ending</text>

  <defs>
    <marker id="sh" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L10 5 L0 10 z" fill="currentColor" class="arrow"/>
    </marker>
  </defs>
</svg>
<figcaption>Ready order decides only <em>within</em> a severity, which keeps the
outcome a property of the plan rather than of the schedule. Reporting a
suspension over a failure would defer the unwind until an event that may never
arrive.</figcaption>
</figure>

### A failed compensation is not compensated further

It is not a problem more compensation solves. Unwinding further would undo steps
*before* one now in an unknown state, which is strictly worse. The run is
quarantined, half-unwound, naming the step that could not be undone.

### Phases

Compensating effects run under `Phase::Compensating`, which is part of both the
effect key and the record body. Without it a step's compensation would restart
its ordinal at zero and collide with its own forward effects — replay would read
the forward result back as the compensation's, and the store's uniqueness
constraint would reject the second announcement. The phase is skipped in the wire
format when `Forward`, so ordinary records cost no extra bytes and hash
identically whether or not compensation exists in the build.

## Effect groups: the unit between an effect and a step

A per-step saga leaves a gap, and it is a sharp one. `Skill::compensate`
receives the step's **output** — and a step that failed has none. So a step that
reserved inventory, authorised a card and then failed hands its compensation the
absence of an output and asks it to guess what to undo. Both available guesses
are wrong: reverse something that never happened, or leave a charge standing
while unwinding everything around it.

The missing unit is smaller than a step and larger than an effect.

```rust
let mut g = cx.group("checkout", ["inventory", "payments", "notify"]).await?;

// Runs now. The reversal is built from the id this call actually returned.
let hold = g.reversible("inventory", Reserve::new(sku, 2), |out| {
    Release::new(out["hold"].as_str().unwrap_or_default())
}).await?;

// A read has nothing to take back, and is not asked to declare one.
let stock = g.read("inventory", Look::new(sku)).await?;

// Held at the gate. An aborted group never sends it at all.
g.deferred("notify", Notify::new("order confirmed"))?;

// The frontier.
g.commit(&[Invariant::new("the hold covers the order", covered)]).await?;
```

### A reversal is captured, not reconstructed

Each reversible member registers the concrete call that undoes it, built from
that member's **actual output at the moment it landed** — the hold id, the
authorisation reference. Nothing is reconstructed later from state that may have
moved since, and nothing is looked up in a name-to-constructor registry that can
disagree with the code.

That choice has a corollary worth stating: reversals dispatch through the
ordinary effect path. An undo is journaled, keyed, retried, policy-gated and
metered exactly like the forward call, and a replayed run reads it back rather
than performing it a second time. Nothing about being an undo makes it
privileged.

### The frontier is where reversibility ends

A group has two regions and one boundary.

**Before the frontier**, members are reversible and the group can still be
abandoned at no cost to the outside world.

**The frontier** is `commit`. It checks the invariants that must hold before
anything becomes permanent, and only then releases the deferred members.
Invariants are checked *there* rather than earlier for the reason that makes
them worth having: it is the last instant at which failing them is free. Naming
one — rather than writing `if !ok { return Err(..) }` — puts *which* condition
stopped the group on the record instead of in a message someone can reword.

**After the frontier** there is no group. A skill that continues with ordinary
`cx.effect` calls is past the point of no return, and a failure there does not
unwind: undoing a committed group would reverse a decision the outside world has
already acted on. That is the saga pivot rule, applied at the granularity where
the individual calls live.

### Deferral is stronger than compensation

A member that runs immediately and is undone on abort leaves a visible trace:
the reservation existed, the webhook fired, the email arrived and a correction
arrived after it. A member that does not run **at all** until the group is
certain leaves none.

So `deferred` is where an irreversible send belongs — the mail, the capture, the
published event. This is the one place where putting an effect *inside* a
transaction makes it safer rather than merely tidier, and it is why a group is
not just a saga with smaller steps.

### The footprint is enforced, not documented

A group declares the resources it touches and every member names the resource it
touches; a member naming anything else is refused **before it runs**. Without
that, "this group touches inventory and payments" is a comment, and a frontier
over an unknown set of resources is a frontier over nothing.

An effect that mutates cannot be declared a group `read`. A read is exempt from
registering a reversal because it has nothing to take back, and an effect that
took that exemption while leaving something standing is exactly the member the
unwind would miss.

**Nor can a mutation happen beside the group rather than inside it.** The
footprint bounds the ambient surface, not only members. A skill holding an open
group must not reach the world through the ordinary effect path — journaled,
gated and metered like anything else, and no member: no reversal registered, and
still standing after an unwind that settled `Aborted`, which claims the world was
taken back whole. A mutating effect dispatched while a group is open is
refused unless it is a member's own dispatch. Reads are untouched, because a
read leaves nothing to take back.

Nor can a member bind its own outbound arguments. Anything exposing
`sink_arguments` must go through `cx.sink`, which checks a labelled value the
group does not have on the member's behalf. A **deferred** member is refused
outright, because nothing has run and the group can still be taken back whole.
A **reversal** that turns out to be undispatchable is a *quarantine*: the
forward member has already landed and there is now no way to undo it, so
settling as aborted would put "discharged" in the journal while the hold still
stands.

### Three endings, because two would lie

| Outcome | What is standing |
|---|---|
| `Committed` | Every member. Deferred members ran; reversals were discarded. |
| `Aborted` | Nothing. Reversible members were reversed; deferred members never ran. |
| `Quarantined` | Unknown. A member is in doubt, or a reversal would not come back. |

Doubt is the one condition under which nothing may be reversed — undoing a call
that may or may not have landed is a coin flip with the outside world's money on
it — so a group in doubt is reported unsettled and the run is quarantined. A
reversal that fails stops the unwind for the same reason a failed compensation
does: continuing would undo members *around* one now in an unknown state.

A group is bracketed in the journal by `GroupOpened` and `GroupSettled`, and an
opened group with no settlement beside it is delivered through the run that
owns it: only a crash or a store failure can leave one, both of which put the
run in a backlog somebody already drains (failed, abandoned, quarantined), and
the resume that clears the backlog re-walks the members and settles. The state
no resume can repair — a **sealed** conclusion over an unsettled group — is an
`agentplane audit` finding, because nothing may resume a sealed run and
whether its members were taken or taken back is then permanently undecided.

### The model, and what it proves

The frontier is specified in TLA+ and model-checked, because "several calls take
together" is the kind of claim that reads as obviously true and has interleavings
nobody thinks of. The invariants worth naming are that a gated member runs only
past the frontier, that an aborted group has **nothing standing** — every member
reversed, no gated member run, no transaction committed — that a group nobody
settled does not commit, and that once an irreversible member is out the group
is never taken back.

Each is checked twice over: a mutant of the model must be caught by the invariant
written for it, and every invariant is mapped to a test that checks the same
property against the code. A model verifying a protocol the runtime does not
implement is a green job that says nothing, so that mapping is itself enforced.

One invariant had to be weakened before it verified, and the weakening is the
interesting part: "a gated member runs only for a **committed** group" is false,
because a member is legitimately released while the group is still open — commit
is what *follows* the last release. Stated over the frontier instead, it holds.
The model rejected the sentence a person would have written.

### The strongest class: committing *with* the journal

Everything above is the saga form, and it is the right answer when the members
live in systems that cannot share a transaction. It is **not** the best answer
when the resource lives in the same database as the journal.

```rust
g.atomic("ledger", Arc::new(PostEntry { account, amount }))?;
```

That member does not run when it is registered. It runs inside the transaction
`commit` opens, alongside the records saying it happened — and the difference
that buys is not a refinement:

- **nothing is externalised and later reversed**, so no reversal can fail;
- **the in-doubt window shrinks to one instant**: the connection dropping
  between `COMMIT` and its acknowledgement. A commit the server **refused** is
  a clean rollback and takes the cheap abort; a commit whose answer never
  arrived **quarantines the group**, because the writes may be standing and
  settling `Aborted` over them would claim *taken back whole* about work
  nobody took back;
- **an abort is a `ROLLBACK`**, which is free and cannot itself fail halfway.

Compensation that never has to run beats compensation that runs correctly. DBOS
makes the same observation for same-database steps, and it is the one place this
design can do better than a saga rather than merely do a saga carefully.

The seam is SQL, and only Postgres offers it. That is the premise, not a
limitation to apologise for: the resource is *already there* — a ledger table
beside the journal — so the seam speaks the language that table is written in. A
key-value seam every backend could implement would only reach a table this crate
defined, which is not the table anyone wants to be atomic with. A store that
cannot lend its transaction answers `None`, and the member is refused when it is
**registered** rather than at the frontier, because by then every eager member
has already run.

Two things it deliberately does not do. The transaction carries the members and
their records, **not** the group's settlement: a group is not finished when its
transaction is, since deferred members run afterwards and can still fail, and a
`Committed` record inside the transaction would be a claim about work not yet
attempted. And replay applies nothing — atomicity exempts no one from the effect
protocol, and a transaction re-run on replay is a second real write made
*reliable* rather than acceptable by being transactional.

One consequence is enforced rather than left to be inferred: **once the
transaction commits, the cheap abort is gone.** A deferred member that fails
after it quarantines the group even when it was the first deferred member to
fail — the abort path's premise is "nothing has externalised", and a committed
transaction is an externalisation with no reversal registered and none
possible. Settling `Aborted` there would put *taken back whole* in the journal
over a ledger row that stands, which is precisely the claim the quarantine
outcome exists to refuse. The TLA+ model's `AbortIsComplete` invariant carries
the same conjunct, and a mutant restoring the old behaviour is caught by it.

### What a group is not

It is not a distributed transaction, and nothing here pretends otherwise: there
is no two-phase commit across a payment provider and a warehouse, because those
systems do not offer one. Where one transaction is available the section above
takes it; everywhere else a group is the saga form made precise — captured
reversals, an explicit frontier, and deferral for what must not be externalised
early.

### Forgetting to settle is not a commit

A skill that fails with `?` never reaches `commit` or `abort`, and `Drop` cannot
run an async reversal. So the group lives on the step context rather than in the
handle, and the executor settles what the handle abandoned — the same
relationship it already has with a step's compensation. A step that *returns
successfully* with a group still open has its group reversed and fails loudly,
because a group that commits by being forgotten would make the most consequential
thing a group does the thing that happens when an author writes nothing.

A suspension is not an abandonment. The frame is persisted and the step re-runs
from the top, rebuilding the group from the journal as it replays the members, so
a group may legitimately span a durable wait.

## Stopping a run

Article 14 is not "a human can approve things". It is oversight, and the half
most runtimes omit is the ability to intervene and **stop**.

### Cooperative, at a step boundary

`Runtime::request_cancel` records the request durably and returns. The executor
observes it at the top of its next ready-set loop — never mid-effect, because
interrupting between "announced" and "recorded" manufactures exactly the
in-doubt case the effect protocol exists to avoid. A suspended run has no thread
to notice anything, so `request_cancel` resumes it itself; a run executing
elsewhere sees the request at its own next boundary.

### Four state lifetimes, not one “memory” switch

Agentplane keeps four concerns separate:

| Lifetime | Mechanism | Meaning |
|---|---|---|
| one run and its replays | journal | immutable effect history and replay input |
| conversation or business matter | case state and correlated events | resumable shared workflow state; not automatic chat-history injection |
| across runs | `MemoryStore` | erasable, versioned agent/team facts |
| one model call | assembled prompt/request | a context projection that may be trimmed without changing durable truth |

This distinction matters when provider APIs offer conversations or opaque
compaction. They may optimize a live request, but they are not replay truth.
Anything they return that affects a later request has to be represented in that
request's journaled identity. Summarising an active context does not silently
promote it into durable memory.

LangGraph and CoALA further name long-term content **semantic** (facts),
**episodic** (experiences/few-shot traces), and **procedural** (instructions).
Those are useful application schemas, not three storage engines. `MemoryStore`
stores versioned labelled JSON collections for semantic or episodic records;
procedural changes belong in a reviewed manifest version, not writable memory
that can silently rewrite the system prompt. A single mutable user “profile” is
also not a special primitive: use narrow versioned items unless the application
owns a typed profile/patch contract and its conflict policy.

Formation is currently **hot-path and synchronous**, making latency and failure
part of the run. Background formation can be built as an explicit scheduled
skill over journal/case inputs; it is not a hidden hook, because another run and
effect history must own that mutation.

An application chooses durable sharing with `subject`: use an agent-qualified
subject for private memory or a team-qualified subject for several agents in one
tenant. `purpose` partitions what may be recalled for a particular job. These
are query scopes, not ACLs. The policy engine sees `memory.recall` and
`memory.remember`, the acting agent, tenant, subject/purpose, and write security
metadata; deployments authorize private/team access there. Tenant-bound store
handles provide the hard cross-tenant boundary.

Runtime writes take a `MemoryWrite` destination and `Tainted<Value>` content.
Trust, provenance and sensitivity are derived from that value. They are not
caller-settable metadata: allowing a skill to mark model output trusted while
storing it would be an unjournaled release and a delayed privilege escalation.
Operator/import tooling may still write complete `MemoryItem`s directly through
the store trait; that path is outside a run and is deployment authority.

The built stores are redb for one node and PostgreSQL for several instances.
Both run the same memory conformance contract. PostgreSQL serializes concurrent
revisions of one id; each write atomically replaces the current version and its
derivation edges. An id cannot move between subject/purpose scopes or be reused
after erasure, because old journal selections and retained lineage must never
name unrelated future content. Derived writes validate that every named source
version and commitment exists and remain in the same subject, so subject erasure
cannot strand a summary elsewhere.

Core recall intentionally filters by subject/purpose and orders most trusted
first, then newest. It does not hide semantic/vector search inside
`MemoryStore`. Embeddings and indexes drift; `SemanticRetriever` is a separately
journaled effect recording query text/vector, embedding revision, immutable
index snapshot, filters, scores, a lifecycle cutoff and exact final
commitments. A derived index is stale by construction between rebuilds, so
live dispatch screens every hit against authoritative memory at the run's
journaled clock before the selection is recorded: a hit naming a superseded,
expired, or erased version leaves the selection, via `MemoryStore::current` —
the by-id twin of recall's lifecycle rule. Without the screen, a corrected
memory keeps being served by the ranked tier until reindex, an expired one is
served past its stated disposal date, and a lawful retention sweep fails every
query that ranks a swept item. The runtime then materializes the surviving
versions from authoritative memory and re-checks scope and digest — an index
that *contradicts* durable truth, rather than merely trailing it, stays a loud
refusal. The built-in implementation is deterministic exact cosine for tests
and small corpora; an external ANN database implements the seam and never
becomes memory truth.

**A vector says which space it lives in, and a caller never does.** Cosine
similarity is defined between any two vectors of equal width, so a query
embedded by one revision against an index built by another does not fail — it
ranks unrelated memories confidently, with no exception to catch. An index
therefore declares the `Embedder::revision` it takes *queries* in,
`RuntimeBuilder::semantic_memory` takes the embedder and the index together, and
`build` refuses a pairing that disagrees. The two strings differing is normal:
asymmetric embedders embed a query and a document deliberately differently, so
an index built from `…/search_document` asks for `…/search_query`. `cx.embed`
returns the floats and the revision that produced them; `cx.semantic_recall`
takes a subject, purpose, limit and ceiling and assembles the rest.

**A declarative agent reads memory as well as writing it.** `spec.memory.recall`
folds the selected items into the prompt under `/memory`, each carrying the
label it was written with; `spec.memory.formation` writes after the answer.
Semantic search stays out of the manifest deliberately: similarity is computed
over item content, so anything able to write a memory is a ranking signal, and
accepting that channel belongs where somebody visibly decides to.

Lifecycle is explicit and deterministic. A write may declare immutable
`expires_at`; fresh recall compares it with `StepCtx`'s journaled clock. Exact
versions remain available for replay until `sweep_expired` atomically erases all
versions and reserves the id. `StepCtx::sweep_expired_memories` wraps that
operation as an effect with a journaled cutoff/count; unknown crash recovery
requires an operator because repeating can delete idempotently but cannot
reproduce the first removed count. Legal hold blocks ordinary, subject,
cascading and expiry erasure atomically on both backends. Sliding retention is
opt-in: `refresh_access` adds a separate journaled, idempotent touch effect, so
ordinary reads remain pure and strict replay does not refresh twice.

### Memory is delayed code

A vector store bolted onto an agent looks like a cache and behaves like a
program. What is written today is read back tomorrow *into a context window*,
where a model treats it as established fact — so a single poisoned write becomes
a standing instruction that fires on every later session, and nothing at read
time looks wrong. Three rules follow, and none of them is about the storage
engine.

**Trust comes from provenance, never from content.** A recalled item is labelled
by where it came from. Content-inferred trust is gameable by construction: text
asserting its own reliability is the cheapest thing an attacker can write. So a
memory derived from a model, a peer or an inbound message stays untrusted however
many times it is re-read, and reaching a mutating sink with it takes the same
journaled release as any other untrusted value.

**Retrieval is an effect, not a lookup.** Memory is mutable state outside the
chain, so a search inside the deterministic zone would make a replayed run
retrieve whatever the store holds *now* — different items, different
conclusions, a history that disagrees with itself. The journal records the
**selection**: ids, versions and commitments to content plus immutable security
metadata. Replay re-materialises those exact versions instead of re-running the
ranking, so the result cannot drift as the corpus grows or acquire a different
trust label under identical bytes.

Two consequences fall out of recording the selection rather than the content.
Personal data stays in an erasable store rather than a hash chain that cannot be
redacted. And a version the store can no longer honour makes the history that
used it **unreplayable**, reported in two ways because they call for two
responses. *Gone* is a recorded erasure and **fails** the run. *There and
different* is the store contradicting the immutability its identifiers promise,
so it **quarantines** the run — an integrity finding belongs beside replay
divergence, not in the resumable bucket with a store that was briefly
unreachable.

**Content is versioned and supersedable, never edited in place.** A rewritten
memory cannot be audited and cannot be repaired: there is no way to ask what the
agent believed last Tuesday, and no way to undo one bad write without guessing
what it replaced. Writes append and mark the prior lifecycle record superseded;
forgetting is selective and reaches every version. The id remains tombstoned:
recycling it could make old history refer to unrelated new content.

### A summary is a memory, and it inherits what it summarised

`cx.compact` sends a set of memories to a model and stores the result as a new
memory. Every part of that sentence is a hazard, and the shape of the effect is
what answers each one.

**It is an egress, not housekeeping.** Compaction *shows the memories to a
model*. Without a bound, summarising would be the way to move confidential
content past a limit that stops every other path — and it would look like
tidying up. So `Compaction::max_sensitivity` is the ceiling the summarising
model may be shown; the effect is refused, and nothing is written, when an input
exceeds it. It defaults to `Public`, which refuses to summarise anything above
it.

**Its label is derived, never declared.** The summary's trust, sensitivity and
provenance are the join of the inputs: untrusted if any input was, at least as
sensitive as the most sensitive one, carrying every source. A caller supplies
only where the summary lands — id, subject, purpose, instruction — because the
rest are not matters of opinion. A summary that could declare itself trusted
would make compaction a laundry: read untrusted memories, write a trusted one,
and every gate downstream has nothing left to act on.

**It records what it was made from.** Each summary carries `derived_from` — the
ids, versions and digests actually read. That is what makes it repairable. A
poisoned memory does not stop being a problem when it is forgotten; without the
edge, it stops being *visible* while its content keeps arriving in every summary
that absorbed it, and the attack outlives its own remedy.

Forgetting therefore comes in two forms, and they are separate calls because
defaulting either way is wrong half the time. `forget` is what a **correction**
needs: a stale memory whose summaries remain legitimate should not take them
with it. `forget_cascading` is what an **erasure** needs: the memory and
everything transitively derived from it. A correction retains outgoing lineage,
so deciding later that the request was really an erasure can still reach every
summary. Cascading erasure is a required backend operation, not a default loop
over `derivatives` and `forget`: that loop had a gap in which another writer
could add a summary after traversal. redb uses one write transaction;
PostgreSQL excludes derivative creation for the complete traversal and deletion.

Formation is explicit despite being automatic: a digest-covered manifest field
or `StepCtx::form_memories` invokes a constrained extraction call and bounded
governed writes. There is no generic hook that persists arbitrary conversations.
`EncryptedMemoryStore` makes a tenant/subject wrapping scope the erasure unit,
so destroying it makes backup ciphertext unreadable. Its concrete lifecycle
coordinator is single-node; active-active deployments still need a distributed
database/KMS ceremony. Provider conversations and compaction remain projections,
never durable memory truth.

### Every case mutation is an effect

A case's status and its obligations are shared mutable state that outlives the
run: several runs and an operator all write them over months. Both changes go
through the effect protocol, and the two reasons are separate.

**A write outside the journal is performed again on every replay.** Replaying
last quarter's history to answer a question would close a case that has since
been reopened — a replay reads history, it does not rewrite the world that
history happened in.

**And it leaves nothing to attribute.** *Who closed this case, and when* is
exactly what the journal is for, and a status that changed without a record is a
change nobody can answer for.

The deadline transition also reads the state it moved *from* inside the effect
rather than before it. Reading first would put a store lookup in the
deterministic zone, and a replay would report whatever the deadline says now as
the state it moved from.

### A lease answers "is the owner dead?", and nothing else

Ownership is a lease with a TTL, and the epoch it carries is what fences a
displaced writer. The trap is that expiry answers a second question nobody
asked: **a healthy run that outlives its TTL looks exactly like a crashed one**.
Agent runs routinely outlive a lease, because a single model call can. Another
instance then acquires the run, bumps the epoch, and the original is fenced on
its next append — killed mid-flight, having already done real work, for being
slow.

So the runtime **renews while it executes**, on a task that is aborted the moment
execution returns by any path. The TTL then bounds how long a *crashed* owner
strands its runs, which is what it is for, and stops bounding how long a run may
take, which it should never have bounded. Strict verification renews nothing,
because it never writes and holds no lease.

Renewal runs at a third of the TTL, so two renewals can be lost to a slow store
before the lease lapses. Renewing *at* the TTL would make any hesitation fatal,
and a lapsed lease is one anybody may take — including, per `acquire`'s own
rule, the caller that let it lapse, which would fence a run with its own
heartbeat.

`RuntimeBuilder::lease_ttl` sets it, and **refuses anything under two seconds**.
Both stores keep expiry in whole seconds and lapse on `expires_at <= now`, so a
one-second lease is expired for part of every second it exists and no renewal
frequency saves it. A plane configured that way would have runs taken from it
under load and nowhere else — so it is refused at build rather than left to be
discovered.

### The request lives beside the chain, not in it

Every other write to a run requires the fencing lease, because two writers on one
chain is the corruption fencing prevents. A stop request is the opposite case:
whoever is asking is **not** the owner, holds no epoch, and is usually asking
because the owner is busy doing the thing they want stopped. Requiring the lease
would mean the only party who can stop a running agent is the process running it.

So the request goes to a side table — unfenced, idempotent, first-asker-wins —
and the *owner* journals `RunCancelled` when it acts on the request. That puts
"who asked, and why" inside the hash chain without letting an unfenced writer
append to it. A second asker is told `recorded: false` rather than silently
replacing the first, because an upsert would reassign the intervention to
whoever asked last and make "who stopped this run?" answer wrongly six weeks
later.

### A stop unwinds, including the step it interrupted

Compensation walks *completed* steps, which is right for a failure: the step that
failed ended on its own terms. A stop arrives from outside while a step is
typically **suspended** — waiting for a human, holding effects it already
performed, and never completing. Unwinding only completed steps would leave
exactly the work the operator was trying to stop.

So for a cancellation the list is extended from journal evidence: any step with a
recorded mutating effect that is neither complete nor already compensated. The
interrupted step goes last, so the reverse walk undoes it first.

### And it refuses to unwind around doubt

A run holding an effect that may or may not have landed is quarantined, not
unwound — compensating everything except the one thing nobody can account for is
how a saga refunds money nobody took. Cancellation opened a second door into the
unwind, and it is shut the same way.

That check is scoped to cancellation deliberately. An ordinary failure that
leaves an orphan is not stuck: the announcement is journaled, the effect declared
a `Recovery`, and resuming resolves it. Quarantining there would turn every
recoverable orphan into a permanent operator obligation.

### What building it found

The replay cursor was keyed by *step*, and a step's forward pass and its
compensation share a step id — so they shared a cursor. That was harmless for as
long as compensation could only run after the forward pass had consumed its own
history, which was true of every path that existed. Cancelling a suspended run
reaches compensation *without* re-running the forward pass, and the compensating
effect then read the forward record and reported non-determinism against history
that was perfectly sound.

The cursor is keyed by `(step, phase)` — which is what the effect key has
always said the identity is. A latent bug that only a new entry point could
reach.
