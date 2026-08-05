+++
title = "Architecture"
description = "How the journal, effect protocol, replay, sagas and the Merkle log actually work — mechanism by mechanism."
weight = 4
+++

How the runtime works, and why each piece is shaped the way it is.

## The determinism boundary

Everything else depends on this holding.

```
┌─────────────────────── DETERMINISTIC ZONE ────────────────────────┐
│  plan traversal · guards · retry decisions · budget arithmetic     │
│  policy evaluation · label joins · record upcasting                │
│                                                                    │
│  Replay re-executes this zone and MUST reproduce the identical     │
│  sequence of effect keys. Divergence is a fault, not a retry.      │
└────────────────────────────────┬───────────────────────────────────┘
                                 │  cx.effect(…)
┌────────────────────────────────▼───────────────────────────────────┐
│                     NON-DETERMINISTIC ZONE                         │
│  inference · tool calls · wall clock · network · human input       │
│                                                                    │
│  Executed at most once. Result journaled. Replay reads the journal │
│  and never re-invokes.                                             │
└────────────────────────────────────────────────────────────────────┘
```

Three layers enforce it, because convention is not enforcement:

1. **Capability absence.** Sandboxed skills (planned) get a WASI world with no
   clock, RNG, socket, or filesystem. Non-determinism is unreachable rather than
   discouraged.
2. **Lint gating.** `clippy.toml` denies `SystemTime::now`, `Instant::now`,
   `rand::random`, `Ulid::new`. The two legitimate call sites in the crate carry
   an explicit `#[allow]` and a comment naming the record that captures the
   value.
3. **Effect-key verification.** On replay the key is recomputed from the
   deterministic zone. A mismatch quarantines the run.

Two things sit *inside* the deterministic zone that are easy to get wrong:
**record upcasting** and **correlation matching**. Both are pure by
construction, and both would break replay if they weren't. An upcaster that
reads a config file is the same bug class as a non-deterministic effect, but far
harder to find — it only manifests on old records.

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
  <text class="sub" x="557" y="99"  text-anchor="middle">EffectEnded</text>

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
does not unwind either — it is healthy and waiting.

Failures that *do* unwind: `Failed`, and `Exhausted`.

### Compensation is exempt from the budget

Refusing to undo because the ceiling was reached is how a run ends with a charged
card and no order. The ceiling exists to bound work, not to strand it half-done.
Compensating effects are still billed and journaled, so the overshoot is visible
rather than silent.

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
unwind reverses. The first version of concurrent dispatch returned on the first
non-success in ready order, which discarded later siblings' completions — their
effects had been performed and would never be undone.

**Severity beats ready order.** A suspension is the run working; a failure is the
run over. If one sibling suspends on an approval and another fails after
mutating, reporting the suspension would defer the unwind until an event that may
never arrive. So `Quarantined` > `Failed` > `Exhausted` > `Suspended`, and ready
order decides only within a severity — keeping the choice a property of the plan
rather than of the schedule.

`Quarantined` sits highest because it is the only one that must *not* unwind.

<figure class="diagram">
<svg viewBox="0 0 640 190" role="img" aria-labelledby="st-t st-d" xmlns="http://www.w3.org/2000/svg">
  <title id="st-t">Terminal run statuses, ordered by severity</title>
  <desc id="st-d">When concurrently dispatched siblings disagree about how a run
    ended, severity decides, not the order they happened to be scheduled in.
    Quarantined outranks Failed, which outranks Exhausted, which outranks
    Suspended. Only Quarantined refuses to unwind.</desc>

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
  <text class="sub" x="563" y="140" text-anchor="middle">a wait, not an ending</text>

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

Nor can a member bind its own outbound arguments. Anything exposing
`sink_arguments` must go through `cx.sink`, which checks a labelled value the
group does not have on the member's behalf. A **deferred** member is refused
outright, because nothing has run and the group can still be taken back whole.
A **reversal** that turns out to be undispatchable is a *quarantine*: the
forward member has already landed and there is now no way to undo it, so
settling as aborted would put "discharged" in the journal while the hold still
stands.

### Four endings, because two would lie

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

A group is bracketed in the journal by `GroupOpened` and `GroupSettled`, so an
opened group with no settlement beside it is a query rather than a grep — the
work that was neither taken nor taken back.

### The model, and what it proves

The frontier is specified in TLA+ and model-checked, because "several calls take
together" is the kind of claim that reads as obviously true and has interleavings
nobody thinks of. The invariants worth naming are that a gated member runs only
past the frontier, that an aborted group has **nothing standing** — every member
reversed, no gated member run — that a group nobody settled does not commit, and
that once an irreversible member is out the group is never taken back.

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
- **there is no in-doubt state.** A transaction committed or it did not. The
  undecidable window the whole effect protocol exists to survive is not handled
  here, it is *absent*;
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

## The journal

Append-only, hash-chained, one row per record:

```
seq | kind              | effect_key | prev_hash | hash
────┼───────────────────┼────────────┼───────────┼──────
  1 | RunAdmitted       | –          | 0000…     | 9c2…
  2 | PlanFrozen        | –          | 9c2…      | 41b…
  3 | StepStarted       | –          | 41b…      | e07…
  4 | EffectStarted     | ek:3f9…    | e07…      | 55a…
  5 | EffectDone        | ek:3f9…    | 55a…      | d13…
  6 | Released          | –          | d13…      | 7f2…
  7 | StepFinished      | –          | 7f2…      | 8b6…
```

`hash = H(prev_hash ‖ record_bytes)`.

A run that reaches a conclusion appends a `RunSealed` record *before* the chain
closes over it, so how a run ended is covered by tamper detection and a resumed
run reads its own outcome from the history it just verified. Sealing used to
write only to a side table, which meant "is this run finished?" had to be
inferred from the last step that happened to finish — see below.

### What the chain proves, and what the signature adds

The chain is **per run**: `prev_hash` links to that run's own head, and genesis
is zero for every run. On its own it delivers exactly one thing:

> No record was edited, reordered, or removed **within** a run, by anyone who
> cannot recompute every subsequent hash.

That last clause is the problem. Anyone who can run SHA-256 can rebuild a
consistent chain, and the party holding the store can always run SHA-256 — which
is the party an auditor is being asked to trust.

So every record also carries an optional **`Attestation`**: a key id and a
signature over the record's chain hash. A hash says *what* the history is; a
signature says *who wrote it*.

* **One signature per record is enough.** The hash already chains, so signing
  record *n*'s hash transitively commits to every record before it. Rewriting any
  part of the prefix invalidates every *later* signature, not only its own.
* **It sits beside the hash, not in the body.** Forced, not stylistic: inside the
  body, the hash would cover the signature that covers the hash.
* **Verification is lenient by default, strict on demand.** A plane resuming its
  own history has no basis to reject an unsigned record — and a runtime that
  refused would make signing impossible to adopt incrementally. An auditor has
  every basis, and `require_signature` is the difference between "resume my
  history" and "prove this to me".
* **A plane with no signer writes unsigned records, not self-signed ones.** A
  self-minted key produces records that look attested and prove nothing, because
  the party being audited chose the key.
* **The attestation carries no algorithm field.** A self-described algorithm is
  how a verifier gets talked into checking a signature with something weaker than
  the one that made it. The verifier decides what it accepts.

The crate ships the seam (`Signer`, `Verifier`) and an Ed25519 implementation
behind the `signing` feature. A deployment with workload identity — SPIFFE SVIDs,
which is what the delegation model already assumes — plugs its own signer in, and
then the key id on each record names the *workload* rather than merely a key.

### Binding runs to each other

Signing binds authorship. It does not bind **existence** — and the per-run chain
stops at the run boundary, so deleting an entire run leaves every remaining run
verifying perfectly. The deleted run's signatures leave with it, so those do not
help either. What is left pointing at it is a case row: ordinary mutable data
that goes in the same delete.

So sealed runs enter a **per-plane Merkle log** (RFC 6962 shape), and the store
answers two questions:

* `checkpoint()` — origin, size, and root over every sealed run, in the C2SP
  `tlog-checkpoint` shape so existing verifiers work.
* `inclusion_proof(run)` — that one run's position and the sibling hashes that
  prove it.
* `consistency_proof(old_size)` — that the log has only *grown* since an earlier
  checkpoint.

Delete a run and the root moves; the deleted run can no longer prove inclusion.

**The third of those is what makes the other two mean anything.** The root moves
on every ordinary seal, so an auditor comparing two roots and seeing a difference
has learnt nothing — legitimate growth and deletion-plus-growth look identical. A
consistency proof shows every leaf committed to before is still committed to, in
the same position. Without it the log detects *a* change and cannot say what
kind.

Three details are decisions rather than implementation:

* **Leaf and interior hashes are domain-separated by a prefix byte.** Without
  it a leaf can be made to collide with an interior node, and an attacker who
  controls leaf content presents a subtree as a leaf.
* **The log position always advances; it is never a count of what survives.** A
  count reuses a deleted run's index, so a removed run can be silently replaced
  at the same position — and even the log size looks unchanged. redb keeps a
  monotonic counter, Postgres a sequence; both hand out a position that has
  never been issued before.
* **The proof does not authenticate its own parameters.** An inclusion proof is
  checked against `(leaf, index, size, root)`, all supplied by whoever offers it;
  the size and root come from a *signed checkpoint*. Expecting the fold to
  validate the size is asking the wrong component, and RFC 6962 has this shape
  for the same reason.

### The audit an outsider runs

Every mechanism above is only *checkable*. Somebody has to check it, and if the
only code that can is inside the runtime being audited, the party under
examination is also the party running the examination. So `audit::audit` runs
against a store it did not write, taking inputs the auditor holds:

| Given | Answers |
|---|---|
| nothing | Is each run's chain internally consistent? |
| a public key | Who wrote each record? |
| a **prior checkpoint** | Has anything been *removed* since it was issued? |

Only the third detects deletion, and only because the checkpoint came from
outside. The test that makes this concrete audits a store somebody deleted a run
from **twice**: with no prior checkpoint it comes back clean — honestly, because
there is nothing to compare against — and with one it fails.

That asymmetry is why `AuditReport` carries `not_checked` as prominently as
`findings`, and why `assert_complete` fails on a skipped check as well as a
failed one. `Checkpoint` also has a text form in the C2SP note encoding, because
the one artifact that must leave the operator's control cannot exist only as a
Rust struct.

#### What is still open

* **Publishing.** A checkpoint that never leaves the operator's store is only as
  trustworthy as the operator. It becomes evidence when compared against one they
  handed over earlier — which means witnesses, and those are not built.
* **Split views** — one history to one auditor, a different one to another — are
  refused by a witness that remembers, because the second history cannot prove
  it extends the first. The check exists; what does not is a witness run by
  somebody other than the operator. Hosting your own proves nothing about you,
  so treat this as ready-to-connect rather than closed.
Both backends maintain the log, and both keep their gaps. redb advances a
counter row inside the sealing transaction; Postgres uses a **sequence**, because
several instances seal concurrently there — that is the topology it exists for —
and a position derived from the current maximum by two transactions at once hands
both the same slot.

Positions therefore have holes once a run is removed, deliberately: a freed slot
must never be reissued. The *tree* is built by walking the log in key order,
which yields dense positions with no holes — so the position a proof uses is the
run's rank in that walk, not its stored index. Handing back the stored index
makes every run after a deleted one fail to prove an inclusion that is perfectly
valid.

### Hash the bytes you wrote

Records are hashed over their exact wire bytes, and those bytes are what the
store keeps. Verification never re-serializes.

This matters when schemas evolve. If the chain were computed over the *upcast*
form, then the first time a record shape changed, every historical hash would
change with it — silently destroying tamper evidence for all past records, which
is the one property the chain exists to provide. Upcasting is a read-time view;
the chain is over history as written.

### Schema evolution

The journal is forever, so record shapes must evolve without rewriting history.

1. Records carry `(kind, v)`.
2. **Backward compatibility is permanent.** New code must read every shape ever
   written. There is no "we migrated past that".
3. Upcast on read; never rewrite.
4. **Upcasters are pure and total.** Same input, same output, in this process
   and in one started a year from now.
5. Hash the wire bytes (above).

A golden corpus of historical fixtures belongs in CI: a schema change that
cannot read it should fail the build.

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

**Completion is structural**: every terminal node must have run. A workload
asserting it finished is not evidence.

### Topology

| Topology | Inter-agent failure surface | Cost |
|---|---|---|
| `Single` | None — structurally absent | 1× |
| `Routed` | None — still one agent per task | 1× |
| `Collaborative(reason)` | Full | ~15× tokens |

Routing is not collaboration. Picking one specialist out of thirty by event type
is a dispatch table, and conflating it with multi-agent work makes people pay
for risk they never took on.

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
does not name its predecessor is rejected: an audit trail with a hole where the
lineage should be is not an audit trail.

**Refused once untrusted data is in working memory.** This is the sharp one. The
frozen plan is an authorization graph compiled from trusted input only. A replan
*changes that graph*, so if untrusted data has already been read, anything
shaping the new plan may be attacker-chosen — and choosing the authorization
graph is the whole game. The refusal names the source, because "replanning
refused" without saying what made it unsafe sends an operator through the whole
run. A run that wants a different plan after reading untrusted input is
describing exactly the attack.

**Bounded.** `Budget::replans` caps it. A run that replans without bound has
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

**Closing is guarded.** A case with an unmet obligation refuses to close. That
is the check that stops a missed regulatory window from vanishing behind a tidy
status. Closing releases the correlation keys, so a genuinely new matter about
the same entity opens a fresh case rather than reanimating a concluded one.

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
completing.

Delivery is deduplicated by event id, so a counterparty that retries — and they
all retry — does not deliver twice. Claiming happens inside the transaction that
selects, so two runs waiting on one key cannot both consume a single message.

## Durable timers

A wait whose event is the clock.

```rust
cx.sleep(Duration::from_hours(24)).await?;      // or sleep_until(instant)
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
| Waiting for the world — a rate-limit window, a settlement date, five Werktage | `cx.sleep()` — suspends, costs a row |

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

A run that exhausted its budget replays as exhausted **even under a larger
limit**, because the stopping point is recorded rather than recomputed.

### What can be limited

| Limit | Exact? |
|---|---|
| `max_steps` | Yes — counted in advance |
| `max_effects` | Yes — counted in advance |
| `max_tokens` | No — see below |
| `max_minor_units` | No — see below |
| `max_wallclock_secs` | Opt-in; costs one journaled clock read per step |

### A metered budget overshoots by one operation

An operation's cost is not known until it has run, so a token or money limit
cannot be a hard ceiling. What is enforced is: *once consumption has reached the
limit, nothing further starts.* A run therefore overshoots by at most one
operation's cost.

This is stated rather than hidden, because the alternative — implying a hard cap
— is how somebody sizes a limit at exactly their ceiling and is surprised. Where
a true ceiling matters, set `max_effects` as well.

Money is tracked in **integer minor units**. Money that rounds differently on
two machines is money that produces two different budget verdicts.

### Exhaustion is not failure

`RunStatus::Exhausted` is distinct from `Failed`. The run did what it was told,
and what it was told included a ceiling. Conflating the two has operators
debugging a system that behaved exactly as instructed.

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

## Replay modes

| Mode | Effects | Writes | Use |
|---|---|---|---|
| `Live` | performed | yes | Normal execution |
| `Resume` | replayed, then live past the end of history | yes | Crash recovery |
| `Strict` | replayed; running past the end is an error | no | Determinism verification |

**`Resume` is for crashes, not for code changes.** It requires the journal to be
a *prefix* of what the current code does. A journal written by a different
program is divergence, and the run is quarantined rather than continued.

The same hard boundary applies to authorization. Admission records a structured
policy-bundle identity covering rules, schema, static entities, adapter
configuration/extensions, and evaluator semantics. An open run may resume only
under that exact bundle because resume can dispatch past the recorded prefix.
Dynamic request facts are not bundle inputs; they stay in each policy request.
An effect's request carries the run, step, tenant, whether it mutates, the
arguments — and, when the call came through `sink`, the **label** of the value it
will send. That last one is what lets a rule key on *where the data came from*
rather than only on what it is; without it, provenance and authorization would be
two graphs that meet only in the checks this crate happens to have written.
`Strict` performs nothing and therefore neither loads nor compares policy, which
keeps offline verification independent of historical evaluator availability.

**A succeeded or quarantined run is closed to resume.** Succeeded means nothing
is outstanding, and re-executing would repeat work that is not an effect — a
case-state write, say — which is the same class of bug the effect protocol
prevents, arriving through a side door: the replay cursor is exhausted from the
first instruction, so every step looks live. Quarantined means a human has to
look first; resuming would re-hit whatever could not be decided, and burying that
in a retry loop is how an undecidable situation becomes an unnoticed one. A
*failed* run is deliberately still resumable — that is what crash recovery is.

That is the desired outcome, not a limitation. Continuing would graft new
behaviour onto a history that never produced it, and the resulting audit trail
would be a plausible lie.

A subtlety worth internalising: "run a shorter version of the program" is *not*
a crash simulation. If the shorter version ends with an effect the longer one
has elsewhere (a trailing timestamp, say), that effect lands at a different
ordinal and the journal stops being a prefix. A real crash truncates; it does
not rewrite.

## Module layout

One crate, feature-gated. Crate boundaries are a public API you cannot design
before the code exists, and a `core` crate would be a dependency hub that makes
compile times *worse*, not better.

```
src/
  core/      types, traits, labels, calendar, case model, errors
             — NO I/O (enforced by tests/guards/layering.rs)
  journal/   records, hash chain, replay cursor, upcasters, the Merkle log
             and the witness seam
  case/      CaseStore, EventStore, TaskStore contracts
  plan/      the plan contract: what a plan must satisfy to run at all
  policy/    authorization-engine adapters; the seam itself is core::policy
  memory/    what an agent remembers between runs: versioned items, journaled
             retrieval, and labels taken from provenance rather than content
  netguard/  which IP addresses this plane will connect to — one rule, shared
             by governed media and webhook delivery
  push/      A2A push notifications: webhook registrations and guarded delivery
             (feature `push`)
  quota/     per-tenant ceilings on concurrent work and spend, accounted in
             the store so they survive a second instance
  store/     redb and Postgres backends, journal and cases alike
  blob/      content-addressed bytes kept out of the chain, and the erasure
             that retention needs
  keyring/   envelope encryption for those bytes, and the cryptographic
             erasure that reaches copies deletion cannot (feature `keyring`)
  media/     governed URL dereferencing, DNS pinning, bounded validation and
             digest-only model materialization (feature `media`, off by default)
  runtime/   StepCtx, effect protocol, effect groups, executor, sweeper,
             built-in effects
  batch/     batch runs: item source, outcomes, the BatchStore contract
  tools/     calling tools on other people's servers, and the annotation
             trust decision that implies
  peers/     calling other agents: identity, audience, narrowing authority
  audit      the outsider's verification pass over a journal
  manifest/  the declaration an agent is built from, and the registry it is
             pinned in (feature `manifest`, off by default)
  api/       the HTTP surface for operators (feature `http`, off by default)
  model/     the ModelProvider seam, the metering rules, and two streaming
             drivers (feature `providers`, off by default)
  testkit/   fault injection, a fake model provider, and shared assertions
             (feature `testkit`, off by default) — for this crate's assurance
             layers and for embedders testing their own stores and skills
```

The one discipline to keep: `core/` has zero I/O dependencies. Keep it and an
eventual crate split is mechanical; lose it and no crate layout recovers it.

## Canonical bytes

Every hash — record hashes, effect keys, plan digests — is taken over canonical
bytes, and `core::canon` produces that form itself: object keys are sorted at
serialization time.

It did not always. It relied on `serde_json::Map` being a `BTreeMap`, with a
comment in `Cargo.toml` saying `preserve_order` must never be enabled. That is
unenforceable. Cargo unifies features across the entire dependency graph, so the
flag is not this crate's to refuse — adding `cedar-policy`, which enables it,
turned it on for everyone.

The effect was measured, not theorised. Before the fix, with `cedar` enabled, the
same object built as `{"b":1,"a":2}` and as `{"a":2,"b":1}` produced **different
effect keys**. Two runs performing the same call would fail to recognise each
other's work; exactly-once would stop holding, silently, in the direction that
issues a second payment.

Sorting explicitly costs nothing and removes the dependency on a flag a stranger
controls. Output is byte-identical whether `preserve_order` is on or off —
checked by deriving effect keys under both builds and diffing.

Two consequences worth keeping:

* **`tests/guards/layering.rs` no longer looks for `indexmap` in the lockfile.** That
  question stopped being answerable the moment a legitimate dependency wanted the
  feature. It now checks what would actually undo the fix: no code outside
  `canon` may call `serde_json::to_vec`, because with `preserve_order` on such a
  call takes insertion order into a hash.
* **CI runs the suite under default features *and* `--all-features`.** They are
  not redundant: `--all-features` enables `cedar` and therefore `preserve_order`,
  so the two builds exercise genuinely different canonicalization paths.

## Calling a model

A completion is an effect like any other — journaled once, replayed from the
record, untrusted on the way back. The prompt is part of the effect key, so an
edited template shows up on replay as divergence rather than as a run that
quietly did something else.

What is different is the meter.

### A failed call is not a free call

Every other outward call this crate makes either happens or does not. A model
call has a third state: it ran, generated four hundred tokens, and the stream
died. The provider bills those tokens. The answer is unusable.

The runtime used to charge `Spend::default()` on every failure. The comment said
"a failed call still occupied a call", which is true and counts against
`max_effects` — but the *token and cost* ceilings, the ones that exist to bound
runaway spend, counted zero. A retry loop against a flaky provider would burn real
money against a limit reading nothing.

So `EffectError::Metered` carries what was consumed, the ledger charges it on the
failure path, and `EffectFailed` records it — because without the record a
replayed run reaches a different budget verdict than the one that actually
happened.

### A died-mid-stream call is `Landed`

The usual reasoning about reaching the peer is inverted here. We know it reached
the provider: we watched it generate. What is missing is the *answer*, and
repeating the call buys a second bill for the same question. `InDoubt` would
invite `Recovery` to resolve an outcome that is not uncertain at all.

A refusal *before* generation — bad request, unknown model, rate limit — is
`DidNotHappen` and costs nothing. Rate limiting is the one case in this crate
where retrying is unambiguously safe.

### A note on the test that nearly wasn't

The budget test originally used a fixture that made exactly one call, because an
interrupted stream is `Landed` and therefore never retried. It passed with the
billing reverted. The fixture now does what a real skill would — swallow the
failure and ask again with a reworded prompt — so the second call is refused by
the ceiling the first call's tokens consumed.

## Calling other agents

A peer hop is a tool call with two extra problems, and both are identity rather
than transport.

### Token confusion

To call a peer you hand it a credential. If that credential is not bound to *that
peer*, the peer can replay it elsewhere — and it need not be malicious to do so,
only compromised or confused. A bearer token sent to peer B and accepted by peer
A is the whole vulnerability class, and it is why OAuth grew Resource Indicators
(RFC 8707).

This runtime cannot make peer A check the audience. What it can do, and what
`PeerRegistry::credential_for` enforces, is never hand a peer a credential minted
for someone else. The check lives on the accessor rather than at the call site,
so no code path can reach a credential without passing it.

`PeerCredential` also refuses to render its own secret: this crate writes logs,
span attributes and error messages, and a secret with a `Debug` impl ends up in
all three. The audience stays visible, because that is the part worth debugging.

### Obtaining the credential

`PeerCredential` models a token already bound to one audience. Getting one is
OAuth token exchange (RFC 8693) naming a `resource` (RFC 8707), behind the
`TokenExchange` seam.

Three decisions there are worth stating.

**A credential must never enter the journal.** The journal is append-only,
hash-chained, permanent and read by auditors — a bearer token in an `EffectDone`
record cannot be redacted later, because the record's hash covers it and the
chain would break. It can only be discovered. So acquisition is deliberately not
a journaled effect; it is transport metadata in the same sense a run's lease is.
Replaying a recorded token would be useless anyway, since it has expired.

Three things enforce that rather than describing it: the type has no
`Serialize`, so it cannot be written by accident; its `Debug` redacts, so it
cannot reach a log line or span attribute; and `tests/trust/peers.rs` runs a real peer
call and scans every record's bytes for the secret. `tests/guards/layering.rs` holds the
first two in place, because deriving `Serialize` on a credential is a one-word
change no compiler would object to.

**Freshness is measured against a margin, not the expiry.** A token with two
seconds left will lapse in flight, and the peer's rejection arrives as a failure
of *unknown* disposition — when it was really a refresh nobody scheduled.
`Cached` refreshes at `expiry - skew`.

**The issuer is not taken at its word.** An issuer that ignores `resource` hands
back a token the peer can spend elsewhere, which defeats the binding entirely, so
the returned audience is re-checked locally.

Expiry is checked against a supplied `now` rather than a clock read, which keeps
it testable at arbitrary instants and adds no escape to the determinism gate.

### Authority narrows at the boundary

A peer acts on our behalf, so it receives the caller's chain plus one link.
`Delegation::delegate` already refuses to widen and caps depth, so a hop cannot
lend a peer more than the caller holds, and a request cannot wander arbitrarily
far from the human who authorised it.

A grant wider than the caller's own authority is **refused, not clipped**.
Clipping would silently absorb a misconfiguration; an operator who granted a peer
`billing.*` from an agent holding only `audit.*` has made a mistake worth seeing.

The grant comes from the operator's registry, never from the peer's agent card —
for exactly the reason MCP annotations are not taken from a server. A party
describing its own privileges is not a source of truth about them.

### And the rest is the usual discipline

Fail closed on an unregistered peer. Responses untrusted — a peer feels like ours
because it is our agent, but it runs elsewhere, under someone else's control, and
may itself have read the internet. And a disposition on every failure that says
whether the request reached the far side.

## Calling peers and models over the wire

Two drivers ship, both off by default and both thin. What each carries is a
**failure mapping**, and that is the entire design content — the JSON is
commodity, the mapping decides whether a request may be sent again and whether
the budget is telling the truth.

### A2A, calling out (`a2a`)

The built surface is deliberately exact: an A2A 1.0 JSON-RPC `SendMessage`
client to an operator-pinned endpoint. It sends `A2A-Version: 1.0`, declares its
extension in `A2A-Extensions`, uses ProtoJSON enum/part forms, and validates that
the response contains exactly one `task` or `message`. Agent Card discovery and
verification, interface selection, and polling are not built.

A2A tasks are long-running and stateful, so "did the peer act?" is not a detail.

| Failure | Known | Disposition |
|---|---|---|
| DNS, TLS, connection refused | nothing was written | `DidNotHappen` |
| timeout, or the connection died after the write | it may have arrived | `InDoubt` |
| HTTP 401/403/404; JSON-RPC parse/method/params; A2A failed-precondition/input errors | read and declined | `DidNotHappen` |
| HTTP 5xx; JSON-RPC `-32603`; A2A `-32006`; malformed success envelope | arrived; whether it acted is unknown | `InDoubt` |
| a `Task` in state `TASK_STATE_FAILED`, `TASK_STATE_CANCELED`, or `TASK_STATE_REJECTED` | a task exists and may have acted | `Landed` |

The two expensive rows are the last two. `-32603` can be raised *after* a peer
has started work. A2A 1.0's `-32006` is `InvalidAgentResponseError`, mapped to
`INTERNAL`/HTTP 500 — not a clean decline. Treating either as proof that nothing
happened is how a half-finished transfer gets sent twice. Symmetrically, a task
in a terminal unsuccessful state is not in doubt: the peer created a task and
reported its outcome, so `Recovery` has nothing left to discover.

The delegation chain and provenance travel under a declared extension URI rather
than being smuggled into a free-form field, so a peer that does not understand it
still receives a well-formed message. The delegation chain remains a claim. The
provenance block is separately attested and bound to the call, so a peer with the
workload verifier can check who made that exact request; neither substitutes for
the peer's own authorization decision.

#### Reading somebody else's card

`CardClient` fetches a card from the well-known path, optionally verifies it, and
selects an interface. Four rules, each of which exists because the obvious
version is wrong.

**Fetching is an egress decision.** A card URL usually arrives from a config, a
registry entry or a message — the first attacker-influenced string a deployment
handles — and "just fetch it" is how a plane is made to probe its own network.
The host is checked against the allowlist before the request is built, so a
refused host is never even resolved.

**Verification is opt-in, and once on it is mandatory.** Most cards in the wild
are unsigned, so a client that refused them all would not be used. But a client
that verifies *only when a signature is present* is one an attacker downgrades by
stripping it — so with a verifier configured, an unsigned card is refused.

**Selection matches binding and version.** An agent may publish the same binding
at several protocol versions; matching the binding alone picks an endpoint
speaking a protocol this client does not, and the failure then surfaces as a
confusing wire error rather than "we do not speak that". Card order is the
publisher's preference and is respected within the versions we can speak.

**The tenant travels with the endpoint.** A2A says to echo the selected
interface's `tenant` on every request and to omit it when the interface omits it.
A client that skips this can only ever reach an agent serving the default
tenant — which is why `Endpoint` carries it rather than leaving it to each call
site.

None of this produces authority. A card describes *reachability*; what a peer may
be sent comes from the operator's `PeerRegistry`. That split is what makes a
forged card survivable — the worst it can do is waste a request.

### A2A, being called (`a2a-server`)

The other half, and a different problem: everything arriving here was written by
somebody else.

It is a **separate router**, not routes on the operator API. That surface's
invariant is that every route authenticates, and an Agent Card is public by
definition — it is what a caller reads *before* it has credentials. Adding one
unauthenticated path to a surface built on "every route authenticates" deletes
the invariant for the one route nobody would think to check.

| Method | Behaviour |
|---|---|
| `SendMessage` | admits a run and returns the `Task`; honours `returnImmediately` |
| `GetTask` | the run's state, read from its **last** record |
| `CancelTask` | a durable stop request; the task stays `WORKING` |
| `GetExtendedAgentCard` | the authenticated card |
| `SendStreamingMessage`, `SubscribeToTask` | SSE, read from the journal |
| `ListTasks` | `-32004`, unsupported |
| the push-notification configs | registrations, behind `push` |
| anything else | `-32601`, method not found |

**Blocking is the default, and unset means blocking** — the spec's rule.
`configuration.returnImmediately` switches to returning as soon as the task
exists, leaving the caller to poll `GetTask`. Admission still happens before
either returns: the policy gate, the lease and the admission records are written
first, so the id handed back is one `GetTask` can already answer for. Spawning
first and admitting later would hand out ids for runs the gate went on to
refuse, turning a decline into a task that never appears.

Four further decisions are load-bearing.

**The 1.0 method names only.** 1.0 renamed every method; `message/send` was 0.3.
A server that answers both accepts clients which have silently lost half the
protocol, and they never find out, because the call works.

**A missing `A2A-Version` is a refusal.** The spec reads an empty value as 0.3,
so an absent header is a 0.3 client — and answering it with 1.0 semantics hands
it a response shape it will mis-parse field by field.

**The capability is named, never inferred.** A2A has no "call this skill" field;
the protocol assumes the agent works out what is being asked. This plane will
not. The skill comes from `message.metadata.skill`, matched against the card's
advertised ids; with exactly one skill there is nothing to infer, and with
several and none named the call is refused. Choosing what to run by reading
untrusted prose would let the sender pick the capability.

**A peer's message is untrusted.** It is admitted as `Tainted` with provenance
`peer:<caller>` — never as trusted input — so a protected sink field can name
the one counterparty it will accept an amount from. Admitting it as trusted
would let a value that arrived over the network wear the runtime's own
authority.

Refusals carry the spec's codes rather than a generic error, because a caller
has to tell *this agent cannot do that* from *you spelled it wrong*: one is
worth reporting, the other worth retrying differently. For the same reason a
policy denial comes back as a `Message` decline rather than `-32603` — an
internal error reads as a transient fault, and the caller retries a decision
that will never change. The decline says only that it was declined: the
runtime's own denial names the action and resource the gate keyed on, which is
enough to map this plane's authorization vocabulary by probing it.

Push notifications stay advertised `false` on the card, because a card is a
promise a caller plans against and an unimplemented transport does not degrade
gracefully — it produces a caller waiting for events nobody will send. Streaming
is advertised `true`, because it exists.

#### A signed card says who published it

A card is fetched unauthenticated from a host a caller may not control. TLS says
the bytes came from that host; it says nothing about whether the host is the
party whose capabilities the card describes — and it says nothing at all once
the card has been copied into a registry, a cache, or a repository.
`A2aServer::signing_cards_with` attaches a detached JWS (RFC 7515) over the card
canonicalized per RFC 8785.

Four decisions carry it.

**It is a real JWS.** Everywhere else in this crate a signature covers a digest,
because everywhere else the input is already a hash. Here the signature is over
the standard signing input itself — `BASE64URL(protected).BASE64URL(payload)` —
because a card is verified by software nobody here wrote. Signing `H(m)` instead
produces a perfectly valid signature over the wrong message: it verifies against
our own verifier and is rejected by every conforming one. That is why card
signing has its own seam rather than reusing the record `Signer`.

**The algorithm comes from a constant.** The verifier never reads `alg` from the
card it is checking — that is the oldest JWS attack, and a card is precisely the
attacker-supplied document it was invented for.

**Signed at publish, not at derivation.** The signature covers the card as
*served*, interface URL and tenant included. Those are deployment facts; a
signature taken before they were set would cover a document nobody serves.

**Several signatures coexist**, so a publisher rotates keys without a window in
which nobody can verify the card.

Canonicalization is [`core::canon`](#canonical-bytes), which orders keys by
UTF-16 code unit exactly as RFC 8785 requires. The one JCS rule it does not
implement is ECMAScript number formatting — and a guard asserts the card carries
no numbers, so the day somebody adds an integer field that is a failing test
rather than a signature two implementations disagree about.

#### Push: the one URL a caller chooses

Every other outbound destination in this crate is granted by an operator. A
webhook URL is supplied by whoever created the task, which makes push the one
feature where an untrusted party names an address this plane will connect to,
with a payload about somebody's work.

Three controls, none sufficient alone:

- **An operator host grant.** A caller may pick any URL under a permitted host
  and no host outside it. This is the primary control; the rest are the second
  lock. Matching is exact — suffix matching is how a grant for `acme.example` is
  satisfied by `evil-acme.example`.
- **Every resolved address checked, and the connection pinned to them.** One
  private answer refuses the whole resolution, so a name that answers with a
  public address and a private one reaches nothing — and pinning means the
  client cannot be handed a different answer on the second lookup.
- **HTTPS only.** The payload describes a task; sending it in clear to an
  address the recipient chose is a disclosure with extra steps.

The grant is re-checked **at delivery**, not only at registration. A
registration outlives the configuration that permitted it, and the tasks that
outlive a config change are exactly the long-running ones push exists for.

What is delivered is the task's **state, not its output**. A webhook is an
endpoint we were told about by a caller; it learns that something finished and
must come back through `GetTask` — authenticated — to learn what. That is
stricter than the spec requires, because otherwise a caller who can create a task
can have its contents posted to any permitted host, which turns an allowlist into
an exfiltration channel.

The IP classification is [`netguard`](#module-layout), shared with governed
media. Two implementations of one rule diverge, and the one that diverges is
whichever nobody probed at the boundary.

#### The stream is a view of the journal, not an event bus

The obvious way to stream progress is an in-process broadcast channel: a step
finishes, it publishes, subscribers receive. It is wrong here in three ways that
only appear in production.

A channel's events live in memory, so a subscriber that reconnects has **missed**
whatever happened while it was away and nothing can tell it what. A channel is
per process, so a subscriber attached to the instance that is *not* running the
work receives nothing — and which instance that is changes after every failover.
And a channel is a second record of what happened, which can disagree with the
first.

Reading updates from the journal instead makes the stream exactly as durable as
the run: a client that drops and re-subscribes picks up the current state and
continues, any instance can serve it, and the events cannot disagree with history
because they *are* history. The cost is a poll rather than a push — one indexed
read per subscriber per interval — and it is stated rather than hidden.

Two endings, not one. The spec requires closing on a terminal state; this also
closes on `INPUT_REQUIRED`, because a suspended run may be waiting on a person
for a week and holding a connection open for that is a leak with a spec
reference. Reconnecting costs the client nothing, since the stream is rebuilt
from history rather than resumed from memory.

There is deliberately **no SSE keep-alive**. It was tried: with it the response
body did not end when the stream did, so the connection outlived the task — the
exact failure the design is shaped to avoid. An idle stream may now be reaped by
an intermediary, which is the better failure, because a client can recover from a
closed connection and cannot recover from one that never ends.

### Model providers (`providers`)

Two drivers: the Anthropic Messages API, and the OpenAI **Responses** API —
Responses rather than Chat Completions because it is the current primitive and
reports both usage and completeness directly. They exist mostly to prove the seam
is right: that a driver can report *what a failure consumed*.

Status classification is shared between them, in `model::wire`, because it is
doctrine rather than vendor detail:

| Response | Metered |
|---|---|
| connect/DNS/TLS failure, `4xx`, `429`, `529` | no |
| `5xx` | *unknown* — see below |
| a generated refusal, or an answer with no text | **yes** |

A refusal *before* generating costs nothing; a refusal *after* costs whatever it
took to decide. A budget that cannot tell them apart under-counts exactly when a
model is being difficult.

Three details worth stating:

* **Structured output has two modes, because native support is not universal.**
  `SchemaMode::Native` uses the provider's constrained decoding, where a
  non-conforming answer is *unproducible*. `SchemaMode::ForcedTool` declares one
  tool whose input schema is the answer's shape and forces it with `tool_choice`
  — the universal fallback, working wherever tool calling does. Native is the
  default so an unconsidered deployment gets the strong thing; emulation is
  weaker in one stated way, so a model that ignores the forced call is a loud
  metered failure rather than an empty success.

  The mode is resolved **per model**, not per driver — the constraint belongs to
  the model and one driver serves many. Anthropic's Models API can be asked which
  capabilities a model has; OpenAI's `/v1/models` returns no capability flags at
  all, so configuration is the only answer that works for both. On OpenAI,
  `strict: true` inside a *function definition* works on every tool-capable
  model while native `text.format` is newer-models-only, so emulation there is
  the more compatible option at the same strictness.
* **A schema strict mode cannot accept is refused before it is sent.** OpenAI's
  strict mode takes a subset of JSON Schema — `additionalProperties: false`
  everywhere, every property in `required`, no `default` — and rejects the rest
  with a 400 that does not say which rule broke. The driver names the rule, and
  does not rewrite the schema: that would make the effect key record one shape
  while the wire carried another.
* **Reasoning tokens are billed and invisible.** A driver reporting only readable
  output would tell a reasoning-heavy run's budget it cost a fraction of what it
  did.
* **A cut-off answer says so.** `Completion` carries a typed `truncated` flag
  rather than a stop reason the caller has to recognise. It is not an error —
  prose that stops early is readable, and only the caller knows whether they were
  parsing JSON — but a partial answer returned as a whole one is exactly the
  silent truncation refused everywhere else.
* **A provider's error body is trimmed** before it becomes an error message.
  Providers echo the prompt back in error payloads, and a prompt carries whatever
  the run was working on; an unbounded message turns a failure into an
  exfiltration channel into the log aggregator.

`ModelError::Unavailable` names the 5xx case instead of guessing it. Both guesses
are wrong in different ways — fatal makes a blip end a run, free lets a retry
loop spend against a ceiling reading zero — so it is treated as safe to repeat
(a completion does not change the world) with the documented cost that the
ceiling may under-count by at most one call. A streaming driver, which can see
partial usage, must report `Interrupted` with what it saw.

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

An application chooses durable sharing with `subject`: use an agent-qualified
subject for private memory or a team-qualified subject for several agents in one
tenant. `purpose` partitions what may be recalled for a particular job. These
are query scopes, not ACLs. The policy engine sees `memory.recall` and
`memory.remember`, the acting agent, tenant, subject/purpose, and write security
metadata; deployments authorize private/team access there. Tenant-bound store
handles provide the hard cross-tenant boundary.

The built stores are redb for one node and PostgreSQL for several instances.
Both run the same memory conformance contract. PostgreSQL serializes concurrent
revisions of one id; each write atomically replaces the current version and its
derivation edges. An id cannot move between subject/purpose scopes or be reused
after erasure, because old journal selections and retained lineage must never
name unrelated future content. Derived writes validate that every named source
version and commitment exists and remain in the same subject, so subject erasure
cannot strand a summary elsewhere.

Core recall intentionally filters by subject/purpose and orders newest first. It
does not claim semantic/vector search. Embeddings and indexes drift; a future
semantic retriever belongs behind a separately journaled effect that records its
model/index identity, filters, scores, and final selection.

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
redacted. And a version that was forgotten makes the history that used it
**unreplayable** — reported loudly, because replaying a different memory would be
worse than admitting the record is gone.

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
summary.

What is not built is equally important: no automatic memory formation, semantic
ranking, TTL/access-time expiry, legal hold, or cryptographic deletion of memory
content. Applications explicitly write memories today. Provider conversation
objects and opaque compaction remain conveniences, never the source of truth.

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

The cursor is now keyed by `(step, phase)` — which is what the effect key has
always said the identity is. A latent bug that only a new entry point could
reach.

## Batch runs

A batch is one business act made of many independent ones — a Jahresabrechnung
over 10⁵ meters. It is modelled as neither one run nor N unrelated ones, because
both lose something: one run gives 10⁵ settlements a single failure and a single
budget, and N unrelated runs leave nobody able to answer "did it finish".

So a batch owns N runs sharing one frozen plan. Each item gets its own journal,
its own budget, and its own outcome; the batch holds the cursor, the census, and
the terminal state.

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

## The manifest, and the registry it is pinned in

Everything security-relevant about an agent can be expressed as a builder call.
The problem is not that builder calls are wrong — it is that **a builder call is
invisible in review and a file is not.** A tool grant added by editing three
lines of Rust is a grant nobody notices; the same grant added to a manifest is a
diff with a reviewer's name on it.

```yaml
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: pattern-compliance-auditor
  version: "2.0.0"
spec:
  topology:
    mode: single
    role: specialist
  identity:
    role: "Automated data invariant auditor"
    constraints: "Isolate structural failures. Enforce semantic rule-packs strictly."
  security:
    max_sensitivity_egress: internal
    max_delegation_depth: 2
  budgets:
    max_tokens: 120000
    max_minor_units: 250
  models:
    privileged:  { provider: anthropic, model: claude-sonnet-5 }
    quarantined: { provider: anthropic, model: claude-haiku-4-5-20251001 }
  output:
    schema:
      type: object
      required: [finding, severity]
  tools:
    - ref: "mcp://validator/apply_correction"
      mutates: true
      max_sensitivity: internal
```

### An agent that is only a file

Everywhere else in this crate, behaviour is a `Skill` somebody wrote. That is the
right answer when an agent does real work — a solver, a database, a calculation a
model cannot be trusted with. It is the wrong answer for the large class of
agents that are *a prompt, a model, and a result shape*, because the code adds
nothing a reviewer can check while removing something they could: **the digest
then covers only part of the agent.**

`spec.execution.kind` closes that gap. It names a behaviour this crate
implements, the runtime registers it, and nothing else is written:

```yaml
spec:
  execution:
    kind: completion        # one model call, answered in the declared shape
```

```rust
// The only Rust. Which driver answers to the name `fake` is deployment wiring —
// an agent's declaration must not change when its API key does.
let rt = Runtime::builder(store)
    .provider("fake", provider)
    .agent(Agent::new(&m))
    .build();
```

The claim this unlocks is worth stating precisely, and as a **conjunction**
rather than as a boast about what nobody else has — a negative about every
product in a field moving this fast is not a claim anyone can check. A
declarative agent here is content-addressed **in its entirety**, *and* every step
it takes is journaled, *and* the run replays deterministically.

Each half exists elsewhere; the pairing is the point. Declarative agent formats
(`agent.yaml`, CrewAI, ADK) give you the first — a reviewable, versioned file.
Durable-execution platforms give you the second and third, and as of Dapr 1.18
they sign and attest that history too. What is hard to assemble from either side
is a file that is *both* the whole definition of the agent and the thing whose
execution replays: a signed history of a program you cannot fully see is
evidence about a black box, and a reviewable file with no execution record is a
description of intentions.

Two refusals keep it honest. A manifest declaring `execution` with no capability
is refused — an agent nothing can call is a file that does nothing. And a
provider the manifest names but no driver is registered for is refused rather
than defaulted to whatever driver happens to be present, because falling back
would run the agent on a model its own declaration does not name, which is the
exact substitution this layer exists to prevent.

`kind` is an enum, deliberately short, and every variant is a behaviour that is
implemented and tested. A config format whose behaviours are open-ended is one
nobody can review, because the reviewer would have to know what the string does.
A tool-calling loop is the obvious next kind and is **not** built: the model
layer does not yet surface tool calls from a completion, so a manifest asking for
one would be a promise the crate cannot keep.

### Oversight, declared without a predicate

The Article 14 half. It is declarable *because* the machinery already exists —
durable worklists, four-eyes, declared expiry — so it lands on the binding side
of the rule rather than the intent side:

```yaml
spec:
  execution: { kind: completion }
  oversight:
    approval: required
    approvers: [role:compliance-officer]
    deadline: klaerung          # resolved by your Calendar
    on_expiry: deny             # the default
```

The declarative agent then opens a task with the answer as the proposal — the
answer itself, not a description of it, because a reviewer who cannot see what
will happen is not reviewing — and returns only on approval. A refusal names who
refused and why, since "the agent failed" is not something an operator can act
on.

Three refusals:

* **`oversight` without `execution` is rejected.** A hand-written skill picks its
  own moment to ask, so there is nothing here for the runtime to apply. Allowing
  it would let a file claim a human is in the loop when no human ever is — the
  precise decoration the binding rule exists to prevent.
* **`on_expiry: proceed` needs `allow_unattended: true`.** The runtime already
  demands that; the file demands it too, so the decision is greppable in the
  document a reviewer reads rather than only in code they do not.
* **An unstated `on_expiry` denies.** The safe direction is the one nobody has to
  remember to choose.

**What you will not find is a condition.** "Require approval when severity is
high" is a predicate, and a predicate is one step from an `if` — the point where
config stops being config. An agent whose oversight depends on what it found is a
skill, written in a language built for decisions. This is the field flagged in
advance as most likely to break that line.

### What a manifest is worth: it binds

A field read by convention is two independent copies of one decision. The
reviewer approves `model: haiku`, the code calls opus, and nothing anywhere
disagrees — worse than useless, because it manufactures confidence. So the rule
is: **a field either has an enforcement point, or it is marked as intent.**

What enforces today, before dispatch:

| Field | Refused when | Reported as |
|---|---|---|
| `spec.models` | a completion names an undeclared provider/model | `effect:declared`, journaled |
| `spec.tools` | a call names an ungranted `mcp://server/tool` | `effect:declared`, journaled |
| `spec.budgets` | the ledger reaches a ceiling | `Exhausted` |
| `spec.capabilities.provides` | no registered skill provides it | panic at `build()` |
| `security.max_sensitivity_egress` | a labeled value exceeds the stricter of manifest and sink ceilings | `EgressCeiling` |
| `security.max_delegation_depth` | the configured identity or a handoff chain exceeds the reviewed ceiling | build refusal or `DelegationDepth` |

The refusal carries a **distinct action** from a Cedar denial, because the two
accuse different parties: a policy denial is the deployment's rules saying no to
something the agent was built to do; a manifest refusal is the agent doing
something its own reviewed declaration never mentioned, which is a defect in the
code rather than a tightening of the rules.

There are no review-only security fields. Architectural injection-pattern labels
were removed because arbitrary native skill code cannot be proven to follow one;
keeping the label would manufacture confidence. `spec.output.schema` is carried
to the provider and into the effect key, but is not validated a second time
against a result.

### The prompt is part of the declaration

`spec.identity` is the field that makes the digest worth having. A system prompt
composed in the embedder's Rust has **no version**: it changes in a deploy, the
journal faithfully records every run it affected, and nothing connects the two.
Inside the manifest it is covered by the digest, so a reworded instruction is a
version bump — a diff with a reviewer on it, and something a consumer can pin.

`Identity::system_prompt` renders it with the dullest template that could work:
the role, a blank line, the constraints. Anything cleverer would be agentplane
putting words in an agent's mouth that no reviewer of the manifest ever saw. Its
exact layout is pinned by a test, because changing it would alter every
embedder's prompt without changing a single manifest or moving a single digest —
the one edit in this crate that could silently change model behaviour everywhere.

The field is optional. An embedder composing its prompt in code is a legitimate
choice, and requiring the field would mostly produce manifests with a
placeholder in it. A *declared* identity with a blank role is refused, though:
that is a digest covering a prompt that says nothing, under a field that looks
answered.

### What this agent is in a multi-agent arrangement

MAST measures **inter-agent misalignment at 36.9 % of observed multi-agent
failures** — the one large failure class that exists only because somebody chose
an arrangement. So the arrangement is declared rather than emergent.

`mode` is *how many agents and why*; `role` is *what this one is*. They are
separate because one shape supports several roles, and each agent has its own
manifest:

| `mode` | shape | inter-agent failure surface |
|---|---|---|
| `single` *(default)* | one agent, one context, many tools | structurally absent |
| `routed` | a deterministic router picks exactly **one** agent per trigger | absent — still one agent per task |
| `collaborative` | several agents contribute to one task | the full surface |

| `role` | may delegate | |
|---|---|---|
| `specialist` *(default)* | **no** | does one thing, hands off to nobody |
| `orchestrator` | yes | decomposes, delegates, assembles |
| `router` | no | one dispatch decision, then it steps out |

**Routing is not collaboration.** Picking one specialist out of twenty-nine by
event type is a dispatch table, and carries none of the coordination risk — which
is what most "we run multi-agent" deployments actually are.

Three combinations are refused, because the fields are individually fine and it
is the combination that describes nothing:

* **`specialist` with `max_delegation_depth` above zero.** The consistently
  reported top failure mode of handoff architectures is the infinite loop — A
  hands to B, B to C, C back to A. The structural answer is that most agents in
  an arrangement have no authority to hand off at all, and a specialist that may
  delegate is an orchestrator nobody reviewed as one.
* **`single` with a coordinating role.** There is nobody to orchestrate or route
  to.
* **`collaborative` with no `reason`, or a `reason` without `collaborative`.**
  Collaboration costs roughly an order of magnitude more tokens and opens the
  whole failure surface, so why it is warranted belongs in the file. The
  justifications are enumerated rather than free text so each is checkable in
  principle: `parallel-disjoint` (overlapping inputs are *false parallelism* —
  paying the coordination cost and gaining nothing) and `distinct-authority`.
  There is deliberately no `context-overflow`: whether work exceeds a context
  window is not a property of the graph, so the contract could not check it —
  and an unchecked justification is not a weak control but an escape hatch,
  since a plan refused as false parallelism was approved by editing one word.

`distinct-authority` deserves emphasis because neither side of the public
multi-agent debate raises it: **the best reason to split agents is often
security, not capability.** If a sub-task needs credentials the parent should not
hold, delegating to a narrower agent is least privilege, and the coordination
cost buys a real security property rather than hypothetical speed.

### A model id is a behaviour change, so it is versioned like one

Swapping a model alters what an agent does more than most code edits, and a swap
made in a deploy has no version, no diff, and nothing connecting it to the runs
whose outputs changed. `spec.models` puts the provider and model in the digest.

The role names remain part of the allowlist and digest: a hand-written skill can
route untrusted material to a separately declared quarantined model. The
manifest does not claim that this architecture occurred. That would require
proving the conduct of arbitrary native code, so the former `security.pattern`
label was removed instead of being left as review-only intent.

`models: {}` declares **no inference at all** — a rules-only agent is a
legitimate design, and saying so out loud distinguishes it from one whose model
wiring somebody forgot. Absent `models` is not refused, unlike an absent budget:
an unstated budget is unbounded spend, an unstated model is a wiring decision.
Refuse the silence that costs money, not the silence that costs nothing.

### The result shape is a contract with a version

`capabilities.provides` names a capability; `spec.output.schema` says what comes
back. Narrowing a field is a breaking change to every consumer, so it belongs in
the digest rather than in a deploy.

The crate does **not** validate results against it — the same decision
`Completion::structured` documents, because a second JSON Schema implementation
here could disagree with the one that did the enforcing, and the disagreement
would surface as a run refusing an answer that is in fact conformant.
Enforcement belongs at the provider, during generation, where a constraint
prevents a malformed answer rather than rejecting one already paid for.

That does not make it inert. Handed to `ModelCall::expecting`, the schema goes
into the **effect key** — so editing it makes a replay report divergence instead
of quietly reinterpreting last year's stored answer under today's rules.

`schema: {}` is refused. It is a *valid* JSON Schema meaning "anything", so it
parses, looks answered in review, and promises nothing; an agent with no
machine-readable result omits `output` entirely.

### Unknown fields are refused, never ignored

The single most dangerous property a config format can have is tolerance. In a
permissive parser `max_tokns: 100` does not mean "a token ceiling of 100 with a
typo" — it means **no token ceiling at all**, silently, in the one document
whose purpose was to make the ceiling reviewable. Every struct in the manifest
is `deny_unknown_fields`, so that is a parse error instead.

The same reasoning drives two smaller refusals:

* **The document says what it is.** A foreign `apiVersion` or `kind` is refused
  rather than best-effort parsed, because a format that guesses is a format
  whose meaning changes under you.
* **Unbounded is a decision, so it has to be stated.** A manifest with no
  `budgets` section is refused. Writing `budgets: {}` means it on purpose, and
  that is a line a reviewer can object to.

`ToolGrant.mutates` defaults to **true** for the matching reason: a tool nobody
thought about should get the treatment that makes the runtime cautious, not the
one that makes it fast.

### What a manifest does and does not do

`RuntimeBuilder::agent` binds the document to one agent on the plane: it applies
that agent's budget, carries the declaration into every step it governs, and
registers the behaviour when `spec.execution` is declared. Several agents may be
registered on one plane, each governed by its own manifest. Models and tools are
enforced at dispatch, as the table above says.

The egress ceiling and delegation depth bind at the sink boundary. Each is
combined with the sink's own limit and the stricter value wins. A configured
identity already deeper than the manifest permits is refused at build; a peer
handoff that would cross the ceiling is refused before dispatch.

Because a plane holds several agents, two of them can collide — and a collision
is not merely shadowing. Dispatch resolves a capability to one skill *and to the
manifest governing it*, so a silent overwrite would move work an agent still
advertises out from under that agent's budget, model grants and egress ceiling,
with nothing in the journal to show it. `build` therefore refuses two agents
claiming one capability, and two skills sharing one name. Both are wiring
mistakes with no recovery, so both are refused at startup rather than discovered
at dispatch.

The manifest does **not** describe an injection architecture. The former pattern
field was removed because arbitrary native skill code cannot be proven to follow
it; a security label without an enforcement point is worse than no label.

It also does not set the lease **owner**. That identifies a process, and several
instances of one agent are normal — see [operations](@/docs/operations.md).

### A version is an artifact, not a moment

A manifest has a content digest over [canonical bytes](#canonical-bytes), so two
files that declare the same thing share a digest and a file that declares
something different cannot.

That digest is what makes "which declaration governed this run" answerable after
the file has moved on — but only because the run **records it**. `RunAdmitted`
carries `governed_by`: the agent's name, its version, and the digest of the
manifest that governed it. Name and version say what to look for; only the digest
says what it actually said, including the system prompt, which is inside it. A
run served by a skill registered directly on the plane records `None`, which is a
different answer from "governed by something nobody wrote down".

The record names the capability separately, in a field called `capability`. It
previously held one under the name `agent`, which read as an identity and was
not — the stringly-typed mistake, in the one record where *who did this* is the
question being asked.

The registry is built around three no-rewrite guarantees, and they are not
redundant:

| | catches | at | trusting |
|---|---|---|---|
| **Immutability** | a version republished with different content | write time | the registry |
| **A pin** | a resolve that returns content the caller never reviewed | read time | nothing |
| **Publisher immutability** | identical bytes attributed to a different signer | write time | the registry |

Immutability is what makes "we reviewed 2.0.0" a statement about an artifact
rather than about a Tuesday — the property Go's module proxy and crates.io both
arrived at, and the one whose absence produced the npm and PyPI incidents.
Re-publishing *identical* content still succeeds, because a retried deploy is
not an attack and treating it as one teaches people to force.

A pin is the caller declining to need that promise. It is the only one of the
two that survives the registry itself being the compromised party, which is why
`resolve_pinned` exists beside `resolve` rather than as a flag on it: the safe
call should be the one you can see at the call site.

`publish_signed` supplies the half a digest cannot: *who* approved the artifact.
The signature covers a domain-separated manifest hash, so it cannot be replayed
as a journal-record attestation. An identical unsigned artifact may adopt its
first attestation later without changing its digest; once publisher evidence
exists, another signer is refused rather than silently replacing it. Supporting
several publishers requires an explicit attestation set and is not built.

`MemoryRegistry` is process-local. The trait leaves room for a durable or remote
registry, but none ships today. Key creation, rotation, revocation, and the
decision to trust the identity returned by `resolve_verified` remain deployment
responsibilities.

## Testing

| File | Guards |
|---|---|
| `tests/engine/durability.rs` | The claims that would otherwise be marketing |
| `tests/engine/recovery.rs` | Crash, resume, orphan handling, lease contention |
| `tests/process/cases.rs` | Correlation, case state across runs, obligations, closure |
| `tests/process/waits.rs` | Suspension, delivery, the arrive-before-wait race, dead letters |
| `tests/process/tasks.rs` | Worklist, four-eyes, expiry policy, breach escalation |
| `tests/process/plans.rs` | Contract validation, ready-set, provenance through the graph |
| `tests/trust/budgets.rs` | Limits, overshoot semantics, replay billing identically |
| `tests/engine/retries.rs` | The disposition gate, the policy bound, attempt keys, replay of a retry sequence |
| `tests/engine/reconciliation.rs` | Probing after doubt, the verdict on the record, strict replay staying a pure read |
| `tests/engine/compensation.rs` | Reverse-order unwind, pivots, undeclared steps, refusing to unwind under doubt |
| `tests/process/timers.rs` | Durable sleep, the journaled instant, single-delivery wake-ups, abandoned claims |
| `tests/process/telemetry.rs` | That spans and events are emitted, and that replay is distinguishable |
| `tests/process/replanning.rs` | Versioned successors, lineage, the untrusted-data refusal, replay reading plans back |
| `tests/guards/interactions.rs` | Feature pairs that share machinery — a sleeping compensation, a replan beside a live sibling, sleep/retry/sleep in one step |
| `tests/engine/simulation.rs` | Every crash point in a run — each journal prefix rebuilt, resumed, and re-checked |
| `tests/engine/faults.rs` | Store faults a prefix cannot express — above all, a write that committed and was lost |
| `tests/process/batches.rs` | Failure isolation, partial failure as terminal, item-granular resume, per-item cost |
| `tests/guards/metrics.rs` | What a metrics subscriber actually received, and that gauges are not page-bounded |
| `tests/trust/policy.rs` | The gate, the journaled denial, and that replay never consults the engine |
| `tests/trust/identity.rs` | Scope containment, attenuation, depth, and the chain surviving replay |
| `tests/trust/boundary.rs` | Effect output is labelled at the source, propagates, gates sinks, and survives replay |
| `tests/wire/api.rs` | That the HTTP surface cannot be told who is acting, that both gates run on every route, and that four-eyes survives the hop |
| `tests/trust/attestation.rs` | That a *valid* chain rewritten by somebody who could hash but not sign is still caught |
| `tests/engine/cancellation.rs` | That a stop unwinds what the run did, refuses to unwind around an unknown outcome, and names who asked |
| `tests/wire/drivers.rs` | The two wire drivers' failure mappings — whether a peer acted, and whether a model call was billed |
| `tests/guards/layering.rs` | Architectural invariants — core purity, lint config, canonical JSON, spec/code correspondence |
| `spec/` | TLA+ models of the effect protocol, retry safety, sagas, and fencing, plus the mutants that prove those models constrain anything |

### The size a proof starts from is stated, never inferred

`Witness::cosign` takes `old_size` from the caller. That looks like ceremony and
is not: an RFC 6962 consistency proof is **O(log n) hashes, not one per new
entry**, so nothing about a proof reveals which size it starts from. A 50→100
proof carries seven hashes, and an implementation computing `size - proof.len()`
claims to start at 93 — which every witness refuses.

Only the holder of the log knows. `MemoryWitness` checks the caller's claim
against what it remembers and reports a mismatch as `Stale`, exactly as a remote
witness's `409` does, so the in-process model stays a faithful stand-in rather
than a friendlier one.

This shipped as a real defect and survived its first test, because that test used
a four-entry log with a two-hash proof — the one size where the wrong arithmetic
gives the right answer. The regression test uses fifty and a hundred.

### The specs are mutation-tested

Model checking proves a spec's invariants hold *of the spec*. It says nothing
about whether those invariants constrain anything, and the difference is not
visible by reading.

Writing `spec/RetrySafety.tla` also paid for itself immediately: TLC deadlocked
on an effect that was *safe* to repeat, failing in doubt on its final attempt,
with no rule to apply. The implementation handled it; the rules as first written
did not.

`spec/EffectProtocol.tla` originally modelled "act" and "record" as one atomic
step. TLC explored it exhaustively and found no errors — but the one state the
protocol exists to survive, *the action landed and the process died before
recording it*, was unreachable, so `ExactlyOnce` was true by construction. Green,
and worthless.

So `spec/verify.sh` runs two passes. The first checks the specs. The second
checks the check: each spec is re-run against deliberately broken copies of
itself, and each mutant must be caught by the specific invariant written for it.

| Mutation | Spec | Must be caught by |
|---|---|---|
| Orphaned effect retried instead of escalated | `EffectProtocol` | `ExactlyOnce` |
| Action taken before the announcement is durable | `EffectProtocol` | `DurableIntentPrecedesAction` |
| In-doubt failure retried without checking it is safe to repeat | `RetrySafety` | `ExactlyOnce` |
| A probe answers without identifying the call it is asking about | `RetrySafety` | `ExactlyOnce` |
| A run that left a mutation in doubt reports success | `RetrySafety` | `NoSuccessOnUnresolvedDoubt` |
| A reconcilable effect is escalated without being asked about | `RetrySafety` | `NoQuarantineWithoutAsking` |
| An attempt acts before its announcement is durable | `RetrySafety` | `DurableIntentPrecedesAction` |
| A run holding an unknown outcome is unwound anyway | `Saga` | `NoUnwindUnderDoubt` |
| The unwind continues past the point of no return | `Saga` | `PivotHolds` |
| A step that declared no compensation is undone anyway | `Saga` | `UndeclaredIsNeverUndone` |
| Completed steps are undone in the order they ran | `Saga` | `UnwindIsReverse` |
| A resumed unwind repeats compensations it already performed | `Saga` | `CompensatedAtMostOnce` |
| The unwind passes over a step it could have undone | `Saga` | `UnwindIsComplete` |
| Store accepts a write without checking the epoch | `Fencing` | `EpochsNeverRegress` |

Tripping the top-level `Safety` conjunction is not accepted — that shows only
that *something* broke, not that the invariant aimed at this bug is the one that
caught it. A mutation that no longer matches its spec is a failure too: a
mutation that changes nothing tests nothing.

### Every crash point, without a fault injector

A crash truncates an append-only journal, which means the journal enumerates its
own fault schedules: **every prefix of a real journal is a crash that could have
happened.** `tests/engine/simulation.rs` runs a workload, then for each prefix builds a
fresh store holding exactly that much history, resumes it, and checks the specs'
invariants against the code. For a run of *n* records that is *n* crash points,
exhaustively — no seed, no injector, nothing to get lucky with. It sweeps a run
that succeeds and a run that unwinds.

What it does *not* do is reorder writes, skew clocks, partition a network, or
stall a disk. That needs the runtime on a simulated executor, and is the layer
above this one.

#### The assertion that bites is about failures, not outcomes

The obvious check — no effect performed twice — is nearly vacuous here, and the
reason generalises. Exactly-once is enforced at two layers: replay reads a
completed effect back from the journal, and beneath it the store keys effect
starts by `(run, effect_key)`. Delete the replay path
entirely and the world *still* contains no duplicate, because the re-announcement
is rejected one layer down. The sweep goes green over a runtime that has stopped
replaying at all.

This is not hypothetical. The sweep was written with exactly that assertion, and
a mutation removing the whole read-back survived it.

So the load-bearing assertion is: **replay must never reach the constraint.** A
resume may refuse, but only for a reason the design names — a crash before
`PlanFrozen`, or an undecidable outcome under a recovery mode that forbids
guessing. Being saved by the unique index is the backstop catching what replay
should have caught, and the test says so by name.

The general rule: **a property enforced at more than one layer cannot be tested
by observing the outcome**, because the outer layer masks every inner failure.
The test must assert which layer held.

### Every guarantee is broken on purpose, in CI

The specs are mutation-tested; so is the code. `tools/verify-mutants.sh` walks a
checked-in table of mutations — one per load-bearing guarantee — applies each,
runs the suite, and requires **the test written for that guarantee** to fail.

The distinction between "some test failed" and "the named test failed" is the
whole point. A mutation caught by an unrelated test is reported **weak**, because
it usually means the guarantee has no test of its own: the one holding it up can
be rewritten, or deleted as redundant, without anyone noticing what it was
protecting.

Two things are errors rather than skips. An anchor that no longer matches means
the code moved and the mutation is silently testing nothing. A mutation that
fails to compile broke the file instead of removing the guarantee — it proves
nothing either way.

This exists because a guarantee can be implemented, tested, and unfalsifiable,
and this codebase shipped one: see *The hole this closed* above. Running the
sweep the first time immediately found a second, smaller instance — a test whose
name claimed a property its body could not exercise.

`tests/guards/layering.rs` checks that every test the table names actually exists,
because five invented names cost a full rebuild each to discover the slow way.

### The model and the code are pinned to each other

A verified spec and a passing suite can still be checking different things. The
dangerous direction is a spec gaining an invariant the Rust side never
implements: the model then verifies a protocol the runtime does not have, and a
green TLA+ job reads as assurance about code it says nothing about.

So `every_spec_invariant_is_claimed_by_a_test` in `tests/guards/layering.rs` holds an
explicit map from each spec invariant to the test that checks the same property
of the implementation, and enforces it in both directions — renaming either side
fails the build. An invariant added to a `Safety` conjunction with no counterpart
fails it too.

`tests/guards/layering.rs` deserves a note more generally: it checks properties that no
amount of code review reliably catches, because they are about what is *absent* —
a missing lint entry, an accidental `serde_json/preserve_order`, an I/O import
creeping into `core`, an invariant nobody wired up, a telemetry event nobody
emits, **a public enum variant nothing constructs**, **a pair of features nothing
exercises together**.

That last one exists because the same bug happened five times: a variant, a
recovery mode, an error, a record kind declared and never built, each reading as
a capability the system had. `#[from]` variants are exempt (`?` builds them), and
a variant meant for callers counts only if a *test* constructs it.

The interaction matrix exists because replanning shipped with its own gates
tested and broke the saga: a successor reusing a completed step's id made the
unwind compensate work that never ran. The model↔code guard maps each invariant
to one test, and no test combined a replan with an unwind. Adding a feature
widens where an invariant applies, so the widening is what gets checked — every
pair of the eight feature axes must be exercised together, or declared
independent with the reason.

**A guard that reads source must exclude the source that is the guard.** Both
source-reading guards have been blinded by themselves: the dead-variant check by
its own doc comment naming the canonical example, and the interaction matrix by
its own list of detection literals, which made one file look like a test
exercising every feature. So they strip comments, and the matrix skips
`layering.rs`.
