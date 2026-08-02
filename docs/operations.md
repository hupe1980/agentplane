# ⚙️ Operations

Running this for real: topologies, the store contract, the background sweep,
and what it reports about itself.

---

## Ownership and fencing

Plane instances are stateless. Each run has at most one owner, held as a lease
with an **epoch**.

Every append carries the writer's epoch, and the store compares it *inside the
same transaction that writes*. There is no window between "am I still the
owner?" and the write for a paused instance to slip through, because there is no
gap to slip into.

Two failure modes, deliberately distinct because they need opposite responses:

| Error | Meaning | Response |
|---|---|---|
| `LeaseHeld` | Someone else owns it and is alive | Wait |
| `Fenced` | Your epoch is stale; you were taken over | **Drop the run.** Never retry |

Failover is not a special code path — it is the crash-recovery path. Lease
expires, another instance claims at `epoch + 1`, resumes via replay. That is the
payoff of building on replay: HA costs one lease table and an epoch column.

## Two backends, one contract

`JournalStore` states three guarantees and requires them atomically: fencing,
exactly-once, chaining. They are storage invariants deliberately — application
logic can be bypassed by the next caller, a constraint cannot.

A second backend is where that stops being true, and the mechanism is worth being
precise about. The new store is written from the same prose as the first. It
encodes two guarantees exactly and something *nearly* like the third. Nothing
catches it, because the suite that proves the runtime correct runs against the
embedded store, and the new one gets whatever tests its author wrote — which are the
tests for the parts they were already thinking about. The invariant they misread
is by construction the one with no test.

So the contract is written once, in `testkit::conformance`, and every backend is
run against the same battery. It ships rather than living in `tests/` because an
embedder bringing their own store needs it for the same reason.

Two design choices in the battery:

* **It reports every violation, not the first.** Bringing up a backend is
  iterative, and stopping at the first failure hides whether the second is a
  separate bug or a consequence.
* **It fails if it checked nothing.** A battery that silently runs zero checks
  reports success, which is the worst outcome available to it.

Writing it immediately caught a misreading in the battery itself: a *live* lease
is correctly not stealable — `LeaseHeld`, deliberately distinct from `Fenced`,
because the two call for opposite responses. A fenced writer must drop the run; a
writer refused a live lease is not stale and should wait. That distinction is now
one of the checks.

### The case layer

Five more stores, each settling one race:

| Store | The race |
|---|---|
| cases | two messages, one new matter; and two runs, one case state |
| events | one message, two waiters |
| timers | one wake-up, two sweeps |
| tasks | one decision, two reviewers |
| batches | one item, two reservations |

Each has a battery in `testkit::conformance_case`, run against both backends. The
container tag is pinned in the test rather than inherited: the
`testcontainers-modules` default is `postgres:11-alpine`, which has been end of
life since November 2023, so the default would certify this backend against a
release nobody should be running.
Postgres settles several more cleanly than the embedded store: `UPDATE … RETURNING` collapses
a read-then-write into one statement, so there is no window to reason about
because there is no second statement.

#### A sequential test cannot detect a race

Sequential checks prove the *result* is right, not that it is right for the right
reason — a `SELECT` then `INSERT` returns the correct answer every time it is
called one at a time.

So correlation also has a racing check, and the first version of it was useless.
Two concurrent callers serialised often enough that **dropping the constraint
that arbitrates correlation went undetected**. Only mutation-testing the battery
found it; eight racers across four keys catches it on every run.

* **A race test that does not reliably race reports green** — an untested
  guarantee wearing a test's clothing.
* **A race check corroborates, it does not prove.** Passing means no interleaving
  found a violation; the constraint in the store is what makes absence real.

A store that serialises internally — redb admits one writer at a time — passes
trivially and correctly, having no race to lose. That is not a reason to skip it:
the check exists for the backend where the race is real.

### Postgres

Three traps, each a plausible way to be nearly right:

* **Exactly-once is a partial unique index.** A `SELECT` then `INSERT` has a
  window with two writers, and closing that window is the entire point.
* **Fencing reads the lease `FOR UPDATE` inside the appending transaction.**
  Checking the epoch first and appending second re-opens the gap a paused
  instance wakes up into.
* **`seq` comes from the run's own chain**, never a sequence. Postgres sequences
  are non-transactional and leave gaps; a gap is indistinguishable from a deleted
  record during verification.

Each was confirmed falsifiable by weakening the store and checking the battery
named the right invariant — including one mutation that moved the writes outside
the transaction, which the atomicity check caught with "a rejected batch left 1
record(s) behind".

## The sweeper

Until something runs on a clock, a deadline is a number in a table and an
unclaimed event is a row nobody reads. That is the failure this runtime is built
against — not a crash, but a silence.

One tick, four findings, all of them loud:

| Finding | What happens |
|---|---|
| An obligation is approaching | `DeadlineTransition` → `Warned` |
| An obligation passed unmet | `DeadlineTransition` → `Breached`; the **case** is escalated |
| A task's window closed | The declared `on_expiry` is applied |
| An event nobody claimed aged out | Dead-lettered with a reason |

`now` is passed in rather than read, so the caller controls the clock. That keeps
the sweeper testable at all, and lets a simulation drive a year of obligations
through in milliseconds.

Every field of `SweepReport` is a number worth alerting on. `is_quiet()` is the
useful predicate: a healthy plane sweeps silently, so a non-silent sweep means
something happened.

## Metrics

### The runtime does not measure durations

Ambient clocks are lint-denied with three named escapes, each for a value that
gets journaled or is store metadata. A fourth escape *for instrumentation* would
end the rule, because timing is the most plausible-sounding reason anyone reaches
for a clock. And a replayed run would re-measure durations belonging to calls it
never made, so "effect latency by driver" would average network time with journal
reads — the failure `agentplane.effect.replayed` exists to prevent, arriving
through the metrics door.

Durations are therefore derived from spans, by the collector. The spans carry the
mode and the replay flag, so a collector can compute latency *and* exclude
replays, which an in-crate histogram could not.

### Counters are emitted; gauges are observed

"Open cases" cannot be an increment-on-open, decrement-on-close counter. A crash
between the state change and the emission loses a decrement permanently, and the
dashboard slowly invents open cases that do not exist — *plausibly*, which is
worse than obviously.

So gauges come from a census query against the store, and the sweeper emits them:
it already runs periodically and already takes its `now` as a parameter, so no
clock is read. The census is also the only consumer of a case's `opened_at`, and
the reason that column exists — a count cannot distinguish ten cases open for an
hour from ten open for a month.

A gauge must never be read from a `limit`-bounded query. That is why `census`
exists rather than `by_status(..).len()`: a paged count rises, flattens at the
page size, and looks like a plateau exactly when it has become a backlog.

### Two rules, both guarded

**A dimension is a variant, never a rendered message.** `Display` on a budget
error embeds the allowed and used figures; a label carrying those is one time
series per distinct budget, which is how a metrics backend falls over. Every
dimension comes from an `as_str()` accessor.

**The catalogue is not a wish list.** A declared-but-unemitted event leaves an
empty panel, which at least looks wrong. A declared-but-unemitted *counter* reads
as a hard zero — indistinguishable from "this never happens" — so an operator
concludes the system is healthy from a number nobody wired up.
`tests/guards/layering.rs` fails the build if a catalogue entry has no emitter.

## Observability

`tracing` spans and events, so the runtime is usable by any subscriber — OTel,
JSON logs, a test recorder — without the crate choosing an exporter.

```
agentplane.run                     gen_ai.operation.name = invoke_agent
└── agentplane.step                agentplane.step.id, .capability, .phase
    └── agentplane.effect          .kind, .attempt, .mutates, .replayed
```

Three decisions worth knowing:

- **One span per effect *attempt*.** A retried call shows as several spans rather
  than one long one, which is what makes "how often does this driver need a
  second try" answerable.
- **Replay is marked on every span.** A replayed run re-executes its skills and
  emits spans again. An effect served from the journal is reported as an event
  with `replayed = true`, never as an effect span — otherwise "effect latency by
  driver" averages real calls with journal reads.
- **Spans attach to futures, never to threads.** `Span::enter` returns a guard
  bound to the current thread; held across an `.await` it stays entered while the
  future is suspended, so whatever runs next is attributed to it. With concurrent
  siblings that silently reparents their work. `Instrument` is the only form that
  survives a suspension, and `tests/guards/layering.rs` bans the guard in async code.
- **The vocabulary lives in `runtime::telemetry`.** A span name typed inline at
  twelve call sites is twelve chances to drift, and telemetry drift is invisible:
  the dashboard stops matching and nobody is told.

Every failure P7 exists to surface has its own event target:

| Event | Fires when |
|---|---|
| `agentplane.run.nondeterminism_detected` | Replay recomputed a different effect key |
| `agentplane.run.quarantined` | A run was set aside for a human |
| `agentplane.effect.undecidable` | An outcome could not be determined and guessing was forbidden |
| `agentplane.effect.reconciled` | A probe was asked whether a call landed |
| `agentplane.budget.refused` | A limit refused an operation |
| `agentplane.saga.compensated` | A completed step was undone |
| `agentplane.saga.compensation_failed` | A compensation failed, leaving the run partly unwound |
| `agentplane.event.dead_lettered` | An event aged out with nobody waiting — a correlation bug |
| `agentplane.deadline.breached` | An obligation passed unmet |
| `agentplane.timer.fired` | A sleeping run's instant arrived |

`tests/guards/layering.rs` fails the build if any of those has no emitter, and
`tests/process/telemetry.rs` asserts on what a subscriber actually received rather than
on what the source contains — an instrumentation test that greps is checking the
author's intent, not the runtime's behaviour.

## The operator surface

Feature `http`, off by default. A library embedded in someone else's process
should not open a port unless asked.

### Identity comes from the request, never from its body

This is the whole design, and everything else in the module follows from it.

Four-eyes is enforced in `TaskStore::claim`, which takes an actor and a set of
roles. In-process both come from the embedder's own code, which is trusted. Over
HTTP they would come from whoever is on the socket — and a reviewer who can name
themselves can name the person who proposed the action. That is not a bypass of
the control; it *is* the control, inverted.

Discipline does not hold that. So the wire type has no field to hold it:

```rust
pub struct DecisionRequest {   // no `actor`. no `roles`.
    pub approved: bool,
    pub reason: String,
    pub amendment: Value,
}
```

The handler builds the `Decision` from the authenticated `Caller`, because there
is no other source available to it. A later maintainer cannot be talked into
reading the body's actor, since there is nothing to read.

`deny_unknown_fields` is the other half. Without it, a body carrying
`"actor": "alice"` is accepted and silently ignored — the integrator who wrote it
believes they decided as Alice, the journal says Bob, and the disagreement
surfaces at an audit months later. A `422` says so at the first call instead.

### Two gates, and the surface will not start without the second

Authentication says *who*; it does not say *what they may do*. An operator
surface that stops there hands every authenticated caller the whole plane. So
every route runs `gate()`, which authenticates and then authorizes through the
runtime's own `PolicyEngine` under an `api:` action — and `Api::new` returns an
error against a runtime that has none.

That refusal is deliberate. In-process an absent engine is a choice; on a socket
it is a hole, and a permissive default is one nobody discovers until the port is
reachable. `DenyAll` exists for wiring the surface up before the rules are
written.

The gate runs *before* the path is parsed, so a denied caller cannot learn
whether a run id exists by comparing a `400` against a `404`.

### What the endpoints are for

| Route | The question it answers |
|---|---|
| `GET /runs/{run}` | What is this run doing, and **why is it not finishing**? |
| `GET /tasks` | What is waiting for me? |
| `GET /tasks/{task}` | What is this proposal, and may I decide it? |
| `POST /tasks/{task}/claim` | This one is mine — don't let a colleague duplicate it |
| `POST /tasks/{task}/release` | It isn't mine after all; give it back |
| `POST /tasks/{task}/decide` | Approve or reject, as myself |
| `GET /cases/{case}` | What has happened on this matter, and by when must it end? |
| `POST /runs/{run}/cancel` | Stop it — `202`, because the run stops at its next boundary |
| `POST /events` | This message arrived; wake whoever wanted it |

Two details carry more weight than the plumbing:

**A suspended run says what it is waiting for.** "Suspended" tells an operator a
run is stuck; it does not tell them whether to approve something, chase a
counterparty, or page somebody. The `SuspendReason` is on the record, so it costs
nothing to answer properly.

That status is read from the run's **last** record, not from whether a
suspension appears anywhere in its history. Every run that has ever waited for a
human has a `RunSuspended` in it, forever — scanning would report every completed
approval flow as permanently stuck, which is worse than reporting nothing.

**The worklist says when it was cut off.** The response is an object, not a
bare array, because an array cannot express it: a queue of 140 items paged at
100 returns 100 and reads exactly like a queue of 100. The flag comes from
asking the store for one more than the page and dropping it — inferring it from
`len() == limit` would cry wolf on every queue of exactly `limit`.

**Each worklist item says whether *this* caller may decide it.** A reviewer
barred by four-eyes still sees the task — hiding it leaves them wondering where
it went — and is told on the item rather than by a refusal after they have read
the case and made up their mind. The flag calls `Task::may_decide`, the same
predicate the store enforces, rather than re-implementing it: a second copy of an
authorization rule drifts, and the copy that drifts is the one people read.

### No authenticator is shipped

Same reasoning as the policy engine and the tracing exporter. `Authenticator` is
handed the whole header map, because a deployment may authenticate by bearer
token, mutual TLS, or a signed header from a gateway, and a parser baked in here
would be wrong for one and load-bearing for the other.

### Claiming is what stops duplicated work

`decide` alone makes the queue first-past-the-post at *decision* time: two
reviewers read the same case in parallel and one of them discovers, at the moment
they submit, that the work was wasted. `claim` reserves; `release` gives it back,
and it is `release` that makes `claim` safe to use — without it, a reviewer who
claims something they then cannot decide has parked it until somebody edits the
database, so the queue learns not to claim and the reservation stops meaning
anything.

Claiming is not advisory. `TaskStore::claim` runs four-eyes and role eligibility
in the same transaction that reserves, so an ineligible reviewer is refused
*before* they read the case rather than after they have made up their mind.

#### Eligibility outranks availability

Writing the handler forced a question the in-process API never had to answer:
what status code does a refused claim get? `403` and `409` ask different things
of the reader — *this will never be yours* versus *try again, or ask Bob* — and
that made the store's ordering visible. Both backends checked availability first,
so a barred reviewer asking for a held task was told "held by Bob". They wait for
Bob to release it, ask again, and are refused for a reason nobody has yet
mentioned; and meanwhile they have learnt who is reviewing what, from a queue
they have no standing in.

The order is now part of the `TaskStore` contract, and the conformance battery
holds both backends to it:

```
NotFound → Excluded → WrongRole → NotPending → AlreadyClaimed
```

The permanent refusal wins over the transient one, because the transient one
hides it.

The same battery run then caught a second defect, in Postgres only: `release`
had the right `WHERE` clause and **discarded the row count**, so a release by
somebody who did not hold the task returned `Ok(())`. The caller is told the task
is free; the holder still has it. That is the exact failure mode the shared
contract exists to catch — a second backend gets whatever tests its author
remembered to write, and those are the ones they were already thinking about.
Releasing now reports `ClaimError::NotHeld`, which is deliberately not
`NotFound`: "the id is wrong" and "it is not yours" call for different responses.

### The second thing building it found

Two runs of one plan shared one human task.

`TaskId` was derived from the awaiting effect's key. An `EffectKey` is unique
*within a run* — the journal enforces `(run, effect_key)` and needs nothing more
— but the worklist is a table shared by every run, and two runs of one plan reach
the same step, at the same ordinal, with the same descriptor, and derive the same
key. `TaskStore::open` is idempotent by id, so the second run's task was silently
**not created**. One proposal appeared, carrying the first run's amount; an
operator decided it; the second run went on waiting for an answer nobody would
ever be shown. Two €900 refunds became one €100 approval, and nothing anywhere
reported a problem.

It surfaced while writing a test that needed three tasks in one queue and could
only produce one.

The rule it encodes: **an effect key is unique within its run; anything that
escapes into a shared namespace has to mix the run back in.** `TaskId::derive`
now hashes both, and the field is private, so the collision is unrepresentable
rather than merely fixed. The `("task", …)` correlation key inherits the fix,
since it is derived from the id.

Worth noting *why* no test caught it: every task test ran one run. A one-run
fixture cannot express a two-run collision, and the shape was shared by all of
them — the same failure named in the retrospective as "one test shape hiding a
class of bug".

### What building it found

Writing the first handler failed to compile, and the reason was not in the
handler: `Runtime`'s futures were not `Send`. One field did it — a bare
`&dyn Fn(Append) -> Append` in the executor, which is neither `Send` nor `Sync`
unless it says so, and which infected every future that touched it.

Nothing in the crate had noticed, because nothing needed to: a single-threaded
`#[tokio::test]` awaits futures in place. An embedder calling `tokio::spawn`
would have hit it immediately, as a page of trait error naming a private type
they cannot see. `tests/guards/layering.rs` now holds it at both ends — a compile-time
assertion that every public runtime future is `Send`, and a scan that fails any
bare `dyn Fn` field in `src/runtime/`.

## 🗄️ Retention and erasure

A full-fidelity journal is simultaneously an asset and a GDPR liability, so the
two halves are retained differently:

- **Hash chain and metadata: indefinite.** Small, and it preserves tamper
  evidence.
- **Blobs: a configurable TTL**, then a tombstone that keeps the hash and drops
  the content.

The chain still verifies after expiry. You can prove *what happened* and *that
the record is unaltered* without retaining the personal data — and the **case**
is the erasure unit, because that is what an erasure request actually targets.

## 🚑 Runbook

| Symptom | Where to look |
|---|---|
| A run is `Quarantined` | It holds an effect whose outcome is unknown, or replay diverged. The record names the step. It will not be unwound automatically, and that is deliberate — reversing everything *except* the thing nobody can account for is worse than stopping |
| A run seems stuck | It is almost certainly suspended on an event, a timer, or a human. `GET /runs/{id}` reports *why* rather than only *that* |
| An event was dead-lettered | Nothing was waiting for it, and the grace window elapsed. The reason is on the record — usually a correlation key that does not match what the run subscribed to |
| Budget exhausted | A ceiling doing its job, not a fault. The status carries the limit **and** where consumption actually reached, so it says what to raise it to |
| `LeaseHeld` vs `Fenced` | Opposite responses. `LeaseHeld` means another instance is alive and you should wait; `Fenced` means this writer is stale and must drop the run, never retry |
