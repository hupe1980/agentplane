+++
title = "Concepts"
description = "Runs and cases, effects and dispositions, labels and typed release — the vocabulary everything else is built from."
weight = 2
+++

The vocabulary. Nine ideas, then the two surfaces you program against —
everything else in the crate is a consequence of one of them. Read this once and
the rest of the documentation stops needing footnotes.

---

## 1. ⚡ Effect

Anything the deterministic zone cannot reproduce by thinking: a model call, a
tool call, the clock, randomness, a case-state read, resolving a deadline.

An effect is **announced before it acts and recorded after**. That order is the
whole protocol — announcing first is what makes a crash mid-call detectable at
all, because the journal then holds an intention with no outcome.

```rust
let prompt = Tainted::trusted(prompt);
let answer = cx
    .sink_with(&prompt, |value| ModelCall::new(provider, model, value))
    .await?;
```

Model prompts are outbound data, so they go through the sink gate: `sink_with`
hands the labelled value to the effect and the gate in one motion — the closure
receives the inner value, so the bytes the gates check and the bytes the
provider is sent cannot drift apart. Live, that performs the call and journals the result. On replay, it performs
nothing and returns the recorded answer. The skill code is identical either way,
which is the point: replay is not a special mode a skill has to know about.

**Why it matters:** an effect is the *only* way through the boundary. Anything
that reaches the outside world by another route — a socket opened by a native
skill, a clock read that slipped past the lint — is outside every guarantee
below.

## 2. 🚧 The determinism boundary

Two zones. Above it: plan traversal, guards, retry decisions, budget arithmetic,
policy evaluation, label joins. All of it must produce **the identical sequence
of effect keys** when replayed. Below it: everything unreproducible, performed at
most once.

Three mechanisms enforce it, because convention is not enforcement:

1. **Lint gating** — `SystemTime::now`, `rand::random`, `Ulid::new` and friends
   are denied crate-wide.
2. **Effect-key verification** — on replay, a recomputed key that differs from
   history quarantines the run instead of diverging silently.
3. **Storage constraints** — "an effect starts at most once per run" is a unique
   index, not a code path. Application logic can be bypassed by the next caller;
   a constraint cannot.

## 3. 🧾 The journal

Append-only, hash-chained, one row per record. `hash = H(prev_hash ‖ record)`.

It is not a log *of* the run. It **is** the run — the thing recovery reads, the
thing an auditor checks, the thing cost is summed from, the thing a regression
test replays. Six obligations, one mechanism.

That fusion is the design's central bet: **an audit trail that is also the
recovery mechanism cannot quietly rot**, because the system stops working with
it. Compliance-only logging always rots, and nobody notices for a year.

## 4. 🗂️ Run vs case

A **run** is one goal, one plan, one lifetime — minutes. A **case** is a business
process — a clearing dispute, a supplier switch — spanning weeks and many runs,
correlated by business key.

The obvious alternative is one long-lived workflow per process, and it is a
versioning trap: a six-week workflow pins your code version for six weeks, and
every deploy needs a migration story for in-flight instances. Inverting it —
short runs, long cases — makes deploys free.

<figure class="diagram">
<svg viewBox="0 0 640 210" role="img" aria-labelledby="rc-t rc-d" xmlns="http://www.w3.org/2000/svg">
  <title id="rc-t">A case spans weeks; the runs inside it last minutes</title>
  <desc id="rc-d">One case, correlated by a business key, persists across weeks.
    Inside it, several short runs execute and finish — one on a reply arriving,
    one on a deadline, one on a human decision. Each run pins a code version only
    for its own lifetime, so a deploy between runs needs no migration.</desc>

  <line class="arrow" x1="20" y1="176" x2="620" y2="176" marker-end="url(#rh)"/>
  <text class="sub" x="20" y="198">day 0</text>
  <text class="sub" x="560" y="198">week 6</text>

  <rect class="box" x="20" y="26" width="600" height="44" rx="9"/>
  <text class="lbl" x="36" y="46">case · correlated by business key</text>
  <text class="sub" x="36" y="62">state, deadlines, worklist — outlives every run below</text>

  <g>
    <rect class="run" x="52"  y="104" width="86" height="40" rx="8"/>
    <text class="lbl" x="95"  y="122" text-anchor="middle">run</text>
    <text class="sub" x="95"  y="137" text-anchor="middle">admit</text>

    <rect class="run" x="238" y="104" width="86" height="40" rx="8"/>
    <text class="lbl" x="281" y="122" text-anchor="middle">run</text>
    <text class="sub" x="281" y="137" text-anchor="middle">reply</text>

    <rect class="run" x="424" y="104" width="86" height="40" rx="8"/>
    <text class="lbl" x="467" y="122" text-anchor="middle">run</text>
    <text class="sub" x="467" y="137" text-anchor="middle">deadline</text>
  </g>

  <g class="tick">
    <line x1="95"  y1="70" x2="95"  y2="104"/>
    <line x1="281" y1="70" x2="281" y2="104"/>
    <line x1="467" y1="70" x2="467" y2="104"/>
  </g>

  <text class="danger-lbl" x="186" y="92" text-anchor="middle">deploy — no migration</text>
  <path class="danger" d="M186 96 V150"/>

  <defs>
    <marker id="rh" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L10 5 L0 10 z" fill="currentColor" class="arrow"/>
    </marker>
  </defs>
</svg>
<figcaption>The runs are short by design. A six-week workflow would pin its code
version for six weeks and make every deploy a migration problem; short runs
inside a long case move that cost to one place — case state, written with the
version you read.</figcaption>
</figure>

The cost is that continuity must be explicit: case state, not local variables.
And because a case is shared by several runs, writing it takes the version you
read:

```rust
let (state, at) = cx.case_state().await?;
// ... a model call, taking as long as it takes ...
let at = cx.put_case_state(at, next).await?;   // refused if the case moved
```

## 5. 🎲 Disposition

When an outward call fails, one question decides everything: **did it reach the
other side?**

| | meaning |
|---|---|
| `DidNotHappen` | refused before dispatch, or rejected with the request intact |
| `InDoubt` | timed out, or the connection died mid-flight |
| `Landed` | it took effect; the response could not be used |

This is *not* the same question as "was the error transient". A refused
connection and a timed-out request are both transient — only one of them
provably never reached the peer. Gating retries on "is it transient" would refuse
to retry a payment whose connection was refused: correct-looking, and needlessly
useless.

`InDoubt` is undecidable from the journal alone, and no amount of retrying makes
it decidable. That is what `Recovery` is for.

## 6. 🔁 Recovery

What the *effect* says should happen when its outcome is unknown:

| | |
|---|---|
| `Retry` | a pure read, or an idempotent write |
| `Idempotent { key }` | the provider honours an idempotency key |
| `Reconcile` | **ask the provider what happened** |
| `RequiresOperator` | undecidable — escalate, never guess |

`Reconcile` is the interesting one, and it is the answer the industry usually
skips. The two standard responses to an unknown outcome are *retry and demand
idempotency* or *stop and page someone*. There is a third that every serious
provider supports: retrieve the payment intent by id; query the transfer by
reference. A probe turns an undecidable outcome into a decided one.

`RequiresOperator` is the **default for anything mutating**. An effect that
forgets to describe itself gets the conservative treatment, not the convenient
one.

## 7. 🧬 Effect group

The unit between an effect and a step: several calls that take together, or not
at all.

A step-level compensation is handed the step's **output**, and a step that failed
has none — so a step that reserved inventory, authorised a card and then failed
asks its own undo logic to guess. A group removes the guess. Each reversible
member registers the concrete call that reverses it, built from what that member
*actually returned*:

```rust
let mut g = cx.group("checkout", ["inventory", "notify"]).await?;

let hold = g.reversible("inventory", Reserve::new(sku), |out| {
    Release::new(out["hold"].as_str().unwrap_or_default())
}).await?;

g.deferred("notify", Notify::new("order confirmed"))?;   // does not run yet

g.commit(&[Invariant::new("the hold covers the order", covered)]).await?;
```

`commit` is the **frontier**: the last instant at which failing is free.
Invariants are checked there, and only then are deferred members released. Past
it there is no group, and a failure does not unwind — undoing a committed group
would reverse a decision the world has acted on.

**Why it matters:** `deferred` is the only place in this design where putting an
effect *inside* a transaction makes it safer rather than merely tidier. A member
that runs and is compensated leaves a trace someone saw — the email arrived, then
a correction arrived. A member held until the group is certain leaves none.

Doubt reverses nothing, and a group nobody settled does not commit: the runtime
reverses what an abandoned handle left standing, because a group that commits by
being forgotten would make the most consequential outcome the one you get by
writing nothing.

## 8. 🏷️ Labels

Every payload is opaque to the engine and never *unlabeled*:

```rust
pub struct Label {
    provenance:  BTreeSet<SourceId>,
    trust:       Trust,        // Trusted | Untrusted
    sensitivity: Sensitivity,  // Public | Internal | Confidential | Secret
}
```

Labels **join** on combination — trust degrades to the worse, sensitivity
escalates to the higher, provenance accumulates. Model output derived from
untrusted input stays untrusted, which is the rule most systems get wrong.

The label is applied **by the effect, at the source** — not by the caller. A
label the caller applies is a label the caller forgets, and this crate's own test
fixtures forgot it once, which made an existing guarantee untestable for months.

Every outbound effect must go through the sink gate — `cx.sink_with`, or the
two-arg `cx.sink` for an effect that binds its outbound value internally —
which holds the exact dispatched JSON to the labels being checked. An **egress
ceiling** limits sensitivity. A mutating sink either refuses any untrusted
argument, or declares protected JSON fields whose trust, provenance sources and
sensitivity are checked independently — so an untrusted memo may accompany a
trusted recipient without acquiring authority.

A provenance source names the **concrete** origin, not a family of effects: a
tool call's output carries `tool://server/name`, a model completion
`model:{provider}/{model}`, a commission `agent/{capability}`. That precision
is what a source rule can *say* — "the recipient must come from the CRM
lookup" is unsatisfiable when every granted tool answers under one family
name, because the rule then admits whichever tool an injected prompt reached
first.

`cx.release` is the only way to improve a label. Its typed request names the
trust and/or sensitivity dimension, exact fields, destination, basis and
evidence; policy authorizes `data:release`; the journal records the decision.
The returned value remains labeled and keeps its provenance.

## 9. 📐 The plan is an authorization graph

A plan is compiled from **trusted input only**, frozen, content-addressed, and
journaled. Because it is built before any untrusted data is ingested, injected
content cannot influence it — and every argument declares where it must come
from:

```yaml
args:
  payload:   { source: s0.output, path: "$.intervals" }
  tolerance: { source: const, value: 0.01 }
```

The executor rejects any argument whose journaled provenance does not match.
Labels say *"this is untrusted"*; source binding says *"this must have come from
step s0"* — strictly stronger, and free at replay time because both graphs are
already in the journal.

### The unit of concurrency is the plan node

This is a design statement, not an API detail, and it is the thing to know
before designing around `commission`.

`StepCtx::commission` takes `&mut self` and is singular, and there is no
`join`/`select` helper anywhere — so it is easy to conclude that in-run fan-out
is impossible and to put the concurrency above the runtime. That conclusion is
wrong, and it has been reached and written down as settled by at least one
evaluation.

Independent nodes are a **ready set**: `PlanIR::fan_out` dispatches every branch
concurrently inside one run, each with its own journal slice, feeding one
aggregator keyed by the capability that produced each result.

```rust
use agentplane::core::PlanIR;

let plan = PlanIR::fan_out(["risk.score", "fraud.check"], "decide");
let out = rt.run_plan(plan, Tainted::trusted(input)).await?;
```

`PlanIR` lives in `agentplane::core`, not `agentplane::plan` — the `plan` module
holds `Contract`, `Replanner` and `validate`. That split is a fair share of why
the type gets missed.

Determinism does not depend on completion order: admission happens in
deterministic ready order, outcomes are applied in deterministic ready order,
and every branch's effects are keyed by its own step. What is deliberately
absent is `race` — first-wins-cancel-the-rest would abandon an announced effect
with no terminal record, which is the unknown outcome the effect protocol exists
to prevent.

`run_plan` is the entry point; `Contract` validates the graph before the first
step runs.

---

## 10. ⏳ Human oversight and obligations {#oversight}

An **obligation** is a named deadline attached to a case. It is the primitive for
work that is due rather than work that is slow, and the distinction is the whole
point: a missed retry is an inconvenience, a missed regulatory window is a
breach. The two must not share a mechanism.

```rust,ignore
use std::time::Duration;

// Resolved once against the deployment's Calendar and journaled, so a replay
// never recomputes the due date under a changed holiday table.
let due = cx
    .deadline("aperak", &DeadlineSpec::days(1), Some(Duration::from_secs(3600)))
    .await?;

cx.meet_deadline("aperak").await?;    // discharged
cx.cancel_deadline("aperak").await?;  // no longer applicable
```

`DeadlineSpec::{minutes, hours, days}` are the rules the built-in `WallClock`
understands, and it deliberately understands **no** others. *Five working days,
at 17:00, excluding public holidays observed in any federal state* is a
`DeadlineSpec::new("working-days", json!({ "n": 5 }))` resolved by a `Calendar`
the deployment supplies — and a calendar that does not implement a rule
**refuses** it rather than approximating, because a wrong working-day answer is
worse than no answer: it looks right. The calendar's digest is journaled beside
the resolved instant, so a changed holiday table is a different ruleset rather
than a retroactively different deadline.

Four properties carry it:

* **The instant is journaled, not recomputed.** A business calendar changes;
  history does not. Replaying last quarter under this quarter's holiday table
  would produce a different due date for the same run.
* **A case cannot close while an obligation is open.** Closure is a structural
  check, not a convention somebody remembers.
* **`warn_before` is separate from the deadline**, so *approaching* and *breached*
  are different events reaching different people.
* **The sweep that breaches one writes its own history.** Breaching an obligation
  is the most consequential thing the plane does *without being asked*, and there
  is no run to explain it — so a tick that decides anything writes into a sealed
  run of its own. State alone cannot tell *the sweep breached this at 02:00* from
  *somebody set it*.

**Human tasks** are the other half. `oversight.approval: required` in a manifest
makes a declarative agent register its obligation, open a worklist task carrying
its **actual answer**, and return only once a person decides. Nothing durable is
written until then — memory formation happens *after* approval, because a memory
formed from a refused answer is read by the next run as established fact. `TaskStore::claim` enforces four-eyes, and the
wire types deliberately carry **no actor field** — who is acting comes from the
request's identity, never from its body, so an approval cannot be forged by the
thing being approved.

Unattended expiry needs two explicit opt-ins: a declared `on_expiry: proceed`
*and* `allow_unattended: true`. Acting with no human is a greppable decision
somebody made rather than an enum variant they picked off a list.

See the [manifest reference](@/docs/manifest.md#spec-oversight) for the
declaration, and `api::{Worklist, TaskView, DecisionRequest}` for the HTTP
surface.

## 11. 🧵 `StepCtx` — the surface you program against {#step-context}

Everything above reaches your code through one type. A skill receives a
`StepCtx`, and **every method on it that touches the world is a journaled
effect** — which is why the list is worth reading as a whole rather than
discovering one call at a time.

| | |
|---|---|
| `now()`, `rng()`, `note(text)` | the clock, the per-step RNG, and a line in the chain — all reproduced on replay |
| `effect(e)` | any effect with no labelled value to bind |
| `sink_with(&value, build)` | an outbound effect **with** its labelled arguments, built from them in one motion — the primary dispatch shape, and the only path that can carry protected fields |
| `sink(e, &value)` | the same gate, for an effect built elsewhere or one that binds its outbound value internally |
| `complete(&prompt)`, `complete_with(&prompt, tune)` | a completion on the governing manifest's own model, through the plane's registered driver — no provider `Arc` in the skill |
| `release(request)` | typed, policy-authorized improvement of a label |
| `deadline`, `meet_deadline`, `cancel_deadline` | obligations |
| `sleep(d)`, `await_event(&spec)`, `task(&spec)` | durable suspension — a waiting run is a row, not a thread |
| `case_state()`, `put_case_state(v, s)`, `set_case_status(s)` | shared state across runs, version-checked |
| `remember`, `recall`, `compact`, `form_memories`, `sweep_expired_memories` | governed memory |
| `embed`, `semantic_recall` | vectors and ranking, both journaled |
| `store_blob(bytes)`, `blobs()` | content-addressed payloads |
| `fetch_media(..)` | a governed remote fetch, SSRF controls and all |
| `draw(..)` | spend against a standing authorization |
| `commission(capability, input)` | hand work to another agent on this plane |
| `group()` | a transactional effect group |
| `manifest()`, `budget()`, `run_id()` | what this agent was declared to be, and what it has spent |

Two things about `commission` are worth stating because every multi-agent
adopter asks: it takes `&mut self` and is **singular**, so a step delegates to
one peer at a time. That is deliberate rather than unfinished. `StepCtx` is the
deterministic admission boundary — journal position, policy and budget decisions
all pass through it — and handing out concurrent borrows would move those
decisions outside it. **Fan out above the runtime**: independent opinions are
better as independent runs with their own journals, which is also what makes each
one separately replayable. There is no `join`/`select` helper and there
deliberately will not be one.

## 12. 📄 Coded and declarative agents {#agent-tiers}

A skill you write is one way to have an agent. The other is to write no code:
`spec.execution.kind` names a behaviour the runtime supplies, so the digest
covers the agent *entirely* rather than only its boundary.

| `kind` | The loop | Reach for it when |
|---|---|---|
| `completion` | one model call, answered in the declared shape | the task is a prompt and a result shape |
| `tool-calling` | call tools until the model stops asking | the shape of the work *is* the discovery |
| `planned` | plan once over trusted input, then execute with data routed by reference | the shape is known up front and the data is hostile |

The set is closed on purpose: a config format whose behaviours are open-ended
is one nobody can review. Everything else in this page applies unchanged —
every turn, tool call and parse is an ordinary journaled effect, so a strict
replay reassembles the whole thing without calling anyone.

## The pattern underneath all of them 🔍

Nearly every decision here has the same shape: **make the dangerous thing
unrepresentable, rather than detectable.**

- A widened delegation is not "validated" — `Delegation::delegate` refuses to
  construct one, so there is no code path that must remember to check.
- A lost case update is not "warned about" — the write takes a version, so a
  blind overwrite cannot be spelled.
- A quorum's split panel has no `majority()` accessor, so "pick whichever side
  had more votes" is not something a caller can accidentally do.
- `BatchStatus` has no `Succeeded` variant, so "mostly worked" cannot be reported
  as success.

The pattern has one edge worth knowing about, because it is invisible in a diff:
**deserializing is a construction path too.** A type whose invariant lives in a
fallible constructor, with private fields to keep everyone else out, hands the
bad state straight back if it also derives `Deserialize` — and a value reaches a
runtime from a credential, a store row or a journal record far more often than
from a call to that constructor. `Delegation`, `TenantId` and `Quorum` therefore
deserialize *through* their constructors, so a chain that widens, a tenant name
carrying a key-scope separator, or a panel needing nobody is a read error rather
than a value. If you write a validated type in your own code, do the same.

When you meet an API here that seems to make something inconvenient, that is
usually why.

## Where next 🧭

| | |
|---|---|
| 🏗️ | [Architecture](@/docs/architecture.md) — how each of these is implemented |
| 🍳 | [Cookbook](@/docs/cookbook.md) — using them |
| 🔐 | [Security model](@/docs/security.md) — the trust boundary, its limits, and worked Cedar policies |
| 📄 | [Manifest reference](@/docs/manifest.md) — every field an agent declaration may carry |
| 🧪 | [Testing agents](@/docs/testing.md) — a fake provider, fault injection, and the replay assertion |
