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
  6 | Declassified      | –          | d13…      | 7f2…
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
* **Split views** — one history to one auditor, a different one to another —
  remain undetectable without a witness that has seen both.
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
- `ContextOverflow` — the work exceeds one context window.
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
  journal/   records, hash chain, replay cursor, upcasters
  case/      CaseStore, EventStore, TaskStore contracts
  plan/      the plan contract: what a plan must satisfy to run at all
  store/     redb and Postgres backends, journal and cases alike
  runtime/   StepCtx, effect protocol, executor, sweeper, built-in effects
  batch/     batch runs: item source, outcomes, the BatchStore contract
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

### A2A (`a2a`)

A2A tasks are long-running and stateful, so "did the peer act?" is not a detail.

| Failure | Known | Disposition |
|---|---|---|
| DNS, TLS, connection refused | nothing was written | `DidNotHappen` |
| timeout, or the connection died after the write | it may have arrived | `InDoubt` |
| HTTP 401/403/404; JSON-RPC parse/method/params; A2A `-32006..=-32001` | read and declined | `DidNotHappen` |
| HTTP 5xx; JSON-RPC `-32603` | arrived; whether it acted is unknown | `InDoubt` |
| a `Task` in state `failed` | it acted and says so | `Landed` |

The two expensive rows are the last two. `-32603` can be raised *after* a peer
has started work, so treating it as a clean decline is how a half-finished
transfer gets sent twice. Symmetrically, a task that comes back `failed` is not
in doubt — the peer has said it acted, so `Recovery` has nothing to resolve.

The delegation chain travels under a declared extension URI rather than being
smuggled into a free-form field, so a peer that does not understand it still
receives a well-formed message. It is a **claim, not an attestation**: a peer
authorizing on it is trusting whatever the last hop wrote. Signing it is designed
and not built.

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
checked-in table of 20 mutations — one per load-bearing guarantee — applies each,
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
