# 🧠 Concepts

The vocabulary. Eight ideas; everything else in the crate is a consequence of
one of them. Read this once and the rest of the documentation stops needing
footnotes.

---

## 1. ⚡ Effect

Anything the deterministic zone cannot reproduce by thinking: a model call, a
tool call, the clock, randomness, a case-state read, resolving a deadline.

An effect is **announced before it acts and recorded after**. That order is the
whole protocol — announcing first is what makes a crash mid-call detectable at
all, because the journal then holds an intention with no outcome.

```rust
let answer = cx.effect(ModelCall::new(provider, model, prompt)).await?;
```

Live, that performs the call and journals the result. On replay, it performs
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

## 7. 🏷️ Labels

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

Two gates run at every sink: an **egress ceiling** (a value's sensitivity may not
exceed what the sink is cleared for) and a **taint gate** (untrusted data may not
reach a *mutating* sink without an explicit, journaled declassification).

## 8. 📐 The plan is an authorization graph

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

---

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

When you meet an API here that seems to make something inconvenient, that is
usually why.

## Where next 🧭

| | |
|---|---|
| 🏗️ | [Architecture](architecture.md) — how each of these is implemented |
| 🍳 | [Cookbook](cookbook.md) — using them |
| 🔐 | [Security model](security.md) — the trust boundary and its limits |
