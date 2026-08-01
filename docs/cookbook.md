# 🍳 Cookbook

Task-shaped recipes. Each one states the trap it avoids, because most of these
have an obvious wrong version that works until it doesn't.

For the vocabulary — effect, disposition, label — see
[concepts](concepts.md). For why any of it is shaped this way, see
[architecture](architecture.md).

---

## 🤖 Call a model

```rust
use agentplane::model::{ModelCall, ModelProvider};

let call = ModelCall::new(provider, model_id, json!({ "task": "triage", "ticket": input.peek() }));
let completion = cx.effect(call).await?;   // Tainted<Completion>
```

**The trap:** treating a failed call as free. A model call has a third state
between success and failure — it ran, generated four hundred tokens, and the
stream died. The provider bills for those tokens. If the ceiling counts them as
zero, a retry loop against a flaky provider spends real money against a limit
reading nothing.

The drivers stream by default precisely so a severed call can report what it
burned. You do not have to do anything to get that.

## 📐 Ask for structured output

```rust
let call = ModelCall::new(provider, model, prompt).expecting(schema);
let completion = cx.effect(call).await?;
let value = completion.peek().structured.as_ref().expect("a schema was declared");
```

The schema goes to the provider's own constrained-decoding mode, where it is
enforced **during** generation. A schema applied afterwards rejects an answer you
have already paid for.

**The trap:** assuming every model supports it. They don't, uniformly. Set the
mode per *model*, not per driver — one driver serves many models over one key:

```rust
let provider = Anthropic::new(key)?
    .structured_via_for("claude-legacy-1", SchemaMode::ForcedTool);
```

## ⏸️ Wait for a reply that may arrive first

```rust
let ack = cx.await_event(
    &AwaitSpec::new("acknowledgement.received", "acknowledgement")
        .correlate(CorrelationKey::new("document", &document)),
).await?;
```

**The trap:** the arrive-before-wait race. The obvious implementation matches
inbound events against registered subscriptions on arrival and drops a miss — so
a reply that beats its run to the wait is lost, and the run waits forever for
something that already happened. A fast counterparty wins that race routinely.

Delivery here is **buffer-first**: every event is durably buffered on arrival,
and a wait consults the buffer *after* registering. Both orderings converge on
one delivery. You get this for free; the recipe is just to use `await_event`
rather than rolling your own.

Every wait must name a deadline. An unbounded wait is a plan-contract violation,
which is how "the process just stalled" stops being a category of incident.

## 👤 Require a human, with four eyes

```rust
let decision = cx.task(
    &TaskSpec::new("rejection-handling", justification, "decision")
        .role("compliance-officer")
        .excluding("agent:switch-bot")     // the proposer cannot approve
        .on_expiry(OnExpiry::Escalate),
).await?;
```

**The trap:** letting the request name the actor. Four-eyes is enforced against
an actor, so a body that can name one is a bypass. The actor comes from the
authenticated caller, and the wire type has no field for it — a caller cannot
spoof what they cannot express.

**The other trap:** `OnExpiry::Proceed` — acting because nobody answered — needs
a *second* opt-in (`allow_unattended()`). One enum variant among four is too easy
to pick off a list, and "the human didn't answer so we did it anyway" should be
greppable.

## 😴 Sleep for five working days

```rust
let at = cx.deadline("klaerung", &DeadlineSpec::new("working-days", json!({"n": 5})), None).await?;
```

**The trap:** `tokio::sleep`. A held task forgets everything on restart, and a
process waiting five working days cannot be a thread. `cx.sleep`/`cx.deadline`
persist the frame and let a sweep wake the run — a row on disk, not a task.

**The subtler trap:** recomputing the instant on replay. Calendars change — a
corrected holiday table, a new regulatory notice — and recomputation would
silently move a legally binding deadline under an audit. The *resolved instant*
is journaled, so it is the fact forever.

Domain knowledge lives in your `Calendar` implementation. The engine does not
know what a working day is.

## ↩️ Undo work when a later step fails

```rust
// Declare what a step's place in the unwind is.
Compensation::Compensatable   // reversible
Compensation::Pivot           // the point of no return; nothing before it unwinds
Compensation::Unnecessary     // nothing to undo
Compensation::Undeclared      // the default — judged on journal evidence
```

**The trap:** assuming an undeclared step has nothing to undo. `Undeclared` is
resolved by reading the journal for mutating effects in that step's forward
phase. A step that changed nothing has nothing to undo and the journal proves it;
a step that *did* change something and declared nothing **stops the unwind and
escalates**, naming the step. Silently skipping a charge while reversing
everything around it is exactly what the mechanism exists to prevent.

**A run in doubt is never unwound.** Compensating a payment that may never have
gone out creates a refund for money nobody took.

## 🔐 Restrict where the plane may connect

```rust
let egress = Egress::new().allow("api.anthropic.com");
let provider = Anthropic::new(key)?.egress(egress);
```

Refused **before the request is built** — nothing sent, nothing metered, and the
failure is `DidNotHappen`.

**The trap:** wildcards. `*.example.com` reads as a convenience and grants every
host anybody can register under a domain, including one an attacker controls the
moment a subdomain is left dangling. There are no wildcards, deliberately.

## ⚖️ Judge a high-stakes step more than once

```rust
let quorum = Quorum::new(2, ["correctness", "policy-conformance", "arithmetic"])?;
```

**The trap:** running the same judgement three times and taking the majority.
Identical prompts against the same model share their blind spots, so they agree
confidently and wrongly about exactly the cases a second opinion was for. Lenses
must be *distinct*, and a repeated lens is refused at construction.

**The other trap:** resolving a split panel. There is no `majority()`. A panel
that could not agree is the strongest signal a person should look, and resolving
it silently converts *we do not know* into *approved*.

## 🧪 Test a skill without a model

```rust
use agentplane::testkit::FakeProvider;

let provider = FakeProvider::new();
provider.will_fail(ModelError::Interrupted { model, usage, detail: "reset".into() })
        .will_say("approved");

// ... run ...
assert_eq!(provider.calls(), 1, "replay must not ask again");
assert!(provider.script_exhausted(), "the run made fewer calls than this test assumed");
```

**The trap:** a fake that answers for free. Every budget test then passes over a
runtime that has stopped counting. `FakeProvider` derives usage from the prompt —
monotonic, never zero — and scripted failures carry usage of their own, which is
what makes the metered-failure path testable at all.

It refuses to answer as a real provider (`fake/gpt-5`, not
`anthropic/claude-opus-5`), because the provider slug is in the hash-chained
effect key and a fake cassette that reads as a real one corrupts the corpus later
changes are measured against.

## 💥 Test what a crash does

```rust
use agentplane::testkit::{Fault, Faulty, Schedule};

let store = Faulty::new(inner, Schedule::seeded(42).then(Fault::CommittedThenLost));
```

**The trap:** thinking a truncated journal covers it. Every *prefix* of a journal
is a clean crash, and `tests/engine/simulation.rs` sweeps all of them. What a
prefix structurally cannot reach is the **unclean** one: a write that committed
while the caller was told it failed. History is then *ahead* of what the process
believes it wrote, and blindly retrying the append is how a chain acquires two
records claiming one position.

## 🗄️ Bring your own store

Implement `JournalStore`, then run the contract against it:

```rust
let report = agentplane::testkit::conformance::check(&|| { /* build a fresh store */ }).await;
report.assert_conforms("MyStore");
```

**The trap:** writing your own tests for it. A new backend gets whatever tests
its author thought of — and those are the ones they were already thinking about
while writing it, so the invariant they misread is by construction the one with
no test. The battery states the contract once and runs against every backend,
including a racing check no sequential test can replace.

## 🔎 Audit a store you do not trust

```rust
let report = agentplane::audit::audit(&store, &runs, &Evidence {
    prior: Some(&checkpoint),   // handed over earlier — this is what detects deletion
    verifier: Some(&verifier),
    require_signatures: true,
}).await?;
report.assert_complete();
```

**The trap:** reading "no findings" as "verified". `assert_complete` fails on a
*skipped* check as well as a failed one. Without a prior checkpoint, deletion is
undetectable — every remaining run still verifies — so the report carries
`not_checked` as prominently as its findings.
