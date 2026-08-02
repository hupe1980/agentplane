+++
title = "Cookbook"
description = "Task-shaped recipes: build an agent, keep large bytes out of the chain, require a human, undo work when a later step fails."
weight = 3
+++

Task-shaped recipes. Each one states the trap it avoids, because most of these
have an obvious wrong version that works until it doesn't.

For the vocabulary — effect, disposition, label — see
[concepts](@/docs/concepts.md). For why any of it is shaped this way, see
[architecture](@/docs/architecture.md).

---

## 🧬 Build an agent

An agent here is not a class you subclass. It is **skills** (what it can do), a
**plan** (which capability runs when), and a **policy** (what it may do) — held
together by a `Runtime` that journals every step.

Start with a skill. The system prompt lives in the prompt value, not in a
separate setting, because the prompt is part of the effect key: change the
instruction and a replayed run reports divergence instead of quietly answering a
different question.

```rust
use agentplane::core::{Outcome, Sensitivity, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::model::{ModelCall, ModelId, ModelProvider};
use agentplane::runtime::StepCtx;
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Debug)]
struct Triage {
    provider: Arc<dyn ModelProvider>,
}

#[async_trait::async_trait]
impl Skill for Triage {
    fn descriptor(&self) -> SkillDescriptor {
        // What it *provides* is a capability, not its own name. Plans bind
        // capabilities to skills, so what a step needs is decoupled from who
        // provides it — and swapping the implementation is a binding change.
        SkillDescriptor::new("triage").provides("ticket.triage")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let call = ModelCall::new(
            Arc::clone(&self.provider),
            ModelId::new("anthropic", "claude-sonnet-4-5"),
            json!({
                // `system` is the instruction; each driver spells it the way its
                // API does — top-level `system` on Anthropic, `instructions` on
                // OpenAI Responses. Write it once.
                "system": "You triage support tickets. Answer only with the JSON asked for.",
                "messages": [{ "role": "user", "content": input.peek() }],
            }),
        )
        // The ceiling that matters for a hosted model: a prompt assembled from a
        // secret is an exfiltration whether or not anyone meant it.
        .with_max_sensitivity(Sensitivity::Internal)
        .expecting(json!({
            "type": "object",
            "properties": { "severity": { "type": "string" } },
            "required": ["severity"],
        }));

        let completion = cx.effect(call).await?;
        Ok(Outcome::done(completion.map(|c| {
            c.structured.clone().unwrap_or(Value::Null)
        })))
    }
}
```

Then wire the skills together and run. A single-capability agent needs no plan
at all; a multi-step one gets a `PlanIR`.

```rust
use agentplane::core::{ArgSource, PlanIR, PlanNode, StepId};
use agentplane::journal::JournalStore;
use agentplane::runtime::Runtime;
use agentplane::store::RedbStore;

let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);

let rt = Runtime::builder(Arc::clone(&store))
    .owner("support-plane")
    .skill(Triage { provider: Arc::clone(&provider) })
    .skill(Notify)
    .build();

// One capability: no plan needed.
let out = rt.run("ticket.triage", json!({ "text": "printer on fire" })).await?;

// Several: name the order, and what feeds what.
let plan = PlanIR::new(vec![
    PlanNode::new(0, "ticket.triage").arg("input", ArgSource::run_input()),
    PlanNode::new(1, "ticket.notify")
        .arg("triage", ArgSource::node(StepId(0)))
        .terminal(),
]);
let out = rt.run_plan(plan, json!({ "text": "printer on fire" })).await?;
```

**The trap:** putting the system prompt in a config file that the run does not
hash. The instruction is half of what the model was asked; if it can change
without the effect key changing, a replay reads back an answer to a question
that no longer exists, and nothing reports it.

**Multimodal** needs no extra API — a `messages` array is passed through
verbatim, so the provider's own image and document blocks work as written. Two
things to know before sending large media, both consequences of the journal
being the record of what happened:

- The prompt is stored **in the journal**, which is append-only and hash-chained,
  so an inlined image is kept forever and cannot be pruned. A record over
  `Record::MAX_RECORD_BYTES` (1 MiB) is **refused**, not truncated — put the
  bytes in a blob store and journal the digest instead (below).
- A media **URL** is fetched by the *provider*, not by this plane, so it does not
  pass the egress allowlist ([security](@/docs/security.md)). If where data may come
  from is part of your threat model, fetch it yourself in a skill and inline the
  bytes.

---

## 📦 Keep large bytes out of the chain

The journal refuses a record over 1 MiB, because an append-only hash chain can
never take it back. Bytes that big go in a content-addressed store, and the
*digest* goes in the journal.

```rust
use agentplane::blob::{BlobStore, MemoryBlobs};      // or OpenDalBlobs, feature `opendal`

let blobs: Arc<dyn BlobStore> = Arc::new(MemoryBlobs::new());

// The store hashes the bytes; a caller does not get to say where they live.
let digest = blobs.put(&image_bytes).await?;

// Journal the address, not the payload.
let call = ModelCall::new(provider, model, json!({
    "system": "describe the attached screenshot",
    "screenshot": digest.to_hex(),
}));
```

For real deployments, `OpenDalBlobs` puts them on anything
[OpenDAL](https://opendal.apache.org) reaches — filesystem, S3, GCS, Azure:

```toml
agentplane = { version = "0.2", features = ["opendal"] }
```

```rust
use agentplane::blob::OpenDalBlobs;

let op = opendal::Operator::new(opendal::services::S3::default().bucket("agent-blobs"))?;
let blobs = OpenDalBlobs::new(op, "runs");
```

**The trap:** a reference that is not a digest. This is the
[claim check](https://docs.temporal.io/external-storage) pattern every durable
engine converges on, with one difference that carries the weight — because the
address *is* the hash, the chain still commits to the exact bytes it does not
contain. `get` re-hashes before returning, so a blob edited on disk is refused
rather than served. A token pointing at mutable storage would move the
tamper-evidence boundary without saying so, and the journal would still look
sound.

**What it does not solve:** retention. The chain proves a blob was not altered;
it cannot conjure one somebody deleted. A missing blob reports `NotFound` — a
configuration problem — rather than a corruption, precisely so the two are not
confused when someone is paged.

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
