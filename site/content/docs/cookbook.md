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
        let prompt = input.map(|input| json!({
            // `system` is the instruction; each driver spells it the way its
            // API does — top-level `system` on Anthropic, `instructions` on
            // OpenAI Responses. Write it once.
            "system": "You triage support tickets. Answer only with the JSON asked for.",
            "messages": [{ "role": "user", "content": input }],
        }));
        let call = ModelCall::new(
            Arc::clone(&self.provider),
            ModelId::new("anthropic", "claude-sonnet-4-5"),
            prompt.peek().clone(),
        )
        // The ceiling that matters for a hosted model: a prompt assembled from a
        // secret is an exfiltration whether or not anyone meant it.
        .with_max_sensitivity(Sensitivity::Internal)
        .expecting(json!({
            "type": "object",
            "properties": { "severity": { "type": "string" } },
            "required": ["severity"],
        }));

        let completion = cx.sink(call, &prompt).await?;
        Ok(Outcome::done(completion.map(|c| {
            c.structured.unwrap_or(Value::Null)
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

**Multimodal** uses the provider's inline image and document shapes. Inline
bytes and OpenAI data URLs work; provider-native remote URL blocks are refused
before dispatch. Two things to know before sending media, both consequences of
the journal being the record of what happened:

- The prompt is stored **in the journal**, which is append-only and hash-chained,
  so an inlined image is kept forever and cannot be pruned. A record over
  `Record::MAX_RECORD_BYTES` (1 MiB) is **refused**, not truncated — put the
  bytes in a blob store and journal the digest instead (below).
- A media **URL** would be fetched by the provider, outside this plane's egress
  allowlist and journal, so the model effect and built-in drivers reject it.
  Enable `media` and fetch it through `cx.fetch_media`: every DNS answer and
  redirect is checked, the checked addresses are pinned into the connection,
  and only a digest enters history.

“Only a digest” applies to the **input artifact and effect identity**. The model
completion is still journaled for replay and a provider may quote, transcribe,
or otherwise reproduce media content in that output. Governed media prevents
the original blob from becoming immortal by construction; it cannot promise
that generated output contains no personal data. Apply output classification,
minimization, and retention policy accordingly.

```rust
use agentplane::media::{GovernedMedia, MediaPolicy};

let media = GovernedMedia::new(
    MediaPolicy::new()
        .allow_host("cdn.example.com")
        .allow_media_type("image/png")
        .max_bytes(5 * 1024 * 1024),
);

// URL selection is authority-bearing: untrusted/model-selected URLs need a
// typed policy-authorized release before this trusted selector can be used.
let fetched = cx
    .fetch_media(&media, Tainted::trusted("https://cdn.example.com/chart.png".to_owned()))
    .await?;

// Mapping preserves the fetched artifact's untrusted label and sensitivity.
// The prompt contains a digest marker, not the bytes.
let media_grant = fetched.peek().clone();
let prompt = fetched.map(|artifact| json!({
    "input": [{ "role": "user", "content": [artifact.openai_image()] }]
}));
let call = ModelCall::new(provider, model, prompt.peek().clone())
    .with_max_sensitivity(Sensitivity::Internal)
    .with_media(blobs.clone(), [&media_grant]);
let answer = cx.sink(call, &prompt).await?;
```

Run `cargo run --example media_run --features redb,testkit,media` for the
offline, executable half of this contract: provider-URL refusal, an exact
digest/type capability, live-only materialization, untrusted output, and strict
replay with unchanged blob-read and provider-call counters. The example does
not fake DNS or HTTP and says so explicitly; a fake connector cannot prove DNS
pinning or per-hop redirect authorization.

The default retention regime requires the run to belong to a case and links the
digest automatically. Outside a case, name the lifecycle controller explicitly
with `external_retention("policy/version")`; an unnamed unlinked blob is refused.
HTTPS/443, no retries, identity encoding and three redirects are the defaults.
Cleartext HTTP, another port, or retries each require a separate explicit grant.
Automatic redirects, proxies, referrers, cookies and content decompression are
not used. Common passive formats are checked by magic/parse; other exact media
types require a versioned `MediaValidator` such as a malware scanner.

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

**Store through the context, not the store.** `cx.store_blob` records which case
the bytes belong to — a digest cannot be reversed later to find that out, so the
association has to be made now or never:

```rust
let digest = cx.store_blob(&image_bytes).await?;   // linked to this case
```

**Erasing later.** A request names a person, which resolves to a case — never to
a digest. So erase by case:

```rust
use agentplane::blob::erase_case;

let n = erase_case(blobs.as_ref(), cases.as_ref(), case, now, "art-17 request").await?;
```

Every blob that case produced is tombstoned; other cases are untouched, even
ones holding identical bytes. For a single artifact, `blobs.expire(digest, …)`
does the same for one address.

The chain still verifies — it committed to the digest, not the content — so you
keep the proof of what happened without keeping the data. A read afterwards
returns `BlobError::Expired` with the date and reason, never `NotFound`:
retention doing its job and a blob nobody can account for are different answers,
and only one of them is worth waking somebody for.

**What it does not solve:** scheduling, and anything already inside a record. There
is no TTL — you decide when to call `expire`. And personal data written into a
*journal record* cannot be removed at all, because the chain is append-only. The
1 MiB refusal keeps bulk content out by construction, but a short string still
fits, so keep identifiers out of records deliberately.

---

## 📄 Write an agent with no Rust at all

If the agent is a prompt, a model and a result shape, the code adds nothing a
reviewer can check — and it costs something they would want: the digest then
covers only part of the agent.

```yaml
# summariser.yaml — this file *is* the agent
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: summariser, version: "1.0.0" }
spec:
  execution: { kind: completion }
  identity:
    role: "Summarise a support ticket"
    constraints: "One sentence. No speculation."
  capabilities: { provides: [support.summarise] }
  models:
    privileged: { provider: anthropic, model: claude-sonnet-5 }
  output:
    schema:
      type: object
      required: [summary]
      properties: { summary: { type: string } }
  budgets: { max_tokens: 10000 }
```

```rust
let m = Manifest::parse(&std::fs::read_to_string("summariser.yaml")?)?;

// The only Rust: which driver answers to a provider name. That is deployment
// wiring — an agent's declaration must not change when its API key does.
let rt = Runtime::builder(store)
    .provider("anthropic", anthropic_driver)
    .agent(Agent::new(&m))
    .build();

let out = rt.run("support.summarise", ticket).await?;
```

Add a human to the loop without writing the call:

```yaml
spec:
  execution: { kind: completion }
  oversight:
    approval: required
    approvers: [role:compliance-officer]
    deadline: klaerung        # your Calendar decides what that means
    on_expiry: deny           # the default; `proceed` needs allow_unattended
```

The agent opens a task carrying **its answer** as the proposal — not a
description of it — and returns only on approval. Needs a case and `.tasks(store)`.

**The trap: expecting `kind` to grow keywords.** It will not. `completion` is one
model call; a tool-calling loop will be another named kind when the model layer
can surface tool calls. What you will never find here is sequencing, conditions
or loops — config that encodes control flow stops being config and becomes a poor
programming language. If you need structure, use a plan, which is
contract-validated data.

**And no conditions.** "Require approval when severity is high" is a predicate,
and a predicate is one step from an `if`. An agent whose oversight depends on what
it found is a skill — written in a language built for decisions.

**The second trap: a provider name that is not registered.** It is refused, not
defaulted to whatever driver happens to be present — falling back would run the
agent on a model its own declaration does not name.

`cargo run --example blog_room` has two of these, and one orchestrator that is
still Rust because it delegates.

---

## 📜 Govern a skill you *did* write

The other tier. When the agent does real work — a solver, a database, something a
model cannot be — the behaviour is a `Skill`, and the manifest governs its
**boundary**: which model, which tools, what it may spend.

```toml
agentplane = { version = "0.2", features = ["manifest"] }
```

Everything in the zero-Rust manifest above applies; drop `spec.execution` and add what a coded agent needs:

```yaml
spec:
  # no `execution:` — the behaviour is a skill you registered
  topology: { mode: single, role: specialist }
  security:
    max_sensitivity_egress: internal
    max_delegation_depth: 2
  models:
    privileged:  { provider: anthropic, model: claude-sonnet-5 }
    quarantined: { provider: anthropic, model: claude-haiku-4-5-20251001 }
  tools:
    - ref: "mcp://validator/apply_correction"
      mutates: true
      max_sensitivity: internal
            protected_fields:
                - path: /target
                    require_trusted: true
                - path: /correction
                    allowed_sources: [effect:model.complete]
  budgets:
    max_tokens: 120000
    max_minor_units: 250      # cents, never a float
```

```rust
use agentplane::manifest::Manifest;
use agentplane::runtime::Agent;

let m = Manifest::parse(&std::fs::read_to_string("auditor.yaml")?)?;
// The manifest binds to *an agent*, not to the plane: a runtime hosts several,
// each separately declared and separately bounded.
let runtime = Runtime::builder(store)
    .agent(Agent::new(&m).skill(Auditor))
    .build();

// "Which declaration governed this run" stays answerable after the file has
// moved on — including the prompt, because `spec.identity` is inside the digest.
let governed_by = m.digest()?;
```

Your skill reads the declaration from its context rather than holding a copy —
**an agent has skills**, not the other way round:

```rust
let m = cx.manifest().expect("this agent runs under a manifest");
let system = m.spec.identity.as_ref().map(Identity::system_prompt).unwrap_or_default();
```

**What binds, and what does not.** This is the part worth knowing precisely,
because a field read by convention is two copies of one decision:

| | |
|---|---|
| `models`, `tools` | **enforced** — an effect naming one the file never listed is refused before dispatch and journaled under `effect:declared`; tool protected-field rules are digest-covered and must exactly match the live catalogue |
| `budgets` | **enforced** by the ledger |
| `capabilities.provides` | **enforced** — `build()` panics if no skill provides it |
| `max_sensitivity_egress` | **enforced** — every sink uses the stricter of its own ceiling and the manifest ceiling |
| `max_delegation_depth` | **enforced** — checked against the configured identity and every delegating sink before dispatch |
| `output.schema` | carried to the provider and into the effect key, never validated against a result |

There is no `security.pattern` field. Native skill code cannot be proven to
follow an architectural injection pattern, so the schema refuses to imply that
it can.

`effect:declared` is deliberately a different action from a Cedar denial: a policy
denial is the deployment's rules saying no to something the agent was built to
do; a manifest refusal is the agent doing something its own reviewed file never
mentioned, which is a defect in the code.

**The trap: a permissive parser.** `max_tokns: 100` is not "a ceiling with a
typo" — in a format that ignores unknown fields it means **no ceiling at all**, in
the one document whose purpose was to make the ceiling reviewable. Every struct
is `deny_unknown_fields`. For the same reason a manifest with *no* `budgets` is
refused: unbounded is a decision, and `budgets: {}` is how you state it where a
reviewer can object.

---

## 📌 Pin a version so nobody can swap it

```rust
use agentplane::manifest::{MemoryRegistry, Registry};

let registry = MemoryRegistry::new();
registry.publish(&m).await?;

// Republishing 2.0.0 with different content is refused, not overwritten.
// Republishing *identical* content succeeds — a retried deploy is not an attack.

let m = registry
    .resolve_pinned("pattern-compliance-auditor", "2.0.0", governed_by)
    .await?;
```

Sign it, so the registry proves *who* as well as *what*:

```rust
registry.publish_signed(&m, &signer).await?;

let (m, key_id) = registry
    .resolve_verified("pattern-compliance-auditor", "2.0.0", &verifier)
    .await?;
```

`resolve_verified` returns the key that signed, because "it verified" is not the
whole answer — *which* identity signed is what you decide to trust, and this
crate never decides that for you. Unsigned and badly-signed come back as
different errors: the first usually means it was published before signing was
configured, the second means somebody tampered or a key rotated wrongly.

Signing can be enabled after an identical unsigned version was published:
`publish_signed` attaches that artifact's first publisher attestation without
changing its digest. Once present, publisher evidence is immutable too; another
signer gets `PublisherChanged` rather than silently taking authorship. Multiple
publishers would need an explicit attestation-set design, which is not built.

The signature is over a **domain-separated** hash, not the manifest digest. A
bare digest signature is structurally identical whatever it was about, so without
this a record attestation could be presented as a publisher's blessing of an
agent.

**Pinning is not the same as trusting the registry.** Immutability is a promise
the registry makes about itself, so it is worth nothing if the registry is the
compromised party. `resolve_pinned` is the caller declining to need that promise.
Prefer it anywhere the answer decides what an agent may do.

`MemoryRegistry` is deliberately process-local. The `Registry` trait is the seam
for a durable or remote implementation; no such implementation ships today.

---

## 🤖 Call a model

```rust
use agentplane::model::{ModelCall, ModelProvider};

let prompt = input.map(|ticket| json!({ "task": "triage", "ticket": ticket }));
let call = ModelCall::new(provider, model_id, prompt.peek().clone());
let completion = cx.sink(call, &prompt).await?;   // Tainted<Completion>
```

**The trap:** treating a failed call as free. A model call has a third state
between success and failure — it ran, generated four hundred tokens, and the
stream died. The provider bills for those tokens. If the ceiling counts them as
zero, a retry loop against a flaky provider spends real money against a limit
reading nothing.

The drivers stream by default precisely so a severed call can report what it
burned. You do not have to do anything to get that.

## 🏷️ Send untrusted content without giving it authority

Protect the fields that choose *what the world will do* rather than requiring
every descriptive byte to be trusted:

```rust
let args = Tainted::object([
    ("recipient".to_owned(), Tainted::trusted(json!("treasury"))),
    ("memo".to_owned(), model_written_memo),
]);
let safety = ToolSafety::default()
    .protect(ProtectedField::trusted("/recipient"));
let call = ToolCall::prepare(&catalog, client, tool, args.peek().clone())?;
let result = cx.sink(call, &args).await?;
```

The recipient must remain trusted; the memo may remain untrusted. `sink` also
compares canonical JSON, so a call cannot validate `args` and dispatch a
different recipient. Effects carrying outbound values are rejected by
`cx.effect`, making this gate mandatory rather than conventional.

When a trusted process authorizes a change, release the smallest possible
field and name the decision:

```rust
let args = cx.release(
    args,
    Release::fields(
        ReleaseScope::trust(),
        ["/recipient".to_owned()],
        "operator matched settlement SET-42",
        "mcp://ledger/transfer",
        ["approval:SET-42".to_owned()],
    ),
).await?;
```

Policy evaluates `data:release`; the journal records releaser, prior label,
scope, field, destination, basis and evidence. Provenance is retained, unrelated
fields are unchanged, and the result remains `Tainted<Value>`. Run the complete
success/refusal/release trail with `cargo run --example governed_transfer`.

## 📐 Ask for structured output

```rust
let prompt = Tainted::trusted(prompt);
let call = ModelCall::new(provider, model, prompt.peek().clone()).expecting(schema);
let completion = cx.sink(call, &prompt).await?;
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

Each compensatable skill implements `compensate`; the runtime invokes completed
steps in reverse and journals those effects under `Phase::Compensating`. The
complete runnable checkout example reserves inventory, charges payment, fails
fulfilment, refunds, releases inventory, verifies the journal, and proves strict
replay makes zero calls:

```sh
cargo run --example saga_checkout
```

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

## 🏢 Serve several tenants from one process

One plane per tenant, all over one database. Each store handle is scoped, and the
plane is built with the tenant that handle serves:

```rust
let base = RedbStore::open("plane.redb")?;
let plane = |name: &str| {
    let tenant = TenantId::new(name)?;
    let store = Arc::new(base.clone().for_tenant(tenant.clone()));
    Ok::<_, Box<dyn std::error::Error>>(
        Runtime::builder(store.clone() as Arc<dyn JournalStore>)
            .cases(store as Arc<dyn CaseStore>)
            .tenant(tenant)
            .policy(rules_for(name))
            .skill(Triage)
            .build(),
    )
};

let router = Api::new(
    Planes::one(plane("acme")?).and(plane("globex")?),
    Arc::new(MyAuth),   // must set `Caller::tenant` from the credential
)?
.router();
```

Your `Authenticator` sets `Caller::tenant` — that is the whole wiring. The gate
resolves the plane from it and hands it to the route, so a handler has no way to
reach a store it did not resolve.

**The trap:** deriving the tenant from anything the caller sent. A header, a path
segment or a body field is a value the caller controls, and this one selects a
*store* — so reading it from the request is a cross-tenant read with an
authentication step in front of it. It comes from the credential, like the actor
and the roles.

Two mistakes are refused rather than discovered: a plane whose store or blob
store is scoped to a different tenant fails at `build()`, and a caller whose
tenant has no plane is refused rather than served by a default.

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
