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

## 🔔 Wire durable A2A push

Push is a deployment capability, not merely a Cargo feature. Supply the same
tenant-scoped durable store used by the runtime and a transport with an explicit
host grant, take the worker handle, and only then sign the card:

```rust,ignore
use agentplane::api::a2a::A2aServer;
use agentplane::push::{PushPolicy, PushSender, PushStore, PushTransport};
use std::sync::Arc;

let sender = Arc::new(PushSender::new(
    PushPolicy::new().allow_host("hooks.customer.example"),
));
let server = A2aServer::new(runtime, authenticator, &security, &manifest, public_url)?
    .with_push(
        store.clone() as Arc<dyn PushStore>,
        sender as Arc<dyn PushTransport>,
    )?;
let worker = server.push_worker().expect("push was just configured");
let router = server.signing_cards_with(&card_signer)?.router();

// Run this from the deployment's scheduler on every instance. A saturated
// sweep means more due registrations exist, so drain another bounded batch
// immediately; otherwise wait until the next scheduler tick.
loop {
    // Unix seconds come from this operational scheduler's clock. The worker
    // never reaches for ambient time, which keeps backoff tests deterministic.
    let report = worker.run_once(scheduler_now, 100).await?;
    if !report.saturated {
        break;
    }
}
```

There is deliberately no hidden Tokio worker. Lifecycle, shutdown, frequency
and alerting belong to the process supervisor. Delivery is at least once: a
crash after the receiver accepts but before cursor persistence repeats the
event, and receivers must be idempotent. The journal is the outbox, so there is
no task-transition/outbox dual write to lose. Configure push before card signing
because `pushNotifications` is part of the signed document.

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
        // `Tainted::object`, not `input.map(...)`. The two slots mean different
        // things and must not share a label: `/system` is the order the model
        // reasons *under*, and it is a protected field — untrusted text there is
        // refused before the model sees it. `messages` is content it reasons
        // *about*, and may stay untrusted.
        //
        // `map` cannot prove how a closure reshaped a value, so it taints the
        // whole result — instruction included. That is why building the prompt
        // this way is not a style preference.
        let prompt = Tainted::object([
            // Each driver spells the instruction the way its API does —
            // top-level `system` on Anthropic, `instructions` on OpenAI
            // Responses. Write it once.
            (
                "system".to_owned(),
                Tainted::trusted(json!(
                    "You triage support tickets. Answer only with the JSON asked for."
                )),
            ),
            (
                "messages".to_owned(),
                Tainted::array([input.map(|i| json!({ "role": "user", "content": i }))]),
            ),
        ]);
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

### Which one: a plan, or a commission?

Both compose several steps, and the choice is not a matter of taste.

A **plan** is an authorization graph. Use it when the shape is known before the
work starts: the steps, what feeds what, which one is terminal. It is frozen at
admission and checked against the manifest, so a run cannot execute a step
nobody authorized — and a failure unwinds it in reverse.

A **commission** is an effect. Use it when one agent needs an answer from
another and the shape is decided *while running* — an editor that reads a brief
and then decides it needs research. It is journaled like any other effect, the
answer comes back untrusted, and the sub-run has its own journal and its own
ceiling.

The rule of thumb: **if you can draw the graph before you start, draw it.** A
plan is checkable in advance and a commission is not; the commission's advantage
is that it does not need to be.

Most agents need neither. `rt.run(capability, input)` is one capability and no
graph, which is what nine of the twelve examples use.

### Fan out to several specialists at once

The unit of concurrency is the **plan node**, not the call. Nodes with no edge
between them are one ready set and are dispatched together, each with its own
journal slice — so "ask every relevant specialist, then decide" is one plan:

```rust
let plan = PlanIR::fan_out(
    ["billing.anomaly", "billing.regulatory"],   // run concurrently
    "billing.decide",                            // then combine
);
let out = rt.run_plan(plan, document).await?;
```

The aggregator receives one argument per branch, **keyed by the capability that
produced it** — so adding a specialist cannot silently renumber what it reads,
which hand-wiring by `StepId` does.

Everything stays inside one run: one run id, one budget ledger, one case
binding, and a strict replay that reassembles the whole fan-out without waking a
single specialist.

Two things it deliberately does not do:

* **It does not set `topology`.** Whether a fan-out is collaboration depends on
  whether the branches are other *agents* or this agent's own skills, and the
  plan cannot tell. Declare it if it is: `parallel-disjoint` is for branches over
  genuinely disjoint inputs — a fan-out over one shared input is *not* that, and
  the validator will say so — while `distinct-authority` is the reason that fits
  independent opinions from differently-privileged specialists.
* **There is no `race`.** First-wins-cancel-the-rest is the one shape this
  runtime refuses, and not for want of plumbing: abandoning an in-flight branch
  leaves an announced effect with no terminal record, which is exactly the
  unknown outcome the effect protocol exists to prevent. It would also make a
  crash mid-race unrecoverable — some losers announced, no winner recorded, and
  nothing safe to do on resume — and it would make the answer depend on which
  machine was less loaded that day. Every branch runs to completion and every
  outcome is on the record. That costs more, and it is the only version that can
  be replayed.

**The trap:** letting untrusted text become the instruction. A model reads its
order and its data as the same undifferentiated text, so a document saying
*"ignore previous instructions"* is obeyed like one if it lands in `/system`.
Labelling the data and gating the sinks bounds what the model may then *do* —
this crate does that — but it never answers who was allowed to give the order.
`/system` is therefore protected: untrusted material belongs in `messages`.

This bites the moment an agent is exposed over A2A, because a peer's message
arrives **untrusted** while a locally-invoked run's input is trusted. An agent
built with `input.map(...)` works on your machine and is refused in production,
which is the right way round but worth knowing before it happens.

**The second trap:** putting the system prompt in a config file that the run does
not hash. The instruction is half of what the model was asked; if it can change
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

Use `artifact.anthropic_image()` for Anthropic,
`artifact.openai_image()` for OpenAI, and `artifact.bedrock_image()` or
`artifact.bedrock_document()` for Bedrock Converse. All four produce digest
markers that materialize only during live dispatch. Bedrock documents use the
constant neutral name `document`; AWS explicitly treats caller-chosen document
names as prompt-injection-bearing content. Unsupported media types and every
remote/S3 provider source are refused rather than guessed.

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
agentplane = { version = "0.3", features = ["opendal"] }
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

Rust-generated declarations use `Manifest::builder(name, version)` with
`.configure(|spec| ...)` or `.spec(spec)`, then `.build()`. The builder is
deliberately thin: nested values remain the same public typed `Spec` used by
Serde, and build runs the same normalization and validation as YAML. Direct
struct construction should finish with `manifest.build()`; otherwise the value
has not earned the guarantees a parsed manifest has.

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
agentplane = { version = "0.3", features = ["manifest"] }
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
    - ref: "tool://validator/apply_correction"
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
| `capabilities.provides` | **enforced** — the plane refuses to build if no skill provides it |
| `max_sensitivity_egress` | **enforced** — every sink uses the stricter of its own ceiling and the manifest ceiling |
| `max_delegation_depth` | **enforced** — checked against the configured identity and every delegating sink before dispatch |
| `output.schema` | carried to the provider and effect key, then validated locally without external-reference I/O |

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

## 🧯 Build a plane from a manifest you did not write

`build()` panics on a wiring mistake, and for a binary wiring its own skills that
is right: every refusal is a bug in code the author is looking at, and
`?`-propagating it to a `main` that prints it is ceremony around an abort.

A manifest resolved from a registry is different. It is an **input** — possibly
one tenant's, in a process serving many — and there a panic reports one tenant's
typo by taking down every other tenant's in-flight run. Use `try_build`:

```rust
use agentplane::runtime::{Agent, BuildError, Runtime};

let plane = match Runtime::builder(store)
    .agent(Agent::new(&resolved))
    .provider("anthropic", driver)
    .try_build()
{
    Ok(plane) => plane,
    // The variant matters, not just the failure: "this tenant named a provider
    // we do not have" is a message back to them, and a capability collision
    // between two of their agents is a different message.
    Err(BuildError::UnknownProvider { agent, provider }) => {
        return Err(onboarding_error(agent, provider));
    }
    Err(other) => return Err(other.into()),
};
```

Both entry points run the same checks — `build` is `try_build` with an `expect`,
so the two cannot come to disagree about what is refused. Every variant is listed
on `BuildError`, and each is a wiring mistake with a fix and no recovery: a
capability nothing provides, two agents claiming one capability, two skills
sharing a name, a catalogue laxer than a reviewed grant, a declarative agent
naming an unregistered provider, or a plane whose store serves another tenant.

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
        "tool://ledger/transfer",
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

## 🧬 Undo work when a *call* fails, not a whole step

A step-level compensation is handed the step's **output**, and a step that failed
does not have one. So a step that reserved inventory, authorised a card and then
failed asks its own `compensate` to guess. Group the calls instead:

```rust
let mut g = cx.group("checkout", ["inventory", "payments", "notify"]).await?;

// Runs now. The reversal closes over what this call actually returned.
let hold = g.reversible("inventory", Reserve::new(&sku, 2), |out| {
    Release::new(out["hold"].as_str().unwrap_or_default())
}).await?;

let auth = g.reversible("payments", Authorize::new(amount), |out| {
    Void::new(out["auth"].as_str().unwrap_or_default())
}).await?;

// A read declares no reversal, because it has nothing to take back.
let stock = g.read("inventory", Look::new(&sku)).await?;

// Held at the gate: an aborted group never sends it.
g.deferred("notify", Notify::new("order confirmed"))?;

// The frontier. Past here nothing unwinds.
g.commit(&[Invariant::new("the hold covers the order", covered)]).await?;
```

**The trap:** putting the irreversible send in `reversible` with an apology as
its undo. `deferred` is the stronger tool and costs nothing to use — the member
does not run until the group is certain, so an abort leaves no trace anyone saw.
A compensating email is a second email.

**The second trap:** treating the resource list as documentation. Every member
names its resource and one outside the declared set is refused *before it runs*.
A group that could touch anything has committed to nothing, and the frontier
would be a boundary around nothing.

**The third trap:** reaching for a member that must go through `cx.sink`. An
effect binding its own outbound arguments needs a labelled value checked against
them, and a group has none to offer on its behalf. Do the sink call outside the
group and let a plain effect be the member.

**The fourth trap:** expecting `?` to leave the group alone. It does not — the
executor reverses what the abandoned handle left standing, and a step that
returns *successfully* with a group still open is reversed **and** failed. A
group that commits by being forgotten would make the most consequential thing it
does the thing that happens when you write nothing.

Reversals go through the ordinary effect path, so they are journaled, retried and
metered like any other call and a replay does not perform them twice. Doubt
reverses nothing: a member whose outcome cannot be established quarantines the
run rather than unwinding around it.

## 🧱 Commit a member *with* the journal

If the table lives in the same Postgres as the journal, do not compensate — be
atomic:

```rust
#[async_trait]
impl AtomicResource for PostEntry {
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("ledger.post", json!({ "account": self.account }))
    }

    async fn apply(&self, tx: &dyn AtomicTx) -> Result<Value, EffectError> {
        tx.execute(
            "UPDATE ledger SET balance = balance + $2 WHERE account = $1",
            &[SqlValue::from(self.account.as_str()), SqlValue::from(self.amount)],
        ).await?;
        Ok(json!({ "posted": self.amount }))
    }
}

let mut g = cx.group("checkout", ["inventory", "ledger"]).await?;
g.reversible("inventory", Reserve::new(&sku), |o| Release::new(o))?.await?;
g.atomic("ledger", Arc::new(PostEntry { account, amount }))?;
g.commit(&[]).await?;
```

The member's write and the record that it happened commit together. Nothing is
externalised and taken back, so no reversal can fail; there is no in-doubt state,
because a transaction either committed or did not; and if it refuses, the group
is taken back *whole* — the cheap path, not a quarantine.

**The trap:** expecting the result. An atomic member returns nothing to the
caller, because it has not happened yet when you register it and cannot be seen
before the frontier it commits with. If a later member needs the value, it is not
an atomic member — it is a `reversible` one.

**The second trap:** reaching for it on an embedded store. `RedbStore` has no
notion of a foreign table, so it lends no transaction and the member is refused
at registration. That is a capability being absent, and it is refused where
refusing costs nothing rather than after the eager members have run.

## 🧰 Define a tool once

A tool is one type. Its arguments are its fields and its schema comes from those
fields, so the model is shown exactly what the body deserializes. The description
stays in the manifest because it steers model behaviour and therefore belongs in
the digest-covered review artifact:

```rust
/// Read a ledger account's balance.
#[derive(Deserialize, JsonSchema)]
struct ReadBalance {
    /// The account to read.
    account: String,
}

#[async_trait]
impl Tool for ReadBalance {
    const SERVER: &'static str = "ledger";
    const NAME: &'static str = "read";
    fn mutates() -> bool { false }

    async fn call(self) -> Result<Value, ToolFailure> {
        Ok(json!({ "account": self.account, "balance": 42 }))
    }
}

let rt = Runtime::builder(store)
    .agent(Agent::new(&manifest))
    .toolbox(ToolBox::new().with::<ReadBalance>().with::<PostEntry>())
    .build();
```

`call` takes `self` because **the arguments are the tool**: by the time it runs,
the model's JSON is this type or the call was refused. There is no `Value` left
to index and no field name to misspell.

### What a failure has to say

`ToolFailure` names the **disposition**, not a transport error, because that is
the only thing the runtime does anything with — it decides whether a retry is a
correction or a second real invocation:

```rust
async fn call(self) -> Result<Value, ToolFailure> {
    if !self.account.starts_with("AC-") {
        // Nothing was attempted. Safe to repeat.
        return Err(ToolFailure::DidNotHappen(format!("not an account: {}", self.account)));
    }
    match self.post().await {
        Ok(receipt)              => Ok(json!({ "receipt": receipt })),
        Err(e) if e.is_timeout() => Err(ToolFailure::InDoubt(e.to_string())),
        Err(e)                   => Err(ToolFailure::Landed(e.to_string())),
    }
}
```

The `ToolId` is attached by the box that dispatched the call, so a body cannot
name a tool other than itself and there is no identity to repeat on every error
path. Getting the choice wrong in the `DidNotHappen` direction is how a payment
happens twice, so **`InDoubt` is the honest answer whenever a request left this
process and no acknowledgement came back**. `RequiresOperator` on the grant then
escalates it rather than guessing.

### What the output is labelled

You do not label it, and you cannot. A tool's result comes back
`Tainted<Value>` and **untrusted**, because it is the outside world's data — and
nothing in the catalogue can change that, since the catalogue governs authority
and not provenance. `ToolSafety::output_sensitivity` sets the *sensitivity* floor
its results carry; there is no corresponding knob for trust.

That is deliberate even for the case that feels wrong — an internal registry
lookup whose answer really is reliable. Trust is not a property of where a value
came from in the deployer's head; it is a claim that has to be journaled, and the
way to make it is `cx.release`, which names the destination, basis and evidence
and asks policy under `data:release`. A `trusted: true` field on a tool
declaration would be the same claim with no record, no authorization and no
reviewer.

This is the shape Python's `@tool`, Pydantic AI, the OpenAI Agents SDK and Rig
all arrived at, and the reasons are the same: a schema written twice is a schema
that disagrees with itself. Those SDKs also derive the description from code,
which is right when code is the declaration. Here the manifest is the reviewed,
content-addressed declaration, so model-steering prose belongs there instead.

`.toolbox(..)` is one call because it used to be three, and two of them were
optional. It derives the catalogue from each agent's own declaration — the
grants, their ceilings and their protected fields, stated once — and it
**refuses to build** if the tools this binary implements and the manifests a
reviewer approved have drifted **in either direction**: a tool implemented but
not granted means the binary can do something its declaration does not admit; a
grant with nothing behind it means the model is offered a tool that fails when
chosen. Neither is caught by the dispatch gates, which refuse a *call* long
after the disagreement shaped what the model was told it could do.

The check runs at `build`, not when the box is wired, and that is what makes it
worth trusting: checking on the `.toolbox(..)` call would check against the
agents registered *so far*, so writing `.toolbox(..).agent(..)` would pass by
having nothing yet to disagree with. Every agent on the plane is checked, not
the first.

**The trap:** believing the type is the security boundary. It is not — it is the
*shape*. The manifest still declares what this deployment permits.

## 🧱 Where are the built-in tools?

There are none, and the reason is worth two paragraphs because every other
framework ships some.

The tools they ship are mostly **provider-hosted** — ADK's Google Search and
Code Execution, the OpenAI Agents SDK's `WebSearchTool` and
`CodeInterpreterTool`. Those run on the provider's servers *during generation*.
Here a world-visible action is an effect: announced durably before it acts,
authorized against the agent's declaration, metered against a budget, and read
back from the journal on replay. A hosted tool is none of those and cannot be
made into any of them, because by the time the completion comes back the call has
already happened. Accepting one would put an action outside the journal, which is
the single thing this runtime exists to prevent.

For tools that run *in this process*, the domain-neutral ones already have
governed homes: fetching a URL is the `media` feature,
with SSRF, DNS-pinning and content controls a generic `http_get` would have to
reimplement badly; running untrusted code belongs behind an OS process boundary
as an MCP server, not inside the deterministic zone. What is left is a connector
catalogue — and a catalogue is authority somebody has to review, entry by entry,
forever.

What you get instead: `execution.kind` is the built-in *behaviour* —
`completion` and `tool-calling` are the prebuilt agent loop, minus the part that
runs outside the journal — and a typed `Tool` is about fifteen lines.

## 🔌 Call tools on an MCP server you already run

The tool tier is not "your tools, MCP-shaped". `tools::McpClient` is a real MCP
client: point it at a running server and its tools become callable under the
ordinary governed path — declaration, protected fields, egress ceiling, budget,
disposition and all.

Wiring is two lines. `McpClient::new` takes an already-initialised `rmcp` client,
so the transport — stdio, a child process, streamable HTTP — stays your choice:

```rust
use agentplane::tools::{McpClient, ToolBox};

// One name per server. It is *your* name for it, not one the server chose:
// the catalogue keys on it, and a server able to rename itself could step
// into another server's entry.
let tickets = Arc::new(McpClient::new("tickets", Arc::new(service)));

let rt = Runtime::builder(store)
    .agent(Agent::new(&manifest))
    .toolbox(ToolBox::new().with::<ReadBalance>())   // tools in this binary
    .tool_server("tickets", tickets)                 // tools on that server
    .build();
```

Initialize `service` with `McpClient::host_info()` rather than rmcp's empty
default client handler. That profile negotiates the Tasks extension and nothing
else: elicitation, sampling, roots and subscriptions stay absent until a
governed runtime callback exists.

MCP context is available without turning it into a tool. Exact grants may live
in the manifest:

```yaml
context:
    prompts:
        - server: templates
            name: summarize
            max_input_sensitivity: internal
    resources:
        - server: knowledge
            uri: kb://support/rules
            output_sensitivity: internal
```

Derive the deployment catalogue with
`McpAccess::from_manifest("templates", &manifest)`, then use
`McpClient::prompt` or `McpClient::resource` and dispatch the returned value via
`cx.effect` (or `cx.sink` for prompt arguments). Both results are untrusted and
strict replay performs no second MCP request.

An asynchronous tool result is not flattened into an apparent answer.
`McpTask::from_result` preserves its handle; `client.task(handle)` prepares a
journaled `tasks/get` effect. `update_task` binds the exact labelled input
responses and defaults to operator recovery, while `cancel_task` is an
idempotent cooperative request followed by another poll. The cancellation ack
is never presented as evidence that the server stopped.

The manifest grants both the same way, because a reference names *which tool*
and never which wire carries it:

```yaml
tools:
  - ref: tool://ledger/read      # a typed Rust tool in this binary
    mutates: false
    description: Read a ledger account's balance.
  - ref: tool://tickets/read     # a tool on the MCP server above
    mutates: false
    description: Read a support ticket.
```

That is also why one manifest can run against an in-process double in a test and
a real server in production: the transport is a deployment decision, not
something the reviewed file claims.

One client per server, resolved by name. A `ToolRouter` does the resolving, and
it matters more than it looks: a single client handed every tool id cannot tell
`tool://ledger/read` from `tool://tickets/read`, so a plane that granted one and
wired the other got a **successful answer from the wrong server** under the first
one's operator safety. A server nobody wired is `Unreachable`, and a grant naming
one is refused at build rather than at the first call.

### `discover()` is a diff, not a source

An MCP server advertises its tools with annotations — `readOnlyHint`,
`destructiveHint`, `idempotentHint` — and the obvious convenience is to import
that list and build a catalogue from it. **That is the one thing this client will
not do**, and the specification agrees: clients *must* consider annotations
untrusted.

The composition is what makes it dangerous here rather than merely untidy.
`readOnlyHint: true` would mean the effect does not mutate; a non-mutating effect
defaults to `Recovery::Retry`; and a retried call is a second real call. So a
server that marked its own money-moving tool read-only would be choosing, from
the far side of the trust boundary, the one condition under which this runtime
does something twice.

So `discover()` returns what the server says **for comparison**:

```rust
for (id, advertised) in tickets.discover().await? {
    if let Some(safety) = catalog.safety(&id) {
        // Not an error — a server is entitled to describe itself and an
        // operator is entitled to disagree. It is worth an alert because a
        // server that *starts* claiming to be read-only after an update is
        // what a swapped-out or compromised server looks like from here.
        if advertised.overclaims(safety) {
            tracing::warn!(%id, "server claims more safety than the operator granted");
        }
    }
}
```

**The trap:** treating discovery as configuration. A tool absent from the
operator's catalogue cannot be called however the server advertises it, and that
is the property. Auto-import would let a server widen its own authority — which
is exactly what `Advertised` versus `ToolSafety` exists to prevent.

## 🧾 When the two parties really do differ

`.toolbox(..)` covers the common case, where the tools a binary implements are
the tools its agents declare. The two-party split is still there when it is
real: an operator who wants to say something *different* from the agent's author
builds the catalogue themselves and passes it with the client:

```rust
let catalog = ToolCatalog::from_manifest(&manifest)
    .allow(ToolId::new("ledger", "read"), ToolSafety::read_only());

let rt = Runtime::builder(store)
    .agent(Agent::new(&manifest))
    .tools(Arc::new(catalog), client)
    .build();
```

The manifest's own grant is re-checked at dispatch either way, so a catalogue
can only narrow what a declaration asked for, never widen it.

Wiring both forms on one plane is **refused**, not merged: one would silently
replace the other's grants and nothing would say which won.

**The trap:** believing the catalogue is the security boundary on its own. It is
one of two: the manifest is inside the agent's digest, the catalogue is the
deployment's. A tool absent from *either* is not callable.

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

## 🧠 Give an agent a memory

```rust
let store = Arc::new(RedbStore::open("plane.redb")?);
let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
    .memory(store as Arc<dyn MemoryStore>)
    .skill(Triage)
    .build();
```

Use `PostgresStore` instead of `RedbStore` when several plane instances share
the memory; it implements the same `MemoryStore` contract and serializes
concurrent revisions of one id.

### Choosing a subject: private, team, global

A subject does **three** jobs at once, and picking one means deciding all three:

| | |
|---|---|
| **Sharing** | who retrieves it — by convention, enforced by policy |
| **Retrieval** | `Recall::about(subject)` ranges over exactly this scope |
| **Erasure** | `forget_subject` / `erase_subject` name a subject, so it is the unit a person's erasure request deletes |

```text
agent/triage/account/{account}    one agent's private memory about one account
team/support/account/{account}    shared by the support agents
tenant/policy                     every agent in the tenant reads it
```

Those strings organize retrieval; they do **not** grant access. Authorize
`memory.recall` and `memory.remember` in policy using the acting agent and the
subject/purpose carried in the effect arguments.

**A tenant-global subject is expressible and carries two hazards worth naming**,
because nothing structural stops either:

* **Blast radius.** A poisoned global memory reaches every agent in the tenant.
  Trust ranking bounds the damage — an untrusted global memory cannot evict a
  trusted one, and it stays untrusted at every sink — but it is still read by
  everything. Prefer a narrow subject and widen deliberately.
* **Erasure.** A subject is the unit an erasure request names. Personal data in a
  global subject is therefore *outside* any one person's erasure unit, and
  `forget_subject("tenant/policy")` would erase everybody's. Keep global subjects
  for material that is nobody's personal data — policy text, product facts — and
  keep anything attributable to a person in a subject that names them.

Global memory is the right shape for *"refunds over €5,000 need a manager"*. It
is the wrong shape for *"this customer prefers German"*.

Inside a skill:

```rust
let subject = format!("team/support/account/{account}");
let known = cx.recall(Recall::about(&subject).for_purpose("support").limit(5)).await?;
// Trusted memories come first: recall truncates, and ordering the window by
// recency alone lets anything able to write an untrusted memory evict the
// trusted ones by writing `limit` of them.
// Every item is labelled. Reading metadata is free; acting on the content is not.
for memory in &known {
    println!("{} (trust {:?})", memory.peek().id, memory.label().trust);
}

// `summary` is a `Tainted<Value>` from the model. The runtime derives trust,
// sensitivity and provenance from it; there is no metadata field with which it
// can be promoted while being stored.
cx.remember(
    MemoryWrite::new(format!("triage-{account}"), account.clone(), "support")
        .expires_at(retention_cutoff),
    summary,
).await?;
```

Fresh recall evaluates expiry against `StepCtx`'s journaled clock. Exact
versions remain replayable until a lifecycle skill calls
`cx.sweep_expired_memories()`; its cutoff and removed count are journaled, and
strict replay does not erase twice. The backend sweep erases all versions and
reserves the id. `set_legal_hold(id, true)`
blocks ordinary, subject, cascading and expiry erasure atomically. A hold is
privileged lifecycle administration, not something model output should request.

Use `MemoryWrite::retain_after_access(seconds)` with
`Recall::refresh_access()` only when policy genuinely says “retain after use”.
The refresh is a separate journaled, idempotent touch effect; ordinary recall
remains read-only and strict replay never extends retention twice.

Semantic ranking stays outside `MemoryStore` and inside the journal:

```rust
let hits = cx.semantic_recall(
    retriever, // Arc<dyn SemanticRetriever>
    Tainted::trusted(SemanticQuery {
        subject: account.clone(),
        purpose: Some("support".into()),
        text: "refund policy".into(),
        embedding: query_vector,
        embedding_model: "embed-v3@2026-07-01".into(),
        index_snapshot: "support-2026-08-05".into(),
        limit: 5,
        max_sensitivity: Sensitivity::Internal,
    }),
).await?;
```

The effect records the exact vector, embedding revision, immutable index
snapshot, filters, scores and `(id, version, digest)` selections. Replay does
not rerank. It materializes exact versions from authoritative memory and rejects
out-of-scope or changed commitments. `InMemorySemanticRetriever` is the exact
cosine reference; production ANN stores implement the same seam.

**The trap:** stripping the label before writing. `StepCtx::remember` prevents
the obvious laundering path by accepting `MemoryWrite` plus `Tainted<Value>` and
deriving all security metadata. If a memory genuinely needs improved trust or
sensitivity, call `cx.release` first so policy and the journal record the
decision; then store the released value.

For governed automatic formation, declare `spec.memory_formation` on a
declarative agent. It requires a reviewed subject, purpose, extraction
instruction, item bound and retention. The model proposes only `key/content`;
runtime derives stable ids and security labels. Coded skills invoke
`cx.form_memories` explicitly. There is intentionally no generic post-model hook
that silently stores every conversation.

With feature `keyring`, wrap a single-node memory backend in
`EncryptedMemoryStore::new_single_node`. Content is ciphertext in the backing
store. `erase_subject(subject, at, reason)` checks legal holds, destroys the
tenant/subject wrapping scope, then cleans rows, leaving pre-erasure backups
undecryptable. This process-local lifecycle coordinator is not an active-active
erasure barrier.

**The second trap:** expecting `forget` to be enough for an erasure request. It
removes one memory and every version of it, which is what selective repair
needs; a *subject* is the unit a person's erasure names, and `forget_subject` is
that. If summaries were made from the memory, see the next recipe — erasure has
to reach them too. A forgotten id remains reserved forever; generate a new id
for new content rather than recycling an old journal identity.

## ☁️ Use Amazon Bedrock Converse

Enable the separate `bedrock` feature, then load AWS's standard credential
chain and an explicit region:

```rust
let provider: Arc<dyn ModelProvider> = Arc::new(
    agentplane::model::bedrock::Bedrock::from_env("eu-west-1").await?
);
```

The driver supports Converse text, tools/results, usage, truncation, native JSON
Schema output with forced-tool fallback and exact reasoning-content
continuation. It streams through `ConverseStream` by default and classifies
partial failures according to whether generation and usage were observed;
`.buffered()` is explicit. Region, stream mode, timeout and schema mode are in
effect identity. Explicit `reasoning_effort` is refused because Converse has no
portable mapping across its model families.

Attach an `Arc<dyn ModelStreamObserver>` with
`ModelCall::streaming_to(observer)` to expose live visible text while retaining
one canonical journaled completion. Events are labelled untrusted at the call's
output sensitivity; opaque reasoning is never emitted and strict replay emits
nothing live. Observers should enqueue quickly and enforce network backpressure
outside the provider callback.

The split is worth stating, because getting it backwards produces either a
useless log or an unreplayable run. **The completion is the truth** — one
record, one effect key, read back on replay — and deltas are never journaled: a
partial answer is not evidence, and a chain holding a thousand of them answers
exactly the same questions at a thousand times the verification cost. **The
observer is a view**: not provider-visible, so not part of effect identity, so
attaching or removing one cannot change a run's history.

Strict replay therefore calls the observer **zero times**, and that is the
honest interface rather than a gap. Replay is not a rerun; a framework that
re-streamed from a cache would be reconstructing a live experience, which is a
different claim from reproducing a run. `cargo run --example streaming_run`
prints all three facts, including the deltas reassembling into the completion
byte for byte.

Testing your own observer needs a provider that streams, so `FakeProvider`
does — call `.streaming()` and every scripted answer is emitted as text deltas
followed by a usage snapshot, before the completion returns:

```rust
let provider = FakeProvider::new();
provider.streaming().will_say("Settlement GB-4471 clears on Thursday.");
```

The chunking is whitespace with the separator kept on the preceding chunk, so
concatenating every delta reproduces `Completion::text` exactly — which is the
property an observer that appends into a buffer actually depends on.

OpenAI and Anthropic declarative tool loops preserve reasoning automatically.
`Completion::continuation` carries opaque OpenAI output items or Anthropic
thinking/signature blocks. A custom loop must pass that value through
`ModelCall::with_continuation` beside `continuing(exchanges)`; otherwise a
reasoning-enabled continuation fails closed.

## 🗜️ Compact a memory without laundering it

Summarising is itself a memory write, so it goes through the effect protocol
rather than around it:

```rust
let old = cx.recall(Recall::about(&account).for_purpose("support").limit(50)).await?;

cx.compact(
    Compaction {
        id: format!("digest-{account}"),
        subject: account.clone(),
        purpose: "support".to_owned(),
        at: cx.now().await?,
        instruction: "Summarise these support interactions in under 200 words.".to_owned(),
        // What the summarising model may be shown. Refuses if an input exceeds it.
        max_sensitivity: Sensitivity::Confidential,
    },
    &old,
    provider,
    ModelId::new("gpt-5"),
).await?;
```

Notice what you did **not** pass: trust, sensitivity, provenance, or the prompt.
All four are derived. The label is the join of the inputs, so a summary of
untrusted memories is untrusted; and the prompt is assembled from the sources
here rather than accepted, because a caller who could shape it could show the
model something other than what was checked.

**The trap:** treating `max_sensitivity` as a storage detail. Compaction sends
memories *to a model*, so it is an egress. Set it too high and summarising
becomes the quiet route around every other limit; it defaults to `Public` for
that reason, and refuses rather than truncating.

**The second trap:** forgetting a poisoned memory and considering it handled. Its
content is now inside every summary that read it. `forget` is right for a
**correction** — the memory was stale, the summaries are still legitimate.
`forget_cascading` is right for an **erasure**, and takes the derivatives with
it; `derivatives(id)` shows you what that would remove before you commit to it.
Correction retains that lineage, so a later erasure can still find summaries
even though the source content has already gone.

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

Give each tenant a ceiling while you are there — the plane's store already
implements the accounting:

```rust
.quota(store.clone() as Arc<dyn QuotaStore>, TenantQuota {
    max_concurrent_runs: Some(50),
    max_tokens_per_period: Some(20_000_000),
    ..Default::default()
})
```

**The trap:** deriving the tenant from anything the caller sent. A header, a path
segment or a body field is a value the caller controls, and this one selects a
*store* — so reading it from the request is a cross-tenant read with an
authentication step in front of it. It comes from the credential, like the actor
and the roles.

Two mistakes are refused rather than discovered: a plane whose store or blob
store is scoped to a different tenant fails at `build()`, and a caller whose
tenant has no plane is refused rather than served by a default.

**The second trap:** counting concurrency in memory. That ceiling doubles the
moment a second instance starts — and it fails open, so nothing tells you. The
accounting belongs in the store, which is why `quota` takes one.

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
