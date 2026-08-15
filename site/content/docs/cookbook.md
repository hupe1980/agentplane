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
        // A skill that declares nothing answers its own name — the right
        // default for a first program. `.provides(..)` is declared here because
        // the plan below binds the *capability* `ticket.triage`, decoupling
        // what a step needs from who provides it — and swapping the
        // implementation is then a binding change. Declaring a capability
        // replaces the name default rather than adding to it.
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
        // `sink_with` hands the labelled value to the effect and the gates in
        // one motion: the closure receives the inner value, so the bytes the
        // egress ceiling checks and the bytes the provider is sent cannot be
        // two versions of one prompt.
        let provider = Arc::clone(&self.provider);
        let completion = cx
            .sink_with(&prompt, |value| {
                ModelCall::new(provider, ModelId::new("anthropic", "claude-sonnet-4-5"), value)
                    // The ceiling that matters for a hosted model: a prompt
                    // assembled from a secret is an exfiltration whether or
                    // not anyone meant it.
                    .with_max_sensitivity(Sensitivity::Internal)
                    .expecting(json!({
                        "type": "object",
                        "properties": { "severity": { "type": "string" } },
                        "required": ["severity"],
                    }))
            })
            .await?;
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
let out = rt.run("ticket.triage", Tainted::trusted(json!({ "text": "printer on fire" }))).await?;

// Several: name the order, and what feeds what.
let plan = PlanIR::new(vec![
    PlanNode::new(0, "ticket.triage").arg("input", ArgSource::run_input()),
    PlanNode::new(1, "ticket.notify")
        .arg("triage", ArgSource::node(StepId(0)))
        .terminal(),
]);
let out = rt.run_plan(plan, Tainted::trusted(json!({ "text": "printer on fire" }))).await?;
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

Most agents need neither. `rt.run(capability, Tainted::trusted(input))` is one capability and no
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
let out = rt.run_plan(plan, Tainted::trusted(document)).await?;
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
let answer = cx
    .sink_with(&prompt, |value| {
        ModelCall::new(provider, model, value)
            .with_max_sensitivity(Sensitivity::Internal)
            .with_media(blobs.clone(), [&media_grant])
    })
    .await?;
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

let out = rt.run("support.summarise", Tainted::trusted(ticket)).await?;
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

**The trap: expecting `kind` to grow keywords.** It is a closed enum —
`completion`, `tool-calling`, `planned` — and each is a behaviour the runtime
implements and tests. What you will never find here is sequencing, conditions
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

## 🎫 Work with labelled values

`Tainted<T>` is the type every value in a skill arrives in. Reading is free;
the gate is at sinks, so there is no unwrap:

```rust
let name = input.peek()["name"].as_str().unwrap_or_default();  // reading is fine
let label = input.label();                                     // trust, sensitivity, provenance
```

Build values so the labels stay *per field* rather than collapsing to the
worst one:

```rust
let args = Tainted::object([
    ("recipient".to_owned(), Tainted::trusted(json!("treasury"))),
    ("memo".to_owned(), from_the_model),          // untrusted, and stays that way
]);
```

`object` and `array` keep each field's label at its RFC 6901 path, which is
what lets a protected `/recipient` be satisfied while `/memo` remains
untrusted. `map` and `zip` cannot — the runtime cannot prove how a closure
reshaped a value — so they keep the conservative whole-value label and drop
field paths. Reach for `object` when the difference matters.

Labels **join**: combine anything untrusted and the result is untrusted;
combine anything `Confidential` and the result is at least `Confidential`.
Effect output is labelled at the source, untrusted by default, so this happens
without a skill saying so.

**The trap:** `Tainted::trusted(...)` on something a model or a tool produced.
It compiles, and it is the laundering every gate downstream depends on not
happening. Trusted means *from the operator, the manifest, or the run's own
trusted input*; raising anything else is `cx.release`, which asks policy and
leaves a record.

## 🔩 Reach a system this crate has never heard of

Tools, models and peers are effects with drivers written for them. Everything
else is an `Effect` you write — the extension seam:

```rust
#[async_trait::async_trait]
impl Effect for ChargeCard {
    type Output = Receipt;

    fn descriptor(&self) -> EffectDescriptor {
        // Hashed with the position into the effect key: these arguments are
        // what makes this call *this* call on replay.
        EffectDescriptor::new("psp.charge", json!({ "order": self.order, "cents": self.cents }))
    }

    fn mutates(&self) -> bool { true }
    fn recovery(&self) -> Recovery { Recovery::Reconcile }

    async fn perform(&self) -> Result<Receipt, EffectError> {
        match self.client.post(&self.order).await {
            Ok(r)                      => Ok(r),
            Err(e) if e.is_connect()   => Err(EffectError::Unavailable {
                driver: "psp".into(), detail: e.to_string() }),
            Err(e) if e.is_timeout()   => Err(EffectError::Timeout {
                driver: "psp".into(), waited_ms: 30_000 }),
            Err(e)                     => Err(EffectError::Rejected(e.to_string())),
        }
    }
}
```

**The one decision that matters is the error mapping**, and it is a claim about
the world, not about the wire: `Unavailable` and `Rejected` mean *nothing was
applied*, so the runtime may retry; `Timeout` and `Interrupted` mean *it may
have landed*, so it will not. Map a timeout to `Rejected` and a card gets
charged twice.

One more distinction pays for itself on the failure path: `Refused` means the
peer *understood the request and said no* — an answer, not a fault — and the
runtime spends no retry on it. Use it for the refusals no repeat can change (a
validation error, an unknown account); keep `Rejected` for the ones a repeat
might (an overloaded gateway). Conflating them is how a wrong request burns
every permitted attempt with backoff before failing anyway.

`recovery` says what to do with a call that may have landed: `Retry` (safe to
repeat), `Reconcile` (ask the provider what happened — implement `reconcile`),
or `RequiresOperator`. A mutating effect that declares nothing gets
`RequiresOperator`.

Declare `trust()` only if the output is *not* somebody else's data — the
default is untrusted, and it is the right default. If the effect carries an
outbound value, dispatch it through the sink gate — `cx.sink_with(&args, |v|
...)` builds the effect from the labelled value in one motion, and the two-arg
`cx.sink(effect, &args)` remains for an effect that binds its outbound value
internally — rather than `cx.effect`, which refuses it. Provenance names the
concrete source: `source()` defaults to `effect:{kind}`, and the effects whose
outputs feed authority-bearing fields override it with the identity an operator
actually grants — a tool call answers as `tool://server/name`, a model
completion as `model:{provider}/{model}`, a commission as `agent/{capability}`.
A family name would be too coarse for the rule that matters: "the recipient
must come from the CRM lookup" is unsatisfiable when every granted tool answers
under one family.

You do not need an effect for the ordinary nondeterminism: `cx.now()` is the
journaled clock, `cx.rng()` is seeded per step and reproduces on replay, and
`cx.note("...")` puts a line in the chain for whoever reads it later.
`SystemTime::now()` and a thread RNG are lint errors here, because a replay
that recomputed them would disagree with the history it claims to reproduce.

## 🤖 Call a model

```rust
use agentplane::model::{ModelCall, ModelProvider};

let prompt = input.map(|ticket| json!({ "task": "triage", "ticket": ticket }));
let completion = cx
    .sink_with(&prompt, |value| ModelCall::new(provider, model_id, value))
    .await?;   // Tainted<Completion>
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
let prompt = Tainted::trusted(prompt);
let completion = cx
    .sink_with(&prompt, |value| ModelCall::new(provider, model, value).expecting(schema))
    .await?;
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

`.toolbox(..)` is one call rather than three, two of them optional. It derives
the catalogue from each agent's own declaration — the
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

## 📜 Govern a skill you *did* write

The other tier. When the agent does real work — a solver, a database, something a
model cannot be — the behaviour is a `Skill`, and the manifest governs its
**boundary**: which model, which tools, what it may spend.

```sh
cargo add agentplane --features manifest
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
          allowed_sources: [model:anthropic/claude-sonnet-5]
  budgets:
    max_tokens: 120000
    max_minor_units: 250      # cents, never a float
```

A source rule names the **concrete** source, because that is what an effect's
output carries as provenance: a tool call answers as `tool://server/name`, a
model completion as `model:{provider}/{model}`, a commission as
`agent/{capability}`. A family spelling like `effect:model.complete` matches
nothing — a family is too coarse for the rule that matters, since "the
correction must come from the privileged model" is unsatisfiable when every
completion answers under one name.

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

## 🗃️ Keep state across runs, not inside one

A month-long process is a **case** plus short runs. Start a run correlated by
business key, and it joins the existing case or opens one:

```rust
rt.run_correlated("claim.assess", Tainted::trusted(input), "claim", &[CorrelationKey::new("claim", "CLM-9")]).await?;
```

Inside the skill, case state is versioned and every access is journaled:

```rust
let (state, version) = cx.case_state().await?;      // untrusted: many runs write it
let next = json!({ "stage": "assessed" });
cx.put_case_state(version, next).await?;            // refused if the case moved
cx.deadline("respond-by", &DeadlineSpec::days(5), None).await?;
cx.meet_deadline("respond-by").await?;
cx.set_case_status(CaseStatus::Closed).await?;      // refused with an open obligation
```

**The trap:** treating `put_case_state` like a setter. It names the version it
read, and a concurrent run that wrote first makes it fail — which is the lost
update it exists to prevent. Re-read and decide again; do not retry the same
write. Closing releases the correlation keys, so a closed case stops
collecting new matter.

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
let result = cx
    .sink_with(&args, |value| ToolCall::prepare(&catalog, client, tool, value))
    .await?;
```

The recipient must remain trusted; the memo may remain untrusted. `sink_with`
hands the labelled value to the call and the gates in one motion, and the
byte-for-byte binding check still runs underneath — canonical JSON is compared,
so a call cannot validate `args` and dispatch a different recipient. Effects
carrying outbound values are rejected by `cx.effect`, making this gate
mandatory rather than conventional.

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

```sh
cargo add agentplane --features opendal
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

## 📚 Embed a directory of manifests

One file per agent, embedded in the binary, keyed by what each document declares:

```rust
let agents = agentplane::manifests![
    "agents/obligation-watch.yaml",
    "agents/clearing-triage.yaml",
]?;

let rt = agents.values().fold(Runtime::builder(store), |b, m| {
    b.agent(Agent::new(m))
}).try_build()?;
```

`Manifest::parse_all` is for a **room** — several agents in one file, because
they are one deployable thing. This is the other layout, and it had no support at
all, so every embedder wrote the same table by hand:

```text
const AGENTS: &[(&str, &str)] = &[
    ("obligation-watch", include_str!(agents/obligation-watch.yaml)),
    ...
];
```

**Two defects, both silent.** The name beside each path is *already in the
document* as `metadata.name`, so it is one fact written twice with nothing
checking that the two agree. And a file included under two constants — which is
what happens while adding the next agent — builds, runs, and registers one agent
twice while the other is simply absent. The macro keys on the declared name and
refuses a duplicate, naming both paths.

There is deliberately no glob: a macro that expanded a directory listing would
make the set of agents a plane runs depend on what is on disk at build time
rather than on what is in the source a reviewer reads.

---

## ✨ Use Google Gemini

```rust
let gemini = Gemini::from_env()?                      // GEMINI_API_KEY, or GOOGLE_API_KEY
    .safety(SafetySettings::new().block(
        HarmCategory::DangerousContent,
        HarmBlockThreshold::LowAndAbove,
    ));

Runtime::builder(store).provider("gemini", Arc::new(gemini)).build();
```

```yaml
models:
  privileged: { provider: gemini, model: "gemini-3.5-flash" }
```

It speaks `generateContent`/`streamGenerateContent` natively rather than
Google's `OpenAI`-compatible endpoint, and the difference is not cosmetic.
Gemini's thinking models attach an encrypted **thought signature** to the parts
they emit and reject a follow-up turn that does not carry it back. This driver
keeps the model's turn *verbatim* as opaque continuation state — the same way
the `OpenAI` driver carries encrypted reasoning and Anthropic carries signed
thinking — so there is no field to know about and none to lose.

`reasoning_effort` maps to Gemini's thinking levels: `minimal`, `low`, `medium`
and `high` exactly, and `none`, `xhigh` and `max` are **refused** rather than
bent to the nearest one that exists — Google documents that thinking cannot be
switched off on the Gemini 3 models. Schemas go to `responseJsonSchema` and are
enforced during generation, never rewritten into Gemini's trimmed dialect.

`safety(..)` passes the deployment's own thresholds through, exactly as
`Bedrock::guardrail(..)` does: this crate ships no classifier, and what the
runtime owns is that the thresholds are **effect identity** — loosening one
between a run and its replay is divergence — and that an intervention is a
*metered refusal* rather than an answer. A blocked prompt names its reason; a
`SAFETY` stop carries the tokens it burned.

No sampling parameter (`temperature`, `topP`, `topK`, `seed`) is ever sent:
none is in `Request`, so none could be in the effect key, and a knob outside
effect identity is one a replay cannot account for.

---

## 🏠 Run a Hugging Face model locally

The de-facto wire of self-hosted inference is the `OpenAI`-compatible
`/v1/chat/completions` endpoint — TGI (Hugging Face's own server), vLLM,
Ollama, llama.cpp's server and LM Studio all speak it, and Hugging Face's
hosted router *is* one. So one driver reaches every local host, and the model
stays behind a process boundary where an inference engine belongs — the plane
never carries weights, a GPU toolchain, or an engine's faults.

```sh
ollama pull llama3.2            # or: TGI, vLLM, llama-server, LM Studio…
```

```rust
use agentplane::model::chat_completions::ChatCompletions;

let local = ChatCompletions::new("http://localhost:11434")?;
let runtime = Runtime::builder(store)
    .provider("chat-completions", Arc::new(local))
    .agent(Agent::new(&manifest).skill(Triage))
    .build();
```

Or with no Rust at all — the same manifest runs against Ollama on a laptop,
TGI on a GPU box, or Hugging Face's hosted router, and its digest never
changes, because where a model is served is deployment wiring, not part of the
declaration:

```yaml
  models:
    privileged: { provider: chat-completions, model: "llama3.2" }
```

```sh
CHAT_COMPLETIONS_BASE_URL=http://localhost:11434 \
    agentplane run triage.yaml --input '{"ticket": "printer on fire"}'

# The identical declaration against Hugging Face's hosted endpoint:
CHAT_COMPLETIONS_BASE_URL=https://router.huggingface.co/v1 \
CHAT_COMPLETIONS_API_KEY=$HF_TOKEN \
    agentplane run triage.yaml --input '{"ticket": "printer on fire"}'
```

**The trap:** believing "compatible" covers semantics. Every compatible server
implements the shape; not every one counts. Usage is metered **as reported** —
a server that reports none meters zero, visibly, rather than being backfilled
with a guess — and structured output defaults to the forced-tool fallback
because whether a server honours `json_schema` is exactly what cannot be
assumed. A deployment that knows its server enforces it opts up with
`.structured_via(SchemaMode::Native)`. Two controls are refused outright
rather than silently dropped: `reasoning_effort` (no neutral spelling on this
wire) and governed media (a per-server dialect). Against `api.openai.com`
itself, use the `openai` driver — Responses is the current primitive there.

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

## 🔔 Tell a desk without stopping the run

`cx.task` asks and blocks, which is right when the answer decides what happens
next and wrong when nothing does. An agent that has *finished*, whose finding a
compliance desk must see, does not need its run suspended — it needs a row in a
worklist. Gating the answer to achieve that costs one suspended run per finding,
at whatever rate the world produces them.

```rust
cx.open_task(
    &TaskSpec::new("deadline.breach", justification, "triage-breach")
        .role("grid-operations")
        .priority(Priority::High),
).await?;
// The run keeps going. Nothing resumes on the decision, because nothing waits.
```

Declaratively, that is `spec.oversight.triage` — a predicate over the declared
`output.schema` and an audience:

```yaml
oversight:
  approval: none
  deadline: { name: unused, kind: hours, params: { n: 4 } }
  triage:
    - name: breach
      summary: "a regulatory deadline was missed"
      audience: [grid-operations]
      when:
        - { path: /deadline_status, equals: BREACH }
      deadline: { name: triage-breach, kind: working-days, params: { n: 2 } }
```

**The trap:** expecting the taint gate to apply. It does not, on either path. A
worklist row's whole purpose is to put untrusted content in front of a person, so
refusing untrusted content there would mean a task could only ever carry findings
nobody needs to review. The label is still on the run's journal; the control the
reviewer *is* is the review.

**The other trap:** `approval: none` with an empty `triage`. That is an oversight
block that performs nothing while reading in review as a human control, and it is
refused at parse.

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

## 🤝 Consult another agent, from a file

A grant spelled `tool://agent/<capability>` offers another agent's capability
to a tool-calling model — so a multi-agent room needs no Rust at all:

```yaml
# editor.yaml — the only agent permitted to delegate, and it says why
spec:
  topology: { mode: collaborative, role: orchestrator, reason: distinct-authority }
  security: { max_delegation_depth: 1, max_sensitivity_egress: internal }
  capabilities: { provides: [blog.report] }
  models: { privileged: { provider: chat-completions, model: "llama3.2" } }
  tools:
    - ref: tool://agent/research.summarise
      description: Ask the researcher to summarise a topic.
      arguments:
        type: object
        properties: { topic: { type: string } }
        required: [topic]
  execution: { kind: tool-calling, max_turns: 4 }
  budgets: {}
```

```yaml
# researcher.yaml — a specialist, structurally unable to delegate further
spec:
  topology: { mode: single, role: specialist }
  security: { max_sensitivity_egress: internal }
  capabilities: { provides: [research.summarise] }
  models: { privileged: { provider: chat-completions, model: "llama3.2" } }
  execution: { kind: completion }
  budgets: {}
```

Dispatch is `commission`, not a transport: the consultation is a journaled
delegation effect, so a strict replay reassembles the whole room without
waking anyone, the researcher's answer arrives labelled untrusted, its spend
bills the editor's run, and the depth ceiling sees the hop. The `agent` server
name is reserved — wiring a transport under it is refused at build, and a
grant naming a capability no agent on the plane provides refuses the build
too, rather than offering the model a consultation that fails when chosen.

The `blog_room` example runs both shapes side by side — a coded editor that
*dictates* the sequence, and this desk, on one plane. And the whole YAML room
lives in **one file**: `examples/room.yaml` holds all three manifests
separated by `---`, so the CLI runs it directly —
`agentplane run examples/room.yaml --input '{"topic": "..."}'` — starting at
the room's one declared orchestrator. Each document keeps its own digest; the
file is packaging, not identity.

**The trap:** treating the grant like a transported tool. It is not one, and
the parser says so: `mutates: false` is refused (what the specialist does to
the world is *its* declaration's statement to make), and `protected_fields` /
`max_sensitivity` are refused because the commission path never passes the
sink gate those act at — declare ceilings on the consulted agent instead. Two
ceilings interact by design: a commissioned input is `Internal` at least, so
both agents need `max_sensitivity_egress: internal` or the room refuses its
own point. `requires_approval: true` works exactly as on any grant — a person
sees the capability and the arguments before any specialist runs.

## 🗺️ Plan once, then execute without the model

When the task's shape is known up front and the data the tools return is
hostile, `kind: planned` beats the loop: one privileged call fixes the steps
before anything untrusted is read, and step outputs travel between steps as
references no model reads.

```yaml
spec:
  execution: { kind: planned, max_turns: 4 }
  models:
    privileged:   { provider: anthropic, model: claude-sonnet-5 }
    quarantined:  { provider: anthropic, model: claude-haiku-4-5-20251001 }
```

The planner answers with steps like
`{ "tool": "crm__lookup", "args": { "id": "$input/customer" } }` and
`{ "tool": "mail__send", "args": { "to": "$step0/email" } }` — the references
are resolved by the runtime, labels intact. A `parse` step hands a prior
output to the quarantined model under a bounded schema. Run
`cargo run --example planned_run --features redb,testkit,manifest` to watch a
prompt injection arrive in a tool output and find no reader.

**The trap:** planning over untrusted input. It is refused outright — the
planner reads the input to write the plan, so hand hostile content to a tool
or a `parse` step instead, or use `tool-calling`.

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
`completion`, `tool-calling` and `planned` are the prebuilt agent loops, minus
the part that runs outside the journal — and a typed `Tool` is about fifteen
lines.

## 🛠️ Call a tool from a skill you wrote

Use `cx.call_tool`. It dispatches over the **plane's own** catalogue — the one
`try_build` already checked against every agent's declaration:

```rust
let overdue = cx
    .call_tool(
        ToolId::new("obsd", "list_overdue_processes"),
        Tainted::trusted(json!({ "since": cutoff })),
    )
    .await?;
```

**The trap it removes:** building a `ToolCatalog` inside the skill. That is the
obvious thing to write, it compiles, it runs, and **nothing binds it to the
manifest governing the skill** — so the reach it grants is whatever the code
says. Worse, it can be *laxer*: `ToolSafety::read_only` for a tool the manifest
calls mutating exempts it from the whole-value taint gate and carries
`Recovery::Retry`, so a timed-out money-moving call is sent a second time.
`try_build` refuses exactly that divergence for the plane's catalogue; a
catalogue constructed inside a skill never passed under that check.

Where a skill genuinely needs its own — assembled before a runtime exists, or one
for a test — derive it with `ToolCatalog::from_manifest(&m)`, which reads the
reach off the declaration instead of restating it. See
`examples/governed_transfer.rs`.

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

## ⚖️ Turn on a policy engine

The policy text is in [security](@/docs/security.md); this is the wiring, which
nothing else showed.

```rust
use agentplane::policy::CedarEngine;

let engine = CedarEngine::new(std::fs::read_to_string("policy.cedar")?.as_str())?;
let runtime = Runtime::builder(store)
    .policy(Arc::new(engine) as Arc<dyn PolicyEngine>)
    .skill(MySkill)
    .build();
```

`CedarEngine::from_bundle` takes a schema and static entities too, and validates
the policies against the schema **at startup** — a policy set that cannot compile
should fail when you deploy it, not on the first request that needs it.

Three things bite:

- **There is no `AllowAll`.** No engine wired means no gate; a permissive engine
  and no engine are the same behaviour, so having two spellings is how a plane
  ends up with a policy layer everyone believes is on.
- **A broken policy denies everything, and says so differently.** Cedar is total,
  so a rule that fails to evaluate simply does not contribute and the answer is a
  clean `Deny`. That is reported as *malformed* rather than as a refusal —
  `policy_error=true` in the `tracing` event — because "the rules say no" and
  "the rules are broken and nobody noticed" call for opposite responses.
- **The runtime's gates see no caller roles.** `run:admit` and `effect:perform`
  are asked by the runtime, which has a plan and a delegation chain, not an HTTP
  request. `context.roles` exists on the `api:*` and `a2a:*` actions only; to key
  the runtime's gates on who asked, give the run a delegation chain, whose
  context is merged into those requests.

## 📡 Host an agent as an A2A peer

```sh
agentplane serve examples/served.yaml \
  --url https://agent.example.com --addr 0.0.0.0:8080 \
  --policy policy.cedar --tokens tokens.yaml --store ./served.redb \
  --operator-addr 127.0.0.1:9090 --push-host hooks.example.com
```

Serves the public Agent Card and the A2A 1.0 methods, sweeps deadlines and due
timers every 30s, and — on a **separate** listener — the operator surface:
`GET /runs?outcome=quarantined`, the worklist, task decisions. The two are
separated by *policy* (`peer` reaches `a2a:*`, `operator` reaches `api:*`), so
the port split is defence in depth rather than the control.

The worklist's claim protocol has three verbs, and the third has its own
policy action on purpose. A reviewer `claim`s a task and only the holder can
`release` it — which leaves the absent-holder case: a task claimed by someone
who is not coming back is parked until its deadline breaches. `POST
/tasks/{task}/takeover` (`api:task.takeover`) displaces a **named** holder —
the body's `from` is a compare-and-swap, so a stale queue view fails rather
than displacing whoever holds it now — and re-checks eligibility in full: a
take-over is a claim, and four-eyes exclusion does not thin because the
previous reviewer left. Its own verb means a policy set can hand it to a queue
lead without handing displacement to every reviewer.

`--policy`, `--tokens` and `--store` have no defaults. A served task's id is a
promise it can be fetched again, which an in-memory journal breaks at the next
restart. Needs `--features cli,a2a-server,cedar`, or the `:full` image. The full
walkthrough is in [getting started](@/docs/getting-started.md).

## 📤 Emit an event per run, without an outbox table

A2A push is **caller-shaped**: the URL comes from whoever created the task, which
is why three controls sit around it. The shape a service wants beside it is the
mirror — one destination the *deployment* configured, receiving one payload the
embedder shapes, for every run.

```rust
use agentplane::push::{Destination, DeliveryWorker, Outbox, PushSender, RunCompleted};

let outbox = Arc::new(Outbox::new(
    Arc::clone(&store) as Arc<dyn PushStore>,
    vec![Destination::new("bus", "http://events.internal/ingest")],
));
let rt = Runtime::builder(store).agent(..).outbox(Arc::clone(&outbox)).try_build()?;

// Scheduled by the operator, like every other sweep.
let worker = DeliveryWorker::new(
    Arc::clone(rt.journal()),
    Arc::clone(&store) as Arc<dyn PushStore>,
    Arc::new(PushSender::for_operator_destinations(outbox.destinations())),
    Arc::new(RunCompleted::new("urn:mako:agentd")),
);
let report = worker.run_once(now_secs, 100).await?;
```

Each destination is registered against a run **at admission**, so there is no
window in which a run exists and nothing is watching it; delivery then reads the
run's own records past a durable cursor that advances only on 2xx. There is no
outbox table to fall out of sync with the history — **the journal is the outbox**,
which is the point.

`RunCompleted` emits one `CloudEvents` message per sealed run carrying the run
id, the case, the outcome and the chain head. It deliberately does **not** carry
the answer: a run's output is domain data with a label on it, and a default that
shipped it would make an egress decision nobody declared. Implement `Projection`
to shape your own.

**What is relaxed, and why it is not a weakening.** An operator destination skips
the host allowlist (there is no caller to check — the URL is in the deployment's
own configuration), HTTPS (an in-cluster collector on plaintext HTTP is ordinary,
and refusing it pushes operators toward a TLS-terminating sidecar that forwards in
clear) and the public-address check (resolving inward is the entire point). The
cursor discipline, the retry ceiling, the abandon-and-report on a permanent
refusal, and the no-proxy/no-redirect posture are all unchanged.

**The trap:** reusing an id in the operator namespace. Both kinds of registration
share one store and are told apart by the `operator:` prefix; the A2A server
refuses a caller-supplied `pushNotificationConfig.id` that begins with it,
because operator destinations are exempt from the URL controls precisely on the
grounds that there is no caller involved.

## ✍️ Sign the body a destination receives

A bearer header proves the *sender* held a token — a claim about the connection,
not about the bytes — and that token transits every hop between here and the
receiver. Signing is the other claim, and destinations take both:

```rust
let bus = Destination::new("bus", "http://events.internal/ingest")
    .authenticated("Bearer", Secret::new(std::env::var("BUS_TOKEN")?))
    .signed_with("X-Mako-Signature", Secret::new(std::env::var("BUS_SIGNING_KEY")?));
```

Every delivery to it then carries `X-Mako-Signature: sha256=<hex>`, which is
`HMAC-SHA256` over the **exact bytes POSTed** — the GitHub/Stripe convention, so
a receiver already written against one of those verifies this one. The key is
never written to the push store: it is deployment configuration read at every
start, so there is no copy of a forge-anything key sitting in a row per run, and
rotating it takes effect on the next sweep rather than on the next admission.
That is why `for_operator_destinations` takes the destinations — a sender built
without them would deliver unsigned, and only the receiver could ever notice.

**What a valid signature does not prove.** Not freshness: there is no timestamp
and no nonce in what is MACed, so a captured delivery replays forever and every
check still passes. Only the receiver closes that, by deduplicating on the
event's own identity — which `RunCompleted` supplies as CloudEvents' `(source,
id)` pair, and which a receiver already needs, because at-least-once delivery
repeats events on an ordinary crash. Not origin in the third-party sense either:
the secret is symmetric, so anyone holding it can mint the same signature. And
a receiver must **require** the header — verifying it when present and accepting
it when absent buys nothing, because an attacker simply omits it.

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

**Which drivers ask.** Anthropic, `OpenAI`, Gemini and the `OpenAI`-compatible
driver, plus the `OpenAI` embedder. **Bedrock does not** — it is handed a built
AWS client whose endpoint the SDK will not disclose, so the only host it could
check is one derived from the region, which an endpoint override makes a
fiction. Constrain a Bedrock plane where the SDK does: a VPC endpoint, an egress
proxy, or an IAM policy. What the driver does give you is the region on the
record — read from the client, and part of effect identity, so a change of
region is replay divergence rather than a quiet move.

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

## 💳 Bound what one authorization is good for

Three ceilings exist and they answer different questions. A `Budget` bounds
**one run**. A `TenantQuota` bounds **one tenant over a billing period**. Neither
can say *this customer approved €500, across however many runs it takes, until
they take it back* — that is an authorization rather than a throttle, and it is
what `authority` is for.

```rust
use agentplane::authority::{AuthorityId, AuthorityStore, StandingAuthority};
use agentplane::core::Spend;

// Issued once, from wherever the approval actually happened.
store.issue(
    &StandingAuthority::new("mandate-42", "approval:SET-42", Spend::money(50_000))
        .max_draws(10)
        .expires_at(end_of_quarter),
).await?;
```

Inside a skill, drawing is an ordinary journaled effect:

```rust
let drawn = cx.draw(&AuthorityId::new("mandate-42"), Spend::money(12_000)).await?;
// drawn.remaining is what is left, from the receipt — not a second read
```

Four things make this different from a counter:

**It is drawn on as an effect.** The balance is mutable state outside the
journal, so a skill reading it directly would make replay depend on what the
store holds *now* — a run replayed after a later draw would take a different
branch than its own history records. Strict replay reads the receipt back and
consumes nothing.

**A retry spends once.** The store deduplicates on the *dispatch* identifier,
which is stable across attempts, rather than the effect key, which deliberately
is not. Getting that backwards double-spends a customer's authorization and only
under retry — the condition hardest to notice in testing.

**A draw that already landed stays landed.** Retrying it after revocation
returns the original receipt rather than a refusal, because the money moved;
reporting it as refused would make a caller compensate something that stands.
New draws are refused, which is the half revocation is for.

**Revoked and exhausted are different answers.** One may be followed by a larger
authority; the other is a decision that has been taken back. `AuthorityError`
keeps them apart, along with expired, out-of-draws and unknown, so a caller does
not retry a decision that will never change.

Terms are immutable once issued — re-issuing identical terms is a retried
deploy and succeeds, differing terms are refused. A ceiling somebody agreed to
must not be editable under them; changing it means revoking and issuing another,
which leaves both on the record.

The accounting is in the store rather than the process, for the same reason
quotas are: an in-memory balance fails **open** the moment a second instance
starts, which is exactly when a shared ceiling was needed.

`cargo run --example standing_authority --features redb,testkit` runs all of
this end to end: one envelope spent across two separate runs, a draw over the
ceiling that consumes nothing, a revocation, and the terms still readable
afterwards — because an authority that vanished on revocation would take with it
the record of what the draws already taken were authorized by.

There is deliberately no refund. `Spend` is unsigned, so no draw can un-spend a
ceiling — a negative amount reverses the accumulation every ceiling here is
built on, and one would have removed the per-run budget and the tenant quota
alongside this. Restoring headroom means issuing another authority, which leaves
both decisions on the record rather than netting them out to a number nobody can
explain.

Both backends implement `AuthorityStore` against **one conformance battery**,
and that is where they differ in kind rather than degree. redb has a single
writer, so draws serialise for free. On `PostgreSQL` two instances can draw on
one authority at the same instant, and only the row lock the draw takes stops
both passing a check the other has already invalidated — which is why the
balance is read `FOR UPDATE` and why the receipt and the balance commit in one
transaction. A balance that advanced without its receipt would let the next
retry draw again, which is the double-spend the receipt table exists to make
impossible.

---

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

Semantic ranking stays outside `MemoryStore` and inside the journal. Get the
query vector from `cx.embed` — **never** by calling an embedder yourself: the
vector is inside the retrieval effect's identity, and an embedding service does
not promise the same floats twice, so a self-computed one quarantines a healthy
run on the next replay:

```rust
let query_vector = cx
    .embed(
        embedder,
        Tainted::trusted("refund policy".to_owned()),
        // Embedding sends the text to a provider, so it is an egress and the
        // ceiling is yours to set. A real query is untrusted — a user's
        // question, a model's rewrite — and therefore already `Internal`.
        Sensitivity::Internal,
    )
    .await?
    .peek()
    .clone();

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
out-of-scope or changed commitments.

### The embedder

`OpenAiEmbedder` speaks `POST /v1/embeddings`, which is `OpenAI`'s wire and the
one every compatible server answers — so it reaches OpenAI, Ollama, vLLM, TGI,
LM Studio and Hugging Face's router without a second driver, exactly as
`chat-completions` does for completions:

```rust
use agentplane::model::embeddings::OpenAiEmbedder;

let embedder = Arc::new(
    OpenAiEmbedder::new("text-embedding-3-small")?
        .key(std::env::var("OPENAI_API_KEY")?)
        .dimensions(512)
        .egress(Egress::new().allow("api.openai.com")),
);
```

Three drivers ship, chosen by which wire the provider speaks:

| Driver | Reaches | Feature |
|---|---|---|
| `OpenAiEmbedder` | `OpenAI`, **Voyage AI**, Ollama, vLLM, TGI, LM Studio, Hugging Face's router — anything answering `POST /v1/embeddings` | `providers` |
| `GeminiEmbedder` | Google `gemini-embedding-001` via `:embedContent` | `providers` |
| `BedrockEmbedder` | Amazon Titan Embed and Cohere Embed on Bedrock | `bedrock` |

**Anthropic has no embeddings API** and recommends Voyage AI, which the first
driver reaches by base URL alone — Voyage speaks the same `/v1/embeddings` wire,
so it needs no driver of its own:

```rust
OpenAiEmbedder::new("voyage-3-large")?
    .base("https://api.voyageai.com")
    .key(std::env::var("VOYAGE_API_KEY")?)
    .input_type("query")   // ← the one thing that is not optional in practice
```

`input_type` matters more than it looks. Voyage and Cohere embed questions and
documents into deliberately different regions and **rank worse when the two are
swapped** — returning vectors of exactly the right shape, so nothing downstream
notices. `OpenAI`'s own models are symmetric and take no such parameter, which is
why it is opt-in. Gemini's equivalent (`taskType`) is not a knob at all: this
seam only ever embeds the thing being looked *for*, so it is fixed to
`RETRIEVAL_QUERY`.

Bedrock's is a **declared dialect**, never sniffed from the model id — Titan
takes `inputText` and answers `embedding`, Cohere takes `texts` and answers
`embeddings`, and cross-region inference profiles prefix the id, so a substring
match would bind behaviour to a naming convention AWS owns:

```rust
BedrockEmbedder::from_env("eu-central-1", "amazon.titan-embed-text-v2:0",
                          EmbeddingDialect::Titan).await?
```

`revision()` names the model **and** the width, because both change the floats:
a 1536-wide vector and a 512-wide one from the same model rank against different
geometry, and the effect key is what stops a replay reading one as the other.
`BedrockEmbedder` puts the **region** in it too, because a Bedrock model id names
a model rather than a deployment: the same id in two regions is two services, and
a vector from one has no standing in an index built from the other. The region is
read from the client rather than passed beside it — it decides which index a
vector belongs to, so a copy that could disagree with the service the vectors
actually came from would be the copy the revision attests. It embeds one
text per call on purpose — one effect is one observation, and a batching driver
would have to decide how a partial failure maps onto several effect keys.

A reply that cannot be honestly read is **refused**, not repaired, and the two
that look harmless are the reason. A component no `f32` can hold — `1e39` is an
ordinary JSON number, and `1e39 as f32` is `inf` — would journal as `null`, so
every out-of-range component would share one effect key with every other. And a
vector of zero magnitude has no direction, so cosine against it is `0/0`;
handing it back would surface layers away as *the retriever returned a
non-finite score*, naming the retriever for the driver's answer. Both are
refused where the bytes arrive, naming the driver and the URL.

### Hybrid retrieval

**`SemanticQuery` carries the query text alongside the vector, and the text is a
search input rather than only provenance.** That is what makes hybrid retrieval
expressible: dense similarity finds meaning, the literal terms find the things
embeddings famously lose — identifiers, error codes, product names — and a
retriever fusing the two has everything it needs already in the struct.

Where the fusion is *declared* is `SemanticRetriever::profile()`, which is **in
the effect key**. So a weighting change, or switching fusion off, is replay
divergence rather than a quietly different ranking:

```rust
#[derive(Debug)]
struct LanceHybrid { table: Arc<lancedb::Table>, alpha: f32 }

#[async_trait]
impl SemanticRetriever for LanceHybrid {
    // Everything that changes the ranking, and nothing secret. A run whose
    // ranking was produced under `alpha: 0.5` must not replay under `0.7`
    // and call itself the same history.
    fn profile(&self) -> Value {
        json!({ "engine": "lancedb", "fusion": "rrf", "alpha": self.alpha })
    }

    async fn search(&self, q: &SemanticQuery) -> Result<Vec<SemanticHit>, StoreError> {
        // Dense from `q.embedding`, lexical from `q.text`, fused — then return
        // **commitments**, never content: `(id, version, digest)` and a score.
        // The index is derived; authoritative memory is what the runtime reads
        // back, and it verifies scope and digest before anything is exposed.
    }
}
```

The rule a retriever must not break: return `Selected` commitments and scores,
never item content. An index is derived and may be stale, poisoned or simply
wrong; the runtime materializes the exact versions from `MemoryStore` and
refuses out-of-scope or changed digests. A retriever that returned text would be
handing the model something nothing verified.

`InMemorySemanticRetriever` is the exact-cosine reference and ranks on the
vector alone — a reference implementation, not a statement about what the seam
permits.

### Several passes, and rephrasing

A conversational agent that rephrases before retrieving is a *composition*, not a
new execution kind — and every step is already an effect, so the whole pass
replays without repeating a call:

```rust
// 1. What has been said, from case state — journaled, so replay reads it back.
let (history, _version) = cx.case_state().await?;

// 2. Rephrase. A model call like any other: keyed, metered, replayable.
//    The history is untrusted, so it goes in `messages`; the instruction that
//    says *rewrite this as a standalone question* is the manifest's, and
//    trusted, which is why `/system` is a protected field.
let standalone = cx.sink_with(&prompt, |value| ModelCall::new(provider, model, value)).await?;

// 3. Embed the rewritten question — never the raw turn.
let vector = cx
    .embed(
        embedder,
        standalone.map(|c| c.text.clone()),
        Sensitivity::Internal,
    )
    .await?;

// 4. Retrieve, 5. answer with what came back.
```

The reason to rephrase at all is the reason it belongs *before* the embedding:
"what about the second one?" embeds to nothing useful, and the vector is inside
the retrieval effect's identity — so the rewrite has to happen where the journal
can see it, not inside a helper that reruns differently next time.

There is deliberately **no `execution.kind: rag`**. The pipeline above is a plan:
which passes, whether to rephrase, whether to rerank are decisions a deployment
makes, and a fourth hardcoded tier would answer them once for everybody. That is
the prompt-framework job this runtime's non-goals disclaim.

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

**The third trap, and the one with legal teeth: a literal subject.** The subject
is the unit `forget_subject` erases, so

```yaml
memory_formation:
  subject: "agent:triage"       # every customer, one pile
```

pools every party the agent ever reasoned about under one key. One party's facts
are then recalled into another party's run, and an erasure request naming one
person cannot be satisfied without destroying everybody's. Bind it instead:

```yaml
memory_formation:
  subject: "$correlation/customer"   # resolved from the run's business keys
```

`$correlation/<namespace>`, `$case` and `$input/<pointer>` are the three sources;
an unrecognised `$` value is refused rather than filed as a constant, and
`$input` is refused unless the field it names is **trusted** — a subject taken
from untrusted input is whoever supplied it choosing whose memories this run
writes into. A hand-written skill reads the same values back with
`cx.correlation_value("customer")`, so the two tiers agree on the scope without
sharing a naming convention nobody wrote down. Full rules:
[`spec.memory_formation`](@/docs/manifest.md#spec-memory-formation).

With feature `keyring`, wrap a single-node memory backend in
`EncryptedMemoryStore::new`. Content is ciphertext in the backing
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
effect identity.

Explicit `reasoning_effort` is refused by default, because Converse has no
portable mapping across its model families — one envelope covers Anthropic's
adaptive thinking, Amazon Nova's `reasoningConfig`, and several families with no
such control at all. Say which family this driver instance serves and it stops
guessing:

```rust
let nova = Bedrock::from_env("us-east-1")
    .await?
    .reasoning(ReasoningDialect::Nova);   // us.amazon.nova-2-lite-v1:0
```

That renders a declared effort as Nova 2 documents it —
`additionalModelRequestFields.reasoningConfig`, with `type: enabled` and a
`maxReasoningEffort` of `low`, `medium` or `high` — on the buffered *and*
streaming paths, and puts the dialect in the request profile so switching it is
replay divergence rather than a quiet change in what governed the call.

Two edges worth knowing. `ReasoningEffort::None` sends `type: disabled` rather
than nothing, so *this call must not reason* is on the record. And `minimal`,
`xhigh` and `max` are **refused** — Nova has three levels, and collapsing a
request into the nearest one is a substitution nothing downstream could see.

Nova models are Bedrock models, so there is no separate Nova driver to reach
for.

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
        // `builder_on` wires every store to this tenant's scoped handle.
        Runtime::builder_on(store)
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

## 🗝️ Erase a customer's data everywhere

Deleting from the live store leaves every backup. Seal instead: one key ring on
the builder seals the journal, the case store, the worklist, the event buffer
and blob payloads.

```rust
// `builder_on` wires all six stores — journal, cases, tasks, events, timers,
// memory — to one backend in one call, which is what a deployment on a single
// `RedbStore` or `PostgresStore` means anyway.
let rt = Runtime::builder_on(store)
    .keyring(keys)          // seals all of them
    .build();
```

Erasing a case destroys its wrapping key, so every copy becomes unreadable at
once — including the ones nobody can reach:

```rust
blob::erase_case(&blobs, cases.as_ref(), Some(keys.as_ref()), &tenant, case, at, reason).await?;
```

The chain still verifies afterwards, because it commits to the sealed bytes
rather than the plaintext. An erasure costs the data, not the proof that
nothing was altered. See it end to end with
`cargo run --example sealed_run --features redb,testkit,keyring`.

**The trap: assuming everything is erasable.** What a store is asked questions
*about* stays readable — correlation keys, event `source`/`id`, task summaries,
deadline names — because sealing them would leave a buffer that cannot
deduplicate and a worklist nobody can read. And an inbound event is its own
erasure unit rather than the case's: it is buffered before any subscription
matches it, so an unclaimed one belongs to no case at all. Check
[erasure and keys](@/docs/erasure.md#what-lands-where-and-what-can-be-erased)
row by row before deciding what may enter a run.

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
