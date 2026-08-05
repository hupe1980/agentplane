+++
title = "Getting started"
description = "Fifteen minutes from nothing to a run that survives a crash, replays exactly, and refuses to rewrite its own history."
weight = 1
+++

Fifteen minutes from nothing to a run that survives a crash, replays exactly, and
refuses to rewrite its own history.

Every snippet here is either lifted from a working example in `examples/` — which
CI runs on every push — or from the crate's own compile-checked rustdoc. If one
does not build, that is a bug worth reporting.

---

## 1. See it work first 👀

Before writing anything, run the thing that demonstrates the whole claim:

```sh
git clone https://github.com/hupe1980/agentplane
cd agentplane
cargo run --example durable_pipeline
```

```
1. live run      → Succeeded
   external calls: 3

2. strict replay → Succeeded
   external calls: 3 (unchanged: true)

3. run crashed   → Failed("simulated crash after stage 0")
   external calls: 1
   resumed        → Succeeded
   external calls: 3 — stage 0 was replayed, not repeated

4. changed build → Quarantined("non-determinism at seq 8: expected ek:cf87…")

5. all journals verify — no record was altered after the fact
```

Read those five lines slowly, because they are the product:

- **2** — replaying performed *nothing*. The counter did not move.
- **3** — the crash resumed at stage 2. Stage 0 ran once across both attempts,
  not twice.
- **4** — a *different build* replaying an old journal is *quarantined*. It is
  not silently accepted, and it is not a crash to recover from. Changing code and
  crashing are different things, and only one of them is recoverable.

## 2. Add the crate 📦

```toml
[dependencies]
agentplane = "0.2"
```

## An agent with no Rust

If the agent is a prompt, a model and a result shape, it needs no program at all
— a file and a key are the whole thing:

```yaml
# summariser.yaml
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
    privileged: { provider: fake, model: sum-1 }
  output:
    schema:
      type: object
      required: [summary]
      properties: { summary: { type: string } }
  budgets: { max_tokens: 10000 }
```

```sh
cargo install agentplane --features cli

agentplane validate summariser.yaml
agentplane digest   summariser.yaml     # what a registry pins
agentplane run      summariser.yaml --input '{"ticket": "printer on fire"}'
```

This exact file uses the deterministic fake driver, so the first run needs
**no API key and no network**. To go live, change the provider and model in the
file (that intentionally changes its digest), install the `providers` feature,
and export the matching key.

The answer goes to stdout and everything else to stderr, so it pipes. A run that
is refused, exhausted or failed exits non-zero, because whoever scripts this
needs the shell's own answer to "did it work".

Keys come from the environment (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`), never
from the file; Bedrock uses `AWS_REGION` and AWS's standard credential chain.
An agent's declaration must not change when its credential does. And only
the providers the manifest *names* are registered — otherwise exporting the wrong
variable would make the agent runnable on a model its declaration never named.

An embedded [redb](https://github.com/cberner/redb) store is the default backend
— pure Rust, two crates deep, with a stable on-disk format and no C toolchain in
your build. Everything else is opt-in:

```toml
[dependencies]
agentplane   = "0.2"
serde_json   = "1"
# A `Skill` is an async trait, and the runtime is async. Both are yours to
# choose, so neither is re-exported — but the snippets below will not compile
# without them.
async-trait  = "0.1"
tokio        = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Everything beyond a single-node runtime is opt-in:

```toml
agentplane = { version = "0.2", features = ["postgres", "http", "mcp", "providers", "bedrock", "media", "cedar", "signing"] }
```

| feature | gives you |
|---|---|
| `redb` *(default)* | journal + case store, single node, embedded |
| `postgres` | the same contract, for several plane instances sharing a store |
| `http` | the operator surface: worklist, decisions, run status |
| `mcp` | MCP tool transport |
| `a2a` | A2A peer transport — calling other agents |
| `a2a-server` | being called: the public Agent Card and the A2A 1.0 JSON-RPC methods |
| `push` | Persistent A2A registration cursors, retrying worker API, and SSRF-guarded webhook delivery; `a2a-server` includes it |
| `providers` | Anthropic and OpenAI model drivers |
| `bedrock` | Amazon Bedrock Runtime Converse through the AWS SDK; separate because the dependency graph is substantial |
| `media` | governed remote-media fetch: exact grants, SSRF-safe pinned DNS, redirects, limits, validation, digest and retention |
| `cedar` | Cedar as the authorization engine |
| `signing` | Ed25519 record attestation |
| `manifest` | declare an agent's grants and ceilings in a reviewable YAML file, and pin it by digest |
| `cli` | the `agentplane` binary — run a declarative agent from a YAML file with no Rust at all |
| `witness-http` | submit checkpoints to a real witness over C2SP `tlog-witness` — the half that gives the split-view guarantee a counterparty |
| `opendal` | content-addressed blob storage on S3, GCS, Azure or a filesystem — where bytes too large for the journal go |
| `keyring` | envelope encryption for payload bytes, and the cryptographic erasure it makes provable — destroying a key erases every copy, including backups |
| `keyring-vault` | a key ring that is somebody else: HashiCorp Vault's transit engine over its HTTP API, so the wrapping key never leaves Vault |
| `testkit` | fault injection, store conformance, a fake model provider |

## 3. Write a skill 🛠️

A skill is one unit of work. It gets a `StepCtx`, which is how it reaches
anything non-deterministic.

```rust
use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::runtime::StepCtx;
use serde_json::{Value, json};

#[derive(Debug)]
struct Greet;

#[async_trait::async_trait]
impl Skill for Greet {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("greet").provides("demo.greet")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // `now()` is a journaled effect: on replay it returns the recorded
        // instant rather than reading the clock again.
        let at = cx.now().await?;

        Ok(Outcome::done(input.map(|v| json!({
            "greeted": v,
            "at": at.to_string(),
        }))))
    }
}
```

Two things in that signature carry most of the design:

**`Tainted<Value>`, not `Value`.** Input arrives labeled — where it came from,
whether it is trusted, how sensitive it is. `peek()` reads it; `map()` transforms
it while carrying the label along. There is no infallible unwrap, because leaving
the lattice is a decision that gets journaled. See
[concepts](@/docs/concepts.md).

**`cx.now()`, not `SystemTime::now()`.** The ambient clock is denied crate-wide by
lint. Anything non-deterministic goes through `cx`, which journals it — and that
is exactly what makes replay possible.

## 4. Run it ▶️

```rust
use agentplane::journal::JournalStore;
use agentplane::runtime::{Mode, Runtime};
use agentplane::store::RedbStore;
use std::sync::Arc;

let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);

let runtime = Runtime::builder(Arc::clone(&store))
    .owner("my-service")
    .skill(Greet)
    .build();

let outcome = runtime.run("demo.greet", json!({ "name": "world" })).await?;
println!("{:?} → {:?}", outcome.status, outcome.output);

// Re-executes the logic, reads every effect back. Nothing is performed again.
let replayed = runtime.replay(outcome.run_id, Mode::Strict).await?;
assert_eq!(outcome.output, replayed.output);
```

Note `run("demo.greet", …)` takes the **capability**, not the skill name. Plans
bind capabilities to skills, so what a step needs is decoupled from who provides
it.

## 5. Do something to the outside world 🌍

The point of the journal is effects. Here is a tool call:

```rust
use agentplane::core::{ProtectedField, Release, ReleaseScope, Tainted};
use agentplane::tools::{ToolCall, ToolCatalog, ToolId, ToolSafety};

// The operator declares what a tool does. A tool absent from the catalogue
// cannot be called at all — a tool nobody declared is one nobody reasoned about.
let catalog = ToolCatalog::new()
  .allow(
    ToolId::new("ledger", "post_entry"),
    ToolSafety::default().protect(ProtectedField::trusted("/account")),
  );

let args = Tainted::object([
  ("account".to_owned(), Tainted::trusted(json!("receivables"))),
  ("memo".to_owned(), model_written_memo), // may remain untrusted
]);
let call = ToolCall::prepare(
  &catalog,
  client,
  ToolId::new("ledger", "post_entry"),
  args.peek().clone(),
)?;
let result = cx.sink(call, &args).await?; // exact bytes, protected account
```

`ToolSafety::default()` says **mutates**, and that default is the whole posture: a
tool nobody has thought about gets the treatment that makes the runtime cautious,
not the one that makes it fast. A mutating call whose outcome is unknown escalates
to an operator rather than being retried. Any effect that exposes outbound
arguments must use `sink`; `effect` refuses it, so the check cannot be skipped.
The protected account must be trusted, while an ordinary memo can retain model
provenance.

If a person or trusted process authorizes a label change, use a typed release:

```rust
let args = cx.release(
  args,
  Release::fields(
    ReleaseScope::trust(),
    ["/account".to_owned()],
    "operator matched the account to settlement SET-42",
    "mcp://ledger/post_entry",
    ["approval:SET-42".to_owned()],
  ),
).await?;
```

This asks policy under `data:release`, retains provenance, and journals the
releaser, scope, destination, basis and evidence. It never returns a bare value.

## 6. Wait for a human ⏸️

```rust
let decision = cx.task(
    &TaskSpec::new("rejection-handling", justification, "decision")
        .role("ops")
        .excluding("agent:proposer")   // four eyes: the proposer cannot approve
        .on_expiry(OnExpiry::Escalate),
).await?;
```

The run **suspends**. Its frame goes to disk and the task is dropped — a
suspended run costs bytes, not a thread, so a plane can hold 10⁵ of them waiting
for approval. When someone decides, the run resumes exactly where it was.

## 7. Test it 🧪

The `testkit` feature gives you a model provider with no model behind it, so a
test can exercise the whole path with no key and no network:

```rust
use agentplane::testkit::FakeProvider;

let provider = FakeProvider::new();
provider.will_say("approved");

// ... run, then assert on what the run did ...
assert_eq!(provider.calls(), 1, "replay must not ask the model again");
```

It is deterministic on purpose, and it never reports a call as free — a fake that
answered differently each time would make every replay test a coin-toss, and one
that reported zero usage would let every budget test pass over a runtime that had
stopped counting.

## Where next 🧭

Pick the example for the question you have; none needs credentials or network:

| Question | Example |
|---|---|
| Does replay or crash recovery repeat calls? | `durable_pipeline` |
| How do long-lived cases, early events and human work fit? | `clearing_case` |
| How are plans validated and provenance propagated? | `plan_graph` |
| Can untrusted content accompany a trusted tool selector safely? | `governed_transfer` |
| What happens after the third system in a transactionless workflow fails? | `saga_checkout` |
| Does a replay call the model or spend again? | `model_run` |
| How do governed media capabilities materialize without entering the journal? | `media_run` |
| Can prompt, model, schema and ceilings be one digest-covered file? | `manifest_run` |
| How are separate agents and handoffs bounded? | `blog_room` |

| | |
|---|---|
| 🧠 | [Concepts](@/docs/concepts.md) — runs vs cases, effects, dispositions, labels |
| 🍳 | [Cookbook](@/docs/cookbook.md) — "how do I …" recipes |
| 🏗️ | [Architecture](@/docs/architecture.md) — how the mechanisms actually work |
| 🔐 | [Security model](@/docs/security.md) — the trust boundary and its limits |
| ⚙️ | [Operations](@/docs/operations.md) — running it for real |

## Troubleshooting 🔧

**`Quarantined("non-determinism at seq …")`** — the code changed since the
journal was written, and replay found a different effect than history records.
That is the mechanism working. Use `Mode::Resume` for crash recovery of the
*same* build; a changed build replaying old history is divergence, not recovery.

**`StepError::Denied`** — the policy engine refused. The journal has the reason;
what the *model* is told is one uniform sentence on purpose, because a precise
refusal is an oracle an injected prompt can probe. See
[security](@/docs/security.md).

**`sink ... requires cx.sink` / argument mismatch** — an outbound effect was
sent through `cx.effect`, or the effect carries different JSON from the labeled
value checked. Build the call from `args.peek().clone()` and dispatch it with
`cx.sink(call, &args)`.

**`protected field ...`** — an authority-bearing path is absent, untrusted,
derived from a source outside the allowlist, or above its own sensitivity
ceiling. Fix the dataflow or use a narrowly scoped, policy-authorized `Release`;
do not mark the whole object trusted.

**`Exhausted(...)`** — a declared step/effect/token/cost/time/denial budget
bound the run. This is a terminal, journaled outcome, not a transient provider
failure. Raise the reviewed ceiling or reduce the plan.

**A run that never finishes** — it is probably suspended waiting for an event,
a timer, or a human. `GET /runs/{id}` reports *why* it is not finishing rather
than just that it is not.
