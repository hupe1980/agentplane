# 🚀 Getting started

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
agentplane = "0.1"
```

SQLite is the default backend. Everything else is opt-in:

```toml
agentplane = { version = "0.1", features = ["postgres", "http", "mcp", "providers", "cedar", "signing"] }
```

| feature | gives you |
|---|---|
| `sqlite` *(default)* | journal + case store, single node |
| `postgres` | the same contract, for several plane instances sharing a store |
| `http` | the operator surface: worklist, decisions, run status |
| `mcp` | MCP tool transport |
| `a2a` | A2A peer transport |
| `providers` | Anthropic and OpenAI model drivers |
| `cedar` | Cedar as the authorization engine |
| `signing` | Ed25519 record attestation |
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
[concepts](concepts.md).

**`cx.now()`, not `SystemTime::now()`.** The ambient clock is denied crate-wide by
lint. Anything non-deterministic goes through `cx`, which journals it — and that
is exactly what makes replay possible.

## 4. Run it ▶️

```rust
use agentplane::journal::JournalStore;
use agentplane::runtime::{Mode, Runtime};
use agentplane::store::SqliteStore;
use std::sync::Arc;

let store: Arc<dyn JournalStore> = Arc::new(SqliteStore::open_in_memory()?);

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
use agentplane::tools::{ToolCall, ToolCatalog, ToolId, ToolSafety};

// The operator declares what a tool does. A tool absent from the catalogue
// cannot be called at all — a tool nobody declared is one nobody reasoned about.
let catalog = ToolCatalog::new()
    .allow(ToolId::new("ledger", "post_entry"), ToolSafety::default());

let call = ToolCall::prepare(&catalog, client, ToolId::new("ledger", "post_entry"), args)?;
let result = cx.effect(call).await?;   // Tainted<Value>, untrusted
```

`ToolSafety::default()` says **mutates**, and that default is the whole posture: a
tool nobody has thought about gets the treatment that makes the runtime cautious,
not the one that makes it fast. A mutating call whose outcome is unknown escalates
to an operator rather than being retried.

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

| | |
|---|---|
| 🧠 | [Concepts](concepts.md) — runs vs cases, effects, dispositions, labels |
| 🍳 | [Cookbook](cookbook.md) — "how do I …" recipes |
| 🏗️ | [Architecture](architecture.md) — how the mechanisms actually work |
| 🔐 | [Security model](security.md) — the trust boundary and its limits |
| ⚙️ | [Operations](operations.md) — running it for real |

## Troubleshooting 🔧

**`Quarantined("non-determinism at seq …")`** — the code changed since the
journal was written, and replay found a different effect than history records.
That is the mechanism working. Use `Mode::Resume` for crash recovery of the
*same* build; a changed build replaying old history is divergence, not recovery.

**`StepError::Denied`** — the policy engine refused. The journal has the reason;
what the *model* is told is one uniform sentence on purpose, because a precise
refusal is an oracle an injected prompt can probe. See
[security](security.md).

**A run that never finishes** — it is probably suspended waiting for an event,
a timer, or a human. `GET /runs/{id}` reports *why* it is not finishing rather
than just that it is not.
