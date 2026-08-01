# agentplane

**A durable, replayable, policy-governed runtime for AI agents — in Rust.** 🦀

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#-license)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange)](#-status)
[![MSRV](https://img.shields.io/badge/rustc-1.94%2B-lightgrey)](#-status)

Not a prompt framework. Not an agent library. The layer *beneath* those — the
thing that makes an agent's actions survivable, auditable, and governable when it
is calling real systems that move real money.

```rust
// Performs its effects once, and journals everything.
let outcome = runtime.run("reconcile", input).await?;

// Replay re-executes the logic and reads every effect back from the journal.
// No tool is called again. No clock is read again. No invoice is issued twice.
runtime.replay(outcome.run_id, Mode::Strict).await?;
```

---

## 🔥 The problem

Production agents fail in ways a better model does not fix:

- A 40-minute run dies at minute 38, and the retry re-issues every invoice.
- *"Why did the agent refund €4,200?"* has no answer, because the reasoning was
  prose in a log line.
- Untrusted tool output steers the next tool call.
- A prompt change ships with no way to know what it broke.

These are **runtime** problems. agentplane is a runtime.

## 💡 The idea

> **The journal is the plan of record.** Orchestration is deterministic and
> replayable. Everything non-deterministic — model inference, tool calls, the
> clock, randomness — is an *effect*: performed at most once, written to an
> append-only hash-chained log, and read back on replay.

Get that right and six things fall out of **one** mechanism: crash recovery,
audit, cost accounting, regression testing, tamper evidence, and regulatory
record-keeping. They stop being six subsystems that can each rot independently.

And critically: **the audit trail is also the recovery mechanism**, so it cannot
quietly stop working — the system would stop working with it. Logging that exists
only to satisfy an auditor always rots.

## 🚀 Try it

```sh
cargo run --example durable_pipeline   # crash, resume, divergence
cargo run --example clearing_case      # correlation, obligations, human tasks
cargo run --example plan_graph         # multi-step plans, contract, provenance

# Calls a model and replays without calling it again — no API key, no network.
cargo run --example model_run --features turso,testkit
```

`durable_pipeline` prints the whole claim in four steps: a live run, a strict
replay that touches nothing, a crash that resumes without repeating work, and a
changed build that is **quarantined instead of quietly rewriting history**.

New here? → **[docs/getting-started.md](docs/getting-started.md)**

## 📦 What you get

| | |
|---|---|
| 🧾 | **A journal you can audit** — append-only, hash-chained, per-record signatures naming the workload that wrote them, and a per-plane Merkle log so deleting a whole run is detectable |
| ⏱️ | **Durable execution** — crash mid-run and resume from the last completed effect; a suspended run costs a row on disk, not a task |
| 🗂️ | **Cases, not long-lived workflows** — runs stay minutes, business processes span months, so a deploy never has to migrate an in-flight workflow |
| 🛡️ | **Policy before every effect** — a total, I/O-free gate; a run denied at step 7 never starts at step 1 |
| 🏷️ | **Information-flow labels** — *may this principal act* and *may this value go there* are different questions, and both are answerable |
| 💸 | **Budgets that bind** — a failed model call is billed for what it burned, because the provider bills for it too |
| 👤 | **Human oversight** — durable worklists with four-eyes, declared expiry behaviour, and an operator who can *stop* a run and have it unwind |
| 🔌 | **Real wires** — MCP tools, A2A peers, Anthropic and OpenAI drivers, each with a failure mapping that says whether the call landed |

Full inventory, including what is **not** built →
**[docs/status.md](docs/status.md)**

## 📚 Documentation

| | |
|---|---|
| 🚀 | [Getting started](docs/getting-started.md) — first run, first skill, first replay |
| 🧠 | [Concepts](docs/concepts.md) — the ideas the rest is built from |
| 🏗️ | [Architecture](docs/architecture.md) — how it actually works, mechanism by mechanism |
| 🍳 | [Cookbook](docs/cookbook.md) — task-shaped recipes |
| 🔐 | [Security model](docs/security.md) — the trust boundary, and what it does not cover |
| ⚙️ | [Operations](docs/operations.md) — deploying, HA, retention, observability |
| 📋 | [Status](docs/status.md) — built vs designed-not-built |
| 🤝 | [Contributing](CONTRIBUTING.md) — the assurance ladder, and how to run it |

## 🧪 Assurance

Each layer answers a question the others structurally cannot.

```sh
just              # list every check
just ci           # lint · 3 feature configs · examples · docs · packaging
just ci-full      # the above, plus TLA+ specs and the full mutation sweep
```

Two are unusual enough to name:

**🔬 Formal specs.** Six TLA+ specifications are model-checked on every push —
the effect protocol, retry safety, sagas, fencing, authorization, delegation. And
because a spec whose invariants cannot be violated proves nothing, each is
re-checked against 18 deliberately broken copies of itself; every mutant must be
caught by the *specific* invariant written for it.

**🧬 Mutation testing over the code.** 102 guarantees are broken on purpose, and
the test *named for each one* must fail. A mutation caught by some other test is
reported **weak**, not passing — that usually means the guarantee has no test of
its own and is being held up by one that could be rewritten without anyone
noticing what it protected.

This is not decoration. The project shipped an unfalsifiable guarantee once: the
refusal to replan on untrusted data was implemented, tested, and green — and
deleting it would have failed no test, because the fixtures laundered the taint
before it reached the check. It was found by accident. The sweep is so the next
one is not.

## 🚫 Non-goals

| agentplane does **not** | Use instead |
|---|---|
| Ship a prompt library or IDE | Your manifests; agentplane hashes and versions them |
| Route or proxy model traffic | LiteLLM, Bifrost, your own `ModelProvider` |
| Implement a vector database | LanceDB / pgvector behind a seam |
| Replace a deterministic protocol engine | Keep it; agentplane sits *beside* it, never inside it |
| Require Kubernetes | One static binary |
| Train, fine-tune, or serve models | Permanently out of scope |
| Grade output quality | It emits replayable traces; grade them elsewhere |
| Interpret payload contents | Payloads are opaque, and labeled |
| Claim regulatory compliance | It provides technical means; compliance is the deployer's |

**Who should not use this:** a team running three agents against low-stakes data.
The complexity is justified when agents touch money, meters, or regulated
records.

## 📌 Status

**Pre-alpha, pre-release, no API stability.** Breaking changes land without
deprecation. The journal record format and the storage schema will change.

Rust **1.94+**. `#![forbid(unsafe_code)]`. One crate, feature-gated: an embedded
[Turso](https://github.com/tursodatabase/turso) store by default — SQLite
semantics, pure Rust, no C toolchain — with everything else opt-in.

Honest framing on regulation: agentplane is not "compliant" and cannot be.
Compliance attaches to a system in a context, assessed by its provider or
deployer. What this gives you is the **technical means** to discharge EU AI Act
Articles 12, 14 and 26 — means that are already load-bearing for recovery and
testing, and therefore cannot quietly rot.

## 📄 License

MIT OR Apache-2.0, at your option.
