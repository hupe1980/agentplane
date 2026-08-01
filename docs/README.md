# 📚 Documentation

Routed by what you are trying to do.

| I want to… | Read |
|---|---|
| 🚀 get something running | [Getting started](getting-started.md) |
| 🧠 understand the vocabulary | [Concepts](concepts.md) |
| 🍳 do a specific thing | [Cookbook](cookbook.md) |
| 🏗️ know how it actually works | [Architecture](architecture.md) |
| 🔐 evaluate the trust boundary | [Security model](security.md) |
| ⚙️ run it in production | [Operations](operations.md) |
| 📋 know what is and isn't built | [Status](status.md) |
| 🤝 change the code | [Contributing](../CONTRIBUTING.md) |

The API reference is `cargo doc --all-features --open`, or
[docs.rs](https://docs.rs/agentplane). It lives there rather than here because
rustdoc cannot drift from the code — an earlier revision of the design document
carried a hand-transcribed API section that had gone quietly wrong in half a
dozen signatures, describing a shape the code no longer had.

## 📖 Reading order

**Evaluating it** — is this the right tool?
[Status](status.md) for what exists, then [Concepts](concepts.md) for the model,
then [Security](security.md) for what it does not cover. The last one is the
honest part: every gap that is open is listed rather than omitted.

**Building on it** — [Getting started](getting-started.md), then
[Cookbook](cookbook.md) as tasks come up, then [Architecture](architecture.md)
when a mechanism surprises you.

**Operating it** — [Operations](operations.md), which has the runbook, the
topologies, and what the plane reports about itself.

## 🎯 The one idea

If you read nothing else:

> **The journal is the plan of record.** Orchestration is deterministic and
> replayable; everything non-deterministic is an *effect* — performed at most
> once, journaled, and read back on replay.

Recovery, audit, cost accounting, regression testing, tamper evidence and
regulatory record-keeping are then six views over one log, rather than six
subsystems that can each rot independently. Every document here is downstream of
that sentence.
