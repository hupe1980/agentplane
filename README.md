# agentplane

**A durable, replayable, policy-governed runtime for AI agents — in Rust.** 🦀

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#-license)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange)](#-status)
[![MSRV](https://img.shields.io/badge/rustc-1.94.1%2B-lightgrey)](#-status)

Not a prompt framework. Not an agent library. The layer *beneath* those — the
thing that makes an agent's actions survivable, auditable, and governable when it
is calling real systems that move real money.

```rust
// Performs its effects once, and journals everything.
let outcome = runtime.run("reconcile", Tainted::trusted(input)).await?;

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
cargo run --example hello_skill        # one skill, one run, one replay — start here
cargo run --example durable_pipeline   # crash, resume, divergence
cargo run --example clearing_case      # correlation, obligations, human tasks
cargo run --example plan_graph         # multi-step plans, contract, provenance
cargo run --example governed_transfer --features manifest
                                        # field provenance, protected arguments
cargo run --example saga_checkout      # reverse compensation, replay-safe unwind
cargo run --example effect_group       # calls that take together, or not at all
cargo run --example memory_run         # private/team memory, provenance, recall
cargo run --example budget_pause       # a ceiling pauses the run; a raise
                                        # resumes it, on the record, nothing repeated
cargo run --example operator_stop      # cancel a run and it unwinds; halt a
                                        # tenant and nothing new starts
cargo run --example recovered_run      # an instance dies mid-run; the survivor's
                                        # sweep finds it and finishes it
cargo run --example bedrock_live --features bedrock
                                        # env-gated Amazon Bedrock Converse call
cargo run --example openai_live --features providers
                                        # env-gated OpenAI Responses call
cargo run --example tool_loop --features redb,testkit,manifest
                                        # a model choosing tools, and four refusals
cargo run --example approved_call --features redb,testkit,manifest
                                        # a person approves the exact call —
                                        # suspend, worklist, approve or refuse
cargo run --example planned_run --features redb,testkit,manifest
                                        # plan once, execute without the model —
                                        # a prompt injection with no reader, and
                                        # an invented recipient refused
cargo run --example sealed_run --features redb,testkit,keyring
                                        # erase a case: every copy unreadable,
                                        # and the chain still verifies

# Calls a model and replays without calling it again — no API key, no network.
cargo run --example model_run --features redb,testkit

# Digest-only multimodal dispatch and zero-I/O replay — also fully offline.
cargo run --example media_run --features redb,testkit,media

# An agent whose prompt, model, result shape and ceilings come from a file.
cargo run --example manifest_run --features redb,testkit,manifest

# A real MCP server in this process beside a typed Rust tool — one agent
# reaching both, and a strict replay that calls neither.
cargo run --example mcp_tools --features redb,testkit,manifest,mcp

# Four agents, one plane: a coded editor that dictates the sequence, and a
# YAML desk that consults the same specialists as tool://agent/... grants.
cargo run --example blog_room --features redb,testkit,manifest

# This plane served as an A2A 1.0 agent, called the way a peer would call it:
# a public card, authenticated methods, and a message that arrives untrusted.
cargo run --example a2a_peer --features redb,a2a-server,manifest

# Two planes in one process: a served reviewer and a desk that consults it
# through `cx.call_peer` — the peer sees the run's chain plus one link, and a
# strict replay of the desk's run never reaches the reviewer.
cargo run --example peer_call --features redb,testkit,manifest,a2a,a2a-server

# Live tokens for a human, one journaled completion for the machine — and a
# replay that performs neither.
cargo run --example streaming_run --features redb,testkit

# One customer's approved €500, spent across two separate runs, then revoked —
# with the terms still readable afterwards.
cargo run --example standing_authority --features redb,testkit
```

Or skip Rust entirely — a file and a key are the whole agent, and a file may
hold a whole **room**: several manifests separated by `---`, the Kubernetes
packaging convention. Each document keeps its own digest — the file is
packaging, not identity — and a run starts at the room's declared orchestrator:

```sh
cargo install agentplane --features cli
agentplane run examples/summariser.yaml --input '{"ticket": "printer on fire"}'
agentplane run examples/room.yaml       --input '{"topic": "durable execution"}'
```

Or without a Rust toolchain at all — needing one to run a YAML file rather
defeats the point of the file:

```sh
docker run --rm -v "$PWD/examples:/work:ro" ghcr.io/hupe1980/agentplane \
  run /work/summariser.yaml --input '{"ticket": "printer on fire"}'
```

Distroless, nonroot, no shell. It runs `--read-only --network none` because the
default journal is genuinely in memory and the example's provider is the
deterministic fake — so the first run needs neither a disk nor the internet.
`:slim` (the default, and `:latest`) carries every model provider — Anthropic,
OpenAI, Gemini, Bedrock, any OpenAI-compatible server; `:full` adds MCP, the A2A
peer server, the operator HTTP API, Cedar, key rings, governed media and
Postgres. Both are multi-arch, cosign-signed keylessly, and carry SLSA build
provenance and an SBOM attached to the digest:

```sh
cosign verify ghcr.io/hupe1980/agentplane:slim \
  --certificate-identity-regexp 'https://github.com/hupe1980/agentplane/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/hupe1980/agentplane:slim -R hupe1980/agentplane
```

`durable_pipeline` prints the whole claim in four steps: a live run, a strict
replay that touches nothing, a crash that resumes without repeating work, and a
changed build that is **quarantined instead of quietly rewriting history**.

A first program is one import and about forty lines:

```rust
use agentplane::prelude::*;
```

And when it goes wrong, the plane answers with what it *does* have rather than
with a variant name — `fn main()` reports through `Debug`, so on the errors you
hold, `Debug` is the message:

```text
Error: no skill provides capability 'demo.greeet' — this plane provides:
demo.greet. `run` takes a capability, not a skill name; a skill declares its own
with `SkillDescriptor::new(..).provides(..)`
```

A declarative **tool loop** runs from a file too — the manifest grants
`tool://tickets/read`, and which transport reaches `tickets` is deployment
wiring rather than part of the reviewed declaration:

```sh
agentplane run examples/tool-calling.yaml --input '{"ticket": "T-1"}' \
  --mcp "tickets=python3 examples/mcp-server.py"
```

A grant naming a server nobody wired is refused at **build**, not on every run.
Needs `--features cli,mcp-stdio`, or the `:full` image.

And an agent can be **hosted** from the same file — the A2A 1.0 server that
passes the protocol project's own conformance kit, started without writing Rust:

```sh
agentplane serve examples/served.yaml \
  --url http://localhost:8080 \
  --policy examples/serve-policy.cedar \
  --tokens examples/serve-tokens.yaml \
  --store ./served.redb
```

Add `--operator-addr 127.0.0.1:9090` and the operator surface is served too —
the worklist and task decisions, plus the backlogs an on-call person asks for by
question rather than by id: what is quarantined, what is escalated, and what
obligations were missed ([the full table](https://hupe1980.github.io/agentplane/docs/operations/#what-the-endpoints-are-for))
— on their **own** listener, off
unless asked for, and separated from the peer surface by *policy* (`peer` reaches
`a2a:*`, `operator` reaches `api:*`) rather than by the port. A served plane also
sweeps deadlines, task expiry, dead letters, due timers **and abandoned runs**
— a lease that expired while still naming an owner is an instance that died
holding the run, and the sweep takes it over and resumes it — so a run that
sleeps, waits or loses its instance actually finishes.

Both `--policy` and `--tokens` are required and have no defaults. That is the
design rather than an inconvenience: a permissive engine and no engine are the
same behaviour, and a server that authenticates nobody has no actor to record a
decision against. A token may carry its caller's own `scope` and `not_after`;
every run that caller starts is then admitted under a chain rooted at the
caller — checked against the plan, refused once expired — and the journal
names the caller, never the plane, as who the run acted for. Needs
`--features cli,a2a-server,cedar`, or the `:full` image.

New here? → **[docs/getting-started.md](https://hupe1980.github.io/agentplane/docs/getting-started/)**

## 📦 What you get

| | |
|---|---|
| 🧾 | **A journal you can audit** — append-only, hash-chained, per-record signatures naming the workload that wrote them, and a per-plane Merkle log so deleting a whole run is detectable |
| ⏱️ | **Durable execution** — crash mid-run and resume from the last completed effect; a suspended run costs a row on disk, not a task. Recovery is *initiated*, not merely possible: the sweep finds every run whose owner died holding it — an expired, unreleased lease — and resumes it, journaling the takeover in its own sealed run |
| 🗂️ | **Cases, not long-lived workflows** — runs stay minutes, business processes span months, so a deploy never has to migrate an in-flight workflow. Inbound messages arrive at-least-once, so admission takes an idempotency key and claims it in the same transaction that writes the run's first record: a redelivery is answered with the original run — including when that run is parked on a human decision — rather than opening a second identical approval |
| 🛡️ | **Policy before live dispatch** — a total, I/O-free gate; denials are journaled, strict replay never re-judges history, and plan authority is checked before step 1 |
| 🏷️ | **Field-level information flow** — exact outbound arguments are bound to hierarchical provenance; recipient, amount, path, URL and other authority-bearing fields can require trusted or named sources while ordinary content remains untrusted |
| 💸 | **Budgets and tenant quotas that bind** — a failed model call is billed for what it burned, because the provider bills for it too. Tenant spend is settled exactly once per live pass: a durable journal marker supplies recovery intent, and an idempotent store receipt makes a lost acknowledgement retryable without charging twice |
| 🧬 | **Effects that take together, or not at all** — a group declares the resources it touches and refuses any member outside them. Each reversible member records the concrete call that undoes it, built from what that call *actually returned* rather than reconstructed later from state that has moved — the gap a per-step saga leaves, since `compensate` is handed the output of a step that failed and therefore has none. `commit` is the frontier: invariants are checked there because it is the last instant at which failing them is free, and only then are **deferred** members released. That is what makes an irreversible send safe — an aborted group never sends it, which beats sending and apologising. Doubt reverses nothing |
| 👤 | **Human oversight on the *call*, not a summary of it** — `requires_approval: true` on a tool grant opens a task carrying the exact tool and arguments about to be dispatched, and nothing happens until somebody approves. A reviewer may also answer *with* the arguments — an approval's amendment dispatches in the model's place, as the reviewer's own trusted value. Gating the agent's answer instead is a review that arrives after the money moved. Durable worklists, four-eyes, declared expiry behaviour, and an operator who can *stop* a run and have it unwind |
| 🔑 | **Erasure that reaches the backups** — deleting clears the live store; the backup taken an hour earlier still has everything, and backups are offsite and often immutable *by design*. So payload bytes are sealed under a per-case data key wrapped by a key the crate never holds: erasing a case **destroys the key**, and every copy becomes unreadable at once — including the ones nobody can reach. Sealed bytes are rotation-immutable, because the chain commits to them, so the erasure scope *is* the rotation unit. **And the journal too**: `SealedJournal::wrap(store, keys, tenant)` seals run input, prompts and tool-call arguments, effect outputs, failure messages, notes and frozen plans under the same per-case scope. Only the *payload* is sealed, so exactly-once and every index keep working with no key; and the chain commits to the **ciphertext**, so an auditor holding no keys still verifies the history of a run whose data is gone → [erasure and keys](https://hupe1980.github.io/agentplane/docs/erasure/) |
| 📄 | **An agent that is only a file** — `agentplane run agent.yaml`. No Rust, no `main`, no skill. The digest covers the agent *in its entirety* rather than only its boundary, **and** the run is journaled and deterministically replayable. Declarative formats give you the first; durable platforms give you the second; the pairing is what makes the evidence about something you can actually read |

Ten rows, not the inventory. The full surface — the export/audit/restore
toolchain, typed release, standing authorities, effect groups that commit with
the journal, the emergency stop, the audited sweeper, model drivers and
streaming, MCP and A2A on both sides, signed Agent Cards, governed media and
memory, multi-tenancy, quotas, witnessing, break-glass, and why there is no
`AllowAll` anywhere — is documented mechanism by mechanism on the site:
**[what you get, in full](https://hupe1980.github.io/agentplane/docs/)**.

What is deliberately **not** built, and what will move →
**[docs/status.md](https://hupe1980.github.io/agentplane/docs/status/)**

## 📚 Documentation

| | |
|---|---|
| 🚀 | [Getting started](https://hupe1980.github.io/agentplane/docs/getting-started/) — first run, first skill, first replay |
| 🐣 | [Your first agent](https://hupe1980.github.io/agentplane/docs/first-agent/) — a step-by-step tutorial: one agent, from an empty file to a durable, tool-using, pinnable declaration, no Rust required |
| 🧠 | [Concepts](https://hupe1980.github.io/agentplane/docs/concepts/) — the ideas the rest is built from |
| 🏗️ | [Architecture](https://hupe1980.github.io/agentplane/docs/architecture/) — how it actually works, mechanism by mechanism |
| 🍳 | [Cookbook](https://hupe1980.github.io/agentplane/docs/cookbook/) — task-shaped recipes, including wiring an MCP server beside typed tools |
| 📄 | [Manifest reference](https://hupe1980.github.io/agentplane/docs/manifest/) — every field, what enforces it, and what an absent value means; the [published JSON Schema](https://hupe1980.github.io/agentplane/agent.schema.json) gives editors autocomplete and inline errors via one modeline |
| 🧪 | [Testing agents](https://hupe1980.github.io/agentplane/docs/testing/) — the fake provider, fault injection, and proving a replay actually replayed |
| 🔐 | [Security model](https://hupe1980.github.io/agentplane/docs/security/) — the trust boundary, and what it does not cover |
| 🗝️ | [Erasure and keys](https://hupe1980.github.io/agentplane/docs/erasure/) — erasure that reaches backups, key rotation and revocation, and how tenants are kept apart |
| ⚙️ | [Operations](https://hupe1980.github.io/agentplane/docs/operations/) — deploying, HA, retention, observability |
| ⚖️ | [Regulation](https://hupe1980.github.io/agentplane/docs/regulation/) — EU AI Act obligation by obligation, and what is missing |
| 📋 | [Status](https://hupe1980.github.io/agentplane/docs/status/) — what is pre-alpha, what to pin, what is deliberately absent |
| ⬆️ | [Upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/) — what breaks between pre-alpha releases, and the shortest correct fix |
| 📜 | [Changelog](CHANGELOG.md) — what changed and when, including every mechanism's reasoning as it landed |
| 🤝 | [Contributing](CONTRIBUTING.md) — the assurance ladder, and how to run it |

## 🧪 Assurance

Each layer answers a question the others structurally cannot.

```sh
just              # list every check
just ci           # lint · 3 feature configs · examples · docs · packaging
just ci-full      # the above, plus TLA+ specs and the full mutation sweep

python3 tools/mutants.py <name> --verify   # break one guarantee, run its test
```

Two are unusual enough to name:

**🔬 Formal specs.** TLA+ specifications are model-checked on every push — the
effect protocol, retry safety, sagas, fencing, authorization, delegation. And
because a spec whose invariants cannot be violated proves nothing, each is
re-checked against deliberately broken copies of itself; every mutant must be
caught by the *specific* invariant written for it.

**🧾 Conformance by the protocol's own kit.** `just test-a2a-tck` runs the
official [a2a-tck](https://github.com/a2aproject/a2a-tck) against this crate's
A2A server on a live socket. Every other A2A test drives this server with this
crate's own client, which proves symmetry, not conformance — a client and
server written from the same misreading agree everywhere. The kit's first run
found five defects no in-repo test could reach.

**🌐 Tests against a real provider.** `just test-live` runs the OpenAI and
Gemini drivers against the actual APIs. They are gated twice — an explicit `AGENTPLANE_LIVE=1`
*and* a key — because a credential being available is not a decision to spend
money with it, and they are never part of `ci`. They exist because a stubbed
provider is structurally unable to have the defects a real one finds: it never
rejects a malformed request and never returns a shape the driver mis-reads.
Writing them found two, both of which every offline test had passed. The Gemini
battery is the sharpest case: a **thought signature** is minted and validated by
Google, so a canned server accepts whatever a fixture tells it to and says
nothing about whether Gemini takes the signature back — the one check that
distinguishes a driver carrying the model's turn verbatim from one rebuilding
it, which is where the rest of the ecosystem has been losing this.

**🧬 Mutation testing over the code.** Every load-bearing guarantee is broken on
purpose, and the test *named for each one* must fail. A mutation caught by some other test is
reported **weak**, not passing — that usually means the guarantee has no test of
its own and is being held up by one that could be rewritten without anyone
noticing what it protected.

This is not decoration. The project shipped an unfalsifiable guarantee once: the
refusal to replan on untrusted data was implemented, tested, and green — and
deleting it would have failed no test, because the fixtures laundered the taint
before it reached the check. It was found by accident. The sweep is so the next
one is not.

It runs on **every push**, sharded six ways. It was gated to pull requests, on
the reasoning that a push to `main` had already passed it — true of a repository
that merges, and this one has never opened a pull request, so the gate switched
the sweep off rather than making it cheaper. Three mutations then rotted into
code that no longer *compiled*, leaving three guarantees unfalsifiable with
every check green. `just anchors` reported all three present, correctly: it
checks that a mutation still **matches** the code it names, which is text and
not types.

`MUTANTS_SHARD=k/n` takes a round-robin slice — round-robin because the table
groups mutations by subject, so a contiguous split would hand one shard every
expensive target. Each line carries a `[current/total]` progress counter, and
each shard needs its own checkout: the sweep rewrites source in place.

## 🚫 Non-goals

| agentplane does **not** | Use instead |
|---|---|
| Ship a prompt library or IDE | Your prompts; agentplane pins the manifest that governs them by digest |
| Route or proxy model traffic | LiteLLM, Bifrost — **the drivers themselves ship**: OpenAI Responses, Anthropic Messages and Bedrock Converse are here, with streaming, structured output, reasoning continuation and per-provider failure mappings. What is out of scope is *choosing between them at runtime* |
| Implement a vector database | LanceDB / pgvector behind the `SemanticRetriever` seam; embedding is a journaled effect so the query vector is history rather than a recomputation |
| Ship a built-in tool catalogue | Write a typed `Tool`, or wire an MCP server. The tools other frameworks ship — web search, code interpreter — are mostly **provider-hosted**: they run during generation, so the call is not announced, authorized, metered or replayable. That is a world-visible action outside the journal, which is the one thing this runtime is for. Governed URL fetching is the `media` feature; untrusted code belongs behind a process boundary |
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

Rust **1.94.1+**. `#![forbid(unsafe_code)]`. One crate, feature-gated: an embedded
[redb](https://github.com/cberner/redb) store by default — pure Rust, two crates
deep, no C toolchain — with everything else opt-in.

Honest framing on regulation: agentplane is not "compliant" and cannot be.
Compliance attaches to a system in a context, assessed by its provider or
deployer. What this gives you is the **technical means** to discharge EU AI Act
Articles 12 and 14 — means that are already load-bearing for recovery and
testing, and therefore cannot quietly rot. [Regulation](https://hupe1980.github.io/agentplane/docs/regulation/) maps
obligation to mechanism, names what is *not* built, and notes that the Digital
Omnibus moved the high-risk dates to December 2027 without amending the
articles.

## 📄 License

MIT OR Apache-2.0, at your option.
