# agentplane

**A durable, replayable, policy-governed runtime for AI agents — in Rust.** 🦀

[![crates.io](https://img.shields.io/crates/v/agentplane.svg)](https://crates.io/crates/agentplane)
[![API docs](https://img.shields.io/docsrs/agentplane)](https://docs.rs/agentplane)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#-license)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange)](#-status)
[![MSRV](https://img.shields.io/badge/rustc-1.94.1%2B-lightgrey)](#-status)

**[Documentation](https://hupe1980.github.io/agentplane/docs/) ·
[Getting started](https://hupe1980.github.io/agentplane/docs/getting-started/) ·
[API reference](https://docs.rs/agentplane) ·
[What will move](https://hupe1980.github.io/agentplane/docs/status/)**

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
```

`durable_pipeline` prints the whole claim in four steps: a live run, a strict
replay that touches nothing, a crash that resumes without repeating work, and a
changed build that is **quarantined instead of quietly rewriting history**.
[`hello_skill`](https://github.com/hupe1980/agentplane/blob/main/examples/hello_skill.rs)
is a first program: one `use agentplane::prelude::*;` and about forty lines.
Every other example, by the question it answers and with the features it
needs, is in
[the example index](https://hupe1980.github.io/agentplane/docs/getting-started/#where-next).

And when it goes wrong, the plane answers with what it *does* have rather than
with a variant name — `fn main()` reports through `Debug`, so on the errors you
hold, `Debug` is the message:

```text
Error: no skill provides capability 'demo.greeet' — this plane provides:
demo.greet. `run` takes a capability, not a skill name; a skill declares its own
with `SkillDescriptor::new(..).provides(..)`
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

Or without a Rust toolchain at all:

```sh
docker run --rm --read-only --network none \
  -v "$PWD/examples:/work:ro" ghcr.io/hupe1980/agentplane \
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
# `serve` refuses the shipped placeholders and any token under 32 bytes.
sed -e "s/replace-me:peer-a:openssl-rand-hex-32/$(openssl rand -hex 32)/" \
    -e "s/replace-me:ops-alice:openssl-rand-hex-32/$(openssl rand -hex 32)/" \
    -e "s/replace-me:app-1:openssl-rand-hex-32/$(openssl rand -hex 32)/" \
    examples/serve-tokens.yaml > tokens.yaml

agentplane serve examples/served.yaml \
  --url http://localhost:8080/a2a \
  --policy examples/serve-policy.cedar \
  --tokens tokens.yaml \
  --store ./served.redb
```

`--store` takes a redb file or a `postgres://` connection string, and `--tenant`
says whose plane — one flag apart, because on the shared store several instances
coexist and so do an operator's verbs and a serving process. A `postgres://`
store needs `--features cli,postgres`, or the `:full` image
([which verb needs which feature](https://hupe1980.github.io/agentplane/docs/operations/#cli-features)).

Every verb exits by one table — `0` ok, `1` a finding or a negative answer, `2`
a command it refuses, `3` a run waiting, `4` a store or network it could not
use, `5` a partial answer, `6` an export under a `canon` this build does not
implement — printed at the foot of `agentplane --help`
([exit statuses](https://hupe1980.github.io/agentplane/docs/operations/#exit-statuses)).

Add `--mcp-addr 127.0.0.1:8081` and every agent in the file is an MCP tool at
`/mcp` over Streamable HTTP, under the same tokens and policy — the URL and
bearer header an agent framework in any language is configured with. A call is
admitted as that caller, and `execution.kind: call` governs one tool call with
no model of the plane's own.

Add `--operator-addr 127.0.0.1:9090` and the operator surface is served too, on
its **own** listener, off unless asked for, and separated from the peer surface
by *policy* — the example bundle gives `peer` the A2A actions and `operator`
the API ones it uses, not the whole vocabulary — rather than by the port. It is
an HTTP API rather than a console: **anything holding a delegation that carries
the verbs can drive it**, and who is acting comes from the authenticated
identity, never from the request body — the decision type has no actor field to
spoof. It serves the worklist and task decisions, plus the backlogs an on-call
person asks for by question rather than by id: what is quarantined, what is
escalated, which obligations were missed, which messages reached nobody, which
webhook receivers stopped accepting, **what is executing right now** and **what
is stopped**
([the full table](https://hupe1980.github.io/agentplane/docs/operations/#what-the-endpoints-are-for)).

`GET /runs/live` carries the agent, the revision and the delegation subject
beside each id, because an incident is rarely *cancel this run* but a bad deploy
or a credential somebody has just withdrawn.

Every backlog that is *work* has a verb that empties it, including
[the hard one](https://hupe1980.github.io/agentplane/docs/operations/#answering-a-quarantine)
— a run stopped on an effect nobody can account for. The one listing with no verb
is dead letters, because it is a *diagnosis* rather than a queue: the fix is a
correlation key in somebody's emitter, so it is ordered newest-first. A served
plane also sweeps deadlines, task expiry, dead letters, due timers **and
abandoned runs** — a lease that expired while still naming an owner is an
instance that died holding the run — so a run that sleeps, waits or loses its
instance actually finishes.

And it **drains** on `SIGTERM`: stop accepting, answer what is in hand, close
admission, and give the runs still executing `--drain-secs` to reach a journaled
resting point. A process killed mid-call leaves an effect nothing can decide the
outcome of, and a rolling deploy should not be the ordinary way a plane produces
those ([stopping an
instance](https://hupe1980.github.io/agentplane/docs/operations/#stopping-an-instance)).

Both `--policy` and `--tokens` (a file, or `AGENTPLANE_TOKENS_FILE`) are
required and have no defaults: a permissive engine and no engine are the same
behaviour, and a server that authenticates nobody has no actor to record a
decision against. A token may carry its caller's own `scope` and `not_after`;
every run that caller starts is then admitted under a chain rooted at the
caller — checked against the plan, refused once expired — and the journal
names the caller, never the plane, as who the run acted for. A token with
neither is bounded by the plane's chain but holds none of its authority. Needs
`--features cli,a2a-server,cedar`, or the `:full` image.

New here? → **[docs/getting-started.md](https://hupe1980.github.io/agentplane/docs/getting-started/)**

## 📦 What you get

| | |
|---|---|
| 🧾 | **A journal you can audit** — append-only, hash-chained, per-record signatures naming the workload that wrote them, and a per-plane Merkle log so deleting a whole run is detectable |
| ⏱️ | **Durable execution** — crash mid-run and resume from the last completed effect. Recovery is *initiated*, not merely possible: a sweep finds every run whose owner died holding it and takes it over, and a scheduled stop drains rather than becoming a crash |
| 🗂️ | **Cases, not long-lived workflows** — runs stay minutes, business processes span months, so a deploy never migrates an in-flight workflow. Admission claims an idempotency key in the transaction that writes the first record, so a redelivery is answered with the original run |
| 🛡️ | **Policy before live dispatch** — a total, I/O-free gate; denials are journaled, strict replay never re-judges history, and plan authority is checked before step 1 |
| 🏷️ | **Field-level information flow** — outbound arguments carry hierarchical provenance, so an authority-bearing field can require a trusted or named source while ordinary content stays untrusted. Volume is the axis a label lacks, so the size crossing each sink is journaled and `max_egress_bytes` bounds it |
| 💸 | **Budgets and tenant quotas that bind** — a failed model call is billed for what it burned, because the provider bills for it too; a replayed run reaches the same tally at the same point; and a tenant's period reserves each run's worst case at admission, so suspended and concurrent runs cannot carry it past its ceiling → [budgets](https://hupe1980.github.io/agentplane/docs/plans-cases/#budgets) |
| 🧬 | **Effects that take together, or not at all** — each reversible member records the concrete call that undoes it, built from what that call *actually returned*; an irreversible send is **deferred** to commit, so an aborted group never sends it → [effects](https://hupe1980.github.io/agentplane/docs/effects/) |
| 👤 | **Human oversight on the *call*, not a summary of it** — a task carries the exact tool and arguments about to be dispatched, and a read-only `preview` puts *four thousand records* on the reviewer's screen instead of `older_than: "2024-01-01"`. Characters that render as nothing are shown escaped, a word mixing alphabets is flagged, and a proposal the plane cannot open is withheld rather than approved → [what a reviewer is shown](https://hupe1980.github.io/agentplane/docs/security/#what-a-reviewer-is-shown) |
| 🔑 | **Erasure that reaches the backups** — payload bytes are sealed under a per-case key the crate never holds, so erasing a case destroys the key and last hour's backup with it. The chain commits to the **ciphertext**, so an auditor with no keys still verifies the run — and a legal hold refuses the sweep for a matter you must preserve → [erasure and keys](https://hupe1980.github.io/agentplane/docs/erasure/) |
| 📄 | **An agent that is only a file** — `agentplane run agent.yaml`. No Rust, no `main`, no skill. The digest covers the agent *in its entirety*, and the run is journaled and deterministically replayable — under an edited file too: `replay --strict` names the first effect the edit changes and both digests, from a store or an export, with no provider credential → [replaying an edited declaration](https://hupe1980.github.io/agentplane/docs/operations/#strict-replay) |

A selection, not the inventory. The full surface — the export/audit/restore
toolchain, `policy check` re-deriving an export's policy verdicts offline and
measuring a candidate bundle against them, `subject` saying where one memory
subject's data went, `grants` naming the tool grants no run used, `bind` tying
an outside grader's verdict to the records it judged, a durable manifest registry with an enumerable inventory, typed
release, standing authorities, effect groups that commit with the journal,
batch runs over 10⁵ items with per-item journals and an item-granular resume,
the scoped emergency stop, the audited sweeper, a scheduled recovery drill, a
retention pass that says what it could not reach and the legal holds that stop
one, model drivers and streaming, MCP and A2A on both sides, signed Agent Cards,
a tamper-evident record beside an agent this plane does *not* run, governed
media and memory, multi-tenancy, quotas, witnessing, break-glass, and why there
is no `AllowAll` anywhere — is documented mechanism by mechanism on
the site:
**[what you get, in full](https://hupe1980.github.io/agentplane/docs/)**.

What is deliberately **not** built, and what will move →
**[docs/status.md](https://hupe1980.github.io/agentplane/docs/status/)**

## 📚 Documentation

| | |
|---|---|
| 🚀 | [Getting started](https://hupe1980.github.io/agentplane/docs/getting-started/) — first run, first skill, first replay |
| 🐣 | [Your first agent](https://hupe1980.github.io/agentplane/docs/first-agent/) — a step-by-step tutorial: one agent, from an empty file to a durable, tool-using, pinnable declaration, no Rust required |
| 🧠 | [Concepts](https://hupe1980.github.io/agentplane/docs/concepts/) — the ideas the rest is built from |
| 🏗️ | [Architecture](https://hupe1980.github.io/agentplane/docs/architecture/) — the determinism boundary, the module layout, and where each mechanism lives |
| ⚛️ | [The effect protocol](https://hupe1980.github.io/agentplane/docs/effects/) — at-most-once outward calls, unknown outcomes, sagas, transactional groups, stopping a run |
| 🧾 | [The journal](https://hupe1980.github.io/agentplane/docs/journal/) — the hash chain, the signatures and the Merkle log, and the claims they refuse to make |
| 🗺️ | [Plans, cases and time](https://hupe1980.github.io/agentplane/docs/plans-cases/) — frozen authorization graphs, month-long cases, waits, timers, budgets, worklists |
| 🔌 | [Models, agents and peers](https://hupe1980.github.io/agentplane/docs/interop/) — everything this runtime calls that it does not own |
| 📦 | [Publishing and pinning agents](https://hupe1980.github.io/agentplane/docs/registry/) — the manifest as an artifact, and a registry that will not rewrite a version |
| 🍳 | [Cookbook](https://hupe1980.github.io/agentplane/docs/cookbook/) — task-shaped recipes, including wiring an MCP server beside typed tools |
| 📄 | [Manifest reference](https://hupe1980.github.io/agentplane/docs/manifest/) — every field, what enforces it, and what an absent value means; the [published JSON Schema](https://hupe1980.github.io/agentplane/agent.schema.json) gives editors autocomplete and inline errors via one modeline |
| 🧪 | [Testing agents](https://hupe1980.github.io/agentplane/docs/testing/) — the fake provider, fault injection, and proving a replay actually replayed |
| 🔬 | [How this is proven](https://hupe1980.github.io/agentplane/docs/assurance/) — model-checked specifications, mutation-tested specs, and every guarantee broken on purpose |
| 📐 | [Record format](https://hupe1980.github.io/agentplane/docs/format/) — the normative wire specification: canonical JSON, the chain, the Merkle log, the export file. Enough to verify a history without this crate |
| 🔐 | [Security model](https://hupe1980.github.io/agentplane/docs/security/) — the trust boundary, and what it does not cover |
| 🗝️ | [Erasure and keys](https://hupe1980.github.io/agentplane/docs/erasure/) — erasure that reaches backups, key rotation and revocation, and how tenants are kept apart |
| ⚙️ | [Operations](https://hupe1980.github.io/agentplane/docs/operations/) — deploying, HA, retention, observability; the operator API's [OpenAPI document](https://hupe1980.github.io/agentplane/openapi.json) generates clients |
| ⚖️ | [Regulation](https://hupe1980.github.io/agentplane/docs/regulation/) — EU AI Act obligation by obligation, and what is missing |
| 📋 | [Status](https://hupe1980.github.io/agentplane/docs/status/) — what is pre-alpha, what to pin, what is deliberately absent |
| ⬆️ | [Upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/) — what a hard cut means, and moving a plane to a new build |
| 📜 | [Changelog](CHANGELOG.md) — what changed, when, and what to do about it |
| 🤝 | [Contributing](CONTRIBUTING.md) — the assurance ladder, and how to run it |

## 🧪 Assurance

Each layer answers a question the others structurally cannot.

```sh
just              # list every check
just ci           # lint · every feature alone · tests · examples · docs · packaging
just ci-full      # the above, plus TLA+ specs and the full mutation sweep

python3 tools/mutants.py <name> --verify   # break one guarantee, run its test
```

The unusual ones:

**🔬 Formal specs.** TLA+ specifications are model-checked on every push — the
effect protocol, effect groups, retry safety, sagas, fencing, authorization,
delegation, equivocation (showing two histories of one log, and which reader
can still see it), tenant quota scheduling, the rate window, the sink gate under
replay and resume, the key lifecycle, and message, timer and task delivery. And
because a spec whose invariants cannot be violated proves nothing, each is
re-checked against deliberately broken copies of itself; every mutant must be
caught by the *specific* invariant or liveness property written for it.

**📐 A second reader of the record format.** The
[format specification](https://hupe1980.github.io/agentplane/docs/format/) is
normative prose, and `tools/verify_export.py` is written from it and reads none
of this crate's Rust — enforced by a guard, because a verifier that consulted
`src/` would agree with the implementation by construction. `just verify-golden`
runs it: it **re-derives** all 33 record vectors from their parsed values with
its own canonicalizer and chain digest, verifies the sealed export end to end,
and then damages that export and asserts every damage is reported.

**🧯 A recovery drill, not a backup.** The restore path is exercised against a
real `PostgreSQL` server — restoring one tenant's history into another tenant of
a database somebody else is already using, which is the shape a disaster
actually puts an operator in. It asserts equal roots at equal size, records
hash-for-hash, the matter with its obligation and its artifact, isolation in
both directions, and a first lease past the journal's highest epoch. Then it
asks the restored plane to take **new work**, and checks that the seal extends
the log it restored. The RPO/RTO tables, and the list of what an operator re-establishes by
hand, are on the
[operations page](https://hupe1980.github.io/agentplane/docs/operations/#disaster-recovery).

**🔗 An anchor from a party this plane does not control.** The hash chain, the
signatures and the Merkle log all draw both halves of their comparison from
the store, so an operator who removes a run and recomputes the tree satisfies
every one of them — and `agentplane audit` says so rather than reporting a
clean history. `RuntimeBuilder::witnesses(..)` submits each checkpoint to
witnesses over C2SP `tlog-witness` on the periodic sweep, and `agentplane
audit --witness <prefix> --witness-key <name>=<key>` reads back what they
hold. That second direction is the one that matters: the anchor reaches a
reader who did not get it from the operator, and two witnesses holding one
tree size with two different roots is a split view no single anchor exhibits.

**🧾 Conformance by the protocol's own kit.** `just test-a2a-tck` runs the
official [a2a-tck](https://github.com/a2aproject/a2a-tck) against this crate's
A2A server on a live socket — a reader this crate's own client is not.

**🌐 Tests against a real provider.** `just test-live` runs the OpenAI, Gemini
and `OpenAI`-compatible drivers, plus the embedding wire, against the actual
APIs. They are gated twice — an explicit `AGENTPLANE_LIVE=1` *and* a key —
and are never part of `ci`. A stubbed provider never rejects a malformed
request and never returns a shape the driver mis-reads; a real one does, and
only Gemini can say whether it takes a **thought signature** back.

**🧬 Mutation testing over the code.** Every load-bearing guarantee is broken on
purpose, and the test *named for each one* must fail. A mutation caught by some other test is
reported **weak**, not passing: the guarantee has no test of its own.

It runs on **every push**, sharded across a CI matrix. `MUTANTS_SHARD=k/n` takes a
contiguous slice of a list grouped by the feature set each mutation builds
under, cut on measured seconds rather than count. Each shard needs its own
checkout: the sweep rewrites source in place.

`just anchors` is the cheap half, and it checks text rather than types: a
mutation still *matching* the code it names does not prove its replacement still
compiles. That is what `--verify` is for.

## 🚫 Non-goals

| agentplane does **not** | Use instead |
|---|---|
| Ship a prompt library or IDE | Your prompts; agentplane pins the manifest that governs them by digest |
| Route or proxy model traffic | LiteLLM, Bifrost. **The drivers themselves ship** — what is out of scope is *choosing between them at runtime* |
| Implement a vector database | LanceDB / pgvector behind the `SemanticRetriever` seam; embedding is a journaled effect so the query vector is history rather than a recomputation |
| Ship a built-in tool catalogue | Write a typed `Tool`, or wire an MCP server. The tools other frameworks ship are mostly **provider-hosted** — they run during generation, so the call is never announced, authorized, metered or replayable |
| Replace a deterministic protocol engine | Keep it; agentplane sits *beside* it, never inside it |
| Require Kubernetes | One static binary |
| Train, fine-tune, or serve models | Permanently out of scope |
| Grade output quality | It emits replayable traces; grade them elsewhere, and `agentplane bind` ties the verdict to the records it judged |
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
obligation to mechanism and names what is *not* built.

## 📄 License

MIT OR Apache-2.0, at your option.
