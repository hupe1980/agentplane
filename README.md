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
cargo run --example governed_transfer  # field provenance, protected arguments
cargo run --example saga_checkout      # reverse compensation, replay-safe unwind
cargo run --example effect_group       # calls that take together, or not at all
cargo run --example memory_run         # private/team memory, provenance, recall
cargo run --example bedrock_live --features bedrock
                                        # env-gated Amazon Bedrock Converse call
cargo run --example tool_loop --features redb,testkit,manifest
                                        # a model choosing tools, and four refusals

# Calls a model and replays without calling it again — no API key, no network.
cargo run --example model_run --features redb,testkit

# Digest-only multimodal dispatch and zero-I/O replay — also fully offline.
cargo run --example media_run --features redb,testkit,media

# An agent whose prompt, model, result shape and ceilings come from a file.
cargo run --example manifest_run --features redb,testkit,manifest

# Three agents — an orchestrator and two specialists — each with its own manifest.
cargo run --example blog_room --features redb,testkit,manifest
```

Or skip Rust entirely — a file and a key are the whole agent:

```sh
cargo install agentplane --features cli
agentplane run examples/summariser.yaml --input '{"ticket": "printer on fire"}'
```

`durable_pipeline` prints the whole claim in four steps: a live run, a strict
replay that touches nothing, a crash that resumes without repeating work, and a
changed build that is **quarantined instead of quietly rewriting history**.

New here? → **[docs/getting-started.md](https://hupe1980.github.io/agentplane/docs/getting-started/)**

## 📦 What you get

| | |
|---|---|
| 🧾 | **A journal you can audit** — append-only, hash-chained, per-record signatures naming the workload that wrote them, and a per-plane Merkle log so deleting a whole run is detectable |
| ⏱️ | **Durable execution** — crash mid-run and resume from the last completed effect; a suspended run costs a row on disk, not a task |
| 🗂️ | **Cases, not long-lived workflows** — runs stay minutes, business processes span months, so a deploy never has to migrate an in-flight workflow |
| 🛡️ | **Policy before live dispatch** — a total, I/O-free gate; denials are journaled, strict replay never re-judges history, and plan authority is checked before step 1 |
| 🏷️ | **Field-level information flow** — exact outbound arguments are bound to hierarchical provenance; recipient, amount, path, URL and other authority-bearing fields can require trusted or named sources while ordinary content remains untrusted |
| 🔓 | **Typed, authorized release** — improving trust or sensitivity names the exact fields, destination, basis and evidence, asks policy under `data:release`, retains provenance, and leaves a permanent decision record |
| 💸 | **Budgets that bind** — a failed model call is billed for what it burned, because the provider bills for it too |
| 🧬 | **Effects that take together, or not at all** — a group declares the resources it touches and refuses any member outside them. Each reversible member records the concrete call that undoes it, built from what that call *actually returned* rather than reconstructed later from state that has moved — the gap a per-step saga leaves, since `compensate` is handed the output of a step that failed and therefore has none. `commit` is the frontier: invariants are checked there because it is the last instant at which failing them is free, and only then are **deferred** members released. That is what makes an irreversible send safe — an aborted group never sends it, which beats sending and apologising. Doubt reverses nothing |
| 🧱 | **A member that commits *with* the journal** — when the resource shares the journal's database, its write and the record that it happened go in one transaction. No reversal to fail, no in-doubt window to survive, and an abort is a rollback. It is the one place this design can do better than a saga, and it says so rather than letting the word *transactional* imply it everywhere else |
| 👤 | **Human oversight** — durable worklists with four-eyes, declared expiry behaviour, and an operator who can *stop* a run and have it unwind |
| 🕰️ | **The sweeper is audited too** — breaching an obligation and escalating a case happen on a clock, with no run to explain them, so a tick that decides anything writes its decisions into a sealed run of its own. State cannot tell *the sweep breached this at 02:00* from *somebody set it*, and no human was there to remember |
| 🔦 | **A finding you can find** — every conclusion the runtime reaches is queryable by whoever must clear it, including its own worst one: `GET /runs?outcome=quarantined`. A status returned to a caller that already returned, an event on a stream nobody reads, and a counter with no alert are all detection without delivery — the failure production studies of agent runtimes report most |
| 🔌 | **Real wires** — MCP tools, an A2A 1.0 JSON-RPC `SendMessage` client, Anthropic/OpenAI drivers, and a separately gated AWS Bedrock Converse driver, each with a conservative failure mapping that says what is known about whether the call landed |
| 🪪 | **Agent Cards derived, not written** — an A2A v1.0 card built from the manifest, so what an agent advertises and what it is permitted cannot drift. Its skills are exactly the declared capabilities, and unimplemented transports are advertised as **absent** rather than aspirational |
| 📡 | **An honest A2A 1.0 server subset** — blocking/non-blocking tasks, journal-backed streaming, cursor-paginated `ListTasks`, context-based multi-turn as new immutable runs in one case, cancellation, extended cards and deployment-gated push. `taskId` mutation remains refused: continue with `contextId`. Parts are oneof-validated, remote/raw media is refused, every operation is authorized, and peer input is untrusted |
| 📝 | **An instruction is not data that reads like one** — `/system` is a protected field, so the order a model reasons *under* must be trusted while the content it reasons *about* may stay untrusted. Every other control bounds what a model may **do**; this one is the only one that asks who was allowed to give the order, and it is why a prompt is built with `Tainted::object` rather than mapped from one value |
| 🧠 | **Memory that cannot promote itself** — explicit writes and digest-covered declarative formation derive labels from source/model output. Fixed expiry and opt-in sliding access retention use separate journaled effects; legal hold blocks erasure. Semantic ranking is a sensitivity-bounded journaled retriever, never memory truth. `EncryptedMemoryStore` seals per item under a tenant/subject wrapping scope so subject erasure makes backup ciphertext unreadable; its built adapter is deliberately single-node until KMS destruction can share an active-active coordinator |
| 🌊 | **Live model output without a second truth** — `ModelCall::streaming_to` emits labelled visible text and usage during live provider consumption. Opaque reasoning never leaks, strict replay emits nothing live, and one terminal `Completion` remains the only journaled outcome |
| 🧩 | **Reasoning that survives tools without provider state** — OpenAI Responses output items, including encrypted reasoning and assistant phase, and Anthropic thinking/signature blocks are carried as opaque journaled continuation state into the next tool turn. The next effect key commits to them; no `previous_response_id` or expiring provider conversation is replay truth |
| 🔔 | **Webhooks that cannot be aimed inward** — push notifications go only to an operator-granted host, over HTTPS, after every resolved address is checked and the connection pinned to it. The grant is re-checked at delivery, so revoking a host stops registrations made before it. And the payload carries the task's *state*, not its output — otherwise an allowlist is an exfiltration channel |
| 🧭 | **Discovery that grants nothing** — a peer's card is fetched under an egress allowlist, verified against keys you trust, and used to pick an interface by binding *and* version. What it never does is confer authority: a party describing its own privileges is not a source of truth about them, so peer grants stay in the operator's registry and a forged card can waste a request but not widen one |
| ✒️ | **Agent Cards you can verify** — a detached JWS over the card, canonicalized per RFC 8785, so a peer checks *who published it* rather than only which host served it — and keeps checking after the card is copied into a registry. A real JWS over the standard signing input, not over its hash; the algorithm is read from a constant, never from the card being checked |
| 📻 | **Streaming that survives a dropped connection** — `SendStreamingMessage` and `SubscribeToTask` are served from the **journal**, not an in-process channel. So a client that reconnects is told the current state and continues, any instance can serve the stream, and the events cannot disagree with history because they *are* history |
| 🖼️ | **Governed remote media** — provider-side URLs are refused; the `media` feature fetches through exact host/port grants, all-answer public-IP checks, pinned DNS, manual redirects, byte/time/type/signature bounds, versioned content validators, digest-only journaling and explicit retention. Bytes materialize only inside live model dispatch, never strict replay |
| 🗑️ | **Erasure that keeps the proof** — drop a payload's bytes and the chain still verifies, because it only ever committed to a digest. A later read says *expired, on this date, for this reason* — never *missing* |
| 🔑 | **Erasure that reaches the backups** — deleting clears the live store; the backup taken an hour earlier still has everything, and backups are offsite and often immutable *by design*. So payload bytes are sealed under a per-case data key wrapped by a key the crate never holds: erasing a case **destroys the key**, and every copy becomes unreadable at once — including the ones nobody can reach. Rotation re-wraps without rewriting bulk data; an erased case never comes back. `VaultTransit` speaks Vault's transit engine, so the wrapping key never leaves Vault |
| 📄 | **An agent that is only a file** — `agentplane run agent.yaml`. No Rust, no `main`, no skill. The digest covers the agent *in its entirety* rather than only its boundary, **and** the run is journaled and deterministically replayable. Declarative formats give you the first; durable platforms give you the second; the pairing is what makes the evidence about something you can actually read |
| 🧑‍⚖️ | **Oversight in the file, not in the code** — `oversight.approval: required` makes a declarative agent wait for a person, showing them its actual answer. Declared where nothing would apply it, it is *refused* — a file must not claim a human is in the loop when none is |
| 🧰 | **A tool is one type** — arguments are fields, the schema comes from the fields, and `call` takes `self` so the body receives the declared shape or the call was refused. Model-steering prose stays in the digest-covered manifest, where changing it becomes a reviewed version change. No `Value` to index, no field to misspell, no dispatch on a name. And `.toolbox(..)` derives the catalogue from the agent's own declaration and refuses to build where the code and the reviewed manifest have drifted either way |
| 🛠️ | **Tool calling where the model proposes and the operator decides** — `execution.kind: tool-calling` runs the loop from a file. The model is offered exactly the manifest's grants, and the name it picks is matched **byte for byte** — a resolver that corrects a near miss lets a model reach a tool by describing it. A name matching nothing comes back as a failed call, so the model can correct itself and never gets the tool it nearly named. Arguments stay untrusted, so protected fields and the egress ceiling apply. `max_turns` bounds it, and an agent still asking when it runs out fails rather than passing off half-formed reasoning as an answer. Every turn is a journaled effect, so a replay reassembles the conversation without calling a model or a tool |
| 🔒 | **The declaration binds** — an effect naming a model or tool the file never listed is refused *before dispatch* and journaled, under an action distinct from a policy denial. A config field read by convention is two copies of one decision; this is one |
| 📜 | **Grants and prompts declared in a file, not a builder call** — a manifest states an agent's instructions, tools and ceilings where a reviewer sees them as a diff, and refuses a field it does not recognise, because `max_tokns:` in a permissive parser means *no token ceiling at all*. The prompt is inside the digest, so rewording it is a version bump rather than an untracked deploy |
| 🕸️ | **Multi-agent shape is declared, not emergent** — `single` or `collaborative`, with roles `specialist` or `orchestrator`. A **specialist may not delegate**, even when a duplicate numeric ceiling is omitted; collaboration must state *why*. Routing one trigger to one agent is ordinary deployment dispatch and was removed from the manifest because accepting YAML that the runtime never executes manufactures confidence |
| 🔀 | **A model swap is a version bump** — provider and model id are in the digest, and `dual-llm` is refused unless the quarantined role names a *different* model than the privileged one; one model in both roles keeps the label and removes the control. There is no declarative fallback role: fallback changes behavior and must be explicit orchestration, not accepted YAML nothing executes |
| ✍️ | **Signed manifests, bound to their purpose** — a digest says *what* was published; a signature says *who*. Made over a domain-separated hash, so a record attestation can never be replayed as a publisher's blessing of an agent |
| 📌 | **A registry that will not rewrite history or authorship** — a published version is immutable; an unsigned artifact can adopt its first publisher attestation, but that identity cannot be silently reassigned. A resolve can be pinned to a digest, which is the check that still holds when the registry is the compromised party |
| 👁️ | **Witnessing by somebody who is not you** — a checkpoint is cosigned only if it provably extends the last one seen, so a shrunken log and a second history of the same size are both rejected. `HttpWitness` speaks C2SP `tlog-witness`, so the counterparty can be the existing public network rather than a second process you also own. A **409 is a stale cursor, never a fork**: one is a routine retry, the other an integrity incident, and conflating them is how the alert that matters stops being believed |
| 🏢 | **Multi-tenancy in the key, not in a filter** — the tenant leads every stored key on both backends, so a query that forgets it returns *nothing* rather than another tenant's rows. Blob paths lead with it too: content addressing otherwise puts two tenants' identical bytes in one object, and erasing it for one destroys the other's data while reporting both requests done. One process serves many tenants, resolving the plane from the caller's credential — never from the request — and refusing a tenant it does not serve rather than falling back to a default |
| 📊 | **Per-tenant metrics without leaking tenants** — the label is opt-in, off by default, and bounded by *configuration* rather than data: it is the plane's own tenant, so no request can grow the cardinality. There is no pseudonymous mode, deliberately: the tenant already appears in store keys, blob paths and a publicly served Agent Card, so hashing it in one place would invite the belief that it is contained |
| 🚦 | **Ceilings that survive scaling out** — a budget bounds one run; a tenant that can start runs can start a thousand. Per-tenant limits on concurrent runs and spend are accounted **in the store**, because an in-process counter fails *open*: it silently doubles the moment a second instance starts, which is exactly when it was needed. Refusals are back-pressure, distinct from a policy denial — one means *not right now*, the other *never* |
| 🛰️ | **One plane, several agents** — a runtime owns the journal, the drivers and the process identity; an agent owns a manifest and its skills. Each agent on a plane is separately declared, bounded and answerable, and two of them claiming one capability is *refused at startup* rather than silently resolved. `StepCtx::commission` hands work to a peer as a **journaled effect**, so a replay reassembles the room without waking it, the label travels with the answer, and the specialist's spend is billed to the run that asked |

Full inventory, including what is **not** built →
**[docs/status.md](https://hupe1980.github.io/agentplane/docs/status/)**

## 📚 Documentation

| | |
|---|---|
| 🚀 | [Getting started](https://hupe1980.github.io/agentplane/docs/getting-started/) — first run, first skill, first replay |
| 🧠 | [Concepts](https://hupe1980.github.io/agentplane/docs/concepts/) — the ideas the rest is built from |
| 🏗️ | [Architecture](https://hupe1980.github.io/agentplane/docs/architecture/) — how it actually works, mechanism by mechanism |
| 🍳 | [Cookbook](https://hupe1980.github.io/agentplane/docs/cookbook/) — task-shaped recipes |
| 🔐 | [Security model](https://hupe1980.github.io/agentplane/docs/security/) — the trust boundary, and what it does not cover |
| 🗝️ | [Erasure and keys](https://hupe1980.github.io/agentplane/docs/erasure/) — erasure that reaches backups, key rotation and revocation, and how tenants are kept apart |
| ⚙️ | [Operations](https://hupe1980.github.io/agentplane/docs/operations/) — deploying, HA, retention, observability |
| ⚖️ | [Regulation](https://hupe1980.github.io/agentplane/docs/regulation/) — EU AI Act obligation by obligation, and what is missing |
| 📋 | [Status](https://hupe1980.github.io/agentplane/docs/status/) — built vs designed-not-built |
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

**🌐 Tests against a real provider.** `just test-live` runs the OpenAI driver
against the actual API. They are gated twice — an explicit `AGENTPLANE_LIVE=1`
*and* a key — because a credential being available is not a decision to spend
money with it, and they are never part of `ci`. They exist because a stubbed
provider is structurally unable to have the defects a real one finds: it never
rejects a malformed request and never returns a shape the driver mis-reads.
Writing them found two, both of which every offline test had passed.

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

## 🚫 Non-goals

| agentplane does **not** | Use instead |
|---|---|
| Ship a prompt library or IDE | Your prompts; agentplane pins the manifest that governs them by digest |
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
