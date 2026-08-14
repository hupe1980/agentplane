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
cargo run --example governed_transfer  # field provenance, protected arguments
cargo run --example saga_checkout      # reverse compensation, replay-safe unwind
cargo run --example effect_group       # calls that take together, or not at all
cargo run --example memory_run         # private/team memory, provenance, recall
cargo run --example bedrock_live --features bedrock
                                        # env-gated Amazon Bedrock Converse call
cargo run --example tool_loop --features redb,testkit,manifest
                                        # a model choosing tools, and four refusals
cargo run --example planned_run --features redb,testkit,manifest
                                        # plan once, execute without the model —
                                        # a prompt injection with no reader
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

Add `--operator-addr 127.0.0.1:9090` and the worklist, task decisions and
`GET /runs?outcome=quarantined` are served too — on their **own** listener, off
unless asked for, and separated from the peer surface by *policy* (`peer` reaches
`a2a:*`, `operator` reaches `api:*`) rather than by the port. A served plane also
sweeps deadlines, task expiry, dead letters, due timers **and abandoned runs**
— a lease that expired while still naming an owner is an instance that died
holding the run, and the sweep takes it over and resumes it — so a run that
sleeps, waits or loses its instance actually finishes.

Both `--policy` and `--tokens` are required and have no defaults. That is the
design rather than an inconvenience: a permissive engine and no engine are the
same behaviour, and a server that authenticates nobody has no actor to record a
decision against. Needs `--features cli,a2a-server,cedar`, or the `:full` image.

New here? → **[docs/getting-started.md](https://hupe1980.github.io/agentplane/docs/getting-started/)**

## 📦 What you get

| | |
|---|---|
| 🧾 | **A journal you can audit** — append-only, hash-chained, per-record signatures naming the workload that wrote them, and a per-plane Merkle log so deleting a whole run is detectable |
| 📤 | **A record you can take away** — `agentplane export` writes framed JSON Lines an auditor reads with no Rust toolchain; `audit --key --prior` checks authorship and deletion against a store it did not write; `verify` re-walks a copy offline, from the file alone; `restore` rebuilds a store — journal **and** case layer, since a matter's status, obligations and blob links are beside the history, not derivable from it — and proves the journal by one comparison — equal Merkle roots at equal size. A truncated export is told from a whole one by its missing trailer, and runs that could not be read are named, not counted |
| ⏱️ | **Durable execution** — crash mid-run and resume from the last completed effect; a suspended run costs a row on disk, not a task. Recovery is *initiated*, not merely possible: the sweep finds every run whose owner died holding it — an expired, unreleased lease — and resumes it, journaling the takeover in its own sealed run |
| 🗂️ | **Cases, not long-lived workflows** — runs stay minutes, business processes span months, so a deploy never has to migrate an in-flight workflow |
| 🚫 | **There is no `AllowAll`** — the default is `DenyAll`, and a permissive engine and no engine are the same behaviour, so having two ways to spell it is how a plane ends up with a policy layer everyone believes is on. The same reason there is no `Egress::allow_all()`. Note the direction: a catch-all `permit` left in a policy set makes every later rule redundant, because Cedar allows on *any* matching permit — a baseline is something to remove deliberately, not to inherit |
| 🛡️ | **Policy before live dispatch** — a total, I/O-free gate; denials are journaled, strict replay never re-judges history, and plan authority is checked before step 1 |
| 🏷️ | **Field-level information flow** — exact outbound arguments are bound to hierarchical provenance; recipient, amount, path, URL and other authority-bearing fields can require trusted or named sources while ordinary content remains untrusted |
| 🔓 | **Typed, authorized release** — improving trust or sensitivity names the exact fields, destination, basis and evidence, asks policy under `data:release`, retains provenance, and leaves a permanent decision record |
| 💸 | **Budgets that bind** — a failed model call is billed for what it burned, because the provider bills for it too |
| 🧾 | **A ceiling that outlives the run** — a budget bounds one run and a quota bounds a billing period; neither can say *this customer approved €500, across however many runs it takes, until they take it back*. A standing authority is that, and it is an authorization rather than a throttle: revoked and exhausted are different answers, because one may be followed by asking for less and against the other that is a loop. Drawing is a journaled effect deduplicated on the dispatch identifier — the effect key deliberately changes per attempt, so keying on it would spend a customer's authorization twice for one purchase. And there is no refund: `Spend` is unsigned, so no amount can un-spend a ceiling |
| 🧬 | **Effects that take together, or not at all** — a group declares the resources it touches and refuses any member outside them. Each reversible member records the concrete call that undoes it, built from what that call *actually returned* rather than reconstructed later from state that has moved — the gap a per-step saga leaves, since `compensate` is handed the output of a step that failed and therefore has none. `commit` is the frontier: invariants are checked there because it is the last instant at which failing them is free, and only then are **deferred** members released. That is what makes an irreversible send safe — an aborted group never sends it, which beats sending and apologising. Doubt reverses nothing |
| 🧱 | **A member that commits *with* the journal** — when the resource shares the journal's database, its write and the record that it happened go in one transaction. No reversal to fail, no in-doubt window to survive, and an abort is a rollback. It is the one place this design can do better than a saga, and it says so rather than letting the word *transactional* imply it everywhere else |
| 👤 | **Human oversight on the *call*, not a summary of it** — `requires_approval: true` on a tool grant opens a task carrying the exact tool and arguments about to be dispatched, and nothing happens until somebody approves. Gating the agent's answer instead is a review that arrives after the money moved. Durable worklists, four-eyes, declared expiry behaviour, and an operator who can *stop* a run and have it unwind |
| 🛑 | **An emergency stop that a restart does not forget** — halt a tenant and every instance refuses new work, because the flag is in the store rather than in one process. It is its own refusal, not a ceiling: a ceiling means *not right now* and invites the retry a halt exists to stop. New work only — runs already in flight are stopped by cancelling them, which unwinds what they did |
| 🕰️ | **The sweeper is audited too** — breaching an obligation and escalating a case happen on a clock, with no run to explain them, so a tick that decides anything writes its decisions into a sealed run of its own. State cannot tell *the sweep breached this at 02:00* from *somebody set it*, and no human was there to remember |
| 🔦 | **A finding you can find** — every conclusion the runtime reaches is queryable by whoever must clear it, including its two worst: `GET /runs?outcome=quarantined` and `GET /cases?status=escalated`. Both are newest-first and say when the page overflowed. A status returned to a caller that already returned, an event on a stream nobody reads, and a counter with no alert are all detection without delivery — the failure production studies of agent runtimes report most. Grant `api:run.list` and `api:case.list`: they are the two read verbs an on-call person needs, and the two an allowlist built from route names alone will miss |
| 🛡️ | **Your guardrail, not ours** — this crate ships no content classifier, for the same reason it ships no policy evaluator: a deployment that needs one already has a better one, administered where its compliance people can see it. `Bedrock::guardrail(..)` passes the deployment's own through and owns everything around it — the guardrail's id and version are **effect identity**, so disabling it between a run and its replay is divergence rather than a silent change; an intervention is a **metered refusal** rather than an answer, because Bedrock returns 200 with whatever survived redaction; streaming assesses *before* releasing; and both request paths carry it, since a control on one path is one a streaming deployment loses |
| 🔌 | **Model drivers included** — `OpenAI` Responses, Anthropic Messages, Google Gemini `generateContent`, a separately gated AWS Bedrock Converse driver, and a `chat-completions` driver for the OpenAI-compatible wire every self-hosted server speaks (TGI, vLLM, Ollama, llama.cpp — and with it the Hugging Face catalogue, local or hosted), so adopting this does not mean keeping your provider plumbing. Streaming, native structured output, reasoning continuation across tool turns and cached-token accounting are in each one; OpenAI provider retention is explicitly off by default and replay-visible when enabled. What makes a driver work is not the transport but the **failure mapping**: every error is reduced to whether the call landed, and guessing that wrong is how a payment happens twice |
| 🔌 | **Real context, tool and peer wires** — a genuine MCP host for exact-granted prompts, resources, tools and async Tasks, several servers beside typed in-process tools, and an A2A 1.0 JSON-RPC client/server with typed remote-task handles and journaled polling. Each maps wire outcomes conservatively into recovery; elicitation is not advertised because no server may open an ungoverned human loop inside an effect |
| 🪪 | **Agent Cards derived, not written** — an A2A v1.0 card built from the manifest, so what an agent advertises and what it is permitted cannot drift. Its skills are exactly the declared capabilities, and unimplemented transports are advertised as **absent** rather than aspirational |
| 📡 | **A2A 1.0 task lifecycles on both sides** — blocking/non-blocking tasks, direct normative `GetTask`, journal-backed status/artifact streaming, cursor-paginated `ListTasks`, context-based new tasks, exact `taskId` continuation of `INPUT_REQUIRED`, cancellation, durable push and extended cards. Continuation atomically targets the named wait, carries the authenticated peer as provenance, reconstructs every turn in history, and deduplicates transport retries. Outbound `PeerTask`/`PeerTaskCall` preserve handles and journal each poll |
| 📝 | **An instruction is not data that reads like one** — `/system` is a protected field, so the order a model reasons *under* must be trusted while the content it reasons *about* may stay untrusted. Every other control bounds what a model may **do**; this one is the only one that asks who was allowed to give the order, and it is why a prompt is built with `Tainted::object` rather than mapped from one value |
| 🧠 | **Memory that cannot promote itself** — explicit writes and digest-covered declarative formation derive labels from source/model output. Fixed expiry and opt-in sliding access retention use separate journaled effects; legal hold blocks erasure. Semantic ranking is a sensitivity-bounded journaled retriever, never memory truth. `EncryptedMemoryStore` seals per item under a tenant/subject wrapping scope so subject erasure makes backup ciphertext unreadable; its built adapter is deliberately single-node until KMS destruction can share an active-active coordinator |
| 🔖 | **A memory subject is an erasure unit, so it names the party** — `forget_subject` is what an erasure request actually names, so a *literal* `memory_formation.subject` pools every customer under one key: one party's facts recalled into another's run, and erasing one destroys everybody's. A subject may be **bound** — `$correlation/malo`, `$case`, `$input/<pointer>` — and resolved per run from keys correlation settled at admission. An unrecognised `$` value is refused rather than filed as a constant, since a typo would file every party under the typo; a binding that cannot resolve fails the run rather than guessing; and `$input` is refused unless the field is **trusted**, because a subject taken from untrusted input is whoever supplied it choosing whose memories this run writes into. The keys come from the run's own journal record, not from a case that has since accumulated more |
| 🌊 | **Live model output without a second truth** — `ModelCall::streaming_to` emits labelled visible text and usage during live provider consumption. Opaque reasoning never leaks, strict replay emits nothing live, and one terminal `Completion` remains the only journaled outcome |
| 🧩 | **Reasoning that survives tools without provider state** — OpenAI Responses output items, including encrypted reasoning and assistant phase, and Anthropic thinking/signature blocks are carried as opaque journaled continuation state into the next tool turn. The next effect key commits to them; no `previous_response_id` or expiring provider conversation is replay truth |
| 🔔 | **At-least-once A2A push without a second truth** — the task journal is the outbox and each redb/PostgreSQL registration stores its next unacknowledged sequence. An explicitly scheduled worker sends the same status/artifact union as streaming, advances only after HTTP 2xx, persists bounded retry state, and accepts duplicates rather than losing events after a crash. `PushSender` permits only operator-granted HTTPS hosts after all-address checks and DNS pinning; the card advertises push only when the durable store and transport are wired |
| 📤 | **The journal is the outbox for your events too** — the same cursor loop, with the payload left to you: an operator-configured `Outbox` registers each destination at **admission**, so no run exists unwatched, and a `Projection` turns records into whatever your bus consumes. No outbox table to fall out of sync with the history. The three URL controls are lifted for an operator destination and only for one — there is no caller to check, an in-cluster collector on plaintext HTTP is ordinary, and resolving inward is the point — while the cursor discipline, retry ceiling and abandon-and-report are unchanged. A caller cannot register into that namespace |
| 🧭 | **Discovery that grants nothing** — a peer's card is fetched under an egress allowlist, verified against keys you trust, and used to pick an interface by binding *and* version. What it never does is confer authority: a party describing its own privileges is not a source of truth about them, so peer grants stay in the operator's registry and a forged card can waste a request but not widen one |
| ✒️ | **Agent Cards you can verify** — a detached JWS over the card, canonicalized per RFC 8785, so a peer checks *who published it* rather than only which host served it — and keeps checking after the card is copied into a registry. A real JWS over the standard signing input, not over its hash; the algorithm is read from a constant, never from the card being checked |
| 📻 | **Streaming that survives a dropped connection** — `SendStreamingMessage` and non-terminal `SubscribeToTask` are served from the **journal**, not an in-process channel. Status and output-artifact events are ordered from durable history, any instance can serve them, and reconnecting clients first read the current task snapshot |
| 🖼️ | **Governed remote media** — provider-side URLs are refused; the `media` feature fetches through exact host/port grants, all-answer public-IP checks, pinned DNS, manual redirects, byte/time/type/signature bounds, versioned content validators, digest-only journaling and explicit retention. Bytes materialize only inside live model dispatch, never strict replay |
| 🗑️ | **Erasure that keeps the proof** — drop a payload's bytes and the chain still verifies, because it only ever committed to a digest. A later read says *expired, on this date, for this reason* — never *missing* |
| 🔑 | **Erasure that reaches the backups** — deleting clears the live store; the backup taken an hour earlier still has everything, and backups are offsite and often immutable *by design*. So payload bytes are sealed under a per-case data key wrapped by a key the crate never holds: erasing a case **destroys the key**, and every copy becomes unreadable at once — including the ones nobody can reach. Rotation re-wraps without rewriting bulk data; an erased case never comes back. `VaultTransit` speaks Vault's transit engine, so the wrapping key never leaves Vault. **And the journal too**: `SealedJournal::wrap(store, keys, tenant)` seals run input, effect arguments — prompts and tool calls — and effect outputs under the same per-case scope, so one erasure reaches blobs and journal alike. Only the *payload* is sealed, so exactly-once and every index keep working with no key; and the chain commits to the **ciphertext**, so an auditor holding no keys still verifies the history of a run whose data is gone → [erasure and keys](https://hupe1980.github.io/agentplane/docs/erasure/) |
| 📄 | **An agent that is only a file** — `agentplane run agent.yaml`. No Rust, no `main`, no skill. The digest covers the agent *in its entirety* rather than only its boundary, **and** the run is journaled and deterministically replayable. Declarative formats give you the first; durable platforms give you the second; the pairing is what makes the evidence about something you can actually read |
| 🧑‍⚖️ | **Oversight in the file, not in the code** — `oversight.approval: required` makes a declarative agent wait for a person, showing them its actual answer. Declared where nothing would apply it, it is *refused* — a file must not claim a human is in the loop when none is |
| 🔔 | **A task beside the answer, not in front of it** — a `tool-calling` agent granting no mutating tool structurally *cannot act*, and for those the other two modes are both wrong: `tools-only` gates nothing, `required` is a worklist that blocks. `oversight.triage` returns the answer **and** opens a task when it matches a predicate over the declared `output.schema`, for a named audience. It may hold a condition where `approval` may not, and the distinction is load-bearing: a triage rule changes nothing the run does — same answer, same memories — so it is reporting rather than control flow. Every condition is typed against the schema and refused where that schema provably cannot produce the field, because a rule that can never fire reads exactly like one that does |
| 🔭 | **A tool reference names the tool, not the wire** — a grant is `tool://server/name`, and which transport reaches that server is a deployment decision. So one manifest runs against an in-process double in a test and a real MCP server in production, and the reviewed file never claims a supply-chain fact it cannot know. The server component is load-bearing: `ToolRouter` gives each server its own client, so two servers that both offer `read` stay two tools — and a plane can use typed in-process tools **and** MCP at once, which one client handed every id could not represent |
| 🧭 | **An embedding is an observation** — `StepCtx::embed` journals the query vector and the model revision that produced it. An embedding service does not promise the same floats twice, and the vector is inside the retrieval effect's identity, so a skill computing its own would quarantine a healthy run on the next replay for a reason nothing on the record explains |
| 🧰 | **A tool is one type** — arguments are fields, the schema comes from the fields, and `call` takes `self` so the body receives the declared shape or the call was refused. Model-steering prose stays in the digest-covered manifest, where changing it becomes a reviewed version change. No `Value` to index, no field to misspell, no dispatch on a name. And `.toolbox(..)` derives the catalogue from the agent's own declaration and refuses to build where the code and the reviewed manifest have drifted either way |
| 🛠️ | **Tool calling where the model proposes and the operator decides** — `execution.kind: tool-calling` runs the loop from a file. The model is offered exactly the manifest's grants, and the name it picks is matched **byte for byte** — a resolver that corrects a near miss lets a model reach a tool by describing it. A name matching nothing comes back as a failed call, so the model can correct itself and never gets the tool it nearly named. Arguments stay untrusted, so protected fields and the egress ceiling apply. `max_turns` bounds it, and an agent still asking when it runs out fails rather than passing off half-formed reasoning as an answer. Every turn is a journaled effect, so a replay reassembles the conversation without calling a model or a tool |
| 🗺️ | **Plan-then-execute, from a file** — `execution.kind: planned` is the dual-LLM pattern completed and journaled: one privileged call over **trusted** input fixes the control flow before anything hostile is read, then the runtime executes the plan itself, routing step outputs between steps as labelled references (`$step0/email`) that **no model reads**. A protected field like *recipient must be trusted* is satisfiable by a reference to trusted input and refused for a planner literal — provenance the tool-calling loop structurally cannot carry, because an argument a model retypes always wears the completion's label. `parse` steps run hostile text through the **quarantined** model under a bounded schema and a runtime-injected *not-enough-information* escape that fails the step rather than letting a guess stand. And unlike CaMeL's own research interpreter, every step is a journaled effect: strict replay reassembles the whole plan and dispatches nothing |
| 🔒 | **The declaration binds** — an effect naming a model or tool the file never listed is refused *before dispatch* and journaled, under an action distinct from a policy denial. A config field read by convention is two copies of one decision; this is one |
| 📜 | **Grants and prompts declared in a file, not a builder call** — a manifest states an agent's instructions, tools and ceilings where a reviewer sees them as a diff, and refuses a field it does not recognise, because `max_tokns:` in a permissive parser means *no token ceiling at all*. The prompt is inside the digest, so rewording it is a version bump rather than an untracked deploy |
| 🧪 | **Agents you can actually test** — `testkit` ships a deterministic `FakeProvider` (assert the assembled prompt, the exact tool surface offered, and what the next turn was told about a refusal), seeded fault injection including the `CommittedThenLost` case that journal truncation cannot reach, a store conformance battery for your own backend, and `assert_replay_was_not_backstopped` — which proves replay *replayed* rather than being rescued by the store's unique index one layer down |
| 🕸️ | **Multi-agent shape is declared, not emergent** — `single` or `collaborative`, with roles `specialist` or `orchestrator`. A **specialist may not delegate**, even when a duplicate numeric ceiling is omitted; collaboration must state *why*. Routing one trigger to one agent is ordinary deployment dispatch and was removed from the manifest because accepting YAML that the runtime never executes manufactures confidence |
| 🔀 | **A model swap is a version bump** — provider and model id are in the digest. The `privileged` and `quarantined` roles are refused when they name the *same* model: two roles behind one model keeps the label and removes the control it stands for. There is no declarative fallback role either — fallback changes behaviour and must be explicit orchestration, not accepted YAML nothing executes |
| ✍️ | **Signed manifests, bound to their purpose** — a digest says *what* was published; a signature says *who*. Every signature this crate defines — manifest, record attestation, provenance seal — is made over a hash carrying its own domain label, so one can never be replayed as another |
| 📌 | **A registry that will not rewrite history or authorship** — a published version is immutable; an unsigned artifact can adopt its first publisher attestation, but that identity cannot be silently reassigned. A resolve can be pinned to a digest, which is the check that still holds when the registry is the compromised party |
| 👁️ | **Witnessing by somebody who is not you** — a checkpoint is cosigned only if it provably extends the last one seen, so a shrunken log and a second history of the same size are both rejected. `HttpWitness` speaks C2SP `tlog-witness`, so the counterparty can be the existing public network rather than a second process you also own. A **409 is a stale cursor, never a fork**: one is a routine retry, the other an integrity incident, and conflating them is how the alert that matters stops being believed. And the quorum is a declaration, not a hope: `WitnessQuorum::of(n)` is enforced per submission round, a shortfall is a finding rather than a log line, and a fork report **survives a met quorum** — two honest cosigners don't outvote the witness that remembers a different history |
| 🔓 | **Break-glass that writes to the tenant it crossed** — reaching another tenant's data is the one designed exception to isolation, so the crossing is sealed into *that tenant's* journal — actor, roles, mandatory reason — **before** any data is served, and a failure to record is a failure to access. It enters their chain, signature and Merkle log, and lists under `GET /runs?outcome=broke-glass`. An exception without a record is indistinguishable from the breach it is meant to be |
| 🏢 | **Multi-tenancy in the key, not in a filter** — the tenant leads every stored key on both backends, so a query that forgets it returns *nothing* rather than another tenant's rows. Blob paths lead with it too: content addressing otherwise puts two tenants' identical bytes in one object, and erasing it for one destroys the other's data while reporting both requests done. One process serves many tenants, resolving the plane from the caller's credential — never from the request — and refusing a tenant it does not serve rather than falling back to a default |
| 📊 | **Per-tenant metrics without leaking tenants** — the label is opt-in, off by default, and bounded by *configuration* rather than data: it is the plane's own tenant, so no request can grow the cardinality. There is no pseudonymous mode, deliberately: the tenant already appears in store keys, blob paths and a publicly served Agent Card, so hashing it in one place would invite the belief that it is contained |
| 🚦 | **Ceilings that survive scaling out** — a budget bounds one run; a tenant that can start runs can start a thousand. Per-tenant limits on concurrent runs and spend are accounted **in the store**, because an in-process counter fails *open*: it silently doubles the moment a second instance starts, which is exactly when it was needed. Refusals are back-pressure, distinct from a policy denial — one means *not right now*, the other *never* |
| 🛰️ | **One plane, several agents** — a runtime owns the journal, the drivers and the process identity; an agent owns a manifest and its skills. Each agent on a plane is separately declared, bounded and answerable, and two of them claiming one capability is *refused at startup* rather than silently resolved — as a panic naming the mistake when a binary wired itself, or a typed `BuildError` from `try_build` when the manifest arrived from a registry or a tenant, where a bad declaration is an input rather than a bug and a panic would take every other tenant's in-flight run down with it. `StepCtx::commission` hands work to a peer as a **journaled effect**, so a replay reassembles the room without waking it, the label travels with the answer, and the specialist's spend is billed to the run that asked |

What is deliberately **not** built, and what will move →
**[docs/status.md](https://hupe1980.github.io/agentplane/docs/status/)**

## 📚 Documentation

| | |
|---|---|
| 🚀 | [Getting started](https://hupe1980.github.io/agentplane/docs/getting-started/) — first run, first skill, first replay |
| 🧠 | [Concepts](https://hupe1980.github.io/agentplane/docs/concepts/) — the ideas the rest is built from |
| 🏗️ | [Architecture](https://hupe1980.github.io/agentplane/docs/architecture/) — how it actually works, mechanism by mechanism |
| 🍳 | [Cookbook](https://hupe1980.github.io/agentplane/docs/cookbook/) — task-shaped recipes, including wiring an MCP server beside typed tools |
| 📄 | [Manifest reference](https://hupe1980.github.io/agentplane/docs/manifest/) — every field, what enforces it, and what an absent value means |
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
expensive target. Each line carries `[142/379]`, and each shard needs its own
checkout: the sweep rewrites source in place.

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
