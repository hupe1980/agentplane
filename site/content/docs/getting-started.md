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

```sh
cargo add agentplane
```

**Check what you got.** The MSRV is **1.94.1**, and the patch component is the
part that bites: a workspace declaring `rust-version = "1.94"` does not fail
against it. Cargo silently resolves an *older* agentplane and says so in a line
that is easy to lose in a build log:

```
warning: ignoring agentplane@0.6.0 (which requires rustc 1.94.1)
         to maintain <your crate>'s rust-version of 1.94
```

The first sign is that the API does not match this page. `cargo tree -p
agentplane` says which version you have; declare `1.94.1` in your own manifest.

Deliberately not a version number to copy. The version a reader should depend on
is the latest **published** one, which is a fact this repository does not hold —
`Cargo.toml` carries the version being *developed*, and the two differ for as
long as a release takes. `cargo add` asks the registry, so the answer cannot go
stale between a bump and a publish.

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

Or with no Rust toolchain at all, which is rather the point of a tier whose
premise is *a file and a key are the whole agent*:

```sh
docker run --rm --read-only --network none -v "$PWD:/work:ro" \
  ghcr.io/hupe1980/agentplane \
  run /work/summariser.yaml --input '{"ticket": "printer on fire"}'
```

`--read-only --network none` are not decoration — they are the check that the
claim below is true. The default journal is in memory and the fake driver needs
no network, so the first run needs neither a disk nor the internet; the image's
own smoke test runs exactly this way, which is how it caught that "in memory"
had been an unlinked file under `TMPDIR` all along.

The image is distroless, nonroot, has no shell, and is published multi-arch,
cosign-signed and with SLSA provenance and an SBOM bound to the digest.
`:slim` — the default and `:latest` — carries every model provider; `:full`
adds MCP, the A2A peer server, the operator HTTP surface, Cedar, key rings,
governed media and Postgres. The split is about **surface**, not size: they are
within a megabyte of each other, and the reason to run `:slim` is that it does
not contain an HTTP server or a database client at all.

### Tools, still without Rust

`execution.kind: tool-calling` runs the loop from a file — but a loop needs
tools, and until now reaching a tool server took a Rust program. The manifest
grants `tool://tickets/read`; **which transport reaches `tickets`** is named on
the command line, exactly as a model's base URL is:

```sh
agentplane run examples/tool-calling.yaml \
  --input '{"ticket": "T-1"}' \
  --mcp "tickets=python3 examples/mcp-server.py"
```

That split is deliberate. An agent's declaration — and therefore its digest —
must not change when it moves between a laptop and a cluster, so grants are
reviewed and wiring is deployed. A grant naming a server nobody wired is
**refused at build**, in the same breath as a grant nothing implements:

```text
'tickets/read' is granted but nothing implements it and no transport is wired
for server 'tickets' — the model will be offered a tool that fails when chosen
```

`--mcp` **runs a command**, and that is worth being explicit about: it is not an
escalation over what the caller already had — the operator typed it on the same
line as the manifest path — and nothing in a run's data path can reach it.
A manifest, a model and an A2A peer all cannot choose a server; only argv can.
The command is split on whitespace and no shell is involved: no globbing, no
pipelines, no `$(...)`. Needs `--features cli,mcp-stdio`, or the `:full` image.

**One constraint worth knowing before you reach for the image.** `:full` has
`mcp-stdio` compiled in, and a distroless image has **no interpreter and no
shell** — so the `npx`- and Python-based servers most of the MCP ecosystem
publishes cannot run inside it. Only a statically linked server binary mounted
into the container can. That is the price of a base image with no package
manager, and it is a real trade rather than an oversight: run the CLI on a host
that has the runtime your server needs, or ship your MCP server as a static
binary. The container smoke test asserts the image has no interpreter, so if a
base image ever gains one, that assumption fails loudly instead of drifting.

### Hosting it, still without Rust

A manifest can also be **served** — the A2A 1.0 peer surface that passes the
protocol project's own conformance kit, started from the same file:

```sh
agentplane serve examples/served.yaml \
  --url http://localhost:8080 \
  --policy examples/serve-policy.cedar \
  --tokens examples/serve-tokens.yaml \
  --operator-addr 127.0.0.1:9090 \
  --store ./served.redb

curl http://localhost:8080/.well-known/agent-card.json
curl "http://localhost:9090/runs?outcome=quarantined" -H 'authorization: Bearer …'
```

That second URL is the point of `--operator-addr`. Every conclusion this runtime
reaches is meant to be *queryable by whoever must clear it* rather than merely
emitted — and until a shipped binary could serve it, that guarantee needed a Rust
program to reach. It is **off unless asked for and on its own listener**: the
public address is the one a peer holds, and putting the worklist and task
decisions behind it is one policy mistake away from a peer reading every run.

The separation is enforced by **policy**, not by the port. In
`serve-policy.cedar` the `peer` role reaches `a2a:*` and the `operator` role
reaches `api:*`, so a peer token that reaches the operator socket is still
refused — the separate port is defence in depth rather than the control itself.

`--push-host <host>` (repeatable) turns on **A2A push notifications** to that
exact host. Without one, push is not wired and the Agent Card advertises it as
*absent* rather than claiming a capability nothing serves. That flag is the
whole of the configuration: `PushSender` owns HTTPS-only, the all-answer
public-IP check, DNS pinning, manual redirects, the timeout and secret
redaction; what an operator decides is *where*, which is the one thing the crate
cannot. The grant is checked at **registration** as well as at delivery, so a
peer learns straight away:

```text
this deployment does not permit webhooks to 'evil.example.net'
a webhook URL must be https — the payload describes a task, and sending it in
clear to an address the recipient chose is a disclosure
```

Note the ordering: a peer also needs `a2a:task.push` in the policy set, and that
gate runs **first**. A policy that omits it declines with the uniform *this
request was not permitted*, saying nothing about the URL — which is correct, and
worth knowing when a webhook registration is refused for a reason that looks
nothing like a webhook problem.

A served plane also **sweeps**: deadlines warn and breach, tasks expire, dead
letters are retired, and due timers fire, every `--sweep-every` seconds (30 by
default, `0` to drive it from your own scheduler). Without it an agent that calls
`cx.sleep`, waits on an event, or opens a human task would be accepted and then
never make progress — a suspended run is a row, and something has to come back
for it.

Four things are refused rather than defaulted, and each refusal is the design:

- **`--policy`** — a Cedar policy set. A permissive engine and no engine are the
  same behaviour, and only one of them looks governed.
- **`--tokens`** — bearer tokens naming callers. A server that authenticates
  nobody has no actor to record a decision against; an unknown credential is
  refused rather than becoming an anonymous caller.
- **`--store`** — a served task's id is a promise it can be fetched again, and
  an in-memory journal breaks that promise at the next restart. `run` may
  journal to memory because it exits with its answer.
- **A room** — `serve` hosts one agent, because A2A's card path is well-known
  and singular, so a bundle would advertise one document and quietly not serve
  the rest.

`served.yaml` differs from `summariser.yaml` by one line, and it is the
interesting one: `security.max_sensitivity_egress: internal`. A message from a
peer arrives labelled `Internal` — it came from outside — while `--input` on
your own command line arrives `Public`. Without that line the peer's text cannot
reach the model, and the run fails with *sensitivity Internal exceeds sink
'model.complete' ceiling Public*. An agent that may talk to strangers says so in
the reviewed file rather than acquiring the permission by being put behind a
socket.

Needs `--features cli,a2a-server,cedar`; a build without them says so and names
the flag. The `:full` image is built with them.

This exact file uses the deterministic fake driver, so the first run needs
**no API key and no network**. To go live, change the provider and model in the
file (that intentionally changes its digest), install the `providers` feature,
and export the matching key.

A file may hold **several** manifests separated by `---`, exactly as
Kubernetes packages resources — so a multi-agent room (an orchestrator
granted its specialists as `tool://agent/...` tools) deploys and runs as one
file with no Rust anywhere. Each document keeps its own digest: the file is
packaging, not identity. `agentplane run room.yaml` starts at the room's one
declared orchestrator; say `--capability` when the file leaves any doubt.

Every verb takes only its own flags — `agentplane run --push-host …` does not
parse, because the flag lives on `serve`'s struct. Deployment wiring also reads
`AGENTPLANE_STORE`, `AGENTPLANE_URL`, `AGENTPLANE_POLICY`, `AGENTPLANE_TOKENS`,
`AGENTPLANE_ADDR` and `AGENTPLANE_OPERATOR_ADDR`, with the flag winning when
both are given — one rule, rather than a config file and a precedence table.
`agentplane <verb> --help` is generated from the same structs that enforce the
flags, so it cannot describe an option nobody implemented.

The answer goes to stdout and everything else to stderr, so it pipes. A run that
is refused, exhausted or failed exits non-zero, because whoever scripts this
needs the shell's own answer to "did it work".

Keys come from the environment (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
`GEMINI_API_KEY` — or `GOOGLE_API_KEY`), never from the file; Bedrock uses `AWS_REGION` and AWS's standard credential chain,
and a local or Hugging Face model is `provider: chat-completions` with
`CHAT_COMPLETIONS_BASE_URL` pointing at any OpenAI-compatible server — Ollama,
TGI, vLLM, llama.cpp, or `https://router.huggingface.co/v1` with
`CHAT_COMPLETIONS_API_KEY=$HF_TOKEN`.
An agent's declaration must not change when its credential does. And only
the providers the manifest *names* are registered — otherwise exporting the wrong
variable would make the agent runnable on a model its declaration never named.

An embedded [redb](https://github.com/cberner/redb) store is the default backend
— pure Rust, two crates deep, with a stable on-disk format and no C toolchain in
your build. Everything else is opt-in:

```sh
cargo add agentplane
cargo add serde_json
# A `Skill` is an async trait, and the runtime is async. Both are yours to
# choose, so neither is re-exported — but the snippets below will not compile
# without them.
cargo add async-trait
cargo add tokio --features macros,rt-multi-thread
```

Everything beyond a single-node runtime is opt-in:

```sh
cargo add agentplane --features postgres,http,mcp,providers,bedrock,media,cedar,signing
```

| feature | gives you |
|---|---|
| `redb` *(default)* | journal + case store, single node, embedded |
| `postgres` | the same contract, for several plane instances sharing a store |
| `http` | the operator surface: worklist, decisions, run status |
| `mcp` | MCP host: governed prompts, resources, tools, and asynchronous Tasks |
| `mcp-stdio` | reach an MCP server by **running** it — the stdio child process most published servers are. What lets `agentplane run`/`serve` execute a declarative `tool-calling` agent with no Rust |
| `a2a` | A2A peer transport — calling other agents |
| `a2a-server` | being called: the public Agent Card and the A2A 1.0 JSON-RPC methods |
| `push` | Persistent A2A registration cursors, retrying worker API, and SSRF-guarded webhook delivery; `a2a-server` includes it |
| `providers` | Anthropic, OpenAI, Google Gemini and OpenAI-compatible model drivers |
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
| `testkit` | fault injection, store conformance, and a fake model provider that can stream — so an observer is testable without a key or a network |

## 3. Write a skill 🛠️

A skill is one unit of work. It gets a `StepCtx`, which is how it reaches
anything non-deterministic.

`agentplane::prelude::*` is the one import: the skill you write, the context it
is handed, the labels its data carries, and the plane that runs it. Everything
in it is also reachable by its full path — the prelude adds no API, it just
stops the first program opening with five `use` lines. Names that are common
here but likely to collide in your crate (`Record`, `Digest`, `Label`,
`Capability`) are deliberately left out.

```rust
use agentplane::prelude::*;
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
// Everything below is already in scope from the prelude imported above.
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

Get it wrong and the plane tells you what it *does* have, because it is the only
party that knows:

```text
Error: no skill provides capability 'demo.greeet' — this plane provides:
demo.greet. `run` takes a capability, not a skill name; a skill declares its own
with `SkillDescriptor::new(..).provides(..)`
```

That is `Debug`, not `Display`, and the distinction is why it reads that way:
`fn main() -> Result<_, E>` reports through `Debug`, so on the errors you
actually hold this crate makes the two the same. Otherwise the message above
would have been written, and never shown to anyone — you would have got
`NoProvider("demo.greeet")`.

This exact skill and run is on disk as a runnable file — `cargo run --example
hello_skill` — so the shape above is something you execute, not only read.

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
    "tool://ledger/post_entry",
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

It can stream, too, which is what makes a live view testable:

```rust
provider.streaming().will_say("approved");
// every scripted answer now arrives as text deltas and a usage snapshot
// before the completion returns
```

Chunking keeps the separator on the preceding chunk, so concatenating every delta
reproduces the completion byte for byte — the property an observer appending into
a buffer depends on, and the one an assertion on chunk *count* would miss.

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
| What does another organisation's agent see when it calls this one? | `a2a_peer` |
| How do live tokens coexist with a journal that must replay exactly? | `streaming_run` |

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
