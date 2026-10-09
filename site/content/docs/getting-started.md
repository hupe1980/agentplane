+++
title = "Getting started"
description = "Fifteen minutes from nothing to a run that survives a crash, replays exactly, and refuses to rewrite its own history."
weight = 1

[extra]
group = "Start here"
+++

Fifteen minutes from nothing to a run that survives a crash, replays exactly, and
refuses to rewrite its own history.

Every snippet here is either lifted from a working example in `examples/` — which
CI runs on every push — or from the crate's own compile-checked rustdoc. If one
does not build, that is a bug worth reporting.

Sections 2 and 3 are two doorways onto the same guarantees; the first needs no
Rust at all. The
[compatibility promise](@/docs/status.md#what-the-freeze-promises) attaches to
the evidence both produce — the record, the export and the operator
vocabulary — not to either doorway; Rust function signatures carry the ordinary
pre-alpha risk.

---

## 1. See it work first 👀 {#see-it-work-first}

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
- **3** — the crash resumed at stage 1. Stage 0 ran once across both attempts,
  not twice.
- **4** — a *different build* replaying an old journal is *quarantined*. It is
  not silently accepted, and it is not a crash to recover from. Changing code and
  crashing are different things, and only one of them is recoverable.

## 2. An agent with no Rust 📄 {#an-agent-with-no-rust}

If the agent is a prompt, a model and a result shape, it needs no program at all
— a file and a key are the whole thing. (Prefer to build this up one command at
a time, with each refusal explained as you hit it? That is
[your first agent](@/docs/first-agent.md), the step-by-step tutorial; this
section is the condensed version.)

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
      additionalProperties: false
      required: [summary]
      properties: { summary: { type: string } }
  budgets: { max_tokens: 10000 }
```

```sh
cargo install agentplane --features cli

agentplane init agent.yaml              # or start from a starter that validates
agentplane validate summariser.yaml
agentplane digest   summariser.yaml     # what a registry pins
agentplane run      summariser.yaml --input '{"ticket": "printer on fire"}'
agentplane schema                       # the format as a JSON Schema
```

For editor autocomplete and inline errors while writing the file, put the
published schema in a modeline — see
[the manifest reference](@/docs/manifest.md#editor-validation):

```yaml
# yaml-language-server: $schema=https://hupe1980.github.io/agentplane/agent.schema.json
```

`--input -` reads stdin, the convention every pipe-shaped tool honours. A
recorded run is re-executed with its own verb — `agentplane replay <run-id>
--store runs.redb --manifest summariser.yaml`, plus `--strict` to verify rather
than resume, under the same manifest or an [edited one](@/docs/operations.md#strict-replay) — and `agentplane card <manifest> --url <base>` prints the Agent
Card a served manifest would advertise, so what a peer will see is reviewable
before anything listens on a socket.

Or with no Rust toolchain at all:

```sh
docker run --rm --read-only --network none -v "$PWD:/work:ro" \
  ghcr.io/hupe1980/agentplane \
  run /work/summariser.yaml --input '{"ticket": "printer on fire"}'
```

`--read-only --network none` check the claim: the default journal is in memory
and the fake driver needs no network, so the first run needs neither a disk nor
the internet. The image's own smoke test runs exactly this way.

The image is distroless, nonroot, has no shell, and is published multi-arch,
cosign-signed and with SLSA provenance and an SBOM bound to the digest.
`:slim` — the default and `:latest` — carries every model provider; `:full`
adds MCP, the A2A peer server, the operator HTTP surface, Cedar, key rings,
governed media and Postgres. The split is about **surface**, not size: `:slim`
contains no HTTP server and no database client.

### Tools, still without Rust

`execution.kind: tool-calling` runs the loop from a file, and a loop needs
tools. The manifest grants `tool://tickets/read`; **which transport reaches `tickets`** is named on
the command line, exactly as a model's base URL is:

```sh
agentplane run examples/tool-calling.yaml \
  --input '{"ticket": "T-1"}' \
  --mcp "tickets=python3 examples/mcp-server.py"
```

An agent's declaration — and therefore its digest — must not change when it
moves between a laptop and a cluster, so grants are reviewed and wiring is
deployed. A grant naming a server nobody wired is **refused at build**:

```text
agentplane: agent 'ticket-desk' declares `execution.kind: tool-calling` and grants
tools on tickets, but nothing reaches them. Name the process that serves each
one: `--mcp tickets=<command>` for an MCP server, or `--peer <name>=<url>` for
an A2A peer
```

`--mcp` **runs a command**. Only argv can choose a server — a manifest, a model
and an A2A peer cannot. The command is split on whitespace and no shell is
involved: no globbing, no pipelines, no `$(...)`. Needs
`--features cli,mcp-stdio`, or the `:full` image.

**`:full` has no interpreter and no shell**, so the `npx`- and Python-based
servers most of the MCP ecosystem publishes cannot run inside it — only a
statically linked server binary mounted into the container can. Run the CLI on
a host that has the runtime your server needs, or ship your MCP server as a
static binary.

### Hosting it, still without Rust

A manifest can also be **served** — the A2A 1.0 peer surface that passes the
protocol project's own conformance kit, an MCP listener a framework calls tools
on, and the operator API — started from the same file.

#### From nothing to a governed call {#zero-to-governed}

**Six commands** take a machine with `git`, `docker` and `uv` to a framework's
tool call that the plane admitted, journaled and answered, with no model key.
Each line is one command, run in order from an empty directory:

```sh
git clone --depth 1 https://github.com/hupe1980/agentplane
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/hupe1980/agentplane:full init --serve plane
docker compose -f plane/compose.yaml up --wait
export AGENTPLANE_TOKEN="$(cat plane/framework.token)"
cd agentplane/examples/frameworks/pydantic-ai
uv run --no-project --python 3.12 --with-requirements requirements.lock quickstart.py
```

The last two run any of the quickstarts below; change the directory.
`init --serve` writes seven files into `plane/`: the starter agent on the `fake`
provider, the shipped policy, a token file with three freshly generated callers
(`peer-1`, `framework-1`, `ops-1`), the framework caller's token alone, a
generated Postgres password, the plane's connection string holding it
(`store.env`), and a compose file that runs the plane against Postgres. The
four secret files are mode 0600. It refuses if any of the seven exists, and
removes what it wrote if it fails partway. Run it as the user the plane should
run as: the container runs as the token file's owner, and `init --serve` refuses
to write a plane that would run as root. The plane serves A2A on
`127.0.0.1:8080`, MCP on `127.0.0.1:8081` and the operator API on
`127.0.0.1:9090`; the token file is mounted as a secret, never passed in the
environment, and no secret is on a command line. To serve other machines,
publish `8080` and `8081` on an address they reach and set `--url` and
`--mcp-allowed-host` to the names they use — the compose file says where.

| Framework | Door | Quickstart |
|---|---|---|
| OpenAI Agents SDK | MCP — `MCPServerStreamableHttp` | `examples/frameworks/openai-agents/` |
| LangGraph | MCP — `langchain-mcp-adapters` | `examples/frameworks/langgraph/` |
| Pydantic AI | MCP — `MCPToolset` | `examples/frameworks/pydantic-ai/` |
| Google ADK | MCP — `McpToolset`; A2A — `RemoteA2aAgent` | `examples/frameworks/google-adk/` |
| Microsoft Agent Framework | MCP — `MCPStreamableHTTPTool`; A2A — `A2AAgent` | `examples/frameworks/microsoft-agent-framework/` |

Each is one file that imports nothing of this project. `requirements.txt` pins
its framework exactly; `requirements.lock` pins the whole dependency closure
with hashes, which `uv pip install --require-hashes -r requirements.lock`
checks — how CI installs every one before walking it against the `:full` image.
With no `QUICKSTART_MODEL` set, each drives the framework's own MCP client
without a model key; set it (with that provider's key) and the framework's
model decides. The A2A half runs when `AGENTPLANE_PEER_TOKEN` holds the
`peer-1` token. The plane governs the tool call, not the framework's loop.

#### By hand

```sh
# The shipped token file holds placeholders `serve` refuses: generate the tokens.
sed -e "s/replace-me:peer-a:openssl-rand-hex-32/$(openssl rand -hex 32)/" \
    -e "s/replace-me:ops-alice:openssl-rand-hex-32/$(openssl rand -hex 32)/" \
    -e "s/replace-me:app-1:openssl-rand-hex-32/$(openssl rand -hex 32)/" \
    examples/serve-tokens.yaml > tokens.yaml

agentplane serve examples/served.yaml \
  --url http://localhost:8080/a2a \
  --policy examples/serve-policy.cedar \
  --tokens tokens.yaml \
  --operator-addr 127.0.0.1:9090 \
  --mcp-addr 127.0.0.1:8081 \
  --store ./served.redb

curl http://localhost:8080/.well-known/agent-card.json
curl "http://localhost:9090/runs?outcome=quarantined" -H 'authorization: Bearer …'
```

`serve` refuses a token shorter than 32 bytes, and it refuses the file's
placeholders by name: a credential copied out of a public repository is one
every reader holds. The bearer for the operator surface is the `ops-alice` line
of `tokens.yaml`.

That second URL is the operator surface: **off unless asked for and on its own
listener**, away from the address a peer holds. The separation is enforced by
**policy**, not by the port: in `serve-policy.cedar` the `peer` role reaches the
A2A actions and the `operator` role the API ones, so a peer token that reaches
the operator socket is still refused.

`--mcp-addr` serves every agent in the file as MCP tools over Streamable HTTP,
at `http://127.0.0.1:8081/mcp` — the URL and bearer header an agent framework
in any language is configured with. Same token file, same policy, asked as
`mcp:*` actions: the `app-1` line's `framework` role reaches them. A call is
admitted as that caller, and its arguments arrive as untrusted data from
`peer:app-1`. It needs the `mcp-server-http` feature, which the `:full` image
has; [MCP, being served](@/docs/interop.md#mcp-being-served) has the rest.

**What the shipped policy grants.** `peer` reaches the A2A actions a peer needs,
`framework` the `mcp:*` caller actions, and `operator` the read and task verbs
plus the on-call verbs — `api:halt.place`, `api:halt.lift`, `api:run.cancel`,
`api:run.abandon`, `api:effect.reconcile`, `api:hold.place`, `api:hold.release`
— so an incident is not the first time a verb is denied. It does not permit
`data:release`, so a run that reaches a typed release is refused: which labels
may leave is a deployment's decision, and the file carries the rule to
uncomment beside the [release gate](@/docs/security.md#information-flow-labels)
it controls. Cedar denies what no rule permits, and the caller is told only that
it was declined.

`--push-host <host>` (repeatable) turns on **A2A push notifications** to that
exact host. Without one, push is not wired and the Agent Card advertises it as
*absent*. That flag is the whole of the configuration: `PushSender` owns
HTTPS-only, the all-answer public-IP check, DNS pinning, manual redirects, the
timeout and secret redaction. The grant is checked at **registration** as well
as at delivery, so a peer learns straight away:

```text
this deployment does not permit webhooks to 'evil.example.net'
a webhook URL must be https — the payload describes a task, and sending it in
clear to an address the recipient chose is a disclosure
```

A peer also needs `a2a:task.push` in the policy set, and that gate runs
**first**: a policy that omits it declines with the uniform *this request was
not permitted*, saying nothing about the URL.

A served plane also **sweeps**: deadlines warn and breach, tasks expire, dead
letters are retired, and due timers fire, every `--sweep-every` seconds (30 by
default, `0` to drive it from your own scheduler). Without it a run that sleeps,
waits on an event, or opens a human task never makes progress.

And it **drains**. `SIGTERM` or `SIGINT` stops it accepting, answers what it has
in hand, and gives the runs already executing `--drain-secs` (25 by default) to
finish. Without that a deploy cuts runs mid-tool-call, which the journal can only
report as *this call may or may not have happened* — see [stopping an
instance](@/docs/operations.md#stopping-an-instance).

Refused rather than defaulted:

- **`--policy`** — a Cedar policy file, or a bundle directory. A permissive engine and no engine are the
  same behaviour, and only one of them looks governed.
- **`--tokens`** — a file of bearer tokens naming callers
  (`AGENTPLANE_TOKENS_FILE`). An unknown credential is refused rather than
  becoming an anonymous caller. An entry may carry a
  `scope` (and a `not_after`), which becomes that caller's own delegation
  chain: every run it starts is admitted under it and recorded as acting for
  the caller, not for the plane.
- **`--store`** — a served task's id is a promise it can be fetched again, and
  an in-memory journal breaks that promise at the next restart. `run` may
  journal to memory because it exits with its answer.
- **A room** — A2A serves the file's one `topology.role: orchestrator`, and
  refuses a room without exactly one, because A2A's card path is well-known and
  singular. `--mcp-addr` serves every agent in it, or those `--mcp-agent`
  names.

`served.yaml` differs from `summariser.yaml` in two places. `spec.input` is the
shape a caller is offered, which serving over MCP requires. The interesting one
is `security.max_sensitivity_egress: internal`. A message from a
peer arrives labelled `Internal` — it came from outside — while `--input` on
your own command line arrives `Public`. Without that line the peer's text cannot
reach the model, and the run fails with *sensitivity Internal exceeds sink
'model.complete' ceiling Public*. An agent that may talk to strangers says so in
the reviewed file.

Needs `--features cli,a2a-server,cedar`; a build without them says so and names
the flag. The `:full` image is built with them.

This exact file uses the deterministic fake driver, so the first run needs
**no API key and no network**. To go live, change the provider and model in the
file (that intentionally changes its digest) and export the matching key: the
`cli` feature already carries every model provider, Bedrock included.

A file may hold **several** manifests separated by `---`, exactly as
Kubernetes packages resources — so a multi-agent room (an orchestrator
granted its specialists as `tool://agent/...` tools) deploys and runs as one
file with no Rust anywhere. Each document keeps its own digest: the file is
packaging, not identity. `agentplane run room.yaml` starts at the room's one
declared orchestrator; say `--capability` when the file leaves any doubt.

Every verb takes only its own flags — `agentplane run --push-host …` does not
parse, because the flag lives on `serve`'s struct. Deployment wiring also reads
`AGENTPLANE_STORE`, `AGENTPLANE_TENANT`, `AGENTPLANE_URL`, `AGENTPLANE_POLICY`,
`AGENTPLANE_TOKENS_FILE`, `AGENTPLANE_ADDR`, `AGENTPLANE_OPERATOR_ADDR`,
`AGENTPLANE_MCP_ADDR`, `AGENTPLANE_SWEEP_EVERY`, `AGENTPLANE_DRILL_EVERY`, `AGENTPLANE_DRAIN_SECS` and
`AGENTPLANE_LOG_FORMAT`, with the flag winning when both are given.
`agentplane <verb> --help` is generated from the same structs that enforce the
flags.

The answer goes to stdout and everything else to stderr, so it pipes. A run that
did not succeed — refused by policy, exhausted or failed — exits `1`. A run that
stopped to **wait** — for a person, a timer or an event — exits `3`, and prints
what it waits for and the commands that move it on, naming the store and the
tenant it ran on (a `postgres://` password is left out; a store taken from
`AGENTPLANE_STORE` is printed as that variable). A command this binary refuses —
a bad flag, an unknown capability or tenant, a manifest the plane will not
assemble from — exits `2`, a store it cannot reach `4`, and an answer `--limit`
cut short `5` —
the whole table is at the foot of `agentplane --help` and in
[operations](@/docs/operations.md#exit-statuses).

Every `run` opens or joins a **case**, because oversight, obligations and
`$correlation/<namespace>` memory subjects all live on one. With no
`--correlate` the run gets a case of its own; `--correlate customer=C-7`
(repeatable) joins the open case that key belongs to. So a manifest with
`spec.oversight` runs from a terminal end to end —
`examples/approval.yaml` is one:

```sh
agentplane run examples/approval.yaml --input '{"ticket": "T-1"}' --store runs.redb
# run run_01… is waiting for a person to decide task_…   (exit 3)
agentplane tasks  --store runs.redb                      # the worklist
agentplane decide task_… approve --reason "checked" --actor ada --store runs.redb
agentplane replay run_01… --manifest examples/approval.yaml --store runs.redb
agentplane history run_01… --store runs.redb             # its journal, record by record
```

A run that calls an A2A peer (`--peer`) also needs `--acting-as <subject>`: a
peer call is made on somebody's behalf, and the flag names whose. `--peer`
needs the `a2a` feature, and `--mcp` needs `mcp-stdio` →
[which verb needs which feature](@/docs/operations.md#cli-features).

Keys come from the environment (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
`GEMINI_API_KEY` — or `GOOGLE_API_KEY`), never from the file; Bedrock uses `AWS_REGION` and AWS's standard credential chain
(SSO, roles and `aws login` sessions included) or a Bedrock API key in `AWS_BEARER_TOKEN_BEDROCK`,
and a local or Hugging Face model is `provider: chat-completions` with
`CHAT_COMPLETIONS_BASE_URL` pointing at any OpenAI-compatible server — Ollama,
TGI, vLLM, llama.cpp, or `https://router.huggingface.co/v1` with
`CHAT_COMPLETIONS_API_KEY=$HF_TOKEN`.
Only the providers the manifest *names* are registered, so exporting the wrong
variable cannot make the agent runnable on a model its declaration never named.

### Trying it on a page {#trying-it-on-a-page}

`redb` admits one writer process, so while something holds the store the
verbs above are locked out of it. `agentplane dev` holds it and carries them:
it builds the plane exactly as `run` does and serves one page for it.

```sh
agentplane dev examples/approval.yaml
# http://127.0.0.1:53817/#t=…
```

<figure class="screenshot">
<picture>
<source srcset="../../dev-page-timeline-dark.png" media="(prefers-color-scheme: dark)">
<img src="../../dev-page-timeline-light.png" alt="The dev page, showing the run list, one run with its status, spend and actions, and its journal as a timeline with call durations" width="1280" height="860" loading="lazy">
</picture>
<figcaption>A run of <code>examples/room.yaml</code> as a timeline, each call with its duration and the consultation linked to the sub-run that answered it.</figcaption>
</figure>

Open the printed URL. The page lists every run in the store with its status,
and for the one you pick:

- shows what its model is writing, as it writes it;
- shows its journal as a timeline, filterable and expandable record by record,
  or as the conversation its model calls held — hidden characters shown as
  `\u{…}`, each call with its duration, each consultation linked to the
  sub-run that answered it;
- starts, cancels and re-runs runs (the input pre-filled from the agent's
  declared schema), and delivers the event a run waits for;
- decides tasks — a consultation's approval showing what the consulted agent
  may do, a call's approval taking amended arguments;
- strict-replays a run, or every run, against the file as it is now, and
  exports the store beside the export's verification.

<figure class="screenshot">
<picture>
<source srcset="../../dev-page-conversation-dark.png" media="(prefers-color-scheme: dark)">
<img src="../../dev-page-conversation-light.png" alt="The dev page conversation view, showing the system prompt, the input, and the model calling the consulted agent" width="1280" height="860" loading="lazy">
</picture>
<figcaption>The same run as the conversation its model calls held.</figcaption>
</figure>

Saving the manifest rebuilds the plane; a file that does not parse leaves the
running one in place and says why.

It is for the agent's author on their own machine — not a deployment surface,
not a reviewer page and not an editor. It listens on loopback only, behind a
token minted per process; keeps its journal in memory, or in a `--scratch
<dir>` it created and marked, following no symbolic link; and refuses any
other store, a tenant other than
`dev`, and `--mcp` or `--peer` without `--allow-live`, since an approval on the
page then performs a real effect. It needs the `dev` feature, which no
published image carries →
[what the page refuses](@/docs/security.md#what-a-reviewer-is-shown).

## 3. Add the crate 📦 {#add-the-crate}

Everything above runs without a Rust toolchain. Past this point you are writing
a **skill**, which is trusted code in this process — the reason there is no
skill tier in any other language, and the line untrusted code does not cross:
it goes behind the effect boundary as a tool instead.

An embedded [redb](https://github.com/cberner/redb) store is the default backend
— pure Rust, two crates deep, with a stable on-disk format and no C toolchain in
your build. Everything else is opt-in:

```sh
cargo add agentplane
cargo add serde_json
# The runtime is async, and which executor runs it is yours to choose — so
# tokio is not re-exported. `async_trait` is: writing a skill starts at the
# prelude, not in Cargo.toml.
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
| `mcp-http` | reach an MCP server over **streamable HTTP** — the transport remote servers speak |
| `mcp-server` | the other direction: serve **this plane's agents as MCP tools** and their reviewed instructions as MCP prompts, so a host you do not run can call a governed agent |
| `mcp-server-http` | the same catalogue over **Streamable HTTP**, behind the plane's tokens, policy and `Host`/`Origin` checks — what `serve --mcp-addr` offers an agent framework |
| `a2a` | A2A peer transport — calling other agents |
| `acp` | record what an agent you do **not** run reported doing: the Agent Client Protocol's session updates mapped onto observation records. Types only — the session stays with the editor that holds it |
| `a2a-server` | being called: the public Agent Card and the A2A 1.0 JSON-RPC methods |
| `push` | Persistent A2A registration cursors, retrying worker API, and SSRF-guarded webhook delivery; `a2a-server` includes it |
| `providers` | Anthropic, OpenAI, Google Gemini and OpenAI-compatible model drivers, plus the `OpenAI`-compatible and Gemini **embeddings** drivers semantic retrieval needs |
| `bedrock` | Amazon Bedrock Runtime Converse through the AWS SDK, plus Titan/Cohere **embeddings**; separate because the dependency graph is substantial |
| `media` | governed remote-media fetch: exact grants, SSRF-safe pinned DNS, redirects, limits, validation, digest and retention |
| `cedar` | Cedar as the authorization engine |
| `signing` | Ed25519 record signing |
| `manifest` | declare an agent's grants and ceilings in a reviewable YAML file, and pin it by digest |
| `cli` | the `agentplane` binary — run a declarative agent from a YAML file with no Rust at all |
| `dev` | `agentplane dev`: a page on your own machine for trying an agent — loopback only, behind a per-process token, over a scratch store. In no published image |
| `witness-http` | submit checkpoints to a real witness over C2SP `tlog-witness`, and read back what it holds — the half that gives the split-view guarantee a counterparty. Included in `cli`, because the deletion check needs a checkpoint from outside the store |
| `opendal` | content-addressed blob storage on S3, GCS, Azure or a filesystem — where bytes too large for the journal go |
| `keyring` | envelope encryption for payload bytes, and the cryptographic erasure it makes provable — destroying a key erases every copy, including backups |
| `keyring-vault` | a key ring that is somebody else: HashiCorp Vault's transit engine over its HTTP API, so the wrapping key never leaves Vault |
| `fake-model` | a model provider with no model behind it: deterministic answers, real usage figures. What makes `provider: fake` run without a key or a network; `cli` includes it |
| `testkit` | fault injection, store conformance, a stub signer that proves nothing, and the plaintext-loopback exceptions. **Never in a shipped build** — no feature a release enables pulls it in, and a guard holds that |

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
Depend on the latest **published** version, which `cargo add` asks the registry
for.

## 4. Write a skill 🛠️ {#write-a-skill}

A skill is one unit of work. It gets a `StepCtx`, which is how it reaches
anything non-deterministic.

`agentplane::prelude::*` is the one import: the skill you write, the context it
is handed, the labels its data carries, and the plane that runs it. Everything
in it is also reachable by its full path. Names likely to collide in your crate
(`Record`, `Digest`, `Label`, `Capability`) are left out.

```rust
use agentplane::prelude::*;
use serde_json::{Value, json};

#[derive(Debug)]
struct Greet;

#[async_trait]
impl Skill for Greet {
    // No `.provides(..)`: a skill that declares nothing answers its own name.
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("greet")
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

## 5. Run it ▶️ {#run-it}

```rust
// Everything below is already in scope from the prelude imported above.
use std::sync::Arc;

let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);

let runtime = Runtime::builder(Arc::clone(&store))
    .owner("my-service")
    .skill(Greet)
    .build();

let outcome = runtime.run("greet", Tainted::trusted(json!({ "name": "world" }))).await?;
println!("{:?} → {:?}", outcome.status, outcome.output);

// Re-executes the logic, reads every effect back. Nothing is performed again.
let replayed = runtime.replay(outcome.run_id, Mode::Strict).await?;
assert_eq!(outcome.output, replayed.output);
```

`build()` **panics** on a wiring fault. A long-running service, or a plane
assembled from a manifest that arrived at run time, uses `try_build()`, which
returns the same checks as a `BuildError`.

Note `run("greet", …)` takes a **capability**. Here the capability *is* the
skill's name, because a skill that declares nothing answers its own name.
`.provides(..)` declares an abstract capability another step names, and
**replaces** the name default rather than adding to it.

Get it wrong and the plane tells you what it *does* have. Here, from a plane
whose skill declared `.provides("demo.greet")`:

```text
Error: no skill provides capability 'demo.greeet' — this plane provides:
demo.greet. `run` takes a capability, not a skill name; a skill declares its own
with `SkillDescriptor::new(..).provides(..)`
```

`fn main() -> Result<_, E>` reports through `Debug`, and this crate's errors
make `Debug` and `Display` the same, so that is what `main` prints.

This exact skill and run is on disk as a runnable file — `cargo run --example
hello_skill` — so the shape above is something you execute, not only read.

## 6. Do something to the outside world 🌍 {#do-something-to-the-outside-world}

The point of the journal is effects. A tool is one type — its arguments are the
tool, so the schema the model is offered comes from the struct and the body
receives the struct:

```rust
use agentplane::prelude::*;
use agentplane::tools::ToolFailure;
use serde_json::{Value, json};

/// Post one entry to the ledger.
#[derive(Debug, serde::Deserialize, agentplane::schemars::JsonSchema)]
#[schemars(crate = "agentplane::schemars")]
struct PostEntry {
    account: String,
    memo: String,
}

#[async_trait]
impl Tool for PostEntry {
    const SERVER: &'static str = "ledger";
    const NAME: &'static str = "post_entry";

    async fn call(self) -> Result<Value, ToolFailure> {
        Ok(json!({ "posted": self.account, "memo": self.memo }))
    }
}
```

What the tool may be handed is the **manifest's** to say, because that is the
document a reviewer signs. The grant names the tool and protects the field that
carries authority:

```yaml
  tools:
    - ref: "tool://ledger/post_entry"
      mutates: true
      description: "Post one ledger entry."
      protected_fields:
        - path: /account
          require_trusted: true
```

Wire the tool with `Runtime::builder(store).toolbox(ToolBox::new().with::<PostEntry>())`
beside `.agent(Agent::new(&manifest).skill(YourSkill))`. `toolbox` derives the
catalogue from the manifests and **refuses to build** when the code and the
reviewed grant disagree — a tool that says it mutates granted as read-only, a
grant nothing implements. Then, inside the skill:

```rust
use agentplane::tools::ToolId;

let args = Tainted::object([
  ("account", Tainted::trusted(json!("receivables"))),
  ("memo", model_written_memo), // may remain untrusted
]);
let result = cx
  .call_tool(ToolId::new("ledger", "post_entry"), args)
  .await?; // exact bytes, protected account
```

`call_tool` is the governed path whole: the manifest gate refuses a tool this
agent's declaration does not grant, the protected account must be trusted while
an ordinary memo can keep its model provenance, the egress ceiling applies, and
the call is journaled — so a replay reads the result back instead of posting
twice. `mutates` defaults to **true**, the cautious treatment. A mutating call whose outcome is
unknown escalates to an operator rather than being retried. The result comes
back `Tainted` and untrusted, whatever the tool says about itself.

If a person or trusted process authorizes a label change, use a typed release:

```rust
let args = cx.release(
  args,
  Release::fields(
    ReleaseScope::trust(),
    ["/account"],
    "operator matched the account to settlement SET-42",
    "tool://ledger/post_entry",
    ["approval:SET-42"],
  ),
).await?;
```

This asks policy under `data:release` — a plane with no policy engine refuses
every release, since nothing permitted it — retains provenance, and journals the
releaser, scope, destination, basis and evidence. It never returns a bare value.

## 7. Wait for a human ⏸️ {#wait-for-a-human}

```rust
use agentplane::core::{Expiry, TaskSpec};

let decision = cx.task(
    &TaskSpec::new("rejection-handling", justification, "decision")
        .role("ops")
        .excluding("agent:proposer")   // four eyes; the run's own requester is barred already
        // Escalation carries who it widens to: the roles are part of the answer.
        .on_expiry(Expiry::escalate_to(["ops-lead"])),
).await?;
```

The run **suspends**. Its frame goes to disk and the task is dropped — a
suspended run costs bytes, not a thread, so a plane can hold 10⁵ of them waiting
for approval. When someone decides, the run resumes exactly where it was.

`Expiry` is `Deny` unless you say otherwise. Acting without a person is spelled
`Expiry::ProceedUnattended` — the only way to write it, so the choice is
explicit and greppable. From a terminal, `agentplane tasks` lists what is
waiting and `agentplane decide <task> approve --reason … --actor …` answers it.

## 8. Test it 🧪 {#test-it}

The `fake-model` feature — which `testkit` and `cli` both enable — gives you a
model provider with no model behind it, so a test can exercise the whole path
with no key and no network:

```rust
use agentplane::model::fake::FakeProvider;

let provider = FakeProvider::new();
provider.will_say("approved");

// ... run, then assert on what the run did ...
assert_eq!(provider.calls(), 1, "replay must not ask the model again");
```

It is deterministic, and it never reports a call as free, so budget tests
count.

It can stream, too, which is what makes a live view testable:

```rust
provider.streaming().will_say("approved");
// every scripted answer now arrives as text deltas and a usage snapshot
// before the completion returns
```

Concatenating every delta reproduces the completion byte for byte.

## Where next 🧭 {#where-next}

Every runnable example, by the question it answers. Run one with
`cargo run --example <name>`, adding `--features` with the set in the third
column; none of these needs credentials or network:

| Question | Example | `--features` |
|---|---|---|
| What is one skill, one run and one replay? | `hello_skill` | |
| Does replay or crash recovery repeat calls? | `durable_pipeline` | |
| Who resumes a run whose *process* died holding it? | `recovered_run` | |
| What happens when a run hits its budget — and who un-pauses it? | `budget_pause` | |
| Can an operator stop a run and have it undone — or stop a whole tenant? | `operator_stop` | |
| What happens to a call nobody can account for? | `answered_doubt` | |
| What does an operator alert on, and what reaches the collector? | `observability` | |
| How do long-lived cases, early events and human work fit? | `clearing_case` | |
| How are plans validated and provenance propagated? | `plan_graph` | |
| Can untrusted content accompany a trusted tool selector safely? | `governed_transfer` | `manifest` |
| What happens after the third system in a transactionless workflow fails? | `saga_checkout` | |
| Can several calls take together, or not at all — including an email? | `effect_group` | |
| How does one act over many items resume without settling any twice? | `batch_run` | |
| What stops a model that chooses its own tools? | `tool_loop` | `fake-model,manifest` |
| How does a person approve the exact call before it happens? | `approved_call` | `fake-model,manifest` |
| Can a prompt injection arrive and find no reader? | `planned_run` | `fake-model,manifest` |
| Does a replay call the model or spend again? | `model_run` | `fake-model` |
| How do governed media capabilities materialize without entering the journal? | `media_run` | `fake-model,media` |
| Can prompt, model, schema and ceilings be one digest-covered file? | `manifest_run` | `fake-model,manifest` |
| How does an MCP server sit beside a typed Rust tool? | `mcp_tools` | `fake-model,manifest,mcp` |
| What does a host see when it calls *this* plane over MCP? | `serve_mcp` | `mcp-server` |
| How does an agent remember across runs without a storage backdoor? | `memory_run` | |
| Can one customer's approved budget span several runs, then be revoked? | `standing_authority` | `fake-model` |
| What does erasing a case actually erase — and what still verifies? | `sealed_run` | `testkit,keyring` |
| What stops a retention pass from erasing a matter under a preservation order? | `retention_hold` | |
| How are separate agents and handoffs bounded? | `blog_room` | `fake-model,manifest` |
| What does another organisation's agent see when it calls this one? | `a2a_peer` | `a2a-server,manifest` |
| How does an agent call another *plane's* agent, and whose chain does the peer see? | `peer_call` | `testkit,manifest,a2a,a2a-server` |
| How do live tokens coexist with a journal that must replay exactly? | `streaming_run` | `fake-model` |

These need something from outside, and none runs in CI:

| What it shows | Example | `--features` | Needs |
|---|---|---|---|
| The `planned_run` shape against a privileged and a quarantined model, checking at the wire which was shown the attack; `just camel-live` runs it from `.env` | `camel_live` | `providers,manifest` | `OPENAI_API_KEY`, and spends money |
| A governed run and a strict replay against a real `OpenAI` model | `openai_live` | `providers` | `OPENAI_API_KEY`, and spends money |
| One Amazon Bedrock Converse call | `bedrock_live` | `bedrock` | `AGENTPLANE_LIVE=1`, `AWS_REGION`, `AGENTPLANE_BEDROCK_MODEL` and AWS credentials |
| This plane's A2A surface, served for the official conformance kit; `just test-a2a-tck` drives it | `a2a_tck_live` | `a2a-server,manifest,testkit` | a checkout of `a2a-tck` |
| What the gate costs, and which part dominates → [what the gate costs](@/docs/operations.md#what-the-gate-costs) | `gate_bench` | `cedar` | a `--release` build |

| | |
|---|---|
| 🧠 | [Concepts](@/docs/concepts.md) — runs vs cases, effects, dispositions, labels |
| 🍳 | [Cookbook](@/docs/cookbook.md) — "how do I …" recipes |
| 🏗️ | [Architecture](@/docs/architecture.md) — how the mechanisms actually work |
| 🔐 | [Security model](@/docs/security.md) — the trust boundary and its limits |
| ⚙️ | [Operations](@/docs/operations.md) — running it for real |

## Troubleshooting 🔧 {#troubleshooting}

**`Quarantined("non-determinism at seq …")`** — the code changed since the
journal was written, and replay found a different effect than history records.
That is the mechanism working. Use `Mode::Resume` for crash recovery of the
*same* build; a changed build replaying old history is divergence, not recovery.

**`Quarantined(…)` on an effect nobody can account for** — a call was announced
and the runtime never learned whether it landed, so nothing unwinds. A resume
will reach the same conclusion, because the missing piece is a *fact*, not a
retry. `GET /runs/{id}` lists the effects in doubt; look one up in the system
that would know, record the answer, and hand the run back — or write it off, in
which case what it left standing becomes an audit finding rather than
disappearing with the status. The whole protocol is
[Answering a quarantine](@/docs/operations.md#answering-a-quarantine).

**`StepError::Denied`** — the policy engine refused. The journal has the reason;
the *model* is told one uniform sentence, so a refusal is no oracle for an
injected prompt. See
[security](@/docs/security.md).

**`StepError::NotWired`** — the step asked for something this plane was not
built with: a task store, a timer store, a case, a peer registry. Nothing was
asked of the world. The run fails rather than relaying the error to a model,
and an open effect group beside it is taken back cleanly. Wire the missing
piece and resume.

**`protected field ...`** — an authority-bearing path is absent, untrusted,
derived from a source outside the allowlist, or above its own sensitivity
ceiling. Fix the dataflow or use a narrowly scoped, policy-authorized `Release`;
do not mark the whole object trusted.

**`Exhausted(...)`** — a declared budget, or a tool's `rate_limit`, bound the
run. This is a journaled **pause**, not a fault: its completed work stands, and
inside an open effect group the group stays open. Raise the reviewed ceiling
and resume — the recorded refusal is re-evaluated against the current ledger —
or cancel, which unwinds and starts no new work. `cargo run --example budget_pause` runs the whole protocol:
pause, re-refusal under the same ceiling, re-admission under a raise, strict
verification.

**A run that never finishes** — it is probably suspended waiting for an event,
a timer, or a human. `GET /runs/{id}` reports *why* it is not finishing rather
than just that it is not.
