+++
title = "Your first agent"
description = "Build one support-triage agent from an empty file to a durable, tool-using, pinnable declaration — every step a command, every mistake a refusal."
weight = 2

[extra]
group = "Start here"
+++

A tutorial, in the strict sense: you build **one** agent, from an empty file to
a durable, tool-using, pinnable declaration, and every step is a command you
run. Nothing here needs an API key, a network, or a Rust toolchain — the model
is the deterministic fake until the last section, which tells you exactly what
changes to go live.

One method note before the first command, because it is the method: **the
format teaches by refusing.** We start with a file that is deliberately too
small and let the parser tell us what is missing and why it matters. Every
refusal below is real output, and each one names the fix — reading them *is*
the tutorial.

The [getting-started](@/docs/getting-started.md) page is the fast tour of the
runtime's claims, and the Rust path — writing a `Skill` against the crate —
lives there. This page is the slower, file-first walk.

## 1. Install the CLI

```sh
cargo install agentplane --features cli
```

Or with no Rust toolchain at all:

```sh
docker run --rm -v "$PWD:/work" ghcr.io/hupe1980/agentplane validate /work/triage.yaml
```

Every command below works the same way through the image; mount your working
directory and prefix paths with `/work/`.

## 2. Start too small, on purpose

Create `triage.yaml`:

```yaml
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: triage, version: "0.1.0" }
spec:
  execution: { kind: completion }
  model: { provider: fake, model: triage-1 }
  budgets: { max_tokens: 20000 }
```

(`agentplane init` writes a starter like this one, with the schema modeline
already in it; `init --tools` writes a tool-calling one.)

That file is the smallest agent this format accepts. `model:` is shorthand for
`models: { privileged: … }`, the single-model case, and the capability the agent
answers defaults to its `metadata.name` — `triage` here — as a skill that
declares none answers its own name. Both resolve before the digest is taken, so
the file that spells them out is the same agent. Say
`capabilities: { provides: [support.triage] }` when callers should ask for
something other than the name.

Each of the three `spec` entries is there because something refuses its
absence. Try deleting them one at a time; each refusal is a design decision
stated at the moment it bites.

Without `execution`, the file still **validates** — it is then the declaration
of an agent whose behaviour is Rust code you register yourself — but
`agentplane run` refuses it, because there is nothing in the file for the
binary to run:

```text
agentplane: manifest 'triage' declares no `spec.execution`, so its behaviour is
a skill somebody wrote and there is nothing here for this binary to run …
```

Without `model` (`agentplane validate` refuses this and the next one):

```text
agentplane: spec.execution cannot be enforced here: this agent's behaviour is
declared, so the runtime drives it by calling a model — and no
`spec.models.privileged` names one. The model is named rather than defaulted,
because falling back to another registered driver would run the agent on a
model its own declaration does not name …
```

Without `budgets`:

```text
agentplane: no budgets declared. An agent with no ceiling is the one that runs
up a bill nobody authorised — write `budgets: {}` if you mean unbounded, so
that the decision is in the file rather than in its absence
```

That last one is the format's whole posture in a sentence: an absent decision
is not a default, it is a refusal — even *unbounded* has to be written down.
With all three present:

```sh
$ agentplane validate triage.yaml
ok: triage 0.1.0
  one call, privileged fake/triage-1: unbounded — spec.models.privileged.max_input_tokens is not declared
  worst case, tokens: no total — unbounded: spec.models.privileged.max_input_tokens
  worst case, minor units: no total — unbounded: spec.budgets.max_minor_units, spec.models.privileged.max_input_tokens
```

The indented lines are what the file says a run can cost, read off it and
nothing else: its ceiling plus one call past it per step in flight. Each
`unbounded` names the field that would bound it. That is fine for a first
agent; under a tenant's spend quota it is what gets a run refused, because an
unbounded run cannot be reserved — see
[what one call can cost](@/docs/manifest.md#per-call-bound).

## 3. Run it

```sh
$ agentplane run triage.yaml --input '{"ticket": "printer on fire"}'
note: journaling to memory; this run will not survive the process
run run_01M13H32MK2V3KTJZDZQB6MQYG — Succeeded
{"text":"fake answer to {\"input\":{\"ticket\":\"printer on fire\"},\"system\":\"\"}"}
```

Three things worth reading off that output. The answer goes to **stdout** and
everything else to stderr, so it pipes. The `note:` line is honest about what
an in-memory journal means — we fix that in step 5. And the fake driver echoes
what it was asked, which makes it a mirror: `\"system\":\"\"` says this agent
walks up to a model with **no instructions at all**.

## 4. Give it an identity and a result contract

The prompt belongs in the file — rewording it should be a version bump a
reviewer sees, not a deploy nothing records. And an agent whose answer feeds a
system, not a human, should say what shape the answer takes. Add both:

```yaml
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: triage, version: "0.1.0" }
spec:
  execution: { kind: completion }
  identity:
    role: "Support ticket triage"
    constraints: "Classify severity. Never promise a refund."
  model: { provider: fake, model: triage-1 }
  output:
    schema:
      type: object
      additionalProperties: false
      required: [severity, summary]
      properties:
        severity: { type: string }
        summary: { type: string }
  budgets: { max_tokens: 20000 }
```

```sh
$ agentplane run triage.yaml --input '{"ticket": "printer on fire"}'
{"severity":"fake","summary":"fake"}
```

The schema travels to the provider and is enforced **during generation** — a
schema applied afterwards rejects an answer you already paid for. The fake
enforces it exactly as a real driver does, which is why the echo became a
schema-shaped object.

While you are editing: this format refuses typos rather than ignoring them.
Misspell a ceiling and the file is rejected —

```text
agentplane: manifest is not well-formed: document 1: unknown field `max_tokns`,
expected one of `max_steps`, `max_effects`, `max_tokens`, `max_minor_units`,
`max_replans`, `max_wallclock_secs`, `max_denials`, `max_egress_bytes`,
`max_parallel_steps`
```

— because in a tolerant parser `max_tokns: 100` does not mean "a ceiling with
a typo"; it means **no ceiling at all**, in the one document whose purpose was
to make the ceiling reviewable. For autocomplete and these errors inline in
your editor, put the published schema in a modeline (see
[editor validation](@/docs/manifest.md#editor-validation)):

```yaml
# yaml-language-server: $schema=https://hupe1980.github.io/agentplane/agent.schema.json
```

## 5. Make it durable, and replay it

```sh
$ agentplane run triage.yaml --input '{"ticket": "printer on fire"}' --store runs.redb
run run_01M13H3XGTE0BHXA1S1YR575BY — Succeeded
{"severity":"fake","summary":"fake"}

$ agentplane replay run_01M13H3XGTE0BHXA1S1YR575BY \
    --store runs.redb --manifest triage.yaml --strict
run run_01M13H3XGTE0BHXA1S1YR575BY — verified — the recorded `succeeded` ending was reproduced
  recorded: triage 0.1.0 8170f033…
  candidate: triage 0.1.0 8170f033…
  (same digest)
```

The second command re-executed the run's logic and read every effect back from
the journal — **the model was not called again**, and no provider key is
needed to do it. That is the runtime's central claim, held by your agent on
your disk: the completion is history, and `--strict` verifies the history
reproduces. Hand it an *edited* `triage.yaml` and it names the first effect
the edit changes, under both digests — the check to run on a manifest change
before it ships ([replaying an edited declaration](@/docs/operations.md#strict-replay)).
Without `--strict`, `replay` *resumes* — the verb you reach for when a run
crashed or suspended partway.

## 6. Give it a tool

A triage agent that can read the ticket system is more useful than one that
only reads the prompt. Tools change the agent's kind — a `completion` agent
answers in one call; a `tool-calling` agent loops until the model stops
asking. Change `execution` and add a grant:

```yaml
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: triage, version: "0.2.0" }
spec:
  execution: { kind: tool-calling, max_turns: 3 }
  identity:
    role: "Support ticket triage"
    constraints: "Classify severity. Never promise a refund. Cite the ticket id."
  capabilities: { provides: [support.triage] }
  models:
    privileged: { provider: fake, model: triage-1 }
  tools:
    - ref: "tool://tickets/read"
      mutates: false
      description: "Read a ticket by id"
      arguments:
        type: object
        additionalProperties: false
        required: [id]
        properties: { id: { type: string } }
  budgets: { max_tokens: 20000 }
```

Note what the grant does **not** say: how `tickets` is reached. An agent's
declaration — and therefore its digest — must not change when it moves between
your laptop and a cluster, so grants are reviewed and wiring is deployed. Run
it without wiring anything and the plane refuses at build, not on turn three:

```text
agentplane: agent 'triage' declares `execution.kind: tool-calling` with
1 tool grant(s), but this plane has no tool catalogue, so every run would fail
identically …
```

The wiring is one flag — `--mcp` names which command serves `tickets`
(`examples/mcp-server.py` in the repository is a minimal stdio MCP server to
play with):

```sh
$ agentplane run triage.yaml --input '{"ticket": "T-1"}' \
    --mcp "tickets=python3 examples/mcp-server.py"
  mcp: tickets <- python3 examples/mcp-server.py (MCP 2026-07-28)
run run_01M13H94M4K11MZKYX4AE6THQX — Succeeded
{"text":"fake answer to {\"system\":\"Support ticket triage\\n\\nClassify severity. Never promise a refund. Cite the ticket id.\",\"input\":{\"ticket\":\"T-1\"}}"}
```

Honesty about what just happened: the wiring, the grant and the loop are all
real, but the deterministic fake has no judgement, so it answered without
choosing the tool. Watching a model actually *choose* — and watching the
refusals that bound what it may choose — is
`cargo run --example tool_loop --features redb,fake-model,manifest` in the
repository, or this same file against a live model (step 8).

One posture rule is worth meeting now, because you will hit it the first time
a tool *changes* something. Declare a grant `mutates: true` with no field
rules and the file is refused:

```text
agentplane: manifest is not well-formed: spec.tools: 'tool://tickets/close'
declares `mutates: true` with no `protected_fields`, and this agent is
`execution.kind: tool-calling`. A tool loop's arguments come from a model
completion, which is always untrusted, so a mutating call with no field rules
is refused by the taint gate on every run — the grant reads as a capability
and is decoration. Three honest fixes: declare the authority-bearing arguments
in `protected_fields` …
```

A model may choose what to *read*; which fields of a *write* it may author is
the operator's decision, written in the grant. The
[manifest reference](@/docs/manifest.md#protected-fields) covers
`protected_fields`, and `requires_approval: true` puts a person in front of
each call — `cargo run --example approved_call --features redb,fake-model,manifest`
runs that whole shape.

## 7. Pin what you built

```sh
$ agentplane digest triage.yaml
8386d584637902cb8b9a1ed4cab4647a7c9238535aa3d585a269b9b6193f8f82
```

That number covers everything you wrote — prompt, model, schema, grants,
ceilings — so it is the answer to *which agent was this, exactly* in every
journal record, and what a registry pins so a published version cannot be
quietly rewritten. It is also on the Agent Card this file would advertise as
an A2A peer:

```sh
agentplane card triage.yaml --url https://triage.example/a2a
```

## 8. Where to go from here

**Go live.** Change the model to a real one — that changes the digest, which
is the point — and export the matching key. Nothing else moves:

```yaml
  models:
    privileged: { provider: anthropic, model: claude-sonnet-5 }
```

```sh
export ANTHROPIC_API_KEY=…
agentplane run triage.yaml --input '{"ticket": "printer on fire"}' --store runs.redb
```

**Host it.** `agentplane serve` puts this same file behind the A2A 1.0 peer
surface — with a policy file and bearer tokens, both required, neither
defaulted. The [getting-started](@/docs/getting-started.md#hosting-it-still-without-rust)
page walks it, including the one manifest line serving requires.

**Grow it into a room.** Several manifests in one file, separated by `---`,
give you a multi-agent room with no Rust anywhere —
`examples/room.yaml` in the repository is a working one, and the
[cookbook](@/docs/cookbook.md#consult-another-agent-from-a-file) explains the
`tool://agent/...` grant that lets one agent consult another.

**Drop to Rust when a decision is code.** A skill with an `if` in it beats a
prompt asking a model to pretend to be one. The
[getting-started](@/docs/getting-started.md#write-a-skill) page begins there,
and `examples/` holds runnable answers to specific questions.
