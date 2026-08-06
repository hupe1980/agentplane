+++
title = "Manifest reference"
description = "Every field an agent declaration may carry, what enforces it, and what an absent value means."
weight = 4
aliases = ["/reference/manifest/", "/docs/reference/manifest/"]
+++

An agent declaration is a YAML file. It is **content-addressed**, so editing it
changes the digest a consumer pins and the journal records; and it is parsed with
`deny_unknown_fields`, so a field this page does not list is a **hard failure**,
not a warning. `max_tokns: 100` in a permissive parser silently means *no token
ceiling at all*, which is the single most dangerous thing a configuration format
can do.

Two rules apply to everything below, and they are the reason the file exists:

* **Every field is enforced or refused.** There is no advisory tier. A control
  the runtime cannot bind is removed from the format rather than left as
  reviewable intent, because a security document that appears to enforce
  something it does not is worse than one that says nothing.
* **Absence means something, and it is stated.** Where silence would be
  expensive — an unbounded budget — it is refused. Where silence is an ordinary
  wiring decision — no declared model — it is allowed.

Every manifest on this site is parsed by the crate's own validator in CI, so
nothing here is a snippet that has never been run.

## The whole document

```yaml
apiVersion: agentplane.hupe1980.github.io/v1alpha1   # the only value
kind: Agent                                          # the only value

metadata:
  name: support-triage
  version: "2.0.0"

spec:
  execution:      { kind: tool-calling, max_turns: 6 }
  identity:       { role: "...", constraints: "..." }
  topology:       { mode: single, role: specialist }
  security:       { max_sensitivity_egress: internal, max_delegation_depth: 0 }
  capabilities:   { provides: [support.triage], requires: [] }
  models:
    privileged:   { provider: anthropic, model: claude-sonnet-5 }
    quarantined:  { provider: anthropic, model: claude-haiku-4-5-20251001 }
  budgets:        { max_tokens: 120000, max_steps: 5 }
  tools:
    - ref: "tool://tickets/read"
      mutates: false
      max_sensitivity: internal
      description: "Read a support ticket."
  output:
    schema: { type: object, required: [severity], properties: { severity: { type: string } } }
  oversight:
    approval: required
    deadline: { name: refund-review, kind: working-days, params: { n: 1 } }
  memory_formation:
    subject: "agent:triage"
    purpose: "support"
    instruction: "Record durable facts about this customer."
```

## `metadata`

| Field | Required | Notes |
|---|---|---|
| `name` | yes | Non-empty. Identifies the agent to an operator; **never** a grant — a rule keyed on a name grants authority to anyone who types it. |
| `version` | yes | Free-form and compared only for equality. The crate does not parse semver, because it has no version-ordering decision to make and pretending to understand a scheme it never checks would invite one. |

## `spec.execution`

Declaring this makes the agent **fully declarative**: the runtime supplies the
behaviour and you write no Rust. Omitting it means the behaviour is a registered
`Skill`, and the manifest governs its boundary rather than its conduct.

The difference is what the digest covers. A declarative agent is
content-addressed *in its entirety*; a coded one only as far as its declaration
reaches.

| Field | Default | Notes |
|---|---|---|
| `kind` | — | `completion` or `tool-calling`. |
| `max_turns` | `8` | `tool-calling` only. A ceiling, not a suggestion: a budget also stops a runaway loop, but only *after* paying for every turn. |

`kind` is a closed enum on purpose. A configuration format whose behaviours are
open-ended is one nobody can review, because the reviewer would have to know what
the string does.

**`completion`** — one model call, answered in the `output.schema` shape, using
the `privileged` model and the `identity` prompt. No tools, no second turn.

**`tool-calling`** — call tools until the model stops asking, then answer. The
model is offered exactly the tools `spec.tools` grants, with the descriptions and
argument schemas declared there; the name it returns is matched **byte for byte**,
and one matching nothing comes back as a failed call so the model can correct
itself. Arguments carry the completion's own untrusted label, so protected fields
and the egress ceiling decide. An agent still asking when `max_turns` runs out
**fails** rather than returning half-formed reasoning as its answer.

A `tool-calling` agent granting a tool with no `description` is refused at parse:
a bare name makes the model guess, and the guess is refused at the field check
*after* the tokens are paid for.

## `spec.identity`

| Field | Required | Notes |
|---|---|---|
| `role` | yes if the block is present | Non-empty. What the agent is for, in one line. |
| `constraints` | no | How it must behave. Separate from `role` because the two are reviewed by different people and change on different schedules. |

The prompt lives here so that rewording it is a **version bump** rather than a
deploy nothing records. A prompt composed in Rust has no version at all: it
changes, the journal records the run, and nothing connects the two.

**Where a long procedure goes: `constraints`.** There is no separate
`instructions` field, and adding one would be surface without semantics — the
prompt is exactly `role`, a blank line, then `constraints`, so a third field
would concatenate the same way while giving a reviewer one more place to look.

`role` is one line because it answers *what is this agent*; `constraints` is
unbounded and is where a hundred-line numbered procedure belongs. That it lives
in the digest is the point rather than a cost: in a regulated domain, editing
step 7 of a procedure **should** change the identity consumers pin, and should
show up as a diff with a reviewer on it. A procedure held in code has no version
at all.

The block is optional because an embedder may compose its prompt in code — in
which case the digest simply does not cover it, and the page says so rather than
implying otherwise.

## `spec.topology`

| Field | Default | Values |
|---|---|---|
| `mode` | `single` | `single`, `collaborative` |
| `role` | `specialist` | `specialist`, `orchestrator` |
| `reason` | — | `parallel-disjoint`, `distinct-authority` |

Three combinations are refused, and each refusal is the point:

* **`specialist` with `max_delegation_depth` above zero** — a specialist that may
  hand off is an orchestrator nobody reviewed as one. A specialist's effective
  ceiling is zero even when the numeric field is omitted.
* **`single` with a role other than `specialist`** — there is nobody to
  orchestrate.
* **`collaborative` with no `reason`** — collaboration costs roughly an order of
  magnitude more tokens and opens the whole inter-agent failure surface, so why
  it is warranted belongs in the file where a reviewer can disagree with it. A
  `reason` on a non-collaborative mode is refused too: a justification for
  something the agent does not do reads in review as one that was required.

`distinct-authority` is the reason worth emphasising, because neither side of the
public multi-agent debate raises it: **the best reason to split agents is often
security, not capability.** If a sub-task needs credentials the parent should not
hold, delegating to a narrower agent is least privilege.

There is no `routed`/`router`. Choosing one agent before a run starts is
deployment dispatch, and accepting YAML the runtime never executes manufactures
confidence.

## `spec.security`

| Field | Default | Notes |
|---|---|---|
| `max_sensitivity_egress` | unbounded | `public`, `internal`, `confidential`, `secret`. Combined with each sink's own ceiling at dispatch; the **stricter** wins. |
| `max_delegation_depth` | role-dependent | Checked against the configured identity *and* against every delegating sink, including in-plane `commission`. |

## `spec.capabilities`

| Field | Notes |
|---|---|
| `provides` | The capability names this agent answers to. `Runtime::run(capability, input)` dispatches on these, and a plane **refuses to build** if two agents claim one capability or if a declarative agent provides none. |
| `requires` | What it expects to reach, via `StepCtx::commission`. Descriptive. |

## `spec.models`

| Role | Notes |
|---|---|
| `privileged` | The model trusted with tool calls and decisions. |
| `quarantined` | The model that reads untrusted material and holds no authority. |

Both are `{ provider, model }`, where `provider` is the name a driver was
registered under — `openai`, `anthropic`, `bedrock`, or your own. The pair is
**refused when both roles name the same provider and model**: two roles behind
one model keeps the label and removes the control it stands for.

Absent means *wired in code*. `models: {}` means **no inference at all**,
declared on purpose — a rules-only agent is a legitimate design, and saying so is
what distinguishes it from one whose model wiring somebody forgot.

There is no `fallback` role. Fallback changes behaviour and must be explicit
orchestration, not decorative configuration the runtime never executes.

## `spec.budgets`

Absent is **refused**. An unstated ceiling is unbounded spend, and that is a
decision that has to be visible — declare `budgets: {}` to mean it.

| Field | Unit |
|---|---|
| `max_steps` | steps |
| `max_effects` | effects |
| `max_tokens` | tokens, across every model call in the run |
| `max_minor_units` | money in **minor units** — cents, not euros. A float would make a budget that fails to bind by a rounding error |
| `max_replans` | replans |
| `max_wallclock_secs` | seconds, named for its unit so a manifest cannot mean minutes |

Budgets bind the whole run including delegation: `commission` is an effect, so a
sub-run's reported spend is billed to the run that ordered it.

## `spec.tools`

| Field | Default | Notes |
|---|---|---|
| `ref` | — | `tool://server/name`. Transport-neutral: which transport reaches `server` is a deployment decision made by `ToolRouter`, so one manifest runs against an in-process double in a test and a real MCP server in production. |
| `mutates` | `true` | Whether calling it changes the world. The cautious default. |
| `max_sensitivity` | `public` | The highest sensitivity this tool may be *sent*. |
| `description` | — | What the model is told. Required for a `tool-calling` agent. In the digest, because text that steers tool selection belongs where the system prompt does. |
| `arguments` | derived | JSON Schema. Omit it for a typed `Tool`: the schema comes from the Rust argument type, and stating it twice is refused because a second copy can only drift. |
| `requires_approval` | `false` | A person approves **this call**, seeing the exact tool and arguments, before it is dispatched. Needs `spec.oversight` (which supplies approvers, the obligation bounding the wait, and what happens when it closes) and `execution.kind: tool-calling`; refused without either. |
| `protected_fields` | none | See below. |

### `protected_fields`

The field-level rule. Each entry is an RFC 6901 JSON Pointer plus the constraints
that path must satisfy:

```yaml
tools:
  - ref: "tool://ledger/transfer"
    mutates: true
    description: "Move funds between accounts."
    protected_fields:
      - path: /recipient
        require_trusted: true            # untrusted data may never select this
      - path: /amount
        allowed_sources: ["operator:treasury"]   # only these provenances
      - path: /memo
        max_sensitivity: internal        # this field's own ceiling
```

Ordinary content fields may stay untrusted beside them. That is the whole design:
a mutating tool with **no** protected fields refuses untrusted arguments
outright, and declaring which fields a model may influence is how you permit the
useful part without permitting the dangerous part.

## `spec.context`

Exact MCP context reads, separate from action-granting tools. They remain
untrusted data, but which external prompt/resource may enter an agent and at
what sensitivity is still a reviewed, digest-covered decision.

```yaml
context:
  prompts:
    - server: templates
      name: summarize
      max_input_sensitivity: internal
      output_sensitivity: internal
  resources:
    - server: knowledge
      uri: kb://support/rules
      output_sensitivity: internal
```

Prompt arguments are outbound data and `max_input_sensitivity` bounds them.
`output_sensitivity` raises the returned label when the server may disclose
classified content; neither field can make server output trusted. Duplicate or
blank grants are refused. URIs are exact — no wildcard whose interpretation can
disagree with the MCP server's URI parser. Use
`McpAccess::from_manifest(server, manifest)` to avoid restating these grants in
code.

## `spec.output`

| Field | Notes |
|---|---|
| `schema` | JSON Schema, digest-covered. Handed to `ModelCall::expecting`, so it enters the effect key — editing it makes a replay report divergence rather than reinterpreting a stored answer. `schema: {}` is refused: it permits anything while looking answered. |

## `spec.oversight`

Only meaningful beside `execution`. Declared next to a *coded* agent it is
**refused**, because nothing there would apply it, and a file must not claim a
human is in the loop when none is.

| Field | Default | Notes |
|---|---|---|
| `approval` | — | `required` gates every answer. `tools-only` gates only the grants that set `requires_approval`, leaving the answer unattended — the shape most deployments want, since gating a tool-calling agent's *answer* is a review that arrives after the tool already ran. Neither is a predicate: *"require approval when severity is high"* is one step from an `if`. |
| `approvers` | anyone | Roles that may decide. Empty means anyone — worth choosing on purpose rather than by omission. |
| `deadline` | — | The obligation that bounds the wait: `{ name, kind, params }`. The agent **registers** it, which is why the declaration carries more than a name — a file-only agent writes no code, so naming an obligation nothing registers made oversight fail outright. `kind` and `params` go to the deployment's `Calendar` unchanged, so "one working day" means whatever that domain says and this crate never guesses. |
| `on_expiry` | deny | What happens when the window closes. |
| `allow_unattended` | `false` | Explicit consent required for `on_expiry: proceed`, so acting with no human is a greppable decision somebody made rather than an enum variant they picked off a list. |

The agent registers the obligation, opens a task carrying its **actual answer**,
and returns only on approval. It applies to **both** execution kinds — a
`tool-calling` agent has already touched the world by the time it answers, which
is the case that most needs a person.

Nothing is written until the answer is approved. In particular
`memory_formation` runs *after* the decision, because a memory formed from a
refused answer would be read by the next run as established fact — a control that
governed the reply and not the write would govern the less important half.

See [human oversight](@/docs/concepts.md#oversight).

## `spec.memory_formation`

Forms bounded durable facts from each declarative answer. Refused without
`execution` (a coded skill calls `StepCtx::form_memories` explicitly) and without
a declared `privileged` model.

| Field | Default | Notes |
|---|---|---|
| `subject` | — | Sharing scope. An agent-private subject names one agent; a team subject is shared by several in one tenant. A naming convention, not an ACL — access is authorized as `memory.remember`/`memory.recall`. |
| `purpose` | — | Mandatory retrieval partition. |
| `instruction` | — | What the extraction model is asked to record. |
| `max_items` | `3` | Between 1 and 10. |
| `retention_seconds` | none | Fixed expiry. |
| `access_retention_seconds` | none | Sliding expiry, refreshed by an explicit journaled touch. |
| `max_sensitivity` | `public` | Ceiling on what the forming model may be shown. |

The model proposes bounded key/content pairs; the **runtime** derives ids, taint,
provenance and retention. Trust is never taken from what the content says.

## What is deliberately not in the format

* **An injection-pattern label.** A manifest may name an enforced pattern only if
  the runtime builds and verifies the corresponding graph. Arbitrary skill code
  cannot be proven to follow one, so the field was removed rather than left as
  review-only intent.
* **`routed`/`router` topology**, and a **`fallback`** model role — both accepted
  YAML the runtime never executed.
* **A model-capability matrix.** Schema mode is configured per model on the
  driver, because a static matrix drifts faster than this crate releases.
