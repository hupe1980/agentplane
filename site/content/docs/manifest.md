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

In the tables below, **required** in the Default column means there is no
default: omitting the field is a parse error.

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
  capabilities:   { provides: [support.triage] }
  models:
    privileged:   { provider: anthropic, model: claude-sonnet-5 }
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
    subject: "$correlation/customer"     # per-party, resolved at run time
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
| `kind` | **required** | `completion`, `tool-calling` or `planned`. |
| `max_turns` | `8` | The loop's turn ceiling, and a `planned` agent's step ceiling. A ceiling, not a suggestion: a budget also stops a runaway loop, but only *after* paying for every turn. |

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
and the egress ceiling decide. `output.schema` rides **every** turn, not only
the last — which turn answers is the model's choice, so there is no moment
before dispatch at which "this is the final turn" is known, and a schema
attached only where the runtime guessed the answer would land is a contract the
model can step around by answering a turn early. A turn that asks for tools is
untouched; the turn that answers is provider-constrained during generation, and
the settled answer is validated against the schema before it is returned. An agent still asking when `max_turns` runs out
**fails** rather than returning half-formed reasoning as its answer.

**`planned`** — plan first, then execute without the model. One privileged
call reads the run's input — which **must be trusted**, refused otherwise —
and answers with a plan in a bounded schema: which granted tools to call, in
what order, with which arguments. The runtime validates every step against
the grants and executes the plan itself. Step outputs travel as **references**
(`$step0/customer/email`, `$input/payee`), resolved with labels intact and
never read by a model — so a hostile tool output cannot steer later steps,
and a protected field is satisfiable by binding to a trusted source. A
`parse` step hands a prior output to the **quarantined** model under a
declared schema and a runtime-injected `have_enough_information` bit whose
`false` fails the step. The trade: a plan cannot react to what it discovers.
Choose `planned` when the task's shape is known up front and the data is
hostile; `tool-calling` when the shape is the discovery.

A `tool-calling` or `planned` agent granting a tool with no `description` is
refused at parse: a bare name makes the model guess, and the guess is refused
at the field check *after* the tokens are paid for.

## `spec.identity`

| Field | Required | Notes |
|---|---|---|
| `role` | yes if the block is present | Non-empty. What the agent is for, in one line. |
| `constraints` | no | How it must behave. Separate from `role` because the two are reviewed by different people and change on different schedules. |

There is no `workload_id` field: nothing would read it, so it would be an
identity claim the runtime never checks. Workload identity is configured on the
plane and recorded in the journal (`IdentityBound`). Same reasoning as
`capabilities.requires`.

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

**A coded skill is not forced into that trade, and reading only the paragraph
above suggests it is.** `StepCtx::manifest()` hands a skill the declaration it is
running under, and `Identity::system_prompt()` renders `role`, a blank line, then
`constraints` — the same string a declarative agent gets:

```rust
use agentplane::manifest::Identity;

let system = cx
    .manifest()
    .and_then(|m| m.spec.identity.as_ref())
    .map(Identity::system_prompt)
    .unwrap_or_default();
```

So behaviour can stay in Rust while the prompt stays in the reviewed, digested
file. What a coded agent gives up is coverage of its **conduct**, not of its
prompt: the manifest still pins what it says, and cannot pin what the code then
does with the answer. That distinction is worth stating plainly, because an
evaluation reasoned from the paragraph above that the two were exclusive and
recorded the trade-off as settled.

There is no templating — no `{variables}`, no dynamic-instructions callback,
no state injection. A templated instruction has no reviewable identity, and
the instruction slot is the trusted slot: run-time values spliced into it
would wear its trust. Per-run data goes in the **input**, journaled and
labelled, beside the instruction.

**A prompt naming a tool the agent was never granted is refused.** An ungranted
name comes back to the model as a *failed call* — deliberately, so it can correct
itself and never gets the tool it nearly named. The cost is that a **procedure**
naming an ungranted tool fails quietly: the model asks, is refused, improvises,
and the step silently does not happen, with nothing in the journal saying the
instruction was unfollowable. So any `tool://server/name` written in `role` or
`constraints` must be a tool `spec.tools` grants.

It only sees references spelled as references. *"call `list_overdue_processes`"*
names a tool in prose, and prose is not something this crate can tell from an
ordinary noun — a check that guessed would refuse manifests over the word
"search". Writing the grant's own `ref` in the prompt is therefore both the
spelling that gets checked and the spelling a reviewer can follow.

## `spec.topology`

| Field | Default | Values |
|---|---|---|
| `mode` | `single` | `single`, `collaborative` |
| `role` | `specialist` | `specialist`, `orchestrator` |
| `reason` | **required** | `parallel-disjoint`, `distinct-authority` |

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
| `max_sensitivity_journaled` | unbounded | The highest sensitivity an argument may reach an effect **whose arguments the journal records**. Egress asks *may this leave*; this asks *may this be written down forever*, and a record is never removed from an append-only chain. Refused at dispatch, before anything is recorded. It is the *refuse it* answer to that question; `.keyring(..)` is the *seal it* answer, and a deployment may take either or both → [erasure and keys](@/docs/erasure.md). |
| `max_delegation_depth` | role-dependent | Checked against the configured identity *and* against every delegating sink, including in-plane `commission`. |

## `spec.capabilities`

| Field | Notes |
|---|---|
| `provides` | The capability names this agent answers to. `Runtime::run(capability, input)` dispatches on these, and a plane **refuses to build** if two agents claim one capability or if a declarative agent provides none. |

A coded agent may provide several capabilities — each has its own skill
behind it, and the build refuses a declared capability no registered skill
serves. A **declarative** agent provides exactly one, refused at parse
otherwise: the capability never reaches the prompt, so a second name would be
a distinction nothing executes. Two capabilities are two documents in one
room file.

There is no `requires` twin. Parsed and digest-covered but never enforced, it would be a control the runtime does not check — exactly what a reviewable file exists to eliminate. A build-time check that every required capability is available on the plane is a well-formed future control; a field that only *documents* intent belongs in prose, not beside enforced ceilings.

There is no `SKILL.md`, no `kind: Skill`, and no free-form `spec.config`:
instructions live in `identity.constraints`, on-demand references are
`spec.context` grants, executable helpers are tools, and behaviour shared
between agents is an agent of its own, granted as `tool://agent/<capability>`.

## `spec.models`

| Role | Notes |
|---|---|
| `privileged` | The model trusted with tool calls and decisions. |
| `quarantined` | The model that reads untrusted material and holds no authority. |

**`quarantined` is refused where nothing would select it.** Two things point a
model at untrusted-derived content on their own: a plan's `parse` steps
(`execution.kind: planned`) and `memory_formation`. A `completion` or
`tool-calling` agent with neither sends *every* call to the privileged model, so
declaring the second role there would read as dual-model isolation while one
model did all the work — a control the file claims and the runtime never
applies. A **coded** agent may declare both: its skill chooses, so the roles are
a reviewed allowlist rather than something a tier selects from.

Both are `{ provider, model }` plus two optional per-role ceilings —
`max_tokens`, a per-call output ceiling, and `reasoning_effort`, an explicit
reasoning depth. The ceilings are enforced on **every** call the role serves:
the quarantined role's included, so a memory-formation extraction or a `parse`
step runs under the reviewed bounds rather than the driver's defaults.
`provider` is the name a driver was registered under. The `agentplane` binary ships `openai`, `anthropic`, `gemini`,
`bedrock`, `chat-completions` and `fake`; an embedder registers its own with
`RuntimeBuilder::provider`, and a name nothing was registered under is refused
at build rather than at the first call. The pair is
**refused when both roles name the same provider and model**: two roles behind
one model keeps the label and removes the control it stands for.

What `quarantined` does today: it is part of the reviewed model allowlist,
**memory formation** runs on it when declared, and a `planned` agent's
**`parse` steps** run on it — no tools, a bounded schema, and nothing handed
back to the privileged path but success or failure. The agent's answer stays
on the privileged model. The runtime does not route ordinary completions
between the two by content.

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
| `max_minor_units` | money in **minor units** — cents, not euros. A float would make a budget that fails to bind by a rounding error, and it is **unsigned**, so a negative ceiling is a parse failure rather than a ceiling that un-spends itself |
| `max_replans` | replans |
| `max_wallclock_secs` | seconds, named for its unit so a manifest cannot mean minutes |

Budgets bind the whole run including delegation: `commission` is an effect, so a
sub-run's reported spend is billed to the run that ordered it.

## `spec.tools`

| Field | Default | Notes |
|---|---|---|
| `ref` | **required** | `tool://server/name`. Transport-neutral: which transport reaches `server` is a deployment decision made by `ToolRouter`, so one manifest runs against an in-process double in a test and a real MCP server in production. |
| `mutates` | `true` | Whether calling it changes the world. The cautious default. |
| `max_sensitivity` | `public` | The highest sensitivity this tool may be *sent*. |
| `description` | **required** | What the model is told. Required for a `tool-calling` agent. In the digest, because text that steers tool selection belongs where the system prompt does. |
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

On a mutating grant, **at least one protected field must carry a trust or
source rule** — `require_trusted: true`, or `allowed_sources` naming where the
value must come from. A grant whose every entry carries only a sensitivity
ceiling is refused at parse: declaring protected fields is what lifts the
whole-object taint gate, and a ceiling bounds how *secret* an argument may be,
not who authored it — so the model's own untrusted completion would fill every
authority-bearing field unconstrained. A source rule names the **concrete**
source an effect's output carries: `tool://server/name`, `model:{provider}/{model}`,
`agent/{capability}`, or an operator identity of your own.

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
| `approval` | **required** | `required` gates every answer. `tools-only` gates only the grants that set `requires_approval`, leaving the answer unattended — the shape most deployments want, since gating a tool-calling agent's *answer* is a review that arrives after the tool already ran. Under `tools-only`, **every mutating grant must declare `requires_approval`** — refused at parse otherwise, because a mode that gates tool calls while a call that changes the world needs nobody is a declared control nothing enforces; read-only grants stay ungated. `none` gates nothing and leaves the deciding to `triage`. None is a predicate: *"require approval when severity is high"* changes what the agent **does**, and that is one step from an `if`. |
| `approvers` | anyone | Roles that may decide. Empty means anyone — worth choosing on purpose rather than by omission. |
| `deadline` | **required** | The obligation that bounds the wait: `{ name, kind, params }`. The agent **registers** it, which is why the declaration carries more than a name — a file-only agent writes no code, so naming an obligation nothing registers made oversight fail outright. `kind` and `params` go to the deployment's `Calendar` unchanged, so "one working day" means whatever that domain says and this crate never guesses. |
| `on_expiry` | deny | What happens when the window closes. |
| `allow_unattended` | `false` | Explicit consent required for `on_expiry: proceed`, so acting with no human is a greppable decision somebody made rather than an enum variant they picked off a list. |
| `triage` | none | Tasks opened **beside** a completed answer. See below. |

The agent registers the obligation, opens a task carrying its **actual answer**,
and returns only on approval. It applies to **both** execution kinds — a
`tool-calling` agent has already touched the world by the time it answers, which
is the case that most needs a person.

Nothing is written until the answer is approved. In particular
`memory_formation` runs *after* the decision, because a memory formed from a
refused answer would be read by the next run as established fact — a control that
governed the reply and not the write would govern the less important half.

An oversight block that performs nothing is **refused**: `approval: none` with an
empty `triage` and no grant asking for approval is a declaration that reads in
review as a human control and is not one.

See [human oversight](@/docs/concepts.md#oversight).

### `spec.oversight.triage`

The mode an **advisory** agent needs. A `tool-calling` agent that grants no
mutating tool cannot act at all — its arguments come from a model completion, so
a mutating call with no `protected_fields` is refused by the taint gate on every
run, which is why that grant is refused outright. For a whole class of agents the
other two modes are therefore both wrong: `tools-only` gates nothing because
there is no mutating call to gate, and `required` suspends every run until
somebody approves a *report*.

`triage` says: **return the answer, and open a task when it says something a
person must see.**

```yaml
oversight:
  approval: none
  deadline: { name: unused, kind: hours, params: { n: 4 } }
  triage:
    - name: breach
      summary: "a regulatory deadline was missed"
      audience: [grid-operations]
      priority: high                     # low | normal | high | urgent
      when:
        - path: /deadline_status
          equals: BREACH
      deadline: { name: triage-breach, kind: working-days, params: { n: 2 } }
```

| Field | Default | Notes |
|---|---|---|
| `name` | **required** | Unique within the block. The task's kind is `agent.triage/<name>`, so a worklist can filter on it and a rule cannot collide with a runtime kind. |
| `when` | **required** | Conditions, **all** of which must hold. Empty is refused: a rule matching every answer is a task per run written as a filter. |
| `summary` | **required** | What the worklist row says, in the words a reviewer reads — in the file, and digest-covered, for the same reason the system prompt is. |
| `audience` | anyone | Roles the row is offered to. |
| `deadline` | **required** | The obligation bounding the row. Its own, not the block's: how long a *run* waits for approval and how long a *row* may sit are different questions. |
| `priority` | normal | How the row is ranked. |

A condition is one JSON Pointer and one of five total operators — `equals`,
`in`, `at_least`, `at_most`, `exists`. There is no nesting, no `or`, and no
negation. Rules are independent: two matching rules open two rows, because two
findings are two desks' work.

**Why this may hold a predicate when `approval` may not.** A triage rule changes
nothing about the run. The answer is produced, validated against `output.schema`,
returned, and the memories are formed identically whether a rule matched or not;
the only effect is a row in a worklist. That is *reporting*, and reporting is the
one place a declaration can carry a condition without becoming control flow.

Two refusals keep it honest:

* **`triage` requires `spec.output`.** A predicate over an answer with no
  declared shape is prose about a document nobody wrote.
* **Every condition is typed against that schema**, and refused where the schema
  *provably* cannot produce the pointer — a `type: object` with
  `additionalProperties: false` whose `properties` lack the field. Deliberately
  narrower than a validator: anything the walk cannot decide (`$ref`, `anyOf`, an
  open object) passes, because a check that guessed would refuse valid manifests.
  A rule that can never fire reads in review exactly like one that does.

Rows are opened **after** the approval gate and after formation, so every row in
a worklist corresponds to an answer that was actually returned. The task carries
the answer itself; it is untrusted model content, deliberately — a worklist whose
rows had to be trusted could only carry findings nobody needs to look at.

## `spec.memory_formation`

Forms bounded durable facts from each declarative answer. Refused without
`execution` (a coded skill calls `StepCtx::form_memories` explicitly) and without
a declared `privileged` model.

| Field | Default | Notes |
|---|---|---|
| `subject` | **required** | Where the memories are filed — a literal, or a **binding** resolved per run. See below. |
| `purpose` | **required** | Mandatory retrieval partition. |
| `instruction` | **required** | What the extraction model is asked to record. |
| `max_items` | `3` | Between 1 and 10. |
| `retention_seconds` | none | Fixed expiry. |
| `access_retention_seconds` | none | Sliding expiry, refreshed by an explicit journaled touch. |
| `max_sensitivity` | `public` | Ceiling on what the forming model may be shown. |

The model proposes bounded key/content pairs; the **runtime** derives ids, taint,
provenance and retention. Trust is never taken from what the content says.

### Binding the subject to the party a run is about

A **subject is the unit `forget_subject` erases**, so a literal one pools every
customer, meter and matter the agent ever reasoned about under one key. One
party's facts are then recalled into another party's run, and an erasure request
naming one person cannot be satisfied without destroying everybody's. Under a
data-protection regime that is a defect, not a caveat.

A binding resolves the subject from something the **run** already established:

| Binding | Resolves to |
|---|---|
| `$correlation/<namespace>` | The value of one of the run's correlation keys. |
| `$case` | The case id. |
| `$input/<pointer>` | An RFC 6901 pointer into the run's input — **only if that field is trusted**. |
| anything else | A literal, exactly as written. `$$x` is the literal `$x`. |

```yaml
memory_formation:
  subject: "$correlation/malo"     # one pile per metering point
  purpose: clearing
  instruction: "Record stable facts stated in the source."
```

Four rules, each a refusal:

* **An unrecognised `$` value is refused**, never taken as a constant. Reading
  `$correlaton/malo` as the string `"$correlaton/malo"` would file every
  customer's memories under a typo, and nothing would look wrong until an
  erasure request.
* **A binding that cannot resolve fails the run.** No fallback: filing under the
  literal pools every party, and filing under a default moves one party's facts
  into another's pile. Both are silent.
* **`$input` requires a trusted field.** A subject taken from untrusted input is
  whoever supplied it choosing whose memories this run writes into — strictly
  worse than the pooling bindings exist to fix. Correlation keys need no such
  check: correlation is a deterministic lookup performed at admission from keys
  the deployment's edge supplied, and no model touches it.
* **A case-bound subject on a plane with no case store is refused at `build`**,
  because nothing could ever resolve it.

The keys a binding resolves against are the ones recorded on the run's
`CaseBound` journal record — **not** the case's keys as they stand now. A case
accumulates keys over months, so re-reading them would let a resumed run resolve
a subject the live run never saw. A hand-written skill reaches the same values
with `cx.correlation()` and `cx.correlation_value(namespace)`, so reading these
memories back does not mean guessing at a naming convention.

A plane declaring `memory_formation` with no memory store is also refused at
`build`: formation runs *after* the answer, so left to run time it fails once the
run has already paid for its model calls.

The extraction runs on the **quarantined** model when `spec.models` declares
one, and on the privileged model otherwise — see `spec.models` above for why.
Write the `instruction` extraction-only, with fabrication refused: *record
stable facts stated in the source; do not infer addresses, dates or
identifiers that are not literally present*.

## What is deliberately not in the format

* **An injection-pattern label.** A manifest may name an enforced pattern only if
  the runtime builds and verifies the corresponding graph. Arbitrary skill code
  cannot be proven to follow one, so there is no such field rather than a
  review-only one.
* **`routed`/`router` topology**, and a **`fallback`** model role — both accepted
  YAML the runtime never executed.
* **A model-capability matrix.** Schema mode is configured per model on the
  driver, because a static matrix drifts faster than this crate releases.
