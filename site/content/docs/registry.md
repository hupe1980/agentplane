+++
title = "Publishing and pinning agents"
description = "A content-addressed agent manifest, signed and published, and a registry that refuses to rewrite a version once it exists."
weight = 11
+++

An agent is a document with a digest. This page is how that document is
published, how a deployment pins one, and why the registry refuses to let a
version mean something different tomorrow.

## The manifest, and the registry it is pinned in

Everything security-relevant about an agent can be expressed as a builder call.
The problem is not that builder calls are wrong — it is that **a builder call is
invisible in review and a file is not.** A tool grant added by editing three
lines of Rust is a grant nobody notices; the same grant added to a manifest is a
diff with a reviewer's name on it.

```yaml
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: pattern-compliance-auditor
  version: "2.0.0"
spec:
  topology:
    mode: single
    role: specialist
  identity:
    role: "Automated data invariant auditor"
    constraints: "Isolate structural failures. Enforce semantic rule-packs strictly."
  security:
    max_sensitivity_egress: internal
    # Zero, because the role above is `specialist`. A specialist that may hand
    # off is an orchestrator nobody reviewed as one, so the pair is refused at
    # parse rather than accepted and quietly ignored.
    max_delegation_depth: 0
  budgets:
    max_tokens: 120000
    max_minor_units: 250
  models:
    privileged:  { provider: anthropic, model: claude-sonnet-5 }
    quarantined: { provider: anthropic, model: claude-haiku-4-5-20251001 }
  output:
    schema:
      type: object
      required: [finding, severity]
  tools:
    - ref: "tool://validator/apply_correction"
      mutates: true
      max_sensitivity: internal
```

### An agent that is only a file

Everywhere else in this crate, behaviour is a `Skill` somebody wrote. That is the
right answer when an agent does real work — a solver, a database, a calculation a
model cannot be trusted with. It is the wrong answer for the large class of
agents that are *a prompt, a model, and a result shape*, because the code adds
nothing a reviewer can check while removing something they could: **the digest
then covers only part of the agent.**

`spec.execution.kind` closes that gap. It names a behaviour this crate
implements, the runtime registers it, and nothing else is written:

```yaml
spec:
  execution:
    kind: completion        # one model call, answered in the declared shape
```

```rust
// The only Rust. Which driver answers to the name `fake` is deployment wiring —
// an agent's declaration must not change when its API key does.
let rt = Runtime::builder(store)
    .provider("fake", provider)
    .agent(Agent::new(&m))
    .build();
```

The claim this unlocks is worth stating precisely, and as a **conjunction**
rather than as a boast about what nobody else has — a negative about every
product in a field moving this fast is not a claim anyone can check. A
declarative agent here is content-addressed **in its entirety**, *and* every step
it takes is journaled, *and* the run replays deterministically.

Each half exists elsewhere; the pairing is the point. Declarative agent formats
(`agent.yaml`, CrewAI, ADK) give you the first — a reviewable, versioned file.
Durable-execution platforms give you the second and third, and as of Dapr 1.18
they sign and attest that history too. What is hard to assemble from either side
is a file that is *both* the whole definition of the agent and the thing whose
execution replays: a signed history of a program you cannot fully see is
evidence about a black box, and a reviewable file with no execution record is a
description of intentions.

Two refusals keep it honest. A manifest declaring `execution` with no capability
is refused — an agent nothing can call is a file that does nothing. And a
provider the manifest names but no driver is registered for is refused rather
than defaulted to whatever driver happens to be present, because falling back
would run the agent on a model its own declaration does not name, which is the
exact substitution this layer exists to prevent.

`kind` is an enum, deliberately short, and every variant is a behaviour that is
implemented and tested. A config format whose behaviours are open-ended is one
nobody can review, because the reviewer would have to know what the string does.
Three exist: `completion` (one model call, answered in the declared shape),
`tool-calling` (call tools until the model stops asking) and `planned` (plan
once over trusted input, then execute with step outputs routed by reference
rather than back through a model's context). A fourth would have to meet the
same standard rather than being a string that happens to parse.

### Oversight, declared without a predicate

The Article 14 half. It is declarable *because* the machinery already exists —
durable worklists, four-eyes, declared expiry — so it lands on the binding side
of the rule rather than the intent side:

```yaml
spec:
  execution: { kind: completion }
  oversight:
    approval: required
    approvers: [role:compliance-officer]
    deadline: klaerung          # resolved by your Calendar
    on_expiry: deny             # the default
```

The declarative agent then opens a task with the answer as the proposal — the
answer itself, not a description of it, because a reviewer who cannot see what
will happen is not reviewing — and returns only on approval. A refusal names who
refused and why, since "the agent failed" is not something an operator can act
on.

Four refusals:

* **`oversight` without `execution` is rejected.** A hand-written skill picks its
  own moment to ask, so there is nothing here for the runtime to apply. Allowing
  it would let a file claim a human is in the loop when no human ever is — the
  precise decoration the binding rule exists to prevent.
* **`on_expiry: proceed` needs `allow_unattended: true`.** The runtime already
  demands that; the file demands it too, so the decision is greppable in the
  document a reviewer reads rather than only in code they do not.
* **`on_expiry: escalate` needs `escalate_to`, and bounded audiences.** Widening
  the audience is escalation's one enforceable meaning — the declared roles join
  the reviewers, the stale claim is cleared — so the declaration must say who is
  added, and an empty audience is refused because it already means *anyone*,
  which no list can widen.
* **An unstated `on_expiry` denies.** The safe direction is the one nobody has to
  remember to choose.

**What you will not find is a condition.** "Require approval when severity is
high" is a predicate, and a predicate is one step from an `if` — the point where
config stops being config. An agent whose oversight depends on what it found is a
skill, written in a language built for decisions. This is the field flagged in
advance as most likely to break that line.

### What a manifest is worth: it binds

A field read by convention is two independent copies of one decision. The
reviewer approves `model: haiku`, the code calls opus, and nothing anywhere
disagrees — worse than useless, because it manufactures confidence. So the rule
is: **a field either has an enforcement point, or it is marked as intent.**

What enforces today, before dispatch:

| Field | Refused when | Reported as |
|---|---|---|
| `spec.models` | a completion names an undeclared provider/model | `effect:declared`, journaled |
| `spec.tools` | a call names an ungranted `tool://server/tool` | `effect:declared`, journaled |
| `spec.budgets` | the ledger reaches a ceiling | `Exhausted` |
| `spec.capabilities.provides` | no registered skill provides it | `BuildError`, before the first run |
| `security.max_sensitivity_egress` | a labeled value exceeds the stricter of manifest and sink ceilings | `EgressCeiling` |
| `security.max_delegation_depth` | the configured identity or a handoff chain exceeds the reviewed ceiling | build refusal or `DelegationDepth` |

Build-time refusals are the same set through either entry point. `build()`
panics with the diagnosis, which is right for a binary wiring its own skills —
every one of them is a bug in code the author is looking at. `try_build()`
returns the refusal as a typed `BuildError` instead, for a plane assembled from
a manifest that arrived at *runtime*: resolved from a registry, read from disk,
or supplied per tenant. There a bad declaration is an input rather than a bug,
and a panic would report one tenant's typo by taking every other tenant's
in-flight run down with it. One implementation underneath both, so they cannot
come to disagree about what is refused.

The refusal carries a **distinct action** from a Cedar denial, because the two
accuse different parties: a policy denial is the deployment's rules saying no to
something the agent was built to do; a manifest refusal is the agent doing
something its own reviewed declaration never mentioned, which is a defect in the
code rather than a tightening of the rules.

There are no review-only security fields, and no architectural injection-pattern
label: arbitrary native skill code cannot be proven to follow one, and such a
label would manufacture confidence. `spec.output.schema` is carried to the
provider, into the effect key, and is checked against the value that comes back
— a parseable but non-conforming answer is a metered unusable result, not data
that reaches downstream code.

### The prompt is part of the declaration

`spec.identity` is the field that makes the digest worth having. A system prompt
composed in the embedder's Rust has **no version**: it changes in a deploy, the
journal faithfully records every run it affected, and nothing connects the two.
Inside the manifest it is covered by the digest, so a reworded instruction is a
version bump — a diff with a reviewer on it, and something a consumer can pin.

`Identity::system_prompt` renders it with the dullest template that could work:
the role, a blank line, the constraints. Anything cleverer would be agentplane
putting words in an agent's mouth that no reviewer of the manifest ever saw. Its
exact layout is pinned by a test, because changing it would alter every
embedder's prompt without changing a single manifest or moving a single digest —
the one edit in this crate that could silently change model behaviour everywhere.

The field is optional. An embedder composing its prompt in code is a legitimate
choice, and requiring the field would mostly produce manifests with a
placeholder in it. A *declared* identity with a blank role is refused, though:
that is a digest covering a prompt that says nothing, under a field that looks
answered.

### What this agent is in a multi-agent arrangement

MAST measures **inter-agent misalignment at 36.9 % of observed multi-agent
failures** — the one large failure class that exists only because somebody chose
an arrangement. So the arrangement is declared rather than emergent.

`mode` is *how many agents and why*; `role` is *what this one is*. They are
separate because one shape supports several roles, and each agent has its own
manifest:

| `mode` | shape | inter-agent failure surface |
|---|---|---|
| `single` *(default)* | one agent, one context, many tools | structurally absent |
| `collaborative` | several agents contribute to one task | the full surface |

| `role` | may delegate | |
|---|---|---|
| `specialist` *(default)* | **no** | does one thing, hands off to nobody |
| `orchestrator` | yes | decomposes, delegates, assembles |

**Routing is not collaboration.** Picking one specialist out of twenty-nine by
event type is a deployment dispatch table. Because the runtime does not perform
that choice, `routed` and `router` are not accepted manifest values: declarations
must govern behavior, not describe behavior implemented somewhere else.

Three combinations are refused, because the fields are individually fine and it
is the combination that describes nothing:

* **`specialist` with `max_delegation_depth` above zero.** The consistently
  reported top failure mode of handoff architectures is the infinite loop — A
  hands to B, B to C, C back to A. The structural answer is that most agents in
  an arrangement have no authority to hand off at all, and a specialist that may
  delegate is an orchestrator nobody reviewed as one. The role itself imposes
  zero at dispatch when the numeric field is omitted.
* **`single` with a coordinating role.** There is nobody to orchestrate or route
  to.
* **`collaborative` with no `reason`, or a `reason` without `collaborative`.**
  Collaboration costs roughly an order of magnitude more tokens and opens the
  whole failure surface, so why it is warranted belongs in the file. The
  justifications are enumerated rather than free text so each is checkable in
  principle: `parallel-disjoint` (overlapping inputs are *false parallelism* —
  paying the coordination cost and gaining nothing) and `distinct-authority`.
  There is deliberately no `context-overflow`: whether work exceeds a context
  window is not a property of the graph, so the contract could not check it —
  and an unchecked justification is not a weak control but an escape hatch,
  since a plan refused as false parallelism was approved by editing one word.

`distinct-authority` deserves emphasis because neither side of the public
multi-agent debate raises it: **the best reason to split agents is often
security, not capability.** If a sub-task needs credentials the parent should not
hold, delegating to a narrower agent is least privilege, and the coordination
cost buys a real security property rather than hypothetical speed.

### A model id is a behaviour change, so it is versioned like one

Swapping a model alters what an agent does more than most code edits, and a swap
made in a deploy has no version, no diff, and nothing connecting it to the runs
whose outputs changed. `spec.models` puts the provider and model in the digest.

The role names remain part of the allowlist and digest: a hand-written skill can
route untrusted material to a separately declared quarantined model. The
manifest does not claim that this architecture occurred. That would require
proving the conduct of arbitrary native code, so there is no `security.pattern`
label rather than a review-only one.

`models: {}` declares **no inference at all** — a rules-only agent is a
legitimate design, and saying so out loud distinguishes it from one whose model
wiring somebody forgot. Absent `models` is not refused, unlike an absent budget:
an unstated budget is unbounded spend, an unstated model is a wiring decision.
Refuse the silence that costs money, not the silence that costs nothing.

### The result shape is a contract with a version

`capabilities.provides` names a capability; `spec.output.schema` says what comes
back. Narrowing a field is a breaking change to every consumer, so it belongs in
the digest rather than in a deploy.

Enforcement starts at the provider, during generation, where constrained
decoding prevents a malformed answer before tokens are emitted rather than
rejecting one already paid for. The crate then validates the parsed value
locally against the same schema as defense in depth — the decision
`Completion::structured` documents — so a provider bug or a forced-tool
best-effort answer surfaces as a loud, metered unusable result instead of
malformed data reaching downstream code, and the declarative runtime checks the
final answer once more before it settles, because what settles is that exact
value. External schema references are never resolved: validation performs no
hidden file or network I/O.

The schema also shapes replay. Handed to `ModelCall::expecting`, it goes
into the **effect key** — so editing it makes a replay report divergence instead
of quietly reinterpreting last year's stored answer under today's rules.

`schema: {}` is refused. It is a *valid* JSON Schema meaning "anything", so it
parses, looks answered in review, and promises nothing; an agent with no
machine-readable result omits `output` entirely.

### Unknown fields are refused, never ignored

The single most dangerous property a config format can have is tolerance. In a
permissive parser `max_tokns: 100` does not mean "a token ceiling of 100 with a
typo" — it means **no token ceiling at all**, silently, in the one document
whose purpose was to make the ceiling reviewable. Every struct in the manifest
is `deny_unknown_fields`, so that is a parse error instead.

The same reasoning drives two smaller refusals:

* **The document says what it is.** A foreign `apiVersion` or `kind` is refused
  rather than best-effort parsed, because a format that guesses is a format
  whose meaning changes under you.
* **Unbounded is a decision, so it has to be stated.** A manifest with no
  `budgets` section is refused. Writing `budgets: {}` means it on purpose, and
  that is a line a reviewer can object to.

`ToolGrant.mutates` defaults to **true** for the matching reason: a tool nobody
thought about should get the treatment that makes the runtime cautious, not the
one that makes it fast.

### What a manifest does and does not do

`RuntimeBuilder::agent` binds the document to one agent on the plane: it applies
that agent's budget, carries the declaration into every step it governs, and
registers the behaviour when `spec.execution` is declared. Several agents may be
registered on one plane, each governed by its own manifest. Models and tools are
enforced at dispatch, as the table above says.

The egress ceiling and delegation depth bind at the sink boundary. Each is
combined with the sink's own limit and the stricter value wins. A configured
identity already deeper than the manifest permits is refused at build; a peer
handoff that would cross the ceiling is refused before dispatch.

Because a plane holds several agents, two of them can collide — and a collision
is not merely shadowing. Dispatch resolves a capability to one skill *and to the
manifest governing it*, so a silent overwrite would move work an agent still
advertises out from under that agent's budget, model grants and egress ceiling,
with nothing in the journal to show it. `build` therefore refuses two agents
claiming one capability, and two skills sharing one name. Both are wiring
mistakes with no recovery, so both are refused at startup rather than discovered
at dispatch.

The manifest does **not** describe an injection architecture. There is no
pattern field, because arbitrary native skill code cannot be proven to follow
one, and a security label without an enforcement point is worse than no label.

It also does not set the lease **owner**. That identifies a process, and several
instances of one agent are normal — see [operations](@/docs/operations.md).

### A version is an artifact, not a moment

A manifest has a content digest over [canonical bytes](@/docs/architecture.md#canonical-bytes), so two
files that declare the same thing share a digest and a file that declares
something different cannot.

That digest is what makes "which declaration governed this run" answerable after
the file has moved on — but only because the run **records it**. `RunAdmitted`
carries `governed_by`: the agent's name, its version, and the digest of the
manifest that governed it. Name and version say what to look for; only the digest
says what it actually said, including the system prompt, which is inside it. A
run served by a skill registered directly on the plane records `None`, which is a
different answer from "governed by something nobody wrote down".

The record names the capability separately, in a field called `capability`.
Naming it `agent` would read as an identity and not be one — the stringly-typed
mistake, in the one record where *who did this* is the question being asked.

The registry is built around three no-rewrite guarantees, and they are not
redundant:

| | catches | at | trusting |
|---|---|---|---|
| **Immutability** | a version republished with different content | write time | the registry |
| **A pin** | a resolve that returns content the caller never reviewed | read time | nothing |
| **Publisher immutability** | identical bytes attributed to a different signer | write time | the registry |

Immutability is what makes "we reviewed 2.0.0" a statement about an artifact
rather than about a Tuesday — the property Go's module proxy and crates.io both
arrived at, and the one whose absence produced the npm and PyPI incidents.
Re-publishing *identical* content still succeeds, because a retried deploy is
not an attack and treating it as one teaches people to force.

A pin is the caller declining to need that promise. It is the only one of the
two that survives the registry itself being the compromised party, which is why
`resolve_pinned` exists beside `resolve` rather than as a flag on it: the safe
call should be the one you can see at the call site.

`publish_signed` supplies the half a digest cannot: *who* approved the artifact.
The signature covers a domain-separated manifest hash, so it cannot be replayed
as a journal-record attestation. An identical unsigned artifact may adopt its
first attestation later without changing its digest; once publisher evidence
exists, another signer is refused rather than silently replacing it. Supporting
several publishers requires an explicit attestation set and is not built.

`MemoryRegistry` is process-local. The trait leaves room for a durable or remote
registry, but none ships today. Key creation, rotation, revocation, and the
decision to trust the identity returned by `resolve_verified` remain deployment
responsibilities.
