+++
title = "Status"
description = "What is pre-alpha in agentplane, which surfaces to pin, what is deliberately not built, the format-freeze conditions, and how to check any of it yourself."
weight = 19

[extra]
group = "Operate"
+++

> **Evaluating this against a control catalogue?** The questions evaluators
> actually ask — and keep re-asking, because the answers are spread across
> pages — are collected in one table:
> [answers evaluators have had to ask for](@/docs/regulation.md#evaluator-questions).
> It sits on the regulation page and is not a statutory table; start there and
> follow the links.

`agentplane` is published on crates.io and pre-alpha. This page answers three questions an
adopter has to answer before writing any code: **what will move**, **what is
deliberately absent**, and **how to check that either answer is still true**.

It deliberately does **not** list what has been built. A row saying *X does Z,
and here is why* is a change wearing a status's clothes, which is the
[changelog](https://github.com/hupe1980/agentplane/blob/main/CHANGELOG.md)'s job
— and keeping one fact in two places is the defect this project treats most
seriously everywhere else. The reasoning behind a mechanism lives at the
mechanism, in the module's own documentation, where it sits next to the code it
describes and cannot rot unnoticed. What exists is answered by
[concepts](@/docs/concepts.md), the [API reference](https://docs.rs/agentplane),
and the test suite.

## 📌 What to pin, and what will move {#what-to-pin-and-what-will-move}

Pre-alpha means every one of these can change. It does not mean they are all
equally likely to, and an adopter deciding what to build against deserves the
difference rather than one blanket warning.

Nothing here is a compatibility promise. It is a statement about where the
remaining design pressure is — grouped by
[what the freeze will be a promise about](#what-the-freeze-promises), so the two
readings of this table do not have to be held apart by hand.

| Surface | Expect | Why |
|---|---|---|
| *What the freeze will cover* | | |
| **Effect / disposition / recovery vocabulary** | stable | `DidNotHappen`/`InDoubt`/`Landed` and the recovery classes are the load-bearing idea; changing them would be a different system |
| **Journal record format** | **will change** | not frozen. Upcasters exist, but a format-freeze milestone has not happened and hard cuts are preferred until it does — see the freeze conditions below for what has to land first, and for the export-as-the-durable-artifact position in the meantime |
| *Additive either way — a new field or variant, never a removed one* | | |
| **Manifest schema** | additive, with hard cuts | `deny_unknown_fields` makes an added field safe and a *removed* one a hard failure. The published [JSON Schema](/agentplane/agent.schema.json) is generated from the parser's types and moves with them |
| **Error enums** | additive; `#[non_exhaustive]` | they gain variants as the runtime learns to say more — a rate limit is its own variant rather than a generic rejection, and the next distinction will be too. Match with a `_` arm |
| **`RetryPolicy` fields** | additive | it is a plain struct, so a literal breaks when a field lands. Build with `RetryPolicy::attempts(n)` and the builder methods, or spread `..RetryPolicy::default()` |
| **Policy seam (`PolicyEngine`, request context)** | stable seam, growing context | the trait is settled; `context` gains attributes as the runtime learns to say more. Guard optional ones with `has` → [security](@/docs/security.md#the-authorization-context) |
| **Store traits** | stable seam, growing contract | the conformance battery is the contract; it gains cases faster than the traits gain methods |
| **`testkit`** | stable, additive | it is how embedders test their own stores and skills, so churn here costs more than it saves |
| *Outside the promise — pin an exact version* | | |
| **`Skill`, `StepCtx` core methods** | stable in shape, additive | new capabilities arrive as new methods; existing ones are not expected to change signature |
| **`Runtime` admission methods** | settled | every door takes `Tainted<Value>` — wrap an operator's own literal in `Tainted::trusted(..)`. `run_in_case` means *this exact case*; correlating is `run_correlated` |
| **`Tool` / `ToolFailure`** | settled | `Tool::call` returns `ToolFailure`, named by disposition rather than transport; references are `tool://server/name` |
| **Effect keys** | **will change** | any change to a descriptor's arguments moves every key for that effect kind. A reference names a server and a tool, never a transport, so the key does not move when the transport does |
| **Store schemas — SQL, redb, and what a blob store writes** | **will change without migration** | there is no migration tooling: recreate rather than migrate. Widening a redb table fails at open rather than at read, and a tombstone carries a version a later build refuses rather than guesses at |
| **A2A / MCP wire behaviour** | tracks the specs | exact released revisions, not a compatibility range: a revision this crate has not been held to is one it does not claim, and the serving and calling roles differ → [which revisions this plane speaks](@/docs/interop.md#protocol-revisions) |

## 🧊 Format freeze: the conditions, and where they stand {#format-freeze}

The single question that decides whether this can be recommended for anything
regulated, asked directly enough to deserve a direct answer: **the strongest
control here — a tamper-evident, offline-verifiable audit trail — cannot be
signed off as a long-term record while its format may break with no migration
path.** Every other gap an adopter finds is closable with integration work.
This one is not.

There is no date, and inventing one would be the kind of claim this page exists
to avoid. What there is instead is a condition list, each row naming what it
demanded and where the evidence is — so *met* is something you can check rather
than something this page asserts.

**Every condition below is met, and the freeze has not happened. Those are two
different statements and this page owes you both.** The conditions were the
*readiness* question and they are answered. What remains is a deliberate act —
the point at which hard cuts stop being available and a shape change becomes an
upcaster plus a version bump — held at the maintainer's discretion, with no
target release. So this list says the obstacles are gone, not that the promise
is imminent.

| # | Condition | Where the evidence is |
|---|---|---|
| 1 | **Canonicalization is versioned and vector-checked** — a rule change must read as *unverifiable*, never as a divergence | RFC 8785 held to the standard's own number vectors → [canonical JSON](@/docs/format.md#canonical-json) |
| 2 | **Golden corpora for the journal record format** — a fixed set of records every future build must still read and still hash identically | `tests/golden/records.jsonl`, with a guard holding the corpus to the record vocabulary |
| 3 | **Golden vectors for the export format** — the artifact a third party verifies without this crate | `tools/verify_export.py`, re-deriving all 30 record vectors from the [specification](@/docs/format.md#vectors) alone |
| 4 | **A stated unknown-field policy per durable format** | per format, not once — a record body, a sealed header and an export's framing each say what they refuse → [format](@/docs/format.md#not-promised) |
| 5 | **Upcasters exercised end-to-end**, not only unit-tested | consulted on every record read; a test lifts a record this build cannot parse → [versioning](@/docs/format.md#versioning) |
| 6 | **A migration and rollback procedure**, written down and rehearsed | rehearsed across two released builds → [operations](@/docs/operations.md) |
| 7 | **An algorithm-agility plan** — how SHA-256 is replaced without invalidating history | [written down](@/docs/format.md#algorithm-agility): hashes agile by version, signatures by key, and nothing rehashes stored bytes |
| 8 | **The deferred format questions are settled** | the set is empty |
| 9 | **The surface the promise attaches to is named** | the artifacts, not either doorway — [below](#what-the-freeze-promises) |

### What the freeze is a promise about {#what-the-freeze-promises}

Both surfaces exist and are published — a crate an embedder links, and a server
an operator runs against a manifest with no Rust anywhere — and they carry the
[same guarantees](@/docs/concepts.md). So the promise does not attach to either
doorway. It attaches to what the guarantees are *made of*:

| | Under the freeze | Terms |
|---|---|---|
| **The journal record format** | yes | a shape changes by upcaster and a version bump, never by a hard cut |
| **The export format** | yes | the artifact a third party verifies, against a published specification a second implementation already reads |
| **The operator verbs and their vocabulary** | yes | an outcome, a disposition, a recovery class and a run status keep their spelling; a verb gains arguments and does not lose them |
| **The manifest schema** | additive | an added field is safe by construction, a removed one is a hard failure |
| **The Rust API** — `Skill`, `StepCtx`, `Runtime`, the store traits | **no** | pre-alpha and additive in intent, pinned by an exact version in practice |
| **Store schemas** | **no**, deliberately | the journal is the record and a store is an index derived from it; a store is rebuilt from an export rather than migrated |

**What an adopter depends on is the evidence, and both doorways produce the
same evidence.** Linking the crate gets the same promise about everything it
stores and exports, and takes the ordinary pre-alpha risk on the signatures it
compiles against — the half a `cargo update` reports and a rebuild settles,
rather than the half that strands a history.

**Until the freeze, the honest position for an adopter is:** treat the export as the
long-term artifact and the store as disposable. `agentplane export` produces
framed JSON Lines with a checkpoint, `agentplane verify` recomputes it from its
own bytes, and `agentplane restore` rebuilds a store from it — three verbs that
already work, and the reason a format change is a rebuild rather than a loss.
That is a real answer, not a promise: an export taken today is verifiable today
by a party who has never run this crate.

## 🚫 Deliberately not built {#deliberately-not-built}

Two kinds, and conflating them is what makes a gap list useless. **Refused** will
not arrive: something in the design forecloses it, and the entry says what.
**Deferred** names what it is waiting on, so a reader can tell whether their own
need would move it.

Nothing here is an oversight. What is genuinely unexamined does not appear on
this page, because a page cannot list what nobody has thought of.

### Refused

**Cross-run mutual exclusion over a declared resource.** An effect group enforces
its footprint *within* a run. Two runs grouping over the same resource are
ordered by the resources themselves, not by the plane.

**Speaking ACS as an observed agent** — asking an external Guardian to permit
each step. ACS-Core's failure posture defaults to *proceed*, for a hook that
times out and for a handshake that never completes, and the specification states
the consequence itself: an adversary who can disrupt the channel converts control
into audit. The gate here is inside effect dispatch, so no partition opens a path
to a sink — and a verdict fetched over the network could not be replayed anyway,
since a recorded decision is re-read on a resume rather than re-asked.

**[ACP](https://agentclientprotocol.com/) as a control plane.** Its client
answers a permission request by selecting an `optionId` from a list the *agent*
supplied, so the vocabulary a reviewer may answer in is written by the party
being reviewed. There is no amendment and no deferral; a pending request dies
with the client process, so an approval cannot reach somebody who is not at the
keyboard; and a tool call carries `rawInput` as arbitrary JSON, which gives a
field-level gate nothing to bind to. The filesystem and terminal a client offers
are a convenience for reading unsaved buffers, not a sandbox — the agent is a
subprocess holding the client's own access.

Recording what such a session did is a different question and the answer is
yes — see [keeping a record beside an agent you do not
run](@/docs/interop.md#observing-an-agent-you-do-not-run).

**Per-capability aggregates as a plane query** — run count, effect count,
outbound bytes, denials and outcome mix for a capability over a window. The
figures are already yours in a stronger form: an export carries **every** record,
so each effect's `outbound_bytes` joins to its run's `capability`, and that is a
distribution rather than a summary. *Forty times the median for its capability*
needs the distribution; a fixed vector of totals can only give you a mean, so the
query would not answer the question that motivates it. Load an export into
whatever you already run and you get medians, percentiles and any window you
like.

The two queries that look like precedent are not. `count_by_outcome` and
`waiting_runs` each answer an operator verb — a worklist to clear, runs to
re-arm — and exist because [a finding must reach whoever must act on
it](@/docs/concepts.md). A baseline names nothing anybody does next; it is input
to a detector a deployment builds, and the deployment is where it belongs. What
would change this: a figure an operator acts on *in the plane* that an export
cannot supply, which is a different request from this one.

**The operator verbs on the MCP tool list.** Every operator route already
carries its own `api:` capability over HTTP, so an external agent can drive the
plane today; projecting those verbs onto a tool list would add discovery, not
permission. What rules it out is narrower: the operator surface's rule is that
who is acting comes from the request's identity, never from its body — and a
tool call is arguments. A naive projection puts an actor there and retires
four-eyes in one translation.

**A rate-limit wait the runtime takes by suspending.** A peer's `Retry-After` is
honoured and bounded by `RetryPolicy::max_advice` (60 s), which is also the bound
on how long one effect holds a worker. Suspending *inside* the retry loop is
refused on replay grounds: a replayed failure is rebuilt from the recorded
message, so a window handed to a skill as a typed value would be a branch input
live and absent on the way back. A long wait is a skill's to take — catch the
terminal failure and call `cx.sleep()` with a **declared** window, an ordinary
journaled effect the cursor consumes in position. The advice still reaches the
record: the failure message names the window the peer asked for.

**A curated event type between the journal and the wire.** The durable,
resumable output stream it would provide already exists: `Runtime::journal()`
plus `JournalStore::read(run, from)` is a seq-cursored, reconnect-safe read any
instance can serve, and the A2A server is an embedder of it. A third vocabulary
between the records and the wire would drift from both. Live in-process deltas
stay advisory (`ModelCall::streaming_to`): none is journaled and strict replay
emits none, because a durable delta stream is a second truth beside the one
terminal `Completion`.

### Deferred

**Symbolic policy analysis.** Cedar can *prove* a policy set cannot widen access
rather than test it — the check that catches Cedar's totality, where a `when`
clause reading an absent attribute makes a rule vanish instead of erroring. The
prover and its solver are released and work. *Waiting on:* a schema. A universal
one is not expressible — `context.args` is caller data of arbitrary shape and
Cedar records are closed — and a per-deployment one needs a vocabulary decision
first, since `effect:perform` spans every effect kind.

**Serving [ACS](https://github.com/GenAI-Security-Project/agent-control-standard)
as a Guardian** — so agents this runtime does not execute can be governed by a
plane that journals the decision. The mapping is close to complete: Cedar is the
deterministic layer, the sink gate is allow/deny, an amendment is `MODIFY`, an
approval task is `ASK`, a suspension is `DEFER`, and the audit chain is already
`SHA-256` over RFC 8785 canonical JSON — ACS's own construction with the fields
in the other order. *Waiting on:* the wire. Where such a session goes is settled
(below).

**A measured containment claim.** The runtime claims injection *containment*, not
immunity, and no external measurement is attached to it. A static attack set
would manufacture exactly the confidence this project refuses. *Waiting on:* one
adaptive, defence-aware evaluation, over A2A, graded from the journal — the
methodology exists in published form
([2606.26479](https://arxiv.org/abs/2606.26479)).

Two things will be published as part of that number rather than under it,
because each moves it more than the attack set does: **the policy bundle it ran
under**, since a deterministic gate has no attack-success rate and a deployment
does, and **how open the tasks were**, since an adaptive attacker does far
better against a task that leaves the agent latitude about what to do
([2606.15057](https://arxiv.org/abs/2606.15057)). A containment figure quoted
without both is a figure about somebody's configuration.

## 🔍 How to check any of this {#how-to-check-any-of-this}

Nothing on this page is a promise; all of it is checkable.

```sh
just anchors    # every mutation still anchors in the code it names
just features   # every optional feature compiles on its own
just audit      # no dependency in the tree has a known advisory
just ci         # lint, feature configurations, examples, docs, packaging
just ci-full    # the above, plus TLA+ specs and the full mutation sweep

just test-a2a-tck   # the protocol project's own conformance kit, on a live socket
just test-postgres  # the shared-store backend against a real server
just test-vault     # the key-ring contract against a real Vault
just test-live      # the model and embedding drivers against real APIs (costs money)

python3 tools/mutants.py <name> --verify   # one guarantee, end to end
MUTANTS_SHARD=2/10 just mutants          # one slice, for a machine that is not alone
```

The mutation sweep is the one that matters most: it breaks each guarantee on
purpose and requires the test *written for it* to fail. That is why this page
asserts no inventory of guarantees — an inventory is a claim a reader has to
trust, and a sweep is one they can run. What the sweep reports, and why
`just anchors` is not a substitute for running it, is on
[assurance](@/docs/assurance.md).
