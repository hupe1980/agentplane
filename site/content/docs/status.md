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
> It is on the regulation page for historical reasons and is not a statutory
> table; start there and follow the links.

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
remaining design pressure is.

| Surface | Expect | Why |
|---|---|---|
| **Effect / disposition / recovery vocabulary** | stable | `DidNotHappen`/`InDoubt`/`Landed` and the recovery classes are the load-bearing idea; changing them would be a different system |
| **`Skill`, `StepCtx` core methods** | stable in shape, additive | new capabilities arrive as new methods; existing ones are not expected to change signature |
| **`Runtime` admission methods** | settled | every door takes `Tainted<Value>` — wrap an operator's own literal in `Tainted::trusted(..)`. `run_in_case` means *this exact case*; correlating is `run_correlated` |
| **Journal record format** | **will change** | not frozen. Upcasters exist, but a format-freeze milestone has not happened and hard cuts are preferred until it does — see the freeze conditions below for what has to land first, and for the export-as-the-durable-artifact position in the meantime |
| **Effect keys** | **will change** | any change to a descriptor's arguments moves every key for that effect kind. A reference names a server and a tool, never a transport, so the key does not move when the transport does |
| **Manifest schema** | additive, with hard cuts | `deny_unknown_fields` makes an added field safe and a *removed* one a hard failure. The published [JSON Schema](/agentplane/agent.schema.json) is generated from the parser's types and moves with them |
| **`Tool` / `ToolFailure`** | settled | `Tool::call` returns `ToolFailure`, named by disposition rather than transport; references are `tool://server/name` |
| **Error enums** | additive; `#[non_exhaustive]` | they gain variants as the runtime learns to say more — a rate limit is its own variant rather than a generic rejection, and the next distinction will be too. Match with a `_` arm |
| **`RetryPolicy` fields** | additive | it is a plain struct, so a literal breaks when a field lands. Build with `RetryPolicy::attempts(n)` and the builder methods, or spread `..RetryPolicy::default()` |
| **Policy seam (`PolicyEngine`, request context)** | stable seam, growing context | the trait is settled; `context` gains attributes as the runtime learns to say more. Guard optional ones with `has` → [security](@/docs/security.md#the-authorization-context) |
| **Store traits** | stable seam, growing contract | the conformance battery is the contract; it gains cases faster than the traits gain methods |
| **Store schemas — SQL, redb, and what a blob store writes** | **will change without migration** | there is no migration tooling: recreate rather than migrate. Widening a redb table fails at open rather than at read, and a tombstone carries a version a later build refuses rather than guesses at |
| **A2A / MCP wire behaviour** | tracks the specs | exact released revisions, not a compatibility range: a revision this crate has not been held to is one it does not claim, and the serving and calling roles differ → [which revisions this plane speaks](@/docs/interop.md#protocol-revisions) |
| **`testkit`** | stable, additive | it is how embedders test their own stores and skills, so churn here costs more than it saves |

## 🧊 Format freeze: the conditions, and where they stand {#format-freeze}

The single question that decides whether this can be recommended for anything
regulated, asked directly enough to deserve a direct answer: **the strongest
control here — a tamper-evident, offline-verifiable audit trail — cannot be
signed off as a long-term record while its format may break with no migration
path.** Every other gap an adopter finds is closable with integration work.
This one is not.

There is no date, and inventing one would be the kind of claim this page exists
to avoid. What there is instead is a **condition list**: freeze happens when
every row below is met, and each row is checkable rather than a matter of
judgement. An adopter tracking this page can see how far along it is without
asking.

✅ met · 🟨 half, and the remaining half is named · ⬜ open. A half is a row
whose *mechanics* are built and whose remaining work is a document or an
exercise — stated as its own state rather than rounded to either neighbour,
because rounding up is how a condition list stops being checkable.

| # | Condition | State |
|---|---|---|
| 1 | **Canonicalization is versioned and vector-checked.** A rule change must read as *unverifiable* rather than as a divergence | ✅ done — versioned at the run, a complete RFC 8785 implementation held to the standard's own number vectors |
| 2 | **Golden corpora for the journal record format.** A fixed set of records, byte-for-byte, that every future build must still read and still hash identically | ✅ done — one canonical record per kind and its chain digest in `tests/golden/records.jsonl`, sealed through the same function every backend appends through, with a guard holding the corpus to the record vocabulary so a new kind cannot ship unpinned |
| 3 | **Golden vectors for the export format** — the artifact a third party verifies without this crate | ✅ done — a sealed export with its case layer is checked in, and `tools/verify_export.py` verifies it from the [published specification](@/docs/format.md) alone, re-deriving all 29 record vectors rather than only accepting them |
| 4 | **A stated unknown-field policy per durable format.** | ✅ done, and strict in both directions — a record is *evidence*, so a reader that drops a field reaches a verdict over evidence it did not see. Refusals are classified as build skew rather than damage, with the deployment order they imply written down beside them |
| 5 | **Upcasters exercised end-to-end, not only unit-tested.** | ✅ done — consulted on *every* record read, with a test lifting a record whose shape this build cannot parse and asserting the chain still commits to the bytes as written. A corpus of genuinely old records arrives with the first post-freeze bump |
| 6 | **A migration and rollback procedure**, written down and rehearsed | 🟨 half — written down (readers before writers; rollback bounded by a *time window*), and the reader's half is pinned: a record from a shape this build does not know is refused as skew, not damage. What is left is the two-build exercise, which needs a version bump to have two builds to run |
| 7 | **An algorithm-agility plan** for every durable or signed format: how SHA-256 is replaced without invalidating history | ✅ done — [written down](@/docs/format.md#algorithm-agility) and already implemented: hashes are agile by version, signatures by key, [digest domains](@/docs/format.md#digest-domains) carry their own, and nothing rehashes stored bytes, so history stays verifiable under the algorithm that wrote it |
| 8 | **The deferred format questions are settled**, each of which moved a record or a wire | ✅ done — the set is empty. The one that could still have added a record was whether a context branch belongs in the runtime at the loop tier, and the answer is a refusal: a branch lowers no label, so it adds no record and relieves none of the pressure it was aimed at |
| 9 | **The surface the promise attaches to is named** — whether the freeze commits a library API, an operator service, or both | ⬜ open — see below |

**Condition 9 is a sentence, not a build.** Both surfaces exist and are
published: a crate an embedder links, and a server an operator runs against a
manifest with no Rust anywhere. What is unwritten is which one an adopter is
expected to depend on, and therefore what the freeze is a promise *about*. It is
a row rather than a footnote because a compatibility commitment with no stated
subject is one an adopter completes in their own favour.

**What is left is an exercise and a sentence**, which is a different kind of
waiting from the rest of this table: neither is a design question, and neither
can still change a record shape.

Two things follow that are worth stating plainly.

**Freezing the journal does not freeze everything.** Store schemas are a
separate promise, and a weaker one on purpose: the journal is the record, the
stores are indexes derived from it. A store rebuilt from an export is not a
migration and does not need one, which is why `export`/`restore` are built and
`ALTER TABLE` is not.

**Until then, the honest position for an adopter is:** treat the export as the
long-term artifact and the store as disposable. `agentplane export` produces
framed JSON Lines with a checkpoint, `agentplane verify` recomputes it from its
own bytes, and `agentplane restore` rebuilds a store from it — three verbs that
already work, and the reason a format change is a rebuild rather than a loss.
That is a real answer, not a promise: an export taken today is verifiable today
by a party who has never run this crate.

## ⬜ Deliberately not built {#deliberately-not-built}

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

**ACP as a record** — journaling what an agent this runtime does not execute was
asked, and what a person allowed. A session update is the agent's own report,
while a journal record means *this runtime announced the effect, dispatched it
under authority and recorded the outcome*; writing a report into that vocabulary
would make every answer the journal gives about authorization false. So an
observed session is a **run of its own** in the one journal — sharing the
canonical form, the Merkle log and the witness, sharing no record kind with a
dispatched effect, and reported as unadmitted by an `audit`. That is the shape
the sweeper's own runs already take: one history, one root, one audit.
*Waiting on:* the wire, for either protocol.

**A measured containment claim.** The runtime claims injection *containment*, not
immunity, and no external measurement is attached to it. A static attack set
would manufacture exactly the confidence this project refuses. *Waiting on:* one
adaptive, defence-aware evaluation, over A2A, graded from the journal — the
methodology exists in published form
([2606.26479](https://arxiv.org/abs/2606.26479)).

**The rest of format freeze.** The mechanics are built and the
[record format](@/docs/format.md) is specified, with a second implementation
deriving the same bytes from that specification alone. *Waiting on:* the open
rows in [Format freeze](#format-freeze) above.

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
purpose and requires the test *written for it* to fail. A capability that could
be deleted without a test noticing is caught by that sweep, not by review — which
is why this page asserts no inventory of them. An inventory is a claim a
reader has to trust; a sweep is one they can run.

`--verify` is the same check for a single guarantee, and it exists because the
cheap one is not enough. `just anchors` proves a mutation still *matches* the
code; only running it proves the mutation still *kills*. A test rewritten around
a mutation passes quietly, and a guarantee that stopped being checked looks
exactly like one that is. The command distinguishes **survived** from **never
ran**, because a run that compiled nothing reports zero failures and reads like
success.
