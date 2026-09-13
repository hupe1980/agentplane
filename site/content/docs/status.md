+++
title = "Status"
description = "What is pre-alpha in agentplane, which surfaces to pin, what is deliberately not built, the format-freeze conditions, and how to check any of it yourself."
weight = 19

[extra]
group = "Operate"
+++

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
| **Manifest schema** | additive, with hard cuts | `deny_unknown_fields` means an added field is safe and a *removed* one is a hard failure. A field the runtime cannot enforce is removed rather than kept as a declaration nothing honours. The published [JSON Schema](/agentplane/agent.schema.json) is generated from the parser's types and moves with them |
| **`Tool` / `ToolFailure`** | settled | `Tool::call` returns `ToolFailure`, named by disposition rather than transport; references are `tool://server/name` |
| **Error enums** | additive; `#[non_exhaustive]` | they gain variants as the runtime learns to say more — a rate limit is its own variant rather than a generic rejection, and the next distinction will be too. Match with a `_` arm |
| **`RetryPolicy` fields** | additive | it is a plain struct, so a literal breaks when a field lands. Build with `RetryPolicy::attempts(n)` and the builder methods, or spread `..RetryPolicy::default()` |
| **Policy seam (`PolicyEngine`, request context)** | stable seam, growing context | the trait is settled. `context` gains attributes as the runtime learns to say more; a `forbid` reading one that does not exist is an evaluation error, and the Cedar adapter **denies an `Allow` that arrives with evaluation errors** rather than letting a broken rule disappear — see [security](@/docs/security.md#the-authorization-context) |
| **Store traits** | stable seam, growing contract | the conformance battery is the contract; it gains cases faster than the traits gain methods |
| **Store schemas — SQL, redb, and what a blob store writes** | **will change without migration** | pre-alpha, and there is no migration tooling. Recreate rather than migrate. All three deliberately: a redb `TableDefinition` pins its value types, so widening one fails at open rather than at read, and an object store's tombstones carry a version a later build refuses rather than guesses at |
| **A2A / MCP wire behaviour** | tracks the specs | exact released versions, not a compatibility range: a version this crate has not been held to is one it does not claim |
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
| 3 | **Golden vectors for the export format** — the artifact a third party verifies without this crate | ✅ done — a sealed export with its case layer is checked in, and `tools/verify_export.py` verifies it from the [published specification](@/docs/format.md) alone, re-deriving all 27 record vectors rather than only accepting them |
| 4 | **A stated unknown-field policy per durable format.** | ✅ done, and strict in both directions — a record is *evidence*, so a reader that drops a field reaches a verdict over evidence it did not see. Refusals are classified as build skew rather than damage, with the deployment order they imply written down beside them |
| 5 | **Upcasters exercised end-to-end, not only unit-tested.** | ✅ done — consulted on *every* record read, with a test lifting a record whose shape this build cannot parse and asserting the chain still commits to the bytes as written. A corpus of genuinely old records arrives with the first post-freeze bump |
| 6 | **A migration and rollback procedure**, written down and rehearsed | 🟨 half — written down (readers before writers; rollback bounded by a *time window*), and the reader's half is pinned: a record from a shape this build does not know is refused as skew, not damage. What is left is the two-build exercise, which needs a version bump to have two builds to run |
| 7 | **An algorithm-agility plan** for every durable or signed format: how SHA-256 is replaced without invalidating history | ✅ done — [written down](@/docs/format.md#algorithm-agility), and already implemented: hashes are agile by version, signatures by key, and nothing rehashes stored bytes, so history stays verifiable under the algorithm that wrote it |
| 8 | **The deferred format questions are settled**, because each one moves a record or a wire: a rate-limit wait that suspends needs a field on `EffectFailed` and a rule for reading it in order | ⬜ open — **eight** questions, each with an answer that changes a durable format or a protocol. Four more that had accumulated here turned out to change neither, whichever way they go, and no longer count against the freeze |

**7 and 8 are independent, with one join.** They can be worked in parallel:
agility is about how a digest says *which function produced it* and how a
verifier meets an older one, while the deferred questions add **fields** to
record kinds that are already hashed — a field on `EffectFailed` changes the
bytes, not the scheme that covers them. The join is the policy-bundle canonical
format, which is itself a hashed artifact: agility enumerates every durable or
signed format, and that enumeration is not complete until the bundle's format
exists. So 8 does not gate 7's *design*, only the last line of its inventory.

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

Each entry says *why*, because the distinction a status page exists to make is
"deliberately deferred" from "never thought about".

**Symbolic policy analysis.** Cedar can prove a policy set cannot widen access
rather than test it — the check that catches Cedar's totality, where a `when`
clause reading an absent attribute makes the rule vanish instead of erroring.
The prover (`cedar-policy-symcc`) and its solver are released and work. The
blocker is that proving needs a **schema**, and a universal one is not
expressible: `context.args` is caller data of arbitrary shape and Cedar records
are closed. A per-deployment schema is expressible but needs a vocabulary
decision first — `effect:perform` spans every effect kind, so one action's
context type would have to cover them all.

**Cross-run mutual exclusion over a declared resource.** An effect group enforces
its footprint *within* a run. Two runs grouping over the same resource are
ordered by the resources themselves, not by the plane.

**Speaking the [Agent Control Standard](https://github.com/GenAI-Security-Project/agent-control-standard).**
Two directions, two different answers.

As an **observed agent** — asking an external Guardian to permit each step —
this is not deferred, it is refused. ACS-Core's failure posture defaults to
*proceed*, for a hook that times out and for a handshake that never completes,
and the specification states the consequence itself: an adversary who can
disrupt the channel converts control into audit. The gate here is inside effect
dispatch, so no partition opens a path to a sink, and a verdict fetched over the
network could not be replayed in the first place — a recorded decision is
re-read on a resume, never re-asked.

As a **Guardian** — serving the wire so agents this runtime does not execute can
be governed by a plane that journals the decision — it is deferred, and the
mapping is close to complete: Cedar is the deterministic layer, the sink gate is
allow/deny, an amendment is `MODIFY`, an approval task is `ASK`, a suspension is
`DEFER`, and the audit chain is already `SHA-256` over RFC 8785 canonical JSON,
which is ACS's own construction with the fields in the other order. What defers
it is a durable-format question rather than effort: ACS's SessionContext is a
second append-only chain over the same session, so either every hook maps onto a
record kind and the chain is *derived*, or this plane keeps two histories of one
session and has to say which is the plan of record. Shipping the wire before
that is answered would be shipping the second one by accident.

**The rest of format freeze.** The mechanics are built, the
[record format](@/docs/format.md) is specified, and a second implementation
reads that specification and derives the same bytes. What is left is
algorithm agility and the deferred questions that would each move a record —
enumerated in [Format freeze](#format-freeze) above.

**A measured containment claim.** The runtime claims injection *containment*, not
immunity, and no external measurement is attached to it. A static attack set
would manufacture exactly the confidence this project refuses; an adaptive,
defence-aware evaluation is what would count, and none has been run here. The
methodology exists in published form
([2606.26479](https://arxiv.org/abs/2606.26479)); what remains is running one,
over A2A, graded from the journal.

**A rate-limit wait that outlives a worker.** A peer's `Retry-After` is honoured
and bounded by `RetryPolicy::max_advice` (60 s), which is also the bound on how
long one effect holds a worker; a longer throttle costs attempts rather than a
row. Suspending instead is a **durable-format** question — the replay cursor is
strictly ordered, so such a wait needs a field on `EffectFailed` and a rule for
reading it — so it waits for freeze rather than being half-built. The workaround
is a skill that catches the failure and calls `cx.sleep()`.

**A curated event type between the journal and the wire.** The durable,
resumable output stream this would provide already exists: `Runtime::journal()`
plus `JournalStore::read(run, from)` is a seq-cursored, reconnect-safe read any
instance can serve, and the A2A server is an embedder of it. A third vocabulary
between the records and the wire would drift from both. Live in-process deltas
stay advisory (`ModelCall::streaming_to`): none is journaled and strict replay
emits none, because a durable delta stream is a second truth beside the one
terminal `Completion`.

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
