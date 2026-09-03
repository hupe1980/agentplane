+++
title = "Status"
description = "What is pre-alpha, what to pin, what is deliberately not built, and how to check."
weight = 12
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

## ⬜ Deliberately not built

Each row says *why* it is deferred, because the distinction a status page exists
to make is "deliberately deferred" from "never thought about".

| | |
|---|---|
| ⬜ | **Symbolic policy analysis, and a schema to prove against** — Cedar can *prove* properties of a policy set rather than test them, which is the only thing that catches the failure this project has hit twice: Cedar is **total**, so a `when` clause reading an attribute that does not exist makes the rule silently vanish rather than error. A worked taint gate on this site denied every mutating call in a tool loop and its unit tests passed, because a hand-written context is a context assembled to suit the rule; `check_never_errors` is the proof obligation that would have caught it. **The mechanics are all available; the blocker is a schema.** The prover is `cedar-policy-symcc`, a *separate crate* at 0.6.0 — not a missing feature of `cedar-policy`, which is at 4.12.0 and is the latest — and the cvc5 solver it needs is a released binary that installs and runs fine. What is missing is one level deeper: symbolic analysis proves against a **schema**, this crate ships none, and a universal one **is not expressible** — `context.args` is caller data of arbitrary shape, Cedar records are closed, and open records (`additionalAttributes`) require Cedar's *experimental* `partial-validate` feature, which is not something to enable on the authorization dependency. What is expressible is a schema per deployment, for the effects that deployment actually calls — and even that is not the small generator it sounds like. Cedar attaches one context type per **action**, and `effect:perform` spans every effect kind, so `context.args` would need a union type Cedar does not have. A generator therefore requires one of two designs, each with a real cost: split the action vocabulary per effect kind using Cedar action groups — but group membership lives in the schema, so `action in` rules would mean different things on a plane with no schema loaded; or merge every declared argument shape into one all-optional record — which collapses the moment any effect carries arbitrary JSON, and a model call's prompt is arbitrary JSON. The generator is deferred until that vocabulary decision is taken deliberately, not because emitting a schema is hard |
| ⬜ | **Cross-run mutual exclusion over a declared resource** — an effect group enforces its footprint *within* a run. Two runs grouping over the same resource are ordered by the resources themselves, not by the plane |
| ⬜ | **The rest of format freeze** — canonicalization is versioned at the run, so a rule change reads as *unverifiable* rather than as a divergence, and it is a complete RFC 8785 implementation held to the standard's own number vectors. What remains is the rest of the ceremony, enumerated as checkable conditions in [Format freeze](#format-freeze) below rather than as a paragraph: golden vectors for the journal and export formats, an unknown-field policy, migration and rollback procedures, and an algorithm-agility plan for every durable or signed format |
| ⬜ | **A measured containment claim** — the runtime claims injection *containment*, not immunity, and that is a falsifiable claim with no external measurement attached to it. A static attack set would manufacture exactly the confidence this project refuses; an adaptive evaluation is what would count, and none has been run against this runtime. The methodology exists in published form: the first adaptive evaluation of the out-of-band defence family this design belongs to ([2606.26479](https://arxiv.org/abs/2606.26479)) confirms that the family had only ever been validated statically — and reports deterministic enforcement holding under its one adaptive template, a data point its authors weight as small-scale. What remains is running one against this runtime, over A2A, graded from the journal |
| ⬜ | **A rate-limit wait that outlives a worker** — a peer's `Retry-After` is read, honoured and bounded by `RetryPolicy::max_advice` (60 s), which is also the bound on how long one effect holds a worker. A genuinely longer throttle costs attempts rather than a row. Suspending the run instead is the doctrinally clean answer and the one Temporal reaches, and it is a **durable-format** question rather than an implementation one: the replay cursor is strictly ordered, so a wait that suspends must be journaled beside the failure that caused it and consumed in order on the way back — a field on `EffectFailed` and a rule for reading it. Deferred until format freeze rather than half-built. The workaround is a skill that catches the failure and calls `cx.sleep()`, which is durable |
| ⬜ | **A curated event type between the journal and the wire** — deliberately absent, and the question is settled rather than open. The durable, resumable output stream embedders want already exists: `Runtime::journal()` plus `JournalStore::read(run, from)` is a seq-cursored, reconnect-safe read that any instance can serve — the exact mechanism A2A streaming is built on, and the A2A server is itself an embedder of it. A third, curated vocabulary between the records and the wire would drift from both, which is the second-truth problem arriving as ergonomics. Live in-process deltas stay advisory (`ModelCall::streaming_to`): no delta is journaled and strict replay emits none, because a durable delta stream is a second truth beside the one terminal `Completion` |

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

| # | Condition | State |
|---|---|---|
| 1 | **Canonicalization is versioned and vector-checked.** A rule change must read as *unverifiable* rather than as a divergence | ✅ done — versioned at the run, a complete RFC 8785 implementation held to the standard's own number vectors |
| 2 | **Golden corpora for the journal record format.** A fixed set of records, byte-for-byte, that every future build must still read and still hash identically | ⬜ open |
| 3 | **Golden vectors for the export format** — the artifact a third party verifies without this crate, so its vectors are the ones another implementation is checked against | ⬜ open |
| 4 | **A stated unknown-field policy per durable format.** Today it is `deny_unknown_fields` everywhere, which is right for a *security* document and wrong for a *record* a newer writer may have extended | ⬜ open |
| 5 | **Upcasters exercised end-to-end, not only unit-tested.** The machinery exists; what is missing is a corpus of genuinely old records it is run against | ⬜ open |
| 6 | **A migration and rollback procedure**, written down and rehearsed — including the answer to *a v2 writer wrote records this v1 reader must read* | ⬜ open |
| 7 | **An algorithm-agility plan** for every durable or signed format: how SHA-256 is replaced without invalidating history | ⬜ open |
| 8 | **The deferred format questions are settled**, because each one moves a record: a rate-limit wait that suspends needs a field on `EffectFailed` and a rule for reading it in order | ⬜ open |

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

## 📌 What to pin, and what will move

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
| **Journal record format** | **will change** | not frozen. Upcasters exist, but a format-freeze milestone has not happened and hard cuts are preferred until it does — see the freeze conditions above for what has to land first, and for the export-as-the-durable-artifact position in the meantime |
| **Effect keys** | **will change** | any change to a descriptor's arguments moves every key for that effect kind. `tool.call` was `mcp.tools/call` until the reference scheme stopped naming a transport |
| **Manifest schema** | additive, with hard cuts | `deny_unknown_fields` means an added field is safe and a *removed* one is a hard failure. Fields have been removed when they could not be enforced — see the design decisions above. The published [JSON Schema](/agentplane/agent.schema.json) is generated from the parser's types and moves with them |
| **`Tool` / `ToolFailure`** | settled | `Tool::call` returns `ToolFailure`, named by disposition rather than transport; references are `tool://server/name` |
| **Error enums** | additive; `#[non_exhaustive]` | they gain variants as the runtime learns to say more — a rate limit is its own variant rather than a generic rejection, and the next distinction will be too. Match with a `_` arm |
| **`RetryPolicy` fields** | additive | it is a plain struct, so a literal breaks when a field lands. Build with `RetryPolicy::attempts(n)` and the builder methods, or spread `..RetryPolicy::default()` |
| **Policy seam (`PolicyEngine`, request context)** | stable seam, growing context | the trait is settled. `context` gains attributes as the runtime learns to say more; a `forbid` reading one that does not exist is an evaluation error, and the Cedar adapter **denies an `Allow` that arrives with evaluation errors** rather than letting a broken rule disappear — see [security](@/docs/security.md#the-authorization-context) |
| **Store traits** | stable seam, growing contract | the conformance battery is the contract; it gains cases faster than the traits gain methods |
| **Store schemas, SQL *and* redb** | **will change without migration** | pre-alpha, and there is no migration tooling. Recreate rather than migrate. This covers both backends deliberately: a redb `TableDefinition` pins its value types, so widening a column is as breaking as an `ALTER TABLE` and fails at open rather than at read. Making money unsigned moved the quota, batch and authority tables on both |
| **A2A / MCP wire behaviour** | tracks the specs | exact released versions, not a compatibility range — see the open protocol-support question in the design decisions above |
| **`testkit`** | stable, additive | it is how embedders test their own stores and skills, so churn here costs more than it saves |

## 🔍 How to check any of this

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

python3 tools/mutants.py <name> --verify   # one guarantee, end to end
MUTANTS_SHARD=2/6 just mutants           # one slice, for a machine that is not alone
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
