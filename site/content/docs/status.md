+++
title = "Status"
description = "What is pre-alpha, what to pin, what is deliberately not built, and how to check."
weight = 10
+++

`agentplane` is pre-alpha and unreleased. This page answers three questions an
adopter has to answer before writing any code: **what will move**, **what is
deliberately absent**, and **how to check that either answer is still true**.

What it deliberately no longer does is list what has been *built*. That list ran
to two hundred rows and twenty-three thousand words — a third of this site — and
nearly every row was a change wearing a status's clothes: *X used to do Y, now it
does Z, and here is why*. That is the [changelog](https://github.com/hupe1980/agentplane/blob/main/CHANGELOG.md)'s
job, and keeping the same fact in two places is the defect this project treats
most seriously everywhere else. The reasoning behind a mechanism now lives at the
mechanism — in the module's own documentation, where it is next to the code it
describes and cannot rot unnoticed — and what exists is answered by
[concepts](@/docs/concepts.md), the [API reference](https://docs.rs/agentplane),
and the test suite.

## ⬜ Deliberately not built

Each row says *why* it is deferred, because the distinction a status page exists
to make is "deliberately deferred" from "never thought about".

| | |
|---|---|
| ⬜ | **Symbolic policy analysis** — Cedar's `symcc` can *prove* properties of a policy set rather than test them; nothing invokes it yet. It needs an external **cvc5** solver binary, so when it lands it will be a development-time check you run when policy changes — never a runtime dependency, and never in the shipped binary |
| ⬜ | **A distributed cryptographic-erasure coordinator for memory** — `EncryptedMemoryStore` serialises subject erasure against writes and legal-hold changes with a **process-local** mutex, so it holds its contract on a single-writer deployment only. `RuntimeBuilder::keyring` therefore does *not* wrap it: silently handing a single-node adapter to an active-active `PostgreSQL` plane would be a control that is worse than absent, because it reads as present. An embedder wraps it explicitly. Closing this needs a ceremony that excludes writes and hold changes across instances while an external KMS destroys the scope |
| ⬜ | **Cross-run mutual exclusion over a declared resource** — an effect group enforces its footprint *within* a run. Two runs grouping over the same resource are ordered by the resources themselves, not by the plane |
| ⬜ | **Client-side A2A interoperability evidence** — the protocol project's conformance kit validates *servers*, and this crate's server passes its MUST battery. Nothing independent yet exercises this crate's **client** against somebody else's server |
| ⬜ | **A measured containment claim** — the runtime claims injection *containment*, not immunity, and that is a falsifiable claim with no external measurement attached to it. A static attack set would manufacture exactly the confidence this project refuses; an adaptive evaluation is what would count, and none has been run against this runtime |
| ⬜ | **A durable, resumable output stream for embedders** — A2A streaming is served from the journal, so any instance can serve it and a reconnect reads the current snapshot first. In-process, `ModelCall::streaming_to` is deliberately **advisory**: no delta is journaled and strict replay emits none, because a durable delta stream is a second truth beside the one terminal `Completion`. Whether a resumable cursor over already-journaled events belongs on the embedder-facing surface is open |

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
| **`Runtime` admission methods** | **recently changed** | every door takes `Tainted<Value>`; the `run_tainted*` twins are gone and `run_in_case` now means *this exact case* rather than *correlate* (that is `run_correlated`). Wrap an operator's own literal in `Tainted::trusted(..)` |
| **Journal record format** | **will change** | not frozen. Upcasters exist, but a format-freeze milestone has not happened and hard cuts are preferred until it does |
| **Effect keys** | **will change** | any change to a descriptor's arguments moves every key for that effect kind. `tool.call` was `mcp.tools/call` until the reference scheme stopped naming a transport |
| **Manifest schema** | additive, with hard cuts | `deny_unknown_fields` means an added field is safe and a *removed* one is a hard failure. Fields have been removed when they could not be enforced — see the design decisions above |
| **`Tool` / `ToolFailure`** | recently changed | `Tool::call` returns `ToolFailure` (disposition-named) rather than `ToolError` (transport-named); references are `tool://server/name` |
| **Error enums** | additive; `#[non_exhaustive]` | they gain variants as the runtime learns to say more — `SkillError::Tool` was added so `?` works on `ToolCall::prepare`. Match with a `_` arm |
| **Policy seam (`PolicyEngine`, request context)** | stable seam, growing context | the trait is settled. `context` gains attributes as the runtime learns to say more, and a policy reading one that does not exist **fails open** — see [security](@/docs/security.md#the-authorization-context) |
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
is also why this page no longer asserts a list of them. An inventory is a claim a
reader has to trust; a sweep is one they can run.

`--verify` is the same check for a single guarantee, and it exists because the
cheap one is not enough. `just anchors` proves a mutation still *matches* the
code; only running it proves the mutation still *kills*. A test rewritten around
a mutation passes quietly, and a guarantee that stopped being checked looks
exactly like one that is. The command distinguishes **survived** from **never
ran**, because a run that compiled nothing reports zero failures and reads like
success.
