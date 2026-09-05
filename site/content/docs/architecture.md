+++
title = "Architecture"
description = "The determinism boundary, module layout, replay modes and canonical bytes — how the pieces of the agent runtime fit together."
weight = 8

[extra]
group = "How it works"
+++

How the runtime is put together, and where each mechanism lives.

This page is the shape of the system. The mechanisms themselves have their own
pages, because each is worth reading on its own:

- [The effect protocol](@/docs/effects.md) — how one outward call is made safe,
  and what a saga, a transactional group and an operator's stop do to the world.
- [The journal](@/docs/journal.md) — what the hash chain, the signatures and the
  Merkle log prove, and what they deliberately do not.
- [Plans, cases and time](@/docs/plans-cases.md) — frozen authorization graphs,
  month-long cases, durable waits and timers, budgets, human tasks, batches.
- [Models, agents and peers](@/docs/interop.md) — everything this runtime calls
  that it does not own.
- [Publishing and pinning agents](@/docs/registry.md) — the manifest as an
  artifact, and the registry that refuses to rewrite a version.
- [How this is proven](@/docs/assurance.md) — the specifications, the mutation
  sweep, and why a green test suite is not the argument.

## The determinism boundary

Everything else depends on this holding.

```
┌─────────────────────── DETERMINISTIC ZONE ────────────────────────┐
│  plan traversal · guards · retry decisions · budget arithmetic     │
│  policy evaluation · label joins · record upcasting                │
│                                                                    │
│  Replay re-executes this zone and MUST reproduce the identical     │
│  sequence of effect keys. Divergence is a fault, not a retry.      │
└────────────────────────────────┬───────────────────────────────────┘
                                 │  cx.effect(…)
┌────────────────────────────────▼───────────────────────────────────┐
│                     NON-DETERMINISTIC ZONE                         │
│  inference · tool calls · wall clock · network · human input       │
│                                                                    │
│  Executed at most once. Result journaled. Replay reads the journal │
│  and never re-invokes.                                             │
└────────────────────────────────────────────────────────────────────┘
```

Three layers enforce it, because convention is not enforcement:

1. **Capability absence.** Sandboxed skills (planned) get a WASI world with no
   clock, RNG, socket, or filesystem. Non-determinism is unreachable rather than
   discouraged.
2. **Lint gating.** `clippy.toml` denies `SystemTime::now`, `Instant::now`,
   `rand::random`, `Ulid::new`. The two legitimate call sites in the crate carry
   an explicit `#[allow]` and a comment naming the record that captures the
   value.
3. **Effect-key verification.** On replay the key is recomputed from the
   deterministic zone. A mismatch quarantines the run.

Two things sit *inside* the deterministic zone that are easy to get wrong:
**record upcasting** and **correlation matching**. Both are pure by
construction, and both would break replay if they weren't. An upcaster that
reads a config file is the same bug class as a non-deterministic effect, but far
harder to find — it only manifests on old records.

## Module layout

One crate, feature-gated. Crate boundaries are a public API you cannot design
before the code exists, and a `core` crate would be a dependency hub that makes
compile times *worse*, not better.

```
src/
  core/      types, traits, labels, calendar, case model, errors
             — NO I/O (enforced by tests/guards/layering.rs)
  journal/   records, hash chain, replay cursor, upcasters, the Merkle log
             and the witness seam
  case/      CaseStore, EventStore, TaskStore contracts
  plan/      the plan contract: what a plan must satisfy to run at all
  policy/    authorization-engine adapters; the seam itself is core::policy
  memory/    what an agent remembers between runs: versioned items, journaled
             retrieval, and labels taken from provenance rather than content
  netguard/  which IP addresses this plane will connect to — one rule, shared
             by governed media, webhook delivery and both A2A URL legs, applied
             at connect time so a pooled client stays guarded
  push/      Durable outbound delivery: the journal-as-outbox cursor loop, A2A
             webhook cursors with SSRF-guarded delivery for caller-supplied URLs,
             and an operator-configured outbox for the deployment's own events
             (feature `push`)
  quota/     per-tenant ceilings on concurrent work and spend; journaled pass
             identity plus idempotent store receipts survive settlement crashes
  authority/ standing authority: a ceiling bound to an authorization rather
             than to a run or a billing period — revocable, drawn on as a
             journaled effect, idempotent across retries
  store/     redb and Postgres backends, journal and cases alike
  blob/      content-addressed bytes kept out of the chain, and the erasure
             that retention needs
  keyring/   envelope encryption for those bytes, and the cryptographic
             erasure that reaches copies deletion cannot (feature `keyring`)
  media/     governed URL dereferencing, DNS pinning, bounded validation and
             digest-only model materialization (feature `media`, off by default)
  runtime/   StepCtx, effect protocol, effect groups, executor, sweeper,
             built-in effects
  batch/     batch runs: item source, outcomes, the BatchStore contract
  tools/     calling tools on other people's servers, and the annotation
             trust decision that implies
  peers/     calling other agents: identity, audience, narrowing authority
  audit      the outsider's verification pass over a journal
  export     the same history as framed JSON Lines, so the outsider can take
             it away as well as check it in place
  drill      the live half of that check: blob bytes re-hashed and sealed
             state proven to open, with erasure told from loss
  retention  the time-windowed erasure pass: closed cases past a window, with
             an honest account of what it cannot make unreadable
  manifest/  the declaration an agent is built from, and the registry it is
             pinned in (feature `manifest`, off by default)
  api/       the HTTP surface for operators (feature `http`, off by default)
  model/     the ModelProvider seam and the metering rules, always present;
             the provider drivers, each with a streaming twin, sit behind
             features (`providers` for Anthropic, OpenAI, Gemini and
             Chat Completions; `bedrock` for Bedrock — both off by default)
  testkit/   fault injection, a fake model provider, and shared assertions
             (feature `testkit`, off by default) — for this crate's assurance
             layers and for embedders testing their own stores and skills
  prelude    the names a program that does nothing unusual needs, so the first
             one is a single `use` — re-exports only, no API of its own
```

The one discipline to keep: `core/` has zero I/O dependencies. Keep it and an
eventual crate split is mechanical; lose it and no crate layout recovers it.

## Replay modes

| Mode | Effects | Writes | Use |
|---|---|---|---|
| `Live` | performed | yes | Normal execution |
| `Resume` | replayed, then live past the end of history | yes | Crash recovery |
| `Strict` | replayed; running past the end is an error | no | Determinism verification |

**`Resume` is for crashes, not for code changes.** It requires the journal to be
a *prefix* of what the current code does. A journal written by a different
program is divergence, and the run is quarantined rather than continued.

The same hard boundary applies to authorization. Admission records a structured
policy-bundle identity covering rules, schema, static entities, adapter
configuration/extensions, and evaluator semantics. An open run may resume only
under that exact bundle because resume can dispatch past the recorded prefix.
Dynamic request facts are not bundle inputs; they stay in each policy request.
An effect's request carries the run, step, tenant, whether it mutates, the
arguments — and, when the call came through `sink`, the **label** of the value it
will send. That last one is what lets a rule key on *where the data came from*
rather than only on what it is; without it, provenance and authorization would be
two graphs that meet only in the checks this crate happens to have written.
`Strict` performs nothing and therefore neither loads nor compares policy, which
keeps offline verification independent of historical evaluator availability.

**A succeeded run is closed to resume**, and so is a cancelled or abandoned one.
Succeeded means nothing is outstanding, and re-executing would repeat work that
is not an effect — a case-state write, say — which is the same class of bug the
effect protocol prevents, arriving through a side door: the replay cursor is
exhausted from the first instruction, so every step looks live. A *failed* run
is deliberately still resumable — that is what crash recovery is.

**A quarantined run is closed until a person answers it.** Resuming an
unanswered one would re-hit whatever could not be decided, and burying that in a
retry loop is how an undecidable situation becomes an unnoticed one. What lifts
it is a journaled decision by a named person, and the verdict is still the
runtime's: a reopened run re-derives its outcome from a history that now holds
whatever they established, and quarantines again if it does not settle.

That is the desired outcome, not a limitation. Continuing would graft new
behaviour onto a history that never produced it, and the resulting audit trail
would be a plausible lie.

A subtlety worth internalising: "run a shorter version of the program" is *not*
a crash simulation. If the shorter version ends with an effect the longer one
has elsewhere (a trailing timestamp, say), that effect lands at a different
ordinal and the journal stops being a prefix. A real crash truncates; it does
not rewrite.

## Canonical bytes

Every hash — record hashes, effect keys, plan digests — is taken over canonical
bytes, and `core::canon` produces that form itself: object keys are sorted at
serialization time.

It did not always. It relied on `serde_json::Map` being a `BTreeMap`, with a
comment in `Cargo.toml` saying `preserve_order` must never be enabled. That is
unenforceable. Cargo unifies features across the entire dependency graph, so the
flag is not this crate's to refuse — adding `cedar-policy`, which enables it,
turned it on for everyone.

The effect was measured, not theorised. Before the fix, with `cedar` enabled, the
same object built as `{"b":1,"a":2}` and as `{"a":2,"b":1}` produced **different
effect keys**. Two runs performing the same call would fail to recognise each
other's work; exactly-once would stop holding, silently, in the direction that
issues a second payment.

Sorting explicitly costs nothing and removes the dependency on a flag a stranger
controls. Output is byte-identical whether `preserve_order` is on or off —
checked by deriving effect keys under both builds and diffing.

Two consequences worth keeping:

* **`tests/guards/layering.rs` does not look for `indexmap` in the lockfile.** That
  question is unanswerable once a legitimate dependency wants the feature. It
  checks what would actually undo the fix: no code outside
  `canon` may call `serde_json::to_vec`, because with `preserve_order` on such a
  call takes insertion order into a hash.
* **CI runs the suite under default features *and* `--all-features`.** They are
  not redundant: `--all-features` enables `cedar` and therefore `preserve_order`,
  so the two builds exercise genuinely different canonicalization paths.
