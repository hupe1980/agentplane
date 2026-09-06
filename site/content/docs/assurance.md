+++
title = "How this is proven"
description = "Model-checked TLA+ specifications, every crash point without a fault injector, and a mutation sweep that breaks each guarantee on purpose."
weight = 13

[extra]
group = "Trust"
+++

A green test suite is not an argument. A guarantee is only worth what its
tests can falsify, so each one here is broken on purpose and the test written for
it must fail.

## Testing

| File | Guards |
|---|---|
| `tests/engine/durability.rs` | The claims that would otherwise be marketing |
| `tests/engine/recovery.rs` | Crash, resume, orphan handling, lease contention |
| `tests/process/cases.rs` | Correlation, case state across runs, obligations, closure |
| `tests/process/waits.rs` | Suspension, delivery, the arrive-before-wait race, dead letters |
| `tests/process/admission.rs` | At-most-once admission: redelivery, racing emitters, a refused admission spending no key |
| `tests/process/tasks.rs` | Worklist, four-eyes, expiry policy, breach escalation |
| `tests/process/plans.rs` | Contract validation, ready-set, provenance through the graph |
| `tests/trust/budgets.rs` | Limits, overshoot semantics, the width of a ready set, and the tally a replay must reach |
| `tests/engine/retries.rs` | The disposition gate, the policy bound, attempt keys, replay of a retry sequence, a peer's named window beating the computed one |
| `tests/engine/reconciliation.rs` | Probing after doubt, the verdict on the record, strict replay staying a pure read |
| `tests/engine/compensation.rs` | Reverse-order unwind, pivots, undeclared steps, refusing to unwind under doubt |
| `tests/process/timers.rs` | Durable sleep, the journaled instant, single-delivery wake-ups, abandoned claims |
| `tests/process/telemetry.rs` | That spans and events are emitted, and that replay is distinguishable |
| `tests/process/replanning.rs` | Versioned successors, lineage, the untrusted-data refusal, replay reading plans back |
| `tests/guards/interactions.rs` | Feature pairs that share machinery — a sleeping compensation, a replan beside a live sibling, sleep/retry/sleep in one step |
| `tests/engine/simulation.rs` | Every crash point in a run — each journal prefix rebuilt, resumed, and re-checked |
| `tests/engine/faults.rs` | Store faults a prefix cannot express — above all, a write that committed and was lost |
| `tests/process/batches.rs` | Failure isolation, partial failure as terminal, item-granular resume, per-item cost |
| `tests/guards/metrics.rs` | What a metrics subscriber actually received, and that gauges are not page-bounded |
| `tests/trust/policy.rs` | The gate, the journaled denial, and that replay never consults the engine |
| `tests/trust/identity.rs` | Scope containment, attenuation, depth, and the chain surviving replay |
| `tests/trust/boundary.rs` | Effect output is labelled at the source, propagates, gates sinks, and survives replay |
| `tests/wire/api.rs` | That the HTTP surface cannot be told who is acting, that both gates run on every route, and that four-eyes survives the hop |
| `tests/trust/attestation.rs` | That a *valid* chain rewritten by somebody who could hash but not sign is still caught |
| `tests/engine/cancellation.rs` | That a stop unwinds what the run did, refuses to unwind around an unknown outcome, and names who asked |
| `tests/engine/quarantine.rs` | That a person can answer a doubt and the runtime still decides the run — and that giving up leaves the doubt reportable |
| `tests/wire/drivers.rs` | The two wire drivers' failure mappings — whether a peer acted, and whether a model call was billed |
| `tests/trust/format.rs` | The durable formats against frozen bytes — every record kind's canonical form and digest, a sealed export a future build must still verify, and what a reader does with a shape it does not know |
| `tests/guards/layering.rs` | Architectural invariants — core purity, lint config, canonical JSON, spec/code correspondence |
| `spec/` | TLA+ models of the effect protocol, retry safety, sagas, and fencing, plus the mutants that prove those models constrain anything |

### A format checks itself against its own bytes, not against its own reader

Two of the entries above are checked-in artifacts rather than assertions:
`tests/golden/records.jsonl` (one canonical record per kind, with its chain
digest) and `tests/golden/export.jsonl` (a sealed export). They exist because a
test that serialises and then deserialises proves only that the build agrees
with itself, and the failure they catch is the one that passes every such test:
a serde attribute renamed, a `skip_serializing_if` added, the canonicalization
rule changed — each rehashing every record this project will ever write, each
reading in review as a tidy-up.

**Both are sealed through the production path**, never re-derived. A vector
generator that serialises the value *equivalently* pins the equivalence rather
than the format: canonical form sorts object members, so a corpus built with
`serde_json` directly is sensitive to struct declaration order — which the chain
does not depend on — and blind to the canonicalization rule, which is the whole
of what it does depend on. The bytes come off `Record::seal`, the one function
every backend appends through, so there is no equivalent way to produce them.

Regenerating them is a separate command:

```sh
AGENTPLANE_BLESS_GOLDEN=1 cargo test --test trust format::
```

Deliberately not a `--fix`, and deliberately not automatic. Until the format
freeze a shape change is a **hard cut** — every journal written by an older
build stops being readable — so blessing the corpus is the moment somebody
decides that, and it should cost a decision.

### The corpus is read by something that is not this crate

Vectors a project generates and then checks are that project agreeing with
itself. They catch drift; they cannot catch a shared misunderstanding, because
there is only one understanding present.

`tools/verify_export.py` is the second one. It is written from the
[published record format](@/docs/format.md) and reads none of this crate's
Rust, which is a property a guard enforces rather than a promise — a verifier
that consulted `src/` would be a paraphrase of the implementation and would
agree with it by construction. It runs in the gate, and it does three things:

```sh
just verify-golden
```

- **`--canon-check`** re-derives all 27 record vectors from their *parsed
  values* — an independent canonicalizer, an independent chain digest. This is
  the half that **produces** bytes rather than accepting them, and it is
  non-circular: the input is what each record means, the output is what the
  format says it must look like. It also holds both implementations to RFC
  8785's own number vectors, the one part of canonicalization no record reaches.
- The default pass **verifies the sealed export**: chains, log positions, the
  Merkle root, the case layer, the frame.
- **`--self-test`** damages that export six ways — an edited readable body, a
  flipped wire byte, a record removed from the middle, a rewritten log leaf,
  the case layer dropped, the trailer cut off — and asserts each one is
  reported. A second reader that answers *0 findings* for everything agrees
  with this crate perfectly and is worth nothing.

What it still does not buy: it is one reader, written by the same project, from
a specification that project also wrote. A genuinely independent implementation
by somebody else remains the strongest evidence available, and this is the next
best thing rather than a substitute for it.

### The size a proof starts from is stated, never inferred

`Witness::cosign` takes `old_size` from the caller. That looks like ceremony and
is not: an RFC 6962 consistency proof is **O(log n) hashes, not one per new
entry**, so nothing about a proof reveals which size it starts from. A 50→100
proof carries seven hashes, and an implementation computing `size - proof.len()`
claims to start at 93 — which every witness refuses.

Only the holder of the log knows. `MemoryWitness` checks the caller's claim
against what it remembers and reports a mismatch as `Stale`, exactly as a remote
witness's `409` does, so the in-process model stays a faithful stand-in rather
than a friendlier one.

This shipped as a real defect and survived its first test, because that test used
a four-entry log with a two-hash proof — the one size where the wrong arithmetic
gives the right answer. The regression test uses fifty and a hundred.

### The specs are mutation-tested

Model checking proves a spec's invariants hold *of the spec*. It says nothing
about whether those invariants constrain anything, and the difference is not
visible by reading.

Writing `spec/RetrySafety.tla` also paid for itself immediately: TLC deadlocked
on an effect that was *safe* to repeat, failing in doubt on its final attempt,
with no rule to apply. The implementation handled it; the rules as first written
did not.

`spec/EffectProtocol.tla` models "act" and "record" as **separate** steps. As one
atomic step TLC explores it exhaustively and finds no errors — but the one state
the protocol exists to survive, *the action landed and the process died before
recording it*, is unreachable, so `ExactlyOnce` holds by construction. Green, and
worthless.

So `spec/verify.sh` runs two passes. The first checks the specs. The second
checks the check: each spec is re-run against deliberately broken copies of
itself, and each mutant must be caught by the specific invariant written for it.

| Mutation | Spec | Must be caught by |
|---|---|---|
| Orphaned effect retried instead of escalated | `EffectProtocol` | `ExactlyOnce` |
| Action taken before the announcement is durable | `EffectProtocol` | `DurableIntentPrecedesAction` |
| In-doubt failure retried without checking it is safe to repeat | `RetrySafety` | `ExactlyOnce` |
| A probe answers without identifying the call it is asking about | `RetrySafety` | `ExactlyOnce` |
| A run that left a mutation in doubt reports success | `RetrySafety` | `NoSuccessOnUnresolvedDoubt` |
| A reconcilable effect is escalated without being asked about | `RetrySafety` | `NoQuarantineWithoutAsking` |
| An attempt acts before its announcement is durable | `RetrySafety` | `DurableIntentPrecedesAction` |
| A run holding an unknown outcome is unwound anyway | `Saga` | `NoUnwindUnderDoubt` |
| The unwind continues past the point of no return | `Saga` | `PivotHolds` |
| A step that declared no compensation is undone anyway | `Saga` | `UndeclaredIsNeverUndone` |
| Completed steps are undone in the order they ran | `Saga` | `UnwindIsReverse` |
| A resumed unwind repeats compensations it already performed | `Saga` | `CompensatedAtMostOnce` |
| The unwind passes over a step it could have undone | `Saga` | `UnwindIsComplete` |
| Store accepts a write without checking the epoch | `Fencing` | `EpochsNeverRegress` |

Tripping the top-level `Safety` conjunction is not accepted — that shows only
that *something* broke, not that the invariant aimed at this bug is the one that
caught it. A mutation that no longer matches its spec is a failure too: a
mutation that changes nothing tests nothing.

### Every crash point, without a fault injector

A crash truncates an append-only journal, which means the journal enumerates its
own fault schedules: **every prefix of a real journal is a crash that could have
happened.** `tests/engine/simulation.rs` runs a workload, then for each prefix builds a
fresh store holding exactly that much history, resumes it, and checks the specs'
invariants against the code. For a run of *n* records that is *n* crash points,
exhaustively — no seed, no injector, nothing to get lucky with. It sweeps a run
that succeeds and a run that unwinds.

What it does *not* do is reorder writes, skew clocks, partition a network, or
stall a disk. That needs the runtime on a simulated executor, and is the layer
above this one.

#### The assertion that bites is about failures, not outcomes

The obvious check — no effect performed twice — is nearly vacuous here, and the
reason generalises. Exactly-once is enforced at two layers: replay reads a
completed effect back from the journal, and beneath it the store keys effect
starts by `(run, effect_key)`. Delete the replay path
entirely and the world *still* contains no duplicate, because the re-announcement
is rejected one layer down. The sweep goes green over a runtime that has stopped
replaying at all.

This is not hypothetical. The sweep was written with exactly that assertion, and
a mutation removing the whole read-back survived it.

So the load-bearing assertion is: **replay must never reach the constraint.** A
resume may refuse, but only for a reason the design names — a crash before
`PlanFrozen`, or an undecidable outcome under a recovery mode that forbids
guessing. Being saved by the unique index is the backstop catching what replay
should have caught, and the test says so by name.

The general rule: **a property enforced at more than one layer cannot be tested
by observing the outcome**, because the outer layer masks every inner failure.
The test must assert which layer held.

### Every guarantee is broken on purpose, in CI

The specs are mutation-tested; so is the code. `tools/verify-mutants.sh` walks a
checked-in table of mutations — one per load-bearing guarantee — applies each,
runs the suite, and requires **the test written for that guarantee** to fail.

The distinction between "some test failed" and "the named test failed" is the
whole point. A mutation caught by an unrelated test is reported **weak**, because
it usually means the guarantee has no test of its own: the one holding it up can
be rewritten, or deleted as redundant, without anyone noticing what it was
protecting.

Two things are errors rather than skips. An anchor that no longer matches means
the code moved and the mutation is silently testing nothing. A mutation that
fails to compile broke the file instead of removing the guarantee — it proves
nothing either way.

This exists because a guarantee can be implemented, tested, and unfalsifiable,
and this codebase shipped one: see *The hole this closed* above. Running the
sweep the first time immediately found a second, smaller instance — a test whose
name claimed a property its body could not exercise.

`tests/guards/layering.rs` checks that every test the table names actually
exists — an invented name otherwise costs a full rebuild to discover.

### The model and the code are pinned to each other

A verified spec and a passing suite can still be checking different things. The
dangerous direction is a spec gaining an invariant the Rust side never
implements: the model then verifies a protocol the runtime does not have, and a
green TLA+ job reads as assurance about code it says nothing about.

So `every_spec_invariant_is_claimed_by_a_test` in `tests/guards/layering.rs` holds an
explicit map from each spec invariant to the test that checks the same property
of the implementation, and enforces it in both directions — renaming either side
fails the build. An invariant added to a `Safety` conjunction with no counterpart
fails it too.

`tests/guards/layering.rs` deserves a note more generally: it checks properties that no
amount of code review reliably catches, because they are about what is *absent* —
a missing lint entry, an accidental `serde_json/preserve_order`, an I/O import
creeping into `core`, an invariant nobody wired up, a telemetry event nobody
emits, **a public enum variant nothing constructs**, **a pair of features nothing
exercises together**.

That last one exists because the same bug happened five times: a variant, a
recovery mode, an error, a record kind declared and never built, each reading as
a capability the system had. `#[from]` variants are exempt (`?` builds them), and
a variant meant for callers counts only if a *test* constructs it.

The interaction matrix exists because replanning shipped with its own gates
tested and broke the saga: a successor reusing a completed step's id made the
unwind compensate work that never ran. The model↔code guard maps each invariant
to one test, and no test combined a replan with an unwind. Adding a feature
widens where an invariant applies, so the widening is what gets checked — every
pair of the eight feature axes must be exercised together, or declared
independent with the reason.

**A guard that reads source must exclude the source that is the guard.** Both
source-reading guards have been blinded by themselves: the dead-variant check by
its own doc comment naming the canonical example, and the interaction matrix by
its own list of detection literals, which made one file look like a test
exercising every feature. So they strip comments, and the matrix skips
`layering.rs`.
