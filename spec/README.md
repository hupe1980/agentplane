# Formal specifications

Four TLA+ models covering the parts of the runtime that must be unconditionally
correct, and that are hardest to convince yourself of by reading code:

| Spec | Question it answers |
|---|---|
| [`EffectProtocol.tla`](EffectProtocol.tla) | Can a crash — anywhere — cause an effect to be performed twice, or to happen with no durable trace? |
| [`RetrySafety.tla`](RetrySafety.tla) | When a call fails without saying whether it landed, is repeating it ever safe — and does asking the provider help? |
| [`Saga.tla`](Saga.tla) | When a step fails, what may be undone — and what must be left exactly where it is? |
| [`Fencing.tla`](Fencing.tla) | Can a paused instance wake up after its run was taken over and still land a write? |

These check the **design**. The `madsim` simulation (planned) checks the
**implementation** against deliberately the same invariant list, and the
integration tests check observable behaviour. Each layer catches what the others
structurally cannot: a model checker explores interleavings no test will think
of, and a test catches the gap between the model and the code.

## Status

Every spec is model-checked exhaustively on every push, and every mutant of
them is checked too:

| Spec | Result | State space |
|---|---|---|
| `EffectProtocol` | verified | 113 distinct states, depth 16 |
| `RetrySafety` | verified | 493 distinct states |
| `Saga` | verified | 63 distinct states |
| `Fencing` | verified | 1171 distinct states |

```sh
spec/verify.sh          # Docker; no local Java needed
```

## Why the mutants matter more than the specs

A spec nobody has run is documentation. A spec whose mutants also pass is worse
— it is decoration that looks like evidence.

`EffectProtocol` and `Fencing` both started out exactly that way. `EffectProtocol` originally
modelled "act" and "record" as a *single atomic step*. That made the one state
the protocol exists to survive — the action landed, the process died before
recording it — **unreachable**, so `ExactlyOnce` was true by construction. TLC
reported no errors. The verification was worthless, and reading the spec did not
reveal it; only mutating it did.

So the second pass injects real bugs and requires each one to be caught by the
specific invariant written for it (see [`mutations.py`](mutations.py)):

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

Tripping the top-level `Safety` conjunction is not accepted: that shows only
that *something* broke. Each generated config names one invariant so a mutation
cannot pass by landing on an unrelated check.

If a mutation stops matching its spec, that is a failure, not a skip — a
mutation that changes nothing tests nothing.

## What each invariant is protecting

**`EffectProtocol`**

- `ExactlyOnce` — no effect reaches the outside world twice, under any crash
  schedule. This is the property that separates a durable runtime from a retry
  loop, and the one that stops a resumed run from re-issuing an invoice.
- `DurableIntentPrecedesAction` — nothing happens that was not durably announced
  first. Otherwise a crash can leave an action with no trace it was attempted:
  invisible to both recovery and audit.
- `NoOutcomeWithoutAnnouncement` — outcomes only exist for announced effects.
- `SuccessMeansComplete` — success is structural. The workload does not get to
  declare it.

The model deliberately loses both `inflight` and `acted` on every crash, because
in-memory knowledge does not survive a process death. That is what makes an
orphaned announcement genuinely undecidable and forces the escalate-to-a-human
branch. A model that remembered across crashes would "prove" a protocol that
cannot be built — which is precisely the failure the atomic-`Perform` version
had.

`Act`'s guard is likewise restricted to what the *implementation* can observe:
"I announced this and have not acted on it yet". It never consults `world`,
because the outside world is not readable. Guarding on `world` would make
`ExactlyOnce` true by construction all over again.

**`RetrySafety`**

- `ExactlyOnce` — no effect changes the outside world twice, whatever the
  failure schedule. A read may repeat freely; it never enters `world` at all,
  which is precisely what "safe to repeat" means.
- `DurableIntentPrecedesAction` — quantified over *attempts*, not pinned to the
  first. A third attempt that lands is announced by its own record, and checking
  only attempt 1 would let an unannounced retry through.
- `NoSuccessOnUnresolvedDoubt` — a run that timed out on a payment never ends
  green *unless a probe settled the question*. "Unresolved" is doing the work
  here, and it earned its keep: the formula originally forbade success after any
  in-doubt failure at all, which was right only because nothing could resolve
  one. TLC rejected it the moment `Probe` was added.
- `NoQuarantineWithoutAsking` — an effect that could have been asked about is
  never escalated without asking. The complement of the one above: that says a
  run must not claim success it cannot support, this says it must not spend a
  human's attention on a question the provider would have answered.
- `SuccessMeansComplete` — as above: success is structural.

`Probe` is the only rule in any of these specs that reads ground truth
(`DidLand`), and it is legitimate for the same reason it is in production: the
provider knows what it did. `CompleteFromProbe` leaves `world` **unchanged** —
the result was recovered, not produced.

The modelling decision that gives this spec teeth is `FailInDoubt`, where the
world **may or may not** have changed:

```tla
/\ \/ world' = Reach(world, Current)   (* it landed *)
   \/ world' = world                   (* it did not *)
```

TLC explores both branches. Collapsing it to either one would model a runtime
that can tell the difference — and no runtime can, which is the entire problem.
That is the same failure the atomic-`Perform` version of `EffectProtocol` had,
and it is why the mutation pass exists.

Writing this spec found a real gap in the rules: an effect that was *safe* to
repeat, failing in doubt on its final attempt, had no applicable transition and
deadlocked the model. The implementation handled that case; the specification
did not. `GiveUp` now covers it.

**`Saga`**

- `NoUnwindUnderDoubt` — a run holding an effect of unknown outcome compensates
  nothing at all. Undoing everything except the one thing nobody can account for
  is worse than stopping.
- `UnwindIsReverse` — compensation runs in reverse order of completion. A later
  step may depend on what an earlier one set up, so undoing the earlier one first
  can leave the later compensation with nothing to work against.
- `PivotHolds` — nothing at or before a committed pivot is reversed.
- `UndeclaredIsNeverUndone` — a step that changed something and declared no
  compensation is never treated as though it had been undone.
- `CompensationFollowsCompletion` — nothing is undone that was not done.
  Compensating a step that never ran is not a no-op against a real system; it is
  a refund for a charge that never happened.
- `UnwindIsComplete` — the converse, and the one that catches a saga quietly
  leaving work in place: once an unwind runs to the bottom, everything undoable
  that *was* done has been undone. One direction stops a spurious refund; the
  other stops a charge nobody reverses, which is easy to miss because it looks
  like nothing happening.
- `CompensatedAtMostOnce` — a second compensation is a second real action. Not
  free: a compensation may *suspend* (a refund needing four eyes), and the
  resumed unwind re-walks from the top rather than remembering a position, so it
  meets its own completed work coming back down and must recognise it.

The bounds matter more here than anywhere else. The unwind stops at the *first*
stopper it meets going backwards, so a config with the compensatable steps below
the stoppers can never compensate more than one step — and `UnwindIsReverse` and
`CompensatedAtMostOnce` then pass for want of a second element rather than
because the protocol is right. The first version of this model did exactly that,
in 25 states. See [`Saga.cfg`](Saga.cfg).

**`Fencing`**

- `EpochsNeverRegress` — a superseded owner never appends after a takeover.
- `SingleCurrentOwner` — at most one instance believes it holds the current
  epoch.
- `NoWriteAboveCurrentEpoch` — nothing in the journal was written under an epoch
  the store had already moved past.

The interesting state is not a clean handover. It is the instance that was
paused by GC or a partition, was declared dead, had its run taken over, and then
wakes up still believing it owns the run — and tries to keep writing. `Write`'s
epoch guard *is* the store's in-transaction check: there is no window between
"am I still the owner?" and the write, because there is no gap to slip into.

## Running them

`spec/verify.sh` uses Docker and needs nothing else installed. With a local
Java 11+ and [`tla2tools.jar`](https://github.com/tlaplus/tlaplus/releases):

```sh
TLA_JAR=/path/to/tla2tools.jar spec/verify.sh --local
```

To check a single spec by hand:

```sh
java -cp tla2tools.jar tlc2.TLC -config spec/EffectProtocol.cfg spec/EffectProtocol.tla
```

## Bounds

| Constant | Value | Why |
|---|---|---|
| `EffectCount` | 3 | Reaches crash-before-announce, crash-between-announce-and-act, crash-after-act-before-record, and crash-during-replay |
| `MaxCrashes` | 2 | A second crash exercises recovery *of a recovery*; a third adds states without a new shape |
| `EffectCount` (retry) | 3 | With `Mutating = {1,2}` and `Reconcilable = {1}`, one model covers all three shapes: mutating-and-askable, mutating-with-nothing-to-ask, and a read |
| `MaxAttempts` | 3 | Reaches retry-after-retry, where an off-by-one in the attempt bound shows up |
| `StepCount` (saga) | 6 | Three compensatable steps *above* both stoppers, so a run can compensate more than one and the ordering invariants have something to constrain |
| `Instances` | `{1, 2}` | Split-brain is a property of "more than one writer" |
| `MaxSteps` | 6 | Enough for acquire → write → takeover → zombie write |

These are small models. They rule out design errors in the interleavings, not
implementation errors in the Rust — that is what the tests are for.
