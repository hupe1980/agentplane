# Formal specifications

TLA+ models covering the parts of the runtime that must be unconditionally
correct, and that are hardest to convince yourself of by reading code:

| Spec | Question it answers |
|---|---|
| [`EffectProtocol.tla`](EffectProtocol.tla) | Can a crash — anywhere — cause an effect to be performed twice, or to happen with no durable trace? |
| [`RetrySafety.tla`](RetrySafety.tla) | When a call fails without saying whether it landed, is repeating it ever safe — and does asking the provider help? |
| [`Saga.tla`](Saga.tla) | When a step fails, what may be undone — and what must be left exactly where it is? |
| [`EffectGroup.tla`](EffectGroup.tla) | Below a step: when several calls must take together, what may be held until the group is certain, what commits *with* the journal, and what can no longer be taken back? |
| [`Fencing.tla`](Fencing.tla) | Can a paused instance wake up after its run was taken over and still land a write? |
| [`Authorization.tla`](Authorization.tla) | Can a replay re-open a decision policy already made, and is a refusal always on the record? |
| [`Delegation.tla`](Delegation.tla) | Can authority grow as it is passed on, and is a chain read from storage trusted or re-checked? |
| [`Quota.tla`](Quota.tla) | Can a period's admitted work settle past its ceiling — through suspended holds, crashes, recovery, a period boundary mid-pass or a resume in a later period — and does one tenant's ceiling ever refuse another's work? |
| [`RateWindow.tla`](RateWindow.tla) | Does a rate ceiling hold over every window ending now, with a retry spending once and two runs' identical calls each spending? |
| [`SinkGate.tla`](SinkGate.tla) | Is every value judged where it is sent live — a resume's live tail included — and is a recorded verdict read back on replay rather than judged again under an edited configuration? |
| [`KeyLifecycle.tla`](KeyLifecycle.tla) | Is an outage ever reported as an erasure, does a rotation drop a version still admitted, and can a destroyed scope be written into again? |
| [`Delivery.tla`](Delivery.tla) | Is each inbound message journaled once, by the one wait that took it — through crashes between store and match, a run concluding first, a second turn on one key, and a message sent to one run by name — and is a timer's wake recorded at most once? |
| [`TaskDelivery.tla`](TaskDelivery.tla) | Does a human task's answer reach its run at most once, never after its conclusion, and is a decider told the truth when the run concluded first? |
| [`Equivocation.tla`](Equivocation.tla) | An operator shows two histories of one log. Which reader still sees it — and which way of combining several witnesses' answers stops seeing it? |

These check the **design**. The implementation is checked against deliberately
the same invariant list by deterministic fault injection at the store seam
(`testkit::faults`, which explains why that seam rather than a simulated
runtime), and the integration tests check observable behaviour. Each layer
catches what the others structurally cannot: a model checker explores
interleavings no test will think of, and a test catches the gap between the
model and the code.

## Status

Every spec is model-checked exhaustively on every push, and every mutant of
them is checked too:

| Spec | Result | State space |
|---|---|---|
| `EffectProtocol` | verified | 113 distinct states |
| `RetrySafety` | verified | 30265 distinct states |
| `Saga` | verified | 63 distinct states |
| `EffectGroup` | verified | 110 distinct states |
| `Fencing` | verified | 231 distinct states |
| `Authorization` | verified | 32 distinct states |
| `Delegation` | verified | 9510 distinct states |
| `Equivocation` | verified | 7086 distinct states |
| `Quota` | verified | 333716 distinct states |
| `RateWindow` | verified | 196 distinct states |
| `SinkGate` | verified | 190 distinct states |
| `KeyLifecycle` | verified | 408 distinct states |
| `Delivery` | verified | 62676 distinct states |
| `TaskDelivery` | verified | 32 distinct states |

The counts are TLC's `distinct states found`, and the command below is what
derives them — if a number here disagrees with what it prints, the number
here is the one that is wrong:

```sh
tla/verify.sh              # Docker; no local Java needed
tla/verify.sh --only Quota  # one spec and its mutants
```

Every `.tla` here is checked: there is no list to add a new spec to, and one
without a `.cfg` fails the run.

## Why the mutants matter more than the specs

A spec whose mutants also pass is decoration that looks like evidence. Modelling
"act" and "record" as a *single atomic step*, for example, makes the one state
the protocol exists to survive — the action landed, the process died before
recording it — **unreachable**, so `ExactlyOnce` holds by construction and TLC
reports no errors. Reading the spec does not reveal that; mutating it does.

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
| A person's answer is a preference rather than a fact about the world | `RetrySafety` | `ExactlyOnce` |
| A person answering a quarantine ends the run instead of supplying a fact | `RetrySafety` | `SuccessMeansComplete` |
| A run holding an unknown outcome is unwound anyway | `Saga` | `NoUnwindUnderDoubt` |
| The unwind continues past the point of no return | `Saga` | `PivotHolds` |
| A step that declared no compensation is undone anyway | `Saga` | `UndeclaredIsNeverUndone` |
| Completed steps are undone in the order they ran | `Saga` | `UnwindIsReverse` |
| A resumed unwind repeats compensations it already performed | `Saga` | `CompensatedAtMostOnce` |
| The unwind passes over a step it could have undone | `Saga` | `UnwindIsComplete` |
| Gated members released before the frontier is reached at all | `EffectGroup` | `DeferredOnlyPastTheFrontier` |
| The gate opens while the atomic members are still uncommitted | `EffectGroup` | `TransactionPrecedesTheGate` |
| A group unwinds after a gated member has already externalised | `EffectGroup` | `NoUnwindPastAnExternalisedDeferred` |
| A deferred failure after the atomic members committed aborts anyway | `EffectGroup` | `AbortIsComplete` |
| A deferred member that externalised itself before failing aborts anyway | `EffectGroup` | `NoUnwindPastAnExternalisedDeferred` |
| A group left open is committed rather than taken back | `EffectGroup` | `NoSilentCommit` |
| A stopped unwind reports aborted with a member never taken back | `EffectGroup` | `AbortIsComplete` |
| Store accepts a write without checking the epoch | `Fencing` | `EpochsNeverRegress` |
| A renewal bumps the epoch as if it had taken the lease over | `Fencing` | `RenewalPreservesOwnership` |
| A delegate is granted authority its delegator does not hold | `Delegation` | `ScopeNeverWidens` |
| A chain loaded from storage is trusted rather than re-checked | `Delegation` | `RehydratedChainsAreWellFormed` |
| Policy is re-evaluated while replaying a recorded run | `Authorization` | `ReplayNeverConsultsPolicy` |
| A run stops on a denial without recording it | `Authorization` | `DenialIsDurable` |
| The audit keeps the tallest anchor instead of checking each one | `Equivocation` | `EveryForkIsSeen` |
| A witness cosigns without recording what it vouched for | `Equivocation` | `NoWitnessVouchesForTwoHistories` |
| The effect protocol is checked without the fairness its termination needs | `EffectProtocol` | `Terminates` (property) |
| The slot count skips a crashed or sealed run still holding its row | `Quota` | `AdmissionsWithinCeiling` |
| A recorded pass is settled again without checking its receipt | `Quota` | `PassSettledOnce` |
| A pass is settled into the current period, not the one it started in | `Quota` | `SpendInAdmittedPeriod` |
| The slot count is shared between tenants | `Quota` | `TenantsIndependent` |
| Admission checks settled spend and ignores outstanding holds | `Quota` | `PeriodSpendWithinCeiling` |
| A resume does not carry its remainder into the period it resumes in | `Quota` | `CarriedHoldFollowsTheResume` |
| A resumed pass writes its marker before it has written anything | `Quota` | `NoMarkerNoSettlement` |
| A resume waits for a free slot | `Quota` | `SuspendedRunsResume` (property) |
| The sweep never releases a sealed run's slot | `Quota` | `SealedSlotEventuallyReleased` (property) |
| The count is a fixed bucket rather than the window ending now | `RateWindow` | `RateWithinWindow` |
| The reservation is keyed by the attempt, not the dispatch | `RateWindow` | `RetrySpendsOnce` |
| The reservation is keyed by the call, so two runs share a row | `RateWindow` | `EveryDispatchCounted` |
| A failed call's reservation is refunded | `RateWindow` | `RowsNeverRefunded` |
| A full window makes the dispatch wait rather than refuse | `RateWindow` | `EveryDispatchAnswered` (property) |
| The gate is skipped for the whole of a resumed pass | `SinkGate` | `NoSinkWithoutCoveringRelease` |
| A replay re-judges a recorded refusal against the current configuration | `SinkGate` | `ReplayReproducesRefusal` |
| A replay sends a recorded send again | `SinkGate` | `SentOnce` |
| A refused send leaves the run stuck at that step | `SinkGate` | `EverySendIsDecided` (property) |
| An outage is answered as a destroyed scope | `KeyLifecycle` | `OutageIsNotErasure` |
| A rotation stops admitting the versions before it | `KeyLifecycle` | `NamedVersionAdmitted` |
| A second destruction rewrites the first one's reason | `KeyLifecycle` | `ErasureIdempotent` |
| A destroyed scope still hands out a data key | `KeyLifecycle` | `NoWriteIntoErasedScope` |
| A read abandons its payload on the first outage | `KeyLifecycle` | `OutageEventuallyAnswered` (property) |
| A wait recovers any claim of its run, consumed or not | `Delivery` | `ConsumedExactlyOnce` |
| A wait already holding a claim takes another, which its retirement sheds | `Delivery` | `EveryMessageReachesAWaiter` (property) |
| A message for a run not waiting is buffered for whoever waits | `Delivery` | `TargetedReachesOnlyItsRun` |
| A closed run's unconsumed addressed message is offered to another run | `Delivery` | `TargetedReachesOnlyItsRun` |
| A delivery journals an answer for a run whose conclusion is durable | `Delivery` | `NoAnswerAfterConclusion` |
| A targeted delivery claims a message it never stored | `Delivery` | `DurableBeforeMatch` |
| The dedup key is the id alone, so another producer's message is a duplicate | `Delivery` | `CollidingIdsAreDistinct` |
| The matching path ignores a wait's named sender | `Delivery` | `SenderFilterHolds` |
| A re-fired timer records its wake again | `Delivery` | `OneWakePerTimer` |
| A timer wakes a run whose conclusion is durable | `Delivery` | `NoWakeAfterConclusion` |
| A counterparty's retry is answered from the dedup and never matched | `Delivery` | `EveryMessageReachesAWaiter` (property) |
| A closed run's unconsumed message stays claimed for it | `Delivery` | `EveryMessageReachesAWaiter` (property) |
| A decision is journaled for a run whose conclusion is durable | `TaskDelivery` | `NoDecisionReachesAConcludedRun` |
| A second answer to the task is journaled as another decision | `TaskDelivery` | `OneDecisionPerTask` |
| A decision that lost to the run's conclusion is reported as delivered | `TaskDelivery` | `DeciderToldTheTruth` |
| A settlement moves a task that is no longer pending | `TaskDelivery` | `WithdrawnStaysWithdrawn` |
| A concluded run's pending task is never withdrawn | `TaskDelivery` | `NoTaskOutlivesItsRun` (property) |

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
cannot be built.

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
  green *unless a probe settled the question*.
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
that can tell the difference — and no runtime can. `GiveUp` covers an effect
that was *safe* to repeat failing in doubt on its final attempt.

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
because the protocol is right. See [`Saga.cfg`](Saga.cfg).

**`EffectGroup`**

The unit below a step. A step's compensation is handed the step's *output*, and
a step that failed has none — so it is asked to guess what to undo. A group's
members register the concrete call that reverses them at the moment they land,
which is why this spec can talk about completeness at all.

- `DeferredOnlyPastTheFrontier` — a gated member runs only once every reversible
  member has landed and the invariants hold. Stated over the frontier rather
  than over the outcome, because a member is legitimately released while the
  group is still open: commit is what *follows* the last release, not what
  precedes the first.
- `AbortIsComplete` — an aborted group has nothing standing: every member that
  landed was taken back, no gated member ever ran, and the atomic members never
  committed. The third conjunct is the atomic form of the same lie — a
  transaction's writes are permanent and have no registered reversal, so
  "aborted" over a committed transaction is the journal saying *taken back
  whole* over a ledger row that stands. This is the half that makes deferral
  worth having, and the one that catches a group reporting *discharged* while a
  hold is still in place.
- `NoSilentCommit` — a group nobody settled does not commit. The safe reading of
  a forgotten group is that it was never meant to take; the alternative makes
  the most consequential outcome the one an author gets by writing nothing.
- `NoUnwindPastAnExternalisedDeferred` — once an irreversible member is out in
  the world, the group is never taken back. Reversing then undoes everything
  *except* the thing that actually happened, which is the worst of the three
  answers available and the one that looks tidiest in a log.
- `TransactionPrecedesTheGate` — atomic members commit before anything is told
  about it. A gated member released while the transaction was still pending
  would announce work that may yet vanish; and if the transaction then failed,
  the group could no longer be taken back whole, because the cheap path would
  already have been spent on an email.
- `CommitIsComplete` — "committed" must not mean "committed except the email".
- `NoUnwindUnderDoubt`, `ReversalIsBackwards`, `ReversedAtMostOnce`,
  `ReversalFollowsLanding` — the saga's rules, restated at member granularity.
- `AlwaysSettles` (temporal) — no group stays open forever. `quarantined` counts:
  refusing to decide is a decision, and the one an operator can act on.

The constants carry the same weight they do in `Saga`. Two gated members are the
minimum that distinguishes "the first one failed" from "one already went out",
and the second case is the only way `NoUnwindPastAnExternalisedDeferred` is
reachable at all. With one gated member it would pass vacuously. See
[`EffectGroup.cfg`](EffectGroup.cfg).

**`Authorization`**

- `ReplayNeverConsultsPolicy` — the load-bearing one. If policy were re-evaluated
  during replay, editing a rule would silently re-judge last year's run under
  this year's rules, and the audit trail would quietly become a lie.
- `DenialIsDurable` — a run that stopped on a denial recorded that it did.
  Without the record, replay reaches that point, finds no history, and reports
  "this build performs more effects than the recorded one" — sending an operator
  to look for a code change that does not exist.
- `NothingForbiddenIsPerformed` — nothing reaches the world that policy refused.
- `ReplayPerformsNothing` — a replay dispatches nothing at all, so re-judging is
  not merely forbidden but impossible.
- `NoRedundantPermitRecords` — a *permit* gets no record. The effect's own
  `EffectStarted` is already the evidence that it was allowed, and journaling
  "yes" beside every call doubles the log to say nothing.

Denial is an initial-state *choice* (`banned \in SUBSET Forbidden`), not a
constant fate: the run that permits everything reaches `done` and replays to
`ReplayFinish`, the run with a refusal stops at `LiveDeny` and replays to
`ReplayDenied`. An unconditional `Forbidden` would force every live run into
the denial and leave `LiveFinish` / `ReplayFinish` dead — see
[`Authorization.cfg`](Authorization.cfg).

**`Delegation`**

- `ScopeNeverWidens` — authority only narrows as it is passed on. A delegate that
  could be granted something its delegator does not hold is not delegation; it is
  privilege escalation with paperwork.
- `RehydratedChainsAreWellFormed` — a chain read back from storage is re-checked
  rather than trusted. Storage is not an authority: a chain that was valid when
  written and a chain that was edited afterwards look identical on the way in.
- `NoLinkExceedsTheOwner` — no link anywhere in a chain holds more than the
  original owner did. Mathematically this adds nothing: subset containment is
  transitive, so it is implied by `ScopeNeverWidens` — authority *cannot* be
  laundered across hops that each genuinely narrow. It is stated separately
  because it is the question an auditor actually asks ("could this agent have
  done something the person who authorized it could not?"), asked directly
  against the owner rather than reconstructed hop by hop — and because it must
  keep holding for any chain that reaches the model by a path the adjacent-pair
  check did not walk.
- `DepthIsBounded` — the chain cannot grow without limit.

**`Fencing`**

- `EpochsNeverRegress` — a superseded owner never appends after a takeover.
- `SingleCurrentOwner` — at most one instance holds the current epoch, stated
  over the *same predicate the store's fence enforces on writes* — so it reads
  "at most one instance can append", not "a value pattern holds".
- `NoWriteAboveCurrentEpoch` — nothing in the journal was written under an epoch
  the store had already moved past, or never issued.
- `RenewalPreservesOwnership` — a renewal never moves the epoch or the owner:
  the epoch counts takeovers, exactly, and a live lease is held by the instance
  whose remembered epoch is current. Acquire and renew are different verbs with
  different failure modes (`src/journal/store.rs`): `acquire` is a pure claim
  that always bumps the epoch and refuses even the holder's own live lease;
  `renew` extends a lease still verifiably held — same owner, same epoch,
  unexpired, unreleased — and never bumps, because a bump would fence the owner
  against its own in-flight writes. The `RenewAsAcquire` mutant is the spec-side
  twin of the Rust test `a_live_lease_blocks_takeover_and_says_so_precisely`
  (`tests/engine/recovery.rs`), which pins the same split in the implementation.

The interesting state is not a clean handover. It is the instance that was
paused by GC or a partition, had its lease lapse, had its run taken over, and
then wakes up still believing it owns the run — and tries to keep writing.
`Write`'s epoch guard *is* the store's in-transaction check
(`src/store/redb.rs`: `if epoch != current`), and it is exact equality: a stale
epoch is fenced, and an epoch above the store's is a writer inventing authority.
There is no window between "am I still the owner?" and the write, because there
is no gap to slip into.

## Running them

`tla/verify.sh` uses Docker and needs nothing else installed. With a local
Java 11+ and [`tla2tools.jar`](https://github.com/tlaplus/tlaplus/releases):

```sh
TLA_JAR=/path/to/tla2tools.jar tla/verify.sh --local
```

To check a single spec by hand:

```sh
java -cp tla2tools.jar tlc2.TLC -config tla/EffectProtocol.cfg tla/EffectProtocol.tla
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
| `MaxSteps` | 6 | Enough for acquire → renew → write → lapse → takeover → write, and for the fenced zombie attempt after a takeover |

## Liveness

Safety is what these models exist for, but each one also states its liveness
assumptions explicitly rather than leaving them implied:

- `EffectProtocol`, `RetrySafety`, `Saga`, `EffectGroup` assume weak fairness
  over `Next` and check termination (`Terminates` / `AlwaysSettles`): every
  run reaches a recorded outcome, with `quarantined` counting as one.
- `Authorization` assumes weak fairness over `Next` and checks `Settles`: a
  run — and its replay, if one starts — comes to rest at `stopped` or `done`.
- `Fencing` assumes weak fairness over `Next` and checks `RunsItsCourse`: no
  interleaving of acquire/renew/expire/write livelocks short of the step bound.
- `Delegation` assumes weak fairness on `Store` and on the load verdict
  (`Rehydrate \/ RejectRehydrate` — one of the two is enabled in every stored
  state) and checks `EveryChainIsJudged`: a chain that is built is eventually
  stored and then accepted or refused, however storage is tampered with.

- `Quota` assumes weak fairness on `Resume`, on a sealed run's own slot
  release and on the sweep, and checks `SuspendedRunsResume` and
  `SealedSlotEventuallyReleased`. A deployment that schedules no sweep keeps a
  dead instance's sealed slot; the property says what the sweep is for.
- `RateWindow` assumes weak fairness on `Reserve` and checks
  `EveryDispatchAnswered`: a dispatch is sent or refused, never left waiting
  for room. Time is not assumed to advance.

- `SinkGate` assumes weak fairness on `Send` and checks `EverySendIsDecided`.
- `KeyLifecycle` assumes weak fairness on `Restore` and strong fairness on
  opening while the key ring answers — a ring that keeps failing could
  otherwise catch every attempt down — and checks `OutageEventuallyAnswered`.
- `Delivery` assumes the plane's own steps are weakly fair and that a
  counterparty retries a delivery that got no answer, and checks
  `EveryMessageReachesAWaiter`. Nothing is assumed to send or conclude.
- `TaskDelivery` assumes weak fairness on answering a held claim and on the
  withdrawal, and checks `NoTaskOutlivesItsRun`.

A row marked *(property)* drops or bends what a liveness claim rests on and
must make TLC report a temporal violation.

The fairness conjuncts are scheduling assumptions about the runtime, not
correctness claims; the comments beside each `Spec` say exactly what is being
assumed. The append-only temporal properties (`JournalIsAppendOnly`,
`WorldIsAppendOnly`, `UndoIsAppendOnly`, `ReversalIsAppendOnly`) check *prefix
equality*, not merely length — a history that swapped one record for another
at the same length would still be a rewritten history.

These are small models. They rule out design errors in the interleavings, not
implementation errors in the Rust — that is what the tests are for.
