#!/usr/bin/env python3
"""Generate a deliberately broken copy of a spec.

Each mutation is a real bug someone could plausibly write. The point of running
them is not to find faults in the *implementation* — it is to find faults in the
*specification*: an invariant that survives its own bug is proving nothing.

Both of this project's specs started out that way. The effect protocol modelled
"act" and "record" as a single atomic step, so the state it exists to rule out —
the action landed, the record did not — was unreachable, and `ExactlyOnce` was
true by construction. It passed. It meant nothing.

Each mutation also names the ONE invariant or temporal property it must trip.
The generated config checks only that one, so a mutation cannot pass by
accident — tripping `Safety` proves only that *something* broke, not that the
check written to catch this bug is the one that caught it. A row whose sixth
element is "property" names a temporal property: a liveness claim is only
evidence if dropping the fairness it rests on breaks it.

Usage:  mutations.py --list          (tab-separated: mutant, spec, check, description, kind)
        mutations.py <mutant> <dir>  (writes <mutant>.tla and <mutant>.cfg)
"""

from __future__ import annotations

import pathlib
import sys

SPEC_DIR = pathlib.Path(__file__).parent

# mutant name -> (source spec, check it must trip, description, find, replace[, kind])
#
# `kind` is "invariant" (the default) or "property".
#
# `find` must appear verbatim in the spec. If it stops matching, the spec has
# moved and the mutation is silently doing nothing — which is an error here,
# because a mutation that changes nothing tests nothing.
MUTATIONS: dict[str, tuple[str, ...]] = {
    # Dropping the fairness a liveness claim rests on. If `Terminates` still
    # held, it would be holding for some other reason than the one stated.
    "WeakFairnessDropped": (
        "EffectProtocol",
        "Terminates",
        "the effect protocol is checked without the fairness its termination needs",
        "Spec == Init /\\ [][Next]_vars /\\ WF_vars(Next)",
        "Spec == Init /\\ [][Next]_vars",
        "property",
    ),
    # Retrying an orphaned effect instead of escalating: the tempting,
    # helpful-looking bug that issues the invoice twice.
    "BlindRetry": (
        "EffectProtocol",
        "ExactlyOnce",
        "orphaned effect retried instead of escalated",
        """    /\\ status' = "quarantined"
    /\\ UNCHANGED <<journal, world, pos, inflight, acted, crashes>>""",
        """    /\\ inflight' = Current
    /\\ UNCHANGED <<journal, world, pos, acted, status, crashes>>""",
    ),
    # Acting before the announcement is durable. A crash in between then leaves
    # an action with no trace it was ever attempted — invisible to recovery and
    # to audit.
    "ActBeforeAnnounce": (
        "EffectProtocol",
        "DurableIntentPrecedesAction",
        "action taken before the announcement is durable",
        """    /\\ inflight = Current
    /\\ acted # Current
    /\\ world' = Append(world, Current)""",
        """    /\\ acted # Current
    /\\ world' = Append(world, Current)""",
    ),
    # ── Effect groups ───────────────────────────────────────────────────────
    # Opening the gate before the frontier at all: no invariants, no landed
    # members, no committed transaction. The irreversible send goes out for a
    # group whose preconditions were never checked.
    #
    # The guard is stripped WHOLE rather than one conjunct at a time, and that
    # is not laziness. `txState # "pending"` transitively implies
    # `invariantsHold`, because only `CommitTransaction` clears it and that
    # requires the invariants — so removing `invariantsHold` alone leaves the
    # property true for a second reason and the mutant survives. It did, when
    # the transaction was added: a mutation that had been catching something
    # quietly stopped, which is the decoration-that-looks-like-evidence failure
    # this whole pass exists to find. `GateBeforeTransaction` covers the other
    # conjunct on its own.
    "GateBeforeFrontier": (
        "EffectGroup",
        "DeferredOnlyPastTheFrontier",
        "gated members released before the frontier is reached at all",
        """    /\\ pos = Reversibles + 1
    /\\ invariantsHold
    /\\ txState # "pending"
    /\\ gatePos <= Deferreds""",
        """    /\\ gatePos <= Deferreds""",
    ),
    # Unwinding after an irreversible member has already gone out. This undoes
    # everything EXCEPT the thing that actually happened — the worst of the
    # three answers available, and the one that looks tidiest in a log.
    "ReverseAfterSending": (
        "EffectGroup",
        "NoUnwindPastAnExternalisedDeferred",
        "a group unwinds after a gated member has already externalised",
        """    /\\ (Len(sent) > 0 \\/ txState = "committed")
    /\\ settled' = "quarantined"
    /\\ UNCHANGED <<landed, reversed, sent, pos, gatePos, unwindPos, doubt, invariantsHold,
                   txState>>""",
        """    /\\ (Len(sent) > 0 \\/ txState = "committed")
    /\\ unwindPos' = Len(landed)
    /\\ settled' = "aborting"
    /\\ UNCHANGED <<landed, reversed, sent, pos, gatePos, doubt, invariantsHold, txState>>""",
    ),
    # The bug the implementation actually had: a deferred member failing first
    # takes the cheap abort path without asking whether the atomic members'
    # transaction has committed. The journal then settles "aborted" — taken
    # back whole — over a permanent write with no reversal registered and none
    # possible.
    "AbortAfterTheTransaction": (
        "EffectGroup",
        "AbortIsComplete",
        "a deferred failure after the atomic members committed aborts anyway",
        """    /\\ gatePos \\in BadDeferreds
    /\\ Len(sent) = 0
    /\\ txState # "committed"
    /\\ unwindPos' = Len(landed)""",
        """    /\\ gatePos \\in BadDeferreds
    /\\ Len(sent) = 0
    /\\ unwindPos' = Len(landed)""",
    ),
    # The bug the implementation had a second time, one member deeper: a
    # deferred member that fails having externalised ITSELF (`Landed`, not
    # `InDoubt`) takes the cheap abort. The `!in_doubt` guard read `Landed` as
    # "nothing externalised", so the group settled "aborted" — taken back whole
    # — over a send that went out. Modelled by having the landed failure record
    # itself as sent (it did go out) and then abort anyway.
    "AbortAfterLandedDeferred": (
        "EffectGroup",
        "NoUnwindPastAnExternalisedDeferred",
        "a deferred member that externalised itself before failing aborts anyway",
        """    /\\ sent' = Append(sent, gatePos)
    /\\ settled' = "quarantined"
    /\\ UNCHANGED <<landed, reversed, pos, gatePos, unwindPos, doubt, invariantsHold,
                   txState>>""",
        """    /\\ sent' = Append(sent, gatePos)
    /\\ unwindPos' = Len(landed)
    /\\ settled' = "aborting"
    /\\ UNCHANGED <<landed, reversed, pos, gatePos, doubt, invariantsHold,
                   txState>>""",
    ),
    # Committing a group nobody settled. The most consequential outcome becomes
    # the one an author gets by writing nothing at all.
    "AbandonCommits": (
        "EffectGroup",
        "NoSilentCommit",
        "a group left open is committed rather than taken back",
        """    /\\ unwindPos = 0
    /\\ Len(sent) = 0
    /\\ txState # "committed"
    /\\ unwindPos' = Len(landed)
    /\\ settled' = "aborting"
    /\\ UNCHANGED <<landed, reversed, sent, pos, gatePos, doubt, invariantsHold, txState>>""",
        """    /\\ unwindPos = 0
    /\\ Len(sent) = 0
    /\\ txState # "committed"
    /\\ settled' = "committed"
    /\\ UNCHANGED <<landed, reversed, sent, pos, gatePos, unwindPos, doubt, invariantsHold,
                   txState>>""",
    ),
    # Reporting a group aborted while a member it landed is still standing:
    # a stopped unwind settled as a completed one. The journal says
    # discharged; the hold is still there.
    "AbortLeavesAMemberStanding": (
        "EffectGroup",
        "AbortIsComplete",
        "a stopped unwind reports aborted with a member never taken back",
        """    /\\ Undoing \\in BadReversals
    /\\ settled' = "quarantined\"""",
        """    /\\ Undoing \\in BadReversals
    /\\ settled' = "aborted\"""",
    ),
    # Opening the gate while the transaction is still pending. The gated member
    # announces work that may yet vanish -- and if the transaction then fails,
    # the group can no longer be taken back whole, because the cheap path has
    # already been spent on an email.
    "GateBeforeTransaction": (
        "EffectGroup",
        "TransactionPrecedesTheGate",
        "the gate opens while the atomic members are still uncommitted",
        """    /\\ invariantsHold
    /\\ txState # "pending"
    /\\ gatePos <= Deferreds""",
        """    /\\ invariantsHold
    /\\ gatePos <= Deferreds""",
    ),
    # Retrying an in-doubt failure without checking whether repeating was
    # declared safe. The single most tempting bug in the whole runtime: the
    # call timed out, retrying "obviously" helps, and the payment goes twice.
    "RetryInDoubtBlindly": (
        "RetrySafety",
        "ExactlyOnce",
        "in-doubt failure retried without checking it is safe to repeat",
        """    /\\ FailedWith(Current, attempt, "indoubt")
    /\\ SafeToRepeat(Current)
    /\\ attempt < MaxAttempts""",
        """    /\\ FailedWith(Current, attempt, "indoubt")
    /\\ attempt < MaxAttempts""",
    ),
    # Reporting success for a run that left a mutation in doubt. Nothing is
    # performed twice here — the damage is the green status on a run whose
    # payment may or may not have gone out.
    "DoubtReportedAsSuccess": (
        "RetrySafety",
        "NoSuccessOnUnresolvedDoubt",
        "a run that left a mutation in doubt reports success",
        """       \\/ ReconciledAs(Current, attempt, "indoubt")
    /\\ status' = "quarantined\"""",
        """       \\/ ReconciledAs(Current, attempt, "indoubt")
    /\\ status' = "succeeded\"""",
    ),
    # Acting on an attempt that was never announced, so a crash in the middle
    # leaves a performance with no trace it was attempted.
    "RetryWithoutAnnouncing": (
        "RetrySafety",
        "DurableIntentPrecedesAction",
        "an attempt acts before its announcement is durable",
        """Succeed ==
    /\\ status = "running"
    /\\ inflight = Current""",
        """Succeed ==
    /\\ status = "running"
    /\\ pos <= EffectCount""",
    ),
    # A probe that answers without actually identifying the call — matching on a
    # timestamp, or on "most recent". It looks like reconciliation and is a guess
    # with extra steps, and the guess authorises a real repeat.
    "ProbeMatchesTooLoosely": (
        "RetrySafety",
        "ExactlyOnce",
        "a probe answers without identifying the call it is asking about",
        """    /\\ \\/ /\\ DidLand(Current)
          /\\ journal' = Append(journal, Entry(Current, attempt, "reconciled", "landed"))
       \\/ /\\ ~DidLand(Current)
          /\\ journal' = Append(journal, Entry(Current, attempt, "reconciled", "clean"))
       \\/ journal' = Append(journal, Entry(Current, attempt, "reconciled", "indoubt"))""",
        """    /\\ \\/ journal' = Append(journal, Entry(Current, attempt, "reconciled", "landed"))
       \\/ journal' = Append(journal, Entry(Current, attempt, "reconciled", "clean"))
       \\/ journal' = Append(journal, Entry(Current, attempt, "reconciled", "indoubt"))""",
    ),
    # Escalating to a human without asking the provider first — spending someone's
    # attention on a question that had an answer available.
    "EscalateWithoutAsking": (
        "RetrySafety",
        "NoQuarantineWithoutAsking",
        "a reconcilable effect is escalated without being asked about",
        """    /\\ ~SafeToRepeat(Current)
    /\\ \\/ Current \\notin Reconcilable
       \\/ ReconciledAs(Current, attempt, "indoubt")
    /\\ status' = "quarantined\"""",
        """    /\\ ~SafeToRepeat(Current)
    /\\ status' = "quarantined\"""",
    ),
    # A person answering a quarantine declares the run finished rather than
    # supplying a fact about one call. It is the tempting shape — the operator
    # knows the payment went through, so surely the run is done — and it closes
    # a run over every step it never reached.
    "AnAnswerDeclaresTheRunFinished": (
        "RetrySafety",
        "SuccessMeansComplete",
        "a person answering a quarantine ends the run instead of supplying a fact",
        """       \\/ /\\ ~DidLand(Current)
          /\\ journal' = Append(journal, Entry(Current, attempt, "reconciled", "clean"))
    /\\ status' = "running\"""",
        """       \\/ /\\ ~DidLand(Current)
          /\\ journal' = Append(journal, Entry(Current, attempt, "reconciled", "clean"))
    /\\ status' = "succeeded\"""",
    ),
    # An answer that is not about the world. This is the residue the design
    # states rather than removes: the runtime records who asserted what and
    # cannot check it, so the exactly-once argument rests on the assertion being
    # true. Breaking it here is what makes that dependency visible instead of
    # assumed — an operator who says "it never landed" about a payment that did
    # authorises a real repeat.
    "AnAnswerNeedNotBeAboutTheWorld": (
        "RetrySafety",
        "ExactlyOnce",
        "a person's answer is a preference rather than a fact about the world",
        """    /\\ \\/ /\\ DidLand(Current)
          /\\ journal' = Append(journal, Entry(Current, attempt, "reconciled", "landed"))
       \\/ /\\ ~DidLand(Current)
          /\\ journal' = Append(journal, Entry(Current, attempt, "reconciled", "clean"))
    /\\ status' = "running\"""",
        """    /\\ \\/ journal' = Append(journal, Entry(Current, attempt, "reconciled", "landed"))
       \\/ journal' = Append(journal, Entry(Current, attempt, "reconciled", "clean"))
    /\\ status' = "running\"""",
    ),
    # Unwinding a run that holds an effect of unknown outcome. Tidying up looks
    # responsible and refunds money nobody took.
    "UnwindUnderDoubt": (
        "Saga",
        "NoUnwindUnderDoubt",
        "a run holding an unknown outcome is unwound anyway",
        """    /\\ doubt' = TRUE
    /\\ status' = "quarantined"
    /\\ UNCHANGED <<completed, undone, pos, unwindPos, suspends>>""",
        """    /\\ doubt' = TRUE
    /\\ status' = "unwinding"
    /\\ unwindPos' = Len(completed)
    /\\ UNCHANGED <<completed, undone, pos, suspends>>""",
    ),
    # Reversing past the point of no return, undoing decisions the outside world
    # has already acted on.
    "UnwindPastPivot": (
        "Saga",
        "PivotHolds",
        "the unwind continues past the point of no return",
        """Compensatable(s) == s \\notin (Pivots \\cup Unnecessaries \\cup Undeclareds)""",
        """Compensatable(s) == s \\notin (Unnecessaries \\cup Undeclareds)""",
    ),
    # Treating a step that changed something and declared nothing as undoable.
    "UndoTheUndeclared": (
        "Saga",
        "UndeclaredIsNeverUndone",
        "a step that declared no compensation is undone anyway",
        """Compensatable(s) == s \\notin (Pivots \\cup Unnecessaries \\cup Undeclareds)
""",
        """Compensatable(s) == s \\notin (Pivots \\cup Unnecessaries)
""",
    ),
    # Compensating in completion order instead of reverse. A later step's
    # compensation may depend on what an earlier one set up, so undoing the
    # earlier one first can leave the later one with nothing to work against.
    "UnwindForwards": (
        "Saga",
        "UnwindIsReverse",
        "completed steps are undone in the order they ran",
        """    /\\ undone' = Append(undone, Undoing)""",
        """    /\\ undone' = Append(undone, completed[Len(completed) - unwindPos + 1])""",
    ),
    # A resumed unwind that re-compensates what it already compensated. The
    # run re-walks from the top after a wait, so without the "already undone"
    # guard every suspension replays the refunds below it.
    "RecompensateAfterWaiting": (
        "Saga",
        "CompensatedAtMostOnce",
        "a resumed unwind repeats compensations it already performed",
        """    /\\ Compensatable(Undoing)
    /\\ ~Contains(undone, Undoing)
    /\\ undone' = Append(undone, Undoing)""",
        """    /\\ Compensatable(Undoing)
    /\\ undone' = Append(undone, Undoing)""",
    ),
    # An unwind that skips a step it could have undone. Nothing is performed
    # twice; the damage is the charge nobody reverses, which looks exactly like
    # nothing happening.
    "SkipACompensation": (
        "Saga",
        "UnwindIsComplete",
        "the unwind passes over a step it could have undone",
        """SkipUnnecessary ==
    /\\ status = "unwinding"
    /\\ unwindPos >= 1
    /\\ Undoing \\in Unnecessaries""",
        """SkipUnnecessary ==
    /\\ status = "unwinding"
    /\\ unwindPos >= 1""",
    ),
    # A delegate granted authority its delegator never held. The escalation the
    # whole mechanism exists to make unrepresentable — and the one that looks
    # like a helpful convenience when a sub-agent "just needs one more scope".
    "DelegateCanWiden": (
        "Delegation",
        "ScopeNeverWidens",
        "a delegate is granted authority its delegator does not hold",
        """    /\\ Depth(chain) < MaxDepth
    /\\ s \\subseteq chain[Len(chain)]
    /\\ chain' = Append(chain, s)""",
        """    /\\ Depth(chain) < MaxDepth
    /\\ chain' = Append(chain, s)""",
    ),
    # Trusting a chain that came back from storage. Nothing widens while the
    # chain is being built; the damage arrives through the load path, which is
    # exactly the path nobody thinks of as an authorization boundary.
    "TrustStoredChain": (
        "Delegation",
        "RehydratedChainsAreWellFormed",
        "a chain loaded from storage is trusted rather than re-checked",
        """Rehydrate ==
    /\\ phase = "stored"
    /\\ WellFormed(stored)""",
        """Rehydrate ==
    /\\ phase = "stored\"""",
    ),
    # Re-evaluating policy while replaying. The single most tempting bug in the
    # authorization layer: the gate looks like it belongs on every dispatch, and
    # putting it there means a rule edited today silently re-judges a run from
    # last year — while every hash in the audit trail still checks out.
    "ReplayReEvaluatesPolicy": (
        "Authorization",
        "ReplayNeverConsultsPolicy",
        "policy is re-evaluated while replaying a recorded run",
        """    /\\ RecordKindAt(pos) = "done"
    /\\ pos' = pos + 1
    /\\ UNCHANGED <<mode, journal, world, asked, ruleset, banned, status>>""",
        """    /\\ RecordKindAt(pos) = "done"
    /\\ asked' = asked \\cup {pos}
    /\\ pos' = pos + 1
    /\\ UNCHANGED <<mode, journal, world, ruleset, banned, status>>""",
    ),
    # Stopping on a denial without journaling it. Nothing is performed twice;
    # the damage is a replay that reports divergence for a code change nobody
    # made, which is how a real divergence stops being believed.
    "DenialNotRecorded": (
        "Authorization",
        "DenialIsDurable",
        "a run stops on a denial without recording it",
        """    /\\ asked' = asked \\cup {pos}
    /\\ journal' = Append(journal, [at |-> pos, kind |-> "denied"])
    /\\ status' = "stopped\"""",
        """    /\\ asked' = asked \\cup {pos}
    /\\ UNCHANGED journal
    /\\ status' = "stopped\"""",
    ),
    # Dropping the store's in-transaction epoch check, so a fenced zombie lands
    # a write after its run was taken over. `held[i] >= 1` stays: the writer
    # still only writes under a lease it once acquired — the bug is the store
    # not comparing that lease's epoch against its own.
    "NoFence": (
        "Fencing",
        "EpochsNeverRegress",
        "store accepts a write without checking the epoch",
        """Write(i) ==
    /\\ steps < MaxSteps
    /\\ HoldsCurrent(i)
""",
        """Write(i) ==
    /\\ steps < MaxSteps
    /\\ held[i] >= 1
""",
    ),
    # Treating a renewal as a re-acquisition: the heartbeat bumps the epoch it
    # was only supposed to extend. Every heartbeat then mints a fresh epoch
    # without a takeover, so an epoch in the journal no longer names the
    # ownership change that produced it — and in the variant where the store
    # bumps without telling the caller, the owner is fenced by its own
    # heartbeat. The renew/acquire split is settled, load-bearing semantics;
    # the Rust side of this same bug is pinned by
    # `a_live_lease_blocks_takeover_and_says_so_precisely`
    # (tests/engine/recovery.rs), which asserts a renewal returns the SAME
    # epoch and that `acquire` refuses even the holder's own live lease.
    "RenewAsAcquire": (
        "Fencing",
        "RenewalPreservesOwnership",
        "a renewal bumps the epoch as if it had taken the lease over",
        """    /\\ leaseLive
    /\\ leaseOwner = i
    /\\ held[i] = leaseEpoch
    /\\ steps' = steps + 1
    /\\ UNCHANGED <<leaseEpoch, leaseOwner, leaseLive, takeovers, held, journal>>""",
        """    /\\ leaseLive
    /\\ leaseOwner = i
    /\\ held[i] = leaseEpoch
    /\\ leaseEpoch' = leaseEpoch + 1
    /\\ held' = [held EXCEPT ![i] = leaseEpoch + 1]
    /\\ steps' = steps + 1
    /\\ UNCHANGED <<leaseOwner, leaseLive, takeovers, journal>>""",
    ),
    # The reduction that looks sound. A later checkpoint does establish more
    # about append-only growth, so ranking the anchors and keeping the tallest
    # reads as strictly better evidence — and it selects the fork, because the
    # history an operator feeds a fresh witness is the longest anybody holds.
    #
    # The Rust side of this same bug is pinned by
    # `a_fork_is_caught_by_the_shorter_anchor_the_highest_would_have_hidden`
    # (tests/trust/attestation.rs) and by the `AnAuditKeepsOnlyTheHighestAnchor`
    # row in tools/mutants.py.
    "AuditKeepsTallest": (
        "Equivocation",
        "EveryForkIsSeen",
        "the audit keeps the tallest anchor instead of checking each one",
        """AuditRule(s) == \\E a \\in s : ~Extends(Hist(a), store)""",
        """AuditRule(s) ==
    /\\ s # {}
    /\\ LET tallest == CHOOSE a \\in s : \\A b \\in s : b.size <= a.size
       IN ~Extends(Hist(tallest), store)""",
    ),
    # A witness that signs without recording. It then has nothing to hold the
    # next submission to, so it vouches for two histories itself — the
    # equivocation it exists to refuse, committed by the refusing party. The
    # implementation's remedy is ordering: `seen.insert` happens BEFORE the
    # signature, so a crash between them only ever refuses more.
    "WitnessForgetsWhatItSigned": (
        "Equivocation",
        "NoWitnessVouchesForTwoHistories",
        "a witness cosigns without recording what it vouched for",
        """    /\\ seen' = [seen EXCEPT ![w] = store]""",
        """    /\\ UNCHANGED seen""",
    ),
    # ── Quota ───────────────────────────────────────────────────────────────
    # Counting only the runs still executing: a crashed run's slot row, or a
    # sealed run's not yet given back, stops counting and a second run is
    # admitted beside it.
    "SlotCountIgnoresStoppedRuns": (
        "Quota",
        "AdmissionsWithinCeiling",
        "the slot count skips a crashed or sealed run still holding its row",
        "SlotRoom(t) == Cardinality({r \\in RunsOf(t) : slot[r]}) < MaxConc",
        "SlotRoom(t) == Cardinality({r \\in RunsOf(t) : slot[r] /\\ st[r] = \"exec\" /\\ alive[r]}) < MaxConc",
    ),
    # Settling from the marker alone: the sweep settles a sealed run's
    # recorded passes again after its conclusion already did.
    "RecoverySettlesWithoutTheReceipt": (
        "Quota",
        "PassSettledOnce",
        "a recorded pass is settled again without checking its receipt",
        "Settles(r) == marker[r][passNo[r]] /\\ ~receipt[r][passNo[r]]",
        "Settles(r) == marker[r][passNo[r]]",
    ),
    # Charging the period that is open at settlement rather than the one the
    # pass was authorized in: midnight passes mid-run and both ledgers are
    # wrong.
    "SettleIntoTheClosingPeriod": (
        "Quota",
        "SpendInAdmittedPeriod",
        "a pass is settled into the current period, not the one it started in",
        "SettlePeriod(r) == startedIn[r][passNo[r]]",
        "SettlePeriod(r) == period",
    ),
    # One counter for the whole plane: a tenant at its ceiling refuses
    # another tenant's admission.
    "SharedCounter": (
        "Quota",
        "TenantsIndependent",
        "the slot count is shared between tenants",
        "SlotRoom(t) == Cardinality({r \\in RunsOf(t) : slot[r]}) < MaxConc",
        "SlotRoom(t) == Cardinality({r \\in Runs : slot[r]}) < MaxConc",
    ),
    # The check the reservation replaced: settled spend alone, so suspended
    # runs' holds are invisible and the period is admitted twice over.
    "SettledOnlyCheck": (
        "Quota",
        "PeriodSpendWithinCeiling",
        "admission checks settled spend and ignores outstanding holds",
        "SpendRoom(t) == Settled(t, period) + Reserved(t, period) + Worst <= Ceiling",
        "SpendRoom(t) == Settled(t, period) + Worst <= Ceiling",
    ),
    # A resume in a later period that leaves its remainder counted in the old
    # one: the new period admits against a hold it cannot see.
    "ResumeLeavesItsHoldBehind": (
        "Quota",
        "CarriedHoldFollowsTheResume",
        "a resume does not carry its remainder into the period it resumes in",
        """    /\\ holdPeriod' = [holdPeriod EXCEPT ![r] = period]
    /\\ carried' = [carried EXCEPT ![r] = @ \\/ holdPeriod[r] # period]
    /\\ UNCHANGED <<alive, hold, pending, wrote, marker, receipt, twice, misfiled,""",
        """    /\\ carried' = [carried EXCEPT ![r] = @ \\/ holdPeriod[r] # period]
    /\\ UNCHANGED <<holdPeriod, alive, hold, pending, wrote, marker, receipt, twice, misfiled,""",
    ),
    # Writing the pass marker when the pass starts rather than with its first
    # record: a pass that writes nothing is still settled.
    "MarkerWrittenEagerly": (
        "Quota",
        "NoMarkerNoSettlement",
        "a resumed pass writes its marker before it has written anything",
        """    /\\ UNCHANGED <<alive, hold, pending, wrote, marker, receipt, twice, misfiled,""",
        """    /\\ marker' = [marker EXCEPT ![r][passNo[r] + 1] = TRUE]
    /\\ UNCHANGED <<alive, hold, pending, wrote, receipt, twice, misfiled,""",
    ),
    # Gating a resume on a free slot: a suspended run waits on work that may
    # never finish, stranded mid-saga.
    "ResumeIsGated": (
        "Quota",
        "SuspendedRunsResume",
        "a resume waits for a free slot",
        """    /\\ st[r] = "susp" /\\ passNo[r] < MaxPasses""",
        """    /\\ st[r] = "susp" /\\ passNo[r] < MaxPasses /\\ SlotRoom(Owner[r])""",
        "property",
    ),
    # A sweep that never looks at sealed runs: an instance that died after
    # sealing keeps its tenant's slot forever.
    "SweepSkipsSealedSlots": (
        "Quota",
        "SealedSlotEventuallyReleased",
        "the sweep never releases a sealed run's slot",
        """    /\\ slot[r] /\\ ~alive[r]
    /\\ Settle(r)""",
        """    /\\ slot[r] /\\ ~alive[r] /\\ FALSE
    /\\ Settle(r)""",
        "property",
    ),
    # ── Rate window ─────────────────────────────────────────────────────────
    # A fixed bucket instead of a sliding window: the end of one bucket and
    # the start of the next each admit the ceiling.
    "FixedBucket": (
        "RateWindow",
        "RateWithinWindow",
        "the count is a fixed bucket rather than the window ending now",
        "InWindow(e) == Cardinality({x \\in rows : x.at > e - Window /\\ x.at <= e})",
        "InWindow(e) == Cardinality({x \\in rows : x.at \\div Window = e \\div Window})",
    ),
    # Keying the row by the attempt: every retry spends again.
    "RateKeyNamesTheAttempt": (
        "RateWindow",
        "RetrySpendsOnce",
        "the reservation is keyed by the attempt, not the dispatch",
        "Reserved(r) == \\E x \\in rows : x.run = r",
        "Reserved(r) == \\E x \\in rows : x.run = r /\\ x.a = attempts[r] + 1",
    ),
    # Keying the row by the call alone: a second run's call reads as a retry.
    "RateKeyOmitsTheRun": (
        "RateWindow",
        "EveryDispatchCounted",
        "the reservation is keyed by the call, so two runs share a row",
        "Reserved(r) == \\E x \\in rows : x.run = r",
        "Reserved(r) == rows # {}",
    ),
    # Handing a failed call's row back: the call may well have landed.
    "RefundOnFailure": (
        "RateWindow",
        "RowsNeverRefunded",
        "a failed call's reservation is refunded",
        """    /\\ done' = [done EXCEPT ![r] = "none"]
    /\\ UNCHANGED <<rows, kept, now, attempts>>""",
        """    /\\ done' = [done EXCEPT ![r] = "none"]
    /\\ rows' = {x \\in rows : x.run # r}
    /\\ UNCHANGED <<kept, now, attempts>>""",
    ),
    # Waiting for room instead of refusing: a dispatch that never answers.
    "RateWaitsForRoom": (
        "RateWindow",
        "EveryDispatchAnswered",
        "a full window makes the dispatch wait rather than refuse",
        """            ELSE /\\ done' = [done EXCEPT ![r] = "refused"]
                 /\\ UNCHANGED <<now, rows, kept>>""",
        """            ELSE /\\ FALSE
                 /\\ UNCHANGED <<now, rows, kept, done>>""",
        "property",
    ),
    # ── Sink gate ───────────────────────────────────────────────────────────
    # Keying the gates on the mode: a resume is "replaying", so the whole live
    # tail past its frontier dispatches unjudged.
    "GatesKeyedOnTheMode": (
        "SinkGate",
        "NoSinkWithoutCoveringRelease",
        "the gate is skipped for the whole of a resumed pass",
        "       THEN IF Covered(pc)\n",
        "       THEN IF Covered(pc) \\/ crashes > 0\n",
    ),
    # Re-judging a recorded refusal against today's configuration: a loosened
    # catalogue sends what the run was refused.
    "ReplayReJudges": (
        "SinkGate",
        "ReplayReproducesRefusal",
        "a replay re-judges a recorded refusal against the current configuration",
        "       ELSE UNCHANGED <<journal, world, allowed>>\n",
        "       ELSE IF journal[pc] = \"refused\" /\\ Covered(pc)\n"
        "            THEN /\\ world' = [world EXCEPT ![pc] = @ + 1]\n"
        "                 /\\ UNCHANGED <<journal, allowed>>\n"
        "            ELSE UNCHANGED <<journal, world, allowed>>\n",
    ),
    # Sending a recorded send again instead of reading it back.
    "ReplayResends": (
        "SinkGate",
        "SentOnce",
        "a replay sends a recorded send again",
        "       ELSE UNCHANGED <<journal, world, allowed>>\n",
        "       ELSE /\\ world' = [world EXCEPT ![pc] = IF journal[pc] = \"performed\" THEN @ + 1 ELSE @]\n"
        "            /\\ UNCHANGED <<journal, allowed>>\n",
    ),
    # A refusal that halts the step instead of answering it: the steps after
    # it are never decided.
    "RefusalStallsTheRun": (
        "SinkGate",
        "EverySendIsDecided",
        "a refused send leaves the run stuck at that step",
        "    /\\ pc' = pc + 1\n    /\\ UNCHANGED <<ceiling, released, crashes>>",
        "    /\\ pc' = IF journal'[pc] = \"refused\" THEN pc ELSE pc + 1\n    /\\ UNCHANGED <<ceiling, released, crashes>>",
        "property",
    ),
    # ── Key lifecycle ───────────────────────────────────────────────────────
    # Reading an unreachable key ring as an erased scope: an outage discharges
    # an erasure request nobody carried out.
    "OutageTreatedAsDestroyed": (
        "KeyLifecycle",
        "OutageIsNotErasure",
        "an outage is answered as a destroyed scope",
        """    /\\ verdict' = IF ~reachable THEN "unavailable\"""",
        """    /\\ verdict' = IF ~reachable THEN "destroyed\"""",
    ),
    # A rotation that admits only the newest version: every older payload
    # reads as retired, a policy change no operator made.
    "RotationDropsANamedVersion": (
        "KeyLifecycle",
        "NamedVersionAdmitted",
        "a rotation stops admitting the versions before it",
        "    /\\ admitted' = admitted \\cup {current + 1}",
        "    /\\ admitted' = {current + 1}",
    ),
    # A retried erasure that overwrites the first one's reason.
    "SecondErasureRewritesReason": (
        "KeyLifecycle",
        "ErasureIdempotent",
        "a second destruction rewrites the first one's reason",
        "    /\\ reason' = IF destroyed THEN reason ELSE r",
        "    /\\ reason' = r",
    ),
    # A data key handed out for a destroyed scope: a live run's late write
    # lands in a unit the erasure reported gone.
    "LateWriteReopensScope": (
        "KeyLifecycle",
        "NoWriteIntoErasedScope",
        "a destroyed scope still hands out a data key",
        "    /\\ reachable\n    /\\ ~destroyed\n    /\\ sealed'",
        "    /\\ reachable\n    /\\ sealed'",
    ),
    # A reader that gives up on the first outage: the read ends at
    # *unavailable*, which is no answer about the payload.
    "GiveUpOnOutage": (
        "KeyLifecycle",
        "OutageEventuallyAnswered",
        "a read abandons its payload on the first outage",
        "    /\\ asking' = ~reachable",
        "    /\\ asking' = FALSE",
        "property",
    ),
    # ── Delivery ────────────────────────────────────────────────────────────
    "ConsumedMessageClaimedAgain": (
        "Delivery",
        "ConsumedExactlyOnce",
        "a wait recovers any claim of its run, consumed or not",
        "    /\\ m \\in stored /\\ ~dead[m] /\\ ~consumed[m] /\\ Accepts(r, m)\n"
        "    /\\ \\/ claim[m] = NoRun /\\ ~parked[r]\n"
        "       \\/ claim[m] = Me(r)",
        "    /\\ m \\in stored /\\ ~dead[m] /\\ Accepts(r, m)\n"
        "    /\\ \\/ claim[m] = NoRun /\\ ~parked[r]\n"
        "       \\/ claim[m].run = r",
    ),
    "ParkedWaitClaimsASecondMessage": (
        "Delivery",
        "EveryMessageReachesAWaiter",
        "a wait already holding a claim takes another, which its retirement sheds",
        "    /\\ \\/ claim[m] = NoRun /\\ ~parked[r]\n",
        "    /\\ \\/ claim[m] = NoRun\n",
        "property",
    ),
    "TargetedDeliveryBuffers": (
        "Delivery",
        "TargetedReachesOnlyItsRun",
        "a message for a run not waiting is buffered for whoever waits",
        "       ELSE UNCHANGED <<stored, claim, parked>>",
        "       ELSE /\\ stored' = stored \\cup {m}\n            /\\ UNCHANGED <<claim, parked>>",
    ),
    "AddressedMessageReleased": (
        "Delivery",
        "TargetedReachesOnlyItsRun",
        "a closed run's unconsumed addressed message is offered to another run",
        "                  dead[m] \\/ (Unconsumed(r, m) /\\ targetOf[m] = r)]\n"
        "    /\\ attempt' = [m \\in Msgs |->\n"
        "                     IF Unconsumed(r, m) /\\ targetOf[m] # r THEN \"matching\"",
        "                  dead[m]]\n"
        "    /\\ attempt' = [m \\in Msgs |->\n"
        "                     IF Unconsumed(r, m) THEN \"matching\"",
    ),
    "AnswerAfterConclusion": (
        "Delivery",
        "NoAnswerAfterConclusion",
        "a delivery journals an answer for a run whose conclusion is durable",
        "    /\\ parked[r] /\\ ~concluded[r]\n",
        "    /\\ parked[r]\n",
    ),
    "MatchBeforeDurable": (
        "Delivery",
        "DurableBeforeMatch",
        "a targeted delivery claims a message it never stored",
        "       THEN /\\ stored' = stored \\cup {m}\n            /\\ claim' = [claim EXCEPT ![m] = Me(r)]",
        "       THEN /\\ UNCHANGED stored\n            /\\ claim' = [claim EXCEPT ![m] = Me(r)]",
    ),
    "DedupKeyIgnoresSource": (
        "Delivery",
        "CollidingIdsAreDistinct",
        "the dedup key is the id alone, so another producer's message is a duplicate",
        "Key(m) == <<m.src, m.id>>",
        "Key(m) == m.id",
    ),
    "SenderFilterIgnored": (
        "Delivery",
        "SenderFilterHolds",
        "the matching path ignores a wait's named sender",
        "    /\\ Open(r) /\\ Accepts(r, m)\n    /\\ claim' = [claim EXCEPT ![m] = Me(r)]\n    /\\ parked' = [parked EXCEPT ![r] = TRUE]\n    /\\ attempt'",
        "    /\\ Open(r)\n    /\\ claim' = [claim EXCEPT ![m] = Me(r)]\n    /\\ parked' = [parked EXCEPT ![r] = TRUE]\n    /\\ attempt'",
    ),
    "WakeAppendedTwice": (
        "Delivery",
        "OneWakePerTimer",
        "a re-fired timer records its wake again",
        "IF @ = 0 /\\ ~concluded[r] THEN @ + 1 ELSE @",
        "IF ~concluded[r] THEN @ + 1 ELSE @",
    ),
    "WakeAfterConclusion": (
        "Delivery",
        "NoWakeAfterConclusion",
        "a timer wakes a run whose conclusion is durable",
        "IF @ = 0 /\\ ~concluded[r] THEN @ + 1 ELSE @",
        "IF @ = 0 THEN @ + 1 ELSE @",
    ),
    "RetryAnsweredFromDedup": (
        "Delivery",
        "EveryMessageReachesAWaiter",
        "a counterparty's retry is answered from the dedup and never matched",
        "    /\\ attempt[m] = \"died\"\n    /\\ attempt' = [attempt EXCEPT ![m] = \"matching\"]",
        "    /\\ attempt[m] = \"died\"\n    /\\ attempt' = [attempt EXCEPT ![m] = \"done\"]",
        "property",
    ),
    "ClosedRunShedsItsMessage": (
        "Delivery",
        "EveryMessageReachesAWaiter",
        "a closed run's unconsumed message stays claimed for it",
        "    /\\ claim' = [m \\in Msgs |-> IF Unconsumed(r, m) THEN NoRun ELSE claim[m]]",
        "    /\\ claim' = claim",
        "property",
    ),
    # ── Task delivery ───────────────────────────────────────────────────────
    "DecisionReachesAConcludedRun": (
        "TaskDelivery",
        "NoDecisionReachesAConcludedRun",
        "a decision is journaled for a run whose conclusion is durable",
        "            /\\ IF concluded\n",
        "            /\\ IF FALSE\n",
    ),
    "TaskDecidedTwice": (
        "TaskDelivery",
        "OneDecisionPerTask",
        "a second answer to the task is journaled as another decision",
        "       ELSE /\\ UNCHANGED <<answer, journaled, retired>>",
        "       ELSE /\\ journaled' = journaled \\cup {d}\n            /\\ UNCHANGED <<answer, retired>>",
    ),
    "LostDecisionReportedDelivered": (
        "TaskDelivery",
        "DeciderToldTheTruth",
        "a decision that lost to the run's conclusion is reported as delivered",
        "                    /\\ UNCHANGED <<journaled, told>>",
        "                    /\\ told' = told \\cup {d}\n                    /\\ UNCHANGED journaled",
    ),
    "DecisionAfterWithdrawal": (
        "TaskDelivery",
        "WithdrawnStaysWithdrawn",
        "a settlement moves a task that is no longer pending",
        "    /\\ state' = IF from = \"pending\" THEN to ELSE from",
        "    /\\ state' = to",
    ),
    "WithdrawalNeverRuns": (
        "TaskDelivery",
        "NoTaskOutlivesItsRun",
        "a concluded run's pending task is never withdrawn",
        "    /\\ concluded /\\ ~retired\n    /\\ retired' = TRUE",
        "    /\\ concluded /\\ ~retired /\\ FALSE\n    /\\ retired' = TRUE",
        "property",
    ),
}


def _constants_of(cfg: pathlib.Path) -> str:
    """Lift the CONSTANTS block out of a spec's config.

    Kept verbatim so a mutant is checked at exactly the bounds its spec is, and
    the two cannot drift apart into "the mutant was caught at a smaller model
    than the spec was verified under".
    """
    lines, keeping, out = cfg.read_text().splitlines(), False, []
    for line in lines:
        if line.startswith("CONSTANTS"):
            keeping = True
        elif keeping and line and not line.startswith((" ", "\t")):
            break
        if keeping:
            out.append(line)
    return "\n".join(out) + "\n"


def kind_of(row: tuple[str, ...]) -> str:
    kind = row[5] if len(row) > 5 else "invariant"
    if kind not in ("invariant", "property"):
        raise SystemExit(f"unknown mutation kind '{kind}'")
    return kind


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--list":
        for mutant, row in MUTATIONS.items():
            spec, check, description = row[:3]
            print(f"{mutant}\t{spec}\t{check}\t{description}\t{kind_of(row)}")
        return 0

    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    mutant, out_dir = sys.argv[1], pathlib.Path(sys.argv[2])
    row = MUTATIONS[mutant]
    spec, invariant, _description, find, replace = row[:5]
    kind = kind_of(row)

    source = (SPEC_DIR / f"{spec}.tla").read_text()
    if find not in source:
        print(
            f"mutation '{mutant}' no longer matches {spec}.tla — the spec moved "
            f"and this mutation is testing nothing",
            file=sys.stderr,
        )
        return 1

    mutated = source.replace(f"MODULE {spec}", f"MODULE {mutant}", 1).replace(
        find, replace, 1
    )
    # Check only the targeted invariant, and drop the temporal properties: a
    # mutant is expected to violate safety, and TLC would otherwise also report
    # unrelated liveness failures that muddy which check actually fired.
    config = "\n".join(
        [
            f"\\* Mutant of {spec}: {_description}.",
            f"\\* Must violate {invariant}.",
            "",
            _constants_of(SPEC_DIR / f"{spec}.cfg"),
            "SPECIFICATION Spec",
            "",
            f"{'PROPERTY' if kind == 'property' else 'INVARIANT'} {invariant}",
            "",
        ]
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{mutant}.tla").write_text(mutated)
    (out_dir / f"{mutant}.cfg").write_text(config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
