#!/usr/bin/env python3
"""Generate a deliberately broken copy of a spec.

Each mutation is a real bug someone could plausibly write. The point of running
them is not to find faults in the *implementation* — it is to find faults in the
*specification*: an invariant that survives its own bug is proving nothing.

Both of this project's specs started out that way. The effect protocol modelled
"act" and "record" as a single atomic step, so the state it exists to rule out —
the action landed, the record did not — was unreachable, and `ExactlyOnce` was
true by construction. It passed. It meant nothing.

Each mutation also names the ONE invariant it must trip. The generated config
checks only that invariant, so a mutation cannot pass by accident — tripping
`Safety` proves only that *something* broke, not that the invariant written to
catch this bug is the one that caught it.

Usage:  mutations.py --list          (tab-separated: mutant, spec, invariant, description)
        mutations.py <mutant> <dir>  (writes <mutant>.tla and <mutant>.cfg)
"""

from __future__ import annotations

import pathlib
import sys

SPEC_DIR = pathlib.Path(__file__).parent

# mutant name -> (source spec, invariant it must trip, description, find, replace)
#
# `find` must appear verbatim in the spec. If it stops matching, the spec has
# moved and the mutation is silently doing nothing — which is an error here,
# because a mutation that changes nothing tests nothing.
MUTATIONS: dict[str, tuple[str, str, str, str, str]] = {
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


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--list":
        for mutant, (spec, invariant, description, _, _) in MUTATIONS.items():
            print(f"{mutant}\t{spec}\t{invariant}\t{description}")
        return 0

    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    mutant, out_dir = sys.argv[1], pathlib.Path(sys.argv[2])
    spec, invariant, _description, find, replace = MUTATIONS[mutant]

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
            f"INVARIANT {invariant}",
            "",
        ]
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{mutant}.tla").write_text(mutated)
    (out_dir / f"{mutant}.cfg").write_text(config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
