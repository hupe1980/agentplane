-------------------------------- MODULE Saga --------------------------------
(***************************************************************************)
(* Undoing a run forward when a later step fails.                          *)
(*                                                                          *)
(* A plan that touches real systems cannot be a transaction — there is       *)
(* nothing to roll back across a payment provider and a warehouse. The saga  *)
(* answer is to compensate completed steps in reverse order.                 *)
(*                                                                          *)
(* Two of the rules here are not the textbook ones, and both come from       *)
(* taking distributed systems seriously rather than tidying up and hoping:   *)
(*                                                                          *)
(*   * A run holding an effect whose outcome is UNKNOWN is never unwound.    *)
(*     Compensating a payment that may never have gone out creates a refund  *)
(*     for money nobody took, and undoing everything around the one thing    *)
(*     nobody can account for is strictly worse than stopping.               *)
(*                                                                          *)
(*   * A step that changed something and declared no compensation stops the  *)
(*     unwind. Reversing the steps around a charge while silently leaving    *)
(*     the charge in place is the outcome the mechanism exists to prevent.   *)
(*                                                                          *)
(* The pivot is the classical rule: once the business has committed, nothing *)
(* before that point is reversed, because the outside world has already      *)
(* acted on it.                                                             *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    StepCount,      (* Steps in the plan, executed in order.                 *)
    MaxSuspends,    (* Bound on waits during an unwind, so TLC terminates.   *)
    Pivots,         (* The points of no return.                              *)
    Unnecessaries,  (* Declared as having nothing to undo.                   *)
    Undeclareds     (* Changed something and said nothing about undoing it.  *)

ASSUME StepCount \in Nat /\ StepCount > 0
ASSUME MaxSuspends \in Nat

Steps == 1 .. StepCount

ASSUME Pivots \subseteq Steps
ASSUME Unnecessaries \subseteq Steps
ASSUME Undeclareds \subseteq Steps

(* Everything not otherwise declared can be undone. *)
Compensatable(s) == s \notin (Pivots \cup Unnecessaries \cup Undeclareds)

VARIABLES
    completed,   (* Seq of steps that finished, in the order they finished.  *)
    undone,      (* Seq of steps compensated, in the order it happened.      *)
    pos,         (* Next step to attempt.                                    *)
    unwindPos,   (* Index into `completed` the unwind is working on.         *)
    doubt,       (* Whether an effect was left with an unknown outcome.      *)
    suspends,    (* How many times a compensation has waited.                *)
    status

vars == <<completed, undone, pos, unwindPos, doubt, suspends, status>>

Contains(s, e) == \E i \in 1 .. Len(s) : s[i] = e

TypeOK ==
    /\ status \in {"running", "unwinding", "waiting", "succeeded", "failed", "quarantined"}
    /\ suspends \in 0 .. MaxSuspends
    /\ pos \in 1 .. (StepCount + 1)
    /\ doubt \in BOOLEAN
    /\ unwindPos \in 0 .. StepCount
    /\ \A i \in 1 .. Len(completed) : completed[i] \in Steps
    /\ \A i \in 1 .. Len(undone) : undone[i] \in Steps

Init ==
    /\ completed = << >>
    /\ undone    = << >>
    /\ pos       = 1
    /\ unwindPos = 0
    /\ doubt     = FALSE
    /\ suspends  = 0
    /\ status    = "running"

-----------------------------------------------------------------------------

(* A step completes. Batches are modelled as repeated `Advance` rather than as  *)
(* a set completing at once: the unwind's obligations depend on *what* ran, not *)
(* on how many ran together, and a step that completed alongside a failing      *)
(* sibling is just a step that completed.                                       *)
Advance ==
    /\ status = "running"
    /\ pos <= StepCount
    /\ completed' = Append(completed, pos)
    /\ pos' = pos + 1
    /\ UNCHANGED <<undone, unwindPos, doubt, suspends, status>>

(* An ordinary failure. Whatever was done is undone. *)
FailCleanly ==
    /\ status = "running"
    /\ pos <= StepCount
    /\ status' = "unwinding"
    /\ unwindPos' = Len(completed)
    /\ UNCHANGED <<completed, undone, pos, doubt, suspends>>

(* A failure that leaves an effect's outcome unknown.                        *)
(*                                                                           *)
(* THE rule this specification exists for: the run stops where it is. Nothing *)
(* is unwound, because unwinding around an unaccounted-for effect can make    *)
(* the damage worse rather than smaller.                                      *)
FailInDoubt ==
    /\ status = "running"
    /\ pos <= StepCount
    /\ doubt' = TRUE
    /\ status' = "quarantined"
    /\ UNCHANGED <<completed, undone, pos, unwindPos, suspends>>

Finish ==
    /\ status = "running"
    /\ pos = StepCount + 1
    /\ status' = "succeeded"
    /\ UNCHANGED <<completed, undone, pos, unwindPos, doubt, suspends>>

-----------------------------------------------------------------------------

Undoing == completed[unwindPos]

(* Reverse order is not a stylistic choice: a later step may depend on what an *)
(* earlier one set up, so undoing the earlier one first can leave the later    *)
(* compensation with nothing to work against.                                  *)
UndoOne ==
    /\ status = "unwinding"
    /\ unwindPos >= 1
    /\ Compensatable(Undoing)
    /\ ~Contains(undone, Undoing)
    /\ undone' = Append(undone, Undoing)
    /\ unwindPos' = unwindPos - 1
    /\ UNCHANGED <<completed, pos, doubt, suspends, status>>

SkipUnnecessary ==
    /\ status = "unwinding"
    /\ unwindPos >= 1
    /\ Undoing \in Unnecessaries
    /\ unwindPos' = unwindPos - 1
    /\ UNCHANGED <<completed, undone, pos, doubt, suspends, status>>

(* The point of no return. Everything from here back stays. *)
StopAtPivot ==
    /\ status = "unwinding"
    /\ unwindPos >= 1
    /\ Undoing \in Pivots
    /\ status' = "failed"
    /\ UNCHANGED <<completed, undone, pos, unwindPos, doubt, suspends>>

(* Nobody said how to undo this, and it changed something. Escalate rather    *)
(* than continue past it.                                                     *)
StopAtUndeclared ==
    /\ status = "unwinding"
    /\ unwindPos >= 1
    /\ Undoing \in Undeclareds
    /\ status' = "quarantined"
    /\ UNCHANGED <<completed, undone, pos, unwindPos, doubt, suspends>>

(* Already compensated, and the journal says so. Reached after a suspended     *)
(* unwind resumes: the run re-walks from the top rather than remembering a      *)
(* position, so it meets its own completed work on the way back down.           *)
SkipAlreadyUndone ==
    /\ status = "unwinding"
    /\ unwindPos >= 1
    /\ Contains(undone, Undoing)
    /\ unwindPos' = unwindPos - 1
    /\ UNCHANGED <<completed, undone, pos, doubt, suspends, status>>

(* A compensation may legitimately wait — a refund that needs four eyes is      *)
(* still a refund. Not a failure: the run is healthy and its frame is durable.  *)
SuspendUnwind ==
    /\ status = "unwinding"
    /\ unwindPos >= 1
    /\ Compensatable(Undoing)
    /\ ~Contains(undone, Undoing)
    /\ suspends < MaxSuspends
    /\ suspends' = suspends + 1
    /\ status' = "waiting"
    /\ UNCHANGED <<completed, undone, pos, unwindPos, doubt>>

(* The answer arrives. The run re-walks the unwind from the top — it does not   *)
(* remember where it was, it reads what it already did. That is what makes      *)
(* `CompensatedAtMostOnce` a real constraint rather than a consequence of       *)
(* keeping a pointer.                                                          *)
ResumeUnwind ==
    /\ status = "waiting"
    /\ status' = "unwinding"
    /\ unwindPos' = Len(completed)
    /\ UNCHANGED <<completed, undone, pos, doubt, suspends>>

(* A compensation can fail like anything else that touches the world. It is    *)
(* not a problem more compensation solves, so the unwind stops here.           *)
UndoFails ==
    /\ status = "unwinding"
    /\ unwindPos >= 1
    /\ Compensatable(Undoing)
    /\ status' = "quarantined"
    /\ UNCHANGED <<completed, undone, pos, unwindPos, doubt, suspends>>

FinishUnwind ==
    /\ status = "unwinding"
    /\ unwindPos = 0
    /\ status' = "failed"
    /\ UNCHANGED <<completed, undone, pos, unwindPos, doubt, suspends>>

Terminal == status \in {"succeeded", "failed", "quarantined"}

Next ==
    \/ Advance
    \/ FailCleanly
    \/ FailInDoubt
    \/ Finish
    \/ UndoOne
    \/ SkipUnnecessary
    \/ SkipAlreadyUndone
    \/ SuspendUnwind
    \/ ResumeUnwind
    \/ StopAtPivot
    \/ StopAtUndeclared
    \/ UndoFails
    \/ FinishUnwind
    \/ (Terminal /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(*                              INVARIANTS                                   *)
-----------------------------------------------------------------------------

(* Nothing is undone that was not done. Compensating a step that never ran is  *)
(* not a no-op against a real system — it is a refund for a charge that never  *)
(* happened.                                                                   *)
CompensationFollowsCompletion ==
    \A i \in 1 .. Len(undone) : Contains(completed, undone[i])

(* Reverse order of completion. Steps complete in increasing order here, so    *)
(* "reverse" is "strictly decreasing".                                          *)
UnwindIsReverse ==
    \A i \in 1 .. (Len(undone) - 1) : undone[i] > undone[i + 1]

(* No step is compensated twice. A second compensation is a second real        *)
(* action against the outside world.                                           *)
CompensatedAtMostOnce ==
    \A i, j \in 1 .. Len(undone) : (undone[i] = undone[j]) => (i = j)

(* Nothing at or before a committed pivot is reversed. *)
PivotHolds ==
    \A i \in 1 .. Len(undone) :
        \A p \in Pivots : Contains(completed, p) => undone[i] > p

(* THE invariant. A run holding an effect of unknown outcome compensates       *)
(* nothing at all.                                                             *)
NoUnwindUnderDoubt ==
    doubt => (Len(undone) = 0)

(* A step that changed something and declared no compensation is never treated *)
(* as though it had been undone.                                               *)
UndeclaredIsNeverUndone ==
    \A i \in 1 .. Len(undone) : undone[i] \notin Undeclareds

(* The converse of `CompensationFollowsCompletion`, and the one that catches a *)
(* saga which quietly leaves work in place.                                     *)
(*                                                                             *)
(* That invariant says nothing is undone that was not done. This says that once *)
(* an unwind runs to the bottom, everything undoable that *was* done has been   *)
(* undone. One direction stops a spurious refund; the other stops a charge that *)
(* nobody reverses, which is the failure that is easy to miss because it looks  *)
(* like nothing happening.                                                      *)
UnwindIsComplete ==
    (status = "failed" /\ unwindPos = 0) =>
        \A i \in 1 .. Len(completed) :
            Compensatable(completed[i]) => Contains(undone, completed[i])

Safety ==
    /\ TypeOK
    /\ CompensationFollowsCompletion
    /\ UnwindIsReverse
    /\ CompensatedAtMostOnce
    /\ PivotHolds
    /\ NoUnwindUnderDoubt
    /\ UndeclaredIsNeverUndone
    /\ UnwindIsComplete

-----------------------------------------------------------------------------
(*                          TEMPORAL PROPERTIES                              *)
-----------------------------------------------------------------------------

(* Compensation only ever grows: an unwind is recorded history, not a scratch  *)
(* pad that gets rewritten. Prefix equality, not merely length — a record of   *)
(* compensations that swapped one entry for another at the same length would   *)
(* still be rewritten history, and a length check would wave it through.       *)
IsPrefixOf(p, s) ==
    /\ Len(p) <= Len(s)
    /\ \A k \in 1 .. Len(p) : s[k] = p[k]

UndoIsAppendOnly == [][IsPrefixOf(undone, undone')]_vars

(* Every run reaches a decision. `quarantined` counts — refusing to unwind is  *)
(* an answer, and the one an auditor can act on.                               *)
Terminates == <>Terminal

=============================================================================
