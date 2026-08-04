----------------------------- MODULE EffectGroup ----------------------------
(***************************************************************************)
(* Several effects that take together, or not at all.                       *)
(*                                                                          *)
(* The saga specification models undo at STEP granularity. This one models   *)
(* the unit below it, and the difference is not a matter of size. A step's    *)
(* compensation is handed the step's OUTPUT, and a step that failed has none, *)
(* so it is asked to guess what to undo. A group's members each register the  *)
(* concrete call that reverses them at the moment they land, so there is      *)
(* nothing to guess.                                                         *)
(*                                                                          *)
(* Three rules here are not in the saga, and each exists because a plausible  *)
(* implementation gets it wrong:                                             *)
(*                                                                          *)
(*   * A DEFERRED member does not run until the group commits. This is the    *)
(*     strongest thing a group offers: an aborted group never performs the    *)
(*     irreversible send at all, rather than performing it and apologising.   *)
(*     The invariants are `DeferredOnlyPastTheFrontier` and                  *)
(*     `AbortIsComplete`.                                                    *)
(*                                                                          *)
(*   * A group that is never settled MUST NOT commit. Committing by omission  *)
(*     would make the most consequential outcome the one an author gets by    *)
(*     writing nothing. The invariant is `NoSilentCommit`.                   *)
(*                                                                          *)
(*   * A deferred member that fails AFTER another has landed quarantines      *)
(*     rather than aborting. Reversing then would undo everything except the  *)
(*     thing that actually happened. The invariant is                         *)
(*     `NoUnwindPastAnExternalisedDeferred`.                                 *)
(*                                                                          *)
(* Doubt is inherited from the saga unchanged: a group holding a member of    *)
(* unknown outcome reverses nothing.                                         *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Reversibles,   (* Members that run eagerly and register a reversal.      *)
    Deferreds,     (* Members held at the gate until commit.                 *)
    BadReversals,  (* Reversals that will not come back.                     *)
    BadDeferreds,  (* Deferred members that fail when released.              *)
    HasAtomic      (* Whether the group has members that commit with the
                      journal, in its own transaction.                       *)

ASSUME Reversibles \in Nat /\ Reversibles > 0
ASSUME Deferreds \in Nat /\ Deferreds >= 0

Members  == 1 .. Reversibles
Gated    == 1 .. Deferreds

ASSUME BadReversals \subseteq Members
ASSUME BadDeferreds \subseteq Gated
ASSUME HasAtomic \in BOOLEAN

VARIABLES
    landed,      (* Seq of reversible members that ran, in landing order.    *)
    reversed,    (* Seq of members taken back, in the order it happened.     *)
    sent,        (* Seq of deferred members actually performed.              *)
    pos,         (* Next reversible member to attempt.                       *)
    gatePos,     (* Next deferred member to release.                         *)
    unwindPos,   (* Index into `landed` the reversal is working on.          *)
    doubt,       (* A member's outcome could not be established.             *)
    invariantsHold,
    txState,     (* The atomic members: "none", "pending", "committed".      *)
    settled      (* "open" until the group ends; then its recorded outcome.  *)

vars == <<landed, reversed, sent, pos, gatePos, unwindPos, doubt,
          invariantsHold, txState, settled>>

Contains(s, e) == \E i \in 1 .. Len(s) : s[i] = e

TypeOK ==
    /\ settled \in {"open", "committed", "aborted", "quarantined"}
    /\ pos \in 1 .. (Reversibles + 1)
    /\ gatePos \in 1 .. (Deferreds + 1)
    /\ unwindPos \in 0 .. Reversibles
    /\ doubt \in BOOLEAN
    /\ invariantsHold \in BOOLEAN
    /\ txState \in {"none", "pending", "committed"}
    /\ \A i \in 1 .. Len(landed)   : landed[i] \in Members
    /\ \A i \in 1 .. Len(reversed) : reversed[i] \in Members
    /\ \A i \in 1 .. Len(sent)     : sent[i] \in Gated

Init ==
    /\ landed         = << >>
    /\ reversed       = << >>
    /\ sent           = << >>
    /\ pos            = 1
    /\ gatePos        = 1
    /\ unwindPos      = 0
    /\ doubt          = FALSE
    /\ invariantsHold \in BOOLEAN   (* Either way; the model explores both.  *)
    /\ txState        = IF HasAtomic THEN "pending" ELSE "none"
    /\ settled        = "open"

-----------------------------------------------------------------------------
(*                          BEFORE THE FRONTIER                              *)
-----------------------------------------------------------------------------

(* A reversible member runs. Its reversal is registered here, from what this  *)
(* call returned — which is the whole difference from a step-level undo.      *)
Land ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos <= Reversibles
    /\ landed' = Append(landed, pos)
    /\ pos' = pos + 1
    /\ UNCHANGED <<reversed, sent, gatePos, unwindPos, doubt, invariantsHold, txState,
                   settled>>

(* An ordinary failure before the frontier. Everything landed is taken back.  *)
FailCleanly ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos <= Reversibles
    /\ unwindPos' = Len(landed)
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, doubt, invariantsHold, txState,
                   settled>>

(* A failure that leaves a member's outcome unknown. Nothing is reversed:     *)
(* undoing a call that may or may not have landed is a coin flip with the      *)
(* outside world's money on it.                                               *)
FailInDoubt ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos <= Reversibles
    /\ doubt' = TRUE
    /\ settled' = "quarantined"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, unwindPos, invariantsHold, txState>>

(* The step walks away without committing or aborting. The runtime settles     *)
(* what the abandoned handle left standing — it does NOT commit.               *)
Abandon ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ Len(sent) = 0
    /\ unwindPos' = Len(landed)
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, doubt, invariantsHold, txState,
                   settled>>

-----------------------------------------------------------------------------
(*                             THE FRONTIER                                  *)
-----------------------------------------------------------------------------

(* Invariants are checked HERE, because this is the last instant at which      *)
(* failing them is free. A broken one takes the group back whole.              *)
FrontierRefused ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos = Reversibles + 1
    /\ gatePos = 1
    /\ ~invariantsHold
    /\ unwindPos' = Len(landed)
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, doubt, invariantsHold, txState,
                   settled>>

(* The atomic members commit, in the journal's own transaction, after the
   invariants and BEFORE the gate. Their write and the record that it happened
   go together, so there is no window between them for a crash to land in.     *)
CommitTransaction ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos = Reversibles + 1
    /\ invariantsHold
    /\ txState = "pending"
    /\ txState' = "committed"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, unwindPos, doubt, invariantsHold,
                   settled>>

(* The transaction did not commit, so nothing in it happened. The group is taken
   back WHOLE — the cheap path, not a quarantine, and that is the property this
   member class exists for. Nothing has been externalised to apologise for.     *)
TransactionFails ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos = Reversibles + 1
    /\ invariantsHold
    /\ txState = "pending"
    /\ unwindPos' = Len(landed)
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, doubt, invariantsHold, txState,
                   settled>>

(* Past the invariants, the gate opens one member at a time. *)
ReleaseDeferred ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos = Reversibles + 1
    /\ invariantsHold
    /\ txState # "pending"
    /\ gatePos <= Deferreds
    /\ gatePos \notin BadDeferreds
    /\ sent' = Append(sent, gatePos)
    /\ gatePos' = gatePos + 1
    /\ UNCHANGED <<landed, reversed, pos, unwindPos, doubt, invariantsHold, txState, settled>>

(* A deferred member fails with NOTHING yet externalised, so the group can     *)
(* still be taken back whole.                                                  *)
DeferredFailsFirst ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos = Reversibles + 1
    /\ invariantsHold
    /\ gatePos <= Deferreds
    /\ gatePos \in BadDeferreds
    /\ Len(sent) = 0
    /\ unwindPos' = Len(landed)
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, doubt, invariantsHold, txState,
                   settled>>

(* A deferred member fails AFTER another has already gone out. Reversing now   *)
(* would undo everything except the thing that actually happened.              *)
DeferredFailsLate ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos = Reversibles + 1
    /\ invariantsHold
    /\ gatePos <= Deferreds
    /\ gatePos \in BadDeferreds
    /\ Len(sent) > 0
    /\ settled' = "quarantined"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, unwindPos, doubt, invariantsHold,
                   txState>>

Commit ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos = Reversibles + 1
    /\ gatePos = Deferreds + 1
    /\ invariantsHold
    /\ txState # "pending"
    /\ settled' = "committed"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, unwindPos, doubt, invariantsHold,
                   txState>>

-----------------------------------------------------------------------------
(*                            TAKING IT BACK                                 *)
-----------------------------------------------------------------------------

Undoing == landed[unwindPos]

(* Newest first: a later member may rest on an earlier one still being there. *)
ReverseOne ==
    /\ settled = "open"
    /\ unwindPos >= 1
    /\ Undoing \notin BadReversals
    /\ ~Contains(reversed, Undoing)
    /\ reversed' = Append(reversed, Undoing)
    /\ unwindPos' = unwindPos - 1
    /\ UNCHANGED <<landed, sent, pos, gatePos, doubt, invariantsHold, txState, settled>>

(* A reversal that will not come back. The unwind STOPS: continuing would      *)
(* take back members around one now in an unknown state.                       *)
ReversalFails ==
    /\ settled = "open"
    /\ unwindPos >= 1
    /\ Undoing \in BadReversals
    /\ settled' = "quarantined"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, unwindPos, doubt, invariantsHold,
                   txState>>

FinishUnwind ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ Len(reversed) = Len(landed)
    /\ Len(landed) > 0
    /\ settled' = "aborted"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, unwindPos, doubt, invariantsHold,
                   txState>>

(* Nothing had landed when the group was abandoned or refused. *)
FinishEmptyUnwind ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ Len(landed) = 0
    /\ pos > 1
    /\ settled' = "aborted"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, unwindPos, doubt, invariantsHold,
                   txState>>

Terminal == settled \in {"committed", "aborted", "quarantined"}

Next ==
    \/ Land
    \/ FailCleanly
    \/ FailInDoubt
    \/ Abandon
    \/ FrontierRefused
    \/ CommitTransaction
    \/ TransactionFails
    \/ ReleaseDeferred
    \/ DeferredFailsFirst
    \/ DeferredFailsLate
    \/ Commit
    \/ ReverseOne
    \/ ReversalFails
    \/ FinishUnwind
    \/ FinishEmptyUnwind
    \/ (Terminal /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(*                              INVARIANTS                                   *)
-----------------------------------------------------------------------------

(* THE invariant, and the reason a group beats a saga for an irreversible      *)
(* send. A gated member runs only PAST the frontier: every reversible member    *)
(* landed, the invariants hold, and no unwind is in progress.                   *)
(*                                                                             *)
(* Stated over the frontier rather than over `settled`, because a member is     *)
(* legitimately released while the group is still open — commit is what         *)
(* follows the last release, not what precedes the first. The other half of     *)
(* the property, that an ABORTED group sent nothing, is `AbortIsComplete`.      *)
DeferredOnlyPastTheFrontier ==
    (Len(sent) > 0) =>
        (/\ pos = Reversibles + 1
         /\ invariantsHold
         /\ unwindPos = 0)

(* A group nobody settled does not commit. The safe reading of a forgotten      *)
(* group is that it was never meant to take; the alternative makes the most     *)
(* consequential outcome the one you get by writing nothing.                    *)
NoSilentCommit ==
    (settled = "committed") =>
        (/\ pos = Reversibles + 1
         /\ gatePos = Deferreds + 1
         /\ invariantsHold)

(* Nothing is taken back that never happened. *)
ReversalFollowsLanding ==
    \A i \in 1 .. Len(reversed) : Contains(landed, reversed[i])

(* Reverse landing order. Members land in increasing order here, so "reverse"  *)
(* is "strictly decreasing".                                                   *)
ReversalIsBackwards ==
    \A i \in 1 .. (Len(reversed) - 1) : reversed[i] > reversed[i + 1]

(* No member is reversed twice. A second reversal is a second real action.     *)
ReversedAtMostOnce ==
    \A i, j \in 1 .. Len(reversed) : (reversed[i] = reversed[j]) => (i = j)

(* Doubt reverses nothing. *)
NoUnwindUnderDoubt ==
    doubt => (Len(reversed) = 0)

(* Once a deferred member is out in the world, the group is never taken back:  *)
(* reversing then undoes everything except the thing that actually happened.   *)
NoUnwindPastAnExternalisedDeferred ==
    (Len(sent) > 0) => (Len(reversed) = 0)

(* The transaction commits before anything is told about it.
   
   The ordering that makes the two classes compose. A gated member released
   while the transaction was still pending would announce work that may yet
   vanish, and a transaction that failed afterwards could no longer be taken
   back whole — the cheap path would be gone, spent on an email.              *)
TransactionPrecedesTheGate ==
    (Len(sent) > 0) => (txState # "pending")

(* An aborted group has nothing standing: every member that landed was taken   *)
(* back, and no gated member ever ran. The converse of                         *)
(* `ReversalFollowsLanding` — one direction stops a spurious undo, this one    *)
(* stops a hold that nobody releases while the journal says discharged.        *)
AbortIsComplete ==
    (settled = "aborted") =>
        (/\ \A i \in 1 .. Len(landed) : Contains(reversed, landed[i])
         /\ Len(sent) = 0)

(* A committed group performed every gated member. "Committed" must not mean   *)
(* "committed except the email".                                               *)
CommitIsComplete ==
    (settled = "committed") => (Len(sent) = Deferreds)

Safety ==
    /\ TypeOK
    /\ DeferredOnlyPastTheFrontier
    /\ NoSilentCommit
    /\ ReversalFollowsLanding
    /\ ReversalIsBackwards
    /\ ReversedAtMostOnce
    /\ NoUnwindUnderDoubt
    /\ NoUnwindPastAnExternalisedDeferred
    /\ TransactionPrecedesTheGate
    /\ AbortIsComplete
    /\ CommitIsComplete

-----------------------------------------------------------------------------
(*                          TEMPORAL PROPERTIES                              *)
-----------------------------------------------------------------------------

(* A reversal is recorded history, not a scratch pad. *)
ReversalIsAppendOnly == [][Len(reversed') >= Len(reversed)]_vars

(* Every group reaches a recorded outcome. `quarantined` counts — refusing to  *)
(* decide is a decision, and the one an operator can act on. An `open` group    *)
(* that never settles is the state this rules out.                             *)
AlwaysSettles == <>Terminal

=============================================================================
