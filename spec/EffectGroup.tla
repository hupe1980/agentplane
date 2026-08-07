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
(*   * A deferred member that fails AFTER something externalised — another    *)
(*     deferred member, or the atomic members' transaction — quarantines      *)
(*     rather than aborting. Reversing then would undo everything except the  *)
(*     thing that actually happened, and an "aborted" settlement would claim  *)
(*     the group was taken back whole while a permanent write stands. The     *)
(*     invariants are `NoUnwindPastAnExternalisedDeferred` and                *)
(*     `AbortIsComplete`.                                                    *)
(*                                                                          *)
(*   * A deferred member that fails having externalised ITSELF — it reached   *)
(*     the world and then its response could not be used (`Landed`) — is the   *)
(*     same shape a member deep. The failure carries the evidence that the     *)
(*     call took effect, so it too quarantines, even as the FIRST deferred     *)
(*     with nothing else out. Modelling this failure as not-externalised is    *)
(*     the misreading that let a deferred member returning `Landed` take the   *)
(*     cheap abort; `DeferredFailsLanded` records it as sent.                  *)
(*                                                                          *)
(* Doubt is inherited from the saga unchanged: a group holding a member of    *)
(* unknown outcome reverses nothing.                                         *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Reversibles,   (* Members that run eagerly and register a reversal.      *)
    Deferreds,     (* Members held at the gate until commit.                 *)
    BadReversals,  (* Reversals that MAY not come back — a choice, like
                      BadDeferreds, so the unwind that completes and the
                      unwind that stops partway are both reachable.          *)
    BadDeferreds   (* Deferred members that MAY fail when released — failure
                      is nondeterministic, not fated, so one model reaches
                      both the member sending and the member failing.        *)

ASSUME Reversibles \in Nat /\ Reversibles > 0
ASSUME Deferreds \in Nat /\ Deferreds >= 0

Members  == 1 .. Reversibles
Gated    == 1 .. Deferreds

ASSUME BadReversals \subseteq Members
ASSUME BadDeferreds \subseteq Gated

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
    settled      (* "open" while members run, "aborting" while the unwind    *)
                 (* takes them back, then the recorded outcome. The        *)
                 (* explicit unwinding state is load-bearing: encoding      *)
                 (* "unwinding" as unwindPos alone conflates a finished     *)
                 (* unwind with a run that never failed, and the forward    *)
                 (* transitions fire again after a completed unwind.        *)

vars == <<landed, reversed, sent, pos, gatePos, unwindPos, doubt,
          invariantsHold, txState, settled>>

Contains(s, e) == \E i \in 1 .. Len(s) : s[i] = e

TypeOK ==
    /\ settled \in {"open", "aborting", "committed", "aborted", "quarantined"}
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
    (* "pending" is a group with atomic members, "none" one without. An       *)
    (* initial-state choice rather than a constant, so one model run explores *)
    (* both — a constant would leave whichever value the config omitted       *)
    (* entirely unchecked, which is how the abort-after-commit hole survived  *)
    (* its first model.                                                       *)
    /\ txState        \in {"none", "pending"}
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
    /\ settled' = "aborting"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, doubt, invariantsHold, txState>>

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
(*                                                                             *)
(* Guarded on the transaction NOT having committed, and that is a fact about   *)
(* the implementation rather than a modelling convenience: `commit` consumes   *)
(* the handle and settles on every path, so the only group an abandoned-handle *)
(* sweep can ever see is one whose transaction has not run. An abandon past    *)
(* the transaction would have to abort a group with permanent writes standing, *)
(* which is the same false claim `DeferredFailsFirst` guards against.          *)
Abandon ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ Len(sent) = 0
    /\ txState # "committed"
    /\ unwindPos' = Len(landed)
    /\ settled' = "aborting"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, doubt, invariantsHold, txState>>

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
    /\ settled' = "aborting"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, doubt, invariantsHold, txState>>

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
    /\ settled' = "aborting"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, doubt, invariantsHold, txState>>

(* Past the invariants, the gate opens one member at a time. A member in       *)
(* BadDeferreds may fail instead — the two transitions below — so failure is   *)
(* a choice the model explores, not a fate that forecloses the other endings.  *)
ReleaseDeferred ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos = Reversibles + 1
    /\ invariantsHold
    /\ txState # "pending"
    /\ gatePos <= Deferreds
    /\ sent' = Append(sent, gatePos)
    /\ gatePos' = gatePos + 1
    /\ UNCHANGED <<landed, reversed, pos, unwindPos, doubt, invariantsHold, txState, settled>>

(* A deferred member fails with NOTHING yet externalised — no deferred member  *)
(* out, and no atomic members committed — so the group can still be taken back *)
(* whole. The `txState` conjunct is the one the implementation forgot first:   *)
(* an atomic member's write is permanent the moment its transaction commits,   *)
(* has no registered reversal, and cannot have one, so "taken back whole" is   *)
(* not a claim that survives it.                                               *)
DeferredFailsFirst ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos = Reversibles + 1
    /\ invariantsHold
    /\ gatePos <= Deferreds
    /\ gatePos \in BadDeferreds
    /\ Len(sent) = 0
    /\ txState # "committed"
    /\ unwindPos' = Len(landed)
    /\ settled' = "aborting"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, doubt, invariantsHold, txState>>

(* A deferred member fails AFTER something externalised — another deferred     *)
(* member went out, or the atomic members committed. Reversing now would undo  *)
(* everything except the thing that actually happened.                         *)
DeferredFailsLate ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos = Reversibles + 1
    /\ invariantsHold
    /\ gatePos <= Deferreds
    /\ gatePos \in BadDeferreds
    /\ (Len(sent) > 0 \/ txState = "committed")
    /\ settled' = "quarantined"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, unwindPos, doubt, invariantsHold,
                   txState>>

(* A deferred member fails having externalised ITSELF: it reached the world     *)
(* and then its response could not be used (`Landed`). A distinct choice from    *)
(* `DeferredFailsFirst` — same member, same state (nothing else out yet), but a  *)
(* failure carrying the evidence that the call took effect — so the model        *)
(* explores both dispositions of one bad member. It is recorded as `sent`,       *)
(* because it went out, and the group quarantines: reversing around it would     *)
(* take back everything except the thing that happened. This is the case the     *)
(* implementation's `!in_doubt` guard missed — `Landed` is not `InDoubt`, so it  *)
(* was read as "nothing externalised" and took the cheap abort. Recording it as  *)
(* NOT sent would reproduce the misreading and hide the bug from every invariant *)
(* below.                                                                        *)
DeferredFailsLanded ==
    /\ settled = "open"
    /\ unwindPos = 0
    /\ pos = Reversibles + 1
    /\ invariantsHold
    /\ gatePos <= Deferreds
    /\ gatePos \in BadDeferreds
    \* A deferred member only runs once the transaction has resolved, exactly as
    \* `ReleaseDeferred` requires — landing before the atomic members committed
    \* would externalise work the transaction could still take back.
    /\ txState # "pending"
    /\ sent' = Append(sent, gatePos)
    /\ settled' = "quarantined"
    /\ UNCHANGED <<landed, reversed, pos, gatePos, unwindPos, doubt, invariantsHold,
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
(* A member in BadReversals may also come back fine — `ReversalFails` is the  *)
(* other branch — so a bad reversal does not foreclose the completed unwind,  *)
(* without which `settled = "aborted"` is unreachable and `AbortIsComplete`   *)
(* is true for want of an abort rather than because aborts are complete.      *)
ReverseOne ==
    /\ settled = "aborting"
    /\ unwindPos >= 1
    /\ ~Contains(reversed, Undoing)
    /\ reversed' = Append(reversed, Undoing)
    /\ unwindPos' = unwindPos - 1
    /\ UNCHANGED <<landed, sent, pos, gatePos, doubt, invariantsHold, txState, settled>>

(* A reversal that will not come back. The unwind STOPS: continuing would      *)
(* take back members around one now in an unknown state.                       *)
ReversalFails ==
    /\ settled = "aborting"
    /\ unwindPos >= 1
    /\ Undoing \in BadReversals
    /\ settled' = "quarantined"
    /\ UNCHANGED <<landed, reversed, sent, pos, gatePos, unwindPos, doubt, invariantsHold,
                   txState>>

FinishUnwind ==
    /\ settled = "aborting"
    /\ unwindPos = 0
    /\ Len(reversed) = Len(landed)
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
    \/ DeferredFailsLanded
    \/ Commit
    \/ ReverseOne
    \/ ReversalFails
    \/ FinishUnwind
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
(* back, no gated member ever ran, and the atomic members never committed.     *)
(* The converse of `ReversalFollowsLanding` — one direction stops a spurious   *)
(* undo, this one stops a hold that nobody releases while the journal says     *)
(* discharged. The third conjunct is the atomic form of the same lie: a        *)
(* transaction's writes are permanent and unregistered, so an abort past them  *)
(* is the journal saying "taken back whole" over a ledger row that stands.     *)
AbortIsComplete ==
    (settled = "aborted") =>
        (/\ \A i \in 1 .. Len(landed) : Contains(reversed, landed[i])
         /\ Len(sent) = 0
         /\ txState # "committed")

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
