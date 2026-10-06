------------------------------- MODULE RateWindow -------------------------------
(***************************************************************************)
(* A grant's rate ceiling: at most `Ceiling` dispatches in any window of    *)
(* `Window` ticks ending now.                                               *)
(*                                                                          *)
(* The window slides (`check_rate`): a fixed bucket would admit twice the   *)
(* ceiling across its boundary, which is the burst a rate ceiling exists to *)
(* stop. One row per dispatch, keyed by the run and the dispatch's FIRST     *)
(* attempt (`RateReservation`), so a retry or a recovered re-dispatch       *)
(* spends once and two runs making the same call each spend. Rows are never *)
(* refunded: nothing proves a failed call did not reach the world. The      *)
(* count and the insert are one transaction (`QuotaStore::reserve_rate`).   *)
(*                                                                          *)
(* A dispatch with no room is refused, never left waiting for room: a wait  *)
(* would be a suspension replay cannot reproduce.                           *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Runs,         (* runs, each making the same one call                    *)
    MaxAttempts,  (* attempts per dispatch, retries included                *)
    Ceiling,
    Window,
    MaxTime

VARIABLES
    now,
    rows,      (* the store's reservations: [run, at, a]                    *)
    kept,      (* history: every row ever inserted                          *)
    attempts,  (* attempts[r]: how many times r's dispatch was attempted    *)
    done       (* done[r]: "none", "sent", or "refused"                     *)

vars == <<now, rows, kept, attempts, done>>

Row == [run : Runs, at : 0 .. MaxTime, a : 1 .. MaxAttempts]

TypeOK ==
    /\ now \in 0 .. MaxTime
    /\ rows \subseteq Row
    /\ kept \subseteq Row
    /\ attempts \in [Runs -> 0 .. MaxAttempts]
    /\ done \in [Runs -> {"none", "sent", "refused"}]

(* The rows a window ending at e counts.                                    *)
InWindow(e) == Cardinality({x \in rows : x.at > e - Window /\ x.at <= e})

(* The key exists: this is a retry of a dispatch that already spent.        *)
Reserved(r) == \E x \in rows : x.run = r

Init ==
    /\ now = 0
    /\ rows = {}
    /\ kept = {}
    /\ attempts = [r \in Runs |-> 0]
    /\ done = [r \in Runs |-> "none"]

-----------------------------------------------------------------------------

(* `QuotaStore::reserve_rate`: count and insert in one transaction.         *)
Reserve(r) ==
    /\ done[r] = "none" /\ attempts[r] < MaxAttempts
    /\ attempts' = [attempts EXCEPT ![r] = @ + 1]
    /\ IF Reserved(r)
       THEN /\ done' = [done EXCEPT ![r] = "sent"]
            /\ UNCHANGED <<now, rows, kept>>
       ELSE IF InWindow(now) < Ceiling
            THEN LET row == [run |-> r, at |-> now, a |-> attempts[r] + 1]
                 IN /\ rows' = rows \cup {row}
                    /\ kept' = kept \cup {row}
                    /\ done' = [done EXCEPT ![r] = "sent"]
                    /\ UNCHANGED now
            ELSE /\ done' = [done EXCEPT ![r] = "refused"]
                 /\ UNCHANGED <<now, rows, kept>>

(* The call failed after its row was written; the dispatch may be retried, *)
(* and its row stays.                                                       *)
Fail(r) ==
    /\ done[r] = "sent" /\ attempts[r] < MaxAttempts
    /\ done' = [done EXCEPT ![r] = "none"]
    /\ UNCHANGED <<rows, kept, now, attempts>>

Advance ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<rows, kept, attempts, done>>

Next ==
    \/ \E r \in Runs : Reserve(r) \/ Fail(r)
    \/ Advance
    \/ UNCHANGED vars

Spec == Init /\ [][Next]_vars /\ \A r \in Runs : WF_vars(Reserve(r))

-----------------------------------------------------------------------------

(* No window ending at any instant so far counts more than the ceiling      *)
(* (`check_rate`).                                                          *)
RateWithinWindow ==
    \A e \in 0 .. now :
        Cardinality({x \in kept : x.at > e - Window /\ x.at <= e}) <= Ceiling

(* A retry spends nothing more: the key is the first attempt's            *)
(* (`RateReservation`).                                                     *)
RetrySpendsOnce ==
    \A r \in Runs : Cardinality({x \in kept : x.run = r}) <= 1

(* A row is never refunded early (`QuotaStore::reserve_rate` prunes only    *)
(* what no window can count).                                               *)
RowsNeverRefunded == kept \subseteq rows

(* Every dispatch that went out is counted: two runs making the same call   *)
(* each spend.                                                              *)
EveryDispatchCounted ==
    \A r \in Runs : done[r] = "sent" => \E x \in kept : x.run = r

Safety ==
    /\ TypeOK
    /\ RateWithinWindow
    /\ RetrySpendsOnce
    /\ RowsNeverRefunded
    /\ EveryDispatchCounted

(* Under WF(Reserve): a dispatch with attempts left is answered — sent or   *)
(* refused — and never left waiting for room.                               *)
EveryDispatchAnswered ==
    \A r \in Runs : (done[r] = "none" /\ attempts[r] < MaxAttempts) ~> done[r] # "none"

=============================================================================
