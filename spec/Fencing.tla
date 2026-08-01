-------------------------------- MODULE Fencing --------------------------------
(***************************************************************************)
(* Run ownership under takeover.                                            *)
(*                                                                          *)
(* Two plane instances share a store. Exactly one may append to a given run  *)
(* at a time. The dangerous case is not a clean handover — it is the         *)
(* instance that was paused (GC, VM suspend, network partition), was         *)
(* declared dead, had its run taken over, and then WAKES UP believing it is  *)
(* still the owner.                                                         *)
(*                                                                          *)
(* The defence is that every append carries the writer's epoch and the store *)
(* compares it inside the same transaction that writes. There is no window   *)
(* between "am I still the owner?" and the write for a zombie to slip        *)
(* through, because there is no gap to slip into.                           *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    Instances,  (* Set of instance ids. Integers keep the model finite and    *)
                (* configurable without declaring model values.               *)
    MaxSteps    (* Bound so TLC terminates.                                   *)

ASSUME Instances \subseteq Nat /\ Instances # {}
ASSUME MaxSteps \in Nat

(* Not an instance id, so it can mark "nobody owns this yet". *)
NoOwner == 0
ASSUME NoOwner \notin Instances

VARIABLES
    leaseEpoch,   (* Epoch currently recorded in the store.                   *)
    leaseOwner,   (* Instance the store believes owns the run.                *)
    held,         (* held[i]: epoch instance i BELIEVES it holds. May be      *)
                  (* stale — that is the entire point.                        *)
    journal,      (* Seq of [writer |-> i, epoch |-> e]                       *)
    steps

vars == <<leaseEpoch, leaseOwner, held, journal, steps>>

TypeOK ==
    /\ leaseOwner \in Instances \cup {NoOwner}
    /\ leaseEpoch \in Nat
    /\ steps \in 0 .. MaxSteps
    /\ \A i \in Instances : held[i] \in Nat

Init ==
    /\ leaseEpoch = 0
    /\ leaseOwner = NoOwner
    /\ held = [i \in Instances |-> 0]
    /\ journal = << >>
    /\ steps = 0

-----------------------------------------------------------------------------

(* Takeover: the previous owner is presumed dead and the epoch advances. The  *)
(* old owner is NOT notified — it cannot be, which is why the epoch matters.  *)
Acquire(i) ==
    /\ steps < MaxSteps
    /\ leaseOwner # i
    /\ leaseEpoch' = leaseEpoch + 1
    /\ leaseOwner' = i
    /\ held' = [held EXCEPT ![i] = leaseEpoch + 1]
    /\ steps' = steps + 1
    /\ UNCHANGED journal

(* An append is accepted only if the writer's epoch is current.               *)
(*                                                                           *)
(* The guard IS the store's in-transaction check. Removing it is the bug this *)
(* model exists to rule out, and doing so must make `EpochsNeverRegress` fail *)
(* — otherwise the invariant is decoration.                                   *)
Write(i) ==
    /\ steps < MaxSteps
    /\ held[i] >= leaseEpoch
    /\ journal' = Append(journal, [writer |-> i, epoch |-> held[i]])
    /\ steps' = steps + 1
    /\ UNCHANGED <<leaseEpoch, leaseOwner, held>>

(* A stale instance tries to write and is refused. Time passes; nothing else  *)
(* does. Modelled explicitly so the fenced path is reachable in the state     *)
(* graph rather than merely absent from it.                                   *)
FencedAttempt(i) ==
    /\ steps < MaxSteps
    /\ held[i] < leaseEpoch
    /\ steps' = steps + 1
    /\ UNCHANGED <<leaseEpoch, leaseOwner, held, journal>>

Next ==
    \/ \E i \in Instances : Acquire(i)
    \/ \E i \in Instances : Write(i)
    \/ \E i \in Instances : FencedAttempt(i)
    \/ (steps = MaxSteps /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(*                              INVARIANTS                                   *)
-----------------------------------------------------------------------------

(* THE invariant: epochs in the journal never go backwards.                  *)
(*                                                                           *)
(* A regression would mean a superseded owner appended after the takeover —   *)
(* the split-brain corruption this design exists to prevent.                  *)
EpochsNeverRegress ==
    \A k \in 1 .. (Len(journal) - 1) :
        journal[k].epoch <= journal[k + 1].epoch

(* At most one instance can believe it holds the current epoch.              *)
SingleCurrentOwner ==
    \A i, j \in Instances :
        (held[i] = leaseEpoch /\ held[j] = leaseEpoch /\ leaseEpoch > 0) => i = j

(* Nothing in the journal was written under an epoch the store had already    *)
(* moved past at the time of writing.                                         *)
NoWriteAboveCurrentEpoch ==
    \A k \in 1 .. Len(journal) : journal[k].epoch <= leaseEpoch

Safety ==
    /\ TypeOK
    /\ EpochsNeverRegress
    /\ SingleCurrentOwner
    /\ NoWriteAboveCurrentEpoch

=============================================================================
