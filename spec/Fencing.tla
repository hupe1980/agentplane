-------------------------------- MODULE Fencing --------------------------------
(***************************************************************************)
(* Run ownership under takeover.                                            *)
(*                                                                          *)
(* Two plane instances share a store. While a run is leased, exactly one     *)
(* instance holds the current fencing epoch, and only a writer presenting    *)
(* that epoch may append. The dangerous case is not a clean handover — it is *)
(* the instance that was paused (GC, VM suspend, network partition), had its *)
(* lease lapse, had the run taken over, and then WAKES UP believing it is    *)
(* still the owner.                                                         *)
(*                                                                          *)
(* The defence is that every append carries the writer's epoch and the store *)
(* compares it for EXACT equality inside the same transaction that writes    *)
(* (src/store/redb.rs: `if epoch != current`). There is no window between    *)
(* "am I still the owner?" and the write for a zombie to slip through,       *)
(* because there is no gap to slip into. A token from the future is refused  *)
(* like a stale one: it is no more proof of ownership (the fencing contract  *)
(* in src/journal/store.rs).                                                 *)
(*                                                                          *)
(* Acquire and Renew are DIFFERENT VERBS with different failure modes, and   *)
(* the split is load-bearing (src/journal/store.rs, `acquire` vs `renew`):   *)
(*                                                                          *)
(*   * `acquire` is a pure claim: it succeeds only on a lease nobody holds   *)
(*     live — including when the caller itself is the holder — and it always *)
(*     bumps the epoch, which fences the previous holder.                    *)
(*   * `renew` extends a lease still verifiably held — same owner, same      *)
(*     epoch, unexpired, unreleased — and NEVER bumps the epoch, because a   *)
(*     bump would fence the owner against its own in-flight writes; and it   *)
(*     never claims, because a renewal that "helpfully" re-took a lapsed     *)
(*     lease would resurrect the fenced past under its old epoch.            *)
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
    leaseEpoch,   (* Epoch currently recorded in the store's lease row.       *)
    leaseOwner,   (* Instance the row names as owner.                         *)
    leaseLive,    (* Whether the lease is held, unexpired and unreleased.     *)
                  (* FALSE also covers "never granted": the row's epoch and   *)
                  (* owner survive a lapse — redb keeps them — but a lapsed   *)
                  (* lease is claimable, not renewable.                       *)
    takeovers,    (* How many times ownership was claimed. A history variable *)
                  (* with no behaviour of its own: it exists so "only a       *)
                  (* takeover advances the epoch" is a checkable invariant    *)
                  (* rather than a comment.                                   *)
    held,         (* held[i]: epoch instance i BELIEVES it holds. 0 = none.   *)
                  (* May be stale — that is the entire point.                 *)
    journal,      (* Seq of [writer |-> i, epoch |-> e]                       *)
    steps

vars == <<leaseEpoch, leaseOwner, leaseLive, takeovers, held, journal, steps>>

TypeOK ==
    /\ leaseOwner \in Instances \cup {NoOwner}
    /\ leaseEpoch \in Nat
    /\ leaseLive \in BOOLEAN
    /\ takeovers \in Nat
    /\ steps \in 0 .. MaxSteps
    /\ \A i \in Instances : held[i] \in Nat

Init ==
    /\ leaseEpoch = 0
    /\ leaseOwner = NoOwner
    /\ leaseLive = FALSE
    /\ takeovers = 0
    /\ held = [i \in Instances |-> 0]
    /\ journal = << >>
    /\ steps = 0

-----------------------------------------------------------------------------

(* Instance i holds the current epoch: it acquired, and no takeover has       *)
(* moved the epoch past it since. `held[i] >= 1` is part of the meaning —     *)
(* 0 is "holds nothing", not "holds epoch 0" — and this is the SAME predicate *)
(* the store's fence enforces on `Write`, so the invariant over it is about   *)
(* who can actually append, not about a value pattern.                        *)
HoldsCurrent(i) == held[i] >= 1 /\ held[i] = leaseEpoch

(* A pure claim. Succeeds only on a lease nobody holds live — a lapse must    *)
(* come first, even for the previous owner — and always bumps the epoch,      *)
(* which fences whoever held it before. The old owner is NOT notified — it    *)
(* cannot be, which is why the epoch matters.                                 *)
Acquire(i) ==
    /\ steps < MaxSteps
    /\ ~leaseLive
    /\ leaseEpoch' = leaseEpoch + 1
    /\ leaseOwner' = i
    /\ leaseLive' = TRUE
    /\ takeovers' = takeovers + 1
    /\ held' = [held EXCEPT ![i] = leaseEpoch + 1]
    /\ steps' = steps + 1
    /\ UNCHANGED journal

(* The lease lapses — the owner paused past its TTL, or released on a clean   *)
(* exit. The row keeps its epoch and owner (redb keeps both); what changes is *)
(* that the lease is now claimable. The old owner still BELIEVES it holds the *)
(* epoch, and until somebody claims, its belief is even correct — which is    *)
(* why takeover safety cannot rest on expiry alone.                           *)
Expire ==
    /\ steps < MaxSteps
    /\ leaseLive
    /\ leaseLive' = FALSE
    /\ steps' = steps + 1
    /\ UNCHANGED <<leaseEpoch, leaseOwner, takeovers, held, journal>>

(* Extend a lease still verifiably held: same owner, same epoch, unexpired,   *)
(* unreleased — checked and written in one store transaction. The epoch is    *)
(* KEPT: bumping it would fence the owner against its own in-flight writes,   *)
(* and claiming a lapsed lease here would resurrect the fenced past. In this  *)
(* model the extension itself is invisible (expiry is nondeterministic, not   *)
(* timed), so what is being verified is the guard — the handshake that        *)
(* refuses every renewal `acquire` would accept, and vice versa. The          *)
(* `RenewAsAcquire` mutant is what proves the guard and the no-bump are       *)
(* load-bearing rather than decorative.                                       *)
Renew(i) ==
    /\ steps < MaxSteps
    /\ leaseLive
    /\ leaseOwner = i
    /\ held[i] = leaseEpoch
    /\ steps' = steps + 1
    /\ UNCHANGED <<leaseEpoch, leaseOwner, leaseLive, takeovers, held, journal>>

(* An append is accepted only if the writer's epoch EQUALS the store's.       *)
(*                                                                            *)
(* The guard IS the store's in-transaction check, and it is HoldsCurrent —    *)
(* exact equality, not `>=`: a stale epoch is fenced, and an epoch above the  *)
(* store's would be a writer that never acquired inventing authority. Note    *)
(* what the guard does NOT include: `leaseLive`. The store's fence compares   *)
(* epochs only, so the rightful holder of the current epoch keeps writing     *)
(* across a lapse until somebody actually claims — safe, because the epoch    *)
(* has not moved. Removing this guard is the bug this model exists to rule    *)
(* out, and doing so must make `EpochsNeverRegress` fail — otherwise the      *)
(* invariant is decoration.                                                   *)
Write(i) ==
    /\ steps < MaxSteps
    /\ HoldsCurrent(i)
    /\ journal' = Append(journal, [writer |-> i, epoch |-> held[i]])
    /\ steps' = steps + 1
    /\ UNCHANGED <<leaseEpoch, leaseOwner, leaseLive, takeovers, held>>

(* A stale instance tries to write and is refused. Time passes; nothing else  *)
(* does. Modelled explicitly so the fenced path is reachable in the state     *)
(* graph rather than merely absent from it. (A REFUSED renewal changes        *)
(* exactly as little and is covered by the same shape, so it gets no action   *)
(* of its own.)                                                               *)
FencedAttempt(i) ==
    /\ steps < MaxSteps
    /\ held[i] >= 1
    /\ held[i] # leaseEpoch
    /\ steps' = steps + 1
    /\ UNCHANGED <<leaseEpoch, leaseOwner, leaseLive, takeovers, held, journal>>

Next ==
    \/ \E i \in Instances : Acquire(i)
    \/ Expire
    \/ \E i \in Instances : Renew(i)
    \/ \E i \in Instances : Write(i)
    \/ \E i \in Instances : FencedAttempt(i)
    \/ (steps = MaxSteps /\ UNCHANGED vars)

(* Weak fairness is the model's one liveness ASSUMPTION, stated rather than   *)
(* implied: the scheduler does not stall forever while some lease action is   *)
(* enabled. It forces nothing about WHICH action runs. Safety is the point of *)
(* this model; `RunsItsCourse` below is what the assumption buys — no         *)
(* interleaving of acquire/renew/expire/write can livelock short of the step  *)
(* bound.                                                                     *)
Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

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

(* At most one instance holds the current epoch — that is, at most one can    *)
(* pass the store's fence. Unguarded: `HoldsCurrent` is the same predicate    *)
(* `Write` is fenced on, so this is exactly "at most one instance may         *)
(* append", not a claim carved down until the model satisfies it. (It used    *)
(* to be guarded with `leaseEpoch > 0` while `Write` accepted `held[i] >=     *)
(* leaseEpoch` — which let two instances interleave epoch-0 appends the       *)
(* invariant was worded to ignore.)                                           *)
SingleCurrentOwner ==
    \A i, j \in Instances :
        (HoldsCurrent(i) /\ HoldsCurrent(j)) => i = j

(* Nothing in the journal was written under an epoch the store had already    *)
(* moved past — or never issued — at the time of writing.                     *)
NoWriteAboveCurrentEpoch ==
    \A k \in 1 .. Len(journal) : journal[k].epoch <= leaseEpoch

(* Renewal preserves ownership and epoch; only a takeover moves either.       *)
(*                                                                            *)
(*   * The epoch counts takeovers, exactly. A renewal that bumped it would    *)
(*     fence the owner with its own heartbeat, and hand out fresh epochs      *)
(*     without a takeover — after which an epoch in the journal no longer     *)
(*     names the ownership change that produced it.                           *)
(*   * A live lease is held by the instance whose remembered epoch is         *)
(*     current. A renewal that claimed a lease for anyone else would move     *)
(*     ownership without fencing the previous holder.                         *)
RenewalPreservesOwnership ==
    /\ leaseEpoch = takeovers
    /\ leaseLive => HoldsCurrent(leaseOwner)

Safety ==
    /\ TypeOK
    /\ EpochsNeverRegress
    /\ SingleCurrentOwner
    /\ NoWriteAboveCurrentEpoch
    /\ RenewalPreservesOwnership

-----------------------------------------------------------------------------
(*                          TEMPORAL PROPERTIES                              *)
-----------------------------------------------------------------------------

(* The journal is recorded history: nothing rewrites, reorders or shortens    *)
(* it. Prefix equality, not merely length — a journal that swapped one        *)
(* record for another at the same length would still be rewritten history.    *)
IsPrefixOf(p, s) ==
    /\ Len(p) <= Len(s)
    /\ \A k \in 1 .. Len(p) : s[k] = p[k]

JournalIsAppendOnly == [][IsPrefixOf(journal, journal')]_vars

(* Under weak fairness the schedule always runs to its bound: no interleaving *)
(* of lease traffic wedges the store or livelocks below MaxSteps.             *)
RunsItsCourse == <>(steps = MaxSteps)

=============================================================================
