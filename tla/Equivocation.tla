------------------------------ MODULE Equivocation -----------------------------
(***************************************************************************)
(* Showing two histories of one log, and who can see it.                    *)
(*                                                                          *)
(* Every other integrity mechanism here compares the store against itself:  *)
(* the store serves the records, the leaf, and the root the inclusion proof *)
(* is checked against. An operator who rewrites history and recomputes the  *)
(* tree satisfies all of them. A witness breaks the symmetry by being       *)
(* somebody else — it remembers the last checkpoint it saw and cosigns only *)
(* what provably extends it (src/journal/witness.rs).                       *)
(*                                                                          *)
(* WHAT A WITNESS DOES NOT PREVENT is the whole subject of this model. A    *)
(* witness that has never seen a log has nothing to check a first           *)
(* submission against, so it records whatever it is given. An operator can  *)
(* therefore fork, hand the fork to a fresh witness, and hold TWO valid     *)
(* cosignatures over incompatible histories — from two parties that each    *)
(* behaved correctly. Across witnesses this is detection, not prevention,   *)
(* and detection is a property of the READER.                               *)
(*                                                                          *)
(* The reader's rule is what this model checks: an audit is held to every   *)
(* checkpoint it gathered, each independently (src/audit.rs, Evidence       *)
(* anchors). The tempting reduction — keep the tallest, since a later       *)
(* checkpoint establishes more about append-only growth — selects the fork: *)
(* the history fed to a fresh witness is the LONGEST anybody holds, so the  *)
(* honest observer's shorter checkpoint, the only evidence the divergence   *)
(* happened, is exactly what the ranking discards. The `AuditKeepsTallest`  *)
(* mutant is that reduction, and it must break `EveryForkIsSeen`.           *)
(*                                                                          *)
(* Division of labour with the suite: `a_fork_is_caught_by_the_shorter_     *)
(* anchor_the_highest_would_have_hidden` builds one concrete instance of    *)
(* the attack against the real code. This explores the interleavings — in   *)
(* which order the operator grows, forks, submits and is refused, and which *)
(* subset of answers the reader manages to gather.                          *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Witnesses,  (* Set of witness ids. Integers keep the model finite.       *)
    ForkAt,     (* Length of the prefix the two histories share. A           *)
                (* checkpoint at or below this is on both.                   *)
    MaxSteps    (* Bound so TLC terminates.                                  *)

ASSUME Witnesses \subseteq Nat /\ Witnesses # {}
ASSUME ForkAt \in Nat
ASSUME MaxSteps \in Nat

(* Two histories that agree up to `ForkAt` and diverge after it. Two is      *)
(* enough: equivocation is a property of "more than one history", and a      *)
(* third adds states without adding a shape.                                 *)
Branches == {1, 2}
Other(b) == 3 - b

(* A checkpoint: which history, and how far along it. `size = 0` is the      *)
(* empty log, which every history extends — this is the "witness has never   *)
(* seen this origin" state, and the reason the attack exists.                *)
Nothing == [branch |-> 1, size |-> 0]

VARIABLES
    store,      (* The history the operator currently serves.                *)
    seen,       (* seen[w]: the last checkpoint witness w cosigned.          *)
    cosigned,   (* Set of [by, branch, size] — every cosignature ever given. *)
    gathered,   (* The subset of them a reader managed to collect.           *)
    audited,    (* Whether the reader has run its check yet.                 *)
    alarm,      (* What that check concluded.                                *)
    steps

vars == <<store, seen, cosigned, gathered, audited, alarm, steps>>

Checkpoints == [branch : Branches, size : 0 .. MaxSteps]
Anchors == [by : Witnesses, branch : Branches, size : 0 .. MaxSteps]
Hist(a) == [branch |-> a.branch, size |-> a.size]

TypeOK ==
    /\ store \in Checkpoints
    /\ \A w \in Witnesses : seen[w] \in Checkpoints
    /\ cosigned \subseteq Anchors
    /\ gathered \subseteq cosigned
    /\ audited \in BOOLEAN
    /\ alarm \in BOOLEAN
    /\ steps \in 0 .. MaxSteps

Init ==
    /\ store = Nothing
    /\ seen = [w \in Witnesses |-> Nothing]
    /\ cosigned = {}
    /\ gathered = {}
    /\ audited = FALSE
    /\ alarm = FALSE
    /\ steps = 0

-----------------------------------------------------------------------------

(* Whether a consistency proof from `old` to `new` can exist: `new` contains *)
(* everything `old` committed to. The empty log is extended by everything,   *)
(* which is exactly the first-submission case. A checkpoint inside the       *)
(* shared prefix is extended by both histories; one past it, only by its     *)
(* own.                                                                      *)
Extends(old, new) ==
    /\ old.size <= new.size
    /\ \/ old.size = 0
       \/ old.branch = new.branch
       \/ old.size <= ForkAt

Compatible(a, b) == Extends(a, b) \/ Extends(b, a)

(* The operator appends honestly. *)
Grow ==
    /\ steps < MaxSteps
    /\ ~audited
    /\ store.size < MaxSteps
    /\ store' = [branch |-> store.branch, size |-> store.size + 1]
    /\ steps' = steps + 1
    /\ UNCHANGED <<seen, cosigned, gathered, audited, alarm>>

(* The operator rewrites: it abandons what it served past the fork point and *)
(* continues on the other history. This is the act every other mechanism in  *)
(* the design is blind to, because the rewritten history is internally       *)
(* perfect.                                                                  *)
Fork ==
    /\ steps < MaxSteps
    /\ ~audited
    /\ store.size > ForkAt
    /\ store' = [branch |-> Other(store.branch), size |-> ForkAt + 1]
    /\ steps' = steps + 1
    /\ UNCHANGED <<seen, cosigned, gathered, audited, alarm>>

(* A submission a witness accepts. The guard is the witness's own: it        *)
(* cosigns what extends the last checkpoint it saw — and a witness that has  *)
(* seen nothing accepts anything, which is not a defect in the witness but   *)
(* the reason a single one cannot settle this.                               *)
Submit(w) ==
    /\ steps < MaxSteps
    /\ ~audited
    /\ store.size > 0
    /\ Extends(seen[w], store)
    /\ seen' = [seen EXCEPT ![w] = store]
    /\ cosigned' = cosigned \cup
        {[by |-> w, branch |-> store.branch, size |-> store.size]}
    /\ steps' = steps + 1
    /\ UNCHANGED <<store, gathered, audited, alarm>>

(* A submission the witness refuses, because what it is offered does not     *)
(* extend what it remembers. Modelled so the refusal is reachable in the     *)
(* state graph rather than merely absent from it.                            *)
Refused(w) ==
    /\ steps < MaxSteps
    /\ ~audited
    /\ store.size > 0
    /\ ~Extends(seen[w], store)
    /\ steps' = steps + 1
    /\ UNCHANGED <<store, seen, cosigned, gathered, audited, alarm>>

(* The reader collects answers. Any subset: witnesses go down, and an        *)
(* auditor reaches the ones they can.                                        *)
Gather(s) ==
    /\ steps < MaxSteps
    /\ ~audited
    /\ s \subseteq cosigned
    /\ gathered' = s
    /\ steps' = steps + 1
    /\ UNCHANGED <<store, seen, cosigned, audited, alarm>>

(* THE RULE UNDER TEST. Every anchor gathered is a separate constraint: the  *)
(* store must prove it extends each one, and failing any of them is the      *)
(* finding. `AuditKeepsTallest` replaces this with the reduction that looks  *)
(* sound and is not.                                                         *)
AuditRule(s) == \E a \in s : ~Extends(Hist(a), store)

Audit ==
    /\ steps < MaxSteps
    /\ ~audited
    /\ audited' = TRUE
    /\ alarm' = AuditRule(gathered)
    /\ steps' = steps + 1
    /\ UNCHANGED <<store, seen, cosigned, gathered>>

Next ==
    \/ Grow
    \/ Fork
    \/ \E w \in Witnesses : Submit(w)
    \/ \E w \in Witnesses : Refused(w)
    \/ \E s \in SUBSET cosigned : Gather(s)
    \/ Audit
    (* The reader's verdict is about the history in front of it, so the model *)
    (* stops there: what the operator did next is a different audit. Stutter  *)
    (* also at the step bound, which is where the shorter interleavings end.  *)
    \/ ((audited \/ steps = MaxSteps) /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(*                              INVARIANTS                                   *)
-----------------------------------------------------------------------------

(* A property of the witness guard, and the one thing a single witness does  *)
(* settle: nothing it cosigned contradicts anything else it cosigned. This   *)
(* is what "recorded before signing" buys in the implementation — a witness  *)
(* that forgot it had vouched could later cosign a divergent history at the  *)
(* same size.                                                                *)
NoWitnessVouchesForTwoHistories ==
    \A a, b \in cosigned :
        (a.by = b.by) => Compatible(Hist(a), Hist(b))

(* The store diverged from something somebody cosigned. This is the ground   *)
(* truth the reader is trying to reach, stated without reference to the      *)
(* reader's rule.                                                            *)
Diverged == \E a \in cosigned : ~Extends(Hist(a), store)

(* THE invariant. A reader who gathered every answer reaches the truth —     *)
(* both ways: every fork raises the alarm, and nothing else does.            *)
(*                                                                          *)
(* The second half is not padding. An alert that fires on two witnesses      *)
(* observing at different times is an alert nobody believes the third time,  *)
(* which is why `split_views` reports equal sizes only and the rest is       *)
(* settled by proof.                                                         *)
EveryForkIsSeen ==
    (audited /\ gathered = cosigned) => (alarm = Diverged)

(* What a partial gather can still promise: an alarm is never raised about a *)
(* history the store does extend. Holds for any subset, which is what makes  *)
(* an auditor's incomplete round safe to act on.                             *)
NoFalseAlarm ==
    audited => (alarm => (\E a \in gathered : ~Extends(Hist(a), store)))

Safety ==
    /\ TypeOK
    /\ NoWitnessVouchesForTwoHistories
    /\ EveryForkIsSeen
    /\ NoFalseAlarm

-----------------------------------------------------------------------------
(*                          TEMPORAL PROPERTIES                              *)
-----------------------------------------------------------------------------

(* A cosignature is never taken back: the set only grows. Two witnesses      *)
(* holding contradictory answers stays true once it is true, which is what   *)
(* makes the evidence showable to a third party later.                       *)
CosignaturesAreKept == [][cosigned \subseteq cosigned']_vars

(* Under weak fairness every schedule reaches a stopping point — the         *)
(* reader's verdict, or the step bound — rather than wedging. Not `<>audited` *)
(* on its own: an auditor who never gets a round in before the bound is an    *)
(* ordinary behaviour, not a livelock, and asserting otherwise would make     *)
(* this property a statement about the bound rather than about the protocol.  *)
RunsItsCourse == <>(audited \/ steps = MaxSteps)

=============================================================================
