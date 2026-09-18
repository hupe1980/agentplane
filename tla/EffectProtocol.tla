---------------------------- MODULE EffectProtocol ----------------------------
(***************************************************************************)
(* The effect protocol: how a run performs externally visible work exactly  *)
(* once, across arbitrary crashes.                                          *)
(*                                                                          *)
(* This is the smallest part of the runtime that must be unconditionally    *)
(* correct. Everything else — planning, policy, cases, budgets — is layered  *)
(* above it, and all of it is worthless if this leaks a duplicate side       *)
(* effect.                                                                  *)
(*                                                                          *)
(* The protocol, in three rules:                                            *)
(*                                                                          *)
(*   1. Announce intent durably BEFORE acting  ("EffectStarted")            *)
(*   2. Record the outcome durably AFTER acting ("EffectDone")              *)
(*   3. On restart, an announcement with no outcome is UNDECIDABLE.         *)
(*      Whether the action landed cannot be known from the journal, so a    *)
(*      mutating effect in that state escalates to a human. It is never     *)
(*      retried on a guess.                                                 *)
(*                                                                          *)
(* Rule 3 is the one that is tempting to get wrong. Retrying looks helpful   *)
(* and is how a duplicate invoice gets issued.                              *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    EffectCount,  (* How many effects the deterministic zone produces.       *)
    MaxCrashes    (* Bound so TLC terminates.                                *)

ASSUME EffectCount \in Nat /\ EffectCount > 0
ASSUME MaxCrashes \in Nat

(* Effects are identified by position. Identity carries no meaning beyond    *)
(* "which one", so integers are enough — and they keep the model finite      *)
(* without a set of model values to declare.                                 *)
Effects == 1 .. EffectCount

(* The plan the deterministic zone produces. Fixed, because the deterministic
   zone is deterministic. *)
Plan == [i \in Effects |-> i]

(* Not an effect id, so it can mark "nothing in flight". *)
NoEffect == 0

VARIABLES
    journal,     (* Seq of [key |-> id, kind |-> "started" | "done"]         *)
    world,       (* Seq of effect ids ACTUALLY performed outside. The thing  *)
                 (* we are protecting: real invoices, real emails.           *)
    pos,         (* Next index into Plan this incarnation will attempt.      *)
    inflight,    (* Effect announced by THIS incarnation. Lost on crash — it *)
                 (* lives in process memory, which is exactly why an orphan  *)
                 (* is undecidable after a restart.                          *)
    acted,       (* Effect THIS incarnation has already acted on. Also       *)
                 (* in-memory, and also lost. Modelled separately from       *)
                 (* `inflight` so a crash can land BETWEEN the action and    *)
                 (* the record — the case the whole protocol exists for.     *)
    status,      (* "running" | "crashed" | "succeeded" | "quarantined"      *)
    crashes

vars == <<journal, world, pos, inflight, acted, status, crashes>>

Occurrences(s, e) == Cardinality({i \in 1 .. Len(s) : s[i] = e})

Started(e) == \E i \in 1 .. Len(journal) :
                 journal[i].key = e /\ journal[i].kind = "started"

Done(e)    == \E i \in 1 .. Len(journal) :
                 journal[i].key = e /\ journal[i].kind = "done"

(* An announcement with no outcome. After a restart this is indistinguishable *)
(* from "the action landed but the process died before recording it".         *)
Orphan(e)  == Started(e) /\ ~Done(e)

Current == Plan[pos]

TypeOK ==
    /\ status \in {"running", "crashed", "succeeded", "quarantined"}
    /\ pos \in 1 .. (EffectCount + 1)
    /\ crashes \in 0 .. MaxCrashes
    /\ inflight \in Effects \cup {NoEffect}
    /\ acted \in Effects \cup {NoEffect}
    /\ \A i \in 1 .. Len(world) : world[i] \in Effects

Init ==
    /\ journal  = << >>
    /\ world    = << >>
    /\ pos      = 1
    /\ inflight = NoEffect
    /\ acted    = NoEffect
    /\ status   = "running"
    /\ crashes  = 0

-----------------------------------------------------------------------------
(* Replay: the journal already holds an outcome, so the effect is read back  *)
(* rather than re-performed. `world` is untouched — this is the whole point. *)
ReplayCompleted ==
    /\ status = "running"
    /\ pos <= EffectCount
    /\ Done(Current)
    /\ pos' = pos + 1
    /\ UNCHANGED <<journal, world, inflight, acted, status, crashes>>

(* Rule 1: durable announcement precedes the action. *)
Announce ==
    /\ status = "running"
    /\ pos <= EffectCount
    /\ ~Started(Current)
    /\ journal' = Append(journal, [key |-> Current, kind |-> "started"])
    /\ inflight' = Current
    /\ UNCHANGED <<world, pos, acted, status, crashes>>

(* The action itself, reaching the outside world.                            *)
(*                                                                           *)
(* Its guard is deliberately only what the IMPLEMENTATION can observe:       *)
(* "I announced this and have not acted on it yet". It does not consult      *)
(* `world` — the outside world is not readable. Guarding on `world` would    *)
(* make ExactlyOnce true by construction and the model would prove nothing.  *)
Act ==
    /\ status = "running"
    /\ pos <= EffectCount
    /\ inflight = Current
    /\ acted # Current
    /\ world' = Append(world, Current)
    /\ acted' = Current
    /\ UNCHANGED <<journal, pos, inflight, status, crashes>>

(* Rule 2: record the outcome, once the action has happened.                 *)
(*                                                                           *)
(* Separating this from `Act` is what lets `Crash` land between them — the    *)
(* state where the invoice went out and nothing recorded it. That is the      *)
(* whole reason the protocol exists, so a model that cannot reach it is a     *)
(* model that verifies nothing.                                               *)
Record ==
    /\ status = "running"
    /\ pos <= EffectCount
    /\ acted = Current
    /\ journal' = Append(journal, [key |-> Current, kind |-> "done"])
    /\ inflight' = NoEffect
    /\ acted' = NoEffect
    /\ pos' = pos + 1
    /\ UNCHANGED <<world, status, crashes>>

(* Rule 3. An orphan this incarnation did not create is undecidable, and a   *)
(* mutating effect must not be guessed at.                                   *)
QuarantineOrphan ==
    /\ status = "running"
    /\ pos <= EffectCount
    /\ Orphan(Current)
    /\ inflight # Current
    /\ status' = "quarantined"
    /\ UNCHANGED <<journal, world, pos, inflight, acted, crashes>>

Finish ==
    /\ status = "running"
    /\ pos = EffectCount + 1
    /\ status' = "succeeded"
    /\ UNCHANGED <<journal, world, pos, inflight, acted, crashes>>

(* Process death at an arbitrary point. Note `inflight` is lost: in-memory    *)
(* knowledge does not survive, which is precisely what makes rule 3 necessary.*)
Crash ==
    /\ status = "running"
    /\ crashes < MaxCrashes
    /\ status' = "crashed"
    (* Both in-memory facts are lost. This is what makes an orphaned
       announcement genuinely undecidable after a restart. *)
    /\ inflight' = NoEffect
    /\ acted' = NoEffect
    /\ crashes' = crashes + 1
    /\ UNCHANGED <<journal, world, pos>>

(* Recovery replays from the start of the plan. It does not resume from a    *)
(* remembered position, because nothing is remembered.                       *)
Restart ==
    /\ status = "crashed"
    /\ status' = "running"
    /\ pos' = 1
    /\ UNCHANGED <<journal, world, inflight, acted, crashes>>

Terminal == status \in {"succeeded", "quarantined"}

Next ==
    \/ ReplayCompleted
    \/ Announce
    \/ Act
    \/ Record
    \/ QuarantineOrphan
    \/ Finish
    \/ Crash
    \/ Restart
    \/ (Terminal /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(*                              INVARIANTS                                   *)
-----------------------------------------------------------------------------

(* THE invariant. No effect is ever performed against the outside world more  *)
(* than once, no matter where the crashes land.                              *)
ExactlyOnce ==
    \A e \in Effects : Occurrences(world, e) <= 1

(* Nothing happens that was not durably announced first. Violating this means *)
(* a crash could leave an action with no trace that it was ever attempted —   *)
(* invisible to recovery and to audit.                                       *)
DurableIntentPrecedesAction ==
    \A i \in 1 .. Len(world) : Started(world[i])

(* Success is structural: it means every planned step was accounted for, not  *)
(* that the workload said so.                                                 *)
SuccessMeansComplete ==
    (status = "succeeded") => (pos = EffectCount + 1)

(* An outcome is only ever recorded for an effect that was announced.         *)
NoOutcomeWithoutAnnouncement ==
    \A e \in Effects : Done(e) => Started(e)

Safety ==
    /\ TypeOK
    /\ ExactlyOnce
    /\ DurableIntentPrecedesAction
    /\ SuccessMeansComplete
    /\ NoOutcomeWithoutAnnouncement

-----------------------------------------------------------------------------
(*                          TEMPORAL PROPERTIES                              *)
-----------------------------------------------------------------------------

(* Prefix equality, not merely length: a history that swapped one record for  *)
(* another at the same length would still be a rewritten history, and a       *)
(* length check would wave it through.                                        *)
IsPrefixOf(p, s) ==
    /\ Len(p) <= Len(s)
    /\ \A k \in 1 .. Len(p) : s[k] = p[k]

(* The journal only grows. Nothing rewrites history. *)
JournalIsAppendOnly == [][IsPrefixOf(journal, journal')]_vars

(* Once performed, an effect stays performed — `world` is a record of what
   happened, not a mutable set. *)
WorldIsAppendOnly == [][IsPrefixOf(world, world')]_vars

(* With crashes bounded, the run reaches a terminal state. It may legitimately *)
(* be `quarantined` — refusing to guess is a correct outcome, not a hang.      *)
Terminates == <>Terminal

=============================================================================
