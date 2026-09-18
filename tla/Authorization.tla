----------------------------- MODULE Authorization -----------------------------
(***************************************************************************)
(* Authorization, and its interaction with replay.                          *)
(*                                                                          *)
(* A policy gate on its own is easy. What is not easy is a policy gate in a  *)
(* system that replays: the policy set can change between a run and its      *)
(* audit, so "was this allowed" has two possible answers depending on WHEN   *)
(* you ask, and only one of them is the truth about what happened.           *)
(*                                                                          *)
(* Two failure modes, in opposite directions:                               *)
(*                                                                          *)
(*   * Re-evaluating on replay lets a rule edited today re-judge a run from  *)
(*     last year. The audit trail still verifies — every hash checks out —   *)
(*     and it now describes a run that never happened.                       *)
(*                                                                          *)
(*   * Not recording a denial leaves the run stopped at a point with no      *)
(*     history. Replay reaches it, finds nothing, and reports that this      *)
(*     build performs more effects than the recorded one: a divergence       *)
(*     alarm for a code change that does not exist.                          *)
(*                                                                          *)
(* The design this models: policy is consulted ONLY when an effect is        *)
(* actually dispatched, and a denial is journaled. A permit needs no record  *)
(* because the effect's own record is already the evidence it was allowed.   *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    EffectCount,   (* Effects the run would perform if permitted.             *)
    Forbidden      (* Positions the policy MAY refuse. A subset of            *)
                   (* 1..EffectCount.                                          *)

ASSUME EffectCount \in Nat
ASSUME Forbidden \subseteq 1 .. EffectCount

VARIABLES
    mode,      (* "live" | "replay"                                           *)
    pos,       (* Next effect position to consider.                           *)
    journal,   (* Seq of records: [at |-> n, kind |-> "done" | "denied"]       *)
    world,     (* Seq of effect positions that actually reached the outside.   *)
    asked,     (* Positions at which the policy engine was consulted.          *)
    ruleset,   (* Which policy set is in force: "original" | "relaxed".        *)
    banned,    (* Positions the ORIGINAL ruleset refuses in this run. An       *)
               (* initial-state choice from SUBSET Forbidden — denial must be  *)
               (* a choice rather than fate. A constant set would force every  *)
               (* live run into LiveDeny and leave "done" (and the whole       *)
               (* replay-of-a-completed-run path) unreachable, which is how    *)
               (* LiveFinish and ReplayFinish were dead transitions for a      *)
               (* while. Same idiom as EffectGroup's txState.                  *)
    status     (* "running" | "stopped" | "done"                               *)

vars == <<mode, pos, journal, world, asked, ruleset, banned, status>>

TypeOK ==
    /\ mode \in {"live", "replay"}
    /\ pos \in 1 .. (EffectCount + 1)
    /\ ruleset \in {"original", "relaxed"}
    /\ banned \subseteq Forbidden
    /\ status \in {"running", "stopped", "done"}

Init ==
    /\ mode = "live"
    /\ pos = 1
    /\ journal = << >>
    /\ world = << >>
    /\ asked = {}
    /\ ruleset = "original"
    /\ banned \in SUBSET Forbidden   (* Either way; the model explores both.  *)
    /\ status = "running"

-----------------------------------------------------------------------------

(* Is `n` permitted under the ruleset currently in force?                    *)
(*                                                                           *)
(* The relaxed set permits everything — it is the "somebody edited the rules  *)
(* between the run and the audit" case, which is the whole reason this model  *)
(* exists.                                                                    *)
Permits(n) == (ruleset = "relaxed") \/ (n \notin banned)

(* Does the journal hold a record at position n?                             *)
RecordedAt(n) == \E k \in 1 .. Len(journal) : journal[k].at = n

RecordKindAt(n) ==
    IF \E k \in 1 .. Len(journal) : journal[k].at = n
    THEN journal[CHOOSE k \in 1 .. Len(journal) : journal[k].at = n].kind
    ELSE "none"

-----------------------------------------------------------------------------
(*                            LIVE EXECUTION                                 *)
-----------------------------------------------------------------------------

(* Permitted: the engine is consulted, the effect reaches the world, and the  *)
(* effect's own record goes in the journal. No separate "permitted" record —  *)
(* the presence of the effect is the evidence.                                *)
LivePermit ==
    /\ status = "running"
    /\ mode = "live"
    /\ pos <= EffectCount
    /\ Permits(pos)
    /\ asked' = asked \cup {pos}
    /\ world' = Append(world, pos)
    /\ journal' = Append(journal, [at |-> pos, kind |-> "done"])
    /\ pos' = pos + 1
    /\ UNCHANGED <<mode, ruleset, banned, status>>

(* Denied: the engine is consulted, NOTHING reaches the world, and the denial *)
(* is journaled. The record is what makes the stop replayable.                *)
LiveDeny ==
    /\ status = "running"
    /\ mode = "live"
    /\ pos <= EffectCount
    /\ ~Permits(pos)
    /\ asked' = asked \cup {pos}
    /\ journal' = Append(journal, [at |-> pos, kind |-> "denied"])
    /\ status' = "stopped"
    /\ UNCHANGED <<mode, pos, world, ruleset, banned>>

LiveFinish ==
    /\ status = "running"
    /\ mode = "live"
    /\ pos = EffectCount + 1
    /\ status' = "done"
    /\ UNCHANGED <<mode, pos, journal, world, asked, ruleset, banned>>

-----------------------------------------------------------------------------
(*                     THE RULES CHANGE, THEN WE REPLAY                      *)
-----------------------------------------------------------------------------

(* Somebody relaxes the policy set after the run is over. This is the         *)
(* ordinary course of business, not an attack — rules change.                 *)
EditPolicy ==
    /\ status \in {"stopped", "done"}
    /\ mode = "live"
    /\ ruleset' = "relaxed"
    /\ UNCHANGED <<mode, pos, journal, world, asked, banned, status>>

(* Begin replaying the recorded run. `asked` is reset so the invariant about  *)
(* consultation is about the replay pass specifically.                        *)
StartReplay ==
    /\ status \in {"stopped", "done"}
    /\ mode = "live"
    /\ mode' = "replay"
    /\ pos' = 1
    /\ world' = << >>
    /\ asked' = {}
    /\ status' = "running"
    /\ UNCHANGED <<journal, ruleset, banned>>

(* A recorded effect is read back. Note what is absent: no call to Permits,   *)
(* and `asked` is unchanged. The effect never reaches the world, so it never  *)
(* reaches the gate.                                                          *)
ReplayDone ==
    /\ status = "running"
    /\ mode = "replay"
    /\ pos <= EffectCount
    /\ RecordKindAt(pos) = "done"
    /\ pos' = pos + 1
    /\ UNCHANGED <<mode, journal, world, asked, ruleset, banned, status>>

(* A recorded denial stops the replay in the same place, with the same        *)
(* reason, whatever the rules say now.                                        *)
ReplayDenied ==
    /\ status = "running"
    /\ mode = "replay"
    /\ pos <= EffectCount
    /\ RecordKindAt(pos) = "denied"
    /\ status' = "stopped"
    /\ UNCHANGED <<mode, pos, journal, world, asked, ruleset, banned>>

(* History ran out with the run still going: the recorded run stopped here    *)
(* and left no record saying why. Reachable only if a denial was NOT          *)
(* journaled, which is what `DenialIsDurable` rules out.                      *)
ReplayOverrun ==
    /\ status = "running"
    /\ mode = "replay"
    /\ pos <= EffectCount
    /\ RecordKindAt(pos) = "none"
    /\ status' = "stopped"
    /\ UNCHANGED <<mode, pos, journal, world, asked, ruleset, banned>>

ReplayFinish ==
    /\ status = "running"
    /\ mode = "replay"
    /\ pos = EffectCount + 1
    /\ status' = "done"
    /\ UNCHANGED <<mode, pos, journal, world, asked, ruleset, banned>>

Next ==
    \/ LivePermit
    \/ LiveDeny
    \/ LiveFinish
    \/ EditPolicy
    \/ StartReplay
    \/ ReplayDone
    \/ ReplayDenied
    \/ ReplayOverrun
    \/ ReplayFinish
    \/ (status \in {"stopped", "done"} /\ mode = "replay" /\ UNCHANGED vars)

(* Weak fairness is the model's one liveness ASSUMPTION, stated rather than   *)
(* implied: the scheduler does not stall forever with a step enabled. It      *)
(* forces nothing about WHICH step runs — a live run may still permit, deny,  *)
(* or finish — it only rules out the run that sits in "running" doing         *)
(* nothing. `Settles` below is what that assumption buys.                     *)
Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(*                              INVARIANTS                                   *)
-----------------------------------------------------------------------------

(* THE invariant. Nothing forbidden ever reached the world.                  *)
(*                                                                           *)
(* Stated against `banned` — the rules in force when the run executed —       *)
(* rather than against `Permits`, deliberately: relaxing the rules afterwards *)
(* must not retroactively make a refused call legal. (`banned` is immutable   *)
(* for the life of a behaviour; only `ruleset` models the edit.)              *)
NothingForbiddenIsPerformed ==
    \A k \in 1 .. Len(world) : world[k] \notin banned

(* The engine is never consulted during replay.                              *)
(*                                                                           *)
(* This is what stops a rule edited today from re-judging a run from last     *)
(* year. A replayed effect does not reach the world, so it must not reach     *)
(* the gate.                                                                  *)
ReplayNeverConsultsPolicy ==
    (mode = "replay") => (asked = {})

(* A stop has a record. Without one, replay reaches the end of history with   *)
(* the run still going and reports divergence for a code change that does     *)
(* not exist — the reason budget refusals are journaled too.                  *)
DenialIsDurable ==
    (status = "stopped" /\ mode = "live") => RecordedAt(pos)

(* Nothing reached the world during a replay.                                *)
ReplayPerformsNothing ==
    (mode = "replay") => (Len(world) = 0)

(* A permit leaves no record of its own: every journal entry is either an     *)
(* effect that happened or a denial that stopped the run.                     *)
NoRedundantPermitRecords ==
    \A k \in 1 .. Len(journal) : journal[k].kind \in {"done", "denied"}

Safety ==
    /\ TypeOK
    /\ NothingForbiddenIsPerformed
    /\ ReplayNeverConsultsPolicy
    /\ DenialIsDurable
    /\ ReplayPerformsNothing
    /\ NoRedundantPermitRecords

-----------------------------------------------------------------------------
(*                          TEMPORAL PROPERTIES                              *)
-----------------------------------------------------------------------------

(* The journal is recorded history: nothing rewrites or shortens it — not     *)
(* even `StartReplay`, which resets everything else. Prefix equality, not     *)
(* merely length: a journal that swapped a "denied" for a "done" at the same  *)
(* length would still be a rewritten history.                                 *)
IsPrefixOf(p, s) ==
    /\ Len(p) <= Len(s)
    /\ \A k \in 1 .. Len(p) : s[k] = p[k]

JournalIsAppendOnly == [][IsPrefixOf(journal, journal')]_vars

(* Under weak fairness, every run — and the replay of it, if one starts —     *)
(* eventually comes to rest at a recorded outcome and stays there. A stop on  *)
(* a denial counts: "stopped" is a decision, not a hang.                      *)
Settles == <>[](status \in {"stopped", "done"})

=============================================================================
