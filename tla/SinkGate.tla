-------------------------------- MODULE SinkGate --------------------------------
(***************************************************************************)
(* The sink gate under replay and resume.                                   *)
(*                                                                          *)
(* A step sends a labelled value into a sink whose ceiling the deployment's *)
(* configuration sets — a tool's catalogue entry, a reviewed grant — and    *)
(* which an operator may edit between passes. `StepCtx::sink` judges the    *)
(* value only where dispatch is LIVE, and "live" is a property of the       *)
(* cursor, not of the mode (`writes_enabled`): a replayed effect reads its  *)
(* verdict back from the record — a pass as the effect's terminal record, a *)
(* refusal as its `PolicyDenied` — and a resume past its frontier judges    *)
(* the live tail under the configuration then in force. A release is        *)
(* journaled before the send it covers, and a replay reads it back.         *)
(*                                                                          *)
(* Two failures this rules out, both of which read as reasonable code:      *)
(* gates keyed on the mode, which switch them off for a resume's whole live *)
(* tail, and a replay that re-judges a recorded effect against today's      *)
(* configuration, which makes a catalogue edit rewrite what a finished run  *)
(* was allowed to do. Concurrent owners are Fencing.tla's; an effect lost   *)
(* between announcement and record is EffectProtocol.tla's.                 *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    N,           (* steps, each one send                                    *)
    High,        (* the steps whose value is above the low ceiling          *)
    MaxCrashes

Steps == 1 .. N

VARIABLES
    pc,          (* the step the current pass is at                         *)
    ceiling,     (* "low" or "high": what the configuration admits now      *)
    released,    (* released[i]: a release covering step i's send is journaled *)
    journal,     (* journal[i]: "none", "performed" or "refused"            *)
    world,       (* world[i]: how often step i's send reached the sink      *)
    allowed,     (* history: whether step i's send was covered when it went *)
    crashes

vars == <<pc, ceiling, released, journal, world, allowed, crashes>>

TypeOK ==
    /\ pc \in 1 .. N + 1
    /\ ceiling \in {"low", "high"}
    /\ released \in [Steps -> BOOLEAN]
    /\ journal \in [Steps -> {"none", "performed", "refused"}]
    /\ world \in [Steps -> 0 .. 2]
    /\ allowed \in [Steps -> BOOLEAN]

(* Whether step i's value may cross now: low, released, or under a high     *)
(* ceiling.                                                                 *)
Covered(i) == i \notin High \/ released[i] \/ ceiling = "high"

(* Dispatch is live where the record holds nothing for this step.           *)
Live(i) == journal[i] = "none"

Init ==
    /\ pc = 1
    /\ ceiling \in {"low", "high"}
    /\ released = [i \in Steps |-> FALSE]
    /\ journal = [i \in Steps |-> "none"]
    /\ world = [i \in Steps |-> 0]
    /\ allowed = [i \in Steps |-> TRUE]
    /\ crashes = 0

-----------------------------------------------------------------------------

(* The step journals a release for its own send, before sending.            *)
Release ==
    /\ pc <= N /\ Live(pc) /\ ~released[pc]
    /\ released' = [released EXCEPT ![pc] = TRUE]
    /\ UNCHANGED <<pc, ceiling, journal, world, allowed, crashes>>

(* The gate: judged where dispatch is live, read back where it is not.     *)
Send ==
    /\ pc <= N
    /\ IF Live(pc)
       THEN IF Covered(pc)
            THEN /\ journal' = [journal EXCEPT ![pc] = "performed"]
                 /\ world' = [world EXCEPT ![pc] = @ + 1]
                 /\ allowed' = [allowed EXCEPT ![pc] = Covered(pc)]
            ELSE /\ journal' = [journal EXCEPT ![pc] = "refused"]
                 /\ UNCHANGED <<world, allowed>>
       ELSE UNCHANGED <<journal, world, allowed>>
    /\ pc' = pc + 1
    /\ UNCHANGED <<ceiling, released, crashes>>

(* An operator edits the configuration: any time, in either direction.      *)
Edit ==
    /\ ceiling' = IF ceiling = "low" THEN "high" ELSE "low"
    /\ UNCHANGED <<pc, released, journal, world, allowed, crashes>>

(* The process dies; the next pass replays the record from the start and   *)
(* runs live past it.                                                       *)
Crash ==
    /\ crashes < MaxCrashes /\ pc > 1
    /\ pc' = 1
    /\ crashes' = crashes + 1
    /\ UNCHANGED <<ceiling, released, journal, world, allowed>>

Next == Release \/ Send \/ Edit \/ Crash \/ UNCHANGED vars

Spec == Init /\ [][Next]_vars /\ WF_vars(Send)

-----------------------------------------------------------------------------

(* No value crossed a sink it was not covered for when it went: the gate    *)
(* runs on every live dispatch, a resume's live tail included               *)
(* (`StepCtx::sink`, `writes_enabled`).                                     *)
NoSinkWithoutCoveringRelease ==
    \A i \in Steps : world[i] > 0 => allowed[i]

(* A refusal on the record is the verdict on every later pass: nothing a    *)
(* configuration edit does makes a refused send go out on replay.           *)
ReplayReproducesRefusal ==
    \A i \in Steps : journal[i] = "refused" => world[i] = 0

(* A replayed send is read back, never sent again.                          *)
SentOnce ==
    \A i \in Steps : world[i] <= 1

Safety ==
    /\ TypeOK
    /\ NoSinkWithoutCoveringRelease
    /\ ReplayReproducesRefusal
    /\ SentOnce

(* Under WF(Send): every step's send is decided, sent or refused.           *)
EverySendIsDecided ==
    <>(\A i \in Steps : journal[i] # "none")

=============================================================================
