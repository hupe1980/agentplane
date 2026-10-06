------------------------------ MODULE KeyLifecycle ------------------------------
(***************************************************************************)
(* One erasure scope's key: rotation, retirement, destruction, outage.      *)
(*                                                                          *)
(* A payload is sealed under the scope's current wrapping-key version and   *)
(* names that version for as long as it exists. Opening it answers one of  *)
(* four things (`KeyRing::open`, `KeyError`), and the answers are the       *)
(* point: an outage is `Unavailable` and may succeed later; a destroyed     *)
(* scope is `Destroyed` and never comes back; a version below the key       *)
(* service's floor is `Retired`, which an operator can undo; anything else  *)
(* opens. Reading an outage as an erasure discharges a request that was     *)
(* never carried out, and reading a retirement as one reports a policy      *)
(* change as data loss.                                                     *)
(*                                                                          *)
(* `KeyRing::destroy` is idempotent and the first destruction stands, with  *)
(* its reason. `KeyRing::data_key` refuses a destroyed scope, so a live run  *)
(* sealing into a case while `erase_case` destroys it cannot reopen the     *)
(* scope with a fresh key.                                                  *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    MaxVersion,  (* wrapping-key versions 1 .. MaxVersion                    *)
    Reasons      (* erasure reasons                                         *)

Versions == 1 .. MaxVersion
NoReason == "none"

VARIABLES
    current,      (* the version new payloads seal under                    *)
    floor,        (* the lowest version the key service decrypts            *)
    admitted,     (* the versions the key service will decrypt              *)
    destroyed,
    reason,       (* the reason the scope records for its destruction       *)
    firstReason,  (* history: the reason the first destruction gave         *)
    reachable,    (* the key ring answers                                   *)
    sealed,       (* the versions payloads were sealed under                *)
    lateWrite,    (* history: a payload was sealed into a destroyed scope   *)
    asking,       (* a read of one payload is pending                       *)
    asked,        (* the version that read names                            *)
    verdict       (* the last answer: "none", "ok", "retired", "destroyed", *)
                  (* "unavailable"                                          *)

vars == <<current, floor, admitted, destroyed, reason, firstReason, reachable,
          sealed, lateWrite, asking, asked, verdict>>

TypeOK ==
    /\ current \in Versions
    /\ floor \in Versions
    /\ admitted \subseteq Versions
    /\ destroyed \in BOOLEAN
    /\ reachable \in BOOLEAN
    /\ sealed \subseteq Versions
    /\ verdict \in {"none", "ok", "retired", "destroyed", "unavailable"}

Init ==
    /\ current = 1
    /\ floor = 1
    /\ admitted = {1}
    /\ destroyed = FALSE
    /\ reason = NoReason
    /\ firstReason = NoReason
    /\ reachable = TRUE
    /\ sealed = {}
    /\ lateWrite = FALSE
    /\ asking = FALSE
    /\ asked = 1
    /\ verdict = "none"

-----------------------------------------------------------------------------

(* `KeyRing::data_key` then seal: refused once the scope is destroyed.      *)
Seal ==
    /\ reachable
    /\ ~destroyed
    /\ sealed' = sealed \cup {current}
    /\ lateWrite' = (lateWrite \/ destroyed)
    /\ UNCHANGED <<current, floor, admitted, destroyed, reason, firstReason,
                   reachable, asking, asked, verdict>>

(* A new version; every version the floor admits stays admitted.           *)
Rotate ==
    /\ current < MaxVersion
    /\ current' = current + 1
    /\ admitted' = admitted \cup {current + 1}
    /\ UNCHANGED <<floor, destroyed, reason, firstReason, reachable, sealed,
                   lateWrite, asking, asked, verdict>>

(* An operator raises or lowers the decryption floor.                       *)
Retire ==
    /\ floor < current
    /\ floor' = floor + 1
    /\ admitted' = admitted \ {floor}
    /\ UNCHANGED <<current, destroyed, reason, firstReason, reachable, sealed,
                   lateWrite, asking, asked, verdict>>

Unretire ==
    /\ floor > 1
    /\ floor' = floor - 1
    /\ admitted' = admitted \cup {floor - 1}
    /\ UNCHANGED <<current, destroyed, reason, firstReason, reachable, sealed,
                   lateWrite, asking, asked, verdict>>

(* `KeyRing::destroy`: the first destruction stands.                         *)
Destroy(r) ==
    /\ reachable
    /\ destroyed' = TRUE
    /\ reason' = IF destroyed THEN reason ELSE r
    /\ firstReason' = IF destroyed THEN firstReason ELSE r
    /\ UNCHANGED <<current, floor, admitted, reachable, sealed, lateWrite,
                   asking, asked, verdict>>

Outage ==
    /\ reachable
    /\ reachable' = FALSE
    /\ UNCHANGED <<current, floor, admitted, destroyed, reason, firstReason,
                   sealed, lateWrite, asking, asked, verdict>>

Restore ==
    /\ ~reachable
    /\ reachable' = TRUE
    /\ UNCHANGED <<current, floor, admitted, destroyed, reason, firstReason,
                   sealed, lateWrite, asking, asked, verdict>>

(* A reader asks to open a sealed payload.                                  *)
Ask(v) ==
    /\ ~asking /\ v \in sealed
    /\ asking' = TRUE
    /\ asked' = v
    /\ UNCHANGED <<current, floor, admitted, destroyed, reason, firstReason,
                   reachable, sealed, lateWrite, verdict>>

(* `KeyRing::open`. An outage answers `Unavailable` and the reader asks     *)
(* again; every other answer settles the read.                              *)
Open ==
    /\ asking
    /\ verdict' = IF ~reachable THEN "unavailable"
                  ELSE IF destroyed THEN "destroyed"
                  ELSE IF asked \notin admitted THEN "retired"
                  ELSE "ok"
    /\ asking' = ~reachable
    /\ UNCHANGED <<current, floor, admitted, destroyed, reason, firstReason,
                   reachable, sealed, lateWrite, asked>>

Next ==
    \/ Seal \/ Rotate \/ Retire \/ Unretire \/ Outage \/ Restore \/ Open
    \/ \E r \in Reasons : Destroy(r)
    \/ \E v \in Versions : Ask(v)
    \/ UNCHANGED vars

(* Weak fairness on Restore; STRONG fairness on opening while reachable: a *)
(* key ring that keeps failing could otherwise catch every attempt down.    *)
Spec == Init /\ [][Next]_vars /\ WF_vars(Restore) /\ SF_vars(Open /\ reachable)

-----------------------------------------------------------------------------

(* An answer of *destroyed* is given only for a destroyed scope: an outage  *)
(* is never an erasure (`KeyError::Unavailable` vs `KeyError::Destroyed`).  *)
OutageIsNotErasure ==
    verdict = "destroyed" => destroyed

(* Rotation never drops a version the floor still admits                    *)
(* (`KeyRing::open`, `KeyError::Retired`).                                  *)
NamedVersionAdmitted ==
    \A v \in Versions : (v >= floor /\ v <= current) => v \in admitted

(* The first destruction stands, with its reason (`KeyRing::destroy`).      *)
ErasureIdempotent ==
    destroyed => reason = firstReason

(* No payload is sealed into a destroyed scope (`KeyRing::data_key`).       *)
NoWriteIntoErasedScope ==
    ~lateWrite

Safety ==
    /\ TypeOK
    /\ OutageIsNotErasure
    /\ NamedVersionAdmitted
    /\ ErasureIdempotent
    /\ NoWriteIntoErasedScope

(* Under WF(Restore) and SF(Open while reachable): a read asked during an *)
(* outage is         *)
(* eventually answered with what is true of the payload, never left at    *)
(* *unavailable*.                                                           *)
OutageEventuallyAnswered ==
    asking ~> (~asking /\ verdict # "unavailable")

=============================================================================
