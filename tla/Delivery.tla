-------------------------------- MODULE Delivery --------------------------------
(***************************************************************************)
(* Inbound messages and timer wakes reaching the runs that wait for them.   *)
(*                                                                          *)
(* A message is stored before anyone looks for a waiter (`Runtime::deliver`)*)
(* and deduplicated on (source, id) (`InboundEvent::dedup_key`). Storing    *)
(* and matching are two writes; a delivery that dies between them leaves a  *)
(* stored message nobody was offered, and the counterparty's retry — a      *)
(* duplicate by its key — offers it again. A claim, by the matching path    *)
(* (`EventStore::match_waiter`), by the waiting step itself (`claim_for`)   *)
(* or by targeted delivery (`deliver_to`), names the wait it is for and     *)
(* parks it, so the wait takes no second message. A wait recovers only its  *)
(* own standing claim; journaling the message and retiring the wait         *)
(* (`unsubscribe`) consumes it, so the run's next wait on the same key is   *)
(* never handed it again. A wait naming a sender takes no other's message,  *)
(* and a message sent to one named run reaches no other.                   *)
(*                                                                          *)
(* A run's conclusion, its seal and the retirement of its waits are steps a *)
(* crash can fall between. A delivery to a run whose conclusion is durable  *)
(* journals nothing (`resume_subscription`); the retirement                 *)
(* (`unsubscribe_run`) offers a message the run claimed and never consumed  *)
(* to the next waiter — and dead-letters one that was sent to that run by   *)
(* name. A timer wake is recorded at most once, and never for a run whose   *)
(* conclusion is durable (`fire_one`).                                      *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Runs,        (* runs waiting on one key                                 *)
    Ending,      (* the runs that may conclude while waiting                *)
    Picky,       (* the run whose wait names a sender                       *)
    Turns,       (* how many waits each run makes on the key                *)
    MaxCrashes

Senders == {"s1", "s2"}
(* Two producers using the same id: a collision the key must survive.      *)
Msgs == {[src |-> s, id |-> 1] : s \in Senders}
NoRun == [run |-> "none", turn |-> 0]   (* no claim                            *)
Nobody == "none"                         (* sent to no run by name              *)
Named == "s1"   (* the sender Picky's wait names                           *)

VARIABLES
    sent,        (* messages a counterparty has sent                        *)
    stored,      (* messages in the buffer                                  *)
    attempt,     (* attempt[m]: "idle", "matching", "died" or "done"        *)
    claim,       (* claim[m]: the [run, turn] it is claimed for, or NoRun   *)
    consumed,    (* consumed[m]: journaled by the wait it was claimed for   *)
    dead,        (* dead[m]: dead-lettered                                  *)
    targetOf,    (* targetOf[m]: the run it was sent to by name, or Nobody  *)
    turn,        (* turn[r]: the wait r is on; 0 before the first           *)
    waiting,     (* waiting[r]: r's current wait is registered              *)
    fresh,       (* fresh[r]: registered, its in-step claim not yet tried   *)
    parked,      (* parked[r]: r's current wait holds an undelivered claim  *)
    got,         (* got[r][t]: messages journaled for r's wait t            *)
    concluded,
    retired,
    late,        (* history: an answer journaled after a conclusion         *)
    crashes,
    armed,       (* armed[r]: r's one timer is still armed                  *)
    wakes,       (* wakes[r]: wakes recorded for it                         *)
    lateWake     (* history: a wake recorded after a conclusion             *)

vars == <<sent, stored, attempt, claim, consumed, dead, targetOf, turn,
          waiting, fresh, parked, got, concluded, retired, late, crashes,
          armed, wakes, lateWake>>

Key(m) == <<m.src, m.id>>
Accepts(r, m) == r # Picky \/ m.src = Named
Open(r) == waiting[r] /\ ~parked[r]
Me(r) == [run |-> r, turn |-> turn[r]]

TypeOK ==
    /\ sent \subseteq Msgs /\ stored \subseteq Msgs
    /\ \A m \in Msgs : attempt[m] \in {"idle", "matching", "died", "done"}
    /\ \A r \in Runs : turn[r] \in 0 .. Turns

Init ==
    /\ sent = {} /\ stored = {}
    /\ attempt = [m \in Msgs |-> "idle"]
    /\ claim = [m \in Msgs |-> NoRun]
    /\ consumed = [m \in Msgs |-> FALSE]
    /\ dead = [m \in Msgs |-> FALSE]
    /\ targetOf = [m \in Msgs |-> Nobody]
    /\ turn = [r \in Runs |-> 0]
    /\ waiting = [r \in Runs |-> FALSE]
    /\ fresh = [r \in Runs |-> FALSE]
    /\ parked = [r \in Runs |-> FALSE]
    /\ got = [r \in Runs |-> [t \in 1 .. Turns |-> {}]]
    /\ concluded = [r \in Runs |-> FALSE]
    /\ retired = [r \in Runs |-> FALSE]
    /\ late = FALSE
    /\ crashes = 0
    /\ armed = [r \in Runs |-> TRUE]
    /\ wakes = [r \in Runs |-> 0]
    /\ lateWake = FALSE

-----------------------------------------------------------------------------

(* A run reaches its next wait on the key and registers it.                 *)
Wait(r) ==
    /\ ~waiting[r] /\ turn[r] < Turns /\ ~concluded[r]
    /\ turn' = [turn EXCEPT ![r] = @ + 1]
    /\ waiting' = [waiting EXCEPT ![r] = TRUE]
    /\ fresh' = [fresh EXCEPT ![r] = TRUE]
    /\ UNCHANGED <<sent, stored, attempt, claim, consumed, dead, targetOf,
                   parked, got, concluded, retired, late, crashes, armed,
                   wakes, lateWake>>

(* `claim_for`, once, as the wait registers: this wait's own standing      *)
(* claim — made after a crash, or by a delivery that reached the wait       *)
(* between its registration and this step — or, when it holds none, a      *)
(* stored message nobody holds. The claim parks it.                         *)
Claimable(r, m) ==
    /\ m \in stored /\ ~dead[m] /\ ~consumed[m] /\ Accepts(r, m)
    /\ \/ claim[m] = NoRun /\ ~parked[r]
       \/ claim[m] = Me(r)

ClaimInStep(r) ==
    /\ fresh[r] /\ waiting[r] /\ ~concluded[r]
    /\ fresh' = [fresh EXCEPT ![r] = FALSE]
    /\ IF \E m \in Msgs : Claimable(r, m)
       THEN \E m \in Msgs :
              /\ Claimable(r, m)
              /\ claim' = [claim EXCEPT ![m] = Me(r)]
              /\ parked' = [parked EXCEPT ![r] = TRUE]
       ELSE UNCHANGED <<claim, parked>>
    /\ UNCHANGED <<sent, stored, attempt, consumed, dead, targetOf, turn,
                   waiting, got, concluded, retired, late, crashes, armed,
                   wakes, lateWake>>

(* The counterparty sends m to whoever waits: stored, deduplicated on its  *)
(* key; the match is a second write.                                        *)
Send(m) ==
    /\ m \notin sent
    /\ sent' = sent \cup {m}
    /\ IF \E n \in stored : Key(n) = Key(m)
       THEN UNCHANGED <<stored, attempt>>
       ELSE /\ stored' = stored \cup {m}
            /\ attempt' = [attempt EXCEPT ![m] = "matching"]
    /\ UNCHANGED <<claim, consumed, dead, targetOf, turn, waiting, fresh,
                   parked, got, concluded, retired, late, crashes, armed,
                   wakes, lateWake>>

(* `match_waiter`: offered to an open wait that accepts it, which is parked *)
(* in the same write. The store passes over a sealed run, not a concluded  *)
(* one, so a conclusion not yet retired can still be matched.               *)
Match(m, r) ==
    /\ attempt[m] = "matching" /\ m \in stored
    /\ claim[m] = NoRun /\ ~consumed[m] /\ ~dead[m]
    /\ Open(r) /\ Accepts(r, m)
    /\ claim' = [claim EXCEPT ![m] = Me(r)]
    /\ parked' = [parked EXCEPT ![r] = TRUE]
    /\ attempt' = [attempt EXCEPT ![m] = "done"]
    /\ UNCHANGED <<sent, stored, consumed, dead, targetOf, turn, waiting,
                   fresh, got, concluded, retired, late, crashes, armed,
                   wakes, lateWake>>

(* No open wait accepts it now: buffered, for a wait that registers later.  *)
Buffered(m) ==
    /\ attempt[m] = "matching"
    /\ ~\E r \in Runs : Open(r) /\ Accepts(r, m)
    /\ attempt' = [attempt EXCEPT ![m] = "done"]
    /\ UNCHANGED <<sent, stored, claim, consumed, dead, targetOf, turn,
                   waiting, fresh, parked, got, concluded, retired, late,
                   crashes, armed, wakes, lateWake>>

(* The delivery dies after storing and before matching.                     *)
Die(m) ==
    /\ attempt[m] = "matching" /\ crashes < MaxCrashes
    /\ attempt' = [attempt EXCEPT ![m] = "died"]
    /\ crashes' = crashes + 1
    /\ UNCHANGED <<sent, stored, claim, consumed, dead, targetOf, turn,
                   waiting, fresh, parked, got, concluded, retired, late,
                   armed, wakes, lateWake>>

(* No answer came, so the counterparty retries: a duplicate by its key, and *)
(* matched again.                                                           *)
Retry(m) ==
    /\ attempt[m] = "died"
    /\ attempt' = [attempt EXCEPT ![m] = "matching"]
    /\ UNCHANGED <<sent, stored, claim, consumed, dead, targetOf, turn,
                   waiting, fresh, parked, got, concluded, retired, late,
                   crashes, armed, wakes, lateWake>>

(* `deliver_to`: stored and claimed for exactly r in one write, or nothing  *)
(* at all when r's wait does not take it.                                   *)
DeliverTo(m, r) ==
    /\ m \notin sent
    /\ sent' = sent \cup {m}
    /\ targetOf' = [targetOf EXCEPT ![m] = r]
    /\ IF Open(r) /\ Accepts(r, m) /\ ~\E n \in stored : Key(n) = Key(m)
       THEN /\ stored' = stored \cup {m}
            /\ claim' = [claim EXCEPT ![m] = Me(r)]
            /\ parked' = [parked EXCEPT ![r] = TRUE]
       ELSE UNCHANGED <<stored, claim, parked>>
    /\ UNCHANGED <<attempt, consumed, dead, turn, waiting, fresh, got,
                   concluded, retired, late, crashes, armed, wakes, lateWake>>

(* The delivery or the redelivery pass journals whatever the wait holds    *)
(* claimed — it does not look again at whether it was consumed — *)
(* and retires the wait — and journals nothing for a run whose conclusion   *)
(* is durable, which the retirement then finishes.                          *)
Resume(r) ==
    /\ parked[r] /\ ~concluded[r]
    /\ \E m \in Msgs :
        /\ claim[m] = Me(r)
        /\ consumed' = [consumed EXCEPT ![m] = TRUE]
        /\ got' = [got EXCEPT ![r][turn[r]] = @ \cup {m}]
        /\ late' = (late \/ concluded[r])
    /\ waiting' = [waiting EXCEPT ![r] = FALSE]
    /\ parked' = [parked EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<sent, stored, attempt, claim, dead, targetOf, turn, fresh,
                   concluded, retired, crashes, armed, wakes, lateWake>>

Conclude(r) ==
    /\ r \in Ending /\ ~concluded[r]
    /\ concluded' = [concluded EXCEPT ![r] = TRUE]
    /\ UNCHANGED <<sent, stored, attempt, claim, consumed, dead, targetOf,
                   turn, waiting, fresh, parked, got, retired, late, crashes,
                   armed, wakes, lateWake>>

(* `unsubscribe_run`: what r claimed and never consumed is offered again — *)
(* unless it was sent to r by name, when it is dead-lettered.               *)
Unconsumed(r, m) == claim[m].run = r /\ ~consumed[m]

Retire(r) ==
    /\ concluded[r] /\ ~retired[r]
    /\ retired' = [retired EXCEPT ![r] = TRUE]
    /\ waiting' = [waiting EXCEPT ![r] = FALSE]
    /\ fresh' = [fresh EXCEPT ![r] = FALSE]
    /\ parked' = [parked EXCEPT ![r] = FALSE]
    /\ armed' = [armed EXCEPT ![r] = FALSE]
    /\ claim' = [m \in Msgs |-> IF Unconsumed(r, m) THEN NoRun ELSE claim[m]]
    /\ dead' = [m \in Msgs |->
                  dead[m] \/ (Unconsumed(r, m) /\ targetOf[m] = r)]
    /\ attempt' = [m \in Msgs |->
                     IF Unconsumed(r, m) /\ targetOf[m] # r THEN "matching"
                     ELSE attempt[m]]
    /\ UNCHANGED <<sent, stored, consumed, targetOf, turn, got, concluded,
                   late, crashes, wakes, lateWake>>

(* `fire_one`: r's timer comes due — again, after a crash before it was     *)
(* disarmed. A recorded wake is not recorded twice; a run whose conclusion  *)
(* is durable is woken for nothing.                                         *)
Fire(r) ==
    /\ armed[r]
    /\ wakes' = [wakes EXCEPT ![r] =
                   IF @ = 0 /\ ~concluded[r] THEN @ + 1 ELSE @]
    /\ lateWake' = (lateWake \/ (wakes'[r] > wakes[r] /\ concluded[r]))
    /\ UNCHANGED <<sent, stored, attempt, claim, consumed, dead, targetOf,
                   turn, waiting, fresh, parked, got, concluded, retired, late,
                   crashes, armed>>

Disarm(r) ==
    /\ armed[r] /\ wakes[r] > 0
    /\ armed' = [armed EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<sent, stored, attempt, claim, consumed, dead, targetOf,
                   turn, waiting, fresh, parked, got, concluded, retired, late,
                   crashes, wakes, lateWake>>

Next ==
    \/ \E r \in Runs :
        \/ Wait(r) \/ ClaimInStep(r) \/ Resume(r) \/ Conclude(r) \/ Retire(r)
        \/ Fire(r) \/ Disarm(r)
    \/ \E m \in Msgs :
        \/ Send(m) \/ Buffered(m) \/ Die(m) \/ Retry(m)
        \/ \E r \in Runs : Match(m, r) \/ DeliverTo(m, r)
    \/ UNCHANGED vars

(* The plane's own steps are fair; the counterparty is assumed to retry a   *)
(* delivery that got no answer. Nothing makes anybody send or conclude.     *)
Spec ==
    /\ Init /\ [][Next]_vars
    /\ \A r \in Runs : /\ WF_vars(Wait(r)) /\ WF_vars(ClaimInStep(r))
                       /\ WF_vars(Resume(r)) /\ WF_vars(Retire(r))
    /\ \A m \in Msgs : /\ WF_vars(Retry(m)) /\ WF_vars(Buffered(m))
                       /\ \A r \in Runs : WF_vars(Match(m, r))

-----------------------------------------------------------------------------

(* No message is journaled twice, by one wait or two (`claim_for`'s own-    *)
(* claim arm, `unsubscribe`).                                               *)
ConsumedExactlyOnce ==
    \A m \in Msgs :
        Cardinality({w \in Runs \X (1 .. Turns) : m \in got[w[1]][w[2]]}) <= 1

(* A wait journals one message (the claim parks it).                       *)
OneMessagePerWait ==
    \A r \in Runs : \A t \in 1 .. Turns : Cardinality(got[r][t]) <= 1

(* A claim is only ever on a stored message (`Runtime::deliver`).           *)
DurableBeforeMatch ==
    \A m \in Msgs : claim[m] # NoRun => m \in stored

(* Two producers' messages with one id are two messages                     *)
(* (`InboundEvent::dedup_key`).                                             *)
CollidingIdsAreDistinct ==
    \A m \in sent : targetOf[m] = Nobody => m \in stored

(* A wait naming its sender takes no other's message (`AwaitSpec::from`).   *)
SenderFilterHolds ==
    \A r \in Runs : \A t \in 1 .. Turns : \A m \in got[r][t] : Accepts(r, m)

(* A message sent to one run by name reaches no other (`deliver_to`,       *)
(* `unsubscribe_run`).                                                      *)
TargetedReachesOnlyItsRun ==
    \A m \in Msgs : \A r \in Runs : \A t \in 1 .. Turns :
        (m \in got[r][t] /\ targetOf[m] # Nobody) => r = targetOf[m]

(* Nothing is journaled after a durable conclusion                          *)
(* (`resume_subscription`, `fire_one`).                                     *)
NoAnswerAfterConclusion == ~late
NoWakeAfterConclusion == ~lateWake

(* A timer's wake is recorded once (`fire_one`).                            *)
OneWakePerTimer == \A r \in Runs : wakes[r] <= 1

Safety ==
    /\ TypeOK
    /\ ConsumedExactlyOnce
    /\ OneMessagePerWait
    /\ DurableBeforeMatch
    /\ CollidingIdsAreDistinct
    /\ SenderFilterHolds
    /\ TargetedReachesOnlyItsRun
    /\ NoAnswerAfterConclusion
    /\ NoWakeAfterConclusion
    /\ OneWakePerTimer

(* A message sent to whoever waits is journaled by a wait that takes it —   *)
(* unless dead-lettered — whatever crashed and whichever run concluded      *)
(* first, so long as a live run keeps waiting.                              *)
EveryMessageReachesAWaiter ==
    \A m \in Msgs : (m \in stored /\ targetOf[m] = Nobody) ~> (consumed[m] \/ dead[m])

=============================================================================
