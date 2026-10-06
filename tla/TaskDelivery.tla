------------------------------ MODULE TaskDelivery ------------------------------
(***************************************************************************)
(* A human task's answer reaching the run that asked for it.                *)
(*                                                                          *)
(* A run waiting on a task is answered through the decision door alone      *)
(* (`Runtime::decide_task_at`): the decider's claim is taken first          *)
(* (`TaskStore::claim`), then the answer is delivered as the one message    *)
(* the task's id names (`answer_task`), so a second answer — another        *)
(* decider's, or the expiry policy's — is a duplicate rather than a second  *)
(* decision. The run journals at most one answer, never after its           *)
(* conclusion is durable, and a run that concludes withdraws its pending    *)
(* tasks (`TaskStore::withdraw_run`). A decider is told the decision landed *)
(* only when a waiting run can still receive it: one that lost to the       *)
(* run's conclusion between the claim and the answer is refused.            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Deciders,    (* people who may answer the task                          *)
    Expiry       (* the name the expiry policy answers under                *)

Answerers == Deciders \cup {Expiry}
Nobody == "nobody"

VARIABLES
    state,       (* the task: "pending", "completed", "expired", "withdrawn" *)
    holder,      (* who holds the claim, or Nobody                          *)
    answer,      (* who the stored answer is from, or Nobody                *)
    journaled,   (* the answers the run journaled                           *)
    concluded,   (* the run's conclusion is durable                         *)
    retired,     (* its waits retired and its tasks withdrawn               *)
    late,        (* history: an answer journaled after the conclusion       *)
    told,        (* deciders told their decision landed                     *)
    reopened     (* history: a withdrawn task was settled to another state  *)

vars == <<state, holder, answer, journaled, concluded, retired, late, told,
          reopened>>

TypeOK ==
    /\ state \in {"pending", "completed", "expired", "withdrawn"}
    /\ holder \in Deciders \cup {Nobody}
    /\ answer \in Answerers \cup {Nobody}
    /\ journaled \subseteq Answerers
    /\ told \subseteq Deciders

Init ==
    /\ state = "pending" /\ holder = Nobody /\ answer = Nobody
    /\ journaled = {} /\ concluded = FALSE /\ retired = FALSE
    /\ late = FALSE /\ told = {} /\ reopened = FALSE

-----------------------------------------------------------------------------

(* `TaskStore::settle` from state `from`: only a pending task moves.        *)
Settle(from, to) ==
    /\ state' = IF from = "pending" THEN to ELSE from
    /\ reopened' = (reopened \/ (from = "withdrawn" /\ state' # from))

(* A run not yet concluded journals the answer.                            *)
Receivable == ~concluded

(* A decider takes the claim on a pending task.                             *)
Claim(d) ==
    /\ state = "pending" /\ holder = Nobody
    /\ holder' = d
    /\ UNCHANGED <<state, answer, journaled, concluded, retired, late, told,
                   reopened>>

(* The claim holder's answer is delivered and the task settled. A run whose *)
(* conclusion is durable journals nothing: the delivery finishes it,        *)
(* withdrawing the task, and the decider is refused. A second answer is a   *)
(* duplicate: its own decider's resubmission settles and succeeds, anybody  *)
(* else's is refused.                                                       *)
Answer(d) ==
    /\ holder = d
    /\ IF answer = Nobody
       THEN /\ answer' = d
            /\ IF concluded
               THEN /\ retired' = TRUE
                    (* The delivery finished the run, withdrawing the task;  *)
                    (* the decision's settlement then meets the withdrawal.  *)
                    /\ Settle(IF state = "pending" THEN "withdrawn" ELSE state,
                              "completed")
                    /\ UNCHANGED <<journaled, told>>
               ELSE /\ journaled' = journaled \cup {d}
                    /\ Settle(state, "completed")
                    /\ told' = told \cup {d}
                    /\ UNCHANGED retired
       ELSE /\ UNCHANGED <<answer, journaled, retired>>
            /\ Settle(state, IF answer \in Deciders THEN "completed" ELSE "expired")
            /\ told' = IF answer = d THEN told \cup {d} ELSE told
    /\ late' = (late \/ (concluded /\ journaled' # journaled))
    /\ holder' = Nobody
    /\ UNCHANGED concluded

(* The expiry policy answers a task nobody decided in time.                 *)
Expire ==
    /\ state = "pending" /\ answer = Nobody
    /\ answer' = Expiry
    /\ journaled' = IF Receivable THEN journaled \cup {Expiry} ELSE journaled
    /\ Settle(state, "expired")
    /\ UNCHANGED <<holder, concluded, retired, late, told>>

(* The run concludes — cancelled, say — and later withdraws its tasks.      *)
Conclude ==
    /\ ~concluded
    /\ concluded' = TRUE
    /\ UNCHANGED <<state, holder, answer, journaled, retired, late, told,
                   reopened>>

Withdraw ==
    /\ concluded /\ ~retired
    /\ retired' = TRUE
    /\ state' = IF state = "pending" THEN "withdrawn" ELSE state
    /\ UNCHANGED <<holder, answer, journaled, concluded, late, told, reopened>>

Next ==
    \/ \E d \in Deciders : Claim(d) \/ Answer(d)
    \/ Expire \/ Conclude \/ Withdraw
    \/ UNCHANGED vars

Spec == Init /\ [][Next]_vars /\ WF_vars(Withdraw)
                              /\ \A d \in Deciders : WF_vars(Answer(d))

-----------------------------------------------------------------------------

(* The run journals one answer per task (`answer_task`'s fixed event id).   *)
OneDecisionPerTask == Cardinality(journaled) <= 1

(* No answer is journaled after the run's conclusion is durable            *)
(* (`resume_subscription`).                                                 *)
NoDecisionReachesAConcludedRun == ~late

(* A withdrawn task is never settled to anything else                       *)
(* (`TaskStore::withdraw_run`, `settle`).                                   *)
WithdrawnStaysWithdrawn == ~reopened

(* A decider told their decision landed made the stored answer, and the     *)
(* task did not end withdrawn under it (`decide_task_at`).                  *)
DeciderToldTheTruth ==
    \A d \in told : answer = d /\ state # "withdrawn"

Safety ==
    /\ TypeOK
    /\ OneDecisionPerTask
    /\ NoDecisionReachesAConcludedRun
    /\ WithdrawnStaysWithdrawn
    /\ DeciderToldTheTruth

(* Under WF(Answer) and WF(Withdraw): a claimed task is answered, and a     *)
(* concluded run's task is withdrawn, so no task is left pending for ever   *)
(* behind a run that ended.                                                 *)
NoTaskOutlivesItsRun == (concluded /\ state = "pending") ~> state # "pending"

=============================================================================
