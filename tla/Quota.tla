--------------------------------- MODULE Quota ---------------------------------
(***************************************************************************)
(* Per-tenant ceilings on concurrent work and on a period's spend.          *)
(*                                                                          *)
(* src/quota/mod.rs states the bound as a claim over interleavings: a       *)
(* period's settled spend never exceeds its ceiling through work admitted   *)
(* in it, however runs suspend, resume, crash, conclude, or admit from      *)
(* several instances at once. Admission (`QuotaStore::reserve`, through     *)
(* `check_spend`) takes the slot and holds the run's worst case against the *)
(* period in ONE transaction; every pass settlement (`QuotaStore::settle`)  *)
(* moves that pass's spend out of the hold, into the period the pass        *)
(* started in, under a receipt; a resume is never gated and carries its     *)
(* remainder into the period it resumes in (`QuotaStore::carry`), which is  *)
(* the one stated way spend reaches past a period's ceiling.                *)
(*                                                                          *)
(* A pass writes its `QuotaPassStarted` marker with its first record, so a  *)
(* pass that writes nothing leaves nothing to settle. Recovery              *)
(* (`settle_recorded_quota_passes`) settles every marked pass of a crashed  *)
(* run once; the sweep (`Runtime::release_sealed_slots`) does the same for  *)
(* a run sealed by an instance that died before giving its slot back.      *)
(*                                                                          *)
(* Excluded by name: an operation reporting more than its per-call bound (a *)
(* pass spends at most its hold here), and clock skew between instances    *)
(* (one clock). Held elsewhere: a plane with no quota store resuming spent  *)
(* work (`a_plane_with_no_ledger_resumes_what_no_pass_billed`), and the     *)
(* sliding rate window (RateWindow.tla).                                    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Runs,       (* run ids                                                  *)
    Second,     (* the runs that belong to tenant 2; the rest are tenant 1's*)
    MaxConc,    (* the concurrency ceiling, per tenant                      *)
    Ceiling,    (* the spend ceiling, per tenant per period                 *)
    Worst,      (* one run's reservation: its worst case                    *)
    MaxPeriod,  (* periods are 1 .. MaxPeriod                               *)
    MaxPasses,  (* passes per run, so the model is finite                   *)
    MaxCrashes

Tenants == {1, 2}
Owner == [r \in Runs |-> IF r \in Second THEN 2 ELSE 1]
Periods == 1 .. MaxPeriod
Passes == 1 .. MaxPasses
States == {"new", "exec", "susp", "sealed", "refused"}

VARIABLES
    st,          (* st[r]: where the run is                                 *)
    slot,        (* slot[r]: it holds a concurrency slot row                *)
    viaResume,   (* viaResume[r]: it took that slot by resuming, ungated    *)
    alive,       (* alive[r]: the instance running it has not crashed       *)
    hold,        (* hold[r]: what is still reserved for it                  *)
    holdPeriod,  (* holdPeriod[r]: the period that reservation counts in    *)
    carried,     (* carried[r]: the hold was carried in, not admitted there *)
    passNo,      (* passNo[r]: its current pass                             *)
    pending,     (* pending[r]: the current pass's unsettled spend          *)
    startedIn,   (* startedIn[r][n]: the period pass n started in           *)
    wrote,       (* wrote[r][n]: pass n wrote a record                      *)
    marker,      (* marker[r][n]: pass n's QuotaPassStarted is journaled    *)
    receipt,     (* receipt[r][n]: pass n's settlement receipt exists       *)
    twice,       (* history: some pass was settled a second time            *)
    misfiled,    (* history: some pass settled into another period than its *)
                 (* own                                                     *)
    empty,       (* history: some pass that wrote nothing was settled       *)
    settledAdm,  (* settledAdm[t][p]: settled spend of holds admitted in p  *)
    settledCar,  (* settledCar[t][p]: settled spend of holds carried into p *)
    justified,   (* justified[r]: a refusal its own tenant's state explains *)
    period,
    crashes

vars == <<st, slot, viaResume, alive, hold, holdPeriod, carried, passNo,
          pending, startedIn, wrote, marker, receipt, twice, misfiled, empty, settledAdm, settledCar, justified, period, crashes>>

-----------------------------------------------------------------------------

RunsOf(t) == {r \in Runs : Owner[r] = t}

RECURSIVE Sum(_, _)
Sum(f, S) == IF S = {} THEN 0
             ELSE LET x == CHOOSE x \in S : TRUE IN f[x] + Sum(f, S \ {x})

Reserved(t, p) == Sum(hold, {r \in RunsOf(t) : holdPeriod[r] = p})
Settled(t, p) == settledAdm[t][p] + settledCar[t][p]

(* The slot count `reserve` takes under its transaction: every row, whether *)
(* its run is executing, crashed, or sealed and not yet given back.         *)
SlotRoom(t) == Cardinality({r \in RunsOf(t) : slot[r]}) < MaxConc

(* The same tenant's own count, kept apart so a refusal can be judged       *)
(* against it whatever SlotRoom is made to read.                            *)
OwnSlotRoom(t) == Cardinality({q \in RunsOf(t) : slot[q]}) < MaxConc

(* `check_spend`: settled plus every outstanding hold plus this one.        *)
SpendRoom(t) == Settled(t, period) + Reserved(t, period) + Worst <= Ceiling

(* A settlement happens only for a pass with a marker and no receipt yet.   *)
Settles(r) == marker[r][passNo[r]] /\ ~receipt[r][passNo[r]]

(* `QuotaSettlement::period`: the period the pass started in.               *)
SettlePeriod(r) == startedIn[r][passNo[r]]

(* Settle run r's current pass: spend leaves the hold, enters the period   *)
(* the pass started in, under a receipt. The caller sets `hold'`.          *)
Settle(r) ==
    LET n == passNo[r]
        t == Owner[r]
        p == SettlePeriod(r)
        amt == pending[r]
    IN /\ receipt' = IF Settles(r) THEN [receipt EXCEPT ![r][n] = TRUE] ELSE receipt
       /\ twice' = (twice \/ (Settles(r) /\ receipt[r][n]))
       /\ misfiled' = (misfiled \/ (Settles(r) /\ p # startedIn[r][n]))
       /\ empty' = (empty \/ (Settles(r) /\ ~wrote[r][n]))
       /\ settledAdm' = IF Settles(r) /\ ~carried[r]
                        THEN [settledAdm EXCEPT ![t][p] = @ + amt] ELSE settledAdm
       /\ settledCar' = IF Settles(r) /\ carried[r]
                        THEN [settledCar EXCEPT ![t][p] = @ + amt] ELSE settledCar
       /\ pending' = [pending EXCEPT ![r] = 0]

SettledHold(r) == IF Settles(r) THEN hold[r] - pending[r] ELSE hold[r]

TypeOK ==
    /\ st \in [Runs -> States]
    /\ slot \in [Runs -> BOOLEAN]
    /\ viaResume \in [Runs -> BOOLEAN]
    /\ alive \in [Runs -> BOOLEAN]
    /\ hold \in [Runs -> 0 .. Worst]
    /\ holdPeriod \in [Runs -> 0 .. MaxPeriod]
    /\ pending \in [Runs -> 0 .. Worst]
    /\ period \in Periods

Init ==
    /\ st = [r \in Runs |-> "new"]
    /\ slot = [r \in Runs |-> FALSE]
    /\ viaResume = [r \in Runs |-> FALSE]
    /\ alive = [r \in Runs |-> TRUE]
    /\ hold = [r \in Runs |-> 0]
    /\ holdPeriod = [r \in Runs |-> 0]
    /\ carried = [r \in Runs |-> FALSE]
    /\ passNo = [r \in Runs |-> 1]
    /\ pending = [r \in Runs |-> 0]
    /\ startedIn = [r \in Runs |-> [n \in Passes |-> 0]]
    /\ wrote = [r \in Runs |-> [n \in Passes |-> FALSE]]
    /\ marker = [r \in Runs |-> [n \in Passes |-> FALSE]]
    /\ receipt = [r \in Runs |-> [n \in Passes |-> FALSE]]
    /\ twice = FALSE
    /\ misfiled = FALSE
    /\ empty = FALSE
    /\ settledAdm = [t \in Tenants |-> [p \in Periods |-> 0]]
    /\ settledCar = [t \in Tenants |-> [p \in Periods |-> 0]]
    /\ justified = [r \in Runs |-> TRUE]
    /\ period = 1
    /\ crashes = 0

-----------------------------------------------------------------------------

(* `QuotaStore::reserve`: slot, spend check and hold in one transaction.    *)
Reserve(r) ==
    /\ st[r] = "new"
    /\ LET t == Owner[r] IN
       IF SlotRoom(t) /\ SpendRoom(t)
       THEN /\ st' = [st EXCEPT ![r] = "exec"]
            /\ slot' = [slot EXCEPT ![r] = TRUE]
            /\ hold' = [hold EXCEPT ![r] = Worst]
            /\ holdPeriod' = [holdPeriod EXCEPT ![r] = period]
            /\ startedIn' = [startedIn EXCEPT ![r][1] = period]
            /\ UNCHANGED <<viaResume, alive, carried, passNo, pending, wrote,
                           marker, receipt, twice, misfiled, empty,
                           settledAdm, settledCar, justified, period, crashes>>
       ELSE /\ st' = [st EXCEPT ![r] = "refused"]
            /\ justified' = [justified EXCEPT ![r] =
                                ~(OwnSlotRoom(t) /\ SpendRoom(t))]
            /\ UNCHANGED <<slot, viaResume, alive, hold, holdPeriod, carried,
                           passNo, pending, startedIn, wrote, marker, receipt,
                           twice, misfiled, empty, settledAdm, settledCar,
                           period, crashes>>

(* A pass spends, at most its hold, and journals a record; the first record *)
(* of a pass carries its QuotaPassStarted marker.                           *)
Spend(r) ==
    /\ st[r] = "exec" /\ alive[r]
    /\ pending[r] + 1 <= hold[r]
    /\ pending' = [pending EXCEPT ![r] = @ + 1]
    /\ wrote' = [wrote EXCEPT ![r][passNo[r]] = TRUE]
    /\ marker' = [marker EXCEPT ![r][passNo[r]] = TRUE]
    /\ UNCHANGED <<st, slot, viaResume, alive, hold, holdPeriod, carried,
                   passNo, startedIn, receipt, twice, misfiled, empty,
                   settledAdm, settledCar, justified, period, crashes>>

(* Suspending settles the pass and gives the slot back; the hold stays.     *)
Suspend(r) ==
    /\ st[r] = "exec" /\ alive[r]
    /\ Settle(r)
    /\ hold' = [hold EXCEPT ![r] = SettledHold(r)]
    /\ st' = [st EXCEPT ![r] = "susp"]
    /\ slot' = [slot EXCEPT ![r] = FALSE]
    /\ viaResume' = [viaResume EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<alive, holdPeriod, carried, passNo, startedIn, wrote,
                   marker, justified, period, crashes>>

(* The concluding pass settles and releases what is left of the hold in    *)
(* the transaction that writes the receipt; the slot is given back after.  *)
Conclude(r) ==
    /\ st[r] = "exec" /\ alive[r]
    /\ Settle(r)
    /\ hold' = [hold EXCEPT ![r] = 0]
    /\ st' = [st EXCEPT ![r] = "sealed"]
    /\ UNCHANGED <<slot, viaResume, alive, holdPeriod, carried, passNo,
                   startedIn, wrote, marker, justified, period, crashes>>

FinishRelease(r) ==
    /\ st[r] = "sealed" /\ slot[r] /\ alive[r]
    /\ slot' = [slot EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<st, viaResume, alive, hold, holdPeriod, carried, passNo,
                   pending, startedIn, wrote, marker, receipt, twice, misfiled,
                   empty, settledAdm, settledCar, justified, period,
                   crashes>>

(* A resume is never gated: no slot check, no spend check. A resume in a    *)
(* later period carries the remainder into it (`QuotaStore::carry`).        *)
Resume(r) ==
    /\ st[r] = "susp" /\ passNo[r] < MaxPasses
    /\ st' = [st EXCEPT ![r] = "exec"]
    /\ slot' = [slot EXCEPT ![r] = TRUE]
    /\ viaResume' = [viaResume EXCEPT ![r] = TRUE]
    /\ passNo' = [passNo EXCEPT ![r] = @ + 1]
    /\ startedIn' = [startedIn EXCEPT ![r][passNo[r] + 1] = period]
    /\ holdPeriod' = [holdPeriod EXCEPT ![r] = period]
    /\ carried' = [carried EXCEPT ![r] = @ \/ holdPeriod[r] # period]
    /\ UNCHANGED <<alive, hold, pending, wrote, marker, receipt, twice, misfiled,
                   empty, settledAdm, settledCar, justified, period,
                   crashes>>

(* The instance running r dies: its pass's spend is unsettled and its slot  *)
(* row stays.                                                               *)
Crash(r) ==
    /\ crashes < MaxCrashes
    /\ st[r] \in {"exec", "sealed"} /\ alive[r]
    /\ alive' = [alive EXCEPT ![r] = FALSE]
    /\ crashes' = crashes + 1
    /\ UNCHANGED <<st, slot, viaResume, hold, holdPeriod, carried, passNo,
                   pending, startedIn, wrote, marker, receipt, twice, misfiled,
                   empty, settledAdm, settledCar, justified, period>>

(* Takeover: `settle_recorded_quota_passes` settles the dead pass from its  *)
(* marker, and the run continues as a new pass in the current period.       *)
Recover(r) ==
    /\ st[r] = "exec" /\ ~alive[r] /\ passNo[r] < MaxPasses
    /\ Settle(r)
    /\ hold' = [hold EXCEPT ![r] = SettledHold(r)]
    /\ alive' = [alive EXCEPT ![r] = TRUE]
    /\ passNo' = [passNo EXCEPT ![r] = @ + 1]
    /\ startedIn' = [startedIn EXCEPT ![r][passNo[r] + 1] = period]
    /\ holdPeriod' = [holdPeriod EXCEPT ![r] = period]
    /\ carried' = [carried EXCEPT ![r] = @ \/ holdPeriod[r] # period]
    /\ UNCHANGED <<st, slot, viaResume, wrote, marker, justified, period,
                   crashes>>

(* `Runtime::release_sealed_slots`: a sealed run whose instance died before *)
(* giving its slot back has its recorded passes settled and the slot freed. *)
SweepRelease(r) ==
    /\ st[r] = "sealed"
    /\ slot[r] /\ ~alive[r]
    /\ Settle(r)
    /\ hold' = [hold EXCEPT ![r] = 0]
    /\ slot' = [slot EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<st, viaResume, alive, holdPeriod, carried, passNo,
                   startedIn, wrote, marker, justified, period, crashes>>

Tick ==
    /\ period < MaxPeriod
    /\ period' = period + 1
    /\ UNCHANGED <<st, slot, viaResume, alive, hold, holdPeriod, carried,
                   passNo, pending, startedIn, wrote, marker, receipt,
                   twice, misfiled, empty, settledAdm, settledCar,
                   justified, crashes>>

Next ==
    \/ \E r \in Runs :
        \/ Reserve(r) \/ Spend(r) \/ Suspend(r) \/ Conclude(r)
        \/ FinishRelease(r) \/ Resume(r) \/ Crash(r) \/ Recover(r)
        \/ SweepRelease(r)
    \/ Tick
    \/ UNCHANGED vars

Spec == Init /\ [][Next]_vars
             /\ \A r \in Runs : /\ WF_vars(Resume(r))
                                /\ WF_vars(FinishRelease(r))
                                /\ WF_vars(SweepRelease(r))

-----------------------------------------------------------------------------

(* New work a tenant admits never holds more than its ceiling of slots;     *)
(* everything above it is a run that resumed (`QuotaStore::reserve`).      *)
AdmissionsWithinCeiling ==
    \A t \in Tenants :
        Cardinality({r \in RunsOf(t) : slot[r] /\ ~viaResume[r]}) <= MaxConc

(* No pass is settled twice: the receipt is checked in the settlement      *)
(* (`QuotaStore::settle`, `settle_recorded_quota_passes`).                  *)
PassSettledOnce == ~twice

(* A pass's spend lands in the period it started in, even across a period  *)
(* boundary while it runs (`QuotaSettlement::period`).                      *)
SpendInAdmittedPeriod == ~misfiled

(* A refusal is explained by the refused tenant's own state, never by       *)
(* another tenant's (`QuotaStore::tenant`).                                 *)
TenantsIndependent ==
    \A r \in Runs : st[r] = "refused" => justified[r]

(* The bound the module documents: what a period's admitted work settles   *)
(* never passes its ceiling (`check_spend`).                                *)
PeriodSpendWithinCeiling ==
    \A t \in Tenants : \A p \in Periods : settledAdm[t][p] <= Ceiling

(* A running pass's hold counts in the period that pass started in: a       *)
(* resume carries the remainder with it (`QuotaStore::carry`).              *)
CarriedHoldFollowsTheResume ==
    \A r \in Runs :
        (st[r] = "exec" /\ alive[r]) => holdPeriod[r] = startedIn[r][passNo[r]]

(* A pass that wrote nothing is settled by nobody: the marker is written    *)
(* with a pass's first record (`QuotaPassStarted`).                         *)
NoMarkerNoSettlement == ~empty

Safety ==
    /\ TypeOK
    /\ AdmissionsWithinCeiling
    /\ PassSettledOnce
    /\ SpendInAdmittedPeriod
    /\ TenantsIndependent
    /\ PeriodSpendWithinCeiling
    /\ CarriedHoldFollowsTheResume
    /\ NoMarkerNoSettlement

(* Under WF(Resume): a suspended run with passes left resumes.              *)
SuspendedRunsResume ==
    \A r \in Runs : (st[r] = "susp" /\ passNo[r] < MaxPasses) ~> st[r] # "susp"

(* Under WF(FinishRelease) and WF(SweepRelease): a sealed run's slot is      *)
(* given back, by its own instance or, if that died, by the sweep. A        *)
(* deployment that schedules no sweep keeps the slot.                       *)
SealedSlotEventuallyReleased ==
    \A r \in Runs : (st[r] = "sealed" /\ slot[r]) ~> ~slot[r]

=============================================================================
