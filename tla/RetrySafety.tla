----------------------------- MODULE RetrySafety -----------------------------
(***************************************************************************)
(* When repeating a failed effect is safe, and when it is not.              *)
(*                                                                          *)
(* `EffectProtocol` covers the outcome a *crash* leaves unknown. This covers *)
(* the same unknown reached from the other direction: the call itself        *)
(* failed, and the failure does not say whether it landed.                   *)
(*                                                                          *)
(* The two are the same situation. A process that dies between "sent" and    *)
(* "recorded" and a request that times out leave the runtime knowing exactly *)
(* as much — which is nothing — and both must be resolved by declaration     *)
(* rather than by guessing.                                                  *)
(*                                                                          *)
(* The distinction that makes retrying safe is NOT whether the error looked  *)
(* transient. A refused connection and a timed-out request are both          *)
(* transient; only one of them provably never reached the peer:              *)
(*                                                                          *)
(*   clean    the request was refused with nothing applied — repeat freely   *)
(*   indoubt  the outcome is unknown — repeat only if declared safe          *)
(*                                                                          *)
(* An in-doubt failure is modelled as genuinely undecidable: the world may   *)
(* or may not have changed, and nothing observable says which. TLC explores  *)
(* both branches, which is what gives the invariant something to catch.      *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    EffectCount,  (* How many effects the run performs, in order.            *)
    MaxAttempts,  (* Bound on repeats, so TLC terminates.                    *)
    Mutating,     (* Which effects change the outside world. The others are  *)
                  (* reads: repeating one is harmless by construction, which *)
                  (* is exactly what makes them safe to repeat.              *)
    Reconcilable  (* Which effects can be ASKED about. The provider knows    *)
                  (* what it did; a probe is how the runtime finds out       *)
                  (* without betting.                                        *)

ASSUME EffectCount \in Nat /\ EffectCount > 0
ASSUME MaxAttempts \in Nat /\ MaxAttempts > 0

Effects == 1 .. EffectCount
ASSUME Mutating \subseteq Effects
ASSUME Reconcilable \subseteq Effects

(* Safe to repeat by declaration. A read changes nothing however many times   *)
(* it runs; a mutation does not get that for free and must not be assumed to. *)
SafeToRepeat(e) == e \notin Mutating

NoEffect == 0

VARIABLES
    journal,   (* Seq of [key, att, kind, disp]                              *)
    world,     (* Seq of effects that ACTUALLY took effect outside. The thing *)
               (* being protected: real invoices, real payments.             *)
    pos,       (* Which effect the run is on.                                *)
    attempt,   (* Which attempt of it, 1-based.                              *)
    inflight,  (* Announced by this attempt and not yet concluded. In-memory. *)
    status

vars == <<journal, world, pos, attempt, inflight, status>>

Current == pos

Occurrences(s, e) == Cardinality({i \in 1 .. Len(s) : s[i] = e})

Announced(e, a) ==
    \E i \in 1 .. Len(journal) :
        /\ journal[i].key = e /\ journal[i].att = a
        /\ journal[i].kind = "started"

FailedWith(e, a, d) ==
    \E i \in 1 .. Len(journal) :
        /\ journal[i].key = e /\ journal[i].att = a
        /\ journal[i].kind = "failed" /\ journal[i].disp = d

(* A recorded probe verdict. *)
ReconciledAs(e, a, d) ==
    \E i \in 1 .. Len(journal) :
        /\ journal[i].key = e /\ journal[i].att = a
        /\ journal[i].kind = "reconciled" /\ journal[i].disp = d

Probed(e, a) ==
    \E d \in {"landed", "clean", "indoubt"} : ReconciledAs(e, a, d)

(* Whether this attempt's outcome is established, by whatever asked. A probe's *)
(* verdict and a person's assertion are the same record and the same fact; the *)
(* runtime does not treat one as better evidence than the other, because the   *)
(* thing that makes either usable is that it is written down.                  *)
Resolved(e, a) ==
    \/ ReconciledAs(e, a, "landed")
    \/ ReconciledAs(e, a, "clean")

(* Ground truth: did this effect actually take effect outside? The RUNTIME     *)
(* cannot read this — only the probe can, and only because the provider knows. *)
DidLand(e) == \E i \in 1 .. Len(world) : world[i] = e

(* What performing an effect does to the outside world. A read leaves no      *)
(* trace, so it cannot be duplicated; a mutation leaves one every time.       *)
Reach(w, e) == IF e \in Mutating THEN Append(w, e) ELSE w

Entry(e, a, k, d) == [key |-> e, att |-> a, kind |-> k, disp |-> d]

TypeOK ==
    /\ status \in {"running", "succeeded", "failed", "quarantined"}
    /\ pos \in 1 .. (EffectCount + 1)
    /\ attempt \in 1 .. MaxAttempts
    /\ inflight \in Effects \cup {NoEffect}
    /\ \A i \in 1 .. Len(world) : world[i] \in Effects

Init ==
    /\ journal  = << >>
    /\ world    = << >>
    /\ pos      = 1
    /\ attempt  = 1
    /\ inflight = NoEffect
    /\ status   = "running"

-----------------------------------------------------------------------------

(* Durable announcement precedes the call, per attempt. *)
Announce ==
    /\ status = "running"
    /\ pos <= EffectCount
    /\ inflight = NoEffect
    /\ ~Announced(Current, attempt)
    /\ journal' = Append(journal, Entry(Current, attempt, "started", "none"))
    /\ inflight' = Current
    /\ UNCHANGED <<world, pos, attempt, status>>

Succeed ==
    /\ status = "running"
    /\ inflight = Current
    /\ world' = Reach(world, Current)
    /\ journal' = Append(journal, Entry(Current, attempt, "done", "none"))
    /\ inflight' = NoEffect
    /\ pos' = pos + 1
    /\ attempt' = 1
    /\ UNCHANGED status

(* A failure that provably never reached the peer. `world` is untouched — that *)
(* is not an assumption about this run, it is the definition of the case.       *)
FailClean ==
    /\ status = "running"
    /\ inflight = Current
    /\ journal' = Append(journal, Entry(Current, attempt, "failed", "clean"))
    /\ inflight' = NoEffect
    /\ UNCHANGED <<world, pos, attempt, status>>

(* A failure whose outcome is unknown.                                        *)
(*                                                                            *)
(* The disjunction is the whole point: the effect may or may not have landed,  *)
(* and NOTHING in the journal distinguishes the two. Collapsing this to one    *)
(* branch would model a runtime that can tell — and would make the invariant   *)
(* below true by assumption rather than by design.                            *)
FailInDoubt ==
    /\ status = "running"
    /\ inflight = Current
    /\ \/ world' = Reach(world, Current)   (* it landed *)
       \/ world' = world                   (* it did not *)
    /\ journal' = Append(journal, Entry(Current, attempt, "failed", "indoubt"))
    /\ inflight' = NoEffect
    /\ UNCHANGED <<pos, attempt, status>>

(* Repeating after a clean failure. Always permitted: nothing happened, so    *)
(* there is nothing to happen twice.                                          *)
RetryClean ==
    /\ status = "running"
    /\ inflight = NoEffect
    /\ FailedWith(Current, attempt, "clean")
    /\ attempt < MaxAttempts
    /\ attempt' = attempt + 1
    /\ UNCHANGED <<journal, world, pos, inflight, status>>

(* Repeating after an in-doubt failure.                                       *)
(*                                                                            *)
(* THE rule this specification exists for. The guard is a declaration, not an  *)
(* observation, because there is nothing to observe. Removing it must break    *)
(* `ExactlyOnce` — otherwise the invariant is decoration.                      *)
RetryInDoubt ==
    /\ status = "running"
    /\ inflight = NoEffect
    /\ FailedWith(Current, attempt, "indoubt")
    /\ SafeToRepeat(Current)
    /\ attempt < MaxAttempts
    /\ attempt' = attempt + 1
    /\ UNCHANGED <<journal, world, pos, inflight, status>>

(* Asking the provider what happened.                                         *)
(*                                                                            *)
(* This is the only rule that reads ground truth, and it is legitimate for the *)
(* same reason it is legitimate in production: the provider knows what it did. *)
(* The probe may also come back unable to tell, which is an honest answer and  *)
(* leaves the doubt exactly where it was.                                      *)
(*                                                                            *)
(* A probe that reported "clean" for something that DID land would be a probe  *)
(* matching on the wrong thing — a timestamp, or "most recent" — and the       *)
(* mutation testing that possibility is what proves this rule is load-bearing. *)
Probe ==
    /\ status = "running"
    /\ inflight = NoEffect
    /\ FailedWith(Current, attempt, "indoubt")
    /\ Current \in Reconcilable
    /\ ~Probed(Current, attempt)
    /\ \/ /\ DidLand(Current)
          /\ journal' = Append(journal, Entry(Current, attempt, "reconciled", "landed"))
       \/ /\ ~DidLand(Current)
          /\ journal' = Append(journal, Entry(Current, attempt, "reconciled", "clean"))
       \/ journal' = Append(journal, Entry(Current, attempt, "reconciled", "indoubt"))
    /\ UNCHANGED <<world, pos, attempt, inflight, status>>

(* The probe found it landed. The effect is complete — and `world` is          *)
(* deliberately UNCHANGED, because nothing was performed. The result was       *)
(* recovered, not produced.                                                     *)
CompleteFromProbe ==
    /\ status = "running"
    /\ inflight = NoEffect
    /\ ReconciledAs(Current, attempt, "landed")
    /\ journal' = Append(journal, Entry(Current, attempt, "done", "none"))
    /\ pos' = pos + 1
    /\ attempt' = 1
    /\ UNCHANGED <<world, inflight, status>>

(* The probe established that nothing landed, so repeating is safe — even for  *)
(* a mutation, and even though the failure was in doubt a moment ago. The       *)
(* difference between this and guessing is the recorded verdict.                *)
RetryAfterProbe ==
    /\ status = "running"
    /\ inflight = NoEffect
    /\ ReconciledAs(Current, attempt, "clean")
    /\ attempt < MaxAttempts
    /\ attempt' = attempt + 1
    /\ UNCHANGED <<journal, world, pos, inflight, status>>

(* Refusing to guess is a correct outcome, not a hang.                        *)
(*                                                                            *)
(* Reachable only when there is nothing to ask, or when asking did not help.   *)
(* Quarantining a reconcilable effect without probing it first would escalate  *)
(* to a human a question the provider would have answered.                     *)
Quarantine ==
    /\ status = "running"
    /\ inflight = NoEffect
    /\ FailedWith(Current, attempt, "indoubt")
    /\ ~Resolved(Current, attempt)
    /\ ~SafeToRepeat(Current)
    /\ \/ Current \notin Reconcilable
       \/ ReconciledAs(Current, attempt, "indoubt")
    /\ status' = "quarantined"
    /\ UNCHANGED <<journal, world, pos, attempt, inflight>>

(* A person answers what the runtime could not, and the run is judged again.  *)
(*                                                                            *)
(* Escalation is where every durable system stops, and stopping there makes   *)
(* the escalation a backlog nothing drains. What a person adds is a *fact*    *)
(* about one attempt — they looked the call up in the system that would know  *)
(* — and it is written as the same reconciliation record a probe writes,      *)
(* because it answers the same question. Nothing here sets `status` to        *)
(* "succeeded": the person supplies evidence and the run is re-derived from   *)
(* it, which is why this returns to "running" rather than to an ending.       *)
(*                                                                            *)
(* Modelled as **truthful**: the assertion agrees with `world`, because the   *)
(* claim under test is that a correct answer cannot cause a double-apply, not *)
(* that a wrong one is harmless. A person who misreads a console is the       *)
(* residue this design states rather than removes, and a model of a lying     *)
(* operator would have nothing left to prove.                                 *)
(*                                                                            *)
(* Quarantine is therefore not terminal, and `Terminal` still names it: an    *)
(* answer may never come, and a spec that forced one would model an operator  *)
(* who is always available.                                                   *)
Answer ==
    /\ status = "quarantined"
    /\ inflight = NoEffect
    /\ ~Resolved(Current, attempt)
    /\ \/ /\ DidLand(Current)
          /\ journal' = Append(journal, Entry(Current, attempt, "reconciled", "landed"))
       \/ /\ ~DidLand(Current)
          /\ journal' = Append(journal, Entry(Current, attempt, "reconciled", "clean"))
    /\ status' = "running"
    /\ UNCHANGED <<world, pos, attempt, inflight>>

(* Out of attempts after a probe established nothing landed. *)
GiveUpAfterProbe ==
    /\ status = "running"
    /\ inflight = NoEffect
    /\ ReconciledAs(Current, attempt, "clean")
    /\ attempt = MaxAttempts
    /\ status' = "failed"
    /\ UNCHANGED <<journal, world, pos, attempt, inflight>>

(* Out of attempts. An ordinary failure: the run stops.                       *)
(*                                                                            *)
(* The in-doubt disjunct is guarded by `SafeToRepeat`, and that is not an      *)
(* oversight to tidy away. Exhausting attempts on something safe to repeat     *)
(* leaves nothing unresolved — a read changes nothing however it ended. The    *)
(* unsafe case is `Quarantine`'s, and it must stay there.                      *)
(*                                                                            *)
(* Without this disjunct the model deadlocks, which is how it was found: TLC   *)
(* reported a safe-to-repeat effect failing in doubt on its final attempt with *)
(* no rule to apply.                                                           *)
GiveUp ==
    /\ status = "running"
    /\ inflight = NoEffect
    /\ \/ FailedWith(Current, attempt, "clean")
       \/ (FailedWith(Current, attempt, "indoubt") /\ SafeToRepeat(Current))
    /\ attempt = MaxAttempts
    /\ status' = "failed"
    /\ UNCHANGED <<journal, world, pos, attempt, inflight>>

Finish ==
    /\ status = "running"
    /\ pos = EffectCount + 1
    /\ status' = "succeeded"
    /\ UNCHANGED <<journal, world, pos, attempt, inflight>>

Terminal == status \in {"succeeded", "failed", "quarantined"}

Next ==
    \/ Announce
    \/ Succeed
    \/ FailClean
    \/ FailInDoubt
    \/ RetryClean
    \/ RetryInDoubt
    \/ Probe
    \/ CompleteFromProbe
    \/ RetryAfterProbe
    \/ Quarantine
    \/ Answer
    \/ GiveUp
    \/ GiveUpAfterProbe
    \/ Finish
    \/ (Terminal /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(*                              INVARIANTS                                   *)
-----------------------------------------------------------------------------

(* THE invariant. No effect changes the outside world twice, whatever the     *)
(* failure schedule. A read may repeat freely — it never enters `world` at     *)
(* all, which is precisely what "safe to repeat" means.                        *)
ExactlyOnce ==
    \A e \in Effects : Occurrences(world, e) <= 1

(* Nothing happens that was not durably announced first.                      *)
(*                                                                            *)
(* Quantified over attempts, not pinned to the first: a third attempt that     *)
(* lands is announced by its own record, and checking only attempt 1 would let *)
(* an unannounced retry through.                                               *)
DurableIntentPrecedesAction ==
    \A i \in 1 .. Len(world) :
        \E a \in 1 .. MaxAttempts : Announced(world[i], a)

(* Success is structural. Reaching it means every effect was accounted for,    *)
(* not that the workload said so.                                              *)
SuccessMeansComplete ==
    (status = "succeeded") => (pos = EffectCount + 1)

(* An effect that mutates and is left in doubt never reports success.          *)
(*                                                                             *)
(* The operator-facing property: a run that timed out on a payment must not    *)
(* end green. Quarantine is the only honest outcome, and this says so.         *)
(* "Unresolved" is doing the work. An in-doubt failure that a probe later       *)
(* settled — either way — is no longer in doubt, and a run may legitimately      *)
(* succeed past it. That distinction did not exist before reconciliation, and    *)
(* this invariant was correspondingly blunter: it forbade success after ANY      *)
(* in-doubt failure on a mutation, which was right only because nothing could    *)
(* resolve one. TLC caught the difference the moment `Probe` was added.          *)
NoSuccessOnUnresolvedDoubt ==
    (status = "succeeded") =>
        ~\E e \in Mutating, a \in 1 .. MaxAttempts :
            /\ FailedWith(e, a, "indoubt")
            /\ ~ReconciledAs(e, a, "landed")
            /\ ~ReconciledAs(e, a, "clean")

(* An effect that could have been asked about is never escalated without       *)
(* asking.                                                                     *)
(*                                                                             *)
(* The operator-facing complement of `NoSuccessOnUnresolvedDoubt`: one says a   *)
(* run must not claim success it cannot support, this says it must not spend a  *)
(* human's attention on a question the provider would have answered.           *)
NoQuarantineWithoutAsking ==
    (status = "quarantined") =>
        \A e \in Reconcilable :
            \A a \in 1 .. MaxAttempts :
                (FailedWith(e, a, "indoubt") /\ e = Current /\ a = attempt)
                    => Probed(e, a)

Safety ==
    /\ TypeOK
    /\ ExactlyOnce
    /\ DurableIntentPrecedesAction
    /\ SuccessMeansComplete
    /\ NoSuccessOnUnresolvedDoubt
    /\ NoQuarantineWithoutAsking

-----------------------------------------------------------------------------
(*                          TEMPORAL PROPERTIES                              *)
-----------------------------------------------------------------------------

(* Prefix equality, not merely length: a journal that swapped one record for  *)
(* another at the same length would still be a rewritten history, and a       *)
(* length check would wave it through.                                        *)
IsPrefixOf(p, s) ==
    /\ Len(p) <= Len(s)
    /\ \A k \in 1 .. Len(p) : s[k] = p[k]

JournalIsAppendOnly == [][IsPrefixOf(journal, journal')]_vars

(* The run always reaches a decision. `quarantined` counts: refusing to guess  *)
(* is an answer, and the one an auditor can act on.                            *)
Terminates == <>Terminal

=============================================================================
