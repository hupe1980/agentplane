------------------------------ MODULE Delegation ------------------------------
(***************************************************************************)
(* Delegation chains, and the one property the runtime depends on.          *)
(*                                                                          *)
(* Credential formats are still moving — SPIFFE, WIMSE, AIP and the OAuth   *)
(* agent drafts are all Internet-Drafts. Binding a runtime to any of their   *)
(* wire formats means a rewrite when they settle. What every one of them     *)
(* provides, and what the design actually rests on, is attenuation:          *)
(*                                                                          *)
(*   A delegate can never hold more authority than its delegator.           *)
(*                                                                          *)
(* Modelled with authority as a SET of grants, so containment is subset and  *)
(* the property is checkable rather than merely stated. The implementation   *)
(* uses capability patterns, which is a compressed encoding of the same set  *)
(* — and the encoding is where the bug lives, so the code tests it directly  *)
(* (`admin.*` must not cover `administrator-override`). This model checks    *)
(* the protocol above that: what the chain does, not how a grant is spelled. *)
(*                                                                          *)
(* Two failure modes, and only one of them is obvious:                      *)
(*                                                                          *)
(*   * A delegate widening its scope is the escalation everyone expects.    *)
(*                                                                          *)
(*   * A chain REHYDRATED from storage that is trusted rather than           *)
(*     re-checked. Credentials expire, so replay cannot re-verify them —     *)
(*     and the tempting shortcut, trusting whatever the journal holds,       *)
(*     lets a tampered chain in through the audit path. The structural       *)
(*     property costs nothing to confirm and must be confirmed.              *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Grants,    (* The universe of authority. Sets of these are scopes.       *)
    MaxDepth   (* Hops permitted below the owner.                            *)

ASSUME Grants # {}
ASSUME MaxDepth \in Nat

VARIABLES
    chain,     (* Seq of scopes, owner first. chain[i] is a SUBSET Grants.   *)
    stored,    (* What storage holds. May be tampered with.                  *)
    rehydrated,(* Whether the stored chain was accepted back.                *)
    phase      (* "building" | "stored" | "loaded" | "rejected"              *)

vars == <<chain, stored, rehydrated, phase>>

TypeOK ==
    /\ phase \in {"building", "stored", "loaded", "rejected"}
    /\ rehydrated \in BOOLEAN
    /\ \A i \in 1 .. Len(chain) : chain[i] \subseteq Grants
    /\ \A i \in 1 .. Len(stored) : stored[i] \subseteq Grants

(* A chain starts at an owner holding everything. *)
Init ==
    /\ chain = << Grants >>
    /\ stored = << >>
    /\ rehydrated = FALSE
    /\ phase = "building"

-----------------------------------------------------------------------------

Depth(c) == Len(c) - 1

(* Every hop narrows, and the chain is no deeper than the cap. This is the   *)
(* predicate the constructor enforces AND the one rehydration re-checks —    *)
(* deliberately the same one, because two definitions of "valid chain" is    *)
(* how the storage path drifts from the construction path.                    *)
WellFormed(c) ==
    /\ Len(c) >= 1
    /\ Depth(c) <= MaxDepth
    /\ \A i \in 1 .. (Len(c) - 1) : c[i + 1] \subseteq c[i]

-----------------------------------------------------------------------------
(*                              BUILDING                                     *)
-----------------------------------------------------------------------------

(* Delegate to a narrower scope. Accepted.                                   *)
Delegate(s) ==
    /\ phase = "building"
    /\ Depth(chain) < MaxDepth
    /\ s \subseteq chain[Len(chain)]
    /\ chain' = Append(chain, s)
    /\ UNCHANGED <<stored, rehydrated, phase>>

(* Attempt to delegate to a WIDER scope. Refused: the chain does not change.  *)
(*                                                                           *)
(* Modelled explicitly rather than merely omitted, so the escalation attempt  *)
(* is reachable in the state graph and the invariant has something to be      *)
(* true about.                                                                *)
AttemptWiden(s) ==
    /\ phase = "building"
    /\ ~(s \subseteq chain[Len(chain)])
    /\ UNCHANGED vars

(* Attempt to delegate past the depth cap. Also refused.                     *)
AttemptTooDeep(s) ==
    /\ phase = "building"
    /\ Depth(chain) >= MaxDepth
    /\ UNCHANGED vars

-----------------------------------------------------------------------------
(*                      STORAGE, TAMPERING, REHYDRATION                      *)
-----------------------------------------------------------------------------

Store ==
    /\ phase = "building"
    /\ Len(chain) >= 1
    /\ stored' = chain
    /\ phase' = "stored"
    /\ UNCHANGED <<chain, rehydrated>>

(* Storage is modified into holding a chain that widens.                     *)
(*                                                                           *)
(* Not a hypothetical: the journal is hash-chained, but this models the case  *)
(* where that defence has failed or the chain arrives from elsewhere. The     *)
(* question is whether the load path notices on its own.                      *)
Tamper(i, s) ==
    /\ phase = "stored"
    /\ i \in 1 .. Len(stored)
    /\ stored' = [stored EXCEPT ![i] = s]
    /\ UNCHANGED <<chain, rehydrated, phase>>

(* Load the stored chain, re-checking the structural property.               *)
(*                                                                           *)
(* The guard IS the re-check. Removing it is the bug this model exists to     *)
(* rule out, and doing so must make `RehydratedChainsAreWellFormed` fail —     *)
(* otherwise the invariant is decoration.                                     *)
Rehydrate ==
    /\ phase = "stored"
    /\ WellFormed(stored)
    /\ rehydrated' = TRUE
    /\ phase' = "loaded"
    /\ UNCHANGED <<chain, stored>>

(* A chain that does not re-check is refused rather than loaded.             *)
RejectRehydrate ==
    /\ phase = "stored"
    /\ ~WellFormed(stored)
    /\ phase' = "rejected"
    /\ UNCHANGED <<chain, stored, rehydrated>>

Next ==
    \/ \E s \in SUBSET Grants : Delegate(s)
    \/ \E s \in SUBSET Grants : AttemptWiden(s)
    \/ \E s \in SUBSET Grants : AttemptTooDeep(s)
    \/ Store
    \/ \E i \in 1 .. 4, s \in SUBSET Grants : Tamper(i, s)
    \/ Rehydrate
    \/ RejectRehydrate
    \/ (phase \in {"loaded", "rejected"} /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(*                              INVARIANTS                                   *)
-----------------------------------------------------------------------------

(* THE invariant. Authority never widens along a chain.                      *)
ScopeNeverWidens ==
    \A i \in 1 .. (Len(chain) - 1) : chain[i + 1] \subseteq chain[i]

(* No link holds authority the owner never had.                              *)
(*                                                                           *)
(* Implied by ScopeNeverWidens transitively, and stated separately because it *)
(* is the property an auditor actually asks about: "could this agent have     *)
(* done something the person who authorized it could not?"                    *)
NoLinkExceedsTheOwner ==
    \A i \in 1 .. Len(chain) : chain[i] \subseteq chain[1]

(* A request never travels further from its human than the cap allows.       *)
DepthIsBounded ==
    Depth(chain) <= MaxDepth

(* Anything loaded back from storage satisfies the same predicate a freshly   *)
(* built chain does.                                                          *)
(*                                                                           *)
(* This is the one that catches "trust the journal": a tampered chain must be  *)
(* refused by the load path itself, not by whatever wrote it.                 *)
RehydratedChainsAreWellFormed ==
    rehydrated => WellFormed(stored)

Safety ==
    /\ TypeOK
    /\ ScopeNeverWidens
    /\ NoLinkExceedsTheOwner
    /\ DepthIsBounded
    /\ RehydratedChainsAreWellFormed

=============================================================================
