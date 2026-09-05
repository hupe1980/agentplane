+++
title = "The journal"
description = "An append-only, hash-chained journal with per-record signatures and a per-plane Merkle log — what it proves, and the claims it refuses to make."
weight = 8
+++

The journal is the product. Recovery, audit, cost accounting and regression
testing are all reads of one append-only structure, which is why they cannot
disagree with each other.

## The journal

Append-only, hash-chained, one row per record:

```
seq | kind              | effect_key | prev_hash | hash
────┼───────────────────┼────────────┼───────────┼──────
  1 | RunAdmitted       | –          | 0000…     | 9c2…
  2 | PlanFrozen        | –          | 9c2…      | 41b…
  3 | StepStarted       | –          | 41b…      | e07…
  4 | EffectStarted     | ek:3f9…    | e07…      | 55a…
  5 | EffectDone        | ek:3f9…    | 55a…      | d13…
  6 | Released          | –          | d13…      | 7f2…
  7 | StepFinished      | –          | 7f2…      | 8b6…
```

`hash = H(prev_hash ‖ record_bytes)`.

A run that reaches a conclusion appends a `RunConcluded` record, so how a run
ended is covered by tamper detection and a resumed run reads its own outcome
from the history it just verified. A side table alone could not answer *is this
run finished?* without inferring it from the last step that happened to finish.

The record keeps machine state machine-readable. An exhausted conclusion carries
the typed `BudgetExceeded` verdict as well as its human reason, so idempotent
redelivery returns `RunStatus::Exhausted` with the exact ceiling and counters;
no projection parses prose back into control flow.

A conclusion is not always a closure. Only conclusions nothing may resume —
`succeeded`, `quarantined`, `cancelled` — **seal**: the journal freezes (the
store refuses further appends as a constraint, not a convention) and the run
enters the Merkle log below. `failed` and `exhausted` leave the run open,
because both are conclusions a resume can honestly answer — completed effects
are read back from history rather than performed again — and a leaf published
for a run its own resume may grow would be a checkpoint attesting a prefix of
a moving history. One chain can therefore carry more than one `RunConcluded`
record, and the *last* one is the run's answer; the outcome index the
operator queries derives from it in the same transaction, so a failed run
that is resumed and succeeds moves between listings rather than being listed
as failed forever.

### What the chain proves, and what the signature adds

The chain is **per run**: `prev_hash` links to that run's own head, and genesis
is zero for every run. On its own it delivers exactly one thing:

> No record was edited, reordered, or removed **within** a run, by anyone who
> cannot recompute every subsequent hash.

That last clause is the problem. Anyone who can run SHA-256 can rebuild a
consistent chain, and the party holding the store can always run SHA-256 — which
is the party an auditor is being asked to trust.

So every record also carries an optional **`Attestation`**: a key id and a
signature over the record's chain hash. A hash says *what* the history is; a
signature says *who wrote it*.

* **One signature per record is enough.** The hash already chains, so signing
  record *n*'s hash transitively commits to every record before it. Rewriting any
  part of the prefix invalidates every *later* signature, not only its own.
* **It sits beside the hash, not in the body.** Forced, not stylistic: inside the
  body, the hash would cover the signature that covers the hash.
* **Verification is lenient by default, strict on demand.** A plane resuming its
  own history has no basis to reject an unsigned record — and a runtime that
  refused would make signing impossible to adopt incrementally. An auditor has
  every basis, and `require_signature` is the difference between "resume my
  history" and "prove this to me".
* **A plane with no signer writes unsigned records, not self-signed ones.** A
  self-minted key produces records that look attested and prove nothing, because
  the party being audited chose the key.
* **The attestation carries no algorithm field.** A self-described algorithm is
  how a verifier gets talked into checking a signature with something weaker than
  the one that made it. The verifier decides what it accepts.

The crate ships the seam (`Signer`, `Verifier`) and an Ed25519 implementation
behind the `signing` feature. A deployment with workload identity — SPIFFE SVIDs,
which is what the delegation model already assumes — plugs its own signer in, and
then the key id on each record names the *workload* rather than merely a key.

### Binding runs to each other

Signing binds authorship. It does not bind **existence** — and the per-run chain
stops at the run boundary, so deleting an entire run leaves every remaining run
verifying perfectly. The deleted run's signatures leave with it, so those do not
help either. What is left pointing at it is a case row: ordinary mutable data
that goes in the same delete.

So sealed runs enter a **per-plane Merkle log** (RFC 6962 shape), and the store
answers three questions:

* `checkpoint()` — origin, size, and root over every sealed run, in the C2SP
  `tlog-checkpoint` shape so existing verifiers work.
* `inclusion_proof(run)` — that one run's position and the sibling hashes that
  prove it.
* `consistency_proof(old_size)` — that the log has only *grown* since an earlier
  checkpoint.

Delete a run and the root moves; the deleted run can no longer prove inclusion.

"RFC 6962 shape" is two specific things, and both are checkable rather than
asserted. Leaf and interior hashes are domain-separated by a prefix byte —
without it an interior node's preimage can be presented as a leaf, and a tree
of *n* leaves reinterpreted as a different tree with the same root. A leaf hash
is therefore its own type: a caller who skips the hashing step does not build
an undifferentiated tree, they fail to compile. And the hashes themselves are
pinned to values computed by another implementation, because a checkpoint is
submitted to witnesses running somebody else's code — a tree that agrees only
with itself would pass every test here and be rejected by every witness in the
network.

**The third of those is what makes the other two mean anything.** The root moves
on every ordinary seal, so an auditor comparing two roots and seeing a difference
has learnt nothing — legitimate growth and deletion-plus-growth look identical. A
consistency proof shows every leaf committed to before is still committed to, in
the same position. Without it the log detects *a* change and cannot say what
kind.

Three details are decisions rather than implementation:

* **Leaf and interior hashes are domain-separated by a prefix byte.** Without
  it a leaf can be made to collide with an interior node, and an attacker who
  controls leaf content presents a subtree as a leaf.
* **The log position always advances; it is never a count of what survives.** A
  count reuses a deleted run's index, so a removed run can be silently replaced
  at the same position — and even the log size looks unchanged. redb keeps a
  monotonic counter, Postgres a sequence; both hand out a position that has
  never been issued before.
* **The proof does not authenticate its own parameters.** An inclusion proof is
  checked against `(leaf, index, size, root)`, all supplied by whoever offers it;
  the size and root come from a *signed checkpoint*. Expecting the fold to
  validate the size is asking the wrong component, and RFC 6962 has this shape
  for the same reason.

### The audit an outsider runs

Every mechanism above is only *checkable*. Somebody has to check it, and if the
only code that can is inside the runtime being audited, the party under
examination is also the party running the examination. So `audit::audit` runs
against a store it did not write, taking inputs the auditor holds:

| Given | Answers |
|---|---|
| nothing | Is each run's chain internally consistent? |
| a public key | Who wrote each record? |
| a **prior checkpoint** | Has anything been *removed* since it was issued? |

Only the third detects deletion, and only because the checkpoint came from
outside. The test that makes this concrete audits a store somebody deleted a run
from **twice**: with no prior checkpoint it comes back clean — honestly, because
there is nothing to compare against — and with one it fails.

That asymmetry is why `AuditReport` carries `not_checked` as prominently as
`findings`, and why `assert_complete` fails on a skipped check as well as a
failed one. `Checkpoint` also has a text form in the C2SP note encoding, because
the one artifact that must leave the operator's control cannot exist only as a
Rust struct.

#### The quorum, enforced

* **Witness policy.** `WitnessQuorum::of(n)` declares how many cosignatures
  suffice, and `cosign_quorum` holds each submission round to it. Three
  answers stay distinguishable: **met**; a **shortfall**, a finding to clear
  rather than a log line; and an **integrity refusal** — a witness that saw
  this log shrink or fork — reported *even when the quorum was met*. A run
  never waits on witnessing: it is retrospective evidence, gathered after
  sealing. The number itself is a deployment trust decision, and a checkpoint
  configured but never published is still only as trustworthy as the
  operator.
* **Split views** — one history to one auditor, a different one to another — are
  refused by a witness that remembers, because the second history cannot prove
  it extends the first. The client and wire protocol exist; independence still
  comes from choosing a witness run by somebody other than the operator.
  Hosting your own proves nothing about you.
* **Cosignatures are verified, not counted.** `HttpWitness::new` takes the
  `TrustedWitness` keys a deployment accepts and refuses to build without at
  least one. Each signature line on a `200` is matched to a trusted key by
  **name and four-byte note key id** — `signed-note`'s conjunction, because a
  name is whatever the answering server typed — then checked as a C2SP
  `cosignature/v1` statement: a big-endian timestamp leads the payload, and
  the signature covers the `cosignature/v1` header, the `time` line, then the
  note body that was submitted. The header is what separates a witness's
  observation from a log's own note signature — same algorithm, same key
  length, different claim. The construction is pinned to the spec's published
  example rather than to a round trip, since a signer and verifier written
  from one misreading round-trip cleanly. A quorum is otherwise a count of
  HTTP status codes, and every guarantee resting on *an independent party
  observed this log* would be a guarantee about string formatting.
Both backends maintain the log, and both keep their gaps. redb advances a
counter row inside the sealing transaction; Postgres uses a **sequence**, because
several instances seal concurrently there — that is the topology it exists for —
and a position derived from the current maximum by two transactions at once hands
both the same slot.

Positions therefore have holes once a run is removed, deliberately: a freed slot
must never be reissued. The *tree* is built by walking the log in key order,
which yields dense positions with no holes — so the position a proof uses is the
run's rank in that walk, not its stored index. Handing back the stored index
makes every run after a deleted one fail to prove an inclusion that is perfectly
valid.

### Hash the bytes you wrote

Records are hashed over their exact wire bytes, and those bytes are what the
store keeps. Verification never re-serializes.

This matters when schemas evolve. If the chain were computed over the *upcast*
form, then the first time a record shape changed, every historical hash would
change with it — silently destroying tamper evidence for all past records, which
is the one property the chain exists to provide. Upcasting is a read-time view;
the chain is over history as written.

### Schema evolution

The journal is forever, so record shapes must evolve without rewriting history.

1. Records carry `(kind, v)`.
2. **Backward compatibility is permanent.** New code must read every shape ever
   written. There is no "we migrated past that".
3. Upcast on read; never rewrite.
4. **Upcasters are pure and total.** Same input, same output, in this process
   and in one started a year from now.
5. Hash the wire bytes (above).

A golden corpus of historical fixtures belongs in CI: a schema change that
cannot read it should fail the build.
