+++
title = "Regulation"
description = "EU AI Act obligation by obligation, mapped to mechanisms that exist — and an explicit list of the ones that do not."
weight = 11
+++

**agentplane is not compliant with anything, and cannot be.** Compliance attaches
to a *system in a context*, assessed by its provider or deployer. A library has
no context.

What it provides is **technical means**: the record-keeping and human-oversight
machinery that several obligations require, built because durable execution needs
them anyway. That last part is the reason to trust them — these mechanisms are
load-bearing for crash recovery and replay, so they are exercised on every run
rather than only when an auditor asks.

This page maps obligations to mechanisms **that exist**, and is equally explicit
about the ones that do not. A compliance page that lists only what a tool offers
is a sales document.

---

## 📅 Where the EU AI Act actually stands

The Digital Omnibus on AI was adopted by Parliament on **16 June 2026** and the
Council on **29 June 2026**, entering into force that July. It moved the
high-risk dates and left the transparency ones alone:

| | Applies from |
|---|---|
| **Art. 50** transparency — disclosing that users are dealing with an AI, marking synthetic content | **2 August 2026** (in force now; watermarking of already-marketed systems graced to 2 December 2026) |
| **Annex III** high-risk obligations (Art. 9–15, 26) — standalone systems | **2 December 2027** (deferred 16 months from 2 August 2026) |
| **Annex I** high-risk — AI embedded in regulated products | **2 August 2028** |

The articles were **deferred, not amended**. The mapping below is unchanged by
the Omnibus; only the calendar moved.

> **Art. 50 is not a runtime obligation.** Telling a user they are talking to an
> AI, and marking generated content, happen in your interface — not in a
> journal. Nothing here discharges it, and the date being live now is exactly
> when a tool claiming "AI Act ready" is worth least.

---

## ✅ What the runtime gives you

### Art. 12 — automatic recording, enabling traceability

The journal is the mechanism, and it is not an audit log bolted alongside the
system: it is what the system executes from. A record that was not written is a
step that did not happen.

| Requirement | Mechanism |
|---|---|
| Automatic, over the lifecycle | Every effect is journaled before it is attempted; nothing reaches the world unrecorded |
| Traceable | Per-record hash chain — any edit to any record invalidates every record after it |
| Attributable | Per-record signatures naming the workload identity that wrote them (`signing`) |
| Detecting removal | A per-plane Merkle log over sealed runs, with inclusion **and consistency** proofs — deleting a whole run is detectable, which a per-run chain alone cannot do |
| Checkable by someone else | An offline auditor (`audit`) that runs against a store it did not write, and reports what it *could not* check as prominently as what it did |
| *Which instructions* produced a decision | The system prompt lives inside the digested manifest (`manifest`), so a rewording is a version bump. A prompt composed in the deployer's code has no version at all: it changes in a deploy, the journal faithfully records every run it affected, and nothing connects the two |

**The limit, stated plainly:** a checkpoint that never leaves the operator's
store is exactly as trustworthy as the operator. The `Witness` seam enforces the
decision that matters — a checkpoint is cosigned only if it provably extends the
last one seen, so a shrunken log and a *split view* (a second history of the same
size) are both refused — and `HttpWitness` speaks C2SP `tlog-witness`, so the
counterparty can be an existing public witness rather than a second process you
also own. It verifies what comes back: a cosignature counts only if it is a
valid Ed25519 signature, over the note that was submitted, by a key the
deployment registered under both its name and its note key id.

What is missing is therefore **not code but a counterparty**. Until a second
party runs a witness for your log, a witness you host yourself proves nothing
about you. See [status](@/docs/status.md).

### Art. 14 — human oversight, and the ability to intervene and stop

| Requirement | Mechanism |
|---|---|
| A person can intervene | Durable worklists: a run suspends and waits, costing a row rather than a thread |
| The right person | Candidate roles, and `excluding` for four eyes — the proposer cannot approve their own action |
| Not answering is a decision | `OnExpiry` is declared up front — deny, escalate, or proceed — so an unanswered approval applies a stated policy instead of hanging. Escalation must name the roles it widens to, and the runtime widens them, so "a higher instance was involved" is a fact the worklist enforces rather than a label on a row |
| The ability to **stop** | Cooperative cancellation: the run unwinds what it did as a saga, and the record names who asked |
| Refusing to guess | A run that cannot account for an outcome is `Quarantined` rather than unwound — reversing everything except the one thing nobody can account for is how a system refunds money nobody took |
| Declared, not remembered | `spec.oversight` puts approval in the reviewable file (`manifest`), so a declarative agent's answer waits for a person by declaration rather than because a developer coded the call. Declaring it where nothing would apply it is refused, so the file cannot claim a human is in the loop when none is |

### Art. 15 — accuracy, robustness, cybersecurity

Not a feature but an evidence question, and the evidence is the assurance ladder:
TLA+ models of the core protocols, an exhaustive crash-schedule sweep over every
prefix of a real journal, store conformance batteries run against every backend,
and a mutation sweep that breaks each guarantee on purpose to prove its test
notices. [Operations](@/docs/operations.md) describes what each layer does and does not
cover.

### Art. 26 — deployers keep logs

The journal *is* the log, it verifies offline against a store it did not write,
and it comes out in a form nothing here has to be present to read:

```sh
agentplane export --store ./journal.redb > history.jsonl
agentplane audit  --store ./journal.redb > report.json
agentplane verify history.jsonl --checkpoint cp.note   # check a copy, offline
agentplane restore history.jsonl --store ./rebuilt.redb
```

`--checkpoint` is the deletion check, and without it there is none. The Merkle
root rebuilt from the file can otherwise only be compared with the file's *own
header* — which whoever dropped a run rewrites too — so the report lists
deletion under `not_checked` rather than calling the file sound. Pass the
checkpoint an earlier `audit` printed, or the `tlog-checkpoint` note a witness
cosigned: the point is that it comes from somewhere other than the file being
checked.

Both verbs take a store and nothing else — no manifest, no source tree, no Rust
toolchain — because that is what an auditor holds. The export is JSON Lines: a
header naming the log, its checkpoint and the canonicalization rule the digests
were computed under; one line per record carrying `prev_hash` and `hash`, so the
chain can be re-walked from the file alone; one line per **case**, carrying the
matter's status, version, correlation, obligations and blob digests — the case
layer is beside the journal, not derivable from it, and a regulator's question
is usually about a matter; and a trailer. The trailer's **absence** is how a
file cut short by a full disk or a killed pipe is told from a complete one, any
run that could not be read is named in it rather than quietly missing, and its
case count is what catches the case layer stripped whole. Case state travels
as stored — sealed stays sealed, because an export of plaintext would quietly
undo erasure.

`verify` takes the **file and nothing else** — no store, no manifest, no
toolchain — and re-seals every record through the same function the store sealed
with, so agreement is a statement about the bytes rather than about the file
agreeing with itself. It then rebuilds the Merkle log from the positions the
export carries and compares the root against the checkpoint in its own header.
That last step is what catches a whole run deleted from the middle: every
surviving chain is internally consistent, because a chain links records *within*
a run and knows nothing about its neighbours.

`restore` is the other direction, and it proves itself the same way: the rebuilt
store must report the checkpoint the export claimed. Signatures do not survive
unless the restoring store holds the original key, which the report says rather
than leaves to be found.

It exports what the chain committed to, which with a key ring configured is
ciphertext. That is deliberate: an export of plaintext would put a copy beyond
the reach of key destruction, and undo the erasure below.

**Erasure is possible without breaking the record — for data you kept out of
the chain.** `BlobStore::expire` drops a blob's bytes and leaves a tombstone;
the hash chain still verifies afterwards because it only ever committed to the
digest. So you can prove *what happened* and *that the record is unaltered*
without retaining those bytes, which is what makes Art. 26 and Art. 17
compatible rather than opposed.

A record is never *deleted* — the chain is append-only. But **erasability is a
wiring decision, not a size one**: the 1 MiB record ceiling is a refusal, not a
router, and sensitivity does not track volume. A name, an address and an IBAN
are a few hundred bytes. Three mechanisms decide it, and they compose:

| | What it does |
|---|---|
| **`.keyring(..)`** | Seals journal payloads under a per-case wrapping key. The chain commits to **ciphertext**, so destroying the key erases every copy — live store, replica, every backup — while the history still verifies with no key at all. `erase_case` then discharges an Art. 17 request against records |
| **`cx.store_blob`** | Puts bytes in a blob at **any** size and journals only the digest |
| **`security.max_sensitivity_journaled`** | Refuses at dispatch, before the announcement, when a value above the ceiling would be journaled |

So customer data in a prompt is permanent on an *unsealed* journal and erasable
on a sealed one. [Erasure and
keys](@/docs/erasure.md#what-lands-where-and-what-can-be-erased) partitions it
row by row.

**Erasure is answered by case**, which is the unit a request actually names.
`erase_case` tombstones every blob that case produced and leaves other cases
alone. Bytes are linked to their case when written, through `cx.store_blob`,
because a digest cannot be reversed afterwards to discover what matter it
belonged to.

**What is still missing:** a scheduled TTL — object-store lifecycle rules do
age-based expiry better than a sweeper could, at the cost of deleting rather
than tombstoning. And on an **unsealed** journal, personal data that reached a
record cannot be removed: wire a key ring, or keep it out through
`cx.store_blob` and `max_sensitivity_journaled`. Governed memory is the one
store `.keyring(..)` deliberately does not wrap — its erasure unit outlives the
case and its adapter is single-node by contract — so wrap it explicitly.

---

## ❌ What it does not give you

| Obligation | Why not |
|---|---|
| **Art. 9** risk management | There is a policy seam and a Cedar adapter, but no risk-tier model. Cedar's `symcc` could *prove* properties of a policy set rather than test them; nothing invokes it |
| **Art. 13** machine-readable description | A manifest declares an agent's prompt, grants, ceilings, models, result shape and oversight; the registry pins it by digest, can verify a domain-separated publisher attestation, and refuses publisher reassignment; the runtime **refuses** effects the declaration never named; and the A2A Agent Card is derived from that same manifest and served by the optional A2A server. What is still absent: the shipped registry is process-local rather than durable or remote, and trust in publisher keys remains a deployment decision |
| **Art. 50** transparency to users | An interface obligation, not a runtime one (above) |
| **A scheduled recovery rehearsal** | The pieces exist: `verify` proves an export from its own bytes, `restore` rebuilds a store and proves it by its own checkpoint, and `Runtime::drill` holds every case's blob digests and sealed-state keys against the live stores — re-hashing the bytes, proving sealed state opens, and telling intact from erased-by-design from lost. The drill also has a CLI verb — `agentplane drill` opens a store and fails only on loss, never on honest erasure — but nothing invokes any of the three on a schedule: the rehearsal itself is still yours to arrange |
| Anything about your **model** | Bias, accuracy, training data, and evaluation are properties of the model and its use. This is a runtime |
| A **conformity assessment** | A person does that, about a system, in a context |

---

## 🧭 Other frameworks

**ISO/IEC 42001** and the **NIST AI RMF** consume the same artifacts — the
journal answers "what happened and can you prove it" regardless of which
framework asks, so no framework-specific integration is needed or planned. The
export is the integration: JSON Lines goes into whatever collects evidence.

---

## 🙋 If you are evaluating this for a regulated deployment

Three questions worth asking of any tool in this space, including this one:

1. **Is the audit record the thing the system executes from, or a copy?** A copy
   can disagree with reality; this one cannot, because a step that was not
   recorded did not run.
2. **Can someone outside the operator check it?** Here: partly — the chain and
   signatures verify offline, but without external anchoring you are trusting the
   operator not to have removed a run wholesale.
3. **What does it refuse to tell you?** The auditor reports skipped checks beside
   findings, and [status](@/docs/status.md) lists what is not built. Anything that
   reports only findings is telling you about its coverage by omission.
