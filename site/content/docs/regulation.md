+++
title = "Regulation"
description = "EU AI Act obligation by obligation, mapped to mechanisms that exist — and an explicit list of the ones that do not."
weight = 7
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

**The limit, stated plainly:** a checkpoint that never leaves the operator's
store is exactly as trustworthy as the operator. The `Witness` seam now exists
and enforces the decision that matters — a checkpoint is cosigned only if it
provably extends the last one seen, so a shrunken log and a *split view* (a
second history of the same size) are both refused. What does **not** yet exist
is a remote witness speaking C2SP `tlog-witness`. Until a second party runs one,
this is a mechanism without a counterparty: a witness you host yourself proves
nothing about you. See [status](@/docs/status.md).

### Art. 14 — human oversight, and the ability to intervene and stop

| Requirement | Mechanism |
|---|---|
| A person can intervene | Durable worklists: a run suspends and waits, costing a row rather than a thread |
| The right person | Candidate roles, and `excluding` for four eyes — the proposer cannot approve their own action |
| Not answering is a decision | `OnExpiry` is declared up front — deny, escalate, or proceed — so an unanswered approval applies a stated policy instead of hanging |
| The ability to **stop** | Cooperative cancellation: the run unwinds what it did as a saga, and the record names who asked |
| Refusing to guess | A run that cannot account for an outcome is `Quarantined` rather than unwound — reversing everything except the one thing nobody can account for is how a system refunds money nobody took |

### Art. 15 — accuracy, robustness, cybersecurity

Not a feature but an evidence question, and the evidence is the assurance ladder:
TLA+ models of the core protocols, an exhaustive crash-schedule sweep over every
prefix of a real journal, store conformance batteries run against every backend,
and a mutation sweep that breaks each guarantee on purpose to prove its test
notices. [Operations](@/docs/operations.md) describes what each layer does and does not
cover.

### Art. 26 — deployers keep logs

The journal *is* the log, it verifies offline, and it exports in a portable form.

**Erasure is possible without breaking the record.** `BlobStore::expire` drops a
blob's bytes and leaves a tombstone; the hash chain still verifies afterwards
because it only ever committed to the digest. So you can prove *what happened*
and *that the record is unaltered* without retaining the personal data — which
is what makes Art. 26 and Art. 17 compatible rather than opposed.

**What is still missing:** a scheduled TTL, and an erasure *unit*. You expire per
digest, so mapping a data-subject request onto the right set of digests is your
bookkeeping. And personal data that reached a journal **record** rather than a
blob cannot be removed at all — the chain is append-only by design. Keep it out
of records; the 1 MiB ceiling pushes bulk content out by construction, but a
short string still fits.

---

## ❌ What it does not give you

| Obligation | Why not |
|---|---|
| **Art. 9** risk management | There is a policy seam and a Cedar adapter, but no risk-tier model. Cedar's `symcc` could *prove* properties of a policy set rather than test them; nothing invokes it |
| **Art. 13** machine-readable description | The manifest and signed agent card are designed and not built; the runtime is wired by builder calls in your code |
| **Art. 50** transparency to users | An interface obligation, not a runtime one (above) |
| Anything about your **model** | Bias, accuracy, training data, and evaluation are properties of the model and its use. This is a runtime |
| A **conformity assessment** | A person does that, about a system, in a context |

---

## 🧭 Other frameworks

**ISO/IEC 42001** and the **NIST AI RMF** consume the same artifacts — the
journal answers "what happened and can you prove it" regardless of which
framework asks. No separate integration exists or is needed; the export is the
integration.

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
