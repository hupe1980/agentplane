+++
title = "Status"
description = "What is built, what is deliberately deferred, and how to check this page is telling the truth."
weight = 8
+++

`agentplane` is pre-alpha. This page is the honest inventory: every row is a
capability that exists in the code, with the tests that hold it. What is *not*
here is not built, and the design document is explicit about which of those are
designed-and-deferred rather than unconsidered.

The rule this page follows: **a row appears only when something would fail if the
capability were removed.** A feature with no test that can falsify it is not a
feature, it is an intention — the mechanisms that make that checkable are in
[operations](@/docs/operations.md).

## ✅ Built

| | |
|---|---|
| | |
| ✅ | Append-only, hash-chained journal — no record can be edited, reordered, or removed *within* a run |
| ✅ | **Record attestation** — every record optionally signed under a named identity, so the journal says *who wrote it*, not only what it says |
| ✅ | **Cross-run binding** — sealed runs enter a per-plane Merkle log with inclusion *and* consistency proofs, so an auditor can tell ordinary growth from a deletion; the per-run chain structurally cannot see either |
| ✅ | **Offline audit** — `audit::audit` runs against a store it did not write, and reports what it *could not* check as loudly as what failed |
| ✅ | Effect protocol — announce durably, act, record; at most once per run |
| ✅ | Replay (`Strict` verification) and resume (`Resume` crash recovery) |
| ✅ | Divergence detection — a changed build is quarantined, never allowed to silently rewrite history |
| ✅ | Exactly-once as a *database constraint*, not a code path |
| ✅ | Run-ownership leases with epoch fencing (split-brain safety) |
| ✅ | Information-flow labels — trust/sensitivity lattice, egress ceilings, taint gates; **effect output is labelled at the source, untrusted by default** |
| ✅ | Journaled clock; reproducible per-step RNG |
| ✅ | Record schema versioning with pure upcasters |
| ✅ | **Cases** — correlation by business key, state across runs, closure rules |
| ✅ | **Deadlines** — pluggable `Calendar`, journaled instants, due sweep |
| ✅ | **Durable waits** — suspend on a correlated event; a waiting run is a row, not a thread |
| ✅ | **Durable timers** — `cx.sleep()` suspends the run; a sweep wakes it, and the instant is journaled |
| ✅ | **Event delivery** — arrival-order-independent, deduplicated, dead-lettered by sweep |
| ✅ | **Human tasks** — worklist, four-eyes enforcement, declared expiry policy |
| ✅ | **Sweeper** — deadline warnings, breach escalation, task expiry, dead letters |
| ✅ | **Plan DAG** — contract validation, **concurrent** ready-set scheduling, provenance binding |
| ✅ | **Topology** — collaboration must justify itself; false parallelism is rejected |
| ✅ | **Replanning** — versioned successors with lineage; refused once untrusted data is in play |
| ✅ | **Budgets** — step/effect/token/cost/wall-clock limits, enforced deterministically |
| ✅ | **Retries** — gated on whether the call reached the peer, not on how the error looked |
| ✅ | **Reconciliation** — resolve an unknown outcome by asking the provider, not by assuming |
| ✅ | **Sagas** — reverse-order compensation, pivots, suspendable unwinds, and a refusal to unwind around doubt |
| ✅ | **Tracing** — run/step/effect spans, a dedicated event per loud failure, replay marked distinctly |
| ✅ | **Batches** — one frozen plan over N items, per-item journals, item-granular resume, partial failure as a terminal state |
| ✅ | **Delegation** — attenuating chains from a human owner down to the acting workload; widening is unrepresentable |
| ✅ | **Tool calls** — an operator-declared catalogue; a server's `readOnlyHint` can never make its own tool safe to repeat |
| ✅ | **Model calls** — usage journaled, and a completion that dies partway is billed for what it generated |
| ✅ | **Peer calls** — audience-bound credentials obtained by token exchange, refreshed before expiry, and never written to the journal |
| ✅ | **MCP** — real round trips over `rmcp`, behind the `mcp` feature; every transport failure states whether the call reached the server |
| ✅ | **Cedar** — the policy seam's first adapter, behind the `cedar` feature; a policy that *fails to evaluate* is reported as broken, not as a refusal |
| ✅ | **Authorization** — a total, fail-closed policy seam; denials journaled, and replay never re-opens the gate |
| ✅ | **OpenTelemetry GenAI conventions** — the run span carries `gen_ai.operation.name = invoke_agent`; tool calls carry `execute_tool` and model calls `chat`, declared by the effect itself rather than sniffed from its name. Effects that are *not* GenAI operations carry no such attribute, which is what keeps it meaningful. The conventions are pre-1.0, so the version targeted is pinned rather than tracked |
| ✅ | **Metrics** — a declared catalogue of counters and observed gauges, guarded against declared-but-unemitted |
| ✅ | **redb** — the default embedded backend: pure Rust, two crates deep, ACID transactions across tables, stable on-disk format |
| ✅ | **PostgreSQL** — journal *and* case layer, for the shared-store topology |
| ✅ | **Store conformance batteries** — one contract per store, run against every backend, including a racing check no sequential test can replace |
| ✅ | **HTTP surface** — worklist, claim/release, decisions, run status, event delivery, behind the `http` feature; the wire types cannot express who is acting |
| ✅ | **Cancellation** — an operator stops a run; it unwinds what it did, refuses to unwind around an unknown outcome, and the record names who asked |
| ✅ | **A2A** — peer calls over the wire behind the `a2a` feature; a peer's internal error is *in doubt*, a failed task has *landed* |
| ✅ | **Content-addressed blobs** — the claim check, with the reference being the digest, so the chain commits to bytes it does not hold; a blob altered on disk is refused, not served. In memory, or on anything OpenDAL reaches behind the `opendal` feature |
| ✅ | **A journal record size ceiling** — 1 MiB, refused rather than truncated, checked at the one point every backend seals through |
| ✅ | **System instructions** — written once as `system` on the prompt, spelled the way each API wants it: a top-level `system` on Anthropic, `instructions` on OpenAI Responses. In the effect key like the rest of the prompt, so editing the instruction shows up on replay as divergence |
| ✅ | **Multimodal content** — image and document blocks pass through verbatim, so a provider's own shapes work without this crate modelling any of them. The prompt is stored in the journal, so inlined media is kept forever; a media *URL* is fetched by the provider and does not pass the egress allowlist |
| ✅ | **Model drivers** — Anthropic Messages and OpenAI Responses behind the `providers` feature; reasoning tokens are billed, a cut-off answer says so, and a completion that generated and then declined is billed for what it generated |
| ✅ | **Structured output** — a JSON Schema enforced by the provider *during* generation and carried in the effect key; with forced-tool emulation for the many models that have no native support, and a refusal that names the rule when a schema is one strict mode cannot take |
| ✅ | **Quorum on high-risk nodes** — several judgements from *distinct declared lenses*, because identical judges share their blind spots; a split panel has no `majority()` to fall back on, so disagreement escalates rather than resolving itself |
| ✅ | **Network egress allowlists** — a model driver or peer client refuses a host nobody granted, before the request is built; no wildcards, and the allowlist never parses a URL itself so it cannot disagree with the client about what the host is |
| ✅ | **Attested provenance** — a tool call carries which run, case, effect and agent, signed by the plane's workload identity and **bound to the call itself**, so a callee can check the claim rather than believe whatever the last hop wrote; a signature over the identifiers alone would verify on any other request |
| ✅ | **Case state is a journaled effect** — mutable storage shared across runs is as non-deterministic as a clock, so a replay reads back what the live run saw instead of whatever the case holds now, and does not write on the way through |
| ✅ | **Concurrent case writers** — a state write names the version it read and the store refuses it if the case moved, because the window between reading and writing contains a model call and two runs on one case overlap as a matter of course |
| ✅ | **Refusals do not teach** — a model is told one uniform sentence whatever the policy actually objected to, while the journal keeps the full reason for an auditor; a denial ceiling bounds the one bit uniformity cannot remove |
| ✅ | **Streaming** — on by default for both drivers, because a severed call can then report *what it burned* rather than being billed as zero and retried for free; the SSE parser is hand-rolled precisely so it never reconnects, since a silently resumed stream is a second bill for one journaled effect |
| ✅ | **The provider asymmetry, named rather than smoothed over** — Anthropic reports usage incrementally so a cut stream bills real tokens; OpenAI reports it only at the end, so a cut stream knows it generated and not what it cost, and says exactly that |
| ✅ | **Cached-token accounting** — normalised across providers that report cache hits *inside* the input count and providers that report them *beside* it |
| ✅ | **Zeroized secrets** — API keys and bearer tokens are wiped when they drop and compared in constant time, not held in a `String` |
| ✅ | **A fake provider** — `testkit::FakeProvider`, so tests and examples can exercise the model path with no key and no network; deterministic by construction, never reports a call as free, and refuses to answer as a real provider so a fake-produced journal cannot read as a genuine one |

## 🚧 Designed, not built

These have a shape in the design document and no implementation. They are listed
so that an evaluator can tell "deliberately deferred" from "never thought about",
which is the distinction a status page exists to make.

| | |
|---|---|
| ⬜ | **Witness cosigning** — publishing checkpoints to a witness that can attest they saw the log grow. Until then a checkpoint that never leaves the operator's store is only as trustworthy as the operator, and a *split view* — a different history shown to each auditor — is undetectable |
| ⬜ | **Manifest loading, signing, registry** — the runtime is wired by builder calls in the embedder's code; the manifest that would replace them, and the digest-pinning that makes a prompt change a versioned artifact, are not implemented |
| ⬜ | **Wasm skill tier** — the capability-absence sandbox where determinism is enforced rather than requested. The native tier is trusted by definition, which is recorded as a residual risk rather than a control |
| ⬜ | **Memory and compaction** — no memory store, retrieval seam, or `cx.compact` effect. The shape is fixed by the effect protocol, which is why it is written down rather than improvised later |
| ⬜ | **Symbolic policy analysis** — Cedar's `symcc` can *prove* properties of a policy set rather than test them; nothing invokes it yet |
| ⬜ | **Retention and erasure** — no TTL, no expiry tombstone, no erasure unit. The journal keeps everything for ever, which is what Art. 12 wants and what an erasure request does not. The blob store is the half that exists: the chain commits only to a digest, so bytes can be removed without breaking it — the policy on top is missing |
| ⬜ | **Argument-level provenance** — a tool call's arguments carry one joined label, so a single untrusted field makes the whole call untrusted. That fails closed, so it is not a hole; the cost is pressure to declassify broadly, which turns a precise mechanism into a rubber stamp. Per-argument labelling is the known remedy |
| ⬜ | **A2A server** — the client is built, including the failure mapping that decides whether a peer acted. Serving a signed Agent Card derived from the manifest is not |

## 🔍 How to check this page is honest

```sh
just anchors    # every mutation still anchors in the code it names
just ci         # lint, three feature configurations, examples, docs, packaging
just ci-full    # the above, plus TLA+ specs and the full mutation sweep
```

The mutation sweep is the one that matters for this page: it breaks each
guarantee on purpose and requires the test *written for it* to fail. A row here
whose guarantee could be deleted without a test noticing would be caught by that
sweep, not by review.

