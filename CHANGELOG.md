# Changelog

Notable changes per release, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

**Pre-alpha, and versioned accordingly.** The crate is not published; `0.x` bumps
carry breaking changes without deprecation cycles, because a hard cut is cheaper
than a compatibility shim nobody has yet depended on. Every breaking entry says
what to do about it, and [upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/)
carries the ones that need more than a sentence.

What this file does **not** do is duplicate the built-vs-designed inventory. That
is [status](https://hupe1980.github.io/agentplane/docs/status/), which answers
*what is true now and what evidence holds it*; this answers *what changed and
when*. Two documents, two questions.

Entries for `0.1.0`–`0.9.0` are reconstructed from tags and commit history rather
than written at the time, so they are deliberately terse — the detail for those
releases lives in the status page and in `git log`, and inventing more would be
archaeology presented as a record.

## [0.10.0] — 2026-08-08

### Changed — breaking

- **Every admission door takes `Tainted<Value>`.** `Runtime::run` took a bare
  `serde_json::Value` and admitted it as `Trusted`, which is right for an
  operator's literal and silently wrong for a plane started by inbound events —
  `require_trusted` protected fields were satisfied by counterparty-chosen
  values, the egress ceiling had nothing untrusted to join with, and the journal
  recorded no contact with outside data, with nothing failing.

  Eleven doors became eight, and two names changed meaning:

  | before | after |
  |---|---|
  | `run(target, Value)` | `run(target, Tainted<Value>)` |
  | `run_tainted(..)` | removed — `run` is the labelled door |
  | `run_in_case(target, .., kind, keys)` (correlated) | `run_correlated(..)` |
  | `run_tainted_in_case(target, .., CaseId)` | `run_in_case(..)` — *this exact case* |
  | `run_tainted_correlated(..)` | `run_correlated(..)` |
  | `run_plan(plan, Value)` | `run_plan(plan, Tainted<Value>)` |
  | `run_plan_in_case(..)` | `run_plan_correlated(..)` |
  | `spawn_tainted_in_case` / `spawn_tainted_correlated` | `spawn_in_case` / `spawn_correlated` |

  Wrap an operator's own literal: `run(cap, Tainted::trusted(json!(..)))`. A
  `run_trusted`/`run_tainted` pair was tried first and rejected — it doubles every
  shape and still lets `run_trusted(cap, payload)` compile over data nobody
  vouched for. A label is a value; a method name cannot be computed.

- **`--no-default-features --features postgres` now delivers a store.** `store`
  was declared under the `redb` feature while holding *both* backends, so a
  Postgres-only build compiled, pulled `tokio-postgres` in, and exposed no store
  module at all. If you worked around it by also enabling `redb`, you no longer
  need to.

### Added

- **`upgrading`** — a migration page for the refusals that break existing
  manifests and call sites, with the shortest correct fix for each.
- **Plans in `concepts`** — *the unit of concurrency is the plan node*, with
  `PlanIR::fan_out`. Its absence had led at least one evaluation to conclude
  in-run fan-out was impossible and to design around it.
- **`cx.manifest()` in the manifest reference** — a coded skill reads its own
  declaration, so behaviour in Rust and a digest-covered prompt are not the
  trade-off the page implied.
- **A near-miss hint on plan tool names.** A hand-written plan naming the
  manifest spelling (`svc__get_gas`) rather than the wire spelling
  (`svc__get_ugas`, `_` escaping as `_u`) was refused as *not granted*, which
  reads as a policy problem. The refusal now names both spellings.
- **`SemanticRetriever` scope**, answered at the trait: a static operator-ingested
  reference corpus is a first-class use, *as memory items* — a hit is a
  `Selected { id, version, digest }`, so an external corpus is ingested rather
  than federated.

### Fixed

- **Three mutations had rotted into code that no longer compiled**, so three
  guarantees were unfalsifiable while every check stayed green: strict replay
  never re-opening the policy gate, a retried draw double-spending a standing
  authorization, and an Agent Card advertising undeclared capabilities. Each was
  broken by a *successful* change elsewhere; `just anchors` reported all three
  present, because it checks text and not types.
- **The mutation sweep was switched off in CI.** The job was gated to pull
  requests on the reasoning that a push to `main` had already passed it — true of
  a repository that merges, and this one has never opened a pull request. It runs
  on every push now.
- **`Append::into_body`** was gated on `redb` while `PostgresStore` calls it on
  every append, so the Postgres backend did not compile standalone at all.
- **`testkit::conformance_case`** was gated on `redb` despite naming no redb
  type, making the Postgres case-layer contract untestable without linking the
  embedded backend.
- **`just test-postgres` / `test-vault`** did not pass `--no-default-features`,
  so the section comment claiming each seam runs "with *only* its own features
  on" was false for both.
- **The A2A conformance verdict could not distinguish a passing MUST row from a
  skipped one.** `just test-a2a-tck` now prints every skip and holds the pass
  count to a floor.
- **`docs/regulation` contradicted `docs/erasure`** on whether journaled personal
  data can be erased. It described the world before `SealedJournal`: with a key
  ring wired, the chain commits to ciphertext and destroying the wrapping key
  erases every copy while the history still verifies. The wrong page is the one a
  data-protection reader reaches first, and it blocked an evaluation.

### Assurance

- **SSRF classifier**: 67 of 111 mutations survived, because the tests were a
  list of addresses that must be refused — which cannot fail when a bound moves
  *outward*. Every range is now pinned from both sides. 67 missed → 1, and that
  one is a provably equivalent mutant.
- **Label lattice**: 39 of 109 survived, including `field_labels` replaced with
  an empty iterator. Pinned from both sides; 39 → 18.
- `build()` now points long-running services at `try_build`.

## [0.9.0] — 2026-08-08

- **Added** `model::embeddings` — OpenAI-compatible, Bedrock Titan and Cohere
  embedding drivers, so semantic retrieval needs no bespoke embedder.
- **Changed — breaking** CLI argument parsing is per-verb: a flag lives on its
  subcommand, `--strict` requires `--replay`, and the two input flags conflict.
  `run --push-host …` no longer parses.

## [0.8.0] — 2026-08-07

- **Added** A2A push notifications — tenant-keyed durable registrations, a
  governed transport, and an `A2aPushWorker` for the operator scheduler.
- **Fixed** a JSON `null` in a Cedar request context denied everything, because
  Cedar refuses a whole context containing one.

## [0.7.0] — 2026-08-07

- **Fixed** A2A task state was derived two ways — an enum match on the immediate
  response and a string match behind `_ => Failed` on every read-back path — so
  one task could give two answers.

## [0.6.0] — 2026-08-07

- **Added** Bedrock reasoning dialects (`ReasoningDialect::Nova`), declared rather
  than sniffed from a model id.
- **Changed** errors user code holds report through `Display` under `Debug`, so
  `fn main() -> Result<_, E>` shows the sentence somebody wrote.
- **Changed** docs use `cargo add` rather than pinning a version that goes stale.

## [0.5.0] — 2026-08-07

- **Added** sealing at rest from one `.keyring(..)` call — journal payloads, case
  state, task proposals, event payloads and blob bytes. The chain commits to
  ciphertext, so an auditor with no keys verifies a run whose payloads are gone.
- **Added** break-glass: a cross-tenant read is sealed into the crossed tenant's
  own journal, with a mandatory reason, before any data is served.
- **Added** `security.max_sensitivity_journaled` — a ceiling on what may be
  written down forever, refused at dispatch before the announcement.

## [0.4.0] — 2026-08-07

- **Added** multi-agent rooms: several manifests in one file separated by `---`,
  with identity staying per-agent.
- **Added** a `chat-completions` driver for the OpenAI-compatible wire — TGI,
  vLLM, Ollama, llama.cpp, hosted routers.
- **Added** documentation guards: every published API name, manifest field and
  YAML fragment is checked against the code.

## [0.3.0] — 2026-08-06

- **Added** standing authority — a spend ceiling bound to an authorization rather
  than a run or a billing period, revocable, with idempotent draws.
- **Changed** canonicalization key ordering moved to UTF-16 code units so signed
  Agent Cards verify against RFC 8785 rather than only against this crate. Every
  digest moved.

## [0.2.0] — 2026-08-05

- **Added** governed memory on both backends — formation, retention, legal hold,
  cascading forget and cryptographic erasure.
- **Added** PostgreSQL push delivery storage.

## [0.1.0] — 2026-08-02

- First tagged release: the effect protocol, the hash-chained journal, replay and
  resume, the redb backend (replacing an earlier Turso/SQLite one),
  content-addressed blobs for oversized records, and the mutation harness that
  requires each guarantee's named test to fail when the guarantee is removed.
