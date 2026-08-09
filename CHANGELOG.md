# Changelog

Notable changes per release, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

**Pre-alpha, and versioned accordingly.** The crate *is* published — `0.x` bumps
carry breaking changes without deprecation cycles, because a hard cut is cheaper
than a compatibility shim, and pre-1.0 is the window in which that is an honest
trade rather than a broken promise. Every breaking entry says what to do about
it, and [upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/)
carries the ones that need more than a sentence.

This line used to read *the crate is not published*, which stopped being true at
the first release and stayed on the page — the shape this project catalogues as a
premise that expired. It matters more here than most: an entry's audience is
somebody who already depends on a version, so "nobody has yet depended on it" is
exactly the assumption a changelog may not make.

**This file carries the reasoning, not just the diff.** It used to share that job
with a status page listing everything built — two hundred rows, nearly all of them
phrased as *X used to do Y, now it does Z*, which is a change and not a status.
Keeping one fact in two places is the defect this project treats most seriously
elsewhere, so the list is gone and the entries below are where a mechanism's
history lives. [Status](https://hupe1980.github.io/agentplane/docs/status/) now
answers only what a status page can: what will move, what is deliberately absent,
and how to check either. What *exists* is answered by the
[concepts](https://hupe1980.github.io/agentplane/docs/concepts/) page, the
[API reference](https://docs.rs/agentplane), and the test suite.

Entries for `0.1.0`–`0.9.0` are reconstructed from tags and commit history rather
than written at the time, so they are deliberately terse — inventing more would be
archaeology presented as a record.

## [0.12.0] — 2026-08-09

### Fixed — testing

- **A flaky Vault container test.** `WaitFor` matching a stdout line means the
  process printed it, not that Docker has finished publishing the port, so a
  one-shot `get_host_port_ipv4` failed as `PortNotExposed` on a loaded machine.
  Both call sites now retry within a bound; a genuinely dead container still
  fails loudly. Worth an entry because a flake trains people to re-run rather
  than read, which costs more than the test is worth.

### Fixed — interoperability

- **An absent `tenant` was sent as JSON `null` instead of being omitted**, and a
  comment above the line said *"omitted entirely when the interface declares
  none"* — which is what it was meant to do and not what it did. `json!` renders
  `None` as `null`; ProtoJSON omits a field at its default value, so the
  reference server answered `invalid type: null, expected a string`. The same
  bug was in `GetTask` and in the governance extension's `provenance`.

  **This crate's own server accepted all of it** — `serde` reads `null` into an
  `Option` as `None` — so every in-repo test agreed with the bug. It took a
  server nobody here wrote to find it, on the first round trip.

### Added

- **Client-side interoperability evidence, against an independent server.** The
  protocol project's conformance kit validates *servers*, so this crate's client
  had no outside authority to talk to — the one interoperability gap the kit
  cannot close, and a release blocker. `a2a-server-lf` (the reference Rust SDK's
  server) now stands up in-process as a **dev-dependency** test double: its
  request handler, its task store, its JSON-RPC framing, none of it written
  here. Two tests: a full `SendMessage` round trip, and a disposition mapping
  taken from the reference server's own refusal rather than from a canned
  fixture written to this crate's reading of the spec.

  Pre-1.0 churn is acceptable here in a way it is not on a shipped boundary:
  nothing in `src/` links these crates and `cargo package` does not carry
  dev-dependencies. `default-features = false` keeps a TLS stack out of it — the
  double binds a loopback port over plain HTTP.

- **Canonicalization is versioned, and a rule change reads as *unverifiable*
  rather than *divergent*.** `core::canon::VERSION` is journaled on
  `RunAdmitted`, defaulting to `1` on read so a record written before the field
  existed says the UTF-8 ordering that produced it. Replay compares it before
  recomputing anything: a run written under another rule is
  `RuntimeError::CanonicalizationChanged`, not a quarantine.

  Why it mattered: every effect key comes out of the canonicalizer, so the
  change from UTF-8 byte ordering to RFC 8785's UTF-16 code units moved all of
  them at once. A replay of healthy history recomputed different keys and
  reported **non-determinism** — the most serious conclusion this runtime
  reaches — with nothing on the record to say the rule had moved. The chain was
  never implicated and the test asserts that too: it hashes the bytes it stored
  rather than re-canonicalizing them, so a refusal that also implied corruption
  would be the wrong answer twice.

- **A plane serves an Agent Card per agent.** `A2aServer::hosting(..)` takes
  several manifests; each agent gets a full card at `/agents/{name}/agent-card.json`,
  and the well-known path stays one valid card describing the first. A new
  `agent-directory` extension on that card lists every agent, its card path and
  its manifest digest. The discriminator is a **path**, not `AgentInterface::tenant`
  — that field's documented meaning is the tenant id a caller echoes back, so
  overloading it to select an agent would put two meanings in one string on a
  multi-tenant plane. Skill dispatch already spanned every agent on the runtime;
  what was missing was discovery. Two agents advertising one skill id is refused
  at construction (`ServerSetupError::AmbiguousSkill`), because A2A dispatch is
  named and a name resolving to two agents is a routing decision the caller did
  not make. An empty plane is `ServerSetupError::NoAgents`.

- **`ErasureCoordinator`, and a PostgreSQL implementation.**
  `EncryptedMemoryStore` serialised subject erasure against writes and
  legal-hold changes with a process-local mutex — correct on a single writer,
  silently nothing on an active-active plane. The lock is now a seam:
  `LocalCoordinator` is the mutex, named for what it is and answering
  `is_distributed() == false`; `PostgresCoordinator` (from
  `PostgresStore::erasure_coordinator()`) is a **session** advisory lock in the
  database the plane already shares, so an instance that dies mid-erasure
  releases by dying. Wire it with `EncryptedMemoryStore::coordinated_by(..)`.
  Held by a test that races two coordinators against a live PostgreSQL and
  asserts both halves — the second instance blocks while the first holds, and is
  granted once it releases.

  **The unsafe pairing is refused at `build`.** `JournalStore::is_shared` (new,
  and **required** — no default, so a shared backend cannot answer
  *single-writer* by saying nothing) meets `MemoryStore::erasure_is_distributed`
  (new, defaulting to `None` for a store with no lifecycle lock), and a shared
  store beside a process-local lock is `BuildError::ErasureCoordinatorNotShared`.
  Four cases are pinned, because the two that must still build are what keep it
  from being a ban.

  `ErasureCoordinator::acquire` is documented as **not cancel-safe**: dropping it
  mid-flight can leave the lock taken with no lease to release, because the
  PostgreSQL coordinator has a query outstanding on a pooled connection at that
  moment. Found by a test that wrapped it in a `timeout` and hung the suite. Use
  `under_lock`; to ask whether a scope is locked without taking it, use
  `PostgresStore::erasure_probe`.

## [0.11.0] — 2026-08-09

### Changed — breaking

- **A `mutates: true` grant with no `protected_fields` is refused at parse for a
  `tool-calling` agent.** Three facts composed: a model completion is untrusted
  unconditionally, the tool loop builds a call's arguments from it, and a
  mutating sink whose grant names no protected fields refuses an untrusted
  argument bundle outright. Together, such a grant could never fire — and the
  run did not fail cleanly, it *succeeded having done nothing the model asked
  for*. Reported from a migration with 108 such grants across 27 manifests, all
  unreachable, each reading as a live capability. Three fixes, and the message
  gives all three: declare the authority-bearing arguments in
  `protected_fields` (ordinary untrusted content may sit beside them, which is
  what the feature is for); move to `execution.kind: planned`, whose arguments
  are resolved by the runtime; or say `mutates: false`.

- **`BuildError::OversightUnreachable`.** An agent declaring `spec.oversight` or
  a `requires_approval` grant now refuses the build on a plane with no case
  store, worklist or timers. Both facts are known at `build`; left to run time
  it arrived at the first real approval with a person already waiting.

- **A2A method parameters are per-method and unknown names are refused.** One
  `CommonParams` served every method, so a field belonging to one was silently
  accepted by another. `ListTasks` was the case that mattered: a request whose
  `contextId` was misspelled — or spelled `context_id`, which the A2A
  specification's §5.5 forbids — parsed cleanly, dropped the filter, and
  answered with **every** task the caller may see, shaped exactly like the
  scoped list. Found by the protocol project's own conformance kit, whose
  JSON-RPC client sends snake_case: five CORE-LIST rows had been passing over a
  filter that never ran.

### Added

- **`Runtime::case_of(run)`** — which case a run belongs to, read from the
  journal rather than a column beside it.
- **`PushSender::allow_plaintext_loopback`** (`testkit` only) — lifts the HTTPS
  and public-address refusals for a webhook on this machine, so the conformance
  kit's `http://localhost:PORT` receiver is reachable and its **ten push MUSTs
  run at all**. The operator host grant is not lifted, and a plaintext public
  destination stays refused.

### Fixed

- **The worked taint-gate policy in `docs/security` was an outage.**
  `context.label` is the *whole bundle's* label, so in a tool loop the `forbid`
  matched every mutating call. A deployment shipped it and its unit tests
  passed, because a hand-written context is a context assembled to suit the
  rule. The page now says so and offers a scoped form.
- The `getting-started` guide points services at `try_build()`.

### Changed — breaking (continued)

- **One `Duration` on the public surface.** `StepCtx::deadline`'s `warn_before`,
  `Runtime::sweep_events`'s `grace` and `Runtime::sweep`'s `event_grace` took
  `time::Duration` while `StepCtx::sleep` took `std::time::Duration` — two types
  spelled the same word, only one from a crate this one re-exports, so a caller
  with the obvious `use std::time::Duration` met a type error naming a
  dependency the guides never mention. They now all take
  `std::time::Duration`. It is also **unsigned**, which makes two states
  unrepresentable that the signed type allowed: a negative `warn_before` put
  `warn_at` *after* the instant it warns about, and a negative grace window
  moved the dead-letter cutoff forward of now.

  `time::Duration::hours(1)` becomes `std::time::Duration::from_secs(3600)`.
  (`Duration::from_hours` is still unstable on the declared MSRV, which is also
  why `clippy::duration_suboptimal_units` is allowed with the command that
  re-derives the premise.)

- **`DeadlineSpec::minutes`** joins `hours` and `days`. `WallClock` resolved
  `"minutes"` and nothing spelled it, which is where `"minute"` and `"mins"`
  start diverging between an application and its calendar adapter.

### Fixed

- **A push webhook that will never be delivered to is abandoned, not retried
  forever.** The operator's host grant is re-checked at *delivery* as well as at
  registration, because a registration outlives the configuration that permitted
  it — but the worker noticed the refusal and then rescheduled it, so a host
  taken off the allowlist bought one more attempt every 256 seconds for as long
  as the journal existed. Permanent refusals (`NotHttps`, `HostNotGranted`,
  `Malformed`) now abandon the registration; transient ones keep their backoff
  and gain a ceiling, `A2aPushWorker::max_attempts` (32 by default). `Unroutable`
  stays transient, because it covers DNS and DNS changes.

- **`PushSweepReport::needs_attention()`**, matching `SweepReport`. Giving up on
  a peer's webhook used to produce `retries: 1` on an *info* line — the same
  shape a rebooting receiver produces — so `agentplane serve` logged an
  unrecoverable delivery failure as routine progress. New field:
  `PushSweepReport::abandoned`.

- **`--features bedrock` alone now exposes `BedrockEmbedder`.** The `embeddings`
  module was gated on `providers` while holding the Bedrock driver, so a
  Bedrock-only build paid for the AWS SDK and could not name an embedder at all —
  leaving semantic retrieval unavailable to the deployments that chose Bedrock
  because their data may not leave one account. The gate is now
  `any(providers, bedrock)`, and a `const _` in `lib.rs` names each embedder so a
  future gate regression fails this crate's build.

- **An embedding component no `f32` can hold is refused.** `1e39` parses as an
  ordinary JSON number and narrows to `inf`, which the length check could not
  see; `serde_json::to_value` then writes it as `null`, so every out-of-range
  component would have shared one effect key. A zero-magnitude vector is refused
  for the neighbouring reason — it has no direction to rank against.

- **The `run_trusted` that never existed.** The README and the getting-started
  page published the plane's *no such capability* message with a method name
  deleted in 0.10.0. A guard now formats the real error and holds both pages to
  it.

- **`DeadlineSpec::working_days`, which never existed either.** The concepts
  page taught obligations with it — beside a comment saying *five working days*
  while the call said one, the tell that nobody had run it. A second guard now
  refuses any documented `Type::associated_fn` this crate does not declare; the
  previous one covered `StepCtx` alone.

- **`Duration::from_hours(24)` in a published snippet.** Still unstable, so the
  `cx.sleep` example on the architecture page did not compile.

### Testing

- `RecordingPush`, the A2A push test double, now honours its own `validate`. It
  did not, so *the grant is re-checked at delivery* had no test that travelled
  the worker's path — the one path an operator's revocation takes.
- An automated sweep over `model::embeddings` left **14 of 53** mutations alive,
  including `check_egress -> Ok(())`, both `revision()` implementations, and the
  whole of `BedrockEmbedder::embed`. 14 became 0. The egress test itself was the
  interesting repair: it pointed at an unresolvable host and asserted the failure
  named it, which a DNS error does too, so it passed with the ceiling deleted.

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
