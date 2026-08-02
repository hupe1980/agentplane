# 🤝 Contributing

Thanks for looking. This project has an unusual amount of machinery aimed at one
question — *can this guarantee actually fail a test?* — so the useful thing to
know before changing anything is how that machinery works and what it will ask of
you.

---

## ⚡ The loop

```sh
just              # every recipe, with what it costs
just anchors      # milliseconds — run this constantly
just ci           # what CI runs, in one pass
just ci-full      # the above, plus TLA+ specs and the full mutation sweep
```

`just ci` is the same set of commands CI runs, called through the same recipes —
so a check cannot drift between your machine and the pipeline. When they differ,
the pipeline is right and you find out late; the justfile exists so they cannot.

**What to run when:**

| | cost | when |
|---|---|---|
| `just anchors` | milliseconds | constantly — after any refactor |
| `just test` | seconds | while working |
| `just ci` | ~2 minutes | before pushing |
| `just mutants` | ~25 minutes | before a release, or after touching a guarantee |
| `just specs` | ~2 minutes | after changing the effect protocol, sagas, fencing, or authorization |

`just mutants` is deliberately **not** an inner-loop check — it rebuilds the
library once per mutation. `just anchors` is the one that belongs in your muscle
memory, and it catches the silent half: a refactor that moves the code a mutation
is anchored to leaves that guarantee unverified while still looking verified.

## 🧪 What a change is expected to come with

**A test that could fail without it.** Not a test that passes — one that would
*fail* if the change were reverted. If you cannot construct that, the change may
not be doing what you think.

**A mutation, if you added a guarantee.** `tools/mutants.py` holds a table: each
row breaks one guarantee on purpose and names the **one** test that must fail.
Add a row when you add a rule that could silently stop holding.

```python
"YourGuaranteeIsGone": (
    "src/where/it/lives.rs",
    "the_test_that_must_fail",
    "what breaking it would do, in the failure's own terms",
    "the exact code that enforces it",     # must appear exactly once
    "the code with the guarantee removed",  # must still compile
),
```

Then check it actually bites:

```sh
python3 tools/mutants.py YourGuaranteeIsGone --apply
cargo test --all-features --test <target> the_test_that_must_fail   # must FAIL
python3 tools/mutants.py YourGuaranteeIsGone --revert
```

Two outcomes are errors rather than skips, and both mean the row is testing
nothing: an anchor that no longer matches, and a mutation that does not compile.
The mutation has to *remove the guarantee*, not break the file.

`just anchors` also checks that the README and the design document state the
real number of mutations — a count drifted three times in one day before that
was guarded. And it **refuses to answer** (exit 2) while a sweep is running,
because a sweep holds one file mutated at a time and every anchor result in that
window is false. A checker that answers wrongly is worse than one that declines.

**The first example must still build.** `just doc-examples` assembles the
getting-started skill and wiring into a fresh crate and runs it, because
`cargo test --doc` only covers rustdoc inside `src/` — the markdown a newcomer
actually copies was unverified until this existed. It is part of `just ci`, so
renaming a public item breaks it immediately rather than at somebody's first
five minutes with the crate.

**A doc update if you changed behaviour.** `site/content/docs/` is kept level
with the code — it is the published documentation, not a copy of it.
A design document that does not update on contact is decoration.

## 🚫 Things that will be pushed back on

**Reading the clock, RNG, or generating an id directly.** These are denied
crate-wide by `clippy.toml`. There are three legitimate escapes, each carrying an
explicit `#[allow]` and a comment naming the journal record that captures the
value. A fourth needs to argue for itself — including for instrumentation, which
is the most plausible-sounding reason to want one and would make a replayed run
re-measure calls it never made.

**A new `Trust::Trusted` effect.** A trusted effect opts out of the taint gate,
the egress ceiling *and* the replan refusal at once, silently. There is a guard
that counts them and fails the build when the count changes.

**An assertion that accepts two outcomes.** `assert!(matches!(x, A(_)) || x.is_b())`
passed for a year here while hiding two separate bugs. `||` between "right" and
"also acceptable", `all()` over a possibly-empty slice, and `is_ok()` without
checking the value are three ways to write a test that cannot fail.

**Silent anything.** No silent truncation, plan repair, replay divergence, budget
degradation, compensation failure, or unmatched inbound event. Each is a loud,
typed, journaled event someone can be paged on. If your change makes something
fail quietly, it will be asked to fail loudly instead.

## 🖼️ The site

`just site` builds it; `just site-serve` runs it with reload. Two things are
generated rather than committed by hand:

- `site/static/og.png` — the social card, rasterised from `site/assets/og.svg`
  by `just og`. The SVG is the source, so the card is reviewable in a diff
  rather than an opaque binary.

  The PNG is **committed** rather than built in CI, because the pipeline has no
  rasteriser and a social card is not worth adding one for. That does make it a
  second copy: **edit the SVG and it is stale until you run `just og`.** Nothing
  checks this, so it is on you.
- `site/public/` — the build output.

Diagrams are **hand-authored inline SVG**, not a diagram-as-code toolchain.
Three diagrams do not justify a Node build step, and inline SVG inherits the
page's colours through `currentColor`, so it themes for free and costs nothing
at runtime. Every one needs `<title>` and `<desc>` — a diagram a screen reader
cannot read is decoration.

`zola check` fails on a broken internal link *or anchor*, which is the check the
prose most often gets wrong.

## 🧭 Finding your way

| | |
|---|---|
| 🧠 | [Concepts](site/content/docs/concepts.md) — read this first; it is short |
| 🏗️ | [Architecture](site/content/docs/architecture.md) — how each mechanism works |
| 🔐 | [Security model](site/content/docs/security.md) — the trust boundary and its limits |
| 📋 | [Status](site/content/docs/status.md) — what is built and what is not |

The module layout, and the one discipline that matters (`core/` has zero I/O
dependencies, enforced by a test), is in
[architecture](site/content/docs/architecture.md#module-layout).

## 🐛 Reporting something

**A bug in a guarantee** is the most valuable thing you can report — that a
mechanism does not do what the docs say. Include what you expected, from which
document, and what happened. If a mutation survives that shouldn't, say which.

**A security issue** should not go in a public issue. The threat model, including
what is deliberately *not* covered, is in [security](site/content/docs/security.md#%EF%B8%8F-what-is-not-covered)
— please check there first, since several gaps are known and recorded rather than
undiscovered.

## 📄 License

By contributing you agree that your work is licensed under MIT OR Apache-2.0, the
same terms as the project.
