//! What the manifest parser accepts and refuses.
//!
//! Pinned against the parser, not against its documentation, so that changing
//! the parser is judged by these behaviours: each one is a parse-time control on
//! a reviewed security document, and a parser that quietly accepted more would
//! widen every declaration that relied on the refusal.

#![cfg(feature = "manifest")]

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use agentplane::manifest::Manifest;

const HEAD: &str = "apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: pinned, version: \"1.0.0\" }
spec:
  capabilities: { provides: [pin.it] }
";

fn with(body: &str) -> String {
    format!("{HEAD}{body}")
}

fn refused(yaml: &str) -> String {
    match Manifest::parse(yaml) {
        Err(e) => e.to_string(),
        Ok(m) => panic!("parsed, and should not have: {m:?}"),
    }
}

/// `yes`, `no`, `on` and `off` are words, not booleans.
///
/// YAML 1.1 read them as booleans, which is how `NO` (Norway) became `false`.
/// A grant's `mutates` written `no` would then be read-only — exempt from the
/// whole-value taint gate and retried after a timeout — from a word a reviewer
/// read as a country, a typo or a string.
#[test]
fn a_yaml_1_1_boolean_word_is_not_a_boolean() {
    for word in ["yes", "no", "on", "off", "y", "n", "Yes", "NO"] {
        refused(&with(&format!(
            "  tools:\n    - {{ ref: tool://a/b, mutates: {word} }}\n  budgets: {{}}\n"
        )));
    }
    let m = Manifest::parse(&with(
        "  tools:\n    - { ref: tool://a/b, mutates: false }\n  budgets: {}\n",
    ))
    .expect("`false` is a boolean");
    assert!(!m.spec.tools[0].mutates);
}

/// A key written twice is refused, not resolved.
///
/// Either resolution is a ceiling a reviewer did not read: first-wins hides the
/// second line, last-wins hides the first, and the line that looks like the
/// ceiling may be the one ignored.
#[test]
fn a_key_written_twice_is_refused() {
    refused(&with(
        "  budgets: { max_tokens: 100 }\n  budgets: { max_tokens: 100000000 }\n",
    ));
    refused(&with(
        "  budgets: { max_tokens: 100, max_tokens: 100000000 }\n",
    ));
}

/// A merge key is refused.
///
/// `<<: *base` copies fields from somewhere else in the file, so what a grant
/// says is no longer on the lines that declare it. The manifest has no field
/// named `<<`, and it stays an unknown one.
#[test]
fn a_merge_key_is_refused() {
    refused(&with(
        "  tools:
    - &base { ref: tool://a/read, mutates: false }
    - { <<: *base, ref: tool://a/write }
  budgets: {}
",
    ));
}

/// Aliases that multiply are refused, and refused quickly.
///
/// Nine levels of nine aliases each name 387 million leaves from a few hundred
/// bytes. A parser that expanded them would spend the plane's memory on a file
/// anybody who can submit a manifest can write.
#[test]
fn an_alias_bomb_is_refused_quickly() {
    let mut bomb = String::from(
        "  tools:\n    - ref: tool://a/b\n      arguments:\n        a: &a [x, x, x, x, x, x, x, x, x]\n",
    );
    let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
    for pair in names.windows(2) {
        let (prev, next) = (pair[0], pair[1]);
        let refs = vec![format!("*{prev}"); 9].join(", ");
        let _ = writeln!(bomb, "        {next}: &{next} [{refs}]");
    }
    bomb.push_str("  budgets: {}\n");
    // The test's own wall clock, timing the parser: nothing a run reads.
    #[allow(clippy::disallowed_methods)]
    let started = Instant::now();
    let why = refused(&with(&bomb));
    assert!(
        why.contains("alias replay limit"),
        "refused, but not by the alias budget: {why}"
    );

    // Bounded for a declaration, not for a data file: 200 aliases of a
    // thousand-item list replay 200 000 nodes, which no reviewed declaration
    // needs and the parser's own default would admit.
    let wide = format!(
        "  tools:\n    - ref: tool://a/b\n      arguments:\n        a: &a [{}]\n        b: [{}]\n  budgets: {{}}\n",
        vec!["x"; 1000].join(", "),
        vec!["*a"; 200].join(", "),
    );
    let why = refused(&with(&wide));
    assert!(
        why.contains("alias replay limit"),
        "refused, but not by the alias budget: {why}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the bomb was refused only after {:?}",
        started.elapsed()
    );
}

/// A YAML tag does not choose an enum variant.
///
/// A content rule's action is a map (`{classify: confidential}`) or a word
/// (`refuse`), in every format the manifest is read from. A `!classify` tag is
/// a second spelling a JSON reader of the same document would not see.
#[test]
fn a_yaml_tag_does_not_choose_an_enum_variant() {
    let rule = |then: &str| {
        with(&format!(
            "  budgets: {{}}
  security:
    content:
      rules:
        - id: r1
          match: {{ contains: [falcon] }}
          at: {{ sinks: [model.complete] }}
          then: {then}
"
        ))
    };
    Manifest::parse(&rule("{ classify: confidential }")).expect("the map form parses");
    Manifest::parse(&rule("refuse")).expect("the word form parses");
    refused(&rule("!classify confidential"));
}

/// A plain scalar in a string field is read as written.
///
/// `version: 1.10` is the string `1.10`. Read through a float on the way it
/// would be `1.1`, a different version and a different digest.
#[test]
fn a_plain_scalar_in_a_string_field_is_read_as_written() {
    let unquoted = HEAD.replace("version: \"1.0.0\"", "version: 1.10");
    let m = Manifest::parse(&format!("{unquoted}  budgets: {{}}\n"))
        .expect("an unquoted version parses");
    assert_eq!(
        m.metadata.version, "1.10",
        "the version was read through a float"
    );
}

/// A multi-document file names the document that failed.
#[test]
fn a_multi_document_error_names_its_document() {
    let good = with("  budgets: {}\n");
    let bad = with("  budgets: {}\n  surprise: 1\n").replace("name: pinned", "name: other");
    let refused = Manifest::parse_all(&format!("{good}---\n{bad}"))
        .expect_err("an unknown field in the second document");
    assert!(
        refused.to_string().contains("document 2"),
        "the refusal does not say which document: {refused}"
    );
    // A syntax error is located by the parser's document starts, so it names
    // the right document wherever it sits.
    let broken = "metadata: [unclosed\n";
    for (file, expected) in [
        (format!("{broken}---\n{good}"), "document 1"),
        (format!("---\n{good}---\n{good}---\n{broken}"), "document 3"),
    ] {
        let refused = Manifest::parse_all(&file).expect_err("a syntax error");
        assert!(
            refused.to_string().contains(expected),
            "expected {expected}: {refused}"
        );
    }
    let both = Manifest::parse_all(&format!("---\n{good}---\n"))
        .expect("empty documents around one manifest are skipped");
    assert_eq!(both.len(), 1);
}
