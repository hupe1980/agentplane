//! One contract, run against every calendar.
//!
//! The calendar is the seam this crate is most likely to be *replaced* at: the
//! built-in one understands hours, days and minutes, and a deployment with a
//! real regulatory deadline needs working days, public holidays, a cut-off hour
//! and a named timezone. That replacement computes a legally binding instant,
//! and nothing above it can check the answer — the engine journals what the
//! calendar returned and never calls back.
//!
//! So the properties here are the ones a wrong implementation makes invisible:
//!
//! * **resolution is pure.** The same `(from, spec)` resolves to the same
//!   instant, or two runs registered a millisecond apart disagree about one
//!   regulatory window — intermittently, which is worse than always.
//! * **a rule it does not know is refused, never approximated.** A wrong
//!   working-day answer is worse than no answer, because it looks right.
//! * **a count at the boundary of its type is an error, not a panic.** The
//!   count comes out of a manifest's `params`, and `time`'s duration
//!   constructors multiply while its instant operators add — both panic rather
//!   than return. The built-in calendar had exactly this defect: a plane
//!   hosting many agents aborted, taking every other tenant's in-flight run
//!   with it, to report one document's typo.
//! * **the digest identifies the ruleset**, because it is the only record of
//!   which rules produced an instant somebody will be held to.

use crate::core::{Calendar, CalendarError, DeadlineSpec, Timestamp};

use super::conformance::Report;

/// Run the battery against one calendar.
///
/// `supported` is the specs this calendar claims to resolve — at least one, and
/// ideally one per rule it implements. The hostile variants are derived from
/// them rather than supplied, so an implementer cannot hand the battery the
/// inputs their code already handles.
pub fn check(calendar: &dyn Calendar, supported: &[DeadlineSpec], report: &mut Report) {
    let from = Timestamp::from_unix_timestamp(1_760_000_000).expect("a valid test instant");

    report.checked += 1;
    if supported.is_empty() {
        report.record(
            "a calendar resolves something",
            "no supported spec was given, so this battery would pass without \
             resolving anything",
        );
        return;
    }

    the_digest_is_stable(calendar, report);
    for spec in supported {
        resolution_is_pure(calendar, from, spec, report);
        a_count_at_the_edge_of_its_type_is_refused(calendar, from, spec, report);
    }
    a_rule_it_does_not_know_is_refused(calendar, from, report);
}

/// The ruleset's identity does not move between two reads of it.
fn the_digest_is_stable(calendar: &dyn Calendar, r: &mut Report) {
    r.checked += 1;
    if calendar.digest() != calendar.digest() {
        r.record(
            "the digest identifies the ruleset",
            "two reads of the digest disagreed, so the instants this calendar \
             produced cannot be attributed to any ruleset at all",
        );
    }
}

/// The same question, twice, is the same answer.
fn resolution_is_pure(
    calendar: &dyn Calendar,
    from: Timestamp,
    spec: &DeadlineSpec,
    r: &mut Report,
) {
    r.checked += 1;
    let first = calendar.resolve(from, spec);
    let second = calendar.resolve(from, spec);
    match (first, second) {
        (Ok(a), Ok(b)) if a == b => {}
        (Ok(a), Ok(b)) => r.record(
            "resolution is pure",
            format!(
                "'{}' resolved to {a} and then to {b}; two runs a millisecond apart \
                 would disagree about one regulatory window",
                spec.kind
            ),
        ),
        (Err(a), Err(b)) if a.to_string() == b.to_string() => {}
        (a, b) => r.record(
            "resolution is pure",
            format!(
                "'{}' answered {a:?} and then {b:?}; a rule that refuses \
                 intermittently is a rule nobody can act on",
                spec.kind
            ),
        ),
    }
}

/// A count no instant can carry is an error rather than an abort.
fn a_count_at_the_edge_of_its_type_is_refused(
    calendar: &dyn Calendar,
    from: Timestamp,
    spec: &DeadlineSpec,
    r: &mut Report,
) {
    for hostile in hostile_variants(spec) {
        r.checked += 1;
        // A panic here fails the test, which is the honest outcome: this is the
        // failure mode the check exists for, and there is nothing to report it
        // as from inside the call that is taking the process down.
        match calendar.resolve(from, &hostile) {
            Err(_) => {}
            Ok(at) => r.record(
                "a count no instant can carry is refused",
                format!(
                    "'{}' with {} resolved to {at}; a window that long is a typo with \
                     no correct reading, and an obligation registered at that instant \
                     is one nobody will ever be warned about",
                    hostile.kind, hostile.params
                ),
            ),
        }
    }
}

/// The same spec with every integer parameter driven to the edge of its type.
///
/// Derived from the caller's own spec rather than supplied, so an implementer
/// cannot hand the battery the inputs their code already handles.
fn hostile_variants(spec: &DeadlineSpec) -> Vec<DeadlineSpec> {
    let serde_json::Value::Object(params) = &spec.params else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for extreme in [i64::MAX, i64::MIN] {
        let mut hostile = params.clone();
        let mut touched = false;
        for value in hostile.values_mut() {
            if value.is_i64() || value.is_u64() {
                *value = serde_json::Value::from(extreme);
                touched = true;
            }
        }
        if touched {
            out.push(DeadlineSpec::new(
                spec.kind.clone(),
                serde_json::Value::Object(hostile),
            ));
        }
    }
    out
}

/// A rule the calendar does not implement is named, not approximated.
fn a_rule_it_does_not_know_is_refused(calendar: &dyn Calendar, from: Timestamp, r: &mut Report) {
    r.checked += 1;
    let unknown = DeadlineSpec::new(
        "agentplane.conformance/no-such-rule",
        serde_json::json!({ "n": 5 }),
    );
    match calendar.resolve(from, &unknown) {
        Err(CalendarError::UnknownKind(_)) => {}
        Err(other) => r.record(
            "an unknown rule is refused by name",
            format!(
                "a rule this calendar does not implement was refused as {other}, so a \
                 deployment cannot tell a missing rule from a malformed one"
            ),
        ),
        Ok(at) => r.record(
            "an unknown rule is refused, never approximated",
            format!(
                "a rule this calendar does not implement resolved to {at}; a wrong \
                 working-day answer is worse than no answer, because it looks right"
            ),
        ),
    }
}
