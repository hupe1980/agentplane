//! Content rules: deterministic predicates a manifest declares over a value's
//! strings, applied at the boundaries the plane already owns.
//!
//! A rule may refuse a value, raise its sensitivity, or redact it at a sink —
//! and nothing else. There is no verdict that admits, trusts or lowers a
//! label, so the worst a wrong or evaded rule does is fail to refuse. The
//! claim is narrow: *rule R refused, raised or redacted values whose
//! normalised strings matched P at boundary B*. Homoglyphs, encodings and a
//! value split across two fields evade a pattern; this is hygiene beside the
//! label lattice, not a boundary replacing it.
//!
//! One evaluator, [`Rules::at`], serves the runtime's gates and the offline
//! `agentplane content check`, so the two cannot disagree about a value.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

use crate::core::Sensitivity;

/// The largest compiled program one pattern may have. A pattern past it is a
/// parse error naming the rule, not a slow gate.
const PATTERN_SIZE_LIMIT: usize = 1 << 20;

/// `spec.security.content`: the rules a deployment holds this agent's values
/// to.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Content {
    #[serde(default)]
    pub rules: Vec<ContentRule>,
    /// Uses of a registered [`ContentChecker`]: a classifier describes the
    /// value in categories, and the declared `on` table decides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<ContentCheck>,
    #[serde(skip)]
    #[schemars(skip)]
    compiled: Compiled,
}

/// One declared rule: a matcher, where it applies, and its one action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContentRule {
    /// Unique within the manifest; what a refusal names.
    pub id: String,
    #[serde(rename = "match")]
    pub matcher: Matcher,
    pub at: Positions,
    /// JSON pointers narrowing which subtrees are read. Empty reads the whole
    /// value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// `refuse`, `{classify: <sensitivity>}` or `{redact: <token>}` — a map,
    /// not a YAML tag, in every format the manifest is read from.
    #[serde(with = "serde_yaml_ng::with::singleton_map")]
    #[schemars(with = "RuleAction")]
    pub then: RuleAction,
}

/// A declared use of a registered checker.
///
/// The checker describes; the table decides. A category the table does not
/// name is recorded and changes nothing, and there is no score threshold: a
/// verdict a deployment did not write down is not one it can review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContentCheck {
    /// Unique among the manifest's rules and checks; what a refusal names.
    pub id: String,
    /// The [`ContentChecker::name`] of a checker registered on the builder.
    pub checker: String,
    /// Sinks, and the outputs of model and tool calls: a check runs as an
    /// effect of the step, so it judges what a step sends or what one of its
    /// calls returns.
    pub at: Positions,
    /// From the checker's declared categories to what each one does.
    #[serde(with = "serde_yaml_ng::with::singleton_map_recursive")]
    #[schemars(with = "BTreeMap<String, CheckAction>")]
    pub on: BTreeMap<String, CheckAction>,
}

/// What a category a check reports does. Neither can admit or lower.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckAction {
    Refuse,
    /// Join the value's sensitivity with this one.
    Classify(Sensitivity),
}

/// Exactly one of `pattern`, `contains` or `invisible`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    /// A regular expression under the linear-time engine: no backreferences,
    /// no look-around.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// With `pattern`: a match counts only when its digits pass the Luhn
    /// check, so a card-number rule skips order numbers of the same length.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub luhn: bool,
    /// Literal substrings; any one matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contains: Vec<String>,
    /// With `contains`: `fold` matches regardless of case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<Case>,
    /// The code points that render as nothing: tag characters, variation
    /// selectors, zero-width and bidirectional controls.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invisible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Case {
    Fold,
}

/// Where a rule applies.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Positions {
    /// The run's input, before it is admitted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub admission: bool,
    /// An effect's output, as it is recorded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<Boundary>,
    /// A value about to be sent, before the effect is announced.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sinks: Vec<Boundary>,
}

/// An effect kind a rule can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Boundary {
    #[serde(rename = "model.complete")]
    ModelComplete,
    #[serde(rename = "tool.call")]
    ToolCall,
    #[serde(rename = "event.await")]
    EventAwait,
    #[serde(rename = "media.fetch")]
    MediaFetch,
    #[serde(rename = "memory.recall")]
    MemoryRecall,
}

impl Boundary {
    /// The effect kind, as a descriptor names it.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::ModelComplete => "model.complete",
            Self::ToolCall => "tool.call",
            Self::EventAwait => "event.await",
            Self::MediaFetch => "media.fetch",
            Self::MemoryRecall => "memory.recall",
        }
    }

    /// Whether a value is sent here. An awaited event and a recall only
    /// arrive.
    const fn is_sink(self) -> bool {
        matches!(
            self,
            Self::ModelComplete | Self::ToolCall | Self::MediaFetch
        )
    }

    /// Whether a value arrives here. A fetched medium's bytes are the media
    /// validator's, not a rule's.
    const fn is_source(self) -> bool {
        !matches!(self, Self::MediaFetch)
    }
}

/// What a matching rule does. None of these can admit, trust or lower.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Refuse,
    /// Join the value's sensitivity with this one.
    Classify(Sensitivity),
    /// Replace each match with this token. Sinks only.
    Redact(String),
}

/// A boundary a value is judged at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum At<'a> {
    Admission,
    Source(&'a str),
    Sink(&'a str),
}

/// Where a rule matched. The pointer names an object key any applying rule
/// matches as `*`, because a key can be the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule: String,
    pub pointer: String,
}

/// What the rules applying at one boundary said about one value.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Outcome {
    /// Every rule that applies here, matched or not, so a record can tell
    /// "passed the rules" from "no rule applied".
    pub evaluated: Vec<String>,
    /// Refuse rules that matched, and redact rules that matched an object
    /// key (redaction rewrites strings, never the shape). Any entry refuses.
    pub refused: Vec<Hit>,
    /// Redact rules that matched a string.
    pub redactions: Vec<Hit>,
    /// Classify rules that matched.
    pub classified: Vec<String>,
    /// The join of every matched classification.
    pub sensitivity: Option<Sensitivity>,
    /// The value with every redaction applied, when any applied.
    pub redacted: Option<Value>,
}

impl Outcome {
    /// `declared` joined with every matched classification: never lower.
    #[must_use]
    pub fn raise(&self, declared: Sensitivity) -> Sensitivity {
        crate::core::content_joined(declared, self.sensitivity)
    }
}

impl Content {
    /// Check the declaration and compile it, so a rule the engine refuses is a
    /// parse error rather than a gate failure.
    ///
    /// # Errors
    ///
    /// The first rule that is malformed, named.
    pub fn validate(&self) -> Result<(), String> {
        self.rules()?;
        let mut seen: std::collections::BTreeSet<&str> =
            self.rules.iter().map(|r| r.id.trim()).collect();
        for check in &self.checks {
            let id = check.id.trim();
            if id.is_empty() {
                return Err("spec.security.content.checks: a check has an empty id".to_owned());
            }
            let named = |detail: &str| format!("spec.security.content.checks '{id}': {detail}");
            if !seen.insert(id) {
                return Err(named("the id is declared twice"));
            }
            if check.checker.trim().is_empty() {
                return Err(named("`checker` is empty"));
            }
            let at = &check.at;
            if at.admission {
                return Err(named(
                    "a check runs as an effect of a run, and at admission there is no run yet",
                ));
            }
            if at.sources.is_empty() && at.sinks.is_empty() {
                return Err(named(
                    "`at` names no boundary, so the check could never run",
                ));
            }
            if let Some(kind) = at.sinks.iter().find(|b| !b.is_sink()) {
                return Err(named(&format!("'{}' is not a sink", kind.kind())));
            }
            if let Some(kind) = at
                .sources
                .iter()
                .find(|b| !matches!(b, Boundary::ModelComplete | Boundary::ToolCall))
            {
                return Err(named(&format!(
                    "a check judges the output of a model or tool call, not of '{}'",
                    kind.kind()
                )));
            }
            if check.on.is_empty() {
                return Err(named(
                    "`on` maps no category, so the check could decide nothing",
                ));
            }
        }
        Ok(())
    }

    /// The checks that apply at this boundary, in declaration order.
    pub fn checks_at<'a>(&'a self, at: At<'a>) -> impl Iterator<Item = &'a ContentCheck> + 'a {
        self.checks.iter().filter(move |c| match at {
            At::Admission => false,
            At::Source(kind) => c.at.sources.iter().any(|b| b.kind() == kind),
            At::Sink(kind) => c.at.sinks.iter().any(|b| b.kind() == kind),
        })
    }

    /// The compiled rules, compiled once.
    ///
    /// # Errors
    ///
    /// As [`validate`](Self::validate).
    pub fn rules(&self) -> Result<&Rules, String> {
        self.compiled
            .0
            .get_or_init(|| Rules::compile(&self.rules).map(Arc::new))
            .as_deref()
            .map_err(Clone::clone)
    }
}

/// The compiled form, cached beside the declaration it was compiled from.
/// Not part of the document: equality and the digest are the declaration's.
#[derive(Clone, Default)]
struct Compiled(OnceLock<Result<Arc<Rules>, String>>);

impl PartialEq for Compiled {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl std::fmt::Debug for Compiled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Compiled")
    }
}

/// A declaration's rules, compiled.
#[derive(Debug)]
pub struct Rules {
    rules: Vec<Rule>,
}

#[derive(Debug)]
struct Rule {
    id: String,
    find: Find,
    at: Positions,
    fields: Vec<String>,
    then: RuleAction,
}

#[derive(Debug)]
enum Find {
    Pattern { re: regex::Regex, luhn: bool },
    Invisible,
}

impl Rules {
    fn compile(declared: &[ContentRule]) -> Result<Self, String> {
        let mut seen = std::collections::BTreeSet::new();
        let mut rules = Vec::with_capacity(declared.len());
        for rule in declared {
            let id = rule.id.trim();
            if id.is_empty() {
                return Err("spec.security.content.rules: a rule has an empty id".to_owned());
            }
            let named = |detail: &str| format!("spec.security.content.rules '{id}': {detail}");
            if !seen.insert(id) {
                return Err(named("the id is declared twice"));
            }
            let find = Find::compile(&rule.matcher).map_err(|e| named(&e))?;
            let at = &rule.at;
            if !at.admission && at.sources.is_empty() && at.sinks.is_empty() {
                return Err(named(
                    "`at` names no boundary, so the rule could never apply",
                ));
            }
            if let Some(kind) = at.sinks.iter().find(|b| !b.is_sink()) {
                return Err(named(&format!("'{}' is not a sink", kind.kind())));
            }
            if let Some(kind) = at.sources.iter().find(|b| !b.is_source()) {
                return Err(named(&format!("'{}' is not a source", kind.kind())));
            }
            if matches!(rule.then, RuleAction::Redact(_))
                && (at.admission || !at.sources.is_empty())
            {
                return Err(named(
                    "`redact` applies at sinks only — a value that arrived is recorded as it \
                     arrived",
                ));
            }
            if let Some(bad) = rule
                .fields
                .iter()
                .find(|p| !p.is_empty() && !p.starts_with('/'))
            {
                return Err(named(&format!("'{bad}' in `fields` is not a JSON pointer")));
            }
            rules.push(Rule {
                id: id.to_owned(),
                find,
                at: rule.at.clone(),
                fields: rule.fields.clone(),
                then: rule.then.clone(),
            });
        }
        Ok(Self { rules })
    }

    /// Judge `value` at one boundary under every rule that applies there.
    ///
    /// Reads every string leaf and object key, after Unicode NFC, within each
    /// rule's `fields`. Never records or returns matched text.
    #[must_use]
    pub fn at(&self, at: At<'_>, value: &Value) -> Outcome {
        let applying: Vec<&Rule> = self.rules.iter().filter(|r| r.applies(at)).collect();
        let mut outcome = Outcome {
            evaluated: applying.iter().map(|r| r.id.clone()).collect(),
            ..Outcome::default()
        };
        if applying.is_empty() {
            return outcome;
        }
        let masks = |key: &str| {
            let key = normalised(key);
            applying.iter().any(|r| r.find.matches(&key))
        };
        // Redactions by the real pointer of the leaf they rewrite, in rule
        // order, applied to one copy after every rule has read the original.
        let mut edits: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, rule) in applying.iter().enumerate() {
            for root in rule.roots() {
                let Some(sub) = value.pointer(root) else {
                    continue;
                };
                walk(sub, root, root, &masks, &mut |real, shown, text, key| {
                    if !rule.find.matches(&normalised(text)) {
                        return;
                    }
                    let hit = Hit {
                        rule: rule.id.clone(),
                        pointer: shown.to_owned(),
                    };
                    match &rule.then {
                        RuleAction::Refuse => outcome.refused.push(hit),
                        RuleAction::Classify(level) => {
                            if !outcome.classified.contains(&rule.id) {
                                outcome.classified.push(rule.id.clone());
                            }
                            outcome.sensitivity =
                                Some(outcome.sensitivity.map_or(*level, |s| s.max(*level)));
                        }
                        RuleAction::Redact(_) if key => outcome.refused.push(hit),
                        RuleAction::Redact(_) => {
                            let at_leaf = edits.entry(real.to_owned()).or_default();
                            if !at_leaf.contains(&index) {
                                at_leaf.push(index);
                                outcome.redactions.push(hit);
                            }
                        }
                    }
                });
            }
        }
        if !edits.is_empty() {
            let mut copy = value.clone();
            for (pointer, indices) in edits {
                if let Some(Value::String(leaf)) = copy.pointer_mut(&pointer) {
                    let mut text = normalised(leaf);
                    for index in indices {
                        if let RuleAction::Redact(token) = &applying[index].then {
                            text = applying[index].find.replace(&text, token);
                        }
                    }
                    *leaf = text;
                }
            }
            outcome.redacted = Some(copy);
        }
        outcome
    }
}

impl Rule {
    fn applies(&self, at: At<'_>) -> bool {
        match at {
            At::Admission => self.at.admission,
            At::Source(kind) => self.at.sources.iter().any(|b| b.kind() == kind),
            At::Sink(kind) => self.at.sinks.iter().any(|b| b.kind() == kind),
        }
    }

    fn roots(&self) -> Vec<&str> {
        if self.fields.is_empty() {
            vec![""]
        } else {
            self.fields.iter().map(String::as_str).collect()
        }
    }
}

impl Find {
    fn compile(matcher: &Matcher) -> Result<Self, String> {
        let Matcher {
            pattern,
            luhn,
            contains,
            case,
            invisible,
        } = matcher;
        let declared = usize::from(pattern.is_some())
            + usize::from(!contains.is_empty())
            + usize::from(*invisible);
        if declared != 1 {
            return Err(
                "`match` takes exactly one of `pattern`, `contains` or `invisible`".to_owned(),
            );
        }
        if *luhn && pattern.is_none() {
            return Err("`luhn` qualifies a `pattern`".to_owned());
        }
        if case.is_some() && contains.is_empty() {
            return Err("`case` qualifies `contains`".to_owned());
        }
        if *invisible {
            return Ok(Self::Invisible);
        }
        let (source, fold) = if let Some(pattern) = pattern {
            (pattern.clone(), false)
        } else {
            if contains.iter().any(String::is_empty) {
                return Err("`contains` holds an empty string, which matches everything".to_owned());
            }
            let alternatives: Vec<String> = contains
                .iter()
                .map(|c| regex::escape(&normalised(c)))
                .collect();
            (alternatives.join("|"), *case == Some(Case::Fold))
        };
        let re = regex::RegexBuilder::new(&source)
            .case_insensitive(fold)
            .size_limit(PATTERN_SIZE_LIMIT)
            .dfa_size_limit(PATTERN_SIZE_LIMIT)
            .build()
            .map_err(|e| format!("the pattern does not compile: {e}"))?;
        Ok(Self::Pattern { re, luhn: *luhn })
    }

    fn matches(&self, text: &str) -> bool {
        match self {
            Self::Pattern { re, luhn: false } => re.is_match(text),
            Self::Pattern { re, luhn: true } => re.find_iter(text).any(|m| luhn(m.as_str())),
            Self::Invisible => text.chars().any(crate::core::visible::is_hidden),
        }
    }

    fn replace(&self, text: &str, token: &str) -> String {
        match self {
            Self::Pattern { re, luhn: checked } => {
                let mut out = String::with_capacity(text.len());
                let mut last = 0;
                for m in re.find_iter(text) {
                    if *checked && !luhn(m.as_str()) {
                        continue;
                    }
                    out.push_str(&text[last..m.start()]);
                    out.push_str(token);
                    last = m.end();
                }
                out.push_str(&text[last..]);
                out
            }
            Self::Invisible => text
                .chars()
                .map(|c| {
                    if crate::core::visible::is_hidden(c) {
                        token.to_owned()
                    } else {
                        c.to_string()
                    }
                })
                .collect(),
        }
    }
}

/// A classifier a deployment brings: it describes a value, and never decides.
///
/// Registered on the builder by [`name`](Self::name); a manifest's checks
/// name it, and map the categories it reports to a verdict.
///
/// It is reached as a journaled `content.check` effect: announced, authorized
/// as `effect:perform` on `content.check`, refused by the sink gate when the
/// value is above [`max_sensitivity`](Self::max_sensitivity) — sending text to
/// a classifier is egress — metered, and read back on replay without being
/// called. An error, a timeout or a category outside
/// [`categories`](Self::categories) refuses the value it was asked about.
#[async_trait::async_trait]
pub trait ContentChecker: Send + Sync + std::fmt::Debug {
    /// The name a manifest's check refers to it by.
    fn name(&self) -> &str;
    /// The version of the ruleset it applies; part of the check's effect key,
    /// so a changed classifier is a changed effect.
    fn revision(&self) -> &str;
    /// Every category it may report.
    fn categories(&self) -> &std::collections::BTreeSet<String>;
    /// The highest sensitivity it may be shown.
    fn max_sensitivity(&self) -> Sensitivity;
    /// Describe `value`.
    ///
    /// # Errors
    ///
    /// Anything that kept it from answering. The value is refused.
    async fn check(&self, value: &Value) -> Result<Assessment, String>;
}

/// The checkers registered on a plane, by name.
pub type Checkers = Arc<BTreeMap<String, Arc<dyn ContentChecker>>>;

/// What a checker reported.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Assessment {
    pub categories: std::collections::BTreeSet<String>,
    pub spend: crate::core::Spend,
}

/// A check's recorded answer: what the checker reported, and what the
/// declared table made of it at the time. Replay reads both and calls nobody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checked {
    pub categories: std::collections::BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<crate::core::ContentVerdict>,
    #[serde(default, skip_serializing_if = "crate::core::Spend::is_free_ref")]
    pub spend: crate::core::Spend,
}

/// One check of one value, as an effect.
#[derive(Debug)]
pub(crate) struct CheckEffect {
    pub(crate) checker: Arc<dyn ContentChecker>,
    pub(crate) check: ContentCheck,
    pub(crate) arguments: Value,
}

#[async_trait::async_trait]
impl crate::core::Effect for CheckEffect {
    type Output = Checked;

    fn descriptor(&self) -> crate::core::EffectDescriptor {
        // The value by digest: its bytes are the guarded call's, and a second
        // copy in the journal would be a second thing to seal and erase.
        crate::core::EffectDescriptor::new(
            CHECK_KIND,
            serde_json::json!({
                "check": self.check.id,
                "checker": self.checker.name(),
                "revision": self.checker.revision(),
                "value": crate::core::Digest::of(&crate::core::canon::value_bytes(&self.arguments)),
            }),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn recovery(&self) -> crate::core::Recovery {
        crate::core::Recovery::Retry
    }

    /// One attempt: a checker that could not answer refuses the value it was
    /// asked about, and asking again would only delay that answer.
    fn retry(&self) -> crate::core::RetryPolicy {
        crate::core::RetryPolicy::never()
    }

    fn max_sensitivity(&self) -> Sensitivity {
        self.checker.max_sensitivity()
    }

    fn sink_arguments(&self) -> Option<&Value> {
        Some(&self.arguments)
    }

    async fn perform(&self) -> Result<Checked, crate::core::EffectError> {
        let fail = |detail: String| {
            crate::core::EffectError::Other(format!(
                "content check '{}' could not judge the value: {detail}",
                self.check.id
            ))
        };
        let Assessment { categories, spend } =
            self.checker.check(&self.arguments).await.map_err(fail)?;
        if let Some(unknown) = categories
            .iter()
            .find(|c| !self.checker.categories().contains(*c))
        {
            return Err(fail(format!(
                "it reported '{unknown}', a category it does not declare"
            )));
        }
        Ok(Checked {
            verdict: map_categories(&self.check, &categories),
            categories,
            spend,
        })
    }

    fn spend(&self, output: &Checked) -> crate::core::Spend {
        output.spend
    }
}

/// The effect kind of a content check.
pub(crate) const CHECK_KIND: &str = "content.check";

/// What `check`'s table makes of the reported categories; `None` where it
/// names none of them.
fn map_categories(
    check: &ContentCheck,
    categories: &std::collections::BTreeSet<String>,
) -> Option<crate::core::ContentVerdict> {
    let mut sensitivity = None;
    let mut refused = None;
    for category in categories {
        match check.on.get(category) {
            Some(CheckAction::Refuse) if refused.is_none() => {
                refused = Some(crate::core::ContentRefusal {
                    rule: check.id.clone(),
                    pointer: String::new(),
                });
            }
            Some(CheckAction::Classify(level)) => {
                sensitivity = Some(crate::core::content_joined(*level, sensitivity));
            }
            _ => {}
        }
    }
    (refused.is_some() || sensitivity.is_some()).then(|| crate::core::ContentVerdict {
        rules: vec![check.id.clone()],
        sensitivity,
        refused,
    })
}

/// NFC, so a precomposed and a decomposed spelling of one word match alike.
fn normalised(text: &str) -> String {
    if unicode_normalization::is_nfc(text) {
        text.to_owned()
    } else {
        text.nfc().collect()
    }
}

/// Whether the digits in `text` pass the Luhn check.
fn luhn(text: &str) -> bool {
    let digits: Vec<u32> = text.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 2 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Visit every string leaf and object key under `value`, with its real
/// pointer and the pointer a record may show.
fn walk(
    value: &Value,
    real: &str,
    shown: &str,
    masks: &dyn Fn(&str) -> bool,
    visit: &mut dyn FnMut(&str, &str, &str, bool),
) {
    match value {
        Value::String(text) => visit(real, shown, text, false),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk(
                    item,
                    &format!("{real}/{i}"),
                    &format!("{shown}/{i}"),
                    masks,
                    visit,
                );
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let segment = crate::core::canon::pointer_token(key);
                let real = format!("{real}/{segment}");
                let shown = if masks(key) {
                    format!("{shown}/*")
                } else {
                    format!("{shown}/{segment}")
                };
                visit(&real, &shown, key, true);
                walk(item, &real, &shown, masks, visit);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(yaml: &str) -> Content {
        let content: Content = serde_yaml_ng::from_str(yaml).expect("parses");
        content.validate().expect("valid");
        content
    }

    /// A boundary is written in a manifest exactly as the effect kind it is
    /// matched against, so a rule cannot name a kind no effect carries.
    #[test]
    fn every_boundary_is_spelled_as_its_effect_kind() {
        for boundary in [
            Boundary::ModelComplete,
            Boundary::ToolCall,
            Boundary::EventAwait,
            Boundary::MediaFetch,
            Boundary::MemoryRecall,
        ] {
            assert_eq!(
                serde_json::to_value(boundary).expect("serializes"),
                serde_json::json!(boundary.kind())
            );
        }
    }

    /// A declaration built in Rust validates and judges as one parsed from
    /// a file does.
    #[test]
    fn a_declaration_built_in_code_validates_like_a_parsed_one() {
        let content = Content {
            rules: vec![ContentRule {
                id: "salary".to_owned(),
                matcher: Matcher {
                    contains: vec!["salary".to_owned()],
                    ..Matcher::default()
                },
                at: Positions {
                    admission: true,
                    ..Positions::default()
                },
                fields: Vec::new(),
                then: RuleAction::Classify(Sensitivity::Confidential),
            }],
            checks: vec![ContentCheck {
                id: "guard".to_owned(),
                checker: "guard".to_owned(),
                at: Positions {
                    sinks: vec![Boundary::ModelComplete],
                    ..Positions::default()
                },
                on: BTreeMap::from([("S7".to_owned(), CheckAction::Classify(Sensitivity::Secret))]),
            }],
            compiled: Compiled::default(),
        };
        content.validate().expect("valid");
        let outcome = content.rules().expect("compiled").at(
            At::Admission,
            &serde_json::json!({ "q": "the salary table" }),
        );
        assert_eq!(outcome.sensitivity, Some(Sensitivity::Confidential));
        assert_eq!(content.checks_at(At::Sink("model.complete")).count(), 1);
    }

    #[test]
    fn luhn_accepts_a_valid_number_and_refuses_a_near_miss() {
        assert!(luhn("4111 1111 1111 1111"));
        assert!(!luhn("4111 1111 1111 1112"));
    }

    #[test]
    fn a_matched_key_is_masked_and_redaction_rewrites_only_the_matched_leaf() {
        let content = rules(
            "rules:
  - id: falcon
    match: {contains: [falcon], case: fold}
    at: {sinks: [tool.call]}
    then: {redact: '[x]'}
",
        );
        let value = serde_json::json!({"a": "Project FALCON now", "b": "calm", "falcon": "k"});
        let outcome = content
            .rules()
            .expect("compiled")
            .at(At::Sink("tool.call"), &value);
        assert_eq!(
            outcome.refused,
            vec![Hit {
                rule: "falcon".to_owned(),
                pointer: "/*".to_owned()
            }]
        );
        assert_eq!(
            outcome.redacted,
            Some(serde_json::json!({"a": "Project [x] now", "b": "calm", "falcon": "k"}))
        );
    }
}
