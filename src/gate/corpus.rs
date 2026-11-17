//! The two-way corpus gate (issue #1745 P-P2, design §5 layer 2) plus
//! the whole-tree report the `gate` CLI prints.
//!
//! Direction (a) — detection duty: every `rules/` rule must own a
//! `corpus/exploits/<rule-id>.json` sample AND that sample must MATCH
//! the rule under the consumer-verdict mirror ([`matcher::RequestForms`]);
//! a sample-less rule or a non-matching sample refuses approval (a
//! literal that cannot detect its own recorded exploit is a guess).
//!
//! Direction (b) — false-positive duty: NO rule may match ANY
//! `corpus/benign/*.json` request; a match names all three rows
//! (benign file, rule id, the rule's exploit sample) so the curator can
//! judge which side is wrong. The benign corpus has a hard floor
//! ([`BENIGN_MIN`] = 200 honest innocent requests — design §5 layer 2:
//! publication never starts below it), and the corpus carries an
//! honesty seal: no benign request may contain a consumer seed pattern
//! in any of its match forms (the benign corpus must not contain the
//! very strings the seeds are the model of).
//!
//! Approval-PR qualification: every `candidates/*.json` approvable
//! candidate (`proposed` + provenance) must pass the literal lint; the
//! report lists failures as warnings and the exit reflects them — a
//! literal that cannot pass the lint has no approval PR qualification.

use crate::gate::lint::{lint_candidate_literal, lint_rule, publish_gate_check, Diagnostic};
use crate::gate::matcher::RequestForms;
use crate::schema::{CorpusRequest, PatternType};
use config_model::waf_feed::WafFeedRule;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The design §5 layer-2 floor: the gate refuses a tree whose benign
/// corpus carries fewer honest innocent requests than this.
pub const BENIGN_MIN: usize = 200;

/// One corpus- or tree-level violation (rule lint diagnostics live in
/// [`Diagnostic`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpusDiagnostic {
    RuleFileUnparsable {
        file: String,
    },
    ExploitSampleMissing {
        rule_id: String,
    },
    ExploitSampleUnparsable {
        rule_id: String,
        file: String,
    },
    ExploitSampleNoMatch {
        rule_id: String,
        file: String,
    },
    BenignFileUnparsable {
        file: String,
    },
    /// The three-row identification: WHICH benign file, WHICH rule,
    /// WHICH exploit sample defines the rule's intent.
    BenignMatch {
        benign_file: String,
        rule_id: String,
        exploit_sample: String,
    },
    BenignCorpusTooSmall {
        count: usize,
    },
}

impl CorpusDiagnostic {
    pub fn code(&self) -> &'static str {
        match self {
            CorpusDiagnostic::RuleFileUnparsable { .. } => "rule_file_unparsable",
            CorpusDiagnostic::ExploitSampleMissing { .. } => "exploit_sample_missing",
            CorpusDiagnostic::ExploitSampleUnparsable { .. } => "exploit_sample_unparsable",
            CorpusDiagnostic::ExploitSampleNoMatch { .. } => "exploit_sample_no_match",
            CorpusDiagnostic::BenignFileUnparsable { .. } => "benign_file_unparsable",
            CorpusDiagnostic::BenignMatch { .. } => "benign_match",
            CorpusDiagnostic::BenignCorpusTooSmall { .. } => "benign_corpus_too_small",
        }
    }

    pub fn explain(code: &str) -> Option<&'static str> {
        Some(match code {
            "rule_file_unparsable" => {
                "A rules/*.json file is not a valid UVPB feed rule; \
                the gate cannot judge what it cannot parse."
            }
            "exploit_sample_missing" => {
                "Every rule must carry a recorded exploit sample \
                it demonstrably detects (design §5 layer 2a) — a literal without a \
                matching sample is a guess, not a virtual patch."
            }
            "exploit_sample_unparsable" => {
                "The rule's exploit sample is not a valid \
                corpus request; detection duty cannot be evidenced."
            }
            "exploit_sample_no_match" => {
                "The recorded exploit sample does NOT match its \
                rule under the consumer's own match semantics — the rule would not fire \
                on the very exploit it was written for."
            }
            "benign_file_unparsable" => {
                "A benign corpus file is not a valid corpus \
                request; fix or remove it."
            }
            "benign_match" => {
                "A rule matches an honest innocent request (design §5 \
                layer 2b) — the named benign file, rule, and its exploit sample let the \
                curator judge which side is wrong before publication."
            }
            "benign_corpus_too_small" => {
                "Publication never starts with a benign corpus \
                below 200 honest innocent requests (design §5 layer 2, L3)."
            }
            _ => return None,
        })
    }
}

impl std::fmt::Display for CorpusDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorpusDiagnostic::RuleFileUnparsable { file } => {
                write!(formatter, "rule file {file} does not parse as a feed rule")
            }
            CorpusDiagnostic::ExploitSampleMissing { rule_id } => {
                write!(formatter, "rule {rule_id} has no corpus/exploits/{rule_id}.json sample")
            }
            CorpusDiagnostic::ExploitSampleUnparsable { rule_id, file } => {
                write!(formatter, "rule {rule_id}'s exploit sample {file} does not parse")
            }
            CorpusDiagnostic::ExploitSampleNoMatch { rule_id, file } => write!(
                formatter,
                "rule {rule_id}'s exploit sample {file} does NOT match the rule"
            ),
            CorpusDiagnostic::BenignFileUnparsable { file } => {
                write!(formatter, "benign corpus file {file} does not parse")
            }
            CorpusDiagnostic::BenignMatch {
                benign_file,
                rule_id,
                exploit_sample,
            } => write!(
                formatter,
                "BENIGN MATCH: {benign_file} matches rule {rule_id} (its exploit sample: {exploit_sample})"
            ),
            CorpusDiagnostic::BenignCorpusTooSmall { count } => write!(
                formatter,
                "benign corpus has {count} requests (floor is {BENIGN_MIN})"
            ),
        }
    }
}

/// One approvable candidate whose literal failed the lint: listed as a
/// warning with file and literal, and reflected in the exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateWarning {
    pub file: String,
    pub literal: String,
    pub diagnostics: Vec<Diagnostic>,
}

/// The whole-tree gate result. `is_green` is the exit law: no rule
/// lint diagnostics, no corpus diagnostics, no candidate warnings, and
/// the codec publish gate accepted the assembled rule set.
#[derive(Debug, Default)]
pub struct GateReport {
    pub rules_checked: usize,
    pub benign_count: usize,
    pub rule_diagnostics: BTreeMap<String, Vec<Diagnostic>>,
    pub corpus_diagnostics: Vec<CorpusDiagnostic>,
    pub candidate_warnings: Vec<CandidateWarning>,
    pub publish_rejection: Option<waf_bundle_encoder::PublishRejection>,
}

impl GateReport {
    pub fn is_green(&self) -> bool {
        self.rule_diagnostics.is_empty()
            && self.corpus_diagnostics.is_empty()
            && self.candidate_warnings.is_empty()
            && self.publish_rejection.is_none()
    }
}

fn json_files(directory: &Path) -> Vec<(String, PathBuf)> {
    let mut files: Vec<(String, PathBuf)> = std::fs::read_dir(directory)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                let name = path.file_name()?.to_str()?.to_owned();
                Some((name, path))
            } else {
                None
            }
        })
        .collect();
    files.sort();
    files
}

fn parse_requests(files: &[(String, PathBuf)]) -> Vec<(String, Option<CorpusRequest>)> {
    files
        .iter()
        .map(|(name, path)| {
            let parsed = std::fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<CorpusRequest>(&bytes).ok());
            (name.clone(), parsed)
        })
        .collect()
}

/// The schema-level pattern type of a feed rule (the matcher's
/// vocabulary; identical wire spellings).
fn rule_pattern_type(rule: &WafFeedRule) -> PatternType {
    match rule.pattern_type {
        config_model::ManagedWafPatternType::QueryString => PatternType::QueryString,
        config_model::ManagedWafPatternType::RequestUri => PatternType::RequestUri,
        config_model::ManagedWafPatternType::UserAgent => PatternType::UserAgent,
        config_model::ManagedWafPatternType::RequestMethod => PatternType::RequestMethod,
        config_model::ManagedWafPatternType::RequestBody => PatternType::RequestBody,
    }
}

/// The two-way corpus gate over already-parsed rules: detection duty
/// per rule, false-positive duty and the floor over the benign corpus.
fn corpus_check(rules: &[WafFeedRule], root: &Path) -> Vec<CorpusDiagnostic> {
    let mut diagnostics = Vec::new();
    let exploits = json_files(&root.join("corpus/exploits"));
    let exploit_requests: BTreeMap<String, Option<CorpusRequest>> =
        parse_requests(&exploits).into_iter().collect();
    let benign = json_files(&root.join("corpus/benign"));
    let benign_requests = parse_requests(&benign);

    let mut rule_forms: Vec<(&WafFeedRule, RequestForms)> = Vec::new();
    for rule in rules {
        let sample_file = format!("{}.json", rule.id);
        let Some(Some(sample)) = exploit_requests.get(&sample_file) else {
            diagnostics.push(CorpusDiagnostic::ExploitSampleMissing {
                rule_id: rule.id.clone(),
            });
            continue;
        };
        let forms = RequestForms::build(sample);
        if forms.matches(rule_pattern_type(rule), &rule.pattern) {
            rule_forms.push((rule, forms));
        } else {
            diagnostics.push(CorpusDiagnostic::ExploitSampleNoMatch {
                rule_id: rule.id.clone(),
                file: format!("corpus/exploits/{sample_file}"),
            });
        }
    }

    for (name, request) in &benign_requests {
        let Some(request) = request else {
            diagnostics.push(CorpusDiagnostic::BenignFileUnparsable {
                file: format!("corpus/benign/{name}"),
            });
            continue;
        };
        let forms = RequestForms::build(request);
        for (rule, _) in &rule_forms {
            if forms.matches(rule_pattern_type(rule), &rule.pattern) {
                diagnostics.push(CorpusDiagnostic::BenignMatch {
                    benign_file: format!("corpus/benign/{name}"),
                    rule_id: rule.id.clone(),
                    exploit_sample: format!("corpus/exploits/{}.json", rule.id),
                });
            }
        }
    }
    // The floor counts VALID requests, not files: an unparsable file
    // is its own diagnostic and simultaneously drops the valid count.
    let benign_valid = benign_requests
        .iter()
        .filter(|(_, request)| request.is_some())
        .count();
    if benign_valid < BENIGN_MIN {
        diagnostics.push(CorpusDiagnostic::BenignCorpusTooSmall {
            count: benign_valid,
        });
    }
    diagnostics
}

/// The approvable-candidate lint pass: every `proposed` candidate with
/// a provenance must pass the literal lint to keep its approval-PR
/// qualification; failures are warnings (and fail the exit).
fn candidate_check(root: &Path) -> Vec<CandidateWarning> {
    let mut warnings = Vec::new();
    for (name, path) in json_files(&root.join("candidates")) {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(file) = serde_json::from_slice::<crate::schema::CandidateFile>(&bytes) else {
            continue;
        };
        for candidate in file.approvable() {
            let diagnostics = lint_candidate_literal(&candidate.literal, candidate.pattern_type);
            if !diagnostics.is_empty() {
                warnings.push(CandidateWarning {
                    file: format!("candidates/{name}"),
                    literal: candidate.literal.clone(),
                    diagnostics,
                });
            }
        }
    }
    warnings
}

/// Runs the whole-tree gate: rule lint + two-way corpus + approvable
/// candidate lint + the codec publish-gate assertion. Missing
/// directories read as empty (a tree before its first curation PR is
/// a legal green tree of zero rules).
pub fn run_gate(root: &Path) -> GateReport {
    let mut rule_diagnostics: BTreeMap<String, Vec<Diagnostic>> = BTreeMap::new();
    let mut corpus_diagnostics: Vec<CorpusDiagnostic> = Vec::new();
    let mut rules = Vec::new();
    for (name, path) in json_files(&root.join("rules")) {
        match std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<WafFeedRule>(&bytes).ok())
        {
            Some(rule) => {
                let diagnostics = lint_rule(&rule);
                if !diagnostics.is_empty() {
                    rule_diagnostics.insert(format!("rules/{name}"), diagnostics);
                }
                rules.push(rule);
            }
            None => {
                corpus_diagnostics.push(CorpusDiagnostic::RuleFileUnparsable {
                    file: format!("rules/{name}"),
                });
            }
        }
    }
    corpus_diagnostics.extend(corpus_check(&rules, root));
    let candidate_warnings = candidate_check(root);
    let publish_rejection = publish_gate_check(&rules).err();
    let benign_count = json_files(&root.join("corpus/benign")).len();
    GateReport {
        rules_checked: rules.len(),
        benign_count,
        rule_diagnostics,
        corpus_diagnostics,
        candidate_warnings,
        publish_rejection,
    }
}
