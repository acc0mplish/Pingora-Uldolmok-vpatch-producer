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
    /// Fail-closed (L4): a curation directory could not be read at
    /// all — the gate refuses rather than treating it as empty.
    DirectoryUnreadable {
        path: String,
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
    /// The corpus honesty seal (design §5), enforced BY the gate: a
    /// benign request contains a consumer seed pattern in one of its
    /// match forms — the corpus must not carry the very strings the
    /// seeds model.
    BenignSeedViolation {
        benign_file: String,
        seed_type: String,
        seed_pattern: String,
    },
    BenignCorpusTooSmall {
        count: usize,
    },
    /// An approvable-candidate file that does not parse is named
    /// instead of silently skipped (L2).
    CandidateFileUnparsable {
        file: String,
    },
}

impl CorpusDiagnostic {
    pub fn code(&self) -> &'static str {
        match self {
            CorpusDiagnostic::RuleFileUnparsable { .. } => "rule_file_unparsable",
            CorpusDiagnostic::DirectoryUnreadable { .. } => "directory_unreadable",
            CorpusDiagnostic::ExploitSampleMissing { .. } => "exploit_sample_missing",
            CorpusDiagnostic::ExploitSampleUnparsable { .. } => "exploit_sample_unparsable",
            CorpusDiagnostic::ExploitSampleNoMatch { .. } => "exploit_sample_no_match",
            CorpusDiagnostic::BenignFileUnparsable { .. } => "benign_file_unparsable",
            CorpusDiagnostic::BenignMatch { .. } => "benign_match",
            CorpusDiagnostic::BenignSeedViolation { .. } => "benign_seed_violation",
            CorpusDiagnostic::BenignCorpusTooSmall { .. } => "benign_corpus_too_small",
            CorpusDiagnostic::CandidateFileUnparsable { .. } => "candidate_file_unparsable",
        }
    }

    pub fn explain(code: &str) -> Option<&'static str> {
        Some(match code {
            "rule_file_unparsable" => {
                "A rules/*.json file is not a valid UVPB feed rule; \
                the gate cannot judge what it cannot parse."
            }
            "directory_unreadable" => {
                "A curation directory could not be read (fail-closed): \
                the gate refuses rather than treating the tree as empty — fix the \
                filesystem error before curating."
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
            "benign_seed_violation" => {
                "A benign corpus request contains a consumer seed \
                pattern in one of its match forms — the corpus is dishonest about its \
                innocence and must be cleaned before publication."
            }
            "benign_corpus_too_small" => {
                "Publication never starts with a benign corpus \
                below 200 honest innocent requests (design §5 layer 2, L3)."
            }
            "candidate_file_unparsable" => {
                "A candidates/*.json file does not parse — its \
                approvable candidates cannot be qualified, so the file is named \
                instead of silently skipped."
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
            CorpusDiagnostic::DirectoryUnreadable { path } => {
                write!(formatter, "directory {path} is unreadable (fail-closed)")
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
            CorpusDiagnostic::BenignSeedViolation {
                benign_file,
                seed_type,
                seed_pattern,
            } => write!(
                formatter,
                "BENIGN SEED VIOLATION: {benign_file} contains seed ({seed_type}, `{seed_pattern}`)"
            ),
            CorpusDiagnostic::BenignCorpusTooSmall { count } => write!(
                formatter,
                "benign corpus has {count} requests (floor is {BENIGN_MIN})"
            ),
            CorpusDiagnostic::CandidateFileUnparsable { file } => {
                write!(formatter, "candidate file {file} does not parse")
            }
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

/// Lists a curation directory's *.json files. Errors propagate (L4,
/// fail-closed): an unreadable directory must be reported, never
/// silently treated as empty — a permissions failure would otherwise
/// read as a green tree of zero rules.
fn json_files(directory: &Path) -> std::io::Result<Vec<(String, PathBuf)>> {
    let mut files: Vec<(String, PathBuf)> = std::fs::read_dir(directory)?
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                let name = path.file_name()?.to_str()?.to_owned();
                Some((name, path))
            } else {
                None
            }
        })
        .collect();
    files.sort();
    Ok(files)
}

/// Lists a directory, reporting a [`CorpusDiagnostic::DirectoryUnreadable`]
/// on failure (the caller then proceeds over an empty listing — every
/// downstream duty check fails closed on the empty side). A MISSING
/// directory stays legal-empty: a tree before its first curation PR
/// (no `rules/` entries, no exploit samples) is a legitimate green
/// tree, while an unreadable PRESENT directory is a filesystem fault.
fn list_or_report(
    directory: &Path,
    diagnostics: &mut Vec<CorpusDiagnostic>,
) -> Vec<(String, PathBuf)> {
    match json_files(directory) {
        Ok(files) => files,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => {
            diagnostics.push(CorpusDiagnostic::DirectoryUnreadable {
                path: directory.display().to_string(),
            });
            Vec::new()
        }
    }
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

/// The seed blocklist's wire spelling of a pattern type (identical
/// snake_case vocabulary). Unknown spellings (a future codec seed
/// type) return `None` and are skipped — the seal coverage is the
/// known set.
fn seed_pattern_type(wire: &str) -> Option<PatternType> {
    match wire {
        "query_string" => Some(PatternType::QueryString),
        "request_uri" => Some(PatternType::RequestUri),
        "user_agent" => Some(PatternType::UserAgent),
        "request_method" => Some(PatternType::RequestMethod),
        "request_body" => Some(PatternType::RequestBody),
        _ => None,
    }
}

/// The two-way corpus gate over already-parsed rules: detection duty
/// per rule, false-positive duty, the honesty seal, and the floor over
/// the benign corpus.
fn corpus_check(rules: &[WafFeedRule], root: &Path) -> Vec<CorpusDiagnostic> {
    let mut diagnostics = Vec::new();
    let exploits = list_or_report(&root.join("corpus/exploits"), &mut diagnostics);
    let exploit_requests: BTreeMap<String, Option<CorpusRequest>> =
        parse_requests(&exploits).into_iter().collect();
    let benign = list_or_report(&root.join("corpus/benign"), &mut diagnostics);
    let benign_requests = parse_requests(&benign);

    let mut rule_forms: Vec<(&WafFeedRule, RequestForms)> = Vec::new();
    for rule in rules {
        let sample_file = format!("{}.json", rule.id);
        // L1: an absent sample and an UNPARSABLE sample are different
        // failures — the latter names the broken file.
        match exploit_requests.get(&sample_file) {
            None => diagnostics.push(CorpusDiagnostic::ExploitSampleMissing {
                rule_id: rule.id.clone(),
            }),
            Some(None) => diagnostics.push(CorpusDiagnostic::ExploitSampleUnparsable {
                rule_id: rule.id.clone(),
                file: format!("corpus/exploits/{sample_file}"),
            }),
            Some(Some(sample)) => {
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
        // The corpus honesty seal (design §5), enforced here in the
        // gate — not only by a test: no benign request may contain a
        // consumer seed pattern in any of its match forms.
        for (seed_type, seed_pattern) in waf_bundle_encoder::seed_blocklist() {
            if let Some(pattern_type) = seed_pattern_type(seed_type) {
                if forms.matches(pattern_type, seed_pattern) {
                    diagnostics.push(CorpusDiagnostic::BenignSeedViolation {
                        benign_file: format!("corpus/benign/{name}"),
                        seed_type: seed_type.clone(),
                        seed_pattern: seed_pattern.clone(),
                    });
                }
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
/// qualification; failures are warnings (and fail the exit). An
/// unparsable candidate FILE is named (L2) instead of silently
/// skipping its qualification.
fn candidate_check(root: &Path, diagnostics: &mut Vec<CorpusDiagnostic>) -> Vec<CandidateWarning> {
    let mut warnings = Vec::new();
    for (name, path) in list_or_report(&root.join("candidates"), diagnostics) {
        let parsed = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<crate::schema::CandidateFile>(&bytes).ok());
        let Some(file) = parsed else {
            diagnostics.push(CorpusDiagnostic::CandidateFileUnparsable {
                file: format!("candidates/{name}"),
            });
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
/// a legal green tree of zero rules); present-but-unreadable
/// directories are fail-closed diagnostics (L4).
pub fn run_gate(root: &Path) -> GateReport {
    let mut rule_diagnostics: BTreeMap<String, Vec<Diagnostic>> = BTreeMap::new();
    let mut corpus_diagnostics: Vec<CorpusDiagnostic> = Vec::new();
    let mut rules = Vec::new();
    for (name, path) in list_or_report(&root.join("rules"), &mut corpus_diagnostics) {
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
    let candidate_warnings = candidate_check(root, &mut corpus_diagnostics);
    let publish_rejection = publish_gate_check(&rules).err();
    let benign_count = list_or_report(&root.join("corpus/benign"), &mut corpus_diagnostics).len();
    GateReport {
        rules_checked: rules.len(),
        benign_count,
        rule_diagnostics,
        corpus_diagnostics,
        candidate_warnings,
        publish_rejection,
    }
}
