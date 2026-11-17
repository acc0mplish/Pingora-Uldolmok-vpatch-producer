//! Candidate generation (issue #1745 P-P1, design D2 rules 1-4).
//!
//! The rules, verbatim:
//! 1. Product tokens are extracted from the NVD record's CPE criteria
//!    strings (lowercase, version stripped — the `vendor:product` pair
//!    of `cpe:2.3:a:vendor:product:version:...`) and from the KEV
//!    entry's `vendorProject`/`product` pair.
//! 2. A relation table (v1-minimal: WordPress plugin slugs and the
//!    highest-frequency server products) turns a token into a
//!    `request_uri` hint candidate. The table is small ON PURPOSE —
//!    candidate quality is bound by the P-P2 corpus gate, not by the
//!    table (design D2).
//! 3. PoC/exploit-tagged NVD references are recorded as
//!    [`Provenance::PocReference`] HINT candidates: the literal holds
//!    the link until a curator replaces it with a string observed in
//!    the PoC. The v1 pipeline performs NO network extraction (the
//!    design's switch is off by default; the hint keeps the link and
//!    its tag).
//! 4. Every candidate carries a provenance. A candidate that somehow
//!    reaches the file without one is force-flipped to
//!    `excluded_no_provenance` at the write boundary
//!    ([`schema::CandidateFile::enforce_provenance`]) and never
//!    approvable (C-P1-1).
//!
//! The generator never approves: every candidate it emits is `proposed`
//! — literal selection is always a human decision (design D2/§7).

use crate::intake::{KevEntry, NvdFacts};
use crate::schema::{Candidate, CandidateFile, CandidateStatus, PatternType, Provenance, Severity};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// The compile-time-embedded relation table (the codec crate's
/// `include_str!` asset pattern; the repo-root `data/` seat, no
/// run-time file reads).
const RELATION_TABLE_JSON: &str = include_str!("../data/relation_table.json");
/// The WordPress plugin entrypoint template (design D2 rule 2's
/// example, promoted to the v1 constant).
const PLUGIN_ENTRYPOINT_TEMPLATE: &str = "/wp-content/plugins/";
/// The NVD field path a CPE-derived provenance names (design D2 rule
/// 4: "which field it came from").
const NVD_CPE_FIELD: &str = "configurations.nodes.cpeMatch.criteria";
/// The KEV field pair a KEV-derived provenance names.
const KEV_PRODUCT_FIELD: &str = "vendorProject/product";

#[derive(serde::Deserialize)]
struct RelationTableAsset {
    plugins: Vec<String>,
    entries: BTreeMap<String, String>,
}

#[derive(Debug)]
struct RelationTable {
    plugins: BTreeSet<String>,
    entries: BTreeMap<String, String>,
}

impl RelationTable {
    fn parse(embedded: &'static str) -> Self {
        let asset: RelationTableAsset =
            serde_json::from_str(embedded).expect("data/relation_table.json is a committed asset");
        Self {
            plugins: asset.plugins.into_iter().collect(),
            entries: asset.entries,
        }
    }
}

/// The product token of one CPE criteria string: the lowercase
/// `vendor:product` pair of the 2.3 spelling
/// `cpe:2.3:<part>:<vendor>:<product>:<version>:...`, with everything
/// from the version component on stripped. Non-CPE strings, other CPE
/// spellings (e.g. the 2.2 `cpe:/a:...` form, whose vendor sits at a
/// different index — rejected rather than mis-parsed), and empty
/// halves yield `None`. NVD CVE API 2.0 records carry 2.3 strings.
pub fn product_token_from_cpe(criteria: &str) -> Option<String> {
    let parts: Vec<&str> = criteria.trim().split(':').collect();
    if parts.len() < 5 || parts[0] != "cpe" || parts[1] != "2.3" {
        return None;
    }
    let vendor = parts[3].trim().to_ascii_lowercase();
    let product = parts[4].trim().to_ascii_lowercase();
    if vendor.is_empty() || product.is_empty() {
        return None;
    }
    Some(format!("{vendor}:{product}"))
}

/// Every distinct product token the record contributes: the NVD CPE
/// criteria first (record order), then the KEV pair. Mapped or not —
/// the file's `tokens[]` is the curator's extraction trace.
pub fn product_tokens(nvd: Option<&NvdFacts>, kev_entry: Option<&KevEntry>) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let push = |token: Option<String>, tokens: &mut Vec<String>| {
        if let Some(token) = token {
            if !tokens.contains(&token) {
                tokens.push(token);
            }
        }
    };
    if let Some(facts) = nvd {
        for criteria in &facts.cpe_criteria {
            push(product_token_from_cpe(criteria), &mut tokens);
        }
    }
    if let Some(entry) = kev_entry {
        push(entry.product_token(), &mut tokens);
    }
    tokens
}

/// The relation table's entrypoint hint for a product token: a
/// WordPress plugin slug maps to `/wp-content/plugins/<slug>/`, an
/// explicit `vendor:product` row maps to its entrypoint, anything else
/// has no hint.
pub fn entrypoint_hint(product_token: &str) -> Option<String> {
    static TABLE: OnceLock<RelationTable> = OnceLock::new();
    let table = TABLE.get_or_init(|| RelationTable::parse(RELATION_TABLE_JSON));
    let (_, product) = product_token.split_once(':')?;
    if table.plugins.contains(product) {
        return Some(format!("{PLUGIN_ENTRYPOINT_TEMPLATE}{product}/"));
    }
    table.entries.get(product_token).cloned()
}

/// The rule severity mapping (design §7): KEV membership or CVSS ≥ 9.0
/// is `critical`, everything else `warning` (this mapping never emits
/// `info`).
pub fn severity_of(kev: bool, cvss: Option<f64>) -> Severity {
    if kev || cvss.is_some_and(|score| score >= 9.0) {
        Severity::Critical
    } else {
        Severity::Warning
    }
}

/// Builds the whole `candidates/<cve>.json` from the record's narrowed
/// facts (D2 rules 1-4). Deterministic in `nvd`'s and the KEV entry's
/// input order; every candidate is `proposed` and provenanced.
pub fn generate_candidate_file(
    cve: &str,
    kev: bool,
    nvd: Option<&NvdFacts>,
    kev_entry: Option<&KevEntry>,
    generated_at: i64,
) -> CandidateFile {
    let tokens = product_tokens(nvd, kev_entry);
    let mut candidates: Vec<Candidate> = Vec::new();
    let push_candidate = |candidate: Candidate, candidates: &mut Vec<Candidate>| {
        if !candidates.iter().any(|known| {
            known.pattern_type == candidate.pattern_type && known.literal == candidate.literal
        }) {
            candidates.push(candidate);
        }
    };

    // Rules 1+2: CPE-derived tokens through the relation table.
    if let Some(facts) = nvd {
        for criteria in &facts.cpe_criteria {
            let Some(token) = product_token_from_cpe(criteria) else {
                continue;
            };
            let Some(entrypoint) = entrypoint_hint(&token) else {
                continue;
            };
            push_candidate(
                Candidate {
                    literal: entrypoint,
                    pattern_type: PatternType::RequestUri,
                    provenance: Some(Provenance::NvdCpe {
                        field: NVD_CPE_FIELD.to_owned(),
                        raw: criteria.clone(),
                    }),
                    status: CandidateStatus::Proposed,
                },
                &mut candidates,
            );
        }
    }
    // Rule 1: a KEV pair that maps where no CPE hint covered the literal.
    if let Some(entry) = kev_entry {
        if let Some(token) = entry.product_token() {
            if let Some(entrypoint) = entrypoint_hint(&token) {
                push_candidate(
                    Candidate {
                        literal: entrypoint,
                        pattern_type: PatternType::RequestUri,
                        provenance: Some(Provenance::KevMetadata {
                            field: KEV_PRODUCT_FIELD.to_owned(),
                        }),
                        status: CandidateStatus::Proposed,
                    },
                    &mut candidates,
                );
            }
        }
    }
    // Rule 3: PoC-tagged references as extraction-hint candidates.
    if let Some(facts) = nvd {
        for hit in &facts.poc_references {
            push_candidate(
                Candidate {
                    literal: hit.url.clone(),
                    pattern_type: PatternType::RequestUri,
                    provenance: Some(Provenance::PocReference {
                        url: hit.url.clone(),
                        tag: hit.tag.clone(),
                    }),
                    status: CandidateStatus::Proposed,
                },
                &mut candidates,
            );
        }
    }

    CandidateFile {
        cve: cve.to_owned(),
        kev,
        cvss: nvd.and_then(|facts| facts.cvss),
        tokens,
        candidates,
        generated_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_table_asset_satisfies_its_invariants() {
        let table = RelationTable::parse(RELATION_TABLE_JSON);
        assert!(!table.plugins.is_empty());
        assert!(!table.entries.is_empty());
        for slug in &table.plugins {
            assert!(
                !slug.is_empty()
                    && slug.bytes().all(|byte| byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'),
                "plugin slugs must be lowercase ascii slugs: {slug}"
            );
        }
        for (token, entrypoint) in &table.entries {
            assert!(
                token
                    .split_once(':')
                    .is_some_and(|(vendor, product)| !vendor.is_empty() && !product.is_empty()),
                "entry keys must be vendor:product tokens: {token}"
            );
            assert!(
                entrypoint.starts_with('/')
                    && entrypoint.len() >= 4,
                "entrypoints must be '/'-rooted and publishable (>= the 4-byte floor): {entrypoint}"
            );
        }
    }

    #[test]
    fn every_relation_table_row_produces_lint_clean_candidates() {
        // A table row whose generator output the P-P2 lint refuses
        // (e.g. a standalone common word like `/login`) would mint
        // committed candidates that turn the gate REFUSED the moment
        // they exist — the table must only hint context-bound
        // entrypoints. This regression binds every row (and the plugin
        // template) to the lint's literal core.
        use crate::gate::lint::lint_candidate_literal;
        use crate::schema::PatternType;

        let table = RelationTable::parse(RELATION_TABLE_JSON);
        for slug in &table.plugins {
            let literal = format!("{PLUGIN_ENTRYPOINT_TEMPLATE}{slug}/");
            assert!(
                lint_candidate_literal(&literal, PatternType::RequestUri).is_empty(),
                "plugin template output for {slug} must pass the lint: {literal}"
            );
        }
        for (token, entrypoint) in &table.entries {
            assert!(
                lint_candidate_literal(entrypoint, PatternType::RequestUri).is_empty(),
                "relation-table entrypoint for {token} must pass the lint: {entrypoint}"
            );
        }
    }
}
