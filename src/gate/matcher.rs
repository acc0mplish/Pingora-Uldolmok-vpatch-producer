//! The consumer-verdict mirror for the corpus gate (issue #1745 P-P2,
//! bundle interface item 2): the per-request match forms the producer
//! gate tests corpus samples against, built the way the consumer's WAF
//! builds them so a sample that passes here is a sample the consumer's
//! literal matcher would decide identically.
//!
//! Every form source below names the consumer code it mirrors:
//! - query: `HeadMatchForms::build` in `config-model/src/waf_rules.rs`
//!   (`waf_match_forms(&query.replace('+', " "))`, each form
//!   `to_ascii_lowercase`d).
//! - path/uri: the same builder (`waf_match_forms(path)`, lowered).
//! - user_agent / method: `[raw, nfkc(raw)]` lowered. The consumer's
//!   `waf_unicode_forms` is PRIVATE, so this module composes the same
//!   two-element pair from the public `unicode-normalization` 0.1 with
//!   the consumer's exact fold shape (`is_ascii()` keeps the original
//!   bytes, otherwise `nfkc()`); with both crates resolved to one
//!   0.1.x in the lock the produced form vectors are byte-identical to
//!   the private helper's.
//! - body: the body phase in `config-model/src/waf.rs:444-450` —
//!   `[body.to_ascii_lowercase()]` unioned with the lowered
//!   `waf_match_forms(&body.replace('+', " "))` forms.
//!
//! The verdict is the consumer's literal rule: a pattern of a
//! `pattern_type` matches when ANY form selected for that field
//! `contains` the (already lowercase) pattern.

use crate::schema::{CorpusRequest, PatternType};
use unicode_normalization::UnicodeNormalization;

/// The per-request lowered form vectors, one per match field. `body`
/// is empty when the request carries no body — a `request_body` rule
/// can then never match (the consumer never inspects an absent body
/// either).
pub struct RequestForms {
    query: Vec<String>,
    uri: Vec<String>,
    user_agent: Vec<String>,
    method: Vec<String>,
    body: Vec<String>,
}

/// The private `waf_unicode_forms` twin (see the module doc for the
/// byte-equivalence argument): the raw value plus, when NFKC folding
/// moves it, its NFKC fold.
fn unicode_forms(text: &str) -> Vec<String> {
    // Byte-equivalence with the consumer's `fold_unicode`
    // (config-model/src/waf_rules.rs:47-53): identical ASCII fast path
    // (owned clone) and identical `nfkc().to_string()` otherwise, on
    // the same `unicode-normalization` 0.1 version.
    let folded = if text.is_ascii() {
        text.to_owned()
    } else {
        text.nfkc().to_string()
    };
    let mut forms = vec![text.to_owned()];
    if folded != text {
        forms.push(folded);
    }
    forms
}

/// Lowers one form the way every consumer form path does:
/// `to_ascii_lowercase` (context-free, so lowering once then matching
/// many is verdict-identical — the same argument
/// `HeadMatchForms::build` records).
fn lowered(forms: impl Iterator<Item = String>) -> Vec<String> {
    forms.map(|form| form.to_ascii_lowercase()).collect()
}

impl RequestForms {
    /// Builds every field's forms for one corpus request, mirroring the
    /// consumer field-for-field.
    pub fn build(request: &CorpusRequest) -> Self {
        let query_lowered =
            lowered(config_model::waf_match_forms(&request.query.replace('+', " ")).into_iter());
        let uri_lowered = lowered(config_model::waf_match_forms(&request.path).into_iter());
        let user_agent_lowered = lowered(unicode_forms(&request.user_agent).into_iter());
        let method_lowered = lowered(unicode_forms(&request.method).into_iter());
        let body_lowered = match &request.body {
            // Mirror of config-model/src/waf.rs:444-450: the plain
            // lowercase seed plus the `+`-normalized decode forms,
            // deduplicated in first-seen order (order is irrelevant to
            // the any-form verdict; the dedup keeps the vector small).
            Some(body) => {
                let mut forms = vec![body.to_ascii_lowercase()];
                for form in config_model::waf_match_forms(&body.replace('+', " ")) {
                    let lowered = form.to_ascii_lowercase();
                    if !forms.contains(&lowered) {
                        forms.push(lowered);
                    }
                }
                forms
            }
            None => Vec::new(),
        };
        Self {
            query: query_lowered,
            uri: uri_lowered,
            user_agent: user_agent_lowered,
            method: method_lowered,
            body: body_lowered,
        }
    }

    /// The consumer's literal verdict for one pattern on this request:
    /// any form selected for `pattern_type` containing the pattern.
    /// `pattern` must already be lowercase (the lint gate enforces the
    /// canonical spelling before any corpus sample is consulted).
    pub fn matches(&self, pattern_type: PatternType, pattern: &str) -> bool {
        let forms: &[String] = match pattern_type {
            PatternType::QueryString => &self.query,
            PatternType::RequestUri => &self.uri,
            PatternType::UserAgent => &self.user_agent,
            PatternType::RequestMethod => &self.method,
            PatternType::RequestBody => &self.body,
        };
        forms.iter().any(|form| form.contains(pattern))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(path: &str, query: &str, method: &str, user_agent: &str) -> CorpusRequest {
        CorpusRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            query: query.to_owned(),
            user_agent: user_agent.to_owned(),
            body: None,
            source: None,
        }
    }

    #[test]
    fn query_forms_are_plus_normalized_before_matching() {
        let forms = RequestForms::build(&request("/", "q=union+select+*+from", "GET", "ua"));
        assert!(
            forms.matches(PatternType::QueryString, "union select"),
            "the '+' to space normalization must run before form building"
        );
    }

    #[test]
    fn method_rules_only_see_the_method_field() {
        let forms = RequestForms::build(&request("/", "?method=get", "POST", "ua"));
        assert!(!forms.matches(PatternType::RequestMethod, "get"));
        let forms = RequestForms::build(&request("/", "?method=get", "get", "ua"));
        assert!(forms.matches(PatternType::RequestMethod, "get"));
    }

    #[test]
    fn body_rules_only_see_the_body_field() {
        let mut req = request("/submit", "", "POST", "ua");
        req.body = Some("note=union select".to_owned());
        let forms = RequestForms::build(&req);
        assert!(forms.matches(PatternType::RequestBody, "union select"));
        assert!(
            !forms.matches(PatternType::QueryString, "union select"),
            "an empty query can never carry a query_string match"
        );
    }

    #[test]
    fn bodyless_requests_can_never_match_a_body_rule() {
        let forms = RequestForms::build(&request("/x", "", "GET", "ua"));
        assert!(!forms.matches(PatternType::RequestBody, "a"));
    }
}
