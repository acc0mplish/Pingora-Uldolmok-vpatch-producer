//! Claim 8 (issue #1745 P-P2): the corpus gate matcher reproduces the
//! CONSUMER's semantics on the consumer's known evasion classes. The
//! form-set construction itself is the consumer's own public
//! `waf_match_forms` (config-model, pinned at the same rev as the
//! codec); what these tests pin is THIS code's half of the pipeline —
//! the per-field form selection (`pattern_type` → field), the
//! lowering, and the literal `contains` verdict — on cases recorded
//! from the consumer sources (waf_rules.rs HeadMatchForms, waf.rs body
//! phase, waf_unicode_forms).

use uldolmok_vpatch_pipeline::gate::matcher::RequestForms;
use uldolmok_vpatch_pipeline::schema::{CorpusRequest, PatternType};

fn build(
    method: &str,
    path: &str,
    query: &str,
    user_agent: &str,
    body: Option<&str>,
) -> RequestForms {
    RequestForms::build(&CorpusRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        user_agent: user_agent.to_owned(),
        body: body.map(|body| body.to_owned()),
        source: None,
    })
}

/// Sanity helper proving a fixture's RAW field does not contain the
/// pattern — so every `matches` below is attributable to a form
/// transformation this pipeline performs, never to the raw bytes.
fn raw_misses(field: &str, raw: &str, pattern: &str) {
    assert!(
        !raw.contains(pattern),
        "fixture sanity: raw {field} must not contain {pattern:?}"
    );
}

#[test]
fn fidelity_fullwidth_sqlmap_user_agent_matches_through_nfkc() {
    // Consumer anchor: `waf_unicode_forms` closes the fullwidth
    // look-alike class (`ｓｑｌｍａｐ` -> `sqlmap`) — raw + NFKC pair,
    // lowered, contains-checked (config-model/src/waf_rules.rs:62-69,
    // 117-121).
    let raw = "ｓｑｌｍａｐ/1.0";
    raw_misses("user_agent", raw, "sqlmap");
    let forms = build("GET", "/", "", raw, None);
    assert!(
        forms.matches(PatternType::UserAgent, "sqlmap"),
        "the NFKC fold generation must expose sqlmap"
    );
    // The uppercase spelling of the SAME request matches too: the
    // lowering sits between the forms and the contains verdict.
    let forms = build("GET", "/", "", "ＳＱＬＭＡＰ/1.0", None);
    assert!(forms.matches(PatternType::UserAgent, "sqlmap"));
}

#[test]
fn fidelity_query_plus_signs_normalize_to_spaces_before_matching() {
    // Consumer anchor: query forms are built from
    // `query.replace('+', " ")` (HeadMatchForms::build).
    let raw = "id=1+union+select+password";
    raw_misses("query", raw, "union select");
    let forms = build("GET", "/search", raw, "ua", None);
    assert!(
        forms.matches(PatternType::QueryString, "union select"),
        "the '+' normalization must run before form building"
    );
}

#[test]
fn fidelity_double_percent_decoding_exposes_the_traversal() {
    // Consumer anchor: `waf_match_forms` stacks up to 3 decode
    // generations; `%252e%252e%252f` only reaches `../` at generation
    // 2 — a matcher that decoded once would miss it.
    let raw = "/backup/%252e%252e%252fwp-config.php";
    raw_misses("path", raw, "../wp-config.php");
    let forms = build("GET", raw, "", "ua", None);
    assert!(
        forms.matches(PatternType::RequestUri, "../wp-config.php"),
        "the second decode generation must expose ../"
    );
    // Single-decode control: `%2e%2e%2f` reaches `../` at generation 1.
    let single = "/backup/%2e%2e%2fwp-config.php";
    raw_misses("path", single, "../wp-config.php");
    let forms = build("GET", single, "", "ua", None);
    assert!(forms.matches(PatternType::RequestUri, "../wp-config.php"));
}

#[test]
fn fidelity_nfkc_after_decode_exposes_encoded_fullwidth_delimiters() {
    // Consumer anchor: each decode pass is followed by an NFKC fold
    // that may expose the pattern the decode alone did not
    // (`fold_unicode` after `percent_decode_path`). Percent-encoded
    // FULLWIDTH FULL STOP (U+FF0E) decodes to `。。`, which only folds
    // to `..` after the decode.
    let raw = "/uploads/%EF%BC%8E%EF%BC%8E/private.tar";
    raw_misses("path", raw, "/uploads/../");
    let forms = build("GET", raw, "", "ua", None);
    assert!(
        forms.matches(PatternType::RequestUri, "/uploads/../"),
        "the decode-then-NFKC generation must expose ../"
    );
}

#[test]
fn fidelity_pattern_type_selects_its_own_field_only() {
    // The consumer matches each pattern_type against exactly its
    // field's forms (matches_lowered's field table). The same string
    // appearing elsewhere must not decide a different field's rule.
    let forms = build(
        "POST",
        "/api/search",
        "?method=get&token=sqlmap",
        "chrome",
        None,
    );
    // `get` appears in the QUERY but the method is POST.
    assert!(!forms.matches(PatternType::RequestMethod, "get"));
    assert!(forms.matches(PatternType::RequestMethod, "post"));
    // `sqlmap` appears in the QUERY and the UA field is clean.
    assert!(!forms.matches(PatternType::UserAgent, "sqlmap"));
    // A body rule sees ONLY the body: the same payload in the body
    // matches, in the query it does not.
    assert!(!forms.matches(PatternType::RequestBody, "sqlmap"));
    let with_body = build(
        "POST",
        "/api/search",
        "?q=sqlmap",
        "chrome",
        Some("note=sqlmap was here"),
    );
    assert!(with_body.matches(PatternType::RequestBody, "sqlmap"));
    assert!(
        !with_body.matches(PatternType::QueryString, "sqlmap was here"),
        "body forms never feed the query field"
    );
}

#[test]
fn fidelity_body_forms_are_the_lowercase_seed_plus_plus_normalized_forms() {
    // Consumer anchor: body forms = [body.to_ascii_lowercase()] ∪
    // lowered `waf_match_forms(&body.replace('+', " "))`
    // (config-model/src/waf.rs:444-450).
    let body = "x=1+UNION+SELECT+password";
    // The '+'-normalized member carries this one: the seed member
    // lowers to pluses, and the union member rebuilds the string with
    // spaces before its own decode generations.
    let forms = build("POST", "/form", "", "ua", Some(body));
    assert!(forms.matches(PatternType::RequestBody, "union select"));
    // And the decode pipeline's members: an encoded payload inside the
    // body decodes too.
    let encoded = build("POST", "/form", "", "ua", Some("q=%2e%2e%2fadmin"));
    raw_misses("body", "q=%2e%2e%2fadmin", "../admin");
    assert!(encoded.matches(PatternType::RequestBody, "../admin"));
}

#[test]
fn fidelity_lowering_is_ascii_lowercase_on_every_form() {
    // Consumer anchor: every consumer form path lowers with
    // `to_ascii_lowercase` before matching. An all-caps path with an
    // encoded traversal matches its lowercase pattern.
    let forms = build("GET", "/BACKUP/%2E%2E%2FWP-CONFIG.PHP", "", "ua", None);
    assert!(forms.matches(PatternType::RequestUri, "../wp-config.php"));
}
