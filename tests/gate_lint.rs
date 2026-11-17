//! C-P2-1 (issue #1745 P-P2): the static lint refuses EVERY violation
//! class with its own diagnostic. Each case below deviates from one
//! clean base rule in exactly one field, so the assertion is exact:
//! the single expected diagnostic, nothing else. A clean rule passes
//! with zero diagnostics, and a multi-violation rule collects them all
//! (the gate enumerates — it never ranks).

use config_model::waf_feed::{WafFeedAdvisory, WafFeedRule};
use config_model::ManagedWafPatternType;
use uldolmok_vpatch_pipeline::gate::lint::{lint_candidate_literal, lint_rule, Diagnostic};
use uldolmok_vpatch_pipeline::schema::PatternType;

fn base_rule() -> WafFeedRule {
    WafFeedRule {
        id: "vp-cve-2024-12345".to_owned(),
        name: "Elementor upload traversal".to_owned(),
        category: "cve-virtual-patch".to_owned(),
        pattern_type: ManagedWafPatternType::RequestUri,
        pattern: "wp-content/plugins/elementor/upload/".to_owned(),
        severity: "warning".to_owned(),
        description: "Detects the Elementor upload-path traversal variant.".to_owned(),
        sort_order: 0,
        advisory: None,
    }
}

fn only(rule: &WafFeedRule, expected: Diagnostic) {
    let diagnostics = lint_rule(rule);
    assert_eq!(
        diagnostics,
        vec![expected],
        "the single-deviation rule must trip exactly its own diagnostic"
    );
}

fn advisory(cve_ids: Vec<String>, references: Vec<String>, source_note: &str) -> WafFeedAdvisory {
    WafFeedAdvisory {
        cve_ids,
        cvss: None,
        affected: None,
        references,
        source_note: source_note.to_owned(),
    }
}

#[test]
fn c_p2_1_a_clean_rule_passes_with_zero_diagnostics() {
    assert!(lint_rule(&base_rule()).is_empty());
}

#[test]
fn c_p2_1_pattern_length_bounds() {
    let mut rule = base_rule();
    rule.pattern = "abc".to_owned();
    only(&rule, Diagnostic::PatternTooShort { len: 3 });

    let mut rule = base_rule();
    rule.pattern = "a".repeat(257);
    only(&rule, Diagnostic::PatternTooLong { len: 257 });

    // The bounds themselves are inclusive.
    rule.pattern = "a".repeat(256);
    assert!(lint_rule(&rule).is_empty());
}

#[test]
fn c_p2_1_pattern_spelling_is_one_lowercase_ascii_publication() {
    // Exactly one uppercase letter.
    let mut rule = base_rule();
    rule.pattern = "wp-content/plugins/elementor/editoR/".to_owned();
    only(&rule, Diagnostic::PatternNotLowerAscii);

    // Non-ASCII.
    let mut rule = base_rule();
    rule.pattern = "wp-content/plugins/elementor/editör/".to_owned();
    only(&rule, Diagnostic::PatternNotLowerAscii);
}

#[test]
fn c_p2_1_pattern_must_be_trim_canonical() {
    // §3.4 rule 2: the consumer trims; signed bytes must already be
    // trimmed (and a padded seed duplicate must not evade the compare).
    let mut rule = base_rule();
    rule.pattern = "wp-content/plugins/elementor/ ".to_owned();
    only(&rule, Diagnostic::PatternNotCanonical);
}

#[test]
fn c_p2_1_pattern_control_characters_are_refused() {
    let mut rule = base_rule();
    rule.pattern = "wp-content/plugins/el\u{1}ementor/".to_owned();
    only(&rule, Diagnostic::PatternControlChar);
}

#[test]
fn c_p2_1_standalone_common_words_are_refused() {
    let mut rule = base_rule();
    rule.pattern_type = ManagedWafPatternType::RequestUri;
    rule.pattern = "error".to_owned();
    only(
        &rule,
        Diagnostic::GenericWordStandalone {
            word: "error".to_owned(),
        },
    );

    // Punctuation does not launder a standalone word.
    let mut rule = base_rule();
    rule.pattern_type = ManagedWafPatternType::RequestUri;
    rule.pattern = "admin/".to_owned();
    only(
        &rule,
        Diagnostic::GenericWordStandalone {
            word: "admin".to_owned(),
        },
    );

    // The seed's context-bound spelling passes the standalone-word ban
    // (more than one part). `union select` itself is a query_string
    // seed pair, so its remaining diagnostic is the duplicate one the
    // seed test covers; `union select password` shows the compound
    // shape fully clean.
    let mut rule = base_rule();
    rule.pattern_type = ManagedWafPatternType::QueryString;
    rule.pattern = "union select".to_owned();
    let diagnostics = lint_rule(&rule);
    assert!(!diagnostics.contains(&Diagnostic::GenericWordStandalone {
        word: "union".to_owned()
    }));

    let mut rule = base_rule();
    rule.pattern_type = ManagedWafPatternType::QueryString;
    rule.pattern = "union select password".to_owned();
    assert!(lint_rule(&rule).is_empty());
}

#[test]
fn c_p2_1_request_method_patterns_must_be_method_tokens() {
    let mut rule = base_rule();
    rule.pattern_type = ManagedWafPatternType::RequestMethod;
    rule.pattern = "/etc/passwd".to_owned();
    only(
        &rule,
        Diagnostic::MethodTokenMismatch {
            pattern: "/etc/passwd".to_owned(),
        },
    );

    // Tokens at or above the 4-byte floor pass (a sample of the RFC and
    // WebDAV classes). `get`/`put` (3 bytes) are refused by the shared
    // pattern floor — the consumer's own canonicalization enforces the
    // same WAF_FEED_MIN_PATTERN_BYTES=4 on every pattern_type, and the
    // operator method rules in the seed catalog are all 5+ byte tokens
    // (trace/track/connect). A feed rule must publish `post`-shape
    // tokens, not 3-byte ones.
    for token in ["post", "patch", "propfind", "m-search", "version-control"] {
        let mut rule = base_rule();
        rule.pattern_type = ManagedWafPatternType::RequestMethod;
        rule.pattern = token.to_owned();
        let diagnostics = lint_rule(&rule);
        assert!(
            diagnostics.is_empty(),
            "method token {token} must pass: {diagnostics:?}"
        );
    }
    let mut rule = base_rule();
    rule.pattern_type = ManagedWafPatternType::RequestMethod;
    rule.pattern = "get".to_owned();
    only(&rule, Diagnostic::PatternTooShort { len: 3 });
}

#[test]
fn c_p2_1_id_namespace_is_vp_cve() {
    let mut rule = base_rule();
    rule.id = "foo-bar".to_owned();
    only(
        &rule,
        Diagnostic::IdFormat {
            id: "foo-bar".to_owned(),
        },
    );

    // Uppercase, missing serial, empty suffix, and bad suffix chars all
    // refuse with the same code.
    for id in [
        "VP-CVE-2024-12345",
        "vp-cve-2024-",
        "vp-cve-2024-12345-",
        "vp-cve-2024-12345-Suffix",
        "vp-cve-2024-12",
    ] {
        let mut rule = base_rule();
        rule.id = id.to_owned();
        assert!(
            lint_rule(&rule).contains(&Diagnostic::IdFormat { id: id.to_owned() }),
            "id {id} must refuse"
        );
    }

    // The suffix form is legal.
    let mut rule = base_rule();
    rule.id = "vp-cve-2024-12345-variant-b".to_owned();
    assert!(lint_rule(&rule).is_empty());
}

#[test]
fn c_p2_1_reserved_categories_are_refused() {
    for category in ["api_abuse", "bola"] {
        let mut rule = base_rule();
        rule.category = category.to_owned();
        only(
            &rule,
            Diagnostic::ReservedCategory {
                category: category.to_owned(),
            },
        );
    }
    // Case or padding does not launder a reserved category.
    let mut rule = base_rule();
    rule.category = "  API_ABUSE ".to_owned();
    assert!(lint_rule(&rule).contains(&Diagnostic::ReservedCategory {
        category: "  API_ABUSE ".to_owned()
    }));

    let mut rule = base_rule();
    rule.category = String::new();
    only(&rule, Diagnostic::CategoryEmpty);
}

#[test]
fn c_p2_1_severity_vocabulary_is_critical_or_warning_only() {
    for severity in ["high", "info", "CRITICAL", ""] {
        let mut rule = base_rule();
        rule.severity = severity.to_owned();
        only(
            &rule,
            Diagnostic::SeverityVocabulary {
                severity: severity.to_owned(),
            },
        );
    }
}

#[test]
fn c_p2_1_name_and_description_must_be_present() {
    let mut rule = base_rule();
    rule.name = String::new();
    only(&rule, Diagnostic::EmptyName);

    let mut rule = base_rule();
    rule.description = "   ".to_owned();
    only(&rule, Diagnostic::EmptyDescription);
}

#[test]
fn c_p2_1_cve_ids_must_be_canonical_uppercase() {
    let mut rule = base_rule();
    rule.advisory = Some(advisory(vec!["cve-2024-1234".to_owned()], Vec::new(), ""));
    only(
        &rule,
        Diagnostic::CveIdFormat {
            cve: "cve-2024-1234".to_owned(),
        },
    );

    let mut rule = base_rule();
    rule.advisory = Some(advisory(vec!["CVE-2024-123".to_owned()], Vec::new(), ""));
    only(
        &rule,
        Diagnostic::CveIdFormat {
            cve: "CVE-2024-123".to_owned(),
        },
    );
}

#[test]
fn c_p2_1_references_must_be_https() {
    let mut rule = base_rule();
    rule.advisory = Some(advisory(
        Vec::new(),
        vec!["http://example.org/advisory".to_owned()],
        "",
    ));
    only(
        &rule,
        Diagnostic::ReferenceScheme {
            reference: "http://example.org/advisory".to_owned(),
        },
    );
}

#[test]
fn c_p2_1_advisory_re_serialization_ceiling() {
    let mut rule = base_rule();
    rule.advisory = Some(advisory(
        vec!["CVE-2024-1234".to_owned()],
        vec![format!("https://example.org/{}", "a".repeat(2020))],
        "",
    ));
    let bytes = serde_json::to_vec(rule.advisory.as_ref().unwrap()).unwrap();
    assert!(bytes.len() > 2048, "fixture must exceed the ceiling");
    only(&rule, Diagnostic::AdvisoryTooLarge { bytes: bytes.len() });
}

#[test]
fn c_p2_1_source_note_ceiling() {
    let mut rule = base_rule();
    rule.advisory = Some(advisory(Vec::new(), Vec::new(), &"x".repeat(257)));
    only(&rule, Diagnostic::SourceNoteTooLong { bytes: 257 });
}

#[test]
fn c_p2_1_seed_duplicates_are_refused_via_the_codec_blocklist() {
    // Real seed entries (consumed from `seed_blocklist()`, NOT a local
    // seed source): the task's example pair and a query_string one.
    let mut rule = base_rule();
    rule.pattern_type = ManagedWafPatternType::RequestUri;
    rule.pattern = ".env".to_owned();
    only(
        &rule,
        Diagnostic::SeedDuplicate {
            pattern_type: "request_uri".to_owned(),
            pattern: ".env".to_owned(),
        },
    );

    let mut rule = base_rule();
    rule.pattern_type = ManagedWafPatternType::UserAgent;
    rule.pattern = "sqlmap".to_owned();
    only(
        &rule,
        Diagnostic::SeedDuplicate {
            pattern_type: "user_agent".to_owned(),
            pattern: "sqlmap".to_owned(),
        },
    );

    // A method-token pattern that collides with a seed is still a seed
    // duplicate (the whitelist and the blocklist are different gates).
    let mut rule = base_rule();
    rule.pattern_type = ManagedWafPatternType::RequestMethod;
    rule.pattern = "trace".to_owned();
    assert!(lint_rule(&rule).contains(&Diagnostic::SeedDuplicate {
        pattern_type: "request_method".to_owned(),
        pattern: "trace".to_owned(),
    }));
}

#[test]
fn c_p2_1_a_multi_violation_rule_collects_every_diagnostic() {
    let mut rule = base_rule();
    rule.id = "bad-id".to_owned();
    rule.category = "bola".to_owned();
    rule.severity = "high".to_owned();
    rule.pattern = "select".to_owned();
    let diagnostics = lint_rule(&rule);
    for expected in [
        Diagnostic::IdFormat {
            id: "bad-id".to_owned(),
        },
        Diagnostic::ReservedCategory {
            category: "bola".to_owned(),
        },
        Diagnostic::SeverityVocabulary {
            severity: "high".to_owned(),
        },
        Diagnostic::GenericWordStandalone {
            word: "select".to_owned(),
        },
    ] {
        assert!(
            diagnostics.contains(&expected),
            "every violation gets its own diagnostic: missing {expected:?} in {diagnostics:?}"
        );
    }
}

#[test]
fn c_p2_1_candidate_literals_lint_through_the_same_core() {
    // An approvable candidate whose literal is a standalone word fails
    // the same core lint (approval-PR qualification).
    let diagnostics = lint_candidate_literal("error", PatternType::RequestUri);
    assert_eq!(
        diagnostics,
        vec![Diagnostic::GenericWordStandalone {
            word: "error".to_owned()
        }]
    );
    assert!(
        lint_candidate_literal("/wp-content/plugins/elementor/", PatternType::RequestUri)
            .is_empty()
    );
    // A method-pattern candidate still needs a method token.
    assert_eq!(
        lint_candidate_literal("/etc/passwd", PatternType::RequestMethod),
        vec![Diagnostic::MethodTokenMismatch {
            pattern: "/etc/passwd".to_owned()
        }]
    );
}
