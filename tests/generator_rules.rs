//! D2 rules 1-4 (issue #1745 P-P1): token extraction, the
//! relation-table URI hints, PoC reference hints, and the severity
//! mapping boundaries — the generator's whole face, on fixtures.

use uldolmok_vpatch_pipeline::generator::{
    entrypoint_hint, generate_candidate_file, product_token_from_cpe, severity_of,
};
use uldolmok_vpatch_pipeline::intake::{KevEntry, NvdFacts, PocReferenceHit};
use uldolmok_vpatch_pipeline::schema::{CandidateStatus, PatternType, Provenance, Severity};

#[test]
fn product_tokens_come_from_the_cpe_vendor_product_pair() {
    // lowercase + version stripped
    assert_eq!(
        product_token_from_cpe("cpe:2.3:a:VendorCo:ProductX:9.1:*:*:*:*:*:*:*"),
        Some("vendorco:productx".to_owned())
    );
    // the part component does not change the token
    assert_eq!(
        product_token_from_cpe("cpe:2.3:o:microsoft:windows_10:1909:*:*:*:*:*:*:*"),
        Some("microsoft:windows_10".to_owned())
    );
    // non-CPE strings and incomplete spellings are rejected, not guessed
    assert_eq!(product_token_from_cpe("https://example.com/a/b"), None);
    assert_eq!(product_token_from_cpe("cpe:/a:vendor:product:1.0"), None);
    assert_eq!(product_token_from_cpe("cpe:2.3:a:vendor:"), None);
    assert_eq!(product_token_from_cpe(""), None);
}

#[test]
fn relation_table_maps_plugin_slugs_and_explicit_entries() {
    // WordPress plugin slugs (design D2 rule 2's example)
    assert_eq!(
        entrypoint_hint("elementor:elementor"),
        Some("/wp-content/plugins/elementor/".to_owned())
    );
    assert_eq!(
        entrypoint_hint("anyvendor:wp-file-manager"),
        Some("/wp-content/plugins/wp-file-manager/".to_owned())
    );
    // explicit highest-frequency server rows
    assert_eq!(
        entrypoint_hint("microsoft:exchange_server"),
        Some("/ews/".to_owned())
    );
    assert_eq!(
        entrypoint_hint("fortinet:fortios"),
        Some("/remote/logincheck".to_owned())
    );
    // unmapped tokens yield no hint
    assert_eq!(entrypoint_hint("vendorco:unmapped"), None);
    assert_eq!(entrypoint_hint("not-a-token"), None);
}

#[test]
fn generator_emits_uri_and_poc_hints_with_nvd_provenance() {
    let facts = NvdFacts {
        cvss: Some(9.8),
        cpe_criteria: vec![
            "cpe:2.3:a:elementor:elementor:3.6.0:*:*:*:*:*:*:*".to_owned(),
            // duplicate criteria must not duplicate the candidate
            "cpe:2.3:a:elementor:elementor:3.6.0:*:*:*:*:*:*:*".to_owned(),
            "cpe:2.3:a:vendorco:unmapped:1.0:*:*:*:*:*:*:*".to_owned(),
        ],
        poc_references: vec![PocReferenceHit {
            url: "https://example.org/poc".to_owned(),
            tag: "Exploit".to_owned(),
        }],
    };
    let file = generate_candidate_file("CVE-2024-0001", true, Some(&facts), None, 1_800_000_000);

    // tokens: the extraction trace keeps every mapped and unmapped token,
    // deduped, record order
    assert_eq!(
        file.tokens,
        vec!["elementor:elementor", "vendorco:unmapped"]
    );
    assert_eq!(file.cvss, Some(9.8));
    assert!(file.kev);

    // candidates: one uri hint (deduped), one poc hint; nothing for the
    // unmapped token
    assert_eq!(file.candidates.len(), 2);
    let uri = &file.candidates[0];
    assert_eq!(uri.literal, "/wp-content/plugins/elementor/");
    assert_eq!(uri.pattern_type, PatternType::RequestUri);
    assert_eq!(
        uri.provenance,
        Some(Provenance::NvdCpe {
            field: "configurations.nodes.cpeMatch.criteria".to_owned(),
            raw: "cpe:2.3:a:elementor:elementor:3.6.0:*:*:*:*:*:*:*".to_owned(),
        })
    );
    let poc = &file.candidates[1];
    assert_eq!(poc.literal, "https://example.org/poc");
    assert_eq!(
        poc.provenance,
        Some(Provenance::PocReference {
            url: "https://example.org/poc".to_owned(),
            tag: "Exploit".to_owned(),
        })
    );
    assert!(
        file.candidates
            .iter()
            .all(|candidate| candidate.status == CandidateStatus::Proposed),
        "the generator proposes; only a human approves"
    );
}

#[test]
fn kev_pair_tokens_map_with_kev_metadata_provenance() {
    let entry = KevEntry {
        cve_id: "CVE-2023-0002".to_owned(),
        vendor_project: Some("Fortinet".to_owned()),
        product: Some("FortiOS".to_owned()),
    };
    // No NVD record (fetch skipped or record absent): the KEV pair alone
    // still yields a provenanced hint.
    let file = generate_candidate_file("CVE-2023-0002", true, None, Some(&entry), 1_800_000_000);
    assert_eq!(file.tokens, vec!["fortinet:fortios"]);
    assert_eq!(file.cvss, None);
    assert_eq!(file.candidates.len(), 1);
    assert_eq!(file.candidates[0].literal, "/remote/logincheck");
    assert_eq!(
        file.candidates[0].provenance,
        Some(Provenance::KevMetadata {
            field: "vendorProject/product".to_owned(),
        })
    );
}

#[test]
fn severity_mapping_boundaries() {
    // KEV membership is critical regardless of score
    assert_eq!(severity_of(true, Some(3.1)), Severity::Critical);
    assert_eq!(severity_of(true, None), Severity::Critical);
    // CVSS >= 9.0 is critical (inclusive boundary)
    assert_eq!(severity_of(false, Some(9.0)), Severity::Critical);
    assert_eq!(severity_of(false, Some(10.0)), Severity::Critical);
    // below the line is warning, never info
    assert_eq!(severity_of(false, Some(8.9)), Severity::Warning);
    assert_eq!(severity_of(false, None), Severity::Warning);
    // the wire spellings
    assert_eq!(
        serde_json::to_string(&Severity::Critical).unwrap(),
        r#""critical""#
    );
    assert_eq!(
        serde_json::to_string(&Severity::Warning).unwrap(),
        r#""warning""#
    );
}
