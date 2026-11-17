//! Schema roundtrips (issue #1745 P-P1, design §3.2): the candidate
//! file and corpus request shapes serialize and re-parse field-exact,
//! the wire spellings are pinned, and CVE id canonicalization is the
//! producer's only accepted spelling.

use uldolmok_vpatch_pipeline::schema::{
    canonical_cve_id, Candidate, CandidateFile, CandidateStatus, CorpusRequest, PatternType,
    Provenance, Severity,
};

#[test]
fn candidate_file_roundtrips_every_provenance_variant() {
    let file = CandidateFile {
        cve: "CVE-2024-0001".to_owned(),
        kev: true,
        cvss: Some(9.8),
        tokens: vec![
            "elementor:elementor".to_owned(),
            "vendorco:unmapped".to_owned(),
        ],
        candidates: vec![
            Candidate {
                literal: "/wp-content/plugins/elementor/".to_owned(),
                pattern_type: PatternType::RequestUri,
                provenance: Some(Provenance::NvdCpe {
                    field: "configurations.nodes.cpeMatch.criteria".to_owned(),
                    raw: "cpe:2.3:a:elementor:elementor:3.6.0:*:*:*:*:*:*:*".to_owned(),
                }),
                status: CandidateStatus::Proposed,
            },
            Candidate {
                literal: "/package/npm/left-pad/".to_owned(),
                pattern_type: PatternType::RequestUri,
                provenance: Some(Provenance::GhsaAffected {
                    field: "affected[].package".to_owned(),
                    raw: "npm/left-pad".to_owned(),
                }),
                status: CandidateStatus::Proposed,
            },
            Candidate {
                literal: "/ews/".to_owned(),
                pattern_type: PatternType::RequestUri,
                provenance: Some(Provenance::RelationTable {
                    product: "microsoft:exchange_server".to_owned(),
                    entrypoint: "/ews/".to_owned(),
                }),
                status: CandidateStatus::Approved,
            },
            Candidate {
                literal: "/login".to_owned(),
                pattern_type: PatternType::RequestUri,
                provenance: Some(Provenance::KevMetadata {
                    field: "vendorProject/product".to_owned(),
                }),
                status: CandidateStatus::Proposed,
            },
            Candidate {
                literal: "https://example.org/poc.py".to_owned(),
                pattern_type: PatternType::RequestUri,
                provenance: Some(Provenance::PocReference {
                    url: "https://example.org/poc.py".to_owned(),
                    tag: "Exploit".to_owned(),
                }),
                status: CandidateStatus::Proposed,
            },
            Candidate {
                literal: "/curator-added/endpoint/".to_owned(),
                pattern_type: PatternType::QueryString,
                provenance: Some(Provenance::Manual),
                status: CandidateStatus::Proposed,
            },
            Candidate {
                literal: "originless".to_owned(),
                pattern_type: PatternType::RequestBody,
                provenance: None,
                status: CandidateStatus::ExcludedNoProvenance,
            },
        ],
        generated_at: 1_800_000_000,
    };

    let serialized = serde_json::to_string(&file).expect("the file serializes");
    // field order fixed by the declaration order (interface schema):
    // cve → kev → cvss → tokens[] → candidates[] → generated_at
    assert!(
        serialized.starts_with(
            r#"{"cve":"CVE-2024-0001","kev":true,"cvss":9.8,"tokens":["elementor:elementor","vendorco:unmapped"],"candidates":"#
        ),
        "the file header field order is part of the schema: {serialized}"
    );
    assert!(
        serialized.ends_with(r#"],"generated_at":1800000000}"#),
        "generated_at closes the file in schema order: {serialized}"
    );
    // every open-enum provenance kind keeps its wire tag
    for kind in [
        r#""kind":"nvd_cpe""#,
        r#""kind":"ghsa_affected""#,
        r#""kind":"relation_table""#,
        r#""kind":"kev_metadata""#,
        r#""kind":"poc_reference""#,
        r#""kind":"manual""#,
    ] {
        assert!(serialized.contains(kind), "missing wire tag {kind}");
    }
    // the provenance-less candidate carries no provenance key
    assert!(serialized.contains(r#""status":"excluded_no_provenance""#));

    let parsed: CandidateFile =
        serde_json::from_str(&serialized).expect("the stored file parses back");
    assert_eq!(parsed, file, "roundtrip must preserve every field");
    assert_eq!(parsed.approvable().count(), 5);
}

#[test]
fn wire_spellings_are_pinned() {
    assert_eq!(
        serde_json::to_string(&PatternType::RequestUri).unwrap(),
        r#""request_uri""#
    );
    assert_eq!(
        serde_json::to_string(&PatternType::QueryString).unwrap(),
        r#""query_string""#
    );
    assert_eq!(
        serde_json::to_string(&PatternType::UserAgent).unwrap(),
        r#""user_agent""#
    );
    assert_eq!(
        serde_json::to_string(&PatternType::RequestMethod).unwrap(),
        r#""request_method""#
    );
    assert_eq!(
        serde_json::to_string(&PatternType::RequestBody).unwrap(),
        r#""request_body""#
    );
    assert_eq!(
        serde_json::to_string(&CandidateStatus::ExcludedNoProvenance).unwrap(),
        r#""excluded_no_provenance""#
    );
    assert_eq!(
        serde_json::to_string(&Severity::Critical).unwrap(),
        r#""critical""#
    );
    let provenance: Provenance =
        serde_json::from_str(r#"{"kind":"manual"}"#).expect("the minimal variant parses");
    assert_eq!(provenance, Provenance::Manual);
}

#[test]
fn corpus_request_roundtrips_with_and_without_a_body() {
    let with_body = CorpusRequest {
        method: "POST".to_owned(),
        path: "/wp-content/plugins/elementor/".to_owned(),
        query: "a=1".to_owned(),
        user_agent: "probe/1.0".to_owned(),
        body: Some("payload=1".to_owned()),
    };
    let serialized = serde_json::to_string(&with_body).expect("serializes");
    assert!(serialized.contains(r#""body":"payload=1""#));
    let parsed: CorpusRequest = serde_json::from_str(&serialized).expect("parses back");
    assert_eq!(parsed, with_body);

    let without_body: CorpusRequest = serde_json::from_str(
        r#"{"method":"GET","path":"/ews/","query":"","user_agent":"probe/1.0"}"#,
    )
    .expect("a body-less request deserializes");
    assert_eq!(without_body.body, None);
    assert_eq!(
        serde_json::to_string(&without_body).unwrap(),
        r#"{"method":"GET","path":"/ews/","query":"","user_agent":"probe/1.0"}"#
    );
}

#[test]
fn canonical_cve_id_is_the_only_accepted_spelling() {
    assert_eq!(
        canonical_cve_id(" cve-2024-1234 "),
        Some("CVE-2024-1234".to_owned())
    );
    assert_eq!(
        canonical_cve_id("CVE-2024-12345"),
        Some("CVE-2024-12345".to_owned())
    );
    assert_eq!(
        canonical_cve_id("CVE-2024-1234567"),
        Some("CVE-2024-1234567".to_owned())
    );
    // serial too short / too long
    assert_eq!(canonical_cve_id("CVE-2024-123"), None);
    assert_eq!(canonical_cve_id("CVE-2024-12345678"), None);
    // malformed headers
    assert_eq!(canonical_cve_id("CVE-24-1234"), None);
    assert_eq!(canonical_cve_id("2024-1234"), None);
    assert_eq!(canonical_cve_id("notacve"), None);
    assert_eq!(canonical_cve_id(""), None);
}
