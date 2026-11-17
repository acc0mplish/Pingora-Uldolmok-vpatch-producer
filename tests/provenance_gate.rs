//! C-P1-1 (issue #1745): every candidate in a `candidates/*.json` file
//! carries a provenance, and provenance-less candidates are excluded
//! from the approval target. The tests below frame the FAILURE case
//! explicitly: if the pipeline ever let a source-less literal through,
//! the approvable enumeration would include it and these assertions
//! would go red.

use uldolmok_vpatch_pipeline::generator::generate_candidate_file;
use uldolmok_vpatch_pipeline::intake::{NvdFacts, PocReferenceHit};
use uldolmok_vpatch_pipeline::schema::{
    Candidate, CandidateFile, CandidateStatus, PatternType, Provenance,
};

const ELEMENTOR_CRITERIA: &str = "cpe:2.3:a:elementor:elementor:3.6.0:*:*:*:*:*:*:*";
const POC_URL: &str = "https://example.org/poc";

fn elementor_facts() -> NvdFacts {
    NvdFacts {
        cvss: Some(9.8),
        cpe_criteria: vec![ELEMENTOR_CRITERIA.to_owned()],
        poc_references: vec![PocReferenceHit {
            url: POC_URL.to_owned(),
            tag: "Exploit".to_owned(),
        }],
    }
}

#[test]
fn generated_files_carry_provenance_on_every_candidate() {
    let mut file = generate_candidate_file(
        "CVE-2024-0001",
        true,
        Some(&elementor_facts()),
        None,
        1_800_000_000,
    );
    assert!(
        file.candidates.len() >= 2,
        "fixture must yield both a uri hint and a poc hint"
    );
    assert!(
        file.candidates
            .iter()
            .all(|candidate| candidate.provenance.is_some()),
        "the generator never emits a provenance-less candidate"
    );
    assert_eq!(
        file.enforce_provenance(),
        0,
        "enforcement is a no-op on generated files"
    );
}

#[test]
fn c_p1_1_provenance_less_candidates_are_excluded_from_approval() {
    let mut file = generate_candidate_file(
        "CVE-2024-0001",
        false,
        Some(&elementor_facts()),
        None,
        1_800_000_000,
    );
    let generated_count = file.candidates.len();
    // Inject the failure modes the way an external edit or a buggy
    // producer would: a proposed literal with no origin, and a worse
    // one already marked approved.
    file.candidates.push(Candidate {
        literal: "injected-without-origin".to_owned(),
        pattern_type: PatternType::RequestUri,
        provenance: None,
        status: CandidateStatus::Proposed,
    });
    file.candidates.push(Candidate {
        literal: "approved-without-origin".to_owned(),
        pattern_type: PatternType::UserAgent,
        provenance: None,
        status: CandidateStatus::Approved,
    });

    // Before enforcement nothing stops a hand-set approved status on a
    // provenance-less candidate — enforcement must catch both.
    let flipped = file.enforce_provenance();
    assert_eq!(flipped, 2, "both provenance-less candidates must flip");
    for candidate in file.candidates.iter().filter(|c| c.provenance.is_none()) {
        assert_eq!(candidate.status, CandidateStatus::ExcludedNoProvenance);
    }

    // The approval target contains ONLY provenanced proposed candidates.
    let approvable: Vec<&Candidate> = file.approvable().collect();
    assert_eq!(approvable.len(), generated_count);
    assert!(
        approvable
            .iter()
            .all(|c| c.provenance.is_some() && c.status == CandidateStatus::Proposed),
        "approvable enumeration must filter provenance and status together"
    );
    // The direct exclusion assertions: neither injected literal is
    // approvable — this is where a broken pipeline would go red.
    assert!(
        !approvable
            .iter()
            .any(|c| c.literal.contains("without-origin")),
        "provenance-less candidates must not survive in the approval target"
    );
}

#[test]
fn externally_edited_file_without_provenance_heals_to_excluded() {
    // A stored file whose candidate lacks a provenance key entirely
    // (the shape a hand-edited or foreign file would have): it
    // deserializes, then the pipeline excludes it — it can never enter
    // a curation PR as approvable.
    let json = r#"{
        "cve": "CVE-2024-0002",
        "kev": false,
        "cvss": null,
        "tokens": ["vendorco:productx"],
        "candidates": [
            {
                "literal": "originless-literal",
                "pattern_type": "request_uri",
                "status": "proposed"
            }
        ],
        "generated_at": 1800000000
    }"#;
    let mut file: CandidateFile =
        serde_json::from_str(json).expect("a provenance-less candidate still deserializes");
    assert_eq!(file.candidates[0].provenance, None);
    assert_eq!(file.enforce_provenance(), 1);
    assert_eq!(
        file.candidates[0].status,
        CandidateStatus::ExcludedNoProvenance
    );
    assert_eq!(file.approvable().count(), 0);
}

#[test]
fn excluded_candidates_serialize_without_a_provenance_key() {
    // The stored spelling makes the exclusion visible: excluded
    // candidates carry NO provenance key at all.
    let mut file = generate_candidate_file(
        "CVE-2024-0003",
        false,
        Some(&NvdFacts {
            cvss: None,
            cpe_criteria: vec![ELEMENTOR_CRITERIA.to_owned()],
            poc_references: Vec::new(),
        }),
        None,
        1_800_000_000,
    );
    assert!(file.enforce_provenance() == 0);
    for candidate in &mut file.candidates {
        candidate.provenance = None;
    }
    let flipped = file.enforce_provenance();
    assert!(flipped > 0);
    let serialized = serde_json::to_string(&file).expect("file serializes");
    // the quoted KEY (the status VALUE `excluded_no_provenance` contains
    // the bare word, and that visibility is exactly what we want)
    assert!(
        !serialized.contains(r#""provenance""#),
        "excluded candidates must not serialize a provenance key"
    );
    assert!(serialized.contains("excluded_no_provenance"));
}

#[test]
fn provenance_wire_shapes_survive_a_file_roundtrip() {
    let file = CandidateFile {
        cve: "CVE-2024-0004".to_owned(),
        kev: true,
        cvss: Some(9.8),
        tokens: vec!["elementor:elementor".to_owned()],
        candidates: vec![
            Candidate {
                literal: "/wp-content/plugins/elementor/".to_owned(),
                pattern_type: PatternType::RequestUri,
                provenance: Some(Provenance::NvdCpe {
                    field: "configurations.nodes.cpeMatch.criteria".to_owned(),
                    raw: ELEMENTOR_CRITERIA.to_owned(),
                }),
                status: CandidateStatus::Proposed,
            },
            Candidate {
                literal: "https://example.org/poc".to_owned(),
                pattern_type: PatternType::RequestUri,
                provenance: Some(Provenance::PocReference {
                    url: "https://example.org/poc".to_owned(),
                    tag: "Exploit".to_owned(),
                }),
                status: CandidateStatus::Proposed,
            },
        ],
        generated_at: 1_800_000_000,
    };
    let serialized = serde_json::to_string(&file).expect("serializes");
    assert!(serialized.contains(r#""kind":"nvd_cpe""#));
    assert!(serialized.contains(r#""kind":"poc_reference""#));
    let parsed: CandidateFile =
        serde_json::from_str(&serialized).expect("the stored file parses back");
    assert_eq!(parsed, file);
    assert_eq!(parsed.approvable().count(), 2);
}
