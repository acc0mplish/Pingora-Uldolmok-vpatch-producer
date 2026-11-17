//! C-P2-2 (issue #1745 P-P2): the two-way corpus gate — (a) every rule
//! needs an exploit sample that MATCHES under the consumer semantics,
//! including a percent-encoding bypass sample only a decode generation
//! detects, (b) any benign match refuses with the three-row
//! identification, (c) the 200-request benign floor binds on the
//! count, and the approval-PR qualification lint reflects in the
//! report. The final test runs the gate over the REAL tree and seals
//! the committed corpus's honesty: no benign request may contain a
//! consumer seed pattern in any of its match forms.

use std::path::PathBuf;

use uldolmok_vpatch_pipeline::gate::corpus::{run_gate, CorpusDiagnostic, BENIGN_MIN};
use uldolmok_vpatch_pipeline::gate::matcher::RequestForms;
use uldolmok_vpatch_pipeline::schema::{CorpusRequest, PatternType};

fn temp_tree(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vpp-gate-corpus-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["corpus/benign", "corpus/exploits", "rules", "candidates"] {
        std::fs::create_dir_all(dir.join(sub)).expect("temp tree dirs");
    }
    dir
}

fn write_request(path: &std::path::Path, request: &CorpusRequest) {
    std::fs::write(path, serde_json::to_vec_pretty(request).unwrap()).expect("write request");
}

fn request(method: &str, path: &str, query: &str, user_agent: &str) -> CorpusRequest {
    CorpusRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        user_agent: user_agent.to_owned(),
        body: None,
        source: Some("test fixture".to_owned()),
    }
}

fn request_with_body(
    method: &str,
    path: &str,
    query: &str,
    user_agent: &str,
    body: &str,
) -> CorpusRequest {
    let mut request = request(method, path, query, user_agent);
    request.body = Some(body.to_owned());
    request
}

fn honest_benign(index: usize) -> CorpusRequest {
    let paths = [
        "/api/v1/hosts",
        "/api/v1/backups",
        "/dashboard/overview",
        "/static/app.main.js",
        "/api/v1/reports",
    ];
    let path = paths[index % paths.len()];
    request(
        "GET",
        path,
        "page=2&per_page=50",
        "Mozilla/5.0 ops-console/1.2",
    )
}

fn fill_benign(root: &std::path::Path, count: usize) {
    for index in 0..count {
        write_request(
            &root.join(format!("corpus/benign/benign-{:03}.json", index + 1)),
            &honest_benign(index),
        );
    }
}

fn write_rule(root: &std::path::Path, id: &str, pattern_type: &str, pattern: &str) {
    // M3/M4-clean fixture: advisory with CVE ids present (§7 L4) and
    // sort_order inside the consumer's feed window.
    let rule = serde_json::json!({
        "id": id,
        "name": "Fixture rule",
        "category": "cve-virtual-patch",
        "pattern_type": pattern_type,
        "pattern": pattern,
        "severity": "warning",
        "description": "Fixture rule for the corpus gate test.",
        "sort_order": 1_000_000,
        "advisory": {"cve_ids": [cve_of(id)]}
    });
    std::fs::write(
        root.join(format!("rules/{id}.json")),
        serde_json::to_vec_pretty(&rule).unwrap(),
    )
    .expect("write rule");
}

/// The canonical CVE id a fixture rule id encodes
/// (`vp-cve-2099-00001` → `CVE-2099-00001`).
fn cve_of(id: &str) -> String {
    format!("CVE-{}", &id["vp-cve-".len()..])
}

#[test]
fn c_p2_2_a_rule_without_an_exploit_sample_is_refused() {
    let root = temp_tree("missing-sample");
    fill_benign(&root, BENIGN_MIN);
    write_rule(&root, "vp-cve-2099-00001", "request_uri", "wp-config.php");
    let report = run_gate(&root);
    assert_eq!(
        report.corpus_diagnostics,
        vec![CorpusDiagnostic::ExploitSampleMissing {
            rule_id: "vp-cve-2099-00001".to_owned()
        }],
        "a sample-less rule refuses (detection duty, design §5 2a)"
    );
}

#[test]
fn c_p2_2_a_non_matching_exploit_sample_is_refused() {
    let root = temp_tree("no-match-sample");
    fill_benign(&root, BENIGN_MIN);
    write_rule(&root, "vp-cve-2099-00002", "request_uri", "wp-config.php");
    write_request(
        &root.join("corpus/exploits/vp-cve-2099-00002.json"),
        &request(
            "GET",
            "/wp-content/plugins/other/readme.txt",
            "",
            "curl/8.1",
        ),
    );
    let report = run_gate(&root);
    assert_eq!(
        report.corpus_diagnostics,
        vec![CorpusDiagnostic::ExploitSampleNoMatch {
            rule_id: "vp-cve-2099-00002".to_owned(),
            file: "corpus/exploits/vp-cve-2099-00002.json".to_owned(),
        }],
        "a sample the rule does not detect refuses"
    );
}

#[test]
fn c_p2_2_a_percent_encoded_bypass_sample_is_detected_through_decoding() {
    // Positive: the exploit rides `%2e%2e%2f`; the RAW path does not
    // contain the pattern — only the matcher's decode generations
    // expose it, which is exactly what makes the sample load-bearing.
    let root = temp_tree("decode-sample");
    fill_benign(&root, BENIGN_MIN);
    write_rule(
        &root,
        "vp-cve-2099-00003",
        "request_uri",
        "../wp-config.php",
    );
    let sample = request("GET", "/wp-content/%2e%2e%2fwp-config.php", "", "curl/8.1");
    assert!(
        !sample.path.contains("../wp-config.php"),
        "fixture sanity: the raw path must not contain the pattern"
    );
    assert!(
        RequestForms::build(&sample).matches(PatternType::RequestUri, "../wp-config.php"),
        "the decode generation must expose the traversal"
    );
    write_request(
        &root.join("corpus/exploits/vp-cve-2099-00003.json"),
        &sample,
    );
    let report = run_gate(&root);
    assert!(
        !report.corpus_diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            CorpusDiagnostic::ExploitSampleNoMatch { rule_id, .. }
                if rule_id == "vp-cve-2099-00003"
        )),
        "the encoded sample satisfies detection duty: {:?}",
        report.corpus_diagnostics
    );
    assert!(
        report.is_green(),
        "the whole tree is green: {:?}",
        report.corpus_diagnostics
    );
}

#[test]
fn c_p2_2_b_a_benign_match_refuses_with_three_row_identification() {
    let root = temp_tree("benign-match");
    fill_benign(&root, BENIGN_MIN);
    write_rule(&root, "vp-cve-2099-00004", "request_uri", "wp-config.php");
    write_request(
        &root.join("corpus/exploits/vp-cve-2099-00004.json"),
        &request("GET", "/wp-config.php.bak", "", "curl/8.1"),
    );
    // An honest blog request whose path happens to carry the literal:
    // the gate must name the benign file, the rule, AND that rule's
    // exploit sample.
    write_request(
        &root.join("corpus/benign/benign-201.json"),
        &request("GET", "/blog/wp-config.php", "", "Mozilla/5.0"),
    );
    let report = run_gate(&root);
    assert!(
        report
            .corpus_diagnostics
            .contains(&CorpusDiagnostic::BenignMatch {
                benign_file: "corpus/benign/benign-201.json".to_owned(),
                rule_id: "vp-cve-2099-00004".to_owned(),
                exploit_sample: "corpus/exploits/vp-cve-2099-00004.json".to_owned(),
            }),
        "the benign match names all three rows: {:?}",
        report.corpus_diagnostics
    );
    assert!(!report.is_green());
}

#[test]
fn c_p2_2_c_the_benign_floor_binds_below_200_and_releases_at_200() {
    let root = temp_tree("floor-199");
    fill_benign(&root, BENIGN_MIN - 1);
    let report = run_gate(&root);
    assert!(report
        .corpus_diagnostics
        .contains(&CorpusDiagnostic::BenignCorpusTooSmall {
            count: BENIGN_MIN - 1
        }));
    assert!(!report.is_green());

    let root = temp_tree("floor-200");
    fill_benign(&root, BENIGN_MIN);
    let report = run_gate(&root);
    assert!(
        report.is_green(),
        "200 honest requests with zero rules is a legal green tree: {:?}",
        report.corpus_diagnostics
    );
    assert_eq!(report.benign_count, BENIGN_MIN);
}

#[test]
fn c_p2_2_c_an_unparsable_benign_file_is_refused_and_drops_the_floor_count() {
    let root = temp_tree("unparsable-benign");
    // 199 valid requests plus one broken file: the file COUNT is 200,
    // but the floor counts VALID requests — 199 — so it fires.
    fill_benign(&root, BENIGN_MIN - 1);
    std::fs::write(root.join("corpus/benign/benign-999.json"), "{not json").unwrap();
    let report = run_gate(&root);
    assert!(
        report
            .corpus_diagnostics
            .contains(&CorpusDiagnostic::BenignFileUnparsable {
                file: "corpus/benign/benign-999.json".to_owned()
            }),
        "the unparsable file is named"
    );
    assert_eq!(
        report.benign_count, BENIGN_MIN,
        "the display count is files"
    );
    assert!(
        report
            .corpus_diagnostics
            .contains(&CorpusDiagnostic::BenignCorpusTooSmall {
                count: BENIGN_MIN - 1
            }),
        "the floor counts parsed requests, not files"
    );
}

#[test]
fn c_p2_2_an_unparsable_rule_file_is_refused() {
    let root = temp_tree("unparsable-rule");
    fill_benign(&root, BENIGN_MIN);
    std::fs::write(root.join("rules/broken.json"), "not a rule").unwrap();
    let report = run_gate(&root);
    assert!(report
        .corpus_diagnostics
        .contains(&CorpusDiagnostic::RuleFileUnparsable {
            file: "rules/broken.json".to_owned()
        }));
    assert!(!report.is_green());
}

#[test]
fn c_p2_2_approvable_candidate_lint_failures_are_warnings_that_fail_the_exit() {
    let root = temp_tree("candidate-lint");
    fill_benign(&root, BENIGN_MIN);
    // One approvable candidate (proposed + provenance) whose literal
    // cannot pass the literal lint.
    let candidate_file = serde_json::json!({
        "cve": "CVE-2024-9999",
        "kev": false,
        "cvss": null,
        "tokens": ["vendorco:productx"],
        "candidates": [
            {
                "literal": "error",
                "pattern_type": "request_uri",
                "provenance": {"kind": "manual"},
                "status": "proposed"
            },
            {
                "literal": "/wp-content/plugins/elementor/",
                "pattern_type": "request_uri",
                "provenance": {"kind": "manual"},
                "status": "proposed"
            }
        ],
        "generated_at": 1_800_000_000
    });
    std::fs::write(
        root.join("candidates/CVE-2024-9999.json"),
        serde_json::to_vec_pretty(&candidate_file).unwrap(),
    )
    .unwrap();
    let report = run_gate(&root);
    assert_eq!(report.candidate_warnings.len(), 1);
    let warning = &report.candidate_warnings[0];
    assert_eq!(warning.file, "candidates/CVE-2024-9999.json");
    assert_eq!(warning.literal, "error");
    assert_eq!(warning.diagnostics.len(), 1);
    assert!(
        !report.is_green(),
        "an approvable lint failure fails the exit"
    );
}

#[test]
fn an_unparsable_exploit_sample_is_named_not_called_missing() {
    // L1: a PRESENT but broken sample is a different failure from an
    // absent one — the file is named.
    let root = temp_tree("unparsable-exploit");
    fill_benign(&root, BENIGN_MIN);
    write_rule(&root, "vp-cve-2099-00005", "request_uri", "wp-config.php");
    std::fs::write(root.join("corpus/exploits/vp-cve-2099-00005.json"), "{oops").unwrap();
    let report = run_gate(&root);
    assert_eq!(
        report.corpus_diagnostics,
        vec![CorpusDiagnostic::ExploitSampleUnparsable {
            rule_id: "vp-cve-2099-00005".to_owned(),
            file: "corpus/exploits/vp-cve-2099-00005.json".to_owned(),
        }],
        "the unparsable sample is distinguished from a missing one"
    );
}

#[test]
fn an_unparsable_candidate_file_is_named_not_skipped() {
    // L2: a candidates/*.json file that does not parse is reported —
    // its approvable candidates silently escaping qualification is
    // exactly the gap the file naming closes.
    let root = temp_tree("unparsable-candidate");
    fill_benign(&root, BENIGN_MIN);
    std::fs::write(root.join("candidates/broken.json"), "not candidates").unwrap();
    let report = run_gate(&root);
    assert!(
        report
            .corpus_diagnostics
            .contains(&CorpusDiagnostic::CandidateFileUnparsable {
                file: "candidates/broken.json".to_owned()
            }),
        "the unparsable candidate file is named: {:?}",
        report.corpus_diagnostics
    );
    assert!(!report.is_green());
}

#[test]
fn an_oversized_exploit_body_is_a_no_match_like_the_consumer() {
    // M2: the consumer's body phase answers Oversize before any rule
    // comparison past 1 MiB — an oversized sample must be a NO-MATCH
    // here too, or the sample would prove detection duty the consumer
    // cannot deliver. The same body just under the ceiling matches.
    let pattern = "union select password";
    let under = format!("x=1 {} y=2", pattern);
    let forms = RequestForms::build(&request_with_body("POST", "/form", "", "ua", &under));
    assert!(forms.matches(PatternType::RequestBody, pattern));

    let mut oversized = request_with_body("POST", "/form", "", "ua", &under);
    let padding = "a".repeat(1024 * 1024 + 1000 - oversized.body.as_ref().unwrap().len());
    oversized.body = Some(format!("{}{}", oversized.body.unwrap(), padding));
    assert!(oversized.body.as_ref().unwrap().len() > 1024 * 1024);
    assert!(
        oversized.body.as_ref().unwrap().contains(pattern),
        "fixture sanity: the oversized body still carries the pattern"
    );
    assert!(
        !RequestForms::build(&oversized).matches(PatternType::RequestBody, pattern),
        "past the inspection ceiling the consumer never matches"
    );

    // And the full gate refuses the oversized sample as no-match.
    let root = temp_tree("oversize-exploit");
    fill_benign(&root, BENIGN_MIN);
    let rule = serde_json::json!({
        "id": "vp-cve-2099-00006",
        "name": "Oversize body fixture",
        "category": "cve-virtual-patch",
        "pattern_type": "request_body",
        "pattern": pattern,
        "severity": "warning",
        "description": "Fixture rule for the oversized body mirror.",
        "sort_order": 1_000_000,
        "advisory": {"cve_ids": ["CVE-2099-00006"]}
    });
    std::fs::write(
        root.join("rules/vp-cve-2099-00006.json"),
        serde_json::to_vec_pretty(&rule).unwrap(),
    )
    .unwrap();
    write_request(
        &root.join("corpus/exploits/vp-cve-2099-00006.json"),
        &oversized,
    );
    let report = run_gate(&root);
    assert!(
        report
            .corpus_diagnostics
            .contains(&CorpusDiagnostic::ExploitSampleNoMatch {
                rule_id: "vp-cve-2099-00006".to_owned(),
                file: "corpus/exploits/vp-cve-2099-00006.json".to_owned(),
            }),
        "the oversized sample cannot evidence detection duty: {:?}",
        report.corpus_diagnostics
    );
}

#[test]
fn the_committed_corpus_is_honest_and_meets_the_floor() {
    // The landing gate over the REAL tree: zero rules (no curation PR
    // has landed yet), the committed benign corpus at or above the
    // floor, everything green. The honesty seal is enforced INSIDE
    // run_gate (L3): green here already proves no committed benign
    // request contains a consumer seed pattern in any match form —
    // a violation would surface as `benign_seed_violation`.
    let report = run_gate(std::path::Path::new("."));
    assert!(
        report.is_green(),
        "the committed tree must pass its own gate: {:?} / {:?}",
        report.rule_diagnostics,
        report.corpus_diagnostics
    );
    assert!(
        !report
            .corpus_diagnostics
            .contains(&CorpusDiagnostic::BenignCorpusTooSmall {
                count: report.benign_count
            }),
        "the committed corpus meets the design §5 floor"
    );
    assert!(
        report.benign_count >= BENIGN_MIN,
        "the committed corpus meets the design §5 floor (L3)"
    );
    assert!(
        !report
            .corpus_diagnostics
            .iter()
            .any(|diagnostic| matches!(diagnostic, CorpusDiagnostic::BenignSeedViolation { .. })),
        "the gate-enforced honesty seal is green over the committed corpus"
    );
}
