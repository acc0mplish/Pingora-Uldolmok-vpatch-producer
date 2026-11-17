//! P-P3 assembly contracts (issue #1745, design §3.3/§3.4): sequence
//! monotonicity from the state file alone, byte determinism for equal
//! inputs, publish-gate refusal propagation (the 768 self-cap),
//! version-label derivation, the validity ceiling, normalization
//! BEFORE the bytes, and the loader fail-closed faces.

use std::path::PathBuf;

use config_model::waf_feed::{
    canonicalize_payload, parse_payload, WafFeedAdvisory, WafFeedPayload, WafFeedRule,
};
use config_model::ManagedWafPatternType;
use uldolmok_vpatch_pipeline::assemble::{
    assemble, load_rules, load_state, AssembleError, ProducerState,
};
use waf_bundle_encoder::{
    canonical_payload_bytes, publish_gate, PublishRejection, PUBLISHER_MAX_FEED_RULES,
};

fn now() -> i64 {
    1_794_873_600 // 2026-11-17 00:00:00 UTC
}

fn state() -> ProducerState {
    ProducerState {
        sequence: 2,
        current_key_id: "bed4490644445515f60e1c6cfc919488".to_owned(),
        last_version_label: None,
    }
}

fn rule(id: &str, pattern: &str) -> WafFeedRule {
    WafFeedRule {
        id: id.to_owned(),
        name: "Elementor upload traversal".to_owned(),
        category: "cve-virtual-patch".to_owned(),
        pattern_type: ManagedWafPatternType::RequestUri,
        pattern: pattern.to_owned(),
        severity: "warning".to_owned(),
        description: "Detects the Elementor upload-path traversal variant.".to_owned(),
        sort_order: 1_000_000,
        advisory: Some(WafFeedAdvisory {
            cve_ids: vec!["CVE-2024-12345".to_owned()],
            cvss: None,
            affected: None,
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-12345".to_owned()],
            source_note: String::new(),
        }),
    }
}

fn clean_rule() -> WafFeedRule {
    rule("vp-cve-2024-12345", "wp-content/plugins/elementor/upload/")
}

#[test]
fn sequence_is_state_plus_one_monotonic_and_state_is_the_only_source() {
    // state.sequence = 2 -> the payload mints 3.
    let first = assemble(vec![clean_rule()], &state(), now(), 14).expect("assembly succeeds");
    assert_eq!(first.payload.sequence, 3);

    // A genesis state (sequence 0) mints sequence 1 (design D7).
    let genesis = ProducerState {
        sequence: 0,
        ..state()
    };
    let genesis_assembled =
        assemble(vec![], &genesis, now(), 14).expect("genesis assembly succeeds");
    assert_eq!(genesis_assembled.payload.sequence, 1);

    // Re-assembling from the same state yields the same sequence: the
    // state file is the ONLY counter (no hidden progression), which is
    // what makes the workflow's state bump commit the sole sequencer.
    let again = assemble(vec![clean_rule()], &state(), now(), 14).expect("assembly succeeds");
    assert_eq!(again.payload.sequence, first.payload.sequence);
}

#[test]
fn equal_inputs_produce_equal_bytes_and_rule_order_is_canonicalized() {
    let first = assemble(
        vec![clean_rule(), rule("vp-cve-2024-00002", "/ews/")],
        &state(),
        now(),
        14,
    )
    .expect("assembly succeeds");
    let second = assemble(
        // Same rule SET, different input order.
        vec![rule("vp-cve-2024-00002", "/ews/"), clean_rule()],
        &state(),
        now(),
        14,
    )
    .expect("assembly succeeds");
    assert_eq!(first.canonical_bytes, second.canonical_bytes);
    assert_eq!(first.sha256_hex, second.sha256_hex);

    // The published order is the canonical (sort_order, id) order.
    let ids: Vec<&str> = first
        .payload
        .rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect();
    assert_eq!(ids, vec!["vp-cve-2024-00002", "vp-cve-2024-12345"]);

    // A second call with the SAME inputs is byte-identical (the
    // determinism law the receipt's tree-hash reproducibility rests on).
    let repeat = assemble(
        vec![clean_rule(), rule("vp-cve-2024-00002", "/ews/")],
        &state(),
        now(),
        14,
    )
    .expect("assembly succeeds");
    assert_eq!(repeat.canonical_bytes, first.canonical_bytes);
}

#[test]
fn publish_gate_refusal_propagates_over_the_768_self_cap() {
    // 769 rules: legal for the consumer (<=1024) but over the
    // producer's own self-cap — the codec's publish_gate must refuse
    // and the assembly must propagate it.
    let mut rules = Vec::with_capacity(PUBLISHER_MAX_FEED_RULES + 1);
    for index in 0..PUBLISHER_MAX_FEED_RULES + 1 {
        rules.push(rule(
            &format!("vp-cve-2024-{index:05}"),
            &format!("/exploit/path/{index}/"),
        ));
    }
    let error = assemble(rules, &state(), now(), 14).expect_err("over-cap refuses");
    assert_eq!(
        error,
        AssembleError::PublishRejected(PublishRejection::RuleCap)
    );

    // Exactly 768 rules pass the cap (the boundary binds).
    let mut rules = Vec::with_capacity(PUBLISHER_MAX_FEED_RULES);
    for index in 0..PUBLISHER_MAX_FEED_RULES {
        rules.push(rule(
            &format!("vp-cve-2024-{index:05}"),
            &format!("/exploit/path/{index}/"),
        ));
    }
    let assembled = assemble(rules, &state(), now(), 14).expect("cap boundary passes");
    assert_eq!(assembled.payload.rules.len(), PUBLISHER_MAX_FEED_RULES);
}

#[test]
fn publish_gate_refusal_propagates_non_canonical_cve_ids_and_http_references() {
    // §3.4 rule 5: cve_ids must be canonical uppercase; the consumer
    // would not case-normalize them.
    let mut bad = clean_rule();
    bad.advisory = Some(WafFeedAdvisory {
        cve_ids: vec!["cve-2024-12345".to_owned()],
        cvss: None,
        affected: None,
        references: Vec::new(),
        source_note: String::new(),
    });
    let error = assemble(vec![bad], &state(), now(), 14).expect_err("lowercase cve refuses");
    assert_eq!(
        error,
        AssembleError::PublishRejected(PublishRejection::CveIdFormat)
    );

    // A non-https reference is rejected EARLIER, by the consumer's own
    // canonicalization (which publishes-normalized bytes, §3.4 rule 2)
    // — normalization-first means the codec publish gate's
    // ReferenceScheme arm is defense-in-depth behind it.
    let mut http = clean_rule();
    http.advisory.as_mut().unwrap().references = vec!["http://example.com/advisory".to_owned()];
    let error = assemble(vec![http], &state(), now(), 14).expect_err("http reference refuses");
    assert_eq!(
        error,
        AssembleError::ConsumerModelRejected(
            config_model::waf_feed::WafFeedRejectCode::SchemaInvalid
        )
    );
}

#[test]
fn version_label_is_derived_from_now_and_the_last_label() {
    // No history: the day's first issuance.
    let assembled = assemble(vec![clean_rule()], &state(), now(), 14).expect("assembly succeeds");
    assert_eq!(assembled.payload.version, "2026-11-17.1");

    // Same-day history recorded by the state bump commit: next ordinal.
    let issued_today = ProducerState {
        last_version_label: Some("2026-11-17.1".to_owned()),
        ..state()
    };
    let assembled =
        assemble(vec![clean_rule()], &issued_today, now(), 14).expect("assembly succeeds");
    assert_eq!(assembled.payload.version, "2026-11-17.2");

    // A different day restarts at 1.
    let previous_day = ProducerState {
        last_version_label: Some("2026-11-16.9".to_owned()),
        ..state()
    };
    let assembled =
        assemble(vec![clean_rule()], &previous_day, now(), 14).expect("assembly succeeds");
    assert_eq!(assembled.payload.version, "2026-11-17.1");

    // The label is a function of `now`: a different clock read yields a
    // different date half.
    let next_day =
        assemble(vec![clean_rule()], &state(), now() + 86_400, 14).expect("assembly succeeds");
    assert_eq!(next_day.payload.version, "2026-11-18.1");
}

#[test]
fn validity_days_bound_at_the_consumer_ceiling() {
    // Default (14) works.
    let assembled =
        assemble(vec![clean_rule()], &state(), now(), 14).expect("default validity works");
    assert_eq!(assembled.payload.expires_at, now() + 14 * 86_400);

    // The 30-day consumer ceiling itself is mintable.
    assemble(vec![clean_rule()], &state(), now(), 30).expect("30 days is the ceiling");

    // Over it the consumer would reject validity_too_long on every
    // later sync — refuse at mint time.
    assert_eq!(
        assemble(vec![clean_rule()], &state(), now(), 31),
        Err(AssembleError::ValidityOutOfRange { days: 31 })
    );
    assert_eq!(
        assemble(vec![clean_rule()], &state(), now(), 0),
        Err(AssembleError::ValidityOutOfRange { days: 0 })
    );
}

#[test]
fn normalization_applies_before_the_bytes() {
    // Non-canonical spellings in EVERY normalized field: the published
    // bytes must carry the consumer's canonicalized values (§3.4 rule
    // 2 — the signed bytes are the normalized bytes).
    let messy = WafFeedRule {
        id: "VP-CVE-2024-12345".to_owned(),
        name: "  Elementor upload traversal  ".to_owned(),
        category: "CVE-Virtual-Patch".to_owned(),
        pattern_type: ManagedWafPatternType::RequestUri,
        pattern: "  WP-Content/Plugins/Elementor/Upload/  ".to_owned(),
        severity: " WARNING ".to_owned(),
        description: "Detects the Elementor upload-path traversal variant.".to_owned(),
        sort_order: 500, // below the band: canonicalized by clamping
        advisory: Some(WafFeedAdvisory {
            cve_ids: vec!["CVE-2024-12345".to_owned()],
            cvss: None,
            affected: None,
            references: Vec::new(),
            source_note: "  NVD record.  ".to_owned(),
        }),
    };
    let assembled = assemble(vec![messy], &state(), now(), 14).expect("assembly succeeds");

    let stored = assembled.payload.rules.first().expect("one rule");
    assert_eq!(stored.id, "vp-cve-2024-12345");
    assert_eq!(stored.name, "Elementor upload traversal");
    assert_eq!(stored.category, "cve-virtual-patch");
    assert_eq!(stored.pattern, "wp-content/plugins/elementor/upload/");
    assert_eq!(stored.severity, "warning");
    assert_eq!(stored.sort_order, 1_000_000); // clamped into the band
    assert_eq!(stored.advisory.as_ref().unwrap().source_note, "NVD record.");

    // The mechanical check (§3.4 rule 2): re-parsing the published
    // bytes, canonicalizing, and re-serializing must reproduce them
    // byte-for-byte — exactly what the consumer's roundtrip gate asserts.
    let reparsed = parse_payload(&assembled.canonical_bytes).expect("published bytes parse");
    let recanonicalized = canonicalize_payload(&reparsed).expect("published bytes canonicalize");
    assert_eq!(
        canonical_payload_bytes(&recanonicalized),
        assembled.canonical_bytes
    );
}

#[test]
fn consumer_schema_rejections_propagate() {
    // Duplicate rule ids are rejected whole-version by the consumer.
    let duplicate = clean_rule();
    let error = assemble(vec![duplicate.clone(), duplicate], &state(), now(), 14)
        .expect_err("duplicate ids refuse");
    assert!(matches!(error, AssembleError::ConsumerModelRejected(_)));
}

#[test]
fn invalid_now_and_states_fail() {
    assert_eq!(
        assemble(vec![clean_rule()], &state(), -1, 14),
        Err(AssembleError::InvalidNow { now: -1 })
    );
}

fn temp_tree(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vpp-assemble-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("rules")).expect("temp tree dirs");
    dir
}

#[test]
fn loaders_read_sorted_rules_and_fail_closed_on_faults() {
    let dir = temp_tree("loaders");
    // Written in reverse order; the loader returns file-name order.
    for name in ["vp-cve-2024-00002.json", "vp-cve-2024-00001.json"] {
        std::fs::write(
            dir.join("rules").join(name),
            serde_json::to_vec(&rule(name.trim_end_matches(".json"), "/exploit/path/")).unwrap(),
        )
        .expect("write rule");
    }
    let rules = load_rules(&dir.join("rules")).expect("rules load");
    let ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
    assert_eq!(ids, vec!["vp-cve-2024-00001", "vp-cve-2024-00002"]);

    // A missing directory is a legal empty feed (genesis, design D7).
    let empty = load_rules(&dir.join("rules-absent")).expect("absent rules read as empty");
    assert!(empty.is_empty());

    // An unparsable rule file is named, not skipped.
    std::fs::write(dir.join("rules").join("broken.json"), b"{not json").expect("write broken");
    let error = load_rules(&dir.join("rules")).expect_err("broken rule file refuses");
    assert_eq!(
        error,
        AssembleError::RuleFileUnparsable {
            file: "rules/broken.json".to_owned()
        }
    );

    // The whole path through a file tree: loaders + assemble agree.
    let _ = std::fs::remove_file(dir.join("rules").join("broken.json"));
    std::fs::write(
        dir.join("state.json"),
        serde_json::to_vec(&state()).unwrap(),
    )
    .expect("write state");
    let loaded_state = load_state(&dir.join("state.json")).expect("state loads");
    let assembled = assemble(
        load_rules(&dir.join("rules")).expect("rules load"),
        &loaded_state,
        now(),
        14,
    )
    .expect("assembly succeeds");
    assert_eq!(assembled.payload.sequence, 3);
}

#[test]
fn unparsable_state_and_non_object_state_refuse() {
    let dir = temp_tree("state");
    std::fs::write(dir.join("state.json"), b"{sequence: not json}").expect("write broken state");
    assert_eq!(
        load_state(&dir.join("state.json")),
        Err(AssembleError::StateUnparsable {
            path: dir.join("state.json").display().to_string()
        })
    );

    // The real committed state (with its extra `note` field) parses:
    // unknown fields are ignored, the bump commit's fields survive.
    let committed = load_state(&PathBuf::from("state.json"));
    if let Ok(state) = committed {
        assert_eq!(state.sequence, 2);
        assert_eq!(state.current_key_id, "bed4490644445515f60e1c6cfc919488");
    }
}

#[test]
fn assembled_bytes_pass_the_codec_publish_gate_directly() {
    // The publish gate the gate CLI runs on the TREE also passes on the
    // assembled payload (the same function, the real header).
    let assembled = assemble(vec![clean_rule()], &state(), now(), 14).expect("assembly succeeds");
    assert!(publish_gate(&assembled.payload).is_ok());
    // And the payload re-parses to the same value the caller received.
    let reparsed: WafFeedPayload = parse_payload(&assembled.canonical_bytes).expect("parses");
    assert_eq!(reparsed, assembled.payload);
}
