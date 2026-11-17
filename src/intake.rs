//! KEV/NVD intake (issue #1745 P-P1, design D2): an independent copy of
//! the consumer metadata worker's upstream conventions — the CISA KEV
//! single-file catalog and the NVD CVE API 2.0 per-CVE endpoint, the
//! whole-request 30-second deadline and 16 MiB ceiling — deliberately
//! NOT a shared dependency (the consumer's worker stays untouched, C8).
//!
//! Two seams keep this network-free to test: the [`Fetcher`] trait
//! carries the HTTP transport (tests inject fixture bytes), and every
//! budget wait flows through the injected
//! [`UvpbClock`](crate::clock::UvpbClock). Responses are parsed with
//! `serde_json::Value` down to the minimum the candidate pipeline needs
//! — CVE ids, best CVSS score, CPE criteria strings, PoC-tagged
//! references — never a full CVE record model (design D2: dependency
//! leanness).

use crate::budget::{AdmitDecision, Origin, RateBudgets, DAILY_BUDGET};
use crate::clock::UvpbClock;
use serde_json::Value;
use std::time::Duration;

/// The CISA KEV catalog (the single-file URL the consumer metadata
/// worker uses).
pub const KEV_CATALOG_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
/// The NVD CVE API 2.0 single-CVE endpoint prefix (the `cveId=` form).
pub const NVD_CVE_API_PREFIX: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=";
/// The fetch user agent — the consumer's UA shape with the producer's
/// own face.
pub const USER_AGENT: &str = "Uldolmok/0.1 vpatch-intake";
/// The whole-request deadline (the consumer metadata worker's 30 s
/// wrap: connect + headers + body).
pub const FETCH_TOTAL_TIMEOUT_SECS: u64 = 30;
/// The response ceiling (the consumer's one generous 16 MiB cap that
/// fits the KEV catalog's growth).
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Sanity bound on CPE criteria collected from one CVE record.
const MAX_CPE_CRITERIA: usize = 128;
/// Walk depth bound for the defensive `cpeMatch` collector.
const CPE_WALK_MAX_DEPTH: usize = 12;

/// One KEV catalog entry, narrowed to what the candidate pipeline
/// consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevEntry {
    pub cve_id: String,
    pub vendor_project: Option<String>,
    pub product: Option<String>,
}

impl KevEntry {
    /// The lowercase `vendor:product` token (empty halves skipped) —
    /// the KEV-side twin of the CPE-derived token.
    pub fn product_token(&self) -> Option<String> {
        let vendor = self.vendor_project.as_deref()?.trim().to_ascii_lowercase();
        let product = self.product.as_deref()?.trim().to_ascii_lowercase();
        if vendor.is_empty() || product.is_empty() {
            return None;
        }
        Some(format!("{vendor}:{product}"))
    }
}

/// A reference whose tags mark it PoC/exploit-ish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocReferenceHit {
    pub url: String,
    pub tag: String,
}

/// The narrowed facts one NVD CVE record contributes to the generator.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NvdFacts {
    /// The best `baseScore` across the record's CVSS metric entries.
    pub cvss: Option<f64>,
    /// Every `criteria` string under the record's configurations.
    pub cpe_criteria: Vec<String>,
    /// PoC/exploit-tagged reference links (hint candidates; no network
    /// extraction in v1 — design D2 rule 3's default-off switch).
    pub poc_references: Vec<PocReferenceHit>,
}

/// Why an intake step failed. `DailyBudgetExhausted` is a designed
/// outcome (batch callers stop and report), the others are hard.
#[derive(Debug, Clone, PartialEq)]
pub enum IntakeError {
    /// A fetch failed (HTTP status, transport error, size ceiling).
    Fetch {
        origin: Origin,
        url: String,
        detail: String,
    },
    /// A response body was not the JSON shape the parser needs.
    Parse { origin: Origin, detail: String },
    /// The origin's daily ceiling is spent; `resume_at_unix` is the
    /// next UTC midnight.
    DailyBudgetExhausted { origin: Origin, resume_at_unix: i64 },
}

impl std::fmt::Display for IntakeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntakeError::Fetch {
                origin,
                url,
                detail,
            } => write!(
                formatter,
                "[{}] fetch of {url} failed: {detail}",
                origin.as_str()
            ),
            IntakeError::Parse { origin, detail } => {
                write!(
                    formatter,
                    "[{}] response parse failed: {detail}",
                    origin.as_str()
                )
            }
            IntakeError::DailyBudgetExhausted {
                origin,
                resume_at_unix,
            } => write!(
                formatter,
                "[{}] daily budget of {DAILY_BUDGET} spent; resume at unix {}",
                origin.as_str(),
                resume_at_unix
            ),
        }
    }
}

impl std::error::Error for IntakeError {}

/// The HTTP transport seam. Implementations return raw response bytes;
/// every failure is a plain detail string (the wrapper attaches the
/// origin and URL).
pub trait Fetcher: Send + Sync {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, String>;
}

/// The production fetcher: blocking reqwest, rustls, the consumer's
/// whole-request deadline and byte ceiling.
pub struct HttpFetcher {
    client: reqwest::blocking::Client,
}

impl HttpFetcher {
    pub fn new() -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(FETCH_TOTAL_TIMEOUT_SECS))
            .build()
            .map_err(|error| format!("http client build failed: {error}"))?;
        Ok(Self { client })
    }
}

impl Fetcher for HttpFetcher {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        let response = self
            .client
            .get(url)
            .send()
            .map_err(|error| error.to_string())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        let bytes = response
            .bytes()
            .map_err(|error| format!("body read failed: {error}"))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(format!(
                "response of {} bytes exceeds the {MAX_RESPONSE_BYTES} ceiling",
                bytes.len()
            ));
        }
        Ok(bytes.to_vec())
    }
}

/// One budgeted fetch: admits through the budget (window waits go
/// through `clock.sleep_until`, a spent daily ceiling returns
/// [`IntakeError::DailyBudgetExhausted`] instead of a multi-hour
/// sleep), then hands the URL to the fetcher.
pub fn fetch_with_budget(
    fetcher: &dyn Fetcher,
    budgets: &mut RateBudgets,
    clock: &dyn UvpbClock,
    origin: Origin,
    url: &str,
) -> Result<Vec<u8>, IntakeError> {
    loop {
        let now = clock.now_unix();
        match budgets.admit(origin, now) {
            AdmitDecision::Admit => break,
            AdmitDecision::WaitWindow(until) => clock.sleep_until(until),
            AdmitDecision::WaitDaily(resume_at_unix) => {
                return Err(IntakeError::DailyBudgetExhausted {
                    origin,
                    resume_at_unix,
                });
            }
        }
    }
    fetcher.fetch(url).map_err(|detail| IntakeError::Fetch {
        origin,
        url: url.to_owned(),
        detail,
    })
}

/// Fetches and parses the KEV catalog into entries (order preserved,
/// duplicate ids dropped).
pub fn fetch_kev_catalog(
    fetcher: &dyn Fetcher,
    budgets: &mut RateBudgets,
    clock: &dyn UvpbClock,
) -> Result<Vec<KevEntry>, IntakeError> {
    let bytes = fetch_with_budget(fetcher, budgets, clock, Origin::Kev, KEV_CATALOG_URL)?;
    parse_kev_catalog(&bytes)
}

/// Fetches one CVE's NVD record and narrows it to [`NvdFacts`]. `Ok(None)`
/// means the API answered with zero results (the CVE simply has no NVD
/// record yet).
pub fn fetch_nvd_cve(
    fetcher: &dyn Fetcher,
    budgets: &mut RateBudgets,
    clock: &dyn UvpbClock,
    cve_id: &str,
) -> Result<Option<NvdFacts>, IntakeError> {
    let url = format!("{NVD_CVE_API_PREFIX}{cve_id}");
    let bytes = fetch_with_budget(fetcher, budgets, clock, Origin::Nvd, &url)?;
    parse_nvd_cve(&bytes)
}

/// Parses the KEV catalog bytes. Each id is canonicalized to the
/// uppercase producer spelling before use; entries without a `cveID`
/// (or with an id that does not validate as `CVE-YYYY-NNNN[N]`) are
/// skipped, duplicate ids are dropped, and a body without the
/// `vulnerabilities` array is a hard parse error.
pub fn parse_kev_catalog(bytes: &[u8]) -> Result<Vec<KevEntry>, IntakeError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| IntakeError::Parse {
        origin: Origin::Kev,
        detail: error.to_string(),
    })?;
    let Some(entries) = value.get("vulnerabilities").and_then(Value::as_array) else {
        return Err(IntakeError::Parse {
            origin: Origin::Kev,
            detail: "missing the vulnerabilities array".to_owned(),
        });
    };
    let mut out: Vec<KevEntry> = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(raw_id) = entry.get("cveID").and_then(Value::as_str) else {
            continue;
        };
        let Some(cve_id) = crate::schema::canonical_cve_id(raw_id) else {
            continue;
        };
        if out.iter().any(|known| known.cve_id == cve_id) {
            continue;
        }
        out.push(KevEntry {
            cve_id,
            vendor_project: entry
                .get("vendorProject")
                .and_then(Value::as_str)
                .map(str::to_owned),
            product: entry
                .get("product")
                .and_then(Value::as_str)
                .map(str::to_owned),
        });
    }
    Ok(out)
}

/// Parses one NVD CVE API 2.0 response. `Ok(None)` for a zero-result
/// body; a body without the `vulnerabilities` array at all is a hard
/// parse error.
pub fn parse_nvd_cve(bytes: &[u8]) -> Result<Option<NvdFacts>, IntakeError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| IntakeError::Parse {
        origin: Origin::Nvd,
        detail: error.to_string(),
    })?;
    let Some(records) = value.get("vulnerabilities").and_then(Value::as_array) else {
        return Err(IntakeError::Parse {
            origin: Origin::Nvd,
            detail: "missing the vulnerabilities array".to_owned(),
        });
    };
    let Some(record) = records.first().and_then(|wrapper| wrapper.get("cve")) else {
        return Ok(None);
    };
    let mut facts = NvdFacts::default();
    if let Some(metrics) = record.get("metrics") {
        facts.cvss = best_cvss(metrics);
    }
    if let Some(configurations) = record.get("configurations") {
        let mut criteria = Vec::new();
        collect_cpe_matches(configurations, 0, &mut criteria);
        facts.cpe_criteria = criteria;
    }
    if let Some(references) = record.get("references").and_then(Value::as_array) {
        facts.poc_references = references
            .iter()
            .filter_map(|reference| {
                let url = reference.get("url").and_then(Value::as_str)?;
                let tags = reference.get("tags").and_then(Value::as_array)?;
                let tag = exploit_reference_tag(tags)?;
                Some(PocReferenceHit {
                    url: url.to_owned(),
                    tag,
                })
            })
            .collect();
    }
    Ok(Some(facts))
}

/// The maximum `baseScore` across every metric entry in the record's
/// `metrics` map (V31/V30/V2/V4 — the shape carries them as sibling
/// arrays; the generator wants one number).
fn best_cvss(metrics: &Value) -> Option<f64> {
    let mut best: Option<f64> = None;
    if let Some(map) = metrics.as_object() {
        for (_family, entries) in map {
            let Some(entries) = entries.as_array() else {
                continue;
            };
            for entry in entries {
                if let Some(score) = entry
                    .get("cvssData")
                    .and_then(|data| data.get("baseScore"))
                    .and_then(Value::as_f64)
                {
                    best = Some(match best {
                        Some(current) if current >= score => current,
                        _ => score,
                    });
                }
            }
        }
    }
    best
}

/// Collects every `cpeMatch[].criteria` string under a configurations
/// value, tolerating both 2.0 shapes (an object holding `nodes` and a
/// bare array of nodes) and future re-nesting, with depth and count
/// bounds so a hostile body cannot drive unbounded work.
fn collect_cpe_matches(value: &Value, depth: usize, out: &mut Vec<String>) {
    if out.len() >= MAX_CPE_CRITERIA || depth > CPE_WALK_MAX_DEPTH {
        return;
    }
    match value {
        Value::Object(map) => {
            if let Some(matches) = map.get("cpeMatch").and_then(Value::as_array) {
                for entry in matches {
                    if let Some(criteria) = entry.get("criteria").and_then(Value::as_str) {
                        if out.len() < MAX_CPE_CRITERIA {
                            out.push(criteria.to_owned());
                        }
                    }
                }
            }
            for child in map.values() {
                collect_cpe_matches(child, depth + 1, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_cpe_matches(item, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// The first PoC/exploit-indicative tag of a reference (NVD's
/// vocabulary spells it `Exploit`; informal feeds use `PoC`).
fn exploit_reference_tag(tags: &[Value]) -> Option<String> {
    tags.iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .find(|tag| {
            let lower = tag.to_ascii_lowercase();
            lower.contains("exploit") || lower == "poc"
        })
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEV_FIXTURE: &str = r#"{
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "count": 3,
        "vulnerabilities": [
            {"cveID":"CVE-2024-0001","vendorProject":"Elementor","product":"elementor"},
            {"cveID":"CVE-2023-0002","vendorProject":"Fortinet","product":"FortiOS"},
            {"cveID":"CVE-2023-0002","vendorProject":"Fortinet","product":"FortiOS"},
            {"cveID":"cve-2024-0003","vendorProject":"","product":"broken"}
        ]
    }"#;

    const NVD_FIXTURE: &str = r#"{
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0001",
                "metrics": {
                    "cvssMetricV31": [{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","baseScore":9.8}}],
                    "cvssMetricV30": [{"source":"vendor","type":"Secondary","cvssData":{"version":"3.0","baseScore":7.5}}]
                },
                "configurations": {
                    "CVE_record_version": "0.1",
                    "nodes": [{"operator":"OR","negate":false,"cpeMatch":[
                        {"vulnerable":true,"criteria":"cpe:2.3:a:elementor:elementor:3.6.0:*:*:*:*:*:*:*"},
                        {"vulnerable":true,"criteria":"cpe:2.3:a:otherco:unmapped:1.0:*:*:*:*:*:*:*"}
                    ]}]
                },
                "references": [
                    {"url":"https://example.org/poc","source":"cna","tags":["Exploit","Third Party Advisory"]},
                    {"url":"https://example.org/patch","source":"cna","tags":["Patch"]}
                ]
            }
        }]
    }"#;

    const NVD_FIXTURE_ARRAY_CONFIGURATIONS: &str = r#"{
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0002",
                "configurations": [{"nodes":[{"cpeMatch":[
                    {"vulnerable":true,"criteria":"cpe:2.3:a:vendorco:productx:2.0:*:*:*:*:*:*:*"}
                ]}]}]
            }
        }]
    }"#;

    #[test]
    fn kev_catalog_parses_canonical_deduped_entries() {
        let entries = parse_kev_catalog(KEV_FIXTURE.as_bytes()).expect("fixture parses");
        assert_eq!(entries.len(), 3); // duplicate id dropped
        assert_eq!(entries[0].cve_id, "CVE-2024-0001");
        assert_eq!(
            entries[0].product_token().as_deref(),
            Some("elementor:elementor")
        );
        assert_eq!(entries[1].cve_id, "CVE-2023-0002");
        assert_eq!(
            entries[1].product_token().as_deref(),
            Some("fortinet:fortios")
        );
        // lowercase id canonicalized to the producer spelling; empty
        // vendor/product halves yield no token
        assert_eq!(entries[2].cve_id, "CVE-2024-0003");
        assert_eq!(entries[2].product_token(), None);
    }

    #[test]
    fn kev_body_without_vulnerabilities_is_a_parse_error() {
        let error =
            parse_kev_catalog(br#"{"title":"no entries"}"#).expect_err("missing array must fail");
        assert!(matches!(
            error,
            IntakeError::Parse {
                origin: Origin::Kev,
                ..
            }
        ));
    }

    #[test]
    fn nvd_record_narrows_to_minimum_facts() {
        let facts = parse_nvd_cve(NVD_FIXTURE.as_bytes())
            .expect("fixture parses")
            .expect("record present");
        assert_eq!(facts.cvss, Some(9.8)); // max across metric families
        assert_eq!(
            facts.cpe_criteria,
            vec![
                "cpe:2.3:a:elementor:elementor:3.6.0:*:*:*:*:*:*:*",
                "cpe:2.3:a:otherco:unmapped:1.0:*:*:*:*:*:*:*"
            ]
        );
        assert_eq!(
            facts.poc_references,
            vec![PocReferenceHit {
                url: "https://example.org/poc".to_owned(),
                tag: "Exploit".to_owned(),
            }]
        );
    }

    #[test]
    fn nvd_configurations_array_shape_also_collects_criteria() {
        let facts = parse_nvd_cve(NVD_FIXTURE_ARRAY_CONFIGURATIONS.as_bytes())
            .expect("fixture parses")
            .expect("record present");
        assert_eq!(
            facts.cpe_criteria,
            vec!["cpe:2.3:a:vendorco:productx:2.0:*:*:*:*:*:*:*"]
        );
        assert_eq!(facts.cvss, None);
        assert!(facts.poc_references.is_empty());
    }

    #[test]
    fn nvd_zero_results_is_none_not_an_error() {
        let facts = parse_nvd_cve(br#"{"resultsPerPage":0,"totalResults":0,"vulnerabilities":[]}"#)
            .expect("body parses");
        assert_eq!(facts, None);
    }
}
