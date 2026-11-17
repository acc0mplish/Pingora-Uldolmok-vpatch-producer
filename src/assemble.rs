//! The publication assembly's pure core (issue #1745 P-P3, design
//! §3.3/§3.4): `rules/` + `state.json` + an injected clock read ->
//! the canonical payload bytes and their sha256, nothing else.
//!
//! Determinism law (design §3.3): the same (rules tree, state, now)
//! ALWAYS yields the same bytes — the version label is derived, not
//! sampled, the rule order is canonicalized, and no wall clock or
//! directory iteration order leaks into the output. The CLI
//! (`bin/assemble.rs`) is the only process face; this module is the
//! testable contract.
//!
//! Publishing discipline (design §3.4) as enforced here:
//! - rule 2, normalization BEFORE the bytes: the consumer's own
//!   `canonicalize_payload` transformation runs on the assembled
//!   payload and only its output is serialized — the signed bytes are
//!   the normalized bytes.
//! - rule 1, sequence monotonicity: the sequence is fixed to
//!   `state.sequence + 1` (the bump commit in the signing workflow is
//!   the state's only writer).
//! - rules 5/8: the codec's `publish_gate` (canonical `CVE-YYYY-NNNN`
//!   ids, https-only references, the 768-rule producer self-cap) runs
//!   on the canonical payload before serialization.
//! - consumer freshness gates are self-checked against the same
//!   injected `now` (published/expires/window) — a header this module
//!   minted must never fail the sync-path freshness check it was
//!   built for.

use std::path::Path;

use config_model::waf_feed::{
    canonicalize_payload, check_freshness, payload_sha256_hex, WafFeedPayload, WafFeedRejectCode,
    WafFeedRule, MAX_WAF_FEED_VALIDITY_SECONDS,
};
use serde::{Deserialize, Serialize};
use waf_bundle_encoder::canonical_payload_bytes;
use waf_bundle_encoder::{publish_gate, PublishRejection};

/// The weekly cadence's default validity (design §4: weekly issuance,
/// 14-day window = 2x the 7-day cycle of re-issue headroom).
pub const DEFAULT_VALIDITY_DAYS: i64 = 14;

/// The consumer rejects windows over [`MAX_WAF_FEED_VALIDITY_SECONDS`]
/// (30 days) with `validity_too_long` on every later sync — the
/// assembler refuses them at mint time instead.
pub const MAX_VALIDITY_DAYS: i64 = MAX_WAF_FEED_VALIDITY_SECONDS / 86_400;

/// The producer state file (`state.json`, design §3.2). Unknown fields
/// (the operator's `note`) are ignored — the state gains fields without
/// breaking old assemblies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerState {
    /// The last PUBLISHED sequence; the assembly mints `sequence + 1`.
    pub sequence: u64,
    /// The key id the signing job will sign with (informational here —
    /// the envelope is minted by `uvpb-sign`, design D3).
    pub current_key_id: String,
    /// The last published version label (`YYYY-MM-DD.N`). Absent before
    /// the first assembly; present once the state bump commits start
    /// recording it. The SAME-DAY re-issue ordinal is derived from it.
    #[serde(default)]
    pub last_version_label: Option<String>,
}

/// Why an assembly refused. Every arm names the discipline (design
/// §3.3/§3.4) or gate the payload would have violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssembleError {
    /// `state.json` did not parse as a [`ProducerState`].
    StateUnparsable { path: String },
    /// `--now` was not a sane unix second (negative).
    InvalidNow { now: i64 },
    /// The requested validity is outside `1..=[`MAX_VALIDITY_DAYS`]`.
    ValidityOutOfRange { days: i64 },
    /// The previous version label claims the same UTC day but its
    /// ordinal is not a positive integer — re-issuing would risk reusing
    /// an ordinal, so the assembly fails closed.
    LastVersionLabelMalformed { label: String },
    /// A rules/*.json file did not parse as a [`WafFeedRule`].
    RuleFileUnparsable { file: String },
    /// The rules directory exists but could not be read (fail-closed —
    /// a permissions fault must never read as an empty feed).
    RulesDirUnreadable { path: String },
    /// The consumer's canonicalization rejected the payload (schema:
    /// duplicate ids, >1024 rules, field violations).
    ConsumerModelRejected(WafFeedRejectCode),
    /// The consumer's freshness gates failed against the injected now.
    FreshnessRejected(WafFeedRejectCode),
    /// The codec's producer-side publish gate rejected the payload
    /// (cve id spelling, non-https reference, the 768 self-cap).
    PublishRejected(PublishRejection),
    /// The sequence counter exhausted u64 (astronomically unreachable,
    /// checked for totality).
    SequenceOverflow,
}

impl std::fmt::Display for AssembleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssembleError::StateUnparsable { path } => {
                write!(formatter, "state file {path} is not a valid producer state")
            }
            AssembleError::InvalidNow { now } => {
                write!(formatter, "--now {now} is not a valid unix second")
            }
            AssembleError::ValidityOutOfRange { days } => write!(
                formatter,
                "validity {days} days is outside 1..={MAX_VALIDITY_DAYS} (the consumer would reject validity_too_long)"
            ),
            AssembleError::LastVersionLabelMalformed { label } => write!(
                formatter,
                "state's last version label {label:?} claims today but its ordinal is not a positive integer"
            ),
            AssembleError::RuleFileUnparsable { file } => {
                write!(formatter, "rule file {file} is not a valid feed rule")
            }
            AssembleError::RulesDirUnreadable { path } => {
                write!(formatter, "rules directory {path} is unreadable")
            }
            AssembleError::ConsumerModelRejected(code) => {
                write!(formatter, "consumer model rejected: {}", code.as_str())
            }
            AssembleError::FreshnessRejected(code) => {
                write!(formatter, "freshness gate rejected: {}", code.as_str())
            }
            AssembleError::PublishRejected(rejection) => {
                write!(formatter, "publish gate rejected: {rejection}")
            }
            AssembleError::SequenceOverflow => write!(formatter, "sequence counter exhausted"),
        }
    }
}

impl std::error::Error for AssembleError {}

/// What a successful assembly produced: the canonical payload (the
/// value), its canonical bytes (what gets signed), and the sha256 of
/// those bytes (what the receipt and the signing job pin).
#[derive(Debug, Clone, PartialEq)]
pub struct Assembled {
    pub payload: WafFeedPayload,
    pub canonical_bytes: Vec<u8>,
    pub sha256_hex: String,
}

/// The UTC calendar date of a unix second, as the proleptic Gregorian
/// (year, month, day). Pure conversion (Howard Hinnant's
/// civil-from-days) — no clock or timezone dependency; the workflow's
/// runners are UTC and the label must be a function of `--now` only.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let shifted = days_since_epoch + 719_468;
    let era = if shifted >= 0 {
        shifted / 146_097
    } else {
        (shifted - 146_096) / 146_097
    };
    let day_of_era = (shifted - era * 146_097) as u64; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_pointer = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_pointer + 2) / 5 + 1) as u32;
    let month = if month_pointer < 10 {
        month_pointer + 3
    } else {
        month_pointer - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// The `YYYY-MM-DD` half of a version label, derived from the injected
/// clock read alone.
pub fn utc_date_label(now_unix: i64) -> String {
    let (year, month, day) = civil_from_days(now_unix.div_euclid(86_400));
    format!("{year:04}-{month:02}-{day:02}")
}

/// Derives the version label `YYYY-MM-DD.N` (design §3.3/D4 — the
/// format spec's example spelling, <=32 bytes): `N` is the same-day
/// issuance ordinal. With no previous label (or a previous label from
/// an earlier day) the ordinal is 1; when the previous label carries
/// TODAY's date its ordinal is incremented. A malformed same-day label
/// fails closed (an unparsable ordinal must never silently reset to 1
/// and collide with a published version).
pub fn version_label(
    now_unix: i64,
    last_version_label: Option<&str>,
) -> Result<String, AssembleError> {
    let date = utc_date_label(now_unix);
    let ordinal = match last_version_label {
        None => 1,
        Some(label) => match label.split_once('.') {
            Some((last_date, last_ordinal)) if last_date == date => {
                let previous: u64 =
                    last_ordinal
                        .parse()
                        .map_err(|_| AssembleError::LastVersionLabelMalformed {
                            label: label.to_owned(),
                        })?;
                if previous == 0 {
                    return Err(AssembleError::LastVersionLabelMalformed {
                        label: label.to_owned(),
                    });
                }
                previous + 1
            }
            // Earlier day, or a label without an ordinal part: today has
            // no recorded issuance yet.
            Some((_, _)) | None => 1,
        },
    };
    Ok(format!("{date}.{ordinal}"))
}

/// Loads every `rules/*.json` as a [`WafFeedRule`], file-name-sorted
/// (the same listing discipline as the gate). A missing directory is a
/// legal empty feed (the genesis assembly, design D7); a present-but-
/// unreadable one is an error, never a silent empty feed.
pub fn load_rules(rules_dir: &Path) -> Result<Vec<WafFeedRule>, AssembleError> {
    let entries = match std::fs::read_dir(rules_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => {
            return Err(AssembleError::RulesDirUnreadable {
                path: rules_dir.display().to_string(),
            })
        }
    };
    let mut files: Vec<(String, std::path::PathBuf)> = entries
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                let name = path.file_name()?.to_str()?.to_owned();
                Some((name, path))
            } else {
                None
            }
        })
        .collect();
    files.sort();
    let mut rules = Vec::with_capacity(files.len());
    for (name, path) in files {
        let bytes = std::fs::read(&path).map_err(|_| AssembleError::RulesDirUnreadable {
            path: path.display().to_string(),
        })?;
        let rule: WafFeedRule =
            serde_json::from_slice(&bytes).map_err(|_| AssembleError::RuleFileUnparsable {
                file: format!("rules/{name}"),
            })?;
        rules.push(rule);
    }
    Ok(rules)
}

/// Parses a `state.json` file.
pub fn load_state(state_path: &Path) -> Result<ProducerState, AssembleError> {
    let bytes = std::fs::read(state_path).map_err(|_| AssembleError::StateUnparsable {
        path: state_path.display().to_string(),
    })?;
    serde_json::from_slice(&bytes).map_err(|_| AssembleError::StateUnparsable {
        path: state_path.display().to_string(),
    })
}

/// Assembles the canonical payload bytes (design §3.3): sequence =
/// `state.sequence + 1`, version = [`version_label`], published_at =
/// `now`, expires_at = `now + validity_days * 86400`, rules = the
/// canonical-sorted full set. The gate suite (lint + corpus, via
/// `run_gate`) is the caller's precondition — this function enforces
/// the payload-level disciplines itself.
pub fn assemble(
    rules: Vec<WafFeedRule>,
    state: &ProducerState,
    now_unix: i64,
    validity_days: i64,
) -> Result<Assembled, AssembleError> {
    if now_unix < 0 {
        return Err(AssembleError::InvalidNow { now: now_unix });
    }
    if !(1..=MAX_VALIDITY_DAYS).contains(&validity_days) {
        return Err(AssembleError::ValidityOutOfRange {
            days: validity_days,
        });
    }
    let sequence = state
        .sequence
        .checked_add(1)
        .ok_or(AssembleError::SequenceOverflow)?;
    let version = version_label(now_unix, state.last_version_label.as_deref())?;
    let expires_at = now_unix + validity_days * 86_400;

    // §3.4 rule 2 — normalization BEFORE the bytes: the consumer's own
    // transformation (trim/lowercase, sort_order clamp, advisory
    // re-serialization ceiling) runs first and only its output is used.
    let draft = WafFeedPayload {
        format_version: 1,
        sequence,
        version,
        published_at: now_unix,
        expires_at,
        rules,
    };
    let mut canonical =
        canonicalize_payload(&draft).map_err(AssembleError::ConsumerModelRejected)?;

    // Canonical rule order: the canonicalized (clamped) sort order and
    // the canonical (lowercase) id — a total order over the rule set,
    // independent of the rules directory's file order.
    canonical
        .rules
        .sort_by(|left, right| (left.sort_order, &left.id).cmp(&(right.sort_order, &right.id)));

    // The header this module minted must pass the consumer's sync-path
    // freshness gates at the very clock it was minted with.
    check_freshness(&canonical, now_unix).map_err(AssembleError::FreshnessRejected)?;

    // §3.4 rules 5/8 — the codec's producer-side gate (cve id spelling,
    // https references, the 768-rule self-cap).
    publish_gate(&canonical).map_err(AssembleError::PublishRejected)?;

    // §3.4 rule 3 — one fixed structural serializer, never re-serialized.
    let canonical_bytes = canonical_payload_bytes(&canonical);
    let sha256_hex = payload_sha256_hex(&canonical_bytes);
    Ok(Assembled {
        payload: canonical,
        canonical_bytes,
        sha256_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_date_label_converts_days_since_epoch() {
        assert_eq!(utc_date_label(0), "1970-01-01");
        // 2026-11-17 (the design's checkout date, 0:00 UTC).
        assert_eq!(utc_date_label(1_794_873_600), "2026-11-17");
        // Leap day: 2024-02-29.
        assert_eq!(utc_date_label(1_709_164_800), "2024-02-29");
        // Year boundary and the leap-year rollover into 2000.
        assert_eq!(utc_date_label(946_684_799), "1999-12-31");
        assert_eq!(utc_date_label(946_684_800), "2000-01-01");
    }

    #[test]
    fn version_label_counts_same_day_issuances() {
        let now = 1_794_873_600; // 2026-11-17 00:00:00 UTC
        assert_eq!(version_label(now, None).unwrap(), "2026-11-17.1");
        assert_eq!(
            version_label(now, Some("2026-11-17.1")).unwrap(),
            "2026-11-17.2"
        );
        assert_eq!(
            version_label(now, Some("2026-11-16.7")).unwrap(),
            "2026-11-17.1"
        );
        // A label without an ordinal part cannot claim today.
        assert_eq!(
            version_label(now, Some("not-a-version-label")).unwrap(),
            "2026-11-17.1"
        );
        // A malformed same-day ordinal fails closed.
        assert_eq!(
            version_label(now, Some("2026-11-17.x")),
            Err(AssembleError::LastVersionLabelMalformed {
                label: "2026-11-17.x".to_owned()
            })
        );
        assert_eq!(
            version_label(now, Some("2026-11-17.0")),
            Err(AssembleError::LastVersionLabelMalformed {
                label: "2026-11-17.0".to_owned()
            })
        );
    }
}
