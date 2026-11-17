//! The static lint layer of the curation gate (issue #1745 P-P2,
//! design §5 layer 1): every check is deterministic, every violation is
//! its own diagnostic, and a rule carrying ANY diagnostic is refused —
//! the gate never ranks, it enumerates.
//!
//! Scope discipline: this lint is the PRODUCER-side floor the curator's
//! approval PR must clear. Checks the codec already enforces on the
//! assembled payload (`seed_blocklist` duplicates at approval time,
//! `publish_gate`'s §3.4 rules 5/8) are consumed from the codec crate
//! — no seed pair is re-extracted from any schema asset here, and no
//! independent seed source exists in this repository (C-P2-3).
//!
//! Two entry points share the literal-level core:
//! - [`lint_rule`] — a `rules/*.json` feed rule, all layers.
//! - [`lint_candidate_literal`] — a `candidates/*.json` approvable
//!   candidate's literal only (id/category/severity/advisory do not
//!   exist yet); its failures are gate WARNINGS that still fail the
//!   exit, because a literal that cannot pass the lint has no approval
//!   PR qualification.

use crate::schema::{canonical_cve_id, PatternType};
use config_model::waf_feed::{
    WafFeedAdvisory, WafFeedPayload, WafFeedRule, WAF_FEED_SORT_ORDER_MAX, WAF_FEED_SORT_ORDER_MIN,
};
use config_model::ManagedWafPatternType;
use waf_bundle_encoder::{publish_gate, seed_blocklist};

/// The advisory re-serialization ceiling (design §3.4 rule 2: the
/// consumer canonicalization's advisory byte budget the signed bytes
/// must already satisfy).
const ADVISORY_MAX_BYTES: usize = 2048;
/// The advisory `source_note` ceiling — the consumer model's
/// `WAF_FEED_MAX_SOURCE_NOTE_BYTES` value.
const SOURCE_NOTE_MAX_BYTES: usize = 256;
/// Pattern byte floor (design §5 layer 1's legal lower bound; the
/// recommended authoring floor is 8, enforced by review, not lint).
const PATTERN_MIN_BYTES: usize = 4;
/// Pattern byte ceiling.
const PATTERN_MAX_BYTES: usize = 256;
/// Rule name byte ceiling — the consumer's private
/// `WAF_FEED_MAX_NAME_BYTES` (canonicalize_rule).
const NAME_MAX_BYTES: usize = 128;
/// Category byte ceiling — the consumer's private
/// `WAF_FEED_MAX_CATEGORY_BYTES` (canonicalize_rule).
const CATEGORY_MAX_BYTES: usize = 64;
/// Description byte ceiling — the consumer's private
/// `WAF_FEED_MAX_DESCRIPTION_BYTES` (canonicalize_rule).
const DESCRIPTION_MAX_BYTES: usize = 512;

/// Common English words a pattern must never consist of alone (plus a
/// little punctuation): a standalone common word matches ordinary
/// traffic everywhere and can never attribute an exploit. Context-bound
/// seed spellings (`union select`, `document.cookie`) split into more
/// than one part and pass.
const GENERIC_WORDS: &[&str] = &[
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "alert",
    "script",
    "error",
    "admin",
    "administrator",
    "login",
    "logout",
    "password",
    "passwd",
    "username",
    "user",
    "users",
    "test",
    "testing",
    "debug",
    "config",
    "configuration",
    "settings",
    "setup",
    "install",
    "backup",
    "restore",
    "export",
    "import",
    "upload",
    "download",
    "file",
    "files",
    "image",
    "images",
    "search",
    "query",
    "index",
    "home",
    "main",
    "about",
    "contact",
    "account",
    "profile",
    "dashboard",
    "panel",
    "console",
    "shell",
    "root",
    "system",
    "temp",
    "tmp",
    "cache",
    "log",
    "logs",
    "cookie",
    "session",
    "token",
    "auth",
    "secret",
    "key",
    "data",
    "name",
    "value",
    "page",
    "site",
    "web",
    "mail",
    "email",
    "list",
    "item",
    "items",
    "order",
    "status",
    "create",
    "new",
    "edit",
    "view",
    "show",
    "get",
    "post",
    "put",
    "set",
    "add",
    "remove",
    "info",
    "api",
    "app",
    "help",
    "docs",
    "static",
    "assets",
    "media",
];

/// The method tokens a `request_method` pattern may carry: RFC 9110
/// section 9.1, RFC 5789 PATCH, WebDAV (RFC 4918 plus the RFC 5323
/// SEARCH and common extensions). Anything else cannot be an HTTP
/// request method and would silently never match.
const METHOD_TOKENS: &[&str] = &[
    "get",
    "head",
    "post",
    "put",
    "delete",
    "connect",
    "options",
    "trace",
    "patch",
    "propfind",
    "proppatch",
    "mkcol",
    "copy",
    "move",
    "lock",
    "unlock",
    "mkactivity",
    "checkout",
    "merge",
    "m-search",
    "report",
    "mkcalendar",
    "label",
    "search",
    "acl",
    "baseline-control",
    "version-control",
    "purge",
    "notify",
    "subscribe",
    "unsubscribe",
];

/// The categories reserved for consumer-internal rule families — a feed
/// rule may never claim them (design §7: the feed convention is the
/// single `cve-virtual-patch` category).
const RESERVED_CATEGORIES: &[&str] = &["api_abuse", "bola"];

/// One lint violation. `code()` is the stable machine token the CLI's
/// `--explain` consumes; `Display` is the human line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Diagnostic {
    PatternTooShort {
        len: usize,
    },
    PatternTooLong {
        len: usize,
    },
    PatternNotLowerAscii,
    /// §3.4 rule 2's 정규화 선적용 for trim: the consumer trims
    /// patterns, so signed bytes must already be trim-canonical (a
    /// padded pattern would also evade the seed-duplicate compare).
    PatternNotCanonical,
    PatternControlChar,
    GenericWordStandalone {
        word: String,
    },
    MethodTokenMismatch {
        pattern: String,
    },
    IdFormat {
        id: String,
    },
    ReservedCategory {
        category: String,
    },
    CategoryEmpty,
    /// The consumer lowercases + trims the category and then requires
    /// `[a-z0-9_-]`; design §3.4 rule 2 requires the signed bytes to
    /// already be that canonical spelling.
    CategoryNotCanonical {
        category: String,
    },
    SeverityVocabulary {
        severity: String,
    },
    EmptyName,
    NameTooLong {
        bytes: usize,
    },
    NameControlChar,
    EmptyDescription,
    DescriptionTooLong {
        bytes: usize,
    },
    DescriptionControlChar,
    /// The consumer clamps `sort_order` into the feed window; design
    /// §3.4 rule 2 (정규화 선적용) requires values already inside it —
    /// a clamped rule would mean the signed bytes differ from the
    /// stored rule.
    SortOrderOutOfRange {
        sort_order: i64,
    },
    CveIdFormat {
        cve: String,
    },
    ReferenceScheme {
        reference: String,
    },
    AdvisoryTooLarge {
        bytes: usize,
    },
    SourceNoteTooLong {
        bytes: usize,
    },
    /// The consumer trims `source_note` and rejects control characters;
    /// the signed bytes must already be trim-canonical.
    SourceNoteNotCanonical,
    /// §7 L4: every `vp-cve-*` rule must carry an advisory — the
    /// consumer metadata worker only activates on feed rules whose
    /// advisory carries CVE ids, so an advisory-less CVE rule is a
    /// self-inflicted dormant feature.
    AdvisoryRequired {
        id: String,
    },
    /// The advisory is present but carries no CVE ids — the same §7 L4
    /// dormancy with the advisory shell in place.
    CveIdsEmpty {
        id: String,
    },
    SeedDuplicate {
        pattern_type: String,
        pattern: String,
    },
}

impl Diagnostic {
    /// The stable code string (also the `--explain` key).
    pub fn code(&self) -> &'static str {
        match self {
            Diagnostic::PatternTooShort { .. } => "pattern_too_short",
            Diagnostic::PatternTooLong { .. } => "pattern_too_long",
            Diagnostic::PatternNotLowerAscii => "pattern_not_lower_ascii",
            Diagnostic::PatternNotCanonical => "pattern_not_canonical",
            Diagnostic::PatternControlChar => "pattern_control_char",
            Diagnostic::GenericWordStandalone { .. } => "generic_word_standalone",
            Diagnostic::MethodTokenMismatch { .. } => "method_token_mismatch",
            Diagnostic::IdFormat { .. } => "id_format",
            Diagnostic::ReservedCategory { .. } => "reserved_category",
            Diagnostic::CategoryEmpty => "category_empty",
            Diagnostic::CategoryNotCanonical { .. } => "category_not_canonical",
            Diagnostic::SeverityVocabulary { .. } => "severity_vocabulary",
            Diagnostic::EmptyName => "empty_name",
            Diagnostic::NameTooLong { .. } => "name_too_long",
            Diagnostic::NameControlChar => "name_control_char",
            Diagnostic::EmptyDescription => "empty_description",
            Diagnostic::DescriptionTooLong { .. } => "description_too_long",
            Diagnostic::DescriptionControlChar => "description_control_char",
            Diagnostic::SortOrderOutOfRange { .. } => "sort_order_out_of_range",
            Diagnostic::CveIdFormat { .. } => "cve_id_format",
            Diagnostic::ReferenceScheme { .. } => "reference_scheme",
            Diagnostic::AdvisoryTooLarge { .. } => "advisory_too_large",
            Diagnostic::SourceNoteTooLong { .. } => "source_note_too_long",
            Diagnostic::SourceNoteNotCanonical => "source_note_not_canonical",
            Diagnostic::AdvisoryRequired { .. } => "advisory_required",
            Diagnostic::CveIdsEmpty { .. } => "cve_ids_empty",
            Diagnostic::SeedDuplicate { .. } => "seed_duplicate",
        }
    }

    /// The `--explain` paragraph for a code: what the gate refuses and
    /// why the consumer (or the curation contract) demands it.
    pub fn explain(code: &str) -> Option<&'static str> {
        Some(match code {
            "pattern_too_short" => {
                "A pattern under 4 bytes cannot attribute an exploit \
                narrowly; the recommended authoring floor is 8 bytes (review checklist), \
                4 is the hard legal floor the lint enforces."
            }
            "pattern_too_long" => {
                "A pattern over 256 bytes exceeds the consumer's pattern \
                ceiling; split the detection across context-bound patterns instead."
            }
            "pattern_not_lower_ascii" => {
                "Feed rules publish one lowercase-ASCII spelling \
                per literal (design §7: no case-variant duplicates — they multiply false \
                positives and split attribution)."
            }
            "pattern_not_canonical" => {
                "The consumer trims patterns on canonicalization; \
                design §3.4 rule 2 requires the signed bytes to already be canonical, \
                and a padded pattern would evade the seed-duplicate compare."
            }
            "pattern_control_char" => {
                "Control characters cannot appear in wire traffic \
                match forms a curator can review; they are a plant/obfuscation vector."
            }
            "generic_word_standalone" => {
                "A pattern that is one common English word (plus \
                punctuation) matches ordinary traffic everywhere; only context-bound \
                spellings (e.g. seed-style `union select`) attribute an exploit."
            }
            "method_token_mismatch" => {
                "A request_method pattern must be an HTTP method \
                token (RFC 9110 / WebDAV); anything else silently never matches."
            }
            "id_format" => {
                "Rule ids are `vp-cve-<year>-<nnnnn>[-suffix]`, lowercase; the \
                id is an immutable identity and this is the producer's id namespace."
            }
            "reserved_category" => {
                "`api_abuse` and `bola` are consumer-internal rule \
                families; feed rules use the `cve-virtual-patch` category convention."
            }
            "category_empty" => {
                "A rule needs a category — the consumer rejects empty \
                identifiers and the feed convention is one category per rule."
            }
            "category_not_canonical" => {
                "The consumer lowercases + trims the category and then \
                requires `[a-z0-9_-]` bytes; a non-canonical category is refused by the \
                consumer outright and design §3.4 rule 2 requires canonical signed bytes."
            }
            "severity_vocabulary" => {
                "Feed rules publish only `critical` (KEV or CVSS \
                >= 9.0) or `warning`; the consumer vocabulary's `info` is not a producer \
                severity."
            }
            "empty_name" => {
                "A rule needs a human-readable name for the operator-facing \
                catalog and release notes."
            }
            "name_too_long" => {
                "The rule name exceeds the consumer's 128-byte ceiling \
                (canonicalize_rule refuses the whole bundle)."
            }
            "name_control_char" => {
                "The rule name carries a control character — the \
                consumer's canonicalization refuses it."
            }
            "empty_description" => {
                "A rule needs a description stating what exploit \
                variant the literal detects (honest capability statement, design §5)."
            }
            "description_too_long" => {
                "The description exceeds the consumer's 512-byte \
                ceiling (canonicalize_rule refuses the whole bundle)."
            }
            "description_control_char" => {
                "The description carries a control character — the \
                consumer's canonicalization refuses it."
            }
            "sort_order_out_of_range" => {
                "The consumer clamps sort_order into \
                [1_000_000, 1_999_999]; a value outside means the signed bytes would \
                differ from the stored rule (§3.4 rule 2) — publish the final value."
            }
            "cve_id_format" => {
                "The consumer does not case-normalize advisory CVE ids; \
                only canonical uppercase `CVE-YYYY-NNNN[N]` reaches the metadata worker."
            }
            "reference_scheme" => {
                "Advisory references must be https:// (design §3.4 \
                rule 5; the codec's publish_gate refuses anything else)."
            }
            "advisory_too_large" => {
                "The advisory re-serialization must stay within the \
                consumer's 2048-byte budget (design §3.4 rule 2)."
            }
            "source_note_too_long" => {
                "The advisory source note exceeds the consumer's \
                256-byte ceiling."
            }
            "source_note_not_canonical" => {
                "The consumer trims source_note and rejects control \
                characters; the signed bytes must already be canonical (§3.4 rule 2)."
            }
            "advisory_required" => {
                "Every vp-cve-* rule must carry an advisory: the \
                consumer metadata worker activates only on feed rules whose advisory \
                carries CVE ids (design §7 L4) — an advisory-less CVE rule is a \
                self-inflicted dormant feature."
            }
            "cve_ids_empty" => {
                "The advisory carries no CVE ids — the metadata merge \
                stays dormant (design §7 L4). CVE-based rules always publish their ids."
            }
            "seed_duplicate" => {
                "The (pattern_type, pattern) pair already exists as a \
                consumer seed rule (consumed from the codec's seed_blocklist); publishing \
                it would duplicate the consumer's rejection and mis-attribute the \
                exploit to the wrong row."
            }
            _ => return None,
        })
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Diagnostic::PatternTooShort { len } => {
                write!(
                    formatter,
                    "pattern is {len} bytes (floor is {PATTERN_MIN_BYTES})"
                )
            }
            Diagnostic::PatternTooLong { len } => {
                write!(
                    formatter,
                    "pattern is {len} bytes (ceiling is {PATTERN_MAX_BYTES})"
                )
            }
            Diagnostic::PatternNotLowerAscii => {
                write!(formatter, "pattern must be lowercase ASCII")
            }
            Diagnostic::PatternNotCanonical => {
                write!(
                    formatter,
                    "pattern must be trim-canonical (no leading/trailing whitespace)"
                )
            }
            Diagnostic::PatternControlChar => {
                write!(formatter, "pattern contains a control character")
            }
            Diagnostic::GenericWordStandalone { word } => {
                write!(formatter, "pattern is the standalone common word `{word}`")
            }
            Diagnostic::MethodTokenMismatch { pattern } => {
                write!(
                    formatter,
                    "request_method pattern `{pattern}` is not an HTTP method token"
                )
            }
            Diagnostic::IdFormat { id } => {
                write!(
                    formatter,
                    "rule id `{id}` is not vp-cve-<year>-<nnnnn>[-suffix]"
                )
            }
            Diagnostic::ReservedCategory { category } => {
                write!(
                    formatter,
                    "category `{category}` is reserved for consumer-internal families"
                )
            }
            Diagnostic::CategoryEmpty => write!(formatter, "category is empty"),
            Diagnostic::CategoryNotCanonical { category } => {
                write!(
                    formatter,
                    "category `{category}` is not canonical lowercase `[a-z0-9_-]`"
                )
            }
            Diagnostic::SeverityVocabulary { severity } => {
                write!(
                    formatter,
                    "severity `{severity}` is not critical or warning"
                )
            }
            Diagnostic::EmptyName => write!(formatter, "name is empty"),
            Diagnostic::NameTooLong { bytes } => {
                write!(
                    formatter,
                    "name is {bytes} bytes (ceiling {NAME_MAX_BYTES})"
                )
            }
            Diagnostic::NameControlChar => {
                write!(formatter, "name contains a control character")
            }
            Diagnostic::EmptyDescription => write!(formatter, "description is empty"),
            Diagnostic::DescriptionTooLong { bytes } => {
                write!(
                    formatter,
                    "description is {bytes} bytes (ceiling {DESCRIPTION_MAX_BYTES})"
                )
            }
            Diagnostic::DescriptionControlChar => {
                write!(formatter, "description contains a control character")
            }
            Diagnostic::SortOrderOutOfRange { sort_order } => {
                write!(
                    formatter,
                    "sort_order {sort_order} is outside [{WAF_FEED_SORT_ORDER_MIN}, {WAF_FEED_SORT_ORDER_MAX}]"
                )
            }
            Diagnostic::CveIdFormat { cve } => {
                write!(
                    formatter,
                    "cve id `{cve}` is not canonical uppercase CVE-YYYY-NNNN[N]"
                )
            }
            Diagnostic::ReferenceScheme { reference } => {
                write!(formatter, "reference `{reference}` is not https://")
            }
            Diagnostic::AdvisoryTooLarge { bytes } => {
                write!(
                    formatter,
                    "advisory re-serialization is {bytes} bytes (ceiling 2048)"
                )
            }
            Diagnostic::SourceNoteTooLong { bytes } => {
                write!(
                    formatter,
                    "source_note is {bytes} bytes (ceiling {SOURCE_NOTE_MAX_BYTES})"
                )
            }
            Diagnostic::SourceNoteNotCanonical => {
                write!(
                    formatter,
                    "source_note must be trim-canonical without control characters"
                )
            }
            Diagnostic::AdvisoryRequired { id } => {
                write!(
                    formatter,
                    "rule {id} carries no advisory (metadata worker dormancy)"
                )
            }
            Diagnostic::CveIdsEmpty { id } => {
                write!(formatter, "rule {id}'s advisory carries no CVE ids")
            }
            Diagnostic::SeedDuplicate {
                pattern_type,
                pattern,
            } => write!(
                formatter,
                "({pattern_type}, `{pattern}`) is already a consumer seed rule"
            ),
        }
    }
}

/// The schema-level pattern type for a consumer pattern type (the
/// corpus matcher and the seed compare both speak the schema's
/// snake_case vocabulary).
fn schema_pattern_type(pattern_type: ManagedWafPatternType) -> PatternType {
    match pattern_type {
        ManagedWafPatternType::QueryString => PatternType::QueryString,
        ManagedWafPatternType::RequestUri => PatternType::RequestUri,
        ManagedWafPatternType::UserAgent => PatternType::UserAgent,
        ManagedWafPatternType::RequestMethod => PatternType::RequestMethod,
        ManagedWafPatternType::RequestBody => PatternType::RequestBody,
    }
}

/// The wire spelling the codec's seed blocklist stores
/// (`ManagedWafPatternType`'s serde snake_case).
fn wire_pattern_type(pattern_type: PatternType) -> &'static str {
    match pattern_type {
        PatternType::QueryString => "query_string",
        PatternType::RequestUri => "request_uri",
        PatternType::UserAgent => "user_agent",
        PatternType::RequestMethod => "request_method",
        PatternType::RequestBody => "request_body",
    }
}

/// The literal-level core shared by rules and approvable candidates:
/// length, canonical spelling, control characters, the standalone
/// generic-word ban, `request_method` token fitness, and the codec
/// seed duplicate check. Returns every violation, in this fixed order.
pub fn lint_candidate_literal(literal: &str, pattern_type: PatternType) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let len = literal.len();
    if len < PATTERN_MIN_BYTES {
        diagnostics.push(Diagnostic::PatternTooShort { len });
    }
    if len > PATTERN_MAX_BYTES {
        diagnostics.push(Diagnostic::PatternTooLong { len });
    }
    if !literal.is_ascii() || literal.bytes().any(|byte| byte.is_ascii_uppercase()) {
        // Non-lowercase or non-ASCII bytes: one code covers both (an
        // uppercase letter and a non-ASCII byte are the same
        // publishing mistake — a non-canonical spelling). Digits,
        // punctuation, and spaces are legitimate literal content
        // (seed spellings carry them).
        diagnostics.push(Diagnostic::PatternNotLowerAscii);
    }
    if literal.trim() != literal {
        diagnostics.push(Diagnostic::PatternNotCanonical);
    }
    if literal.chars().any(|character| character.is_control()) {
        diagnostics.push(Diagnostic::PatternControlChar);
    }
    // A standalone common word over-matches every field EXCEPT
    // request_method, where the exhaustive token whitelist below is
    // the fitness check (a method token like `search` is both a valid
    // method and a common word — the whitelist governs there).
    if pattern_type != PatternType::RequestMethod {
        let parts: Vec<&str> = literal
            .split(|character: char| !character.is_ascii_alphanumeric())
            .filter(|part| !part.is_empty())
            .collect();
        if parts.len() == 1 && GENERIC_WORDS.contains(&parts[0]) {
            diagnostics.push(Diagnostic::GenericWordStandalone {
                word: parts[0].to_owned(),
            });
        }
    }
    if pattern_type == PatternType::RequestMethod && !METHOD_TOKENS.contains(&literal) {
        diagnostics.push(Diagnostic::MethodTokenMismatch {
            pattern: literal.to_owned(),
        });
    }
    let wire = wire_pattern_type(pattern_type);
    if seed_blocklist()
        .iter()
        .any(|(seed_type, seed_pattern)| seed_type == wire && seed_pattern == literal)
    {
        diagnostics.push(Diagnostic::SeedDuplicate {
            pattern_type: wire.to_owned(),
            pattern: literal.to_owned(),
        });
    }
    diagnostics
}

/// The full static lint of one feed rule. Collects ALL violations —
/// the gate refuses on any and reports every diagnostic.
pub fn lint_rule(rule: &WafFeedRule) -> Vec<Diagnostic> {
    let mut diagnostics =
        lint_candidate_literal(&rule.pattern, schema_pattern_type(rule.pattern_type));

    if !rule
        .id
        .strip_prefix("vp-cve-")
        .and_then(|rest| rest.split_once('-'))
        .map(|(year, rest)| {
            year.len() == 4
                && year.bytes().all(|byte| byte.is_ascii_digit())
                // The serial mirrors the canonical CVE spelling
                // (4-7 digits); the rest is an optional `-suffix`.
                && match rest.split_once('-') {
                    Some((serial, suffix)) => {
                        (4..=7).contains(&serial.len())
                            && serial.bytes().all(|byte| byte.is_ascii_digit())
                            && !suffix.is_empty()
                            && suffix
                                .bytes()
                                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                    }
                    None => (4..=7).contains(&rest.len())
                        && rest.bytes().all(|byte| byte.is_ascii_digit()),
                }
        })
        .unwrap_or(false)
    {
        diagnostics.push(Diagnostic::IdFormat { id: rule.id.clone() });
    }

    let category = rule.category.trim().to_ascii_lowercase();
    if category.is_empty() {
        diagnostics.push(Diagnostic::CategoryEmpty);
    } else {
        // The consumer trims + lowercases the category and then
        // requires `[a-z0-9_-]` within its 64-byte ceiling; the signed
        // bytes must already BE that canonical spelling (§3.4 rule 2).
        if rule.category.trim() != rule.category
            || category != rule.category
            || category.len() > CATEGORY_MAX_BYTES
            || !category.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
            })
        {
            diagnostics.push(Diagnostic::CategoryNotCanonical {
                category: rule.category.clone(),
            });
        }
        if RESERVED_CATEGORIES.contains(&category.as_str()) {
            diagnostics.push(Diagnostic::ReservedCategory {
                category: rule.category.clone(),
            });
        }
    }

    if rule.severity != "critical" && rule.severity != "warning" {
        diagnostics.push(Diagnostic::SeverityVocabulary {
            severity: rule.severity.clone(),
        });
    }

    if rule.name.trim().is_empty() {
        diagnostics.push(Diagnostic::EmptyName);
    }
    let name_bytes = rule.name.len();
    if name_bytes > NAME_MAX_BYTES {
        diagnostics.push(Diagnostic::NameTooLong { bytes: name_bytes });
    }
    if rule.name.chars().any(|character| character.is_control()) {
        diagnostics.push(Diagnostic::NameControlChar);
    }
    if rule.description.trim().is_empty() {
        diagnostics.push(Diagnostic::EmptyDescription);
    }
    let description_bytes = rule.description.len();
    if description_bytes > DESCRIPTION_MAX_BYTES {
        diagnostics.push(Diagnostic::DescriptionTooLong {
            bytes: description_bytes,
        });
    }
    if rule
        .description
        .chars()
        .any(|character| character.is_control())
    {
        diagnostics.push(Diagnostic::DescriptionControlChar);
    }

    if !(WAF_FEED_SORT_ORDER_MIN..=WAF_FEED_SORT_ORDER_MAX).contains(&rule.sort_order) {
        diagnostics.push(Diagnostic::SortOrderOutOfRange {
            sort_order: rule.sort_order,
        });
    }

    // §7 L4: a CVE rule without an advisory (or with an id-less
    // advisory) leaves the consumer metadata merge dormant — the
    // requirement rides the id namespace every feed rule carries.
    if rule.id.starts_with("vp-cve-") {
        match &rule.advisory {
            None => diagnostics.push(Diagnostic::AdvisoryRequired {
                id: rule.id.clone(),
            }),
            Some(advisory) if advisory.cve_ids.is_empty() => {
                diagnostics.push(Diagnostic::CveIdsEmpty {
                    id: rule.id.clone(),
                });
            }
            Some(advisory) => diagnostics.extend(lint_advisory(advisory)),
        }
    } else if let Some(advisory) = &rule.advisory {
        diagnostics.extend(lint_advisory(advisory));
    }
    diagnostics
}

/// The advisory layer: canonical CVE ids, https-only references, the
/// re-serialization ceiling, and the source-note ceiling (design §3.4
/// rules 2 and 5).
pub fn lint_advisory(advisory: &WafFeedAdvisory) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for cve in &advisory.cve_ids {
        // STRICT canonical check: [`canonical_cve_id`] normalizes (trims
        // and uppercases) before validating, but the consumer never
        // case-normalizes advisory ids (§3.4 rule 5) — an id only
        // passes when it is ALREADY the canonical spelling, i.e. when
        // canonicalization would return it unchanged.
        if canonical_cve_id(cve).as_deref() != Some(cve.as_str()) {
            diagnostics.push(Diagnostic::CveIdFormat { cve: cve.clone() });
        }
    }
    for reference in &advisory.references {
        if !reference.starts_with("https://") {
            diagnostics.push(Diagnostic::ReferenceScheme {
                reference: reference.clone(),
            });
        }
    }
    if let Ok(bytes) = serde_json::to_vec(advisory) {
        if bytes.len() > ADVISORY_MAX_BYTES {
            diagnostics.push(Diagnostic::AdvisoryTooLarge { bytes: bytes.len() });
        }
    }
    let note_bytes = advisory.source_note.len();
    if note_bytes > SOURCE_NOTE_MAX_BYTES {
        diagnostics.push(Diagnostic::SourceNoteTooLong { bytes: note_bytes });
    }
    // The consumer trims source_note and refuses control characters;
    // the signed bytes must already be canonical (§3.4 rule 2).
    if advisory.source_note.trim() != advisory.source_note
        || advisory
            .source_note
            .chars()
            .any(|character| character.is_control())
    {
        diagnostics.push(Diagnostic::SourceNoteNotCanonical);
    }
    diagnostics
}

/// The §3.4 rules 5/8 assertion the gate runs at its end, on the
/// rule set the tree would assemble (before any codec assembly work):
/// a thin wrapper over the codec's own `publish_gate` — the same
/// function the assembly pipeline will run. The payload header here is
/// synthetic (sequence 0, zero timestamps): `publish_gate` is
/// rule-set-level by contract, and the real header is the assembly
/// seat's job.
pub fn publish_gate_check(
    rules: &[WafFeedRule],
) -> Result<(), waf_bundle_encoder::PublishRejection> {
    let payload = WafFeedPayload {
        format_version: 1,
        sequence: 0,
        version: String::new(),
        published_at: 0,
        expires_at: 0,
        rules: rules.to_owned(),
    };
    publish_gate(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_rule() -> WafFeedRule {
        WafFeedRule {
            id: "vp-cve-2024-12345".to_owned(),
            name: "Elementor upload traversal".to_owned(),
            category: "cve-virtual-patch".to_owned(),
            pattern_type: ManagedWafPatternType::RequestUri,
            pattern: "wp-content/plugins/elementor/".to_owned(),
            severity: "warning".to_owned(),
            description: "Detects the Elementor upload-path traversal variant.".to_owned(),
            sort_order: 1_000_000,
            advisory: Some(WafFeedAdvisory {
                cve_ids: vec!["CVE-2024-12345".to_owned()],
                cvss: None,
                affected: None,
                references: Vec::new(),
                source_note: String::new(),
            }),
        }
    }

    #[test]
    fn base_rule_is_clean_and_advisory_checks_pass() {
        assert!(lint_rule(&base_rule()).is_empty());
    }

    #[test]
    fn c_p2_1_advisory_is_required_for_cve_rules() {
        // §7 L4 (M3): an advisory-less vp-cve-* rule is refused, and so
        // is an advisory shell with no ids.
        let mut rule = base_rule();
        rule.advisory = None;
        assert_eq!(
            lint_rule(&rule),
            vec![Diagnostic::AdvisoryRequired {
                id: "vp-cve-2024-12345".to_owned()
            }]
        );
        let mut rule = base_rule();
        rule.advisory = Some(WafFeedAdvisory {
            cve_ids: Vec::new(),
            cvss: None,
            affected: None,
            references: Vec::new(),
            source_note: String::new(),
        });
        assert_eq!(
            lint_rule(&rule),
            vec![Diagnostic::CveIdsEmpty {
                id: "vp-cve-2024-12345".to_owned()
            }]
        );
    }

    #[test]
    fn c_p2_1_consumer_canonicalization_contract_is_mirrored() {
        // M4: category canonical spelling + charset, name/description
        // ceilings and control characters, sort_order window,
        // source_note canonical spelling — the consumer refuses the
        // WHOLE bundle over any of these, so the lint refuses the rule.
        let mut rule = base_rule();
        rule.category = "CVE Virtual Patch".to_owned();
        assert_eq!(
            lint_rule(&rule),
            vec![Diagnostic::CategoryNotCanonical {
                category: "CVE Virtual Patch".to_owned()
            }]
        );

        let mut rule = base_rule();
        rule.category = "cve virtual patch!".to_owned();
        assert!(
            lint_rule(&rule).contains(&Diagnostic::CategoryNotCanonical {
                category: "cve virtual patch!".to_owned()
            })
        );

        let mut rule = base_rule();
        rule.name = "x".repeat(129);
        assert_eq!(
            lint_rule(&rule),
            vec![Diagnostic::NameTooLong { bytes: 129 }]
        );

        let mut rule = base_rule();
        rule.name = "traversal\u{7}name".to_owned();
        assert!(lint_rule(&rule).contains(&Diagnostic::NameControlChar));

        let mut rule = base_rule();
        rule.description = "x".repeat(513);
        assert_eq!(
            lint_rule(&rule),
            vec![Diagnostic::DescriptionTooLong { bytes: 513 }]
        );

        let mut rule = base_rule();
        rule.description = "detects\u{7}traversal".to_owned();
        assert!(lint_rule(&rule).contains(&Diagnostic::DescriptionControlChar));

        for order in [999_999, 2_000_000] {
            let mut rule = base_rule();
            rule.sort_order = order;
            assert!(
                lint_rule(&rule).contains(&Diagnostic::SortOrderOutOfRange { sort_order: order }),
                "sort_order {order} must refuse"
            );
        }

        let mut rule = base_rule();
        rule.advisory = Some(WafFeedAdvisory {
            cve_ids: vec!["CVE-2024-12345".to_owned()],
            cvss: None,
            affected: None,
            references: Vec::new(),
            source_note: " padded ".to_owned(),
        });
        assert_eq!(lint_rule(&rule), vec![Diagnostic::SourceNoteNotCanonical]);
    }

    #[test]
    fn seed_blocklist_is_consumed_not_reimplemented() {
        // C-P2-3's in-code proof: the lint compares against the codec's
        // own parsed seed asset; this module contains no SQL parsing.
        let blocklist = seed_blocklist();
        assert!(!blocklist.is_empty());
        let (seed_type, seed_pattern) = &blocklist[0];
        let mut rule = base_rule();
        rule.pattern_type = ManagedWafPatternType::QueryString;
        rule.pattern = seed_pattern.clone();
        assert_eq!(
            wire_pattern_type(schema_pattern_type(rule.pattern_type)),
            seed_type.as_str(),
            "the wire spelling must match the codec's for the compare to bite"
        );
        assert!(lint_rule(&rule).contains(&Diagnostic::SeedDuplicate {
            pattern_type: seed_type.clone(),
            pattern: seed_pattern.clone(),
        }));
    }

    #[test]
    fn publish_gate_check_passes_a_clean_set_and_refuses_bad_cves() {
        let clean = base_rule();
        assert!(publish_gate_check(std::slice::from_ref(&clean)).is_ok());
        let mut bad = clean;
        bad.advisory = Some(WafFeedAdvisory {
            cve_ids: vec!["cve-2024-1234".to_owned()],
            cvss: None,
            affected: None,
            references: Vec::new(),
            source_note: String::new(),
        });
        assert!(publish_gate_check(&[bad]).is_err());
    }
}
