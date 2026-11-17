//! The curation repository's serde schemas (issue #1745 P-P1, design
//! §3.2) — exactly the shapes the interface fixes, nothing more.
//!
//! ```text
//! candidates/<cve>.json        {cve, kev, cvss, tokens[], candidates[...], generated_at}
//! corpus/exploits/<rule>.json  {method, path, query, user_agent, body?}
//! corpus/benign/*.json         same request shape
//! ```
//!
//! Two laws live on [`CandidateFile`], both acceptance C-P1-1:
//! [`CandidateFile::enforce_provenance`] force-flips any candidate
//! without a provenance to `excluded_no_provenance` (the pipeline never
//! lets a source-less literal reach approval), and
//! [`CandidateFile::approvable`] enumerates only proposed candidates
//! that DO carry one — the approval target the P-P2 gate and the
//! curator's PR flow consume.
//!
//! A candidate's `provenance` is an OPEN enum (new origins join as new
//! variants without changing the file shape); every variant names where
//! the literal came from — which upstream field, which PoC link — per
//! design D2 rule 4. `Manual` is the curator's own addition marker.

use serde::{Deserialize, Serialize};

/// The five wire `pattern_type` values the consumer's feed model
/// accepts (UVPB v1 spec §3) — candidate files reuse the vocabulary so
/// a proposed literal's target field is unambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternType {
    QueryString,
    RequestUri,
    UserAgent,
    RequestMethod,
    RequestBody,
}

/// The feed rule severity vocabulary (UVPB v1 spec §2). The generator's
/// mapping ([`crate::generator::severity_of`]) produces only
/// `critical` (KEV or CVSS ≥ 9.0) or `warning`; `info` exists for the
/// wire vocabulary's completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Where a candidate literal came from (design D2 rule 4: every
/// candidate names its origin — which upstream field or which PoC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    /// Derived from an NVD CVE record's CPE criteria field. `raw` keeps
    /// the full criteria string so a curator can re-trace the record.
    NvdCpe { field: String, raw: String },
    /// Derived from a GHSA `affected[].package` field (aux source, v1
    /// pipeline reserved).
    GhsaAffected { field: String, raw: String },
    /// Derived from a producer relation-table row: `product` is the
    /// token that keyed the row, `entrypoint` the URI the table maps it
    /// to.
    RelationTable { product: String, entrypoint: String },
    /// Derived from a KEV entry's metadata field (e.g. the
    /// `vendorProject`/`product` pair).
    KevMetadata { field: String },
    /// A PoC/exploit-tagged reference link recorded as an extraction
    /// HINT: `literal` holds the URL until manual curation replaces it
    /// with a string observed in the PoC (v1 does no network
    /// extraction — design D2 rule 3's switch is off by default).
    PocReference { url: String, tag: String },
    /// The curator added the literal by hand (the approval PR's own
    /// edit, not the generator).
    Manual,
}

/// A candidate's pipeline status. Only `proposed` candidates with a
/// provenance are approvable; `approved` is a MANUAL transition made in
/// the curation PR (no automatic path exists — design D2's hard
/// separation).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    /// Awaiting curator review.
    #[default]
    Proposed,
    /// Force-excluded because no provenance could be attached
    /// (C-P1-1). Never approvable.
    ExcludedNoProvenance,
    /// Approved by the curator in a curation PR.
    Approved,
}

/// One proposed literal in a `candidates/<cve>.json` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// The literal string. For [`Provenance::PocReference`] hints this
    /// is the reference URL pending manual curation.
    pub literal: String,
    pub pattern_type: PatternType,
    /// Absent ONLY for candidates that failed provenance enforcement —
    /// such candidates are force-excluded and never approvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    #[serde(default)]
    pub status: CandidateStatus,
}

/// The whole `candidates/<cve>.json` file (interface schema, field
/// order fixed by this declaration order). `PartialEq` (not `Eq`):
/// the CVSS score is an `f64`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateFile {
    /// Canonical uppercase CVE id (the file name stem).
    pub cve: String,
    /// KEV membership at generation time.
    pub kev: bool,
    /// The NVD record's best CVSS base score, when one was published.
    pub cvss: Option<f64>,
    /// Every product token extracted from the record's CPE criteria and
    /// the KEV entry, mapped or not — the curator's extraction trace.
    pub tokens: Vec<String>,
    pub candidates: Vec<Candidate>,
    /// Generation unix second (the injected clock's read).
    pub generated_at: i64,
}

impl CandidateFile {
    /// C-P1-1 enforcement: every candidate whose `provenance` is `None`
    /// is force-flipped to [`CandidateStatus::ExcludedNoProvenance`] —
    /// including ones already marked `approved` — and the flip count is
    /// returned. The intake write path runs this before persisting, so
    /// a stored file never contains an approvable provenance-less
    /// candidate.
    pub fn enforce_provenance(&mut self) -> usize {
        let mut flipped = 0;
        for candidate in &mut self.candidates {
            if candidate.provenance.is_none()
                && candidate.status != CandidateStatus::ExcludedNoProvenance
            {
                candidate.status = CandidateStatus::ExcludedNoProvenance;
                flipped += 1;
            }
        }
        flipped
    }

    /// The approval target: candidates that are `proposed` AND carry a
    /// provenance. This filter is the machine half of C-P1-1; the
    /// curator's judgment is the other half.
    pub fn approvable(&self) -> impl Iterator<Item = &Candidate> + '_ {
        self.candidates.iter().filter(|candidate| {
            candidate.status == CandidateStatus::Proposed && candidate.provenance.is_some()
        })
    }
}

/// One corpus request — the shape both `corpus/exploits/<rule>.json`
/// and `corpus/benign/*.json` use (the P-P2 two-way corpus gate's
/// input; the gate's matcher mirrors the consumer's semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub user_agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// P-P2 benign-corpus provenance: where the request shape came from
    /// (an e2e scenario script, the ops load driver, or a handwritten
    /// representative). Annotation only — the matcher never reads it,
    /// and absent on exploit samples (their file NAME is the rule id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Canonicalizes a CVE id to the producer's only accepted spelling:
/// uppercase `CVE-YYYY-NNNN[N]` (4-7 serial digits — the same shape the
/// codec's publish gate enforces on `advisory.cve_ids`). Returns `None`
/// for anything else; the intake refuses to mint a candidate file under
/// a non-canonical id.
pub fn canonical_cve_id(raw: &str) -> Option<String> {
    let id = raw.trim().to_ascii_uppercase();
    let rest = id.strip_prefix("CVE-")?;
    let (year, serial) = rest.split_once('-')?;
    let canonical = year.len() == 4
        && year.bytes().all(|byte| byte.is_ascii_digit())
        && (4..=7).contains(&serial.len())
        && serial.bytes().all(|byte| byte.is_ascii_digit());
    canonical.then_some(id)
}
