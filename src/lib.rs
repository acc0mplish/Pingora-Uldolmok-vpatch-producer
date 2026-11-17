//! uldolmok-vpatch-pipeline — the UVPB v1 producer pipeline's P-P1
//! half (issue #1745, design `docs/task-id/i1745-bundle-producer/` D2):
//! KEV/NVD intake, rate budgeting, and automatic candidate generation
//! in the producer repository's curation workspace.
//!
//! Seat map (design §2 D1/D2): this crate is the producer repo's
//! workspace; the codec (`waf-bundle-encoder`, pinned at the same rev
//! `pin.rev` records) is its git dependency — the P-P2 half of the
//! pipeline (the static lint, the two-way corpus gate, and the codec's
//! `seed_blocklist()`/`publish_gate()` consumption) lands on top of
//! this workspace in the next commit. Declaring the codec dependency
//! now is the pin contract seat, and compiling it here is the standing
//! proof the pinned rev builds.
//!
//! The automation boundary is hard (design D2): this crate PROPOSES
//! candidates only. Nothing here approves a literal, writes a rule, or
//! publishes — approval is a human PR (`candidates/` → `rules/`),
//! publication is a separately gated manual workflow. Every generated
//! candidate carries a provenance or is force-excluded
//! (`excluded_no_provenance`), so the approval target
//! ([`schema::CandidateFile::approvable`]) can only contain literals
//! whose origin is traceable.
//!
//! Module map:
//! - [`clock`]: the [`clock::UvpbClock`] seam — all time flows through
//!   it, so budget behavior is virtual-clock testable.
//! - [`budget`]: the per-origin sliding-window budget (5 req / 30 s)
//!   and daily ceiling (≤1024), the producer twin of the consumer
//!   metadata worker's allowance.
//! - [`schema`]: the curation repository's serde schemas
//!   (`candidates/<cve>.json`, corpus request shape) and the
//!   provenance enforcement law (C-P1-1).
//! - [`intake`]: the KEV/NVD fetch + narrow parse (consumer endpoint,
//!   timeout, and byte-ceiling conventions; no consumer code shared).
//! - [`generator`]: D2 rules 1-4 — token extraction, the
//!   relation-table URI hints, PoC reference hints, severity mapping.

pub mod budget;
pub mod clock;
pub mod generator;
pub mod intake;
pub mod schema;
