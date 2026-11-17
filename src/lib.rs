//! uldolmok-vpatch-pipeline — the UVPB v1 producer pipeline's P-P1
//! half (issue #1745, design `docs/task-id/i1745-bundle-producer/` D2):
//! KEV/NVD intake, rate budgeting, and automatic candidate generation
//! in the producer repository's curation workspace.
//!
//! Seat map (design §2 D1/D2): this crate is the producer repo's
//! workspace; the codec (`waf-bundle-encoder`) and the consumer's
//! config model are git dependencies pinned at the same rev `pin.rev`
//! records — the P-P2 gate (`gate`) consumes the codec's
//! `seed_blocklist()`/`publish_gate()` and the consumer's public
//! `config_model::waf_match_forms` directly from those pins. Compiling
//! them here is the standing proof the pinned rev builds and its
//! public API surface is exactly what the gate consumes.
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
//! - [`gate`] (P-P2): the curation gate — the static lint, the
//!   two-way corpus gate (detection duty + false-positive duty over a
//!   ≥200-request honest benign corpus), and the codec
//!   `seed_blocklist()`/`publish_gate()` consumption; the matcher
//!   mirrors the consumer's WAF semantics through the public
//!   `config_model::waf_match_forms` API.

pub mod budget;
pub mod clock;
pub mod gate;
pub mod generator;
pub mod intake;
pub mod schema;
