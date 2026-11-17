//! The curation gate (issue #1745 P-P2, design §5's 3-layer defense,
//! layers 1+2): the static lint and the two-way corpus gate every
//! approval PR and every publication assembly must clear.
//!
//! - [`gate::lint`]: the deterministic static lint — legal pattern
//!   bounds and spelling, the standalone common-word ban,
//!   `request_method` token fitness, id/category/severity format,
//!   advisory ceilings, and the codec-consumed seed duplicate check
//!   (no seed source is re-implemented here — C-P2-3).
//! - [`gate::corpus`]: the two-way corpus gate — detection duty per
//!   rule (`corpus/exploits/<rule-id>.json` must exist and MATCH under
//!   the consumer's semantics), false-positive duty over
//!   `corpus/benign/` (zero matches, hard 200-request floor), plus the
//!   whole-tree [`gate::corpus::run_gate`] report the CLI prints.
//! - [`gate::matcher`]: the consumer-verdict mirror — the per-request
//!   match forms built exactly the way `config-model`'s WAF builds
//!   them (its public `waf_match_forms` + the private
//!   `waf_unicode_forms` twin composed from the same
//!   `unicode-normalization`), so a corpus verdict here is a consumer
//!   verdict.

pub mod corpus;
pub mod lint;
pub mod matcher;
