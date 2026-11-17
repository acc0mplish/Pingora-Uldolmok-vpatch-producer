//! The intake CLI (issue #1745 P-P1, design D2): candidate generation
//! against the KEV catalog and the NVD CVE API 2.0 under the shared
//! budget law.
//!
//! ```text
//! intake --out candidates/ --cve CVE-2024-XXXX   # one CVE
//! intake --out candidates/ --kev [--dry-run]     # KEV snapshot sweep
//! ```
//!
//! Laws this binary keeps (all of them delegated to the lib so the
//! tests hold for the CLI too):
//! - Absence-of-write failure law: a CVE whose NVD fetch or parse
//!   fails gets NO candidate file this run — like the consumer's LKG
//!   preservation, the absence of a write is the safe outcome; the
//!   next run retries it.
//! - Budget stop, not budget sleep: a spent daily ceiling ends the
//!   sweep with a resume instant instead of sleeping to UTC midnight
//!   (single-CVE mode reports it and exits non-zero).
//! - Idempotency: the sweep skips CVEs that already have a candidate
//!   file, so a multi-day sweep makes progress under the 1024/day
//!   ceiling instead of re-fetching the same prefix forever.
//! - Every written file passes [`enforce_provenance`] first (C-P1-1 at
//!   the write boundary).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use uldolmok_vpatch_pipeline::budget::{Origin, RateBudgets};
use uldolmok_vpatch_pipeline::clock::{StdClock, UvpbClock};
use uldolmok_vpatch_pipeline::generator::{generate_candidate_file, severity_of};
use uldolmok_vpatch_pipeline::intake::{
    fetch_kev_catalog, fetch_nvd_cve, Fetcher, HttpFetcher, IntakeError,
};
use uldolmok_vpatch_pipeline::schema::{canonical_cve_id, CandidateFile};

const USAGE: &str = "usage: intake --out <candidates-dir> (--cve <CVE-ID> | --kev) [--dry-run]";

struct Args {
    out: PathBuf,
    mode: Mode,
    dry_run: bool,
}

enum Mode {
    SingleCve(String),
    KevSnapshot,
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let fetcher = match HttpFetcher::new() {
        Ok(fetcher) => fetcher,
        Err(detail) => {
            eprintln!("intake: {detail}");
            return ExitCode::from(1);
        }
    };
    let clock = StdClock;
    let mut budgets = RateBudgets::new();
    let started = Instant::now();
    let failed = match &args.mode {
        Mode::SingleCve(raw) => run_single(&args, &fetcher, &mut budgets, &clock, raw),
        Mode::KevSnapshot => run_kev_snapshot(&args, &fetcher, &mut budgets, &clock),
    };
    println!(
        "intake: finished in {}s (fetch errors: {failed})",
        started.elapsed().as_secs()
    );
    if failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn parse_args<I: Iterator<Item = String>>(args: I) -> Result<Args, String> {
    let mut out: Option<PathBuf> = None;
    let mut cve: Option<String> = None;
    let mut kev = false;
    let mut dry_run = false;
    let mut iter = args;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--out" => {
                out = Some(PathBuf::from(
                    iter.next().ok_or("--out needs a directory argument")?,
                ));
            }
            "--cve" => {
                cve = Some(iter.next().ok_or("--cve needs a CVE id argument")?);
            }
            "--kev" => kev = true,
            "--dry-run" => dry_run = true,
            _ => return Err(format!("intake: unrecognized argument {arg}")),
        }
    }
    let out = out.ok_or("intake: --out is required")?;
    let mode = match (cve, kev) {
        (Some(raw), false) => Mode::SingleCve(raw),
        (None, true) => Mode::KevSnapshot,
        _ => return Err("intake: pass exactly one of --cve <ID> or --kev".to_owned()),
    };
    Ok(Args { out, mode, dry_run })
}

fn run_single(
    args: &Args,
    fetcher: &dyn Fetcher,
    budgets: &mut RateBudgets,
    clock: &dyn UvpbClock,
    raw_cve: &str,
) -> usize {
    let Some(cve) = canonical_cve_id(raw_cve) else {
        eprintln!("intake: {raw_cve:?} is not a canonical CVE id (CVE-YYYY-NNNN[N])");
        return 1;
    };
    // KEV membership: one catalog fetch also hands us the entry's
    // vendor/product pair for token extraction.
    let entries = match fetch_kev_catalog(fetcher, budgets, clock) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("intake: {error}");
            return 1;
        }
    };
    let kev_entry = entries.iter().find(|entry| entry.cve_id == cve);
    let nvd = match fetch_nvd_cve(fetcher, budgets, clock, &cve) {
        Ok(nvd) => nvd,
        Err(IntakeError::DailyBudgetExhausted {
            origin,
            resume_at_unix,
        }) => {
            eprintln!(
                "intake: daily budget spent on {}; resume at unix {resume_at_unix}",
                origin.as_str()
            );
            return 1;
        }
        Err(error) => {
            eprintln!("intake: {error}");
            return 1;
        }
    };
    let mut file = generate_candidate_file(
        &cve,
        kev_entry.is_some(),
        nvd.as_ref(),
        kev_entry,
        clock.now_unix(),
    );
    persist(args, &mut file);
    0
}

fn run_kev_snapshot(
    args: &Args,
    fetcher: &dyn Fetcher,
    budgets: &mut RateBudgets,
    clock: &dyn UvpbClock,
) -> usize {
    let entries = match fetch_kev_catalog(fetcher, budgets, clock) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("intake: {error}");
            return 1;
        }
    };
    let total = entries.len();
    let mut generated = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    for entry in &entries {
        let path = args.out.join(format!("{}.json", entry.cve_id));
        if path.exists() {
            skipped += 1;
            continue;
        }
        let nvd = match fetch_nvd_cve(fetcher, budgets, clock, &entry.cve_id) {
            Ok(nvd) => nvd,
            Err(IntakeError::DailyBudgetExhausted {
                origin,
                resume_at_unix,
            }) => {
                let remaining = total - generated - skipped - failed;
                println!(
                    "intake: daily budget spent on {}; resume at unix {} (remaining CVEs: {remaining})",
                    origin.as_str(),
                    resume_at_unix
                );
                break;
            }
            Err(error) => {
                eprintln!("intake: {error} — no candidate written for this run");
                failed += 1;
                continue;
            }
        };
        let mut file = generate_candidate_file(
            &entry.cve_id,
            true,
            nvd.as_ref(),
            Some(entry),
            clock.now_unix(),
        );
        persist(args, &mut file);
        generated += 1;
    }
    let now = clock.now_unix();
    println!(
        "intake: [kev-snapshot] entries={total} generated={generated} skipped={skipped} failed={failed} nvd_used_today={}",
        budgets.daily_used(Origin::Nvd, now)
    );
    failed
}

/// The C-P1-1 write boundary: enforce provenance on the file itself,
/// then write (or summarize for a dry run). A flip count above zero
/// here would mean the generator emitted a provenance-less candidate —
/// the report line makes that visible instead of silently normalizing.
fn persist(args: &Args, file: &mut CandidateFile) {
    let flipped = file.enforce_provenance();
    let approvable = file.approvable().count();
    let severity = severity_of(file.kev, file.cvss);
    println!(
        "intake: {} kev={} cvss={:?} severity={} tokens={} candidates={} approvable={} excluded_no_provenance_flips={flipped}",
        file.cve,
        file.kev,
        file.cvss,
        serde_json::to_string(&severity).unwrap_or_default(),
        file.tokens.len(),
        file.candidates.len(),
        approvable
    );
    if args.dry_run {
        return;
    }
    if flipped > 0 {
        eprintln!(
            "intake: {} had {flipped} candidate(s) force-excluded at the write boundary",
            file.cve
        );
    }
    if let Err(error) = std::fs::create_dir_all(&args.out) {
        eprintln!("intake: creating {}: {error}", args.out.display());
        return;
    }
    let path = args.out.join(format!("{}.json", file.cve));
    let mut bytes = match serde_json::to_vec_pretty(file) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("intake: serializing {}: {error}", file.cve);
            return;
        }
    };
    bytes.push(b'\n');
    if let Err(error) = std::fs::write(&path, bytes) {
        eprintln!("intake: writing {}: {error}", path.display());
    }
}
