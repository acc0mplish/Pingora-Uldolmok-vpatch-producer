//! The assembly CLI (issue #1745 P-P3, design §3.3): the whole-curation
//! check (the gate binary's report, called as a LIBRARY function — the
//! gate and assembly share one process face, no subprocess), then the
//! deterministic payload assembly.
//!
//! ```text
//! assemble [--root <dir>] --now <unix>
//!          [--validity-days <n>] [--out <file>] [--sha256-out <file>]
//! ```
//!
//! The injected `--now` (a unix second) is REQUIRED: the version label
//! and the validity window are functions of it, so equal inputs always
//! produce equal bytes (design §3.3 determinism law). Exit law mirrors
//! the gate binary: 0 green, 1 any gate/assembly refusal, 2 usage or
//! filesystem error. stdout's LAST line is the bare payload sha256 hex
//! for machine consumption.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use uldolmok_vpatch_pipeline::assemble::{
    assemble, load_rules, load_state, AssembleError, DEFAULT_VALIDITY_DAYS,
};
use uldolmok_vpatch_pipeline::gate::corpus::{run_gate, BENIGN_MIN};

const USAGE: &str = "usage: assemble [--root <dir>] --now <unix> [--validity-days <n>] [--out <file>] [--sha256-out <file>]";

struct Invocation {
    root: PathBuf,
    now: i64,
    validity_days: i64,
    out: PathBuf,
    sha256_out: Option<PathBuf>,
}

/// Pops the value after `flag` from the collected argument list (the
/// shared `cursor` is the walk state — a helper fn, so there is no
/// closure borrow conflict on the list).
fn take_value(arguments: &[String], cursor: &mut usize, flag: &str) -> Result<String, String> {
    *cursor += 1;
    arguments
        .get(*cursor)
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Invocation, String> {
    let mut root = PathBuf::from(".");
    let mut now: Option<i64> = None;
    let mut validity_days = DEFAULT_VALIDITY_DAYS;
    let mut out: Option<PathBuf> = None;
    let mut sha256_out: Option<PathBuf> = None;
    let arguments: Vec<String> = args.collect();
    let mut cursor: usize = 0;
    while let Some(argument) = arguments.get(cursor) {
        match argument.as_str() {
            "--root" => root = PathBuf::from(take_value(&arguments, &mut cursor, "--root")?),
            "--now" => {
                let value = take_value(&arguments, &mut cursor, "--now")?;
                now = Some(
                    value
                        .parse()
                        .map_err(|_| format!("--now {value:?} is not an integer"))?,
                );
            }
            "--validity-days" => {
                let value = take_value(&arguments, &mut cursor, "--validity-days")?;
                validity_days = value
                    .parse()
                    .map_err(|_| format!("--validity-days {value:?} is not an integer"))?;
            }
            "--out" => out = Some(PathBuf::from(take_value(&arguments, &mut cursor, "--out")?)),
            "--sha256-out" => {
                sha256_out = Some(PathBuf::from(take_value(
                    &arguments,
                    &mut cursor,
                    "--sha256-out",
                )?))
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
        cursor += 1;
    }
    let now =
        now.ok_or("--now is required (the injected clock read; assembly is a function of it)")?;
    let out = out.unwrap_or_else(|| root.join("target/uvpb-payload.json"));
    Ok(Invocation {
        root,
        now,
        validity_days,
        out,
        sha256_out,
    })
}

/// The gate precondition (design §4 step 2): the same whole-tree report
/// the gate binary prints, evaluated in-process. Any diagnostic or
/// publish refusal refuses the assembly.
fn require_gate_green(root: &Path) -> Result<(), String> {
    let report = run_gate(root);
    if report.is_green() {
        println!(
            "gate: GREEN ({} rule(s), {} benign corpus file(s), floor {BENIGN_MIN})",
            report.rules_checked, report.benign_count
        );
        return Ok(());
    }
    println!("gate: REFUSED");
    for (file, diagnostics) in &report.rule_diagnostics {
        for diagnostic in diagnostics {
            println!("LINT  {file}: {diagnostic} [{}]", diagnostic.code());
        }
    }
    for diagnostic in &report.corpus_diagnostics {
        println!("CORPUS {diagnostic} [{}]", diagnostic.code());
    }
    for warning in &report.candidate_warnings {
        for diagnostic in &warning.diagnostics {
            println!(
                "CAND  {} literal {:?}: {diagnostic} [{}]",
                warning.file,
                warning.literal,
                diagnostic.code()
            );
        }
    }
    if let Some(rejection) = &report.publish_rejection {
        println!("PUBLISH {rejection} [publish_gate]");
    }
    Err("the curation gate refused this tree; assembly is refused with it".to_owned())
}

fn run(invocation: &Invocation) -> Result<String, String> {
    if !invocation.root.is_dir() {
        return Err(format!("root {:?} is not a directory", invocation.root));
    }
    require_gate_green(&invocation.root)?;
    let state =
        load_state(&invocation.root.join("state.json")).map_err(|error| error.to_string())?;
    let rules = load_rules(&invocation.root.join("rules")).map_err(|error| error.to_string())?;
    let assembled = assemble(rules, &state, invocation.now, invocation.validity_days)
        .map_err(|error: AssembleError| error.to_string())?;
    if let Some(parent) = invocation.out.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create output directory {:?}: {error}", parent))?;
    }
    std::fs::write(&invocation.out, &assembled.canonical_bytes)
        .map_err(|error| format!("cannot write {:?}: {error}", invocation.out))?;
    println!(
        "assemble: sequence {}, version {}, rule(s) {}, validity {}d",
        assembled.payload.sequence,
        assembled.payload.version,
        assembled.payload.rules.len(),
        invocation.validity_days,
    );
    println!(
        "assemble: payload {} ({} byte(s))",
        invocation.out.display(),
        assembled.canonical_bytes.len()
    );
    println!("assemble: key_id {} (from state)", state.current_key_id);
    if let Some(sha256_out) = &invocation.sha256_out {
        if let Some(parent) = sha256_out.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create directory {:?}: {error}", parent))?;
        }
        std::fs::write(sha256_out, format!("{}\n", assembled.sha256_hex))
            .map_err(|error| format!("cannot write {sha256_out:?}: {error}"))?;
        println!("assemble: sha256 file {}", sha256_out.display());
    }
    Ok(assembled.sha256_hex)
}

fn main() -> ExitCode {
    let invocation = match parse_args(std::env::args().skip(1)) {
        Ok(invocation) => invocation,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&invocation) {
        Ok(sha256_hex) => {
            println!("{sha256_hex}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("assemble: {message}");
            ExitCode::from(1)
        }
    }
}
