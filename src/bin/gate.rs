//! The curation gate CLI (issue #1745 P-P2): the whole-tree check a
//! curation PR and the assembly pipeline run before anything else —
//! static lint over every rule, the two-way corpus gate, the
//! approvable-candidate lint, and the codec's `publish_gate`
//! assertion (design §5 layers 1+2, §3.4 rules 5/8).
//!
//! ```text
//! gate [--root <dir>] [--explain <diagnostic-code>]
//! ```
//!
//! Exit law: 0 green, 1 any diagnostic or candidate warning, 2 usage
//! or filesystem error. Diagnostics print one human-readable line
//! each; `--explain <code>` prints the code's rationale instead.

use std::path::PathBuf;
use std::process::ExitCode;

use uldolmok_vpatch_pipeline::gate::corpus::{run_gate, CorpusDiagnostic, BENIGN_MIN};
use uldolmok_vpatch_pipeline::gate::lint::Diagnostic;

const USAGE: &str = "usage: gate [--root <dir>] [--explain <diagnostic-code>]";

enum Invocation {
    Check { root: PathBuf },
    Explain(String),
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Invocation, String> {
    let mut root = PathBuf::from(".");
    let mut explain: Option<String> = None;
    let mut arguments = args;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--root" => {
                root = PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--root needs a directory argument".to_owned())?,
                );
            }
            "--explain" => {
                explain = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--explain needs a diagnostic code".to_owned())?,
                );
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(match explain {
        Some(code) => Invocation::Explain(code),
        None => Invocation::Check { root },
    })
}

fn explain(code: &str) -> bool {
    let lint_explained = Diagnostic::explain(code);
    let corpus_explained = CorpusDiagnostic::explain(code);
    match (lint_explained, corpus_explained) {
        (Some(text), _) | (_, Some(text)) => {
            println!("{code}: {text}");
            true
        }
        (None, None) => false,
    }
}

fn print_report(report: &uldolmok_vpatch_pipeline::gate::corpus::GateReport) {
    println!(
        "gate: {} rule(s), {} benign corpus file(s), floor {BENIGN_MIN}",
        report.rules_checked, report.benign_count
    );
    for (file, diagnostics) in &report.rule_diagnostics {
        for diagnostic in diagnostics {
            println!(
                "LINT  {file}: {} [{code}]",
                diagnostic,
                code = diagnostic.code()
            );
        }
    }
    for diagnostic in &report.corpus_diagnostics {
        println!("CORPUS {} [{code}]", diagnostic, code = diagnostic.code());
    }
    for warning in &report.candidate_warnings {
        for diagnostic in &warning.diagnostics {
            println!(
                "CAND  {} literal {:?}: {} [{code}]",
                warning.file,
                warning.literal,
                diagnostic,
                code = diagnostic.code()
            );
        }
    }
    if let Some(rejection) = &report.publish_rejection {
        println!("PUBLISH {rejection} [publish_gate]");
    }
    if report.is_green() {
        println!("gate: GREEN");
    } else {
        println!("gate: REFUSED");
    }
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
    match invocation {
        Invocation::Explain(code) => {
            if explain(&code) {
                ExitCode::SUCCESS
            } else {
                eprintln!("unknown diagnostic code {code:?}");
                ExitCode::from(2)
            }
        }
        Invocation::Check { root } => {
            if !root.is_dir() {
                eprintln!("root {:?} is not a directory", root);
                return ExitCode::from(2);
            }
            let report = run_gate(&root);
            print_report(&report);
            if report.is_green() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
    }
}
