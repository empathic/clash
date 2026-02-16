//! clester - Claude Tester
//!
//! End-to-end testing tool for clash. Simulates Claude Code hook invocations
//! by feeding scripted inputs to the clash binary and asserting on outputs.
//!
//! # Usage
//!
//! ```bash
//! # Run a single test script
//! clester run tests/basic_permissions.yaml
//!
//! # Run all test scripts in a directory
//! clester run tests/
//!
//! # Run with verbose output
//! clester run -v tests/
//!
//! # Validate a test script without running
//! clester validate tests/basic_permissions.yaml
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

mod assertions;
mod environment;
mod runner;
mod script;

use assertions::check;
use environment::TestEnvironment;
use runner::{find_clash_binary, run_command, run_step};
use script::TestScript;

#[derive(Parser, Debug)]
#[command(name = "clester")]
#[command(about = "End-to-end testing tool for clash")]
#[command(
    long_about = "Simulates Claude Code hook invocations against the clash binary and validates behavior using scripted test scenarios."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run one or more test scripts
    Run {
        /// Path to a test script (.yaml) or directory of scripts
        path: PathBuf,

        /// Verbose output: show stdout/stderr from clash
        #[arg(short, long)]
        verbose: bool,

        /// Path to the clash binary (auto-detected if not specified)
        #[arg(long)]
        clash_bin: Option<PathBuf>,
    },

    /// Validate test scripts without executing
    Validate {
        /// Path to a test script (.yaml) or directory of scripts
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            path,
            verbose,
            clash_bin,
        } => match cmd_run(&path, verbose, clash_bin.as_deref()) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(e) => {
                eprintln!("error: {:#}", e);
                ExitCode::FAILURE
            }
        },
        Commands::Validate { path } => match cmd_validate(&path) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(e) => {
                eprintln!("error: {:#}", e);
                ExitCode::FAILURE
            }
        },
    }
}

/// Run test scripts and return whether all passed.
fn cmd_run(path: &Path, verbose: bool, clash_bin: Option<&Path>) -> Result<bool> {
    let clash_bin = match clash_bin {
        Some(p) => p.to_path_buf(),
        None => find_clash_binary()?,
    };

    eprintln!("using clash binary: {}", clash_bin.display());

    let scripts = collect_scripts(path)?;
    if scripts.is_empty() {
        bail!("no test scripts found at {}", path.display());
    }

    eprintln!("found {} test script(s)\n", scripts.len());

    let mut total_passed = 0;
    let mut total_failed = 0;
    let mut total_steps = 0;
    let mut all_passed = true;

    for script_path in &scripts {
        let script = TestScript::from_file(script_path)
            .with_context(|| format!("failed to parse {}", script_path.display()))?;

        eprintln!("--- {} ({}) ---", script.meta.name, script_path.display());

        let env = TestEnvironment::setup(&script.settings, script.clash.as_ref())
            .context("failed to set up test environment")?;

        let mut script_passed = true;

        for (i, step) in script.steps.iter().enumerate() {
            total_steps += 1;
            let step_label = format!("  [{}] {}", i + 1, step.name);

            let result = if let Some(ref cmd) = step.command {
                run_command(&clash_bin, &env, cmd)
            } else {
                run_step(&clash_bin, &env, step)
            };
            match result {
                Ok(result) => {
                    let assertion = check(&step.expect, &result);

                    if assertion.passed {
                        total_passed += 1;
                        eprintln!("{}  PASS", step_label);
                    } else {
                        total_failed += 1;
                        script_passed = false;
                        all_passed = false;
                        eprintln!("{}  FAIL", step_label);
                        for failure in &assertion.failures {
                            eprintln!("    - {}", failure);
                        }
                    }

                    if verbose {
                        eprintln!("    exit_code: {}", result.exit_code);
                        if !result.stdout.is_empty() {
                            eprintln!("    stdout: {}", result.stdout.trim());
                        }
                        if !result.stderr.is_empty() {
                            eprintln!("    stderr: {}", result.stderr.trim());
                        }
                    }
                }
                Err(e) => {
                    total_failed += 1;
                    script_passed = false;
                    all_passed = false;
                    eprintln!("{}  ERROR: {:#}", step_label, e);
                }
            }
        }

        if script_passed {
            eprintln!("  result: PASS\n");
        } else {
            eprintln!("  result: FAIL\n");
        }
    }

    eprintln!("========================================");
    eprintln!(
        "total: {} steps, {} passed, {} failed",
        total_steps, total_passed, total_failed
    );

    if all_passed {
        eprintln!("result: ALL PASSED");
    } else {
        eprintln!("result: SOME FAILED");
    }

    Ok(all_passed)
}

/// Validate test scripts without running them.
fn cmd_validate(path: &Path) -> Result<bool> {
    let scripts = collect_scripts(path)?;
    if scripts.is_empty() {
        bail!("no test scripts found at {}", path.display());
    }

    let mut all_valid = true;

    for script_path in &scripts {
        match TestScript::from_file(script_path) {
            Ok(script) => {
                eprintln!(
                    "VALID: {} ({} steps) - {}",
                    script.meta.name,
                    script.steps.len(),
                    script_path.display()
                );

                // Validate steps
                let errors = script.validate();
                for e in &errors {
                    eprintln!("  WARNING: {}", e);
                }

                for (i, step) in script.steps.iter().enumerate() {
                    // Tool-related hooks should have tool_name
                    if let Some(ref hook) = step.hook
                        && matches!(
                            hook.as_str(),
                            "pre-tool-use" | "post-tool-use" | "permission-request"
                        )
                        && step.tool_name.is_none()
                    {
                        eprintln!(
                            "  WARNING: step {} ({}) is a tool hook but has no tool_name",
                            i + 1,
                            hook
                        );
                    }
                }
            }
            Err(e) => {
                all_valid = false;
                eprintln!("INVALID: {} - {:#}", script_path.display(), e);
            }
        }
    }

    Ok(all_valid)
}

/// Collect test script paths from a file or directory.
fn collect_scripts(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    if path.is_dir() {
        let mut scripts = Vec::new();
        for entry in std::fs::read_dir(path)
            .with_context(|| format!("failed to read directory {}", path.display()))?
        {
            let entry = entry?;
            let p = entry.path();
            if p.extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                scripts.push(p);
            }
        }
        scripts.sort();
        return Ok(scripts);
    }

    bail!("{} is neither a file nor a directory", path.display());
}
