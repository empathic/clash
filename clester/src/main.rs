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
//!
//! # Run with 4 parallel jobs
//! clester run -j 4 tests/
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rayon::prelude::*;

mod assertions;
mod environment;
mod runner;
mod script;

use assertions::check;
use environment::TestEnvironment;
use runner::{find_clash_binary, run_command, run_shell, run_step};
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

        /// Number of parallel jobs (0 = auto, 1 = serial)
        #[arg(short = 'j', long = "jobs", default_value = "0")]
        jobs: usize,
    },

    /// Validate test scripts without executing
    Validate {
        /// Path to a test script (.yaml) or directory of scripts
        path: PathBuf,
    },
}

/// Result of executing a single test script.
struct ScriptResult {
    script_name: String,
    script_path: String,
    step_results: Vec<StepOutcome>,
}

/// Outcome of a single step within a script.
struct StepOutcome {
    step_name: String,
    passed: bool,
    failures: Vec<String>,
    verbose_output: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            path,
            verbose,
            clash_bin,
            jobs,
        } => match cmd_run(&path, verbose, clash_bin.as_deref(), jobs) {
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

/// Execute a single test script and return a structured result.
///
/// Never panics — all errors are captured as step failures.
fn run_script(script_path: &Path, clash_bin: &Path, verbose: bool) -> ScriptResult {
    let script_path_str = script_path.display().to_string();

    let script = match TestScript::from_file(script_path) {
        Ok(s) => s,
        Err(e) => {
            return ScriptResult {
                script_name: script_path_str.clone(),
                script_path: script_path_str,
                step_results: vec![StepOutcome {
                    step_name: "parse".into(),
                    passed: false,
                    failures: vec![format!("failed to parse script: {:#}", e)],
                    verbose_output: None,
                }],
            };
        }
    };

    let env = match TestEnvironment::setup(&script.settings, script.clash.as_ref()) {
        Ok(e) => e,
        Err(e) => {
            return ScriptResult {
                script_name: script.meta.name.clone(),
                script_path: script_path_str,
                step_results: vec![StepOutcome {
                    step_name: "setup".into(),
                    passed: false,
                    failures: vec![format!("failed to set up test environment: {:#}", e)],
                    verbose_output: None,
                }],
            };
        }
    };

    let mut step_results = Vec::with_capacity(script.steps.len());

    for (i, step) in script.steps.iter().enumerate() {
        let step_name = format!("[{}] {}", i + 1, step.name);

        let result = if let Some(ref cmd) = step.command {
            run_command(clash_bin, &env, cmd)
        } else if let Some(ref shell_cmd) = step.shell {
            run_shell(&env, shell_cmd)
        } else {
            run_step(clash_bin, &env, step)
        };

        match result {
            Ok(result) => {
                let assertion = check(&step.expect, &result, &env.home_dir, &env.project_dir);

                let verbose_output = if verbose {
                    let mut buf = String::new();
                    buf.push_str(&format!("    exit_code: {}\n", result.exit_code));
                    if !result.stdout.is_empty() {
                        buf.push_str(&format!("    stdout: {}\n", result.stdout.trim()));
                    }
                    if !result.stderr.is_empty() {
                        buf.push_str(&format!("    stderr: {}\n", result.stderr.trim()));
                    }
                    Some(buf)
                } else {
                    None
                };

                step_results.push(StepOutcome {
                    step_name,
                    passed: assertion.passed,
                    failures: assertion.failures,
                    verbose_output,
                });
            }
            Err(e) => {
                step_results.push(StepOutcome {
                    step_name,
                    passed: false,
                    failures: vec![format!("ERROR: {:#}", e)],
                    verbose_output: None,
                });
            }
        }
    }

    ScriptResult {
        script_name: script.meta.name.clone(),
        script_path: script_path_str,
        step_results,
    }
}

/// Print structured results and a summary. Returns true if all passed.
fn print_results(results: &[ScriptResult]) -> bool {
    let mut total_steps = 0usize;
    let mut total_passed = 0usize;
    let mut total_failed = 0usize;
    let mut failed_scripts: Vec<(&str, &str)> = Vec::new();

    for sr in results {
        eprintln!("--- {} ({}) ---", sr.script_name, sr.script_path);

        let mut script_passed = true;
        let mut first_failure: Option<&str> = None;

        for step in &sr.step_results {
            total_steps += 1;
            if step.passed {
                total_passed += 1;
                eprintln!("  {}  PASS", step.step_name);
            } else {
                total_failed += 1;
                script_passed = false;
                eprintln!("  {}  FAIL", step.step_name);
                for failure in &step.failures {
                    eprintln!("    - {}", failure);
                }
                if first_failure.is_none() {
                    if let Some(f) = step.failures.first() {
                        first_failure = Some(f.as_str());
                    }
                }
            }

            if let Some(ref verbose) = step.verbose_output {
                eprint!("{}", verbose);
            }
        }

        if script_passed {
            eprintln!("  result: PASS\n");
        } else {
            eprintln!("  result: FAIL\n");
            failed_scripts.push((
                &sr.script_name,
                first_failure.unwrap_or("unknown failure"),
            ));
        }
    }

    eprintln!("========================================");
    eprintln!(
        "{} scripts, {} steps — {} passed, {} failed",
        results.len(),
        total_steps,
        total_passed,
        total_failed
    );

    if failed_scripts.is_empty() {
        eprintln!("result: ALL PASSED");
        true
    } else {
        eprintln!("\nFAILED:");
        for (name, reason) in &failed_scripts {
            eprintln!("  {} — {}", name, reason);
        }
        false
    }
}

/// Run test scripts and return whether all passed.
fn cmd_run(path: &Path, verbose: bool, clash_bin: Option<&Path>, jobs: usize) -> Result<bool> {
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

    let results: Vec<ScriptResult> = if jobs == 1 {
        scripts
            .iter()
            .map(|s| run_script(s, &clash_bin, verbose))
            .collect()
    } else {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(if jobs == 0 { 0 } else { jobs })
            .build()
            .context("failed to build rayon thread pool")?;

        pool.install(|| {
            scripts
                .par_iter()
                .map(|s| run_script(s, &clash_bin, verbose))
                .collect()
        })
    };

    Ok(print_results(&results))
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

/// Collect test script paths from a file or directory, recursively.
fn collect_scripts(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    if path.is_dir() {
        let mut scripts = Vec::new();
        collect_scripts_recursive(path, &mut scripts)?;
        scripts.sort();
        return Ok(scripts);
    }

    bail!("{} is neither a file nor a directory", path.display());
}

/// Recursively collect `.yaml`/`.yml` files from a directory.
fn collect_scripts_recursive(dir: &Path, scripts: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?
    {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            collect_scripts_recursive(&p, scripts)?;
        } else if p
            .extension()
            .is_some_and(|ext| ext == "yaml" || ext == "yml")
        {
            scripts.push(p);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_collect_scripts_single_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.yaml");
        std::fs::write(&file, "").unwrap();

        let scripts = collect_scripts(&file).unwrap();
        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts[0], file);
    }

    #[test]
    fn test_collect_scripts_directory() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("a.yaml"), "").unwrap();
        std::fs::write(tmp.path().join("b.yml"), "").unwrap();
        std::fs::write(tmp.path().join("c.txt"), "").unwrap();

        let scripts = collect_scripts(tmp.path()).unwrap();
        assert_eq!(scripts.len(), 2);
    }

    #[test]
    fn test_collect_scripts_recursive() {
        let tmp = TempDir::new().unwrap();
        let subdir = tmp.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        std::fs::write(tmp.path().join("a.yaml"), "").unwrap();
        std::fs::write(subdir.join("b.yaml"), "").unwrap();
        let nested = subdir.join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("c.yml"), "").unwrap();

        let scripts = collect_scripts(tmp.path()).unwrap();
        assert_eq!(scripts.len(), 3);
        // Should be sorted
        for i in 1..scripts.len() {
            assert!(scripts[i - 1] <= scripts[i]);
        }
    }

    #[test]
    fn test_collect_scripts_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let scripts = collect_scripts(tmp.path()).unwrap();
        assert!(scripts.is_empty());
    }

    #[test]
    fn test_print_results_all_pass() {
        let results = vec![ScriptResult {
            script_name: "test script".into(),
            script_path: "test.yaml".into(),
            step_results: vec![StepOutcome {
                step_name: "[1] step one".into(),
                passed: true,
                failures: vec![],
                verbose_output: None,
            }],
        }];

        assert!(print_results(&results));
    }

    #[test]
    fn test_print_results_with_failure() {
        let results = vec![ScriptResult {
            script_name: "test script".into(),
            script_path: "test.yaml".into(),
            step_results: vec![
                StepOutcome {
                    step_name: "[1] step one".into(),
                    passed: true,
                    failures: vec![],
                    verbose_output: None,
                },
                StepOutcome {
                    step_name: "[2] step two".into(),
                    passed: false,
                    failures: vec!["exit code: expected 0, got 1".into()],
                    verbose_output: None,
                },
            ],
        }];

        assert!(!print_results(&results));
    }
}
