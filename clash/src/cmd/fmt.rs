use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};
use tracing::{Level, debug, instrument};

use crate::settings::ClashSettings;
use crate::style;

/// Handle `clash fmt`.
#[instrument(level = Level::TRACE)]
pub fn run(check: bool, files: Vec<PathBuf>) -> Result<()> {
    let targets = if files.is_empty() {
        discover_policy_files()?
    } else {
        validate_paths(&files)?
    };

    if targets.is_empty() {
        let diag = crate::settings::ClashSettings::diagnose_missing_policies();
        let details: Vec<String> = diag
            .iter()
            .map(|(level, path, reason)| format!("  {level} ({path}): {reason}"))
            .collect();
        anyhow::bail!(
            "no policy files found\n\nChecked:\n{}\n\nhint: run `clash init` to create a policy",
            details.join("\n")
        );
    }

    let ruff = find_ruff()?;
    debug!(?ruff, ?targets, check, "running ruff format");

    let mut cmd = Command::new(&ruff);
    cmd.arg("format");
    if check {
        cmd.arg("--check");
    }
    // Treat .star files as Python — Starlark is a syntactic subset
    cmd.arg("--extension").arg("star:python");
    for target in &targets {
        cmd.arg(target);
    }

    let status = cmd
        .status()
        .with_context(|| format!("failed to run: {}", ruff.display()))?;

    if !status.success() {
        if check {
            let paths: Vec<_> = targets.iter().map(|p| p.display().to_string()).collect();
            eprintln!(
                "\n{}: {} not formatted",
                style::err_red_bold("error"),
                paths.join(", "),
            );
            eprintln!(
                "  {}: run {} to fix",
                style::err_cyan_bold("hint"),
                style::bold("clash fmt"),
            );
        }
        std::process::exit(status.code().unwrap_or(1));
    }

    if !check {
        for target in &targets {
            println!("{} {}", style::green_bold("✓"), target.display());
        }
    }
    Ok(())
}

/// Discover all active policy `.star` files across levels.
fn discover_policy_files() -> Result<Vec<PathBuf>> {
    let levels = ClashSettings::available_policy_levels();
    let paths: Vec<PathBuf> = levels
        .into_iter()
        .filter(|(_, path)| path.extension().is_some_and(|ext| ext == "star"))
        .map(|(_, path)| path)
        .collect();
    Ok(paths)
}

/// Validate that all provided paths exist and are `.star` files.
fn validate_paths(files: &[PathBuf]) -> Result<Vec<PathBuf>> {
    for path in files {
        if !path.exists() {
            anyhow::bail!("file not found: {}", path.display());
        }
        if path.extension().and_then(|e| e.to_str()) != Some("star") {
            anyhow::bail!("expected a .star file, got: {}", path.display(),);
        }
    }
    Ok(files.to_vec())
}

/// Locate the `ruff` binary, or return a helpful error.
fn find_ruff() -> Result<PathBuf> {
    which::which("ruff").map_err(|_| {
        anyhow::anyhow!(
            "ruff is not installed\n\n  \
             Install it with one of:\n    \
             pip install ruff\n    \
             brew install ruff\n    \
             cargo install ruff\n\n  \
             See https://docs.astral.sh/ruff/installation/"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn validate_paths_rejects_non_star() {
        let dir = tempfile::tempdir().unwrap();
        let json_file = dir.path().join("policy.json");
        std::fs::File::create(&json_file)
            .unwrap()
            .write_all(b"{}")
            .unwrap();

        let err = validate_paths(&[json_file]).unwrap_err();
        assert!(err.to_string().contains(".star"), "got: {err}");
    }

    #[test]
    fn validate_paths_rejects_missing_file() {
        let err = validate_paths(&[PathBuf::from("/nonexistent/policy.star")]).unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
    }

    #[test]
    fn validate_paths_accepts_star_file() {
        let dir = tempfile::tempdir().unwrap();
        let star_file = dir.path().join("policy.star");
        std::fs::File::create(&star_file)
            .unwrap()
            .write_all(b"x = 1")
            .unwrap();

        let result = validate_paths(&[star_file.clone()]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![star_file]);
    }
}
