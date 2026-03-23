use anyhow::{Context, Result};
use tracing::{Level, instrument, warn};

use crate::settings::ClashSettings;
use crate::style;

/// File a bug report to Linear (with full diagnostics) and GitHub (public, title + description only).
#[instrument(level = Level::TRACE)]
pub fn run(
    title: String,
    description: Option<String>,
    include_config: bool,
    include_logs: bool,
    include_trace: bool,
) -> Result<()> {
    const HOTLINE_PROXY_URL: &str = "https://hotline.emv.workers.dev";
    const HOTLINE_PROXY_TOKEN: &str = "nkCk16ewj5YDPqhZ7FSBHM44+3y5F5HpH0FdvVrIO8A=";

    let desc_text = description.as_deref().unwrap_or_default();

    // GitHub issue: public, title + description only
    let mut github = hotln::github(HOTLINE_PROXY_URL);
    github.with_token(HOTLINE_PROXY_TOKEN).title(&title);
    if !desc_text.is_empty() {
        github.text(desc_text);
    }
    let github_url = github.create().context("failed to create GitHub issue")?;

    // Linear issue: full diagnostics (private)
    let mut linear = hotln::linear(HOTLINE_PROXY_URL);
    linear.with_token(HOTLINE_PROXY_TOKEN).title(&title);
    if !desc_text.is_empty() {
        linear.text(desc_text);
    }
    linear.text(&format!("GitHub: {github_url}"));
    linear.text(&format!(
        "### System Info\n\n| Key | Value |\n|-----|-------|\n| OS | {} |\n| Arch | {} |\n| Version | {} |",
        std::env::consts::OS,
        std::env::consts::ARCH,
        crate::version::version_long(),
    ));
    if include_config {
        match ClashSettings::policy_file().and_then(|p| {
            std::fs::read_to_string(&p).with_context(|| format!("failed to read {}", p.display()))
        }) {
            Ok(contents) => {
                linear.file("policy.star", &contents);
            }
            Err(e) => warn!("could not read config: {e}"),
        }
    }
    if include_logs {
        match read_recent_logs(100) {
            Ok(contents) => {
                linear.attachment("debug.log", contents.as_bytes());
            }
            Err(e) => warn!("could not read logs: {e}"),
        }
    }
    if include_trace {
        match ClashSettings::active_session_id()
            .and_then(|sid| crate::trace::export_trace(&sid))
            .and_then(|doc| doc.to_json().context("serializing trace"))
        {
            Ok(json) => {
                linear.attachment("trace.json", json.as_bytes());
            }
            Err(e) => warn!("could not export trace: {e}"),
        }
    }
    if let Err(e) = linear.create() {
        warn!("failed to create Linear issue: {e}");
    }

    println!("{} Filed bug: {github_url}", style::green_bold("✓"));
    Ok(())
}

/// Read the last `n` lines from the clash log file.
fn read_recent_logs(n: usize) -> Result<String> {
    let log_path = std::env::var("CLASH_LOG").ok().unwrap_or_else(|| {
        ClashSettings::settings_dir()
            .map(|d| d.join("clash.log"))
            .unwrap_or_else(|_| std::path::PathBuf::from("clash.log"))
            .to_string_lossy()
            .into_owned()
    });

    let contents = std::fs::read_to_string(&log_path)
        .with_context(|| format!("failed to read {}", log_path))?;

    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(n);
    Ok(lines[start..].join("\n"))
}
