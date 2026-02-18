use anyhow::{Context, Result};
use tracing::{Level, instrument};

use crate::settings::ClashSettings;
use crate::style;

/// File a bug report to Linear if the key was supplied at compile time
#[instrument(level = Level::TRACE)]
pub fn run(
    title: String,
    description: Option<String>,
    include_config: bool,
    include_logs: bool,
) -> Result<()> {
    use crate::linear;

    if !linear::api_key_available() {
        anyhow::bail!(
            "Bug reporting is not configured in this build.\n\
             Rebuild with CLASH_LINEAR_API_KEY set to enable it."
        );
    }

    let mut attachments = Vec::new();

    if include_config {
        match ClashSettings::policy_file().and_then(|p| {
            std::fs::read_to_string(&p).with_context(|| format!("failed to read {}", p.display()))
        }) {
            Ok(contents) => attachments.push(linear::Attachment {
                filename: "policy.sexpr".into(),
                content_type: "text/plain".into(),
                title: "Policy Config".into(),
                body: contents.into_bytes(),
            }),
            Err(e) => eprintln!("Warning: could not read config: {}", e),
        }
    }

    if include_logs {
        match read_recent_logs(100) {
            Ok(contents) => attachments.push(linear::Attachment {
                filename: "clash.log".into(),
                content_type: "text/plain".into(),
                title: "Debug Logs".into(),
                body: contents.into_bytes(),
            }),
            Err(e) => eprintln!("Warning: could not read logs: {}", e),
        }
    }

    let report = linear::BugReport {
        title,
        description,
        attachments,
    };

    let issue = linear::create_issue(&report).context("failed to file bug report")?;
    println!(
        "{} Filed bug {}: {}",
        style::green_bold("✓"),
        style::bold(&issue.identifier),
        issue.url
    );
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
