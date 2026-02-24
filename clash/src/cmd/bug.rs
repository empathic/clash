use anyhow::{Context, Result, bail};
use tracing::{Level, instrument};

use crate::settings::ClashSettings;
use crate::style;

/// File a bug report to Linear.
#[instrument(level = Level::TRACE)]
pub fn run(
    title: String,
    description: Option<String>,
    include_config: bool,
    include_logs: bool,
) -> Result<()> {
    // Build the description by combining user text with optional config/logs.
    let mut desc_parts: Vec<String> = Vec::new();

    if let Some(ref d) = description {
        desc_parts.push(d.clone());
    }

    if include_config {
        match ClashSettings::policy_file().and_then(|p| {
            std::fs::read_to_string(&p).with_context(|| format!("failed to read {}", p.display()))
        }) {
            Ok(contents) => {
                desc_parts.push(format!("### Policy Config\n\n```\n{}\n```", contents));
            }
            Err(e) => eprintln!("Warning: could not read config: {}", e),
        }
    }

    if include_logs {
        match read_recent_logs(100) {
            Ok(contents) => {
                desc_parts.push(format!("### Debug Logs\n\n```\n{}\n```", contents));
            }
            Err(e) => eprintln!("Warning: could not read logs: {}", e),
        }
    }

    let full_description = if desc_parts.is_empty() {
        None
    } else {
        Some(desc_parts.join("\n\n"))
    };

    let system_info = [
        ("OS", std::env::consts::OS),
        ("Arch", std::env::consts::ARCH),
        ("Version", env!("CARGO_PKG_VERSION")),
    ];

    let result = if let Some(api_key) = option_env!("CLASH_HOTLINE_LINEAR_KEY") {
        let Some(team_id) = option_env!("CLASH_HOTLINE_LINEAR_TEAM") else {
            bail!("CLASH_HOTLINE_LINEAR_KEY is set but CLASH_HOTLINE_LINEAR_TEAM is missing");
        };
        let Some(project_id) = option_env!("CLASH_HOTLINE_LINEAR_PROJECT") else {
            bail!("CLASH_HOTLINE_LINEAR_KEY is set but CLASH_HOTLINE_LINEAR_PROJECT is missing");
        };
        hotln::direct(api_key, team_id, project_id).create_issue(
            &title,
            full_description.as_deref(),
            &system_info,
        )
    } else {
        let Some(hotline_url) = option_env!("CLASH_HOTLINE_PROXY_URL") else {
            bail!(
                "Bug reporting is not configured in this build.\n\
                 Set CLASH_HOTLINE_LINEAR_KEY or CLASH_HOTLINE_PROXY_URL to enable it."
            );
        };
        let Some(hotline_token) = option_env!("CLASH_HOTLINE_PROXY_TOKEN") else {
            bail!("CLASH_HOTLINE_PROXY_URL is set but CLASH_HOTLINE_PROXY_TOKEN is missing");
        };
        hotln::proxy(hotline_url)
            .with_token(hotline_token)
            .create_issue(&title, full_description.as_deref(), &system_info)
    };

    match result {
        Ok(url) => {
            println!("{} Filed bug: {}", style::green_bold("✓"), url);
            Ok(())
        }
        Err(e) => bail!("failed to file bug report: {e}"),
    }
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
