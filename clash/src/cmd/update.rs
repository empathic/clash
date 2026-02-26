use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::io::Read;
use tracing::{Level, debug, instrument};

use crate::style;

const GITHUB_REPO: &str = "empathic/clash";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

#[instrument(level = Level::TRACE)]
pub fn run(check: bool, yes: bool, version: Option<String>) -> Result<()> {
    let current_version = env!("CARGO_PKG_VERSION");

    let release = match version {
        Some(ref v) => fetch_release(v)?,
        None => fetch_latest_release()?,
    };

    let release_version = release.tag_name.trim_start_matches('v');

    let current =
        semver::Version::parse(current_version).context("failed to parse current version")?;
    let latest = semver::Version::parse(release_version)
        .with_context(|| format!("failed to parse release version '{}'", release_version))?;

    if current >= latest && version.is_none() {
        println!(
            "{} clash is up to date (v{})",
            style::green_bold("✓"),
            current_version,
        );
        return Ok(());
    }

    if check {
        println!(
            "Update available: v{} → v{}",
            current_version, release_version,
        );
        if installed_via_cargo() {
            println!(
                "Run {} to update",
                style::cyan("`cargo install --git https://github.com/empathic/clash clash`"),
            );
        } else {
            println!("Run {} to install", style::cyan("`clash update`"));
        }
        return Ok(());
    }

    if installed_via_cargo() {
        println!(
            "Update available: v{} → v{}",
            current_version, release_version,
        );
        println!(
            "\nclash was installed via {}. Update with:\n\n  {}\n",
            style::cyan("cargo"),
            style::bold("cargo install --git https://github.com/empathic/clash clash"),
        );
        return Ok(());
    }

    let target = target_triple().context("failed to detect platform")?;
    let asset_name = format!("clash-{target}.tar.gz");
    let checksum_name = format!("{asset_name}.sha256");

    let asset_url = release
        .assets
        .iter()
        .find(|a| a.name == asset_name)
        .map(|a| a.browser_download_url.as_str())
        .ok_or_else(|| anyhow::anyhow!("no release asset found for target '{target}'"))?;

    let checksum_url = release
        .assets
        .iter()
        .find(|a| a.name == checksum_name)
        .map(|a| a.browser_download_url.as_str());

    if !yes {
        println!(
            "Update available: v{} → v{}",
            current_version, release_version,
        );
        let confirmed = dialoguer::Confirm::new()
            .with_prompt("Install update?")
            .default(true)
            .interact()
            .context("failed to read confirmation")?;
        if !confirmed {
            println!("Update cancelled.");
            return Ok(());
        }
    }

    println!("Downloading clash v{release_version}...");

    let tarball = download_bytes(asset_url).context("failed to download release archive")?;

    if let Some(url) = checksum_url {
        let expected = download_text(url).context("failed to download checksum")?;
        verify_checksum(&tarball, &expected)?;
        debug!("checksum verified");
    } else {
        eprintln!(
            "{} No checksum available for this release — skipping integrity verification",
            style::yellow("warning:"),
        );
    }

    let binary = extract_binary(&tarball).context("failed to extract clash binary from archive")?;

    let current_exe =
        std::env::current_exe().context("failed to determine current executable path")?;
    let current_exe = current_exe.canonicalize().unwrap_or(current_exe);

    replace_binary(&current_exe, &binary).context("failed to replace binary")?;

    println!(
        "{} Updated clash v{} → v{}",
        style::green_bold("✓"),
        current_version,
        release_version,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// GitHub release API
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(serde::Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

fn fetch_latest_release() -> Result<Release> {
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
    fetch_release_from(&url).context("failed to fetch latest release from GitHub")
}

fn fetch_release(version: &str) -> Result<Release> {
    let tag = if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    };
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/tags/{tag}");
    fetch_release_from(&url).with_context(|| format!("failed to fetch release {tag} from GitHub"))
}

fn fetch_release_from(url: &str) -> Result<Release> {
    let resp = ureq::get(url)
        .set("Accept", "application/vnd.github+json")
        .set("User-Agent", crate::version::user_agent())
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(404, _) => anyhow::anyhow!("release not found"),
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                anyhow::anyhow!("GitHub API returned {code}: {body}")
            }
            other => anyhow::anyhow!(other),
        })?;

    let body = resp
        .into_string()
        .context("failed to read GitHub API response body")?;

    serde_json::from_str::<Release>(&body).context("failed to parse GitHub release response")
}

// ---------------------------------------------------------------------------
// Install-method detection
// ---------------------------------------------------------------------------

/// Returns `true` when the running binary lives inside `~/.cargo/bin/`,
/// which means it was installed via `cargo install` and should be updated
/// through cargo rather than direct binary replacement.
fn installed_via_cargo() -> bool {
    let cargo_bin = dirs::home_dir().map(|h| h.join(".cargo").join("bin"));

    let current_exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok());

    match (cargo_bin, current_exe) {
        (Some(cb), Some(exe)) => exe.starts_with(cb),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

fn target_triple() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        (os, arch) => bail!("unsupported platform: {os}-{arch}"),
    }
}

// ---------------------------------------------------------------------------
// Download helpers
// ---------------------------------------------------------------------------

/// Upper bound on release archive size (500 MB). Guards against a compromised
/// CDN serving an unbounded response.
const MAX_DOWNLOAD_BYTES: u64 = 500 * 1024 * 1024;

fn download_bytes(url: &str) -> Result<Vec<u8>> {
    let resp = ureq::get(url)
        .set("User-Agent", crate::version::user_agent())
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                anyhow::anyhow!("download failed with HTTP {code}: {body}")
            }
            other => anyhow::anyhow!(other),
        })?;

    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_DOWNLOAD_BYTES)
        .read_to_end(&mut buf)
        .context("failed to read download response")?;
    Ok(buf)
}

fn download_text(url: &str) -> Result<String> {
    let resp = ureq::get(url)
        .set("User-Agent", crate::version::user_agent())
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                anyhow::anyhow!("download failed with HTTP {code}: {body}")
            }
            other => anyhow::anyhow!(other),
        })?;

    resp.into_string()
        .context("failed to read download response as text")
}

// ---------------------------------------------------------------------------
// Checksum verification
// ---------------------------------------------------------------------------

fn verify_checksum(data: &[u8], expected_line: &str) -> Result<()> {
    let expected_hash = expected_line
        .split_whitespace()
        .next()
        .context("empty checksum file")?;

    let actual_hash = format!("{:x}", Sha256::digest(data));

    if actual_hash != expected_hash {
        bail!("checksum mismatch\n  expected: {expected_hash}\n  got:      {actual_hash}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tarball extraction
// ---------------------------------------------------------------------------

fn extract_binary(tarball: &[u8]) -> Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(decoder);

    for entry in archive
        .entries()
        .context("failed to read archive entries")?
    {
        let mut entry = entry.context("failed to read archive entry")?;
        let path = entry.path().context("failed to read entry path")?;

        if path.file_name() == Some(std::ffi::OsStr::new("clash")) {
            let mut binary = Vec::new();
            entry
                .read_to_end(&mut binary)
                .context("failed to read clash binary from archive")?;
            return Ok(binary);
        }
    }

    bail!("clash binary not found in release archive")
}

// ---------------------------------------------------------------------------
// Atomic binary replacement
// ---------------------------------------------------------------------------

fn replace_binary(target: &std::path::Path, binary: &[u8]) -> Result<()> {
    let temp = target.with_extension("update-tmp");

    std::fs::write(&temp, binary)
        .with_context(|| format!("failed to write to {}", temp.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to set permissions on {}", temp.display()))?;
    }

    if let Err(e) = std::fs::rename(&temp, target) {
        let _ = std::fs::remove_file(&temp);
        return Err(e).with_context(|| format!("failed to replace {}", target.display()));
    }

    Ok(())
}
