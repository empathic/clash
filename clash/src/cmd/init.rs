use anyhow::{Context, Result};
use dialoguer::Confirm;
use tracing::{Level, info, instrument, warn};

use crate::settings::{ClashSettings, DEFAULT_POLICY};
use crate::style;

/// GitHub repository used to install the clash plugin marketplace.
const GITHUB_MARKETPLACE: &str = "empathic/clash";

/// Initialize or reconfigure a clash policy.
///
/// - If a sexp policy already exists, drop into the interactive wizard.
/// - If only a legacy YAML policy exists, convert it via `claude -p` then
///   drop into the wizard.
/// - Otherwise, write the default policy and launch the wizard.
#[instrument(level = Level::TRACE)]
pub fn run(no_bypass: Option<bool>, project: Option<bool>) -> Result<()> {
    if project.unwrap_or_else(|| {
        dialoguer::Confirm::new()
            .with_prompt("Init clash for the current project?")
            .interact()
            .unwrap_or(false)
    }) {
        run_init_project()?;
    }

    let sexpr_path = ClashSettings::policy_file()?;

    if sexpr_path.exists() && sexpr_path.is_dir() {
        if dialoguer::Confirm::new()
            .with_prompt(format!(
                "{} is a directory. Remove it and continue onboarding?",
                sexpr_path.to_string_lossy(),
            ))
            .interact()
            .context("confirm removeal of dir at sexpr path")?
        {
            std::fs::remove_dir_all(&sexpr_path)?;
        } else {
            anyhow::bail!(
                "{} is a directory. Remove it first, then run `clash init`.",
                sexpr_path.display()
            );
        }
    }

    if sexpr_path.exists()
        && !dialoguer::Confirm::new()
            .with_prompt(format!(
                "A policy already exists at {}. Reconfigure existing policy?",
                sexpr_path.to_string_lossy()
            ))
            .interact()
            .unwrap_or_default()
    {
        return Ok(());
    }

    let yaml_path = ClashSettings::legacy_policy_file()?;
    if yaml_path.exists() && yaml_path.is_file() && Confirm::new().with_prompt("An existing policy.yaml file was found at {}. Should we attempt to migrate your settings?").default(false).interact().unwrap_or(false){
        // Legacy YAML policy found — attempt migration, then launch wizard.
        migrate_yaml_policy(&yaml_path, &sexpr_path)?;
        return crate::wizard::run();
    }

    // Fresh install — write default policy.
    std::fs::create_dir_all(ClashSettings::settings_dir()?)?;
    std::fs::write(&sexpr_path, DEFAULT_POLICY)?;

    // Install the Claude Code plugin from GitHub.
    let plugin_installed = match install_plugin() {
        Ok(()) => true,
        Err(e) => {
            warn!(error = %e, "Could not install clash plugin");
            eprintln!(
                "{} Could not install the clash plugin: {e}\n  \
                 You can install it manually later:\n    \
                 claude plugin marketplace add {GITHUB_MARKETPLACE}\n    \
                 claude plugin install clash",
                style::yellow("!"),
            );
            false
        }
    };

    if plugin_installed {
        // Plugin is installed, so bypassPermissions is safe.
        if !no_bypass.unwrap_or_else(|| {
            dialoguer::Confirm::new()
                .with_prompt(
                    "Use clash as your default permissions provider in Claude Code? \
                     (This sets bypassPermissions so clash handles all permission decisions)",
                )
                .interact()
                .unwrap_or(true)
        }) && let Err(e) = set_bypass_permissions()
        {
            warn!(error = %e, "Could not set bypassPermissions in Claude Code settings");
            eprintln!(
                "warning: could not configure Claude Code to use clash as sole permission handler.\n\
                 You may see double prompts. Run with --dangerously-skip-permissions to avoid this."
            );
        }
    } else {
        eprintln!(
            "{} Skipping bypassPermissions — the clash plugin must be installed first.",
            style::dim("·"),
        );
    }

    println!(
        "{} Clash initialized at {}\n",
        style::green_bold("✓"),
        sexpr_path.display()
    );

    // Launch the wizard so the user can customize immediately.
    crate::wizard::run()
}

/// Initialize a project-level policy in the project root's `.clash/` directory.
fn run_init_project() -> Result<()> {
    let project_root = ClashSettings::project_root()
        .context("could not find project root — are you inside a git repository?")?;

    let clash_dir = project_root.join(".clash");
    let policy_path = clash_dir.join("policy.sexpr");

    if policy_path.exists() {
        println!(
            "{} Project policy already exists at {}",
            style::dim("·"),
            policy_path.display()
        );
        return Ok(());
    }

    std::fs::create_dir_all(&clash_dir)
        .with_context(|| format!("failed to create {}", clash_dir.display()))?;

    let project_policy = "(default deny \"main\")\n(policy \"main\")\n";
    std::fs::write(&policy_path, project_policy)
        .with_context(|| format!("failed to write {}", policy_path.display()))?;

    println!(
        "{} Project policy initialized at {}",
        style::green_bold("✓"),
        policy_path.display()
    );
    Ok(())
}

/// Migrate a legacy YAML policy to s-expression format using `claude -p`.
fn migrate_yaml_policy(yaml_path: &std::path::Path, sexpr_path: &std::path::Path) -> Result<()> {
    let yaml_content =
        std::fs::read_to_string(yaml_path).context("failed to read legacy policy.yaml")?;

    let grammar = include_str!("../../docs/policy-grammar.md");

    let prompt = format!(
        "Convert this YAML clash policy to the s-expression format described in the grammar below.\n\
         Output ONLY the s-expression policy text. No markdown fences, no explanation.\n\n\
         ## Grammar\n\n{grammar}\n\n\
         ## YAML Policy\n\n```yaml\n{yaml_content}\n```"
    );

    println!(
        "{} Migrating legacy policy.yaml to s-expression format...",
        style::cyan("~")
    );

    let output = std::process::Command::new("claude")
        .arg("-p")
        .arg(&prompt)
        .output()
        .context("failed to run `claude -p` for policy migration — is claude on PATH?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(stderr = %stderr, "claude -p failed during YAML migration");
        eprintln!("Migration failed — writing default policy instead.");
        eprintln!(
            "Your legacy policy.yaml is preserved at {}",
            yaml_path.display()
        );
        std::fs::create_dir_all(sexpr_path.parent().unwrap())?;
        std::fs::write(sexpr_path, DEFAULT_POLICY)?;
        return Ok(());
    }

    let sexpr_content = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Validate the converted policy compiles.
    match crate::policy::compile_policy(&sexpr_content) {
        Ok(_) => {
            std::fs::create_dir_all(sexpr_path.parent().unwrap())?;
            std::fs::write(sexpr_path, &sexpr_content)?;
            println!(
                "{} Migrated policy written to {}",
                style::green_bold("✓"),
                sexpr_path.display()
            );
            println!(
                "  Legacy policy.yaml preserved at {}\n",
                yaml_path.display()
            );
        }
        Err(e) => {
            warn!(error = %e, "migrated policy failed validation");
            eprintln!("Converted policy failed validation: {e}");
            eprintln!("Writing default policy instead. Your legacy policy.yaml is preserved.");
            std::fs::create_dir_all(sexpr_path.parent().unwrap())?;
            std::fs::write(sexpr_path, DEFAULT_POLICY)?;
        }
    }

    Ok(())
}

/// Set `bypassPermissions: true` in user-level Claude Code settings.
///
/// This tells Claude Code to skip its built-in permission system so Clash
/// becomes the sole permission handler, avoiding double-prompting.
fn set_bypass_permissions() -> Result<()> {
    let claude = claude_settings::ClaudeSettings::new();
    claude.set_bypass_permissions(claude_settings::SettingsLevel::User, true)?;
    println!(
        "{} Configured Claude Code to use clash as the sole permission handler.",
        style::green_bold("✓")
    );
    Ok(())
}

/// Install the clash plugin into Claude Code from the GitHub marketplace.
///
/// Registers the `empathic/clash` GitHub repo as a marketplace, then installs
/// the `clash` plugin from it. Idempotent — safe to run if already installed.
fn install_plugin() -> Result<()> {
    println!(
        "{} Installing clash plugin from {}...",
        style::cyan("~"),
        GITHUB_MARKETPLACE,
    );

    // Register the marketplace.
    let add_output = std::process::Command::new("claude")
        .args(["plugin", "marketplace", "add", GITHUB_MARKETPLACE])
        .output()
        .context("failed to run `claude plugin marketplace add` — is claude on PATH?")?;

    if !add_output.status.success() {
        let stderr = String::from_utf8_lossy(&add_output.stderr);
        // "already exists" is fine — marketplace was previously registered.
        if !stderr.contains("already") {
            anyhow::bail!("claude plugin marketplace add failed: {stderr}");
        }
        info!("marketplace already registered, continuing");
    }

    // Install the plugin.
    let install_output = std::process::Command::new("claude")
        .args(["plugin", "install", "clash"])
        .output()
        .context("failed to run `claude plugin install`")?;

    if !install_output.status.success() {
        let stderr = String::from_utf8_lossy(&install_output.stderr);
        // "already installed" is fine.
        if !stderr.contains("already") {
            anyhow::bail!("claude plugin install failed: {stderr}");
        }
        info!("plugin already installed");
    }

    println!(
        "{} Clash plugin installed in Claude Code.",
        style::green_bold("✓"),
    );
    Ok(())
}
