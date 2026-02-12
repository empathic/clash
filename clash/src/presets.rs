//! Named presets that expand into policy rules with sensible defaults.
//!
//! Presets provide a simple vocabulary for onboarding: `clash allow editing`
//! instead of `clash policy add-rule "allow edit *" --fs "write+create:subpath(.)"`.

use crate::policy::edit::{self, InlineConstraintArgs};
use crate::settings::ClashSettings;
use anyhow::{Context, Result};
use std::path::PathBuf;

/// A single rule within a preset.
struct PresetRule {
    /// The rule string, e.g. "allow edit *"
    rule: &'static str,
    /// Filesystem constraint, e.g. "write+create:subpath({cwd})"
    /// `{cwd}` is replaced with the absolute cwd at apply time.
    fs: Option<&'static str>,
}

/// A named preset definition.
struct PresetDef {
    /// The preset name used on the CLI, e.g. "editing"
    name: &'static str,
    /// Short description for `--list` output
    description: &'static str,
    /// What to print after applying (positive framing).
    /// `{cwd}` is replaced with the absolute cwd.
    confirm_enabled: &'static str,
    /// What to print about remaining protections.
    confirm_protected: Option<&'static str>,
    /// The rules this preset expands to.
    rules: &'static [PresetRule],
}

static PRESETS: &[PresetDef] = &[
    PresetDef {
        name: "editing",
        description: "Allow Claude to edit files in this project",
        confirm_enabled: "Claude can now edit files in {cwd}.",
        confirm_protected: Some("Files outside this directory are still protected."),
        rules: &[
            PresetRule {
                rule: "allow edit *",
                fs: Some("write:subpath({cwd})"),
            },
            PresetRule {
                rule: "allow write *",
                fs: Some("write+create:subpath({cwd})"),
            },
        ],
    },
    PresetDef {
        name: "commands",
        description: "Allow Claude to run commands in this project",
        confirm_enabled: "Claude can now run commands in {cwd}.",
        confirm_protected: Some("Commands can only access files in this directory."),
        rules: &[PresetRule {
            rule: "allow bash *",
            fs: Some("full:subpath({cwd})"),
        }],
    },
    PresetDef {
        name: "web",
        description: "Allow Claude to search the web and fetch URLs",
        confirm_enabled: "Claude can now search the web and fetch URLs.",
        confirm_protected: None,
        rules: &[
            PresetRule {
                rule: "allow webfetch *",
                fs: None,
            },
            PresetRule {
                rule: "allow websearch *",
                fs: None,
            },
        ],
    },
];

/// Load the policy.yaml file, returning its path and contents.
fn load_policy_yaml() -> Result<(PathBuf, String)> {
    let path = ClashSettings::policy_file()?;
    if path.is_dir() {
        anyhow::bail!(
            "{} is a directory, not a file. Remove it and run `clash init` to create a policy.",
            path.display()
        );
    }
    let yaml = std::fs::read_to_string(&path).with_context(|| {
        if !path.exists() {
            "No policy found. Run `clash init` first.".to_string()
        } else {
            format!("Could not read {}", path.display())
        }
    })?;
    Ok((path, yaml))
}

/// Look up a preset by name.
fn find_preset(name: &str) -> Option<&'static PresetDef> {
    PRESETS.iter().find(|p| p.name.eq_ignore_ascii_case(name))
}

/// Apply a named preset to the user's policy file.
pub fn apply_preset(name: &str) -> Result<()> {
    let preset = find_preset(name).ok_or_else(|| {
        anyhow::anyhow!(
            "Unknown preset '{}'. Run `clash allow --list` to see options.",
            name
        )
    })?;

    let cwd = std::env::current_dir()
        .context("could not determine current directory")?
        .to_string_lossy()
        .into_owned();

    let (path, mut yaml) = load_policy_yaml()?;
    let target_profile = edit::resolve_profile(&yaml, None)?;

    let mut any_added = false;
    for preset_rule in preset.rules {
        let constraints = match preset_rule.fs {
            Some(fs_template) => InlineConstraintArgs {
                fs: vec![fs_template.replace("{cwd}", &cwd)],
                ..Default::default()
            },
            None => InlineConstraintArgs::default(),
        };

        let modified = edit::add_rule(&yaml, &target_profile, preset_rule.rule, &constraints)?;
        if modified != yaml {
            any_added = true;
            yaml = modified;
        }
    }

    if any_added {
        std::fs::write(&path, &yaml)?;
        println!("{}", preset.confirm_enabled.replace("{cwd}", &cwd));
        if let Some(protected) = preset.confirm_protected {
            println!("{}", protected);
        }
    } else {
        println!(
            "Already allowed — the '{}' preset is already in your policy.",
            preset.name
        );
    }

    Ok(())
}

/// Print the list of available presets.
pub fn list_presets() {
    println!("Available presets:");
    for preset in PRESETS {
        println!("  {:<12}{}", preset.name, preset.description);
    }
    println!();
    println!("Usage: clash allow <preset>");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_presets_have_rules() {
        for preset in PRESETS {
            assert!(
                !preset.rules.is_empty(),
                "preset '{}' has no rules",
                preset.name
            );
        }
    }

    #[test]
    fn find_preset_case_insensitive() {
        assert!(find_preset("editing").is_some());
        assert!(find_preset("Editing").is_some());
        assert!(find_preset("EDITING").is_some());
        assert!(find_preset("nonexistent").is_none());
    }

    #[test]
    fn all_preset_names_are_lowercase() {
        for preset in PRESETS {
            assert_eq!(
                preset.name,
                preset.name.to_lowercase(),
                "preset name should be lowercase"
            );
        }
    }

    #[test]
    fn preset_rules_parse() {
        // Verify all preset rules are valid rule syntax
        for preset in PRESETS {
            for rule in preset.rules {
                let result = crate::policy::parse::parse_new_rule_key(rule.rule);
                assert!(
                    result.is_ok(),
                    "preset '{}' rule '{}' failed to parse: {:?}",
                    preset.name,
                    rule.rule,
                    result.err()
                );
            }
        }
    }

    #[test]
    fn preset_fs_constraints_have_valid_format() {
        for preset in PRESETS {
            for rule in preset.rules {
                if let Some(fs) = rule.fs {
                    // Replace template before validation
                    let resolved = fs.replace("{cwd}", "/tmp/test");
                    assert!(
                        resolved.split_once(':').is_some(),
                        "preset '{}' rule '{}' has invalid fs constraint: {}",
                        preset.name,
                        rule.rule,
                        fs
                    );
                }
            }
        }
    }

    #[test]
    fn list_presets_includes_all() {
        assert_eq!(PRESETS.len(), 3, "expected 3 presets: editing, commands, web");
    }
}
