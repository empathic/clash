use std::path::PathBuf;

use anyhow::Result;
use claude_settings::ClaudeSettings;
use claude_settings::policy::compile::CompiledPolicy;
use claude_settings::policy::parse::desugar_legacy;
use claude_settings::policy::{LegacyPermissions, PolicyConfig, PolicyDocument};
use claude_settings::sandbox::SandboxPolicy;
use dirs::home_dir;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Which permission engine to use.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EngineMode {
    /// Only use the new policy engine (policy.yaml rules).
    Policy,
    /// Only use the legacy Claude Code PermissionSet.
    Legacy,
    /// Try the policy engine first; fall back to legacy if no policy file exists.
    #[default]
    Auto,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ClashSettings {
    /// Which permission engine to use.
    #[serde(default)]
    pub engine_mode: EngineMode,

    /// Parsed policy document (not serialized — loaded at runtime from policy.yaml or compiled from Claude settings).
    #[serde(skip)]
    pub(crate) policy: Option<PolicyDocument>,

    /// Parsed sandbox policy (not serialized — loaded at runtime from sandbox section of policy.yaml).
    #[serde(skip)]
    pub(crate) sandbox: Option<SandboxPolicy>,
}

impl ClashSettings {
    pub fn settings_dir() -> PathBuf {
        home_dir()
            .expect("user must have $HOME set in environment")
            .join(".clash")
    }
    pub fn settings_file() -> PathBuf {
        Self::settings_dir().join("settings.json")
    }
    pub fn policy_file() -> PathBuf {
        Self::settings_dir().join("policy.yaml")
    }

    /// Get the sandbox policy, if one is configured.
    pub fn sandbox_policy(&self) -> Option<&SandboxPolicy> {
        self.sandbox.as_ref()
    }

    /// Try to load and compile the policy document from ~/.clash/policy.yaml.
    fn load_policy_file(&mut self) -> Option<PolicyDocument> {
        let path = Self::policy_file();
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(contents) => {
                    // Try to load sandbox section from the same YAML
                    self.load_sandbox_from_yaml(&contents);

                    match claude_settings::policy::parse::parse_yaml(&contents) {
                        Ok(doc) => {
                            info!(path = %path.display(), "Loaded policy document");
                            Some(doc)
                        }
                        Err(e) => {
                            warn!(path = %path.display(), error = %e, "Failed to parse policy.yaml");
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to read policy.yaml");
                    None
                }
            }
        } else {
            None
        }
    }

    /// Try to parse the `sandbox:` section from policy YAML.
    fn load_sandbox_from_yaml(&mut self, yaml: &str) {
        let value: serde_yaml::Value = match serde_yaml::from_str(yaml) {
            Ok(v) => v,
            Err(_) => return,
        };

        if let Some(sandbox_value) = value.get("sandbox") {
            match claude_settings::sandbox::parse_sandbox_section(sandbox_value) {
                Ok(policy) => {
                    info!("Loaded sandbox policy from policy.yaml");
                    self.sandbox = Some(policy);
                }
                Err(e) => {
                    warn!(error = %e, "Failed to parse sandbox section in policy.yaml");
                }
            }
        }
    }

    /// Compile Claude Code's legacy permissions into a PolicyDocument.
    ///
    /// Reads Claude settings via ClaudeSettings::new().effective(), converts the
    /// PermissionSet to LegacyPermissions, and desugars into policy Statements.
    fn compile_claude_to_policy() -> Option<PolicyDocument> {
        let effective = match ClaudeSettings::new().effective() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "Failed to load Claude Code settings for policy compilation");
                return None;
            }
        };

        let perms = effective.permissions.to_permissions();
        let legacy = LegacyPermissions {
            allow: perms.allow,
            deny: perms.deny,
            ask: perms.ask,
        };

        let statements = desugar_legacy(&legacy);
        if statements.is_empty() {
            info!("No legacy Claude permissions found; compiled policy has no statements");
        }

        Some(PolicyDocument {
            policy: PolicyConfig::default(),
            permissions: None,
            constraints: Default::default(),
            profiles: Default::default(),
            statements,
        })
    }

    /// Resolve the policy based on engine_mode:
    /// - Policy: load only from policy.yaml
    /// - Legacy: compile Claude settings into a PolicyDocument
    /// - Auto: use policy.yaml if it exists, else compile Claude settings
    fn resolve_policy(&mut self) {
        self.policy = match self.engine_mode {
            EngineMode::Policy => self.load_policy_file(),
            EngineMode::Legacy => Self::compile_claude_to_policy(),
            EngineMode::Auto => self
                .load_policy_file()
                .or_else(Self::compile_claude_to_policy),
        };
    }

    /// Compile the loaded policy document into a CompiledPolicy for evaluation.
    pub fn compiled_policy(&self) -> Option<CompiledPolicy> {
        self.policy
            .as_ref()
            .and_then(|doc| match CompiledPolicy::compile(doc) {
                Ok(compiled) => Some(compiled),
                Err(e) => {
                    warn!(error = %e, "Failed to compile policy document");
                    None
                }
            })
    }

    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(Self::settings_dir())?;
        Ok(std::fs::write(
            Self::settings_file(),
            serde_json::to_string_pretty(&self)?,
        )?)
    }

    pub fn load() -> Result<Self> {
        let mut loaded: Self =
            serde_json::from_str(&std::fs::read_to_string(Self::settings_file())?)?;
        loaded.resolve_policy();
        Ok(loaded)
    }

    pub fn create() -> Result<Self> {
        let mut this = Self::default();
        this.resolve_policy();
        this.save()?;
        Ok(this)
    }

    pub fn load_or_create() -> Result<Self> {
        Self::load().or_else(|_| Self::create())
    }
}
