use std::path::PathBuf;

use anyhow::Result;
use claude_settings::ClaudeSettings;
use claude_settings::policy::PolicyDocument;
use claude_settings::policy::compile::CompiledPolicy;
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

    /// Legacy Claude Code settings (loaded from Claude's settings hierarchy).
    pub(crate) from_claude: Option<claude_settings::Settings>,

    /// Parsed policy document (not serialized — loaded at runtime from policy.yaml).
    #[serde(skip)]
    pub(crate) policy: Option<PolicyDocument>,
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

    /// Try to load and compile the policy document from ~/.clash/policy.yaml.
    fn load_policy(&mut self) {
        let path = Self::policy_file();
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(contents) => match claude_settings::policy::parse::parse_yaml(&contents) {
                    Ok(doc) => {
                        info!(path = %path.display(), "Loaded policy document");
                        self.policy = Some(doc);
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "Failed to parse policy.yaml");
                    }
                },
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to read policy.yaml");
                }
            }
        }
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
        loaded.from_claude = ClaudeSettings::new().effective().ok();
        loaded.load_policy();
        Ok(loaded)
    }

    pub fn create() -> Result<Self> {
        let mut this = Self {
            from_claude: Some(ClaudeSettings::new().effective()?),
            ..Default::default()
        };
        this.load_policy();
        this.save()?;
        Ok(this)
    }

    pub fn load_or_create() -> Result<Self> {
        Self::load().or_else(|_| Self::create())
    }
}
