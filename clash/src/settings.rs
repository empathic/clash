use std::{default, path::PathBuf};

use anyhow::Result;
use claude_settings::ClaudeSettings;
use dirs::home_dir;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ClashSettings {
    pub(crate) from_claude: Option<claude_settings::Settings>,
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
        Ok(loaded)
    }

    pub fn create() -> Result<Self> {
        let this = Self {
            from_claude: Some(ClaudeSettings::new().effective()?),
        };
        this.save()?;
        Ok(this)
    }

    pub fn load_or_create() -> Result<Self> {
        Self::load().or_else(|_| Self::create())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PermissionSet {
    Allow: Vec<Pattern>,
    Deny: Vec<Pattern>,
    Ask: Vec<Pattern>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Pattern {
    Exact(String),
    Glob(String),
    #[serde(with = "serde_regex")]
    Pattern(regex::Regex),
}

pub enum Permission {
    Shell {},
}
#[derive(Clone, Default)]
struct Find {
    exec: bool,
    remove: bool,
}

// example
#[derive(Clone)]
pub enum KnownCommand {
    Find(Find),
}
