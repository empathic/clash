use std::path::PathBuf;

use anyhow::Result;
use claude_settings::ClaudeSettings;
use dirs::{config_dir, home_dir};
use figment::Figment;
use figment::providers::{Format, Json};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ClashSettings {
    #[serde(skip)]
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
        let mut this = Self::default();
        this.from_claude = Some(ClaudeSettings::new().effective()?);
        this.save()?;
        Ok(this)
    }

    pub fn load_or_create() -> Result<Self> {
        Self::load().or_else(|_| Self::create())
    }
}
