//! Disk cache for compiled .star policies.
//!
//! Content-addressed: `~/.clash/star-cache/<sha256>.json`.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

/// Cache for compiled Starlark policies.
pub struct StarCache {
    cache_dir: PathBuf,
}

impl StarCache {
    /// Create a new cache in the default location (`~/.clash/star-cache/`).
    pub fn new() -> Option<Self> {
        let dir = dirs::home_dir()?.join(".clash").join("star-cache");
        Some(StarCache { cache_dir: dir })
    }

    /// Create a cache at a specific directory (for testing).
    pub fn at(dir: PathBuf) -> Self {
        StarCache { cache_dir: dir }
    }

    /// Compute a cache key from the source content and all loaded file contents.
    pub fn cache_key(source: &str, loaded_files: &[String]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(source.as_bytes());
        for f in loaded_files {
            if let Ok(contents) = std::fs::read(f) {
                hasher.update(&contents);
            }
        }
        let hash = hasher.finalize();
        format!("{hash:x}")
    }

    /// Look up a cached result.
    pub fn get(&self, key: &str) -> Option<String> {
        let path = self.cache_dir.join(format!("{key}.json"));
        std::fs::read_to_string(&path).ok()
    }

    /// Store a result in the cache.
    pub fn put(&self, key: &str, json: &str) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.cache_dir)?;
        let path = self.cache_dir.join(format!("{key}.json"));
        std::fs::write(&path, json)?;
        Ok(())
    }
}
