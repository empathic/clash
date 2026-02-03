//! Unified error types for the policy subsystem.

/// Error during policy parsing (YAML, rule strings, expressions).
#[derive(Debug, thiserror::Error)]
pub enum PolicyParseError {
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("invalid rule '{rule}': {message}")]
    InvalidRule { rule: String, message: String },

    #[error("invalid effect '{0}'")]
    InvalidEffect(String),

    #[error("invalid tool '{0}'")]
    InvalidTool(String),

    #[error("invalid filter expression: {0}")]
    InvalidFilter(String),

    #[error("invalid profile expression: {0}")]
    InvalidProfile(String),

    #[error("unknown constraint or profile '{0}'")]
    UnknownRef(String),

    #[error("circular profile include: {0}")]
    CircularInclude(String),

    #[error("unknown profile '{0}' in include")]
    UnknownInclude(String),

    #[error("invalid new-format rule key '{0}': {1}")]
    InvalidNewRuleKey(String, String),

    #[error("invalid cap-scoped fs key '{0}': {1}")]
    InvalidCapScopedFs(String, String),

    #[error("invalid args entry: {0}")]
    InvalidArg(String),
}

/// Error during policy compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("invalid glob pattern '{pattern}': {source}")]
    InvalidGlob {
        pattern: String,
        source: regex::Error,
    },
    #[error("invalid regex in filter '{pattern}': {source}")]
    InvalidFilterRegex {
        pattern: String,
        source: regex::Error,
    },
    #[error("profile flattening error: {0}")]
    ProfileError(String),
}

/// Unified policy error wrapping parse and compile errors.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error(transparent)]
    Parse(#[from] PolicyParseError),
    #[error(transparent)]
    Compile(#[from] CompileError),
}
