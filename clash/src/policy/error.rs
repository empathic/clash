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

    #[error("circular profile include: {cycle}")]
    CircularInclude {
        /// The profile name where the cycle was detected.
        cycle: String,
        /// The full include path showing the cycle (e.g. "a -> b -> c -> a").
        path: Option<String>,
    },

    #[error("unknown profile '{name}' in include{}", .suggestion.as_ref().map(|s| format!("; did you mean '{}'?", s)).unwrap_or_default())]
    UnknownInclude {
        name: String,
        /// Suggested closest match, if any.
        suggestion: Option<String>,
    },

    #[error("invalid new-format rule key '{0}': {1}")]
    InvalidNewRuleKey(String, String),

    #[error("invalid cap-scoped fs key '{0}': {1}")]
    InvalidCapScopedFs(String, String),

    #[error("invalid args entry: {0}")]
    InvalidArg(String),
}

impl PolicyParseError {
    /// Return a help message suggesting how to fix this error, if applicable.
    pub fn help(&self) -> Option<String> {
        match self {
            PolicyParseError::InvalidEffect(eff) => Some(format!(
                "valid effects are: allow, deny, ask (got '{}')",
                eff
            )),
            PolicyParseError::InvalidTool(tool) => Some(format!(
                "any tool name is valid (bash, read, write, edit, task, glob, etc.) or * for wildcard (got '{}')",
                tool
            )),
            PolicyParseError::InvalidRule { rule, .. } => Some(format!(
                "expected format: 'effect entity tool pattern [: constraint]' (got '{}')",
                rule
            )),
            PolicyParseError::CircularInclude { path, .. } => {
                path.as_ref().map(|p| format!("include cycle: {}", p))
            }
            PolicyParseError::InvalidFilter(_) => Some(
                "valid filter functions: subpath(path), literal(path), regex(pattern); \
                 combine with & (and), | (or), ! (not)"
                    .into(),
            ),
            PolicyParseError::InvalidProfile(_) => Some(
                "profile expressions reference constraint or profile names; \
                 combine with & (and), | (or), ! (not)"
                    .into(),
            ),
            PolicyParseError::InvalidNewRuleKey(_, _) => {
                Some("format: \"effect verb noun\" where effect=allow|deny|ask, verb=bash|read|write|edit|*, noun=command or path pattern. Example: \"allow bash git *\"".into())
            }
            _ => None,
        }
    }
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

/// Compute Levenshtein edit distance between two strings.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0; b_len + 1];

    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

/// Find the closest match to `name` from a set of `candidates`.
/// Returns `None` if no candidate is within a reasonable edit distance (max 3).
pub fn suggest_closest(name: &str, candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .map(|c| (c, levenshtein(name, c)))
        .filter(|(_, dist)| *dist <= 3 && *dist > 0)
        .min_by_key(|(_, dist)| *dist)
        .map(|(c, _)| (*c).to_string())
}
