//! Unified path resolution for sandbox enforcement.
//!
//! Centralises environment-variable expansion (`$PWD`, `$HOME`, `$TMPDIR`)
//! and relative-path resolution into a single [`PathResolver`] type so that
//! every callsite in the codebase behaves consistently.

/// Resolves environment-variable placeholders in paths.
///
/// Constructed with explicit `cwd`, `home`, and `tmpdir` values so that
/// resolution is deterministic and never reads the ambient environment.
#[derive(Debug, Clone)]
pub struct PathResolver {
    cwd: String,
    home: String,
    tmpdir: String,
}

impl PathResolver {
    /// Build a resolver from explicit values.
    pub fn new(cwd: impl Into<String>, home: impl Into<String>, tmpdir: impl Into<String>) -> Self {
        Self {
            cwd: cwd.into(),
            home: home.into(),
            tmpdir: tmpdir.into(),
        }
    }

    /// Build a resolver by reading the current process environment once.
    pub fn from_env() -> Self {
        let cwd = std::env::var("PWD").unwrap_or_default();
        let home = dirs::home_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        Self { cwd, home, tmpdir }
    }

    /// Expand `$PWD`, `$HOME`, and `$TMPDIR` in `path`.
    pub fn resolve_env_vars(&self, path: &str) -> String {
        path.replace("$PWD", &self.cwd)
            .replace("$HOME", &self.home)
            .replace("$TMPDIR", &self.tmpdir)
    }

    /// Expand environment variables, then make relative paths absolute
    /// by prepending the resolver's CWD.
    pub fn resolve_relative(&self, path: &str) -> String {
        let expanded = self.resolve_env_vars(path);
        if expanded.starts_with('/') {
            expanded
        } else {
            format!("{}/{}", self.cwd, expanded)
        }
    }

    /// The working directory this resolver was built with.
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// The home directory this resolver was built with.
    pub fn home(&self) -> &str {
        &self.home
    }

    /// The temp directory this resolver was built with.
    pub fn tmpdir(&self) -> &str {
        &self.tmpdir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver() -> PathResolver {
        PathResolver::new("/work", "/home/alice", "/tmp")
    }

    #[test]
    fn resolve_env_vars_replaces_all_placeholders() {
        let r = resolver();
        assert_eq!(r.resolve_env_vars("$PWD/src"), "/work/src");
        assert_eq!(r.resolve_env_vars("$HOME/.config"), "/home/alice/.config");
        assert_eq!(r.resolve_env_vars("$TMPDIR/build"), "/tmp/build");
    }

    #[test]
    fn resolve_env_vars_no_placeholder() {
        let r = resolver();
        assert_eq!(r.resolve_env_vars("/usr/bin"), "/usr/bin");
    }

    #[test]
    fn resolve_relative_makes_relative_absolute() {
        let r = resolver();
        assert_eq!(r.resolve_relative("src/main.rs"), "/work/src/main.rs");
    }

    #[test]
    fn resolve_relative_keeps_absolute() {
        let r = resolver();
        assert_eq!(r.resolve_relative("/etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn resolve_relative_expands_then_resolves() {
        let r = resolver();
        // $PWD/foo is already absolute after expansion
        assert_eq!(r.resolve_relative("$PWD/foo"), "/work/foo");
    }

    #[test]
    fn from_env_does_not_panic() {
        // Smoke test — just make sure it doesn't blow up.
        let _ = PathResolver::from_env();
    }
}
