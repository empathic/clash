//! Git worktree detection.
//!
//! When the working directory is inside a git worktree, the actual git data
//! (objects, refs, config) lives in the *main* repository's `.git/` directory,
//! not under the worktree itself. This module detects worktrees and resolves
//! the paths that sandboxed processes need access to.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::debug;

/// Resolved paths for a git worktree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeInfo {
    /// The worktree-specific git directory
    /// (e.g. `/path/to/main-repo/.git/worktrees/<name>`).
    pub git_dir: PathBuf,
    /// The common git directory shared by all worktrees
    /// (e.g. `/path/to/main-repo/.git`).
    pub common_dir: PathBuf,
}

/// Detect if `cwd` is inside a git worktree and resolve git directories.
///
/// In a worktree, `.git` is a *file* containing `gitdir: <path>` pointing to
/// the worktree-specific git dir. That directory contains a `commondir` file
/// pointing to the shared git dir (objects, refs, config, hooks).
///
/// Returns `None` if `cwd` is not in a worktree (either not a git repo, or
/// `.git` is a directory — i.e. a normal repo).
pub fn detect_worktree(cwd: &Path) -> Option<WorktreeInfo> {
    match try_detect_worktree(cwd) {
        Ok(info) => info,
        Err(e) => {
            debug!(
                "git worktree detection failed for {}: {:#}",
                cwd.display(),
                e
            );
            None
        }
    }
}

fn try_detect_worktree(cwd: &Path) -> Result<Option<WorktreeInfo>> {
    let dot_git = find_dot_git(cwd)?;

    // In a normal repo `.git` is a directory; in a worktree it's a file.
    if dot_git.is_dir() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&dot_git)
        .with_context(|| format!("reading {}", dot_git.display()))?;

    let git_dir = parse_gitdir_pointer(&content)
        .with_context(|| format!("parsing gitdir pointer in {}", dot_git.display()))?;

    // Resolve relative gitdir paths against the directory containing `.git`.
    let base = dot_git
        .parent()
        .with_context(|| format!("{} has no parent", dot_git.display()))?;
    let git_dir = normalize_path(&base.join(&git_dir));

    // Read the `commondir` file to find the shared git directory.
    let common_dir = resolve_common_dir(&git_dir)?;

    debug!(
        git_dir = %git_dir.display(),
        common_dir = %common_dir.display(),
        "detected git worktree"
    );

    Ok(Some(WorktreeInfo {
        git_dir,
        common_dir,
    }))
}

/// Walk up from `start` looking for `.git` (file or directory).
fn find_dot_git(start: &Path) -> Result<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        let candidate = current.join(".git");
        if candidate.exists() {
            return Ok(candidate);
        }
        if !current.pop() {
            anyhow::bail!("no .git found above {}", start.display());
        }
    }
}

/// Parse a `gitdir: <path>` line from a `.git` file's content.
fn parse_gitdir_pointer(content: &str) -> Result<PathBuf> {
    let line = content
        .lines()
        .find(|l| l.starts_with("gitdir:"))
        .with_context(|| "no 'gitdir:' line found")?;

    let path_str = line
        .strip_prefix("gitdir:")
        .with_context(|| "malformed gitdir line")?
        .trim();

    if path_str.is_empty() {
        anyhow::bail!("empty gitdir path");
    }

    Ok(PathBuf::from(path_str))
}

/// Resolve the common directory from a worktree git dir.
///
/// The `commondir` file in the worktree's git dir contains a (typically
/// relative) path to the shared git directory.
fn resolve_common_dir(git_dir: &Path) -> Result<PathBuf> {
    let commondir_file = git_dir.join("commondir");
    let content = std::fs::read_to_string(&commondir_file)
        .with_context(|| format!("reading {}", commondir_file.display()))?;

    let relative = content.trim();
    if relative.is_empty() {
        anyhow::bail!("empty commondir in {}", commondir_file.display());
    }

    Ok(normalize_path(&git_dir.join(relative)))
}

/// Normalize a path by resolving `.` and `..` components without requiring
/// the path to exist (unlike `std::fs::canonicalize`).
fn normalize_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::CurDir => {}
            other => components.push(other),
        }
    }
    components.iter().collect()
}

/// Return the git directories that need sandbox access for a worktree.
///
/// Returns an empty vec if not in a worktree or if worktree access is
/// disabled via `CLASH_NO_WORKTREE_ACCESS=1`. Paths are canonicalized
/// when possible (needed for macOS Seatbelt which operates on real paths).
pub fn worktree_sandbox_paths(cwd: &Path) -> Vec<String> {
    if std::env::var("CLASH_NO_WORKTREE_ACCESS").is_ok_and(|v| v == "1" || v == "true") {
        debug!("git worktree access disabled via CLASH_NO_WORKTREE_ACCESS");
        return Vec::new();
    }

    let info = match detect_worktree(cwd) {
        Some(info) => info,
        None => return Vec::new(),
    };

    let mut paths = Vec::new();

    // Canonicalize for Seatbelt (resolves symlinks like /var → /private/var).
    let canonicalize = |p: &Path| -> String {
        std::fs::canonicalize(p)
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_else(|_| p.to_string_lossy().into_owned())
    };

    paths.push(canonicalize(&info.git_dir));
    paths.push(canonicalize(&info.common_dir));

    paths.dedup();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a fake worktree structure in a temp directory.
    fn setup_worktree(tmp: &Path) -> (PathBuf, PathBuf) {
        // Main repo structure
        let main_repo = tmp.join("main-repo");
        let git_dir = main_repo.join(".git");
        let worktree_git = git_dir.join("worktrees").join("feature");
        fs::create_dir_all(&worktree_git).unwrap();

        // commondir in the worktree git dir points back to the main .git
        fs::write(worktree_git.join("commondir"), "../..").unwrap();
        // HEAD file so it looks like a real git dir
        fs::write(worktree_git.join("HEAD"), "ref: refs/heads/feature\n").unwrap();

        // Worktree directory with .git file
        let worktree = tmp.join("feature-worktree");
        fs::create_dir_all(&worktree).unwrap();
        fs::write(
            worktree.join(".git"),
            format!("gitdir: {}", worktree_git.display()),
        )
        .unwrap();

        (worktree, git_dir)
    }

    #[test]
    fn detect_worktree_finds_info() {
        let tmp = tempfile::tempdir().unwrap();
        let (worktree, git_dir) = setup_worktree(tmp.path());

        let info = detect_worktree(&worktree).expect("should detect worktree");
        let worktree_git = git_dir.join("worktrees").join("feature");

        // normalize_path won't canonicalize, so compare normalized forms
        assert_eq!(info.git_dir, normalize_path(&worktree_git));
        assert_eq!(info.common_dir, normalize_path(&git_dir));
    }

    #[test]
    fn detect_worktree_returns_none_for_normal_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("normal-repo");
        fs::create_dir_all(repo.join(".git")).unwrap();

        assert!(detect_worktree(&repo).is_none());
    }

    #[test]
    fn detect_worktree_returns_none_for_non_git() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(detect_worktree(tmp.path()).is_none());
    }

    #[test]
    fn parse_gitdir_pointer_valid() {
        let path =
            parse_gitdir_pointer("gitdir: /home/user/repo/.git/worktrees/feature\n").unwrap();
        assert_eq!(
            path,
            PathBuf::from("/home/user/repo/.git/worktrees/feature")
        );
    }

    #[test]
    fn parse_gitdir_pointer_relative() {
        let path = parse_gitdir_pointer("gitdir: ../.git/worktrees/feature\n").unwrap();
        assert_eq!(path, PathBuf::from("../.git/worktrees/feature"));
    }

    #[test]
    fn parse_gitdir_pointer_missing() {
        assert!(parse_gitdir_pointer("something else\n").is_err());
    }

    #[test]
    fn parse_gitdir_pointer_empty_path() {
        assert!(parse_gitdir_pointer("gitdir:  \n").is_err());
    }

    #[test]
    fn normalize_path_resolves_parent() {
        let path = normalize_path(Path::new("/a/b/c/../../d"));
        assert_eq!(path, PathBuf::from("/a/d"));
    }

    #[test]
    fn normalize_path_resolves_current() {
        let path = normalize_path(Path::new("/a/./b/./c"));
        assert_eq!(path, PathBuf::from("/a/b/c"));
    }

    #[test]
    fn worktree_sandbox_paths_returns_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let (worktree, _git_dir) = setup_worktree(tmp.path());

        let paths = worktree_sandbox_paths(&worktree);
        assert_eq!(paths.len(), 2);
        // Both paths should be non-empty strings
        for p in &paths {
            assert!(!p.is_empty());
        }
    }

    #[test]
    fn worktree_sandbox_paths_disabled_by_env_var() {
        let tmp = tempfile::tempdir().unwrap();
        let (worktree, _git_dir) = setup_worktree(tmp.path());

        // SAFETY: this test runs single-threaded and we restore the var immediately.
        unsafe { std::env::set_var("CLASH_NO_WORKTREE_ACCESS", "1") };
        let paths = worktree_sandbox_paths(&worktree);
        unsafe { std::env::remove_var("CLASH_NO_WORKTREE_ACCESS") };

        assert!(paths.is_empty());
    }

    #[test]
    fn worktree_sandbox_paths_empty_for_normal_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("normal-repo");
        fs::create_dir_all(repo.join(".git")).unwrap();

        let paths = worktree_sandbox_paths(&repo);
        assert!(paths.is_empty());
    }

    #[test]
    fn relative_gitdir_resolved_against_dotgit_parent() {
        let tmp = tempfile::tempdir().unwrap();

        // Main repo with .git directory
        let main_repo = tmp.path().join("main-repo");
        let git_dir = main_repo.join(".git");
        let wt_git = git_dir.join("worktrees").join("wt1");
        fs::create_dir_all(&wt_git).unwrap();
        fs::write(wt_git.join("commondir"), "../..").unwrap();
        fs::write(wt_git.join("HEAD"), "ref: refs/heads/wt1\n").unwrap();

        // Worktree next to main repo, using a relative gitdir pointer
        let worktree = tmp.path().join("wt1-dir");
        fs::create_dir_all(&worktree).unwrap();
        fs::write(
            worktree.join(".git"),
            format!("gitdir: ../main-repo/.git/worktrees/wt1"),
        )
        .unwrap();

        let info = detect_worktree(&worktree).expect("should detect worktree");
        assert_eq!(info.git_dir, normalize_path(&wt_git));
        assert_eq!(info.common_dir, normalize_path(&git_dir));
    }
}
