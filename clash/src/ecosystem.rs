//! Ecosystem detection and registry for sandbox auto-configuration.

use std::path::Path;

/// Definition of an ecosystem for sandbox auto-configuration.
#[derive(Debug, Clone)]
pub struct EcosystemDef {
    /// Short name (e.g., "rust", "go", "node").
    pub name: &'static str,
    /// Starlark file to load (e.g., "rust.star").
    pub star_file: &'static str,
    /// Binaries that belong to this ecosystem.
    pub binaries: &'static [&'static str],
    /// Project file markers (checked in `$PWD`).
    pub markers: &'static [&'static str],
    /// Directory markers (checked in `$PWD`).
    pub dir_markers: &'static [&'static str],
    /// Glob markers for extensions (e.g., "*.csproj").
    pub glob_markers: &'static [&'static str],
    /// Safe sandbox name (None if ecosystem has only _full).
    pub safe_sandbox: Option<&'static str>,
    /// Full sandbox name.
    pub full_sandbox: &'static str,
}

/// The complete ecosystem registry.
pub const ECOSYSTEMS: &[EcosystemDef] = &[
    EcosystemDef {
        name: "git",
        star_file: "sandboxes.star",
        binaries: &["git"],
        markers: &[],
        dir_markers: &[".git"],
        glob_markers: &[],
        safe_sandbox: Some("git_safe"),
        full_sandbox: "git_full",
    },
    EcosystemDef {
        name: "rust",
        star_file: "rust.star",
        binaries: &["cargo", "rustc", "rustup"],
        markers: &["Cargo.toml"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: Some("rust_safe"),
        full_sandbox: "rust_full",
    },
    EcosystemDef {
        name: "go",
        star_file: "go.star",
        binaries: &["go"],
        markers: &["go.mod"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: Some("go_safe"),
        full_sandbox: "go_full",
    },
    EcosystemDef {
        name: "node",
        star_file: "node.star",
        binaries: &["node", "npm", "npx", "bun", "deno", "yarn", "pnpm"],
        markers: &["package.json"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: None,
        full_sandbox: "node_full",
    },
    EcosystemDef {
        name: "python",
        star_file: "python.star",
        binaries: &["python", "python3", "pip", "pip3", "uv", "poetry"],
        markers: &["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: None,
        full_sandbox: "python_full",
    },
    EcosystemDef {
        name: "ruby",
        star_file: "ruby.star",
        binaries: &["ruby", "gem", "bundle", "rails"],
        markers: &["Gemfile"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: None,
        full_sandbox: "ruby_full",
    },
    EcosystemDef {
        name: "java",
        star_file: "java.star",
        binaries: &["gradle", "gradlew", "mvn", "mvnw", "java", "javac"],
        markers: &["build.gradle", "pom.xml", "build.gradle.kts"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: None,
        full_sandbox: "java_full",
    },
    EcosystemDef {
        name: "docker",
        star_file: "docker.star",
        binaries: &["docker", "docker-compose", "podman"],
        markers: &["Dockerfile", "docker-compose.yml", "compose.yml"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: Some("docker_safe"),
        full_sandbox: "docker_full",
    },
    EcosystemDef {
        name: "swift",
        star_file: "swift.star",
        binaries: &["swift", "swiftc", "xcodebuild"],
        markers: &["Package.swift"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: None,
        full_sandbox: "swift_full",
    },
    EcosystemDef {
        name: "dotnet",
        star_file: "dotnet.star",
        binaries: &["dotnet", "msbuild"],
        markers: &[],
        dir_markers: &[],
        glob_markers: &["*.csproj", "*.sln", "*.fsproj"],
        safe_sandbox: None,
        full_sandbox: "dotnet_full",
    },
    EcosystemDef {
        name: "make",
        star_file: "make.star",
        binaries: &["make", "cmake", "just"],
        markers: &["Makefile", "CMakeLists.txt", "justfile"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: None,
        full_sandbox: "make_full",
    },
];

/// Look up which ecosystem a binary belongs to.
pub fn ecosystem_for_binary(binary: &str) -> Option<&'static str> {
    ECOSYSTEMS
        .iter()
        .find(|e| e.binaries.contains(&binary))
        .map(|e| e.name)
}

/// Detect ecosystems present in a project directory.
///
/// Combines two signals:
/// - File/directory markers in `project_dir`
/// - Observed binaries from command history
///
/// Returns a deduplicated list of matching ecosystem definitions.
pub fn detect_ecosystems(
    project_dir: &Path,
    observed_binaries: &[&str],
) -> Vec<&'static EcosystemDef> {
    let mut seen = std::collections::BTreeSet::new();
    let mut result = Vec::new();

    for eco in ECOSYSTEMS {
        if seen.contains(eco.name) {
            continue;
        }

        let matched = eco.markers.iter().any(|m| project_dir.join(m).exists())
            || eco.dir_markers.iter().any(|m| project_dir.join(m).is_dir())
            || has_glob_match(project_dir, eco.glob_markers)
            || eco
                .binaries
                .iter()
                .any(|b| observed_binaries.contains(b));

        if matched {
            seen.insert(eco.name);
            result.push(eco);
        }
    }

    result
}

/// Check if any glob pattern matches a file in the directory (root level only).
fn has_glob_match(dir: &Path, patterns: &[&str]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        for pattern in patterns {
            if let Some(ext) = pattern.strip_prefix("*.") {
                if name.ends_with(ext) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_rust_by_marker() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "").unwrap();
        let detected = detect_ecosystems(tmp.path(), &[]);
        assert!(detected.iter().any(|e| e.name == "rust"));
    }

    #[test]
    fn detect_go_by_marker() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("go.mod"), "").unwrap();
        let detected = detect_ecosystems(tmp.path(), &[]);
        assert!(detected.iter().any(|e| e.name == "go"));
    }

    #[test]
    fn detect_by_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let detected = detect_ecosystems(tmp.path(), &["cargo", "docker"]);
        assert!(detected.iter().any(|e| e.name == "rust"));
        assert!(detected.iter().any(|e| e.name == "docker"));
    }

    #[test]
    fn detect_git_by_dir() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        let detected = detect_ecosystems(tmp.path(), &[]);
        assert!(detected.iter().any(|e| e.name == "git"));
    }

    #[test]
    fn detect_deduplicates() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "").unwrap();
        let detected = detect_ecosystems(tmp.path(), &["cargo"]);
        let rust_count = detected.iter().filter(|e| e.name == "rust").count();
        assert_eq!(rust_count, 1);
    }

    #[test]
    fn detect_dotnet_by_glob() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("MyApp.csproj"), "").unwrap();
        let detected = detect_ecosystems(tmp.path(), &[]);
        assert!(detected.iter().any(|e| e.name == "dotnet"));
    }

    #[test]
    fn binary_to_ecosystem_mapping() {
        assert_eq!(ecosystem_for_binary("cargo"), Some("rust"));
        assert_eq!(ecosystem_for_binary("npm"), Some("node"));
        assert_eq!(ecosystem_for_binary("python3"), Some("python"));
        assert_eq!(ecosystem_for_binary("unknown_tool"), None);
    }
}
