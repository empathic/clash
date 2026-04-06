//! Canonical tool name constants for policy generation.
//!
//! All policy generators must use these constants instead of hardcoding
//! tool name strings. Adding a new file-access or network tool means
//! updating exactly one place.

/// File-access tools that perform read operations.
pub const FS_READ_TOOLS: &[&str] = &["Read", "Glob", "Grep"];

/// File-access tools that perform write operations.
pub const FS_WRITE_TOOLS: &[&str] = &["Write", "Edit", "NotebookEdit"];

/// All file-access tools (union of read and write).
pub const FS_ALL_TOOLS: &[&str] = &["Read", "Glob", "Grep", "Write", "Edit", "NotebookEdit"];

/// Network-access tools.
pub const NET_TOOLS: &[&str] = &["WebFetch", "WebSearch"];

/// Returns true if the tool name is a file-access tool.
pub fn is_fs_tool(name: &str) -> bool {
    FS_ALL_TOOLS.contains(&name)
}

/// Returns true if the tool name is a network tool.
pub fn is_net_tool(name: &str) -> bool {
    NET_TOOLS.contains(&name)
}

/// Returns true if the tool name is a "special" tool handled by specific
/// policy rules (fs tools, net tools, Bash). Other tools get generic rules.
pub fn is_categorized_tool(name: &str) -> bool {
    is_fs_tool(name) || is_net_tool(name) || name == "Bash"
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fs_all_is_union_of_read_and_write() {
        for tool in FS_READ_TOOLS {
            assert!(
                FS_ALL_TOOLS.contains(tool),
                "{tool} missing from FS_ALL_TOOLS"
            );
        }
        for tool in FS_WRITE_TOOLS {
            assert!(
                FS_ALL_TOOLS.contains(tool),
                "{tool} missing from FS_ALL_TOOLS"
            );
        }
        assert_eq!(
            FS_ALL_TOOLS.len(),
            FS_READ_TOOLS.len() + FS_WRITE_TOOLS.len(),
            "FS_ALL_TOOLS should be exactly read + write"
        );
    }

    #[test]
    fn no_overlap_between_read_and_write() {
        for tool in FS_READ_TOOLS {
            assert!(
                !FS_WRITE_TOOLS.contains(tool),
                "{tool} in both read and write"
            );
        }
    }

    #[test]
    fn is_fs_tool_works() {
        assert!(is_fs_tool("Read"));
        assert!(is_fs_tool("Edit"));
        assert!(!is_fs_tool("Bash"));
        assert!(!is_fs_tool("WebFetch"));
    }

    #[test]
    fn is_categorized_tool_works() {
        assert!(is_categorized_tool("Read"));
        assert!(is_categorized_tool("WebSearch"));
        assert!(is_categorized_tool("Bash"));
        assert!(!is_categorized_tool("Agent"));
        assert!(!is_categorized_tool("TodoWrite"));
    }
}
