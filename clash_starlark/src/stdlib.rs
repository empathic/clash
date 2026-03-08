//! Embedded prebuilt Starlark sandbox files.
//!
//! These are loaded via `load("@clash//rust.star", "rust_sandbox")` etc.

use include_dir::Dir;
use include_dir::include_dir;

static STDLIB: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/stdlib");

/// Look up an embedded stdlib module by path (e.g. `"rust.star"`).
pub fn get(name: &str) -> Option<&'static str> {
    STDLIB.get_file(name).map(|f| {
        f.contents_utf8()
            .expect("stdlib starlark files must be utf-8 encoded")
    })
}

/// List all available stdlib modules.
pub fn list() -> Vec<String> {
    STDLIB
        .files()
        .map(|f| {
            f.path()
                .file_name()
                .expect("stdlib file names must be utf-8 encoded")
                .to_string_lossy()
                .to_string()
        })
        .collect()
}
