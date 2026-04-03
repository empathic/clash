# Legacy Cleanup Design

Remove unused, deprecated, and legacy code from clash and clash_starlark to reduce maintenance burden and make the codebase easier to work in.

## Guiding principle

Only remove code that is dead, explicitly deprecated, or supports formats/features no user has ever used. Keep all multi-agent support, modern Starlark DSL, and core infrastructure intact.

## Section 1: match_tree.star Legacy DSL Path

The old match_tree.star DSL (`exe()`, `tool()`, `has_arg()`, `policy()` wrappers) was superseded by the modern `when()`/`policy()` DSL in std.star. No external user has ever written policies using match_tree.star directly.

**Remove:**
- `clash_starlark/stdlib/match_tree.star` — the legacy DSL file
- `clash_starlark/src/builders/base.rs` — `BasePolicyValue` struct (only exists for legacy path)
- `clash_starlark/src/compile.rs` — dead compiler wrapping `BasePolicyValue`
- `clash_starlark/src/globals.rs`: `_mt_policy()` function (lines ~131-202)
- `clash_starlark/src/globals.rs`: `_register_policy()` function (lines ~239-286)
- `clash_starlark/src/lib.rs`: all 5 `test_match_tree_*` tests that `load("@clash//match_tree.star", ...)`
- `clash/src/cmd/doctor.rs`: `check_deprecated_match()` and its call site

**Keep:**
- `builders/match_tree.rs` — `MatchTreeNode` is the core IR for both old and new paths
- All `_mt_*` pattern builders in globals.rs — used by modern `when.rs`
- `builders/mod.rs` stays but loses `pub mod base;`

## Section 2: Deprecated Playground REPL

`clash playground` is deprecated in favor of `clash policy edit --test`. The main.rs already prints a deprecation notice before running the old code.

**Remove:**
- `clash/src/cmd/playground.rs` (~1,385 lines)
- `clash/src/cmd/mod.rs`: `pub mod playground;` declaration
- `clash/src/main.rs`: `Commands::Playground` match arm
- CLI enum variant for `Playground` in the `Commands` enum

**Keep:**
- `clash/src/policy/test_eval.rs` — shared test evaluation logic, still used by `tui/test_panel.rs`

## Section 3: Legacy Cap String Format and Unused Parsing

The old `"read + write"` string format for capabilities was replaced by the array format `["read", "write"]`. The migration code runs on every policy load but no policies use the old format.

**Remove:**
- `clash/src/policy_loader.rs`: `migrate_legacy_caps()` and `migrate_cap_value()` functions
- `clash/src/policy/sandbox_types.rs`: `Cap::parse()` — the string expression parser. Only callers are migration code and `parse_sandbox_rule()`.
- `clash/src/policy/sandbox_types.rs`: `parse_sandbox_rule()` — defined but never called outside its own tests
- All associated tests for the above

**Keep:**
- `Cap::parse_single()` — used by the `Deserialize` impl for parsing individual cap names from array format
- `Cap::to_list()` — used for display/serialization

## Section 4: Legacy Session Directory Scanning

The old `/tmp/clash-<session_id>/audit.jsonl` layout was replaced by `~/.clash/sessions/<session_id>/audit.jsonl`. Temp files from the old layout have long been cleaned up by the OS.

**Remove:**
- `clash/src/debug/log.rs`: `scan_legacy_session_dirs()` function
- `clash/src/debug/log.rs`: `backfill_session_id()` function
- The call to `scan_legacy_session_dirs()` in `read_all_session_logs()`

## Section 5: Dead Code Sweep and Structural Simplification

**Remove dead code:**
- `clash/src/cmd/doctor.rs`: `check_settings_dir()` — unused helper, never called
- `clash/src/sandbox_hints/formatter.rs`: dead_code-annotated item at line 11

**Structural simplification:**
- `clash_starlark/src/builders/mod.rs`: remove `pub mod base;`, leaving only `pub mod match_tree;`
- `clash_starlark/src/globals.rs`: clean up imports that become unused after removing legacy functions
- `clash/src/policy_loader.rs`: simplify JSON loading path (no migration fixup pass)

**Leave alone:**
- `tui/inline_form.rs` dead_code items — macro-generated, tied to form system
- `settings/discovery.rs` TestEnv — test-only, harmless

## Estimated impact

~2,300 lines removed across clash and clash_starlark. No user-facing behavior changes except `clash playground` ceasing to exist (already deprecated).
