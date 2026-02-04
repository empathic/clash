# Remove settings.json from ClashSettings

## Problem
`~/.clash/settings.json` only persists `engine_mode`, whose default (`Auto`) is already the right behavior: try `policy.yaml`, fall back to compiling Claude settings. The entire JSON file, along with `EngineMode`, `save()`, `load()`, and `create()`, is dead weight.

## Changes

### `clash/src/settings.rs`
- Delete `EngineMode` enum
- Remove `Serialize`/`Deserialize` derives and `serde` attributes from `ClashSettings` (all fields were `#[serde(skip)]` except `engine_mode`, which is being removed)
- Remove `engine_mode` field
- Delete `settings_file()`, `save()`, `load()`, `create()` methods
- Simplify `resolve_policy()` — always do what `Auto` did (try policy file, fall back to compiling Claude settings)
- Simplify `load_or_create()` to just construct default + call `resolve_policy()`
- Drop unused imports (`serde`, `serde_json`)

### `clash/src/handlers.rs`
- Remove "3. Check settings file" block (lines 168–180) from `handle_session_start` — no more `settings.json` to report on

### `clash/src/permissions.rs` (tests only)
- Remove `engine_mode` field from all `ClashSettings { .. }` struct literals in test helpers

### `clash/src/lib.rs`
- No change needed — doc example still calls `ClashSettings::load_or_create()`

### `clester/src/environment.rs`
- Delete `write_clash_settings()` function
- Remove its call in `TestEnvironment::setup()`
- Delete tests: `test_clash_settings_with_engine_mode`, `test_clash_settings_without_engine_mode`

### `clester/src/script.rs`
- Remove `engine_mode` field from `ClashConfig`

### End-to-end test scripts
- Check `clester/tests/scripts/` for any `engine_mode` references and remove them
