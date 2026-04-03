# Sandbox Violation Hints Design

## Problem

When the sandbox blocks an operation at the OS level (Seatbelt on macOS, Landlock on Linux), the user and model receive cryptic errors like "operation not permitted" with no guidance on what to do. The current hint system exists but has three problems:

1. **Hints are too generic** — say "sandbox is blocking filesystem access" without naming the sandbox, specific operations, or current grants
2. **No configurable directive** — hardcoded "Do NOT retry", but users may want the model to try workarounds or decide based on context
3. **Model behavior is wrong** — Claude stops or tries to circumvent the restriction instead of suggesting policy fixes

## Solution

Improve the existing two-source hint architecture (audit log + stderr heuristics) with precise, actionable hints and a configurable directive via `settings(on_sandbox_violation=...)`.

## `on_sandbox_violation` Setting

New parameter on the `settings()` Starlark function:

```python
settings(default=deny(), on_sandbox_violation="stop")
```

Three values:

- **`"stop"`** (default) — `"Do NOT retry — it will fail again. Fix the policy first, then re-run the command."`
- **`"workaround"`** — `"The sandbox restricts this path. Try an alternative approach to accomplish your goal without accessing these paths. If no workaround is possible, tell the user and suggest the policy fix above."`
- **`"smart"`** — `"Assess: if these paths look like missing dependencies or build artifacts, suggest the policy fix above. If they look like paths outside the project's scope, find an alternative approach instead."`

## Hint Format

### Filesystem violations

```
SANDBOX VIOLATION: sandbox "rust" blocked filesystem access.
- write to /Users/eliot/.cargo/registry (sandbox grants: read+execute)
- write to /Users/eliot/.cargo/bin (sandbox grants: read+execute)

To fix:
  clash sandbox add-rule --name rust --path '/Users/eliot/.cargo/registry/**' --allow 'read+write+create'
  clash sandbox add-rule --name rust --path '/Users/eliot/.cargo/bin/**' --allow 'read+write+create+execute'

[DIRECTIVE]
```

### Network violations

```
SANDBOX VIOLATION: sandbox "rust" blocked network access (policy: deny).

To fix:
  clash sandbox add-rule --name rust --net allow

[DIRECTIVE]
```

Key improvements over current hints:
- Sandbox name included (resolved from policy decision or rewritten command)
- Specific operations — "write to" / "read from" / "execute" instead of just "filesystem access"
- Current grants shown per path — so the user/model understands what's already allowed
- Precise `clash sandbox add-rule` commands using the actual sandbox name
- Configurable directive based on `on_sandbox_violation`

## Architecture Changes

### Starlark layer (`clash_starlark/`)

- `SettingsValue` in `eval_context.rs` gets `on_sandbox_violation: Option<String>` field
- `_register_settings` in `globals.rs` accepts `on_sandbox_violation` kwarg, validates value is one of `stop`/`workaround`/`smart`
- `assemble_document()` emits the field into JSON IR as `"on_sandbox_violation": "<value>"`

### Policy layer (`clash/src/policy/`)

- New enum in an appropriate location:
  ```rust
  #[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
  #[serde(rename_all = "snake_case")]
  pub enum ViolationAction {
      #[default]
      Stop,
      Workaround,
      Smart,
  }
  ```
- `CompiledPolicy` gets `on_sandbox_violation: ViolationAction` field
- `compile.rs` deserializes from JSON IR, defaulting to `Stop`

### Hint generation (`clash/src/sandbox_hints/`, `clash/src/network_hints.rs`)

- `build_fs_hint()` in `formatter.rs` takes sandbox name (`&str`) and `ViolationAction` as additional params
- Formats operation-specific lines ("write to /path") with current grants instead of generic "filesystem access"
- Appends the appropriate directive string based on `ViolationAction`
- `build_network_hint()` in `network_hints.rs` gets same treatment — sandbox name + directive
- `check_for_sandbox_fs_hint()` and `check_for_sandbox_network_hint()` pass through sandbox name and violation action from the resolved policy

### No changes required to

- Violation capture (`sandbox_cmd.rs`) — already captures violations from unified log
- Audit log reading (`sandbox_hints/audit_source.rs`) — already reads violations by tool_use_id
- Stderr parsing (`sandbox_hints/stderr_source.rs`) — already extracts paths from error patterns
- PostToolUse hook handler (`cmd/hooks.rs`) — already assembles hints from both sources

## Data Flow

```
settings(on_sandbox_violation="stop")
  ↓
SettingsValue { on_sandbox_violation: Some("stop") }
  ↓
JSON IR: { "on_sandbox_violation": "stop", ... }
  ↓
CompiledPolicy { on_sandbox_violation: ViolationAction::Stop, ... }
  ↓
PostToolUse hint generation
  ↓
build_fs_hint(sandbox_name, blocked_paths, ViolationAction::Stop)
  ↓
"SANDBOX VIOLATION: sandbox \"rust\" blocked filesystem access.\n..."
  ↓
additional_context in PostToolUseOutput → Claude sees the hint
```

## Testing

- Unit tests for `ViolationAction` serialization/deserialization
- Unit tests for `build_fs_hint()` and `build_network_hint()` with each directive mode
- Unit tests for Starlark `settings()` accepting and validating `on_sandbox_violation`
- Unit tests for `assemble_document()` emitting the field
- End-to-end clester test: sandboxed command hits a violation, verify hint appears in PostToolUse output with correct sandbox name and directive
