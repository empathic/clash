# Problem

Users have no ambient visibility into what Clash is doing. All enforcement feedback is either
ephemeral (denial messages that scroll away), agent-only (additional_context that users never see),
or on-demand (requires running `/clash:status` or `/clash:audit`). A user who hasn't been denied
recently has no indication that Clash is running at all.

This is a trust problem. Clash's value proposition is "I protect you so you don't have to click
yes/no on every action." But if the user can't *see* that protection happening, they have to
take it on faith. The status line is the only mechanism in Claude Code that is both **continuous**
and **user-facing** — it's the right place for Clash to occupy persistent UI real estate.

## Axioms

- The status line must be fast. It runs after every assistant message (debounced 300ms). If
  `clash statusline` takes >50ms, users will notice lag. The hot path must be a file read,
  not a policy compilation or audit log parse.
- The status line should be informative without being noisy. One line of ambient context,
  not a dashboard. Users glance at it, they don't study it.
- The status line must degrade gracefully. If the session directory doesn't exist, if the
  stats file is missing, if the policy can't be loaded — print something reasonable, never
  error or blank out.
- The status line is a *complement* to denial messages and `/clash:status`, not a replacement.
  It shows "what is happening" at a glance; the other tools explain "why" in depth.

## Protocol summary

The Claude Code status line is configured in `~/.claude/settings.json`:

```json
{
  "statusLine": {
    "type": "command",
    "command": "clash statusline"
  }
}
```

The command receives JSON on stdin with session metadata:
- `session_id` — unique session identifier (maps to `/tmp/clash-<session_id>/`)
- `model.id`, `model.display_name` — current model
- `workspace.current_dir`, `workspace.project_dir` — working directory
- `cost.total_cost_usd`, `cost.total_duration_ms` — session cost/time
- `context_window.used_percentage` — context usage
- `version` — Claude Code version

The command prints text to stdout. Supports:
- Multiple lines (each `echo` = separate row in the status area)
- ANSI escape codes for colors
- OSC 8 escape sequences for clickable links

**When it updates:** After each assistant message, permission mode change, or vim mode toggle.
Debounced at 300ms. If a new update triggers while the script is still running, the in-flight
execution is cancelled.

## Design

### What to display

**Single-line default format:**
```
⚡ deny-all | ✓47 ✗3 ?2
```

Components:
- `⚡` — Clash brand mark, color-coded by posture (red=deny-all, green=allow-all, yellow=ask-default)
- `deny-all` — the default policy effect, so users always know the posture
- `✓47` — allowed count (green)
- `✗3` — denied count (red)
- `?2` — asked count (yellow)

The scoreboard answers the question "is Clash doing anything?" at a glance. If the user sees
`✓200 ✗0`, they know everything's flowing. If they see `✗15`, they know something's being
actively blocked and might want to investigate.

**Optional two-line format (for users who want more):**
```
⚡ deny-all +exec +fs:rw -net | ✓47 ✗3 ?2
  last: ✗ denied exec(git push) 3s ago
```

Second line shows the most recent decision with age. This gives a real-time "ticker tape"
without requiring `/clash:audit`.

### What NOT to display

- Full rule listings — that's what `/clash:status` is for
- Audit log entries — that's what `/clash:audit` is for
- Policy file paths or layer information — too detailed for ambient display
- Anything that requires the user to understand policy syntax

### Performance architecture

The status line command runs frequently (~every assistant message). It must be fast.

**Current state:** Clash writes per-session audit logs to `/tmp/clash-<session_id>/audit.jsonl`.
Parsing this file on every render is O(n) in the number of decisions — it grows unboundedly
during a session and would get slower over time.

**Solution: a stats sidecar file.** On every `log_decision()` call, Clash atomically writes a
small stats file alongside the audit log:

```
/tmp/clash-<session_id>/stats.json
```

Contents:
```json
{
  "allowed": 47,
  "denied": 3,
  "asked": 2,
  "last_tool": "Bash",
  "last_input_summary": "git push origin main",
  "last_effect": "deny",
  "last_at": 1706123456.789,
  "default_effect": "deny"
}
```

The `clash statusline` command then:
1. Reads `session_id` from stdin JSON (~negligible, it's small)
2. Reads `/tmp/clash-<session_id>/stats.json` (single small file read)
3. Formats and prints

No policy compilation, no audit log parsing, no decision tree evaluation. Target: <10ms.

The `default_effect` field is written at session init time (by `handle_session_start`) and
captures the policy's default effect so the status line doesn't need to load/compile the policy.

### Integration with existing status lines

Users may already have a status line configured (git info, cost tracking, context bars). Clash
should not clobber their existing setup. Two approaches:

**Option A: Composable script.** `clash statusline` is a standalone command that outputs one line.
Users compose it into their existing status line script:

```bash
#!/bin/bash
input=$(cat)
# Line 1: Clash status
echo "$input" | clash statusline
# Line 2: their existing stuff
MODEL=$(echo "$input" | jq -r '.model.display_name')
echo "[$MODEL] ..."
```

**Option B: Clash wraps the existing command.** `clash statusline --wrap "~/.claude/statusline.sh"`
reads stdin, pipes it to both Clash's own formatter and the user's script, concatenates output.

**Recommendation:** Option A for v1. It's simpler, doesn't require Clash to know about the user's
existing config, and follows the Unix philosophy. Option B could be a convenience in v2.

### Installation

`clash statusline install` writes the config to `~/.claude/settings.json`:
- If no `statusLine` field exists: set it to `{"type": "command", "command": "clash statusline"}`
- If a `statusLine` field already exists: warn and suggest the composable approach (option A)

`clash statusline uninstall` removes the config (or the Clash portion).

This could also be part of `clash init` — after setting up the policy, offer to install the
status line: "Want Clash status in your Claude Code status bar? (clash statusline install)"

## Proposed implementation

### `clash statusline` subcommand

New CLI subcommand that reads Claude Code's status line JSON from stdin, reads session stats,
and prints formatted output.

```rust
/// Display clash status in the Claude Code status line
Statusline {
    /// Output format
    #[arg(long, default_value = "compact")]
    format: StatuslineFormat,
}

enum StatuslineFormat {
    Compact,  // single line: ⚡ deny-all | ✓47 ✗3 ?2
    Full,     // two lines: adds last decision
}
```

The command:
1. Reads JSON from stdin, extracts `session_id`
2. Reads `/tmp/clash-<session_id>/stats.json`
3. Formats output based on `--format`
4. Prints to stdout

If stats.json doesn't exist (session just started, no decisions yet):
```
⚡ deny-all | ready
```

If the session directory doesn't exist at all:
```
⚡ clash
```

### Stats sidecar file

Extend `audit::log_decision()` to also write/update the stats file. This is an atomic
write (write to temp file, rename) to prevent partial reads by the status line command.

The stats file includes `default_effect` which is set during `handle_session_start` via a
new `audit::init_session_stats()` function that writes the initial stats with zero counters
and the policy's default effect.

### `clash statusline install/uninstall`

Reads and modifies `~/.claude/settings.json` using the existing `claude_settings` crate.
Adds or removes the `statusLine` field.

## Execution plan

### Workstreams and task DAG

```
WS1: Stats sidecar ──────────┐
  T1: Define stats.json schema │
  T2: Write stats in log_decision │
  T3: Init stats in session_start ├──→ WS3: Testing
                                  │      T9: Unit tests (stats write)
WS2: Statusline command ─────┤      T10: Unit tests (format output)
  T4: CLI subcommand definition  │      T11: Clester e2e (full flow)
  T5: Stdin JSON parsing         │
  T6: Stats file reading         │
  T7: Output formatting          ├──→ WS3
  T8: Install/uninstall          │
```

**Dependencies:**
- WS2 depends on WS1 (needs stats file to exist)
- T4-T5 can start in parallel with WS1 (stdin parsing doesn't need stats)
- T6-T7 need T1-T3 complete (schema must be defined)
- T8 is independent of everything else
- WS3 needs WS1 + WS2 complete

### WS1: Stats sidecar file

**T1: Define stats.json schema**

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionStats {
    pub allowed: u64,
    pub denied: u64,
    pub asked: u64,
    pub last_tool: Option<String>,
    pub last_input_summary: Option<String>,
    pub last_effect: Option<String>,
    pub last_at: Option<String>,
    pub default_effect: String,
}
```

The struct lives in `audit.rs` alongside the existing audit types.

Files: `clash/src/audit.rs`

**T2: Write stats in log_decision**

After writing the audit log entry (existing behavior), also update the stats file:
1. Read current stats from `/tmp/clash-<session_id>/stats.json` (or start from defaults)
2. Increment the appropriate counter (allowed/denied/asked)
3. Update last_* fields
4. Atomic write (write to `.stats.json.tmp`, rename to `stats.json`)

The read-increment-write cycle is safe because Clash hook invocations are sequential per session
(Claude Code waits for PreToolUse to complete before the next tool call).

Files: `clash/src/audit.rs`

**T3: Init stats in session_start**

Extend `audit::init_session()` to also write the initial stats file:
```json
{
  "allowed": 0, "denied": 0, "asked": 0,
  "last_tool": null, "last_input_summary": null,
  "last_effect": null, "last_at": null,
  "default_effect": "deny"
}
```

The `default_effect` is determined by loading the policy settings and reading the compiled
default effect. This is the one place where policy compilation happens — at session start,
not on every status line render.

Files: `clash/src/audit.rs`, `clash/src/handlers.rs`

### WS2: Statusline command

**T4: CLI subcommand definition**

Add `Statusline` variant to the `Commands` enum in `cli.rs`:

```rust
/// Display clash status in the Claude Code status line
Statusline {
    #[command(subcommand)]
    cmd: Option<StatuslineCmd>,
    /// Output format (when no subcommand given)
    #[arg(long, default_value = "compact")]
    format: StatuslineFormat,
}

enum StatuslineCmd {
    /// Install the status line into Claude Code settings
    Install,
    /// Remove the status line from Claude Code settings
    Uninstall,
}
```

When invoked without a subcommand, it reads stdin and prints the status line.
When invoked with `install` or `uninstall`, it modifies settings.

Files: `clash/src/cli.rs`, `clash/src/cmd/statusline.rs` (new)

**T5: Stdin JSON parsing**

Parse the Claude Code status line JSON input. We only need `session_id` from it, but should
define a struct for the full input in case we want more fields later:

```rust
#[derive(Deserialize)]
struct StatuslineInput {
    session_id: String,
    // Future: model, workspace, cost, context_window for richer display
}
```

Read from stdin with a timeout or size limit — if Claude Code sends malformed input, don't hang.

Files: `clash/src/cmd/statusline.rs`

**T6: Stats file reading**

Read `/tmp/clash-<session_id>/stats.json`. Handle gracefully:
- File doesn't exist → return default SessionStats
- File is malformed → return default SessionStats (log warning to stderr, not stdout)
- Permission error → return default SessionStats

Files: `clash/src/cmd/statusline.rs`

**T7: Output formatting**

Format the output string. Use the existing `style.rs` ANSI color helpers.

**Compact format:**
```rust
fn format_compact(stats: &SessionStats) -> String {
    let posture_color = match stats.default_effect.as_str() {
        "deny" => RED,
        "allow" => GREEN,
        "ask" => YELLOW,
        _ => RESET,
    };
    let shield = format!("{posture_color}⚡{RESET}");
    let posture = &stats.default_effect;
    let allowed = format!("{GREEN}✓{}{RESET}", stats.allowed);
    let denied = format!("{RED}✗{}{RESET}", stats.denied);
    let asked = format!("{YELLOW}?{}{RESET}", stats.asked);

    format!("{shield} {posture}-all | {allowed} {denied} {asked}")
}
```

**Full format:** adds a second line with the last decision:
```rust
fn format_full(stats: &SessionStats) -> String {
    let line1 = format_compact(stats);
    let line2 = match (&stats.last_tool, &stats.last_effect) {
        (Some(tool), Some(effect)) => {
            let summary = stats.last_input_summary.as_deref().unwrap_or("");
            let age = format_age(stats.last_at.as_deref());
            let effect_colored = color_effect(effect);
            format!("  last: {effect_colored} {tool}({summary}) {age}")
        }
        _ => "  ready".to_string(),
    };
    format!("{line1}\n{line2}")
}
```

Edge cases:
- Zero decisions: show `ready` instead of `✓0 ✗0 ?0`
- Very long input summaries: truncate to ~30 chars (status line has limited width)
- Terminal doesn't support color: `style.rs` already handles TTY detection

Files: `clash/src/cmd/statusline.rs`, `clash/src/style.rs`

**T8: Install/uninstall**

`clash statusline install`:
1. Load `~/.claude/settings.json` via `claude_settings`
2. Check if `statusLine` key exists
3. If not: add `{"type": "command", "command": "clash statusline"}`
4. If yes: warn "Status line already configured. To compose with Clash, add
   `echo \"$input\" | clash statusline` to your existing script."
5. Write back

`clash statusline uninstall`:
1. Load settings
2. If `statusLine.command` contains "clash statusline": remove the `statusLine` key
3. If it doesn't (user composed it into their own script): warn "Your status line
   references a custom script. Remove the `clash statusline` call manually."
4. Write back

Files: `clash/src/cmd/statusline.rs`, `claude_settings/src/lib.rs` (if needed)

### WS3: Testing

**T9: Unit tests for stats write**
- `log_decision` creates/updates stats.json
- Counters increment correctly for each effect
- Last decision fields update
- Atomic write doesn't corrupt on concurrent read
- Missing session dir doesn't panic

Files: `clash/src/audit.rs`

**T10: Unit tests for format output**
- Compact format with various counter values
- Full format with last decision
- Zero-decision "ready" state
- Input summary truncation
- Graceful degradation (missing stats file, malformed input)

Files: `clash/src/cmd/statusline.rs`

**T11: Clester e2e test**
- Full flow: session start → tool use → status line reads stats
- Verify stats.json is created and updated
- Verify `clash statusline` produces expected output

Files: `clester/tests/scripts/`

## Integration with onboarding

The status line complements the interactive onboarding plan. Specifically:

- **Phase 1 (deny-all):** The status line shows `⚡ deny-all | ✗N` — the user sees denials
  accumulating, reinforcing that Clash is active and protecting them.
- **Phase 2 (presets):** After `clash allow editing`, the allowed count starts climbing while
  denials for edit/write disappear. The shift is visible: `✓30 ✗2` vs earlier `✓5 ✗15`.
- **Phase 3 (broad allows):** The status line shows mostly allows with rare denials, confirming
  the policy is working as intended.

The status line could also be installed automatically during `clash init` (the onboarding plan's
T3/T4), making it part of the default Clash experience rather than an opt-in feature.

## Future directions (not in v1)

- **Clickable counts:** OSC 8 links on `✗3` that open `clash audit --filter deny` output
- **Policy posture summary:** `+exec +fs:rw -net` compact capability listing
- **Composable wrapper:** `clash statusline --wrap "existing-script.sh"` for seamless integration
- **Notification flash:** Brief color flash on the `⚡` when a new denial occurs
- **Plugin-provided fields:** If Claude Code ever adds extension points to the status line input
  JSON, Clash could publish data directly rather than going through the stats sidecar

## Open questions

- **Should `clash init` auto-install the status line?** Pro: every Clash user gets ambient
  visibility by default. Con: modifying `settings.json` without being asked may surprise users.
  Could be an opt-in prompt during init: "Install Clash status bar? [Y/n]"

- **Should the status line show policy posture detail?** The compact `deny-all` is clear, but
  `+exec +fs:rw -net` requires understanding capability domains. This might be too much for
  new users but valuable for experienced ones. Could be a `--format full` feature.

- **Cache invalidation for default_effect:** If the user changes their policy mid-session (e.g.,
  `clash allow editing`), the `default_effect` in stats.json is stale. Should the stats file
  update when the policy changes? The default effect itself doesn't change (it's always
  deny/allow/ask from the policy header), so this is likely fine. But the posture *feeling*
  changes — after adding allows, the user is more permissive even though the default is still
  deny. Should the status line reflect this somehow?

- **Performance on slow filesystems:** The stats file is in `/tmp` which is typically fast.
  But on some systems (networked home dirs, encrypted volumes), even a single file read could
  be slow. Should the status line command have a hard timeout (e.g., 30ms) after which it
  prints a fallback?

- **Session policy bug:** During research for this plan, we observed that `clash policy allow
  --scope session` claims success but the rule is not loaded by the evaluator or shown by
  `policy list`. This is a separate bug but worth tracking — it affects the status line story
  because session-scoped policy changes would ideally be reflected in the status line display.
