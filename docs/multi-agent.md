# Multi-Agent Support

Clash supports 6 coding agents: Claude Code, Gemini CLI, Codex CLI, Amazon Q CLI, OpenCode, and Copilot CLI. Policies are portable across agents — one policy works for a team where different members use different agents.

## Supported Agents

| Agent | Hook Command | Extension Package |
|-------|-------------|-------------------|
| Claude Code | `clash hook pre-tool-use` (default) | `clash-plugin/` |
| Gemini CLI | `clash hook --agent gemini pre-tool-use` | `clash-gemini-ext/` |
| Codex CLI | `clash hook --agent codex pre-tool-use` | `clash-codex/` |
| Amazon Q CLI | `clash hook --agent amazonq pre-tool-use` | `clash-amazonq/` |
| OpenCode | `clash hook --agent opencode pre-tool-use` | `clash-opencode/` |
| Copilot CLI | `clash hook --agent copilot pre-tool-use` | `clash-copilot/` |

## Setup

```bash
# Claude Code (default)
clash init

# Other agents
clash init --agent gemini
clash init --agent codex

# Verify setup
clash doctor --agent gemini
```

## Writing Portable Policies

### Canonical Tool Names

Clash defines canonical names that work across all agents:

| Canonical | Claude | Gemini | Codex | Amazon Q | OpenCode | Copilot |
|-----------|--------|--------|-------|----------|----------|---------|
| `shell` | Bash | run_shell_command | shell | execute_bash | bash | bash |
| `read` | Read | read_file | — | fs_read | read | view |
| `write` | Write | write_file | — | fs_write | write | — |
| `edit` | Edit | replace | — | — | edit | edit |
| `glob` | Glob | glob | — | — | glob | — |
| `grep` | Grep | grep_search | — | — | grep | — |
| `web_fetch` | WebFetch | web_fetch | — | — | webfetch | — |
| `web_search` | WebSearch | google_web_search | web_search | — | websearch | — |

Use canonical names in policies for portability:

```python
# Portable — works across all agents
tool("shell").allow()
tool("read").allow()

# Agent-specific — only matches Claude Code
tool("Bash").allow()
```

Matching is case-insensitive: `tool("bash")`, `tool("BASH")`, and `tool("shell")` all match the same tool.

### Capability-Level Rules

Capability rules (`exec`, `fs`, `net`) are inherently portable since they operate on extracted values, not tool names:

```python
# These work identically across all agents
policy("default", {"Bash": {("git", "cargo", "npm"): allow()}})
tool(["read", "write", "edit"]).allow()
```

### Agent-Scoped Rules

Use `agent()` conditions for agent-specific behavior:

```python
# Only applies when running under Gemini CLI
policy("default", {Tool("save_memory"): deny()})  # inside an agent("gemini") scope
```

### Checking Portability

```bash
clash policy check
```

Reports agent-specific tool names in your policy and suggests canonical alternatives.

## Architecture

### How It Works

```
Agent (Claude/Gemini/Codex/...)
    ↓ JSON stdin
clash hook --agent <name> pre-tool-use
    ↓ HookProtocol::parse_tool_use()
ToolUseHookInput (internal tool names)
    ↓ check_permission()
Policy Engine (agent-agnostic)
    ↓ PolicyDecision
HookProtocol::format_allow/deny/ask()
    ↓ JSON stdout
Agent
```

Each agent has a protocol adapter (`clash/src/agents/<name>.rs`) that handles:
- Parsing agent-specific JSON into `ToolUseHookInput` with internal tool names
- Formatting decisions back into the agent's expected JSON output
- Sandbox command rewriting for shell tools

The policy engine, sandbox enforcement, and audit system are completely agent-agnostic.

### Adding a New Agent

1. Create `clash/src/agents/<name>.rs` implementing `HookProtocol`
2. Add tool mappings to `TOOL_ALIASES` in `clash/src/agents/mod.rs`
3. Add the agent to `AgentKind` enum
4. Wire it into `get_protocol()` in `clash/src/agents/protocol.rs`
5. Create an extension package directory (`clash-<name>/`)
6. Add setup instructions to `clash init --agent <name>`

The canonical tool alias table in `agents/mod.rs` is the single source of truth for tool name mappings. Each entry is curated case-by-case — tools without a clean cross-agent equivalent are not included.

### Key Files

| File | Purpose |
|------|---------|
| `clash/src/agents/mod.rs` | AgentKind enum, canonical tool alias table |
| `clash/src/agents/protocol.rs` | HookProtocol trait, get_protocol() factory |
| `clash/src/agents/claude.rs` | Claude Code protocol adapter |
| `clash/src/agents/gemini.rs` | Gemini CLI protocol adapter |
| `clash/src/agents/codex.rs` | Codex CLI protocol adapter |
| `clash/src/agents/amazonq.rs` | Amazon Q CLI protocol adapter |
| `clash/src/agents/opencode.rs` | OpenCode protocol adapter |
| `clash/src/agents/copilot.rs` | Copilot CLI protocol adapter |
| `clash/src/policy/match_tree.rs` | Canonical name resolution in policy evaluation |
