---
layout: base.njk
title: Clash
description: Command Line Agent Safety Harness
---

<div class="hero">
  <h1 class="hero-title">clash</h1>
  <p class="hero-tagline">Stop babysitting your agents, go touch grass.</p>
  <p class="hero-subtitle">Command Line Agent Safety Harness</p>
  <div class="hero-install">

```bash
curl -fsSL https://raw.githubusercontent.com/empathic/clash/main/install.sh | bash
clash init
claude
```

  </div>
</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## The problem

Coding agents operate with broad tool access — executing commands, editing
files, and making network requests on your behalf. Their permission models tend
to be all-or-nothing: either you allow a tool entirely or get prompted every
time.

You end up clicking "yes" hundreds of times a session, or giving blanket
approval and hoping for the best.

Clash gives you granular control. Write policy rules that decide what to
**allow**, **deny**, or **ask** about — then let the agent work freely on safe
operations while blocking dangerous ones. On Linux, rules can generate
kernel-enforced filesystem sandboxes so even allowed commands can only touch the
files you specify.

</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## Three concepts

<div class="cards">
  <div class="card card--green">
    <h3>Rule</h3>
    <p>An effect paired with a capability matcher. <code>exe("git").allow()</code> lets the agent run any git command. <code>exe("git", args=["push"]).deny()</code> blocks pushes. Rules use first-match semantics — put specific rules before broad ones.</p>
  </div>
  <div class="card card--amber">
    <h3>Domain</h3>
    <p>Rules target one of three capability domains: <strong>exec</strong> (shell commands), <strong>fs</strong> (file operations), and <strong>net</strong> (network access). Clash speaks in capabilities, not tool names — a single rule can cover multiple agent tools.</p>
  </div>
  <div class="card card--red">
    <h3>Layer</h3>
    <p>Policies stack in three levels: <strong>User</strong> (personal defaults), <strong>Project</strong> (repo-specific rules), and <strong>Session</strong> (temporary overrides). Higher layers shadow lower layers. Session &gt; Project &gt; User.</p>
  </div>
</div>

</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## Without Clash vs. with Clash

<div class="comparison">

| Without Clash | With Clash |
|---|---|
| Click "yes" hundreds of times per session | Auto-approve safe operations, block dangerous ones |
| All-or-nothing tool permissions | Granular rules by command, file path, and domain |
| No visibility into what the agent is doing | Status line shows live allow/deny/ask counts |
| Trust the agent with everything or nothing | Kernel-enforced sandboxes constrain even allowed commands |
| Same permissions for every project | Per-project and per-session policy layers |

</div>

</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## A minimal policy

```python
# ~/.clash/policy.star (user level)
load("@clash//builtin.star", "base")
load("@clash//std.star", "exe", "policy", "cwd", "domains")

def main():
    my_rules = policy(default = ask, rules = [
        cwd(follow_worktrees = True, read = allow, write = allow),
        exe("cargo").allow(),
        exe("git", args = ["push"]).deny(),
        exe("git", args = ["reset", "--hard"]).deny(),
        exe("git").allow(),
        domains({"github.com": allow}),
    ])
    return my_rules.merge(base)
```

<details>
<summary>Compiled JSON IR</summary>

```json
{
  "schema_version": 5,
  "default_effect": "ask",
  "sandboxes": {},
  "tree": [
    { "condition": { "observe": "tool_name", "pattern": { "literal": { "literal": "Bash" } },
        "children": [
          { "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "cargo" } },
              "children": [{ "decision": { "allow": null } }] } },
          { "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "git" } },
              "children": [
                { "condition": { "observe": { "positional_arg": 1 }, "pattern": { "literal": { "literal": "push" } },
                    "children": [{ "decision": "deny" }] } },
                { "condition": { "observe": { "positional_arg": 1 }, "pattern": { "literal": { "literal": "reset" } },
                    "children": [
                      { "condition": { "observe": { "positional_arg": 2 }, "pattern": { "literal": { "literal": "--hard" } },
                          "children": [{ "decision": "deny" }] } }
                    ] } },
                { "decision": { "allow": null } }
              ] } }
        ] } }
  ]
}
```
</details>

Three effects: <span class="badge badge--allow">allow</span> auto-approves, <span class="badge badge--deny">deny</span> blocks, <span class="badge badge--ask">ask</span> prompts you. First matching rule wins — put specific rules before broad ones. Edits take effect immediately — no restart needed.

</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## Quick start

<ol class="steps">
  <li>
    <strong>Install clash</strong>
    <pre><code class="language-bash">curl -fsSL https://raw.githubusercontent.com/empathic/clash/main/install.sh | bash</code></pre>
    Downloads the latest release binary for your platform (Apple Silicon Mac, Linux x86_64, Linux aarch64). On Intel Mac: <code>cargo install clash</code>.
  </li>
  <li>
    <strong>Initialize</strong>
    <pre><code class="language-bash">clash init</code></pre>
    Writes a default policy, installs the Claude Code plugin, configures the status line, and walks you through initial setup.
  </li>
  <li>
    <strong>Launch your agent</strong>
    <pre><code class="language-bash">claude</code></pre>
    Every Claude Code session now loads clash automatically. Use <code>/clash:status</code> inside a session to see your policy in action.
  </li>
</ol>

</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## Agent support

Clash is designed to be **agent-agnostic** — a universal safety harness for any coding agent that executes tools on your behalf. The policy language and capability model are agent-independent; only the integration layer is specific to each agent.

| Agent | Status |
|---|---|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | **Supported** |
| [Codex CLI](https://github.com/openai/codex) | Planned |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | Planned |
| [OpenCode](https://github.com/opencode-ai/opencode) | Planned |

Currently, the Claude Code integration is the most mature. If you'd like to help bring Clash to another agent, [contributions are welcome](https://github.com/empathic/clash).

</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## How it works

<div class="flow">
  <span class="flow-node">Agent</span>
  <span class="flow-arrow">&rarr;</span>
  <span class="flow-node">hook</span>
  <span class="flow-arrow">&rarr;</span>
  <span class="flow-node">clash</span>
  <span class="flow-arrow">&rarr;</span>
  <span class="flow-node badge--allow">allow</span>
  <span class="flow-node badge--deny">deny</span>
  <span class="flow-node badge--ask">ask</span>
</div>

Clash integrates via the agent's plugin system. For Claude Code, a plugin registers hooks that intercept every tool call. Each invocation is evaluated against your policy and returns an allow, deny, or ask decision — before the agent executes anything.

The policy is read on every tool call, so edits take effect immediately. On Linux, allowed exec rules can generate Landlock sandboxes; on macOS, Seatbelt profiles constrain filesystem and network access at the kernel level.

</div>
