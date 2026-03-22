---
layout: base.njk
title: Clash
description: Pattern-matching sandboxes for commands you don't fully trust
---

<div class="hero">
  <h1 class="hero-title">clash</h1>
  <p class="hero-tagline">Sandbox anything, trust what you run.</p>
  <p class="hero-subtitle"><strong>C</strong>ommand <strong>L</strong>ine <strong>A</strong>gent <strong>S</strong>afety <strong>H</strong>arness — a pattern-matching policy engine with kernel-enforced sandboxes for AI agents, build scripts, or anything you don't fully trust.</p>
  <div class="hero-install">

```bash
curl -fsSL https://raw.githubusercontent.com/empathic/clash/main/install.sh | bash
```

  </div>
</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## One tool, two modes

Clash works standalone or as an agent plugin. Same policy engine, same kernel sandboxes, same rules.

<div class="cards">
  <div class="card card--green">
    <h3>Sandbox any command</h3>
    <p>Run any command inside a sandbox with restricted filesystem and network access. No agent needed — just <code>clash sandbox exec</code>.</p>

```bash
# create a sandbox: read-only project, no network
clash sandbox create build --network deny
clash sandbox add-rule build ./src --caps read

# run a build script inside it
clash sandbox exec --sandbox build --cwd . \
  make build
```

  </div>
  <div class="card card--amber">
    <h3>Guard your AI agent</h3>
    <p>Write policy rules that auto-approve safe operations, block dangerous ones, and prompt you only when it matters. Hooks into your agent's plugin system.</p>

```bash
clash init    # install the agent plugin
claude        # every tool call now goes through your policy
```

  </div>
</div>

</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## Kernel-enforced, not honor-system

Clash doesn't ask processes to behave. It tells the kernel what they're allowed to touch.

On **Linux**, Landlock restricts filesystem access and seccomp + proxy filters network calls. On **macOS**, Seatbelt profiles do the same. Either way: restrictions are inherited by every child process, can't be escaped, and work on any binary — not just programs that opt in.

```bash
# verify your platform supports sandboxing
clash sandbox check

# test it interactively
clash sandbox test
```

</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## Yes, we see the irony

Our install instructions say `curl | bash`. So does every Rust toolchain, Node version manager, and Homebrew setup guide. You've probably run a dozen of these this year. Each one had full access to your home directory, your SSH keys, your shell history, everything.

What if you could sandbox that?

```bash
# create a sandbox for install scripts:
# write only to ~/.local/bin, read the rest, no network after download
clash sandbox create installer --network deny
clash sandbox add-rule installer ~/.local/bin --caps write
clash sandbox add-rule installer / --caps read

# now run any install script inside it
curl -fsSL https://example.com/install.sh \
  | clash sandbox exec --sandbox installer --cwd /tmp bash
```

The script can write to `~/.local/bin` and nowhere else. It can't read your SSH keys, can't modify your shell profile, can't phone home. If it tries, the kernel says no.

This is what Clash is for. Not just AI agents — anything you don't trust.

</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## Policies that read like English

```python
# ~/.clash/policy.star
load("@clash//builtin.star", "base")
load("@clash//std.star", "allow", "ask", "deny", "exe", "policy", "cwd", "domains")

def main():
    my_rules = policy(default = ask(), rules = [
        # project files: read and write
        cwd(follow_worktrees = True).allow(read = True, write = True),

        # cargo and git are fine — except the destructive parts
        exe("cargo").allow(),
        exe("git", args = ["push"]).deny(),
        exe("git", args = ["reset", "--hard"]).deny(),
        exe("git").allow(),

        # network: GitHub only
        domains({"github.com": allow()}),
    ])
    return base.update(my_rules)
```

Three effects: <span class="badge badge--allow">allow</span> auto-approves, <span class="badge badge--deny">deny</span> blocks, <span class="badge badge--ask">ask</span> prompts you. First match wins. Edits take effect immediately.

Policies are Starlark (a Python dialect), compiled to a decision tree at load time. Evaluation is in-process and instant — no network, no external process.

</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## How it thinks

<div class="cards">
  <div class="card card--green">
    <h3>Pattern match</h3>
    <p>Every invocation is tested against a tree of pattern-matching rules. Rules match across three domains — <strong>exec</strong> (commands), <strong>fs</strong> (files), and <strong>net</strong> (network). First match wins.</p>
  </div>
  <div class="card card--amber">
    <h3>Sandbox</h3>
    <p>A matched rule can carry a sandbox — kernel-level restrictions on what the process can touch. Filesystem paths, network access, all inherited by child processes, all inescapable.</p>
  </div>
  <div class="card card--red">
    <h3>Decide</h3>
    <p>The match resolves to one of three effects: <span class="badge badge--allow">allow</span> (proceed), <span class="badge badge--deny">deny</span> (block), or <span class="badge badge--ask">ask</span> (prompt the user). No match falls through to the policy default.</p>
  </div>
</div>

</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## Use cases

<div class="cards">
  <div class="card card--green">
    <h3>AI agents</h3>
    <p>Stop clicking "yes" hundreds of times per session. Write policy rules that let your agent work freely on safe operations while blocking dangerous ones. Currently supports <strong>Claude Code</strong>, with more agents planned.</p>
  </div>
  <div class="card card--amber">
    <h3>Build scripts & CI</h3>
    <p>Sandbox <code>make</code>, <code>npm run</code>, or any build command. Restrict it to the source tree and deny network access — so a compromised dependency can't phone home or read your SSH keys.</p>
  </div>
  <div class="card card--red">
    <h3>Untrusted code</h3>
    <p>Running something you didn't write? Give it read-only access to what it needs and nothing else. Kernel enforcement means it can't escape — even if it tries.</p>
  </div>
</div>

</div>

<div class="divider">
  <span class="divider-dot divider-dot--green"></span>
  <span class="divider-dot divider-dot--amber"></span>
  <span class="divider-dot divider-dot--red"></span>
</div>

<div class="section">

## Get started

<ol class="steps">
  <li>
    <strong>Install</strong>
    <pre><code class="language-bash">curl -fsSL https://raw.githubusercontent.com/empathic/clash/main/install.sh | bash</code></pre>
    Downloads the latest binary for your platform (Apple Silicon, Linux x86_64, Linux aarch64). On Intel Mac: <code>cargo install clash</code>.
  </li>
  <li>
    <strong>Sandbox a command</strong>
    <pre><code class="language-bash">clash sandbox create mybox --network deny
clash sandbox add-rule mybox ./src --caps read
clash sandbox exec --sandbox mybox --cwd . cat ./src/main.rs</code></pre>
    You just ran a command with kernel-enforced filesystem and network restrictions.
  </li>
  <li>
    <strong>Or hook into your agent</strong>
    <pre><code class="language-bash">clash init
claude</code></pre>
    Every tool call now evaluates against your policy. Use <code>/clash:status</code> to see it working.
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

Clash's policy engine and sandboxes are agent-independent. The integration layer hooks into each agent's plugin system.

| Agent | Status |
|---|---|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | **Supported** |
| [Codex CLI](https://github.com/openai/codex) | Planned |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | Planned |
| [OpenCode](https://github.com/opencode-ai/opencode) | Planned |

Want to bring Clash to another agent? [Contributions welcome](https://github.com/empathic/clash).

</div>
