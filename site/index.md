---
layout: base.njk
title: Clash
description: Write rules for your AI agent. Clash enforces them.
---

<div class="hero">
  <h1 class="hero-title">clash</h1>
  <p class="hero-tagline">Be an agentic engineer, not an agent babysitter.</p>
  <p class="hero-subtitle">You define the capabilities. Clash enforces them. Your agent never sees a choice.</p>
</div>

<div class="divider"><span>Clash for Claude</span></div>

<div class="section">

Claude interrupts us constantly asking whether it's okay to run some command.
This is why `--dangerously-skip-permissions` is so powerful: we can achieve so
much more per unit prompt.

Every tool call your agent makes requires a decision. Right now, that decision
is yours - *every single time* or **not at all**.

Think of Clash as a new `--safely-skip-permissions` flag.  A way to choose _how_
to run anything safely, not just whether Claude can run it **as *you***.

<div class="cards">
  <div class="card card--red">
    <h3>Approve everything</h3>
    <p><code>git status</code> — Allow. <code>cat file.rs</code> — Allow. <code>cargo test</code> — Allow. Hundreds of times a session. Your flow is gone.</p>
  </div>
  <div class="card card--amber">
    <h3>Approve nothing</h3>
    <p>Skip permissions entirely. Fast, until <code>git push --force</code> hits the wrong remote or <code>rm -rf</code> finds your home directory.</p>
  </div>
  <div class="card card--green">
    <h3>Approve once</h3>
    <p>Write a policy file. Clash enforces it on every tool call, at the OS level. Safe commands run instantly. Dangerous ones are blocked. You stay in flow.</p>
  </div>
</div>

</div>

<div class="divider"><span>Get Started</span></div>

<div class="section">

## Get started with Clash for Claude

Install:
```bash
curl -fsSL https://raw.githubusercontent.com/empathic/clash/main/install.sh | bash
```

Initialize:
```
clash init
```

Run w/ Claude:
```
claude
```

Three commands. One binary, one policy file, full enforcement. See the [Quick Start](/quick-start/) for details.

</div>

<div class="divider"><span>Agent Support</span></div>

<div class="section">

## Agent support

| Agent | Status |
|---|---|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | **Supported** |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | **Protocol ready** |
| [Codex CLI](https://github.com/openai/codex) | **Protocol ready** |
| [Amazon Q CLI](https://github.com/aws/amazon-q-developer-cli) | **Protocol ready** |
| [OpenCode](https://github.com/opencode-ai/opencode) | **Protocol ready** |
| [Copilot CLI](https://github.com/github/copilot-cli) | **Protocol ready** |

Use `clash init --agent <name>` to set up any supported agent. [Contributions welcome](https://github.com/empathic/clash).

</div>
