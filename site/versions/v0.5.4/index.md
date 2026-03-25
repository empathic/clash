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

<hr>

<div class="section">

## The problem

Every tool call your agent makes requires a decision. Right now, that decision is yours — every single time.

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

<hr>

<div class="section">

## Get started

```bash
curl -fsSL https://raw.githubusercontent.com/empathic/clash/main/install.sh | bash
clash init
claude
```

Three commands. One binary, one policy file, full enforcement. See the [Quick Start](/quick-start/) for details.

</div>

<hr>

<div class="section">

## Agent support

| Agent | Status |
|---|---|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | **Supported** |
| [Codex CLI](https://github.com/openai/codex) | Planned |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | Planned |
| [OpenCode](https://github.com/opencode-ai/opencode) | Planned |

Clash is agent-independent. [Contributions welcome](https://github.com/empathic/clash).

</div>
