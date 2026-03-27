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

Clash intercepts every tool call Claude makes and runs it through your policy — before anything executes.

<div class="cards">
  <div class="card card--green">
    <h3>Match</h3>
    <p>Every tool call is pattern-matched against your policy — commands, arguments, file paths, network targets. No AI judgment. Same input, same result, every time.</p>
  </div>
  <div class="card card--amber">
    <h3>Decide</h3>
    <p>The most specific matching rule determines the effect. <strong>Allow</strong> runs silently. <strong>Ask</strong> prompts you. <strong>Deny</strong> blocks invisibly — Claude never knows the capability existed.</p>
  </div>
  <div class="card card--red">
    <h3>Sandbox</h3>
    <p>The action executes inside an OS-level sandbox. File access, network scope, and process boundaries are enforced by the kernel, not by convention.</p>
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
