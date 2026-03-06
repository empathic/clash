---
layout: base.njk
title: FAQ
description: Frequently asked questions about Clash.
permalink: /faq/
---

<h1 class="page-title">FAQ</h1>
<p class="page-desc">Common questions about Clash.</p>

## Which agents does Clash support?

Currently, **Claude Code** is fully supported. Codex CLI, Gemini CLI, and OpenCode are planned. The policy language and capability model are agent-independent — only the integration layer (hooks) is specific to each agent. See the [agent support table](/#agent-support) for tracking issues.

---

## How is Clash different from Claude Code's built-in permissions?

Claude Code's built-in permission model is all-or-nothing per tool. Clash adds **granular, capability-based rules**: you can allow `git status` while denying `git push`, allow file reads under your project while denying writes to `.env`, or allow network access to `github.com` while blocking everything else. Clash also supports kernel-enforced sandboxes, policy composition, and per-project layering.

---

## Does Clash slow down my agent?

No. Clash evaluates policy rules in-process on every tool call with negligible overhead — the policy is compiled into a decision tree at load time. There's no network round-trip, no external process, and no noticeable latency.

---

## What happens if my policy has a syntax error?

Clash blocks **all actions** when the policy fails to compile, rather than silently degrading. This is a safety-first design: a broken policy should never result in unintended approvals. Run `clash policy validate` to diagnose the error, or `clash init` to start fresh.

---

## Can I share policies across a team?

Yes. Use a **project-level** policy at `<repo>/.clash/policy.star` and commit it to version control. Team members get shared rules automatically. Individual developers can override with user-level or session-level policies.

---

## How does the kernel sandbox work?

When an exec rule includes a sandbox (via `.sandbox(sb)` in Starlark, or the `"sandbox"` field in JSON IR), Clash generates OS-level restrictions:

- **Linux:** Landlock LSM constrains filesystem access; seccomp + proxy handles network filtering.
- **macOS:** Seatbelt profiles restrict filesystem and network access at the kernel level.

Sandbox restrictions are inherited by all child processes and cannot be bypassed by the sandboxed command. Run `clash sandbox check` to verify your platform supports sandboxing.

---

## Do exec rules apply to subprocesses?

No. Exec rules match only the **top-level command** the agent invokes. If an allowed command like `make deploy` internally calls `git push`, the deny rule for `git push` does not fire. However, **sandbox restrictions** on filesystem and network access *are* enforced on all child processes at the kernel level.

---

## How do I temporarily disable Clash?

Set the `CLASH_DISABLE` environment variable:

```bash
CLASH_DISABLE=1 claude
```

Clash stays installed but becomes a complete pass-through — no policy enforcement, no sandbox, no prompts. Unset the variable or set it to `0` to re-enable.

---

## Which platforms are supported?

- **macOS** — Apple Silicon and Intel
- **Linux** — x86_64 and aarch64
- **Windows** — not supported

Kernel sandboxing requires Landlock (Linux 5.13+) or Seatbelt (macOS). Clash works without sandboxing on older kernels, but sandbox rules will be ignored.

---

## How do I uninstall Clash?

```bash
# Remove the Claude Code plugin (stops hooks immediately)
claude plugin uninstall clash

# Remove the binary
cargo uninstall clash          # if installed via cargo
rm -f ~/.local/bin/clash       # if installed via the install script

# Optional: clean up configuration
rm -rf ~/.clash                # user-level policy and logs
rm -rf .clash                  # project-level policy
```

After removing the plugin, Claude Code reverts to its built-in permission model immediately. Policy files are left in place so you can resume where you left off if you reinstall.
