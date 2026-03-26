---
layout: base.njk
title: FAQ
description: Frequently asked questions about Clash.
permalink: /faq/
---

<h1 class="page-title">FAQ</h1>
<p class="page-desc">Quick answers to common questions.</p>

## Is Clash only for AI agents?

No. Clash is a general-purpose sandboxing and policy engine. You can use `clash sandbox exec` to sandbox any command — build scripts, install scripts, untrusted binaries, anything. The AI agent integration is one application of the same underlying engine.

---

## How is this different from Docker or Firejail?

Clash is lighter and more targeted. It doesn't virtualize anything — it applies Landlock (Linux) or Seatbelt (macOS) restrictions directly to a process. No container images, no namespaces, no root required. You write a few rules about which paths and network access a command should have, and the kernel enforces them. It's closer to a fine-grained `sandbox-exec` than a container runtime.

---

## How is this different from Claude Code's built-in permissions?

Claude Code gives you per-tool toggles: allow a tool entirely, or get prompted every time. Clash gives you **pattern-matching rules within tools**: allow `git status` while denying `git push`, allow reads under your project while blocking writes to `.env`, allow network access to `github.com` while blocking everything else. Plus kernel-enforced sandboxes, policy composition, and per-project layering.

---

## Which agents does Clash support?

**Claude Code** is fully supported today. Codex CLI, Gemini CLI, and OpenCode are planned. But Clash also works standalone — `clash sandbox exec` sandboxes any command, no agent required. The policy engine is agent-independent; only the hook layer is specific to each agent. See the [agent support table]({{ version.pathPrefix }}/#agent-support).

---

## Will it slow things down?

No. Policies compile into a decision tree at load time. Evaluation is in-process with no network round-trip. Sandbox setup adds a few milliseconds at process launch — then the kernel handles enforcement with zero runtime overhead.

---

## What happens if my policy has a bug?

Clash blocks **everything** when the policy fails to compile. A broken policy should never silently approve things. Run `clash policy validate` to find the error, or `clash init` to start over.

---

## Can I share policies with my team?

Yes. Commit a **project-level** policy at `<repo>/.clash/policy.star`. Team members pick it up automatically. Individuals can still override with user-level or session-level policies.

---

## How does the kernel sandbox work?

When a rule includes a sandbox, Clash generates OS-level restrictions:

- **Linux:** Landlock constrains filesystem access; seccomp + proxy filters network calls.
- **macOS:** Seatbelt profiles restrict filesystem and network access.

Restrictions are inherited by all child processes and cannot be bypassed. Run `clash sandbox check` to verify your platform supports it.

---

## Do rules apply to subprocesses?

Exec rules match only the **top-level command**. If `make deploy` internally runs `git push`, the deny rule for `git push` won't fire. However, **sandbox restrictions** on filesystem and network access are enforced on all child processes at the kernel level — that's the whole point.

---

## How do I turn it off temporarily?

```bash
CLASH_DISABLE=1 claude
```

Clash stays installed but becomes a pass-through — no enforcement, no prompts. Unset the variable to re-enable.

---

## Which platforms work?

- **macOS** — Apple Silicon and Intel
- **Linux** — x86_64 and aarch64
- **Windows** — not supported

Kernel sandboxing needs Landlock (Linux 5.13+) or Seatbelt (macOS). Clash works without sandboxing on older kernels, but sandbox rules will be ignored.

---

## How do I uninstall?

```bash
clash uninstall
```

This removes the Claude Code plugin, the status line, policy files (`~/.clash/`), and the binary — regardless of how it was installed. Use `clash uninstall -y` to skip confirmation prompts.

After uninstalling, Claude Code reverts to its built-in permission model.
