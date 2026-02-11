# clash

**C**ommand **L**ine **A**gent **S**afety **H**arness

Permission enforcement for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that makes working with agents more fun and less frustrating.

**Platforms:** macOS (Apple Silicon, Intel) | Linux (x86_64, aarch64)
**License:** [Apache 2.0](LICENSE)

---

## The Problem

Claude Code's default permission model is all-or-nothing: either you allow a tool entirely or get prompted every time. You end up clicking "yes" hundreds of times a session, or giving blanket approval and hoping for the best.

Clash gives you granular control. Write policy rules that decide what to **allow**, **deny**, or **ask** about — then let the agent work freely on safe operations while blocking dangerous ones. On Linux, rules can generate kernel-enforced filesystem sandboxes so even allowed commands can only touch the files you specify.

---

## Quick Start

```bash
# 1. Install (requires Rust toolchain)
cargo install --path clash

# 2. Initialize — creates ~/.clash/policy.yaml and installs the plugin
clash init --bypass-permissions

# 3. Launch Claude Code with clash managing permissions
clash launch
```

That's it. Clash is now intercepting every tool call and evaluating it against your policy. The default policy allows reads and writes within your project, prompts before git commits, and denies destructive operations like `git push`, `git reset --hard`, and `sudo`.

---

## Interactive Configuration

Once clash is running inside Claude Code, you have access to slash commands (skills) for managing your policy without leaving your session:

| Skill | What it does |
|-------|-------------|
| `/clash:onboard` | Interactively build your policy from scratch |
| `/clash:edit` | Guided editing of your policy file |
| `/clash:status` | Show current policy, rules, and enforcement status |
| `/clash:describe` | Plain-English description of your active policy |
| `/clash:explain` | See which rule matches a specific tool invocation |
| `/clash:allow` | Quickly add an allow rule |
| `/clash:deny` | Quickly add a deny rule |
| `/clash:test` | Test your policy against hypothetical tool uses |
| `/clash:migrate` | Import existing Claude Code permissions |
| `/clash:audit` | View recent permission decisions from the audit log |

If you're new, start with `/clash:onboard` — it walks you through creating a policy tailored to your workflow.

---

## Policy Rules

Your policy lives at `~/.clash/policy.yaml`. Clash reads it on every tool invocation, so edits take effect immediately — no restart needed.

Each rule has three parts: **effect**, **verb**, and **noun**.

```yaml
# ~/.clash/policy.yaml
default:
  permission: ask          # what happens when no rule matches
  profile: main

profiles:
  main:
    rules:
      allow read *:                  # let the agent read any file
      allow bash cargo *:            # let it run cargo commands
      ask bash git commit*:          # prompt before committing
      deny bash git push*:           # never allow push
      deny bash rm -rf *:            # never allow rm -rf
```

**Effects:** `allow` (auto-approve), `deny` (block), `ask` (prompt you)

**Precedence:** `deny` always wins. Among non-deny rules, constrained rules (those with `fs:`, `url:`, etc.) beat unconstrained ones. Within the same tier, `ask` beats `allow`. See [Policy Semantics](docs/policy-semantics.md) for the full algorithm.

### Profiles

Rules are organized into **profiles** that can include other profiles, letting you compose reusable policy layers:

```yaml
profiles:
  cwd:
    rules:
      allow * *:
        fs:
          all: subpath(.)           # allow everything within the project

  main:
    include: [cwd, sensitive]       # compose from other profiles
    rules:
      deny bash git push*:
```

### Kernel Sandbox

Rules can carry filesystem constraints that clash compiles into OS-enforced sandboxes (Landlock on Linux, Seatbelt on macOS):

```yaml
      allow bash cargo *:
        fs:
          read + execute: subpath(.)        # read anywhere in project
          write + create: subpath(./target)  # write only to target/
        network: allow
```

Even if a command is allowed by policy, the sandbox ensures it can only access the paths you specify.

For the full rule syntax, see the [Policy Writing Guide](docs/policy-guide.md).

---

## Useful Commands

```bash
clash policy show                            # see active profile and settings
clash policy list-rules                      # list all rules in the active profile
clash policy add-rule "allow bash npm *"     # add a rule
clash policy remove-rule "deny bash git push*"  # remove a rule
clash policy schema                          # show all configurable fields and types
clash explain bash "git push"                # see which rule matches a command
```

### Migrating from Claude Code Permissions

If you already have permissions configured in Claude Code settings, import them:

```bash
clash migrate --dry-run   # preview what would be imported
clash migrate              # import into ~/.clash/policy.yaml
```

For the full command reference, see the [CLI Reference](docs/cli-reference.md).

---

## Requirements

- **macOS** (Apple Silicon or Intel) or **Linux** (x86_64 or aarch64)
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) installed
- Rust toolchain (for building from source)
- Windows is **not** supported

---

## Troubleshooting

### "command not found: clash"

Make sure `~/.cargo/bin` is on your `PATH`:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

### Double-prompting (clash asks, then Claude Code asks)

This means Claude Code's built-in permissions are still active. Re-run init with `--bypass-permissions`:

```bash
clash init --bypass-permissions
```

This sets `bypassPermissions: true` in your Claude Code user settings so clash is the sole permission handler.

### Policy not working as expected

Use `clash explain` to see exactly which rule matches:

```bash
clash explain bash "git push origin main"
```

Or use the `/clash:explain` skill inside Claude Code for an interactive walkthrough.

### Filing a bug

```bash
clash bug "Short description of the issue" --include-config --include-logs
```

---

## Documentation

- [Policy Writing Guide](docs/policy-guide.md) — rules, profiles, constraints, and recipes
- [CLI Reference](docs/cli-reference.md) — all commands, flags, and options
- [Policy Grammar](docs/policy-grammar.md) — formal EBNF grammar
- [Policy Semantics](docs/policy-semantics.md) — evaluation algorithm and sandbox generation

---

## Development

```bash
just dev         # build plugin and launch Claude Code with it
just check       # fmt + test + clippy
just clester     # end-to-end tests
just ci          # full CI (check + clester)
```

### Project Structure

```
clash/
├── clash/              # CLI binary + library
├── clash-plugin/       # Claude Code plugin (hooks, skills)
├── clash_notify/       # Notification support (desktop, Zulip)
├── claude_settings/    # Claude Code settings library
├── clester/            # End-to-end test harness
└── docs/               # Documentation
```

---

## License

Apache License 2.0
