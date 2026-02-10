# clash

**C**ommand **L**ine **A**gent **S**afety **H**arness

Permission enforcement for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that makes working with agents more fun and less frustrating.

**Platforms:** macOS (Apple Silicon, Intel) | Linux (x86_64, aarch64)
**License:** Apache 2.0

---

## What is clash?

Claude Code's default permission model is all-or-nothing: either you allow a tool entirely or get prompted every time. Clash gives you granular control with policy rules that decide what to allow, deny, or ask about — so you can let the agent work freely on safe operations while blocking dangerous ones.

- **Policy engine** — Profile-based rules with `deny > ask > allow` precedence
- **Kernel sandbox** — `fs:` constraints on bash rules generate OS-enforced sandboxes (Landlock on Linux, Seatbelt on macOS)
- **Plugin mode** — Runs as a Claude Code plugin for seamless integration
- **CLI mode** — Launch Claude Code with managed hooks via `clash launch`

---

## Quick Start

```bash
# 1. Install (build from source)
cargo install --path clash

# 2. Initialize a policy (creates ~/.clash/policy.yaml)
clash init --bypass-permissions

# 3. Run with Claude Code
clash launch
```

Or use as a Claude Code plugin:

```bash
# Build the plugin
just build-plugin

# Launch Claude Code with the plugin
claude --plugin-dir /tmp/clash-dev/clash-plugin/
```

---

## How It Works

Clash intercepts every tool call Claude Code makes and evaluates it against your policy. Each rule has three parts: **effect**, **verb**, and **noun**.

```yaml
# ~/.clash/policy.yaml
default:
  permission: ask          # what happens when no rule matches
  profile: main

profiles:
  main:
    rules:
      allow read *:                  # let the agent read any file
      allow bash cargo *:            # let it run cargo freely
      allow bash git status:         # allow git status
      ask bash git commit*:          # prompt before committing
      deny bash git push*:           # never allow push
      deny bash rm -rf *:            # never allow rm -rf
```

**Effects:** `allow` (auto-approve), `deny` (block), `ask` (prompt you)

**Precedence:** When multiple rules match, the strictest wins: `deny > ask > allow`

Rules can also have filesystem constraints that generate a kernel-enforced sandbox:

```yaml
      allow bash cargo *:
        fs:
          read + execute: subpath(.)        # read anywhere in project
          write + create: subpath(./target)  # write only to target/
        network: allow
```

For the full rule syntax, see the [Policy Writing Guide](docs/policy-guide.md).

---

## Configuration

Your policy lives at `~/.clash/policy.yaml`. Clash reads it on every tool invocation, so changes take effect immediately — no restart needed.

### Useful commands

```bash
clash policy show              # see active profile and settings
clash policy list-rules        # list all rules in the active profile
clash policy add-rule "allow bash npm *"   # add a rule
clash policy remove-rule "deny bash git push*"  # remove a rule
clash explain bash "git push"  # see which rule matches a command
```

### Migrating from Claude Code permissions

If you already have permissions configured in Claude Code settings, migrate them:

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

Make sure the binary is in your `PATH`. If you installed with `cargo install`, check that `~/.cargo/bin` is on your path:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

### "No policy.yaml found"

Run `clash init` to generate a starter policy:

```bash
clash init --bypass-permissions
```

### Double-prompting (clash asks, then Claude Code asks)

Run init with `--bypass-permissions` to make clash the sole permission handler:

```bash
clash init --bypass-permissions
```

This sets `bypassPermissions: true` in your Claude Code user settings.

### Policy not working as expected

Use `clash explain` to debug which rule matches:

```bash
clash explain bash "git push origin main"
```

### Filing a bug

```bash
clash bug "Short description of the issue" --include-config --include-logs
```

---

## Development

```bash
# Build and launch with the plugin
just dev

# Run all checks (fmt + test + clippy)
just check

# Run end-to-end tests
just clester

# Full CI (unit tests + clippy + e2e)
just ci
```

### Project structure

```
clash/
├── clash/              # CLI binary + library
├── clash-plugin/       # Claude Code plugin (hooks, skills)
├── claude_settings/    # Settings library
├── clester/            # End-to-end test harness
└── docs/               # Documentation
    ├── policy-guide.md
    ├── cli-reference.md
    ├── policy-grammar.md
    └── policy-semantics.md
```

---

## Documentation

- [Policy Writing Guide](docs/policy-guide.md) — how to write rules, profiles, constraints, and recipes
- [CLI Reference](docs/cli-reference.md) — all commands, flags, and options
- [Policy Grammar](docs/policy-grammar.md) — formal EBNF grammar
- [Policy Semantics](docs/policy-semantics.md) — evaluation algorithm and sandbox generation

## License

Apache License 2.0
