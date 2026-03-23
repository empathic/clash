---
layout: base.njk
title: Quick Start
description: Get up and running with Clash in under two minutes
permalink: /quick-start/
---

<h1 class="page-title">Quick Start</h1>
<p class="page-desc">From zero to enforced policy in three steps.</p>

## 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/empathic/clash/main/install.sh | bash
```

On Intel Mac, use `cargo install clash` instead.

## 2. Initialize

```bash
clash init
```

This creates a policy file at `~/.clash/policy.star`, installs the Claude Code plugin, and configures permissions so Clash is the sole decision-maker.

To skip the wizard and use sensible defaults:

```bash
clash init --quick
```

## 3. Use it

```bash
claude
```

Every tool call now passes through your policy. Check that it's working:

```bash
clash status
```

To see which rule matches a specific command:

```bash
clash explain bash "git push"
```

---

## What you get out of the box

The default policy:

- <span class="badge badge--allow">allow</span> file reads and writes within your project directory
- <span class="badge badge--allow">allow</span> all command execution inside a sandbox
- <span class="badge badge--deny">deny</span> `git push --force`, `git push --force-with-lease`, `git reset --hard`
- <span class="badge badge--ask">ask</span> for network access (`WebFetch`, `WebSearch`)
- <span class="badge badge--ask">ask</span> for everything else not covered by a rule

---

## Customize it

Open your policy in your editor:

```bash
clash policy edit --raw
```

Or use the CLI to add rules directly:

```bash
# allow cargo commands
clash policy allow "cargo build"
clash policy allow "cargo test"

# block dangerous operations
clash policy deny "rm -rf"

# check what you've got
clash policy list
```

Format your policy file:

```bash
clash fmt
```

---

## Next steps

- [Tutorial](/tutorial/) — Build a policy from scratch, step by step
- [Reference](/reference/) — Full documentation for all policy builders and CLI commands
