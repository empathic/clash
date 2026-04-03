# Git Sandboxes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add worktree-aware, network-enabled git sandboxes (`git_ro` and `git_rw`) to the clash defaults so git operations work properly in worktrees and with remote repos.

**Architecture:** Two new sandbox presets in `sandboxes.star` using existing `subpath(..., follow_worktrees=True)` and `allow()` primitives. Default policy updated to route git commands through these sandboxes based on mode.

**Tech Stack:** Starlark (clash policy DSL)

---

### Task 1: Add `git_ro` and `git_rw` sandboxes to `sandboxes.star`

**Files:**
- Modify: `clash_starlark/stdlib/sandboxes.star`

- [ ] **Step 1: Add `git_ro` sandbox definition**

Add after the `project` sandbox definition (line 33) and before the `workspace` sandbox:

```starlark
git_ro = sandbox(
    name = "git_ro",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow("rx"),
        "$HOME": {
            glob(".gitconfig"): allow("r"),
            glob(".config/git/**"): allow("r"),
            glob(".ssh/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Git read-only: fetch, pull, log, diff. Worktree-aware, network + SSH enabled.",
)
```

- [ ] **Step 2: Add `git_rw` sandbox definition**

Add immediately after `git_ro`:

```starlark
git_rw = sandbox(
    name = "git_rw",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow(FULL),
        "$HOME": {
            glob(".gitconfig"): allow("r"),
            glob(".config/git/**"): allow("r"),
            glob(".ssh/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Git read-write: commit, push, checkout, merge. Worktree-aware, network + SSH enabled.",
)
```

- [ ] **Step 3: Update the comment header to include git sandboxes**

Update the comment block at the top of `sandboxes.star` (lines 1-9) to mention the new sandboxes:

```starlark
# Clash sandbox presets — intent-based trust levels for Bash commands.
#
# These presets express what you trust a command to do, not what
# the command literally says.  Pick a preset based on intent:
#
#   readonly     — read-only project access, network allowed
#   project      — build tools, git: read+write project, no network
#   git_ro       — git read-only: worktree-aware, network + SSH
#   git_rw       — git read-write: worktree-aware, network + SSH
#   workspace    — full home directory access, deny sensitive dirs
#   unrestricted — fully trusted: all filesystem + network access
#
```

- [ ] **Step 4: Validate the policy compiles**

Run: `just check`
Expected: All tests pass, no Starlark compilation errors.

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/sandboxes.star
git commit -m "feat(sandbox): add git_ro and git_rw sandbox presets

Worktree-aware sandboxes with network + SSH access for git operations.
git_ro: read-only (fetch, pull, log, diff)
git_rw: read-write (commit, push, checkout, merge)"
```

---

### Task 2: Update default policy to use git sandboxes

**Files:**
- Modify: `clash/src/default_policy.star`

- [ ] **Step 1: Update the import to include git sandboxes**

Change the load statement on line 2 from:

```starlark
load("@clash//sandboxes.star", "readonly", "project", "workspace")
```

to:

```starlark
load("@clash//sandboxes.star", "readonly", "project", "workspace", "git_ro", "git_rw")
```

- [ ] **Step 2: Add git rule to plan mode**

Update the plan mode block (lines 6-8) to include a git-specific rule:

```starlark
        mode("plan"): {
            glob("**"): allow(sandbox=readonly),
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_ro)
                }
            }
        },
```

- [ ] **Step 3: Update git rule in edit/default mode**

Change the git sandbox in the edit/default mode block (lines 9-15) from `project` to `git_rw`:

```starlark
        (mode("edit"), mode("default")): {
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_rw)
                }
            }
        },
```

- [ ] **Step 4: Validate the policy compiles and tests pass**

Run: `just check`
Expected: All tests pass.

- [ ] **Step 5: Run end-to-end tests**

Run: `just clester`
Expected: All e2e tests pass. If any git-related tests relied on the `project` sandbox by name, they may need updating — check output.

- [ ] **Step 6: Commit**

```bash
git add clash/src/default_policy.star
git commit -m "feat(policy): use git_ro/git_rw sandboxes in default policy

Plan mode routes git through git_ro (read-only, worktree-aware).
Edit/default mode routes git through git_rw (read-write, worktree-aware).
Both sandboxes enable network + SSH access for remote operations."
```

---

### Task 3: Update documentation

**Files:**
- Modify: `clash_starlark/stdlib/sandboxes.star` (already done in Task 1 — header comment)
- Check: any docs that reference the default policy or sandbox presets

- [ ] **Step 1: Check for documentation that references sandbox presets or the default git policy**

Search for references to `project` sandbox in docs, README, or site content that specifically mention git. Update any that describe the default git sandbox behavior.

Run: `grep -r "project.*sandbox\|sandbox.*project\|git.*sandbox\|sandbox.*git" docs/ site/ README.md --include='*.md' -l`

- [ ] **Step 2: Update any affected documentation**

If docs reference that git uses the `project` sandbox, update to mention `git_ro`/`git_rw`. If no docs mention this, skip.

- [ ] **Step 3: Commit documentation changes (if any)**

```bash
git add -A docs/ site/ README.md
git commit -m "docs: update sandbox references for git_ro/git_rw"
```
