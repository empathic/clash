# Git Sandboxes (`git_ro` / `git_rw`)

## Problem

The default clash policy doesn't work well with git, especially in worktrees:

1. **Worktree filesystem access**: The `project` sandbox only allows `$PWD/**`. In a git worktree, git data lives outside the working directory — in `main-repo/.git/worktrees/<name>/` and `main-repo/.git/` (shared objects, refs, config). Git commands fail because the sandbox blocks access to these paths.

2. **Network access**: `project` has no network access, so `git push`, `fetch`, and `pull` fail. Git needs HTTPS and SSH connectivity for remote operations.

3. **SSH/config access**: Git needs `~/.ssh/` for SSH key-based authentication and `~/.gitconfig` / `~/.config/git/` for global configuration. The `project` sandbox doesn't grant access to these. The `workspace` sandbox denies `~/.ssh/` via `UNSAFE_IN_HOME`.

4. **No read-only git option in plan mode**: Plan mode uses the general `readonly` sandbox for everything, which doesn't have `follow_worktrees` and doesn't grant access to git config/SSH paths.

## Solution

Two new preset sandboxes in `sandboxes.star`, purpose-built for git operations. The default policy is updated to use them.

### `git_ro` — Read-only git sandbox

For plan mode / read-only contexts. Supports `status`, `log`, `diff`, `fetch`, `pull`, `ls-remote`, `branch --list`, etc.

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

Filesystem access:
- `rx` (read + execute) on `$PWD` with `follow_worktrees=True` — can read the working tree, git index, objects, and refs, including in worktrees where git data is outside `$PWD`
- Read `~/.gitconfig` — global git configuration
- Read `~/.config/git/**` — XDG-style global git config, ignore, attributes
- Read + execute `~/.ssh/**` — SSH keys and agent socket for remote auth
- Full access to `$TMPDIR/**` — git uses temp files internally

Network: allowed (HTTPS + SSH remotes).

### `git_rw` — Read-write git sandbox

For edit/default modes. Everything `git_ro` supports, plus `commit`, `push`, `checkout`, `merge`, `rebase`, `stash`, `worktree add/remove`, etc.

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

Filesystem access:
- `FULL` (read, write, create, delete, execute) on `$PWD` with `follow_worktrees=True` — can modify the working tree, write to the git index, create refs, etc.
- Same config/SSH/tmpdir access as `git_ro` (read-only — git doesn't need to write config)

Network: allowed.

### Default policy update

```starlark
load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "readonly", "project", "workspace", "git_ro", "git_rw")

policy("default",
    {
        mode("plan"): {
            glob("**"): allow(sandbox=readonly),
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_ro)
                }
            }
        },
        (mode("edit"), mode("default")): {
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_rw)
                }
            }
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=workspace),
        },
    },
)
```

Key changes from current default:
- Plan mode now has an explicit git rule using `git_ro` (previously git inherited the general `readonly` sandbox which lacked worktree/SSH support)
- Edit/default mode git rule switches from `project` to `git_rw` (adds worktree awareness, network, SSH)

## Files to modify

1. **`clash_starlark/stdlib/sandboxes.star`** — Add `git_ro` and `git_rw` sandbox definitions
2. **`clash/src/default_policy.star`** — Update to import and use the new git sandboxes

## Testing

- Existing `just check` unit tests should continue to pass (no Rust changes)
- `just clester` end-to-end tests validate policy behavior
- Manual verification: run `clash sandbox test` with git commands in both a normal repo and a worktree to confirm sandbox grants correct access
