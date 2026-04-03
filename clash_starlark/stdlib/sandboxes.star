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

UNSAFE_IN_HOME = (".ssh", ".gpg", ".config", ".aws", ".gh", ".git")


readonly = sandbox(
    name = "readonly",
    default = ask(),
    fs = {
        glob("$PWD/**"): allow("rx"),
        glob("$HOME/.claude/**"): allow("r"),
    },
    net = allow(),
)

project = sandbox(
    name = "project",
    default=ask(),
    fs = {
        glob("$PWD/**"): allow(FULL),
        glob("$HOME/.claude/**"): allow("rwcd"),
        glob("$TMPDIR/**"): allow(FULL),
    }
)

git_ro = sandbox(
    name = "git_ro",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow("rx"),
        "$HOME": {
            ".gitconfig": allow("r"),
            glob(".config/git/**"): allow("r"),
            glob(".ssh/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Git read-only: fetch, pull, log, diff. Worktree-aware, network + SSH enabled.",
)

git_rw = sandbox(
    name = "git_rw",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow(FULL),
        "$HOME": {
            ".gitconfig": allow("r"),
            glob(".config/git/**"): allow("r"),
            glob(".ssh/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Git read-write: commit, push, checkout, merge. Worktree-aware, network + SSH enabled.",
)

workspace = sandbox(
    name = "workspace",
    default=deny(),
    fs = {
        glob("$HOME/**"): allow(),
        } | {
        glob("$HOME/{}/**".format(d)): deny() for d in UNSAFE_IN_HOME
    },
)

unrestricted = sandbox(
    name = "unrestricted",
    default=allow(),
)
