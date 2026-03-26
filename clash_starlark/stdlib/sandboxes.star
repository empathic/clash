# Clash sandbox presets — intent-based trust levels for Bash commands.
#
# These presets express what you trust a command to do, not what
# the command literally says.  Pick a preset based on intent:
#
#   restricted   — untrusted scripts: read-only project, no network
#   read_only    — linters, analyzers: read project + home, no writes
#   dev          — build tools, git: read+write project, no network
#   dev_network  — package managers, gh: read+write project + network
#   unrestricted — fully trusted: all filesystem + network access

load("@clash//std.star", "allow", "deny", "sandbox", "subpath")

restricted = sandbox(
    name="restricted",
    default=deny(),
    fs={
        "$PWD": allow("rx"),
        "$TMPDIR": allow("rx"),
    },
    doc="Minimal access: read-only project files, no network",
)

read_only = sandbox(
    name="read_only",
    default=deny(),
    fs={
        subpath("$PWD", follow_worktrees=True): allow("rx"),
        "$HOME": allow("rx"),
        "$TMPDIR": allow(),
    },
    doc="Read project and home, write only to temp, no network",
)

dev = sandbox(
    name="dev",
    default=deny(),
    fs={
        subpath("$PWD", follow_worktrees=True): allow("rwcx"),
        "$HOME": allow("rx"),
        "$TMPDIR": allow(),
    },
    doc="Development: read+write project, read home, no network",
)

dev_network = sandbox(
    name="dev_network",
    default=deny(),
    fs={
        subpath("$PWD", follow_worktrees=True): allow("rwcx"),
        "$HOME": allow("rx"),
        "$TMPDIR": allow(),
    },
    net="allow",
    doc="Development with network: read+write project, full network",
)

unrestricted = sandbox(
    name="unrestricted",
    default=deny(),
    fs={
        subpath("$PWD", follow_worktrees=True): allow(),
        "$HOME": allow(),
        "$TMPDIR": allow(),
    },
    net="allow",
    doc="Full access: all filesystem operations, full network",
)
