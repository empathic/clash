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
#

UNSAFE_IN_HOME = (".ssh", ".gpg", ".config", ".aws", ".gh", ".git")


plan = sandbox(
    name = "plan",
    default = ask(),
    fs = {
        glob("$PWD/**"): allow("rx"),
        glob("$HOME/.claude/**"): allow("r"),
    },
    net = allow(),
)

edit = sandbox(
    name = "edit",
    default=ask(),
    fs = {
        glob("$PWD/**"): allow(FULL),
        glob("$HOME/.claude/**"): allow("rwcd"),
        glob("$TMPDIR/**"): allow(FULL),
    }
)

safe_yolo = sandbox(
    name = "safe_yolo",
    default=deny(),
    fs = {
        glob("$HOME/**"): allow(),
        } | {
        glob("$HOME/{}/**".format(d)): deny() for d in UNSAFE_IN_HOME
    },
)

yolo = sandbox(
    name = "yolo",
    default=allow(),
)
