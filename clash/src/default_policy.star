load("@clash//builtin.star", "builtins")
load("@clash//std.star", "allow", "ask", "deny", "match", "policy", "sandbox", "subpath")
load("@clash//sandboxes.star", "{preset}")

# Tighter sandbox for Claude fs tools (no execute, scoped to cwd + ~/.claude)
_fs_box = sandbox(
    name = "cwd",
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),
        "$HOME/.claude": allow("rwc"),
    },
)

def main():
    return policy(
        default = ask(),
        default_sandbox = {preset},
        rules = builtins + [
            # Claude fs tools
            match({("Read", "Glob", "Grep"): allow(sandbox = _fs_box)}),
            match({("Write", "Edit", "NotebookEdit"): allow(sandbox = _fs_box)}),

            # Network tools — prompt user
            match({("WebFetch", "WebSearch"): ask()}),

            # Deny destructive git ops
            match({"Bash": {"git": {
                "push": {
                    "--force": deny(),
                    "--force-with-lease": deny(),
                },
                "reset": {
                    "--hard": deny(),
                },
            }}}),

            # All other commands — sandboxed
            match({"Bash": allow(sandbox = {preset})}),
        ],
    )
