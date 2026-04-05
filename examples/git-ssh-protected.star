# Git Fetch from GitHub, SSH Keys Protected
# git can reach GitHub and read your SSH keys for auth.
# Nothing else can see ~/.ssh or access the network.

sandbox(
    name = "git_github",
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),
        "$HOME": {
            glob(".ssh/**"): allow("rx"),
            ".gitconfig": allow("r"),
            glob(".config/git/**"): allow("r"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = [domains({"github.com": allow(), "*.github.com": allow()})],
)

settings(default = deny())

policy("git-ssh-protected",
    rules = [
        when({"Bash": {
            "git": {"push": deny()},
        }}),
        when({"Bash": {
            "git": allow(sandbox = "git_github"),
        }}),
        when({("Read", "Glob", "Grep"): allow()}),
    ],
)
