# Git Fetch from GitHub, SSH Keys Protected
# git can reach GitHub and read your SSH keys for auth.
# Nothing else can see ~/.ssh or access the network.

sandbox("git_github", {
    default(): deny(),
    path("$PWD", worktree = True): allow("rwc"),
    glob("$HOME/.ssh/**"): allow("rx"),
    path("$HOME/.gitconfig"): allow("r"),
    glob("$HOME/.config/git/**"): allow("r"),
    glob("$TMPDIR/**"): allow(),
    domain("github.com"): allow(),
    domain("*.github.com"): allow(),
}, doc = "Git sandbox: project read/write, SSH keys readable, network limited to github.com.")

settings(default = deny())

policy("git-ssh-protected", {
    tool("Bash"): {
        "git": {
            "push": deny(),
            glob("**"): allow(sandbox = "git_github"),
        },
    },
    tool(("Read", "Glob", "Grep")): allow(),
}, doc = "git can reach github.com and read SSH keys for auth; nothing else has network or ~/.ssh.")
