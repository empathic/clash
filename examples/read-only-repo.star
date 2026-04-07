# Read-Only Repository Access
# Any bash command can read your project directory.
# Nothing else on the filesystem is visible.

sandbox("repo_readonly", {
    default(): deny(),
    path("$PWD", worktree = True): allow("r"),
}, doc = "Read-only access to the current project directory.")

settings(default = deny())

policy("read-only-repo", {
    tool("Bash"): allow(sandbox = "repo_readonly"),
    tool(("Read", "Glob", "Grep")): allow(),
}, doc = "Bash commands run sandboxed with read-only access to the project directory.")
