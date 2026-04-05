# Read-Only Repository Access
# Any bash command can read your project directory.
# Nothing else on the filesystem is visible.

sandbox(
    name = "repo_readonly",
    default = deny(),
    fs = {
        subpath("$PWD"): allow("r"),
    },
)

settings(default = deny())

policy("read-only-repo",
    rules = [
        when({"Bash": allow(sandbox = "repo_readonly")}),
        when({("Read", "Glob", "Grep"): allow()}),
    ],
)
