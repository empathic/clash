# Python Development Policy
# Allows python/pip/uv/pytest with sandboxed filesystem access.

sandbox("python", {
    default(): deny(),
    path("$PWD", worktree = True): allow("rwc"),
    glob("$TMPDIR/**"): allow(),
    network(): allow(),
}, doc = "Python toolchain sandbox: project read/write, network allowed.")

settings(default = ask())

policy("python-dev", {
    tool("Bash"): {
        "git": {
            "push": {"--force": deny()},
            glob("**"): allow(),
        },
        ("python", "python3", "pip", "uv", "pytest"): allow(sandbox = "python"),
    },
    tool(("Read", "Glob", "Grep")): allow(),
}, doc = "Python development: python/pip/uv/pytest sandboxed; git push --force denied.")
