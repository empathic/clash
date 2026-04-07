go_safe = sandbox(
    name = "go_safe",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rx"),
        "$HOME": {glob("go/**"): allow(), glob(".cache/go-build/**"): allow()},
        glob("$TMPDIR/**"): allow(),
    },
    net = deny(),
    doc = "Go safe: vet, test, build. Module cache writable, source read-only.",
)

sandbox("hello")

go_full = sandbox(
    name = "go_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {glob("go/**"): allow(), glob(".cache/go-build/**"): allow()},
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Go full: get, mod tidy, install. Full project access, network enabled.",
)

go = {"Bash": {"go": allow(sandbox = go_full)}}
