load("@clash//std.star", "allow", "deny", "match", "sandbox", "domains", "regex")

python_sandbox = sandbox(
    name = "python_dev",
    default = deny(),
    fs = {
        "$PWD": allow("rwcx"),
        "$HOME": {
            ".local": allow("rwc"),
            ".cache/pip": allow(),
        },
        "$TMPDIR": allow(),
    },
    net = [
        domains({
            "pypi.org": allow(),
            "files.pythonhosted.org": allow(),
            "github.com": allow(),
        }),
    ],
    doc = "Python development: project + pip cache, PyPI/GitHub network",
)

python = match({"Bash": {regex("python3?"): allow(sandbox = python_sandbox)}})
