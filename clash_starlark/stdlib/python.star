python_sandbox = sandbox(
    name = "python_dev",
    default = deny(),
    fs = {
        glob("$PWD/**"): allow("rwcx"),
        "$HOME": {
            glob(".local/**"): allow("rwc"),
            glob(".cache/pip/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
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
