load("@clash//std.star", "allow", "deny", "sandbox", "cwd", "home", "tempdir", "domains", "exe", "regex")

python_sandbox = sandbox(
    name = "python_dev",
    default = deny(),
    fs = [
        cwd().allow(read = True, write = True, execute = True),
        home().child(".local").allow(read = True, write = True),
        home().child(".cache/pip").allow(),
        tempdir().allow(),
    ],
    net = [
        domains({
            "pypi.org": allow(),
            "files.pythonhosted.org": allow(),
            "github.com": allow(),
        }),
    ],
    doc = "Python development: project + pip cache, PyPI/GitHub network",
)

python = exe(regex("python3?")).sandbox(python_sandbox).allow()
