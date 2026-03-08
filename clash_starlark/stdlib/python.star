load("@clash//std.star", "sandbox", "cwd", "home", "tempdir", "domains", "exe", "regex")

python_sandbox = sandbox(
    name = "python_dev",
    default = deny,
    fs = [
        cwd(read = allow, write = allow, execute = allow),
        home().child(".local", read = allow, write = allow),
        home().child(".cache/pip", allow_all = True),
        tempdir(allow_all = True),
    ],
    net = [
        domains({
            "pypi.org": allow,
            "files.pythonhosted.org": allow,
            "github.com": allow,
        }),
    ],
)

python = exe(regex("python3?")).sandbox(python_sandbox).allow()