python_full = sandbox(
    name = "python_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".local/**"): allow(),
            glob(".cache/pip/**"): allow(),
            glob(".virtualenvs/**"): allow(),
            glob(".pyenv/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Python full: pip install, run scripts, virtualenvs. Full project + package access.",
)

python = when({"Bash": {("python", "python3", "pip", "pip3", "uv", "poetry"): allow(sandbox = python_full)}})
