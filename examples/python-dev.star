# Python Development Policy
# Allows python/pip/uv/pytest with sandboxed filesystem access.
load("@clash//std.star", "exe", "tool", "policy", "sandbox", "cwd", "tempdir", "allow", "deny", "ask")

def main():
    py_sandbox = sandbox(
        name = "python",
        default = deny(),
        fs = [
            cwd(follow_worktrees = True).allow(read = True, write = True),
            tempdir().allow(),
        ],
        net = allow(),
    )
    return policy(
        default = ask(),
        rules = [
            exe("python").sandbox(py_sandbox).allow(),
            exe("python3").sandbox(py_sandbox).allow(),
            exe("pip").sandbox(py_sandbox).allow(),
            exe("uv").sandbox(py_sandbox).allow(),
            exe("pytest").sandbox(py_sandbox).allow(),
            exe("git").allow(),
            exe("git", args = ["push", "--force"]).deny(),
            tool("Read").allow(),
            tool("Glob").allow(),
            tool("Grep").allow(),
        ],
    )
