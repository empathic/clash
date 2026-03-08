load("@clash//builtin.star", "base")
load("@clash//std.star", "tool", "policy", "sandbox", "cwd", "home")
load("@clash//rust.star", "rust")
load("@clash//python.star", "python")
load("@clash//node.star", "node")

_fs_access = sandbox(
    name = "cwd",
    fs = [
        cwd(read = allow, write = allow, follow_worktrees = True),
    ],
)

def main():
    my_policy = policy(default = deny, rules = [
        tool(["Read", "Glob", "Grep"]).sandbox(_fs_access).allow(),
        tool(["Write", "Edit", "NotebookEdit"]).sandbox(_fs_access).allow(),
        node,
        python,
        rust,
    ])
    return my_policy.merge(base)
