load("@clash//std.star", "tool", "policy", "sandbox", "cwd", "home")
load("@clash//rust.star", "rust")
load("@clash//python.star", "python")
load("@clash//node.star", "node")

_fs_access = sandbox(fs = [
    cwd(read = allow, write = allow, follow_worktrees = True),
])

def main():
    return policy(default = deny, rules = [
        tool(["Read", "Glob", "Grep"]).sandbox(_fs_access).allow(),
        tool(["Write", "Edit", "NotebookEdit"]).sandbox(_fs_access).allow(),
        node,
        python,
        rust,
    ])
