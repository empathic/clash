load("@clash//std.star", "tool", "policy", "cwd", "home")
load("@clash//rust.star", "rust")
load("@clash//python.star", "python")
load("@clash//node.star", "node")

def main():
    return policy(default = deny, rules = [
        cwd(read=allow, write=allow, follow_worktrees=True),
        home(read=ask, write=ask),
        node,
        python,
        rust,
    ])
