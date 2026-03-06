load("@clash//std.star", "tool", "policy")
load("@clash//rust.star", "rust_sandbox")
load("@clash//python.star", "python_sandbox")

def main():
    return policy(default = deny, rules = [
        tool().allow(),
    ])
