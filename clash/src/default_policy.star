load("@clash//rust.star", "rust_sandbox")
load("@clash//python.star", "python_sandbox")
def main():
    cwd_access = sandbox(
        default = deny,
        fs = [cwd(read = allow)],
    )
    return policy(default = deny, rules = [
        tool().allow(),
    ])
