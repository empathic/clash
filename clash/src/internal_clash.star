load("@clash//std.star", "exe", "tool", "policy", "sandbox", "home")

def main():
    _clash_fs = sandbox(
        default = deny,
        fs = [
            home().child(".clash", read = allow),
        ],
    )

    _clash_net = sandbox(
        default = deny,
        fs = [
            home().child(".clash", read = allow),
        ],
        net = allow,
    )

    return policy(
        default = deny,
        rules = [
            tool(["Read", "Glob", "Grep"]).sandbox(_clash_fs).allow(),
            exe("clash", args = ["bug"]).sandbox(_clash_net).allow(),
            exe("clash", args = ["status"]).allow(),
            exe("clash", args = ["policy", "list"]).allow(),
            exe("clash", args = ["policy", "show"]).allow(),
            exe("clash", args = ["policy", "explain"]).allow(),
            exe("clash", args = ["policy", "schema"]).allow(),
            exe("clash", args = ["policy", "shell"]).ask(),
            exe("clash", args = ["policy", "setup"]).ask(),
        ],
    )
