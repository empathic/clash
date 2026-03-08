load("@clash//std.star", "exe", "policy", "sandbox", "home", "path")

def main():
    _clash_fs = sandbox(
        name = "clash_fs",
        default = deny,
        fs = [
            home().child(".clash", read = allow),
        ],
    )

    _clash_net = sandbox(
        name = "clash_net",
        default = deny,
        fs = [
            home().child(".clash", read = allow),
        ],
        net = allow,
    )

    return policy(
        default = deny,
        rules = [
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
