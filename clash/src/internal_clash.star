load("@clash//std.star", "exe", "policy", "sandbox", "home")

def main():
    net_sandbox = sandbox(
        default = deny,
        fs = [
            home().child(".clash", read = allow),
        ],
        net = allow,
    )

    return policy(
        default = deny,
        rules = [
            home().child(".clash", read = allow),

            exe("clash", args = ["bug"]).allow().sandbox(net_sandbox),
            exe("clash", args = ["status"]).allow(),
            exe("clash", args = ["policy", "list"]).allow(),
            exe("clash", args = ["policy", "show"]).allow(),
            exe("clash", args = ["policy", "explain"]).allow(),
            exe("clash", args = ["policy", "schema"]).allow(),
            exe("clash", args = ["policy", "shell"]).ask(),
            exe("clash", args = ["policy", "setup"]).ask(),
        ],
    )
