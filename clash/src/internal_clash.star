def main():
    net_sandbox = sandbox(
        default=deny,
        fs=[
            home().child(".clash", read=allow),
        ],
        net=allow,
    )

    return policy(
        default=deny,
        rules=[
            home().child(".clash", read=allow),
            exe("clash", args=["bug"], sandbox=net_sandbox),
            exe("clash", args=["status"]),
            exe("clash", args=["policy", "list"]),
            exe("clash", args=["policy", "show"]),
            exe("clash", args=["policy", "explain"]),
            exe("clash", args=["policy", "schema"]),
            exe("clash", args=["policy", "shell"], effect=ask),
            exe("clash", args=["policy", "setup"], effect=ask),
        ],
    )


