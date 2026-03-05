def main():
    return policy(default = deny, rules = [
        home().child(".claude", read = allow, write = allow),
        path(env = "TRANSCRIPT_DIR", read = allow),
        tool().allow(),
    ])
