node_sandbox = sandbox(
    default = deny,
    fs = [
        cwd(read = allow, write = allow, execute = allow),
        home().child(".npm", allow_all = True),
        home().child(".config/npm", read = allow),
        tempdir(allow_all = True),
    ],
    net = [
        domains({
            "registry.npmjs.org": allow,
            "*.npmjs.org": allow,
            "github.com": allow,
        }),
    ],
)
