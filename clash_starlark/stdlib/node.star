load("@clash//std.star", "sandbox", "cwd", "home", "tempdir", "domains", "exe")

node_sandbox = sandbox(
    name = "node_dev",
    default = deny,
    fs = [
        cwd().allow(read = True, write = True, execute = True),
        home().child(".npm").allow(),
        home().child(".config/npm").allow(read = True),
        tempdir().allow(),
    ],
    net = [
        domains({
            "registry.npmjs.org": allow,
            "*.npmjs.org": allow,
            "github.com": allow,
        }),
    ],
)

node = exe(["node", "bun", "deno"]).sandbox(node_sandbox).allow()
