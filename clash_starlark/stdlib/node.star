load("@clash//std.star", "allow", "deny", "match", "sandbox", "cwd", "home", "tempdir", "domains")

node_sandbox = sandbox(
    name = "node_dev",
    default = deny(),
    fs = [
        cwd().allow(read = True, write = True, execute = True),
        home().child(".npm").allow(),
        home().child(".config/npm").allow(read = True),
        tempdir().allow(),
    ],
    net = [
        domains({
            "registry.npmjs.org": allow(),
            "*.npmjs.org": allow(),
            "github.com": allow(),
        }),
    ],
    doc = "Node.js development: project + npm cache, npm registry network",
)

node = match({"Bash": {("node", "bun", "deno"): allow(sandbox = node_sandbox)}})
