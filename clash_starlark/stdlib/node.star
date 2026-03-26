load("@clash//std.star", "allow", "deny", "match", "sandbox", "domains")

node_sandbox = sandbox(
    name = "node_dev",
    default = deny(),
    fs = {
        "$PWD": allow("rwcx"),
        "$HOME": {
            ".npm": allow(),
            ".config/npm": allow("r"),
        },
        "$TMPDIR": allow(),
    },
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
