node_sandbox = sandbox(
    name = "node_dev",
    default = deny(),
    fs = {
        glob("$PWD/**"): allow("rwcx"),
        "$HOME": {
            glob(".npm/**"): allow(),
            glob(".config/npm/**"): allow("r"),
        },
        glob("$TMPDIR/**"): allow(),
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
