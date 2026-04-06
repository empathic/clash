node_full = sandbox(
    name = "node_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".npm/**"): allow(),
            glob(".config/npm/**"): allow("r"),
            glob(".bun/**"): allow(),
            glob(".cache/yarn/**"): allow(),
            glob(".pnpm-store/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Node full: npm/bun/yarn/pnpm install, run scripts. Full project + package access.",
)

node = {"Bash": {("node", "npm", "npx", "bun", "deno", "yarn", "pnpm"): allow(sandbox = node_full)}}
