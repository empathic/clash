# Permissive Policy
# Ask-all default with common dev tools auto-allowed.
# Denies only truly dangerous operations.
load("@clash//std.star", "exe", "tool", "policy", "allow", "deny", "ask")

def main():
    return policy(
        default = ask(),
        rules = [
            exe("git").allow(),
            exe("git", args = ["push", "--force"]).deny(),
            exe("cargo").allow(),
            exe("npm").allow(),
            exe("npx").allow(),
            exe("node").allow(),
            exe("bun").allow(),
            exe("python").allow(),
            exe("pip").allow(),
            exe("uv").allow(),
            exe("make").allow(),
            exe("just").allow(),
            tool("Read").allow(),
            tool("Write").allow(),
            tool("Edit").allow(),
            tool("Glob").allow(),
            tool("Grep").allow(),
        ],
    )
