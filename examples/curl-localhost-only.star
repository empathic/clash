# Curl to Localhost Only
# Allow curl, but only to your local dev server on port 8080.
# Everything else is denied network access at the OS level.

sandbox("localhost_only", {
    default(): deny(),
    path("$PWD"): allow("r"),
    glob("$TMPDIR/**"): allow(),
    localhost(ports = [8080]): allow(),
}, doc = "Localhost-only network access on port 8080; project read-only.")

settings(default = deny())

policy("curl-localhost-only", {
    tool("Bash"): {
        "curl": allow(sandbox = "localhost_only"),
    },
    tool(("Read", "Glob", "Grep")): allow(),
}, doc = "Allow curl to reach localhost:8080 only; everything else denied.")
