# Curl to Localhost Only
# Allow curl, but only to your local dev server on port 8080.
# Everything else is denied network access at the OS level.

sandbox(
    name = "localhost_only",
    default = deny(),
    fs = {
        subpath("$PWD"): allow("r"),
        glob("$TMPDIR/**"): allow(),
    },
    net = localhost(ports = [8080]),
)

settings(default = deny())

policy("curl-localhost-only",
    rules = [
        when({"Bash": {
            "curl": allow(sandbox = "localhost_only"),
        }}),
        when({("Read", "Glob", "Grep"): allow()}),
    ],
)
