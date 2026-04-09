make_full = sandbox(
    name = "make_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        glob("$TMPDIR/**"): allow(),
    },
    net = deny(),
    doc = "Make/CMake/Just full: build targets. Full project access, no network.",
)

make = {tool("Bash"): {("make", "cmake", "just"): allow(sandbox = make_full)}}
