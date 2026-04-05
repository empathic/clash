swift_full = sandbox(
    name = "swift_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".swiftpm/**"): allow(),
            glob("Library/Developer/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Swift full: build, test, package resolve. Full project + SPM cache access.",
)

swift = {"Bash": {("swift", "swiftc", "xcodebuild"): allow(sandbox = swift_full)}}
