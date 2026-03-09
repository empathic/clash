load("@clash//std.star", "sandbox", "cwd", "home", "tempdir", "domains", "exe")

rust_sandbox = sandbox(
    name = "rust_dev",
    default = deny,
    fs = [
        cwd().allow(read = True, write = True, execute = True),
        cwd().child("target").allow(),
        home().child(".cargo").allow(),
        home().child(".rustup").allow(read = True, execute = True),
        tempdir().allow(),
    ],
    net = [
        domains({
            "crates.io": allow,
            "static.crates.io": allow,
            "github.com": allow,
            "static.rust-lang.org": allow,
        }),
    ],
)


rust = exe(["rustc", "cargo"]).sandbox(rust_sandbox).allow()
