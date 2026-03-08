load("@clash//std.star", "sandbox", "cwd", "home", "tempdir", "domains", "exe")

rust_sandbox = sandbox(
    name = "rust_dev",
    default = deny,
    fs = [
        cwd(read = allow, write = allow, execute = allow),
        cwd().child("target", allow_all = True),
        home().child(".cargo", allow_all = True),
        home().child(".rustup", read = allow, execute = allow),
        tempdir(allow_all = True),
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