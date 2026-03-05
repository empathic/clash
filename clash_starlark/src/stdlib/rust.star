rust_sandbox = sandbox(
    default = deny,
    fs = [
        cwd(read = allow, write = allow, execute = allow),
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
