ruby_full = sandbox(
    name = "ruby_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".gem/**"): allow(),
            glob(".bundle/**"): allow(),
            glob(".rbenv/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Ruby full: gem install, bundle, rails. Full project + gem access.",
)

ruby = {tool("Bash"): {("ruby", "gem", "bundle", "rails"): allow(sandbox = ruby_full)}}
