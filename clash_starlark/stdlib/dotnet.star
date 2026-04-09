dotnet_full = sandbox(
    name = "dotnet_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".nuget/**"): allow(),
            glob(".dotnet/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = ".NET full: build, test, restore. Full project + NuGet cache access.",
)

dotnet = {tool("Bash"): {("dotnet", "msbuild"): allow(sandbox = dotnet_full)}}
