docker_safe = sandbox(
    name = "docker_safe",
    default = ask(),
    fs = {
        subpath("$PWD"): allow("rx"),
        "$HOME": {
            ".docker/config.json": allow("r"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Docker safe: ps, images, inspect, logs. Read-only project, Docker daemon access.",
)

docker_full = sandbox(
    name = "docker_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".docker/**"): allow("r"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Docker full: build, run, compose, push. Full project access, network enabled.",
)

docker = when({"Bash": {("docker", "docker-compose", "podman"): allow(sandbox = docker_full)}})
