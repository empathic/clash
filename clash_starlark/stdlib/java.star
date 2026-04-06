java_full = sandbox(
    name = "java_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".gradle/**"): allow(),
            glob(".m2/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Java/JVM full: gradle, maven builds. Full project + dependency cache access.",
)

java = {"Bash": {("gradle", "gradlew", "mvn", "mvnw", "java", "javac"): allow(sandbox = java_full)}}
