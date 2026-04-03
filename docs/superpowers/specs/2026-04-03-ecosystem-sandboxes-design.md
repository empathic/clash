# Ecosystem Sandboxes & Init Detection

## Problem

Clash has language-specific sandboxes (`rust_dev`, `python_dev`, `node_dev`) but they are low quality compared to the recently shipped git sandboxes. They lack proper filesystem scoping, don't cover common toolchain paths, and aren't wired into the init flow. Users have to manually `load()` them.

Additionally, common ecosystems like Go, Java/JVM, Ruby, Docker, Swift, .NET, and Shell/Make have no sandbox support at all.

The init flow (`clash init`) writes a hardcoded policy template with no awareness of what the user's project actually uses.

## Solution

1. Redo all existing language sandboxes and add new ones for missing ecosystems.
2. Add project detection and command history mining to `clash init` so sandboxes are automatically recommended.
3. Dynamically generate the policy using the existing codegen AST infrastructure.

## Naming Convention

Sandboxes use two suffixes:

- **`_safe`**: The toolchain can compile, test, lint, and verify. It writes to build caches, temp dirs, and toolchain-specific directories, but cannot mutate project source files or dependency manifests.
- **`_full`**: Full development — the toolchain can do everything `_safe` allows plus modify lockfiles, dependency manifests, and project configuration.

Ecosystems where the safe/full split doesn't add value get only `_full`.

The existing `git_ro` / `git_rw` are renamed to `git_safe` / `git_full` for consistency.

## Sandbox Definitions

Each ecosystem gets a `.star` file in `clash_starlark/stdlib/` exporting sandbox definitions and a convenience `when()` routing rule.

### Git (`sandboxes.star`)

**`git_safe`**: fetch, pull, log, diff, status, branch --list
- `rx` on `$PWD` with `follow_worktrees=True`
- Read `~/.gitconfig`, `~/.config/git/**`
- Read+execute `~/.ssh/**`
- Full `$TMPDIR`
- Network: allow

**`git_full`**: + commit, push, checkout, merge, rebase, stash
- `FULL` on `$PWD` with `follow_worktrees=True`
- Same config/SSH/tmpdir access as `git_safe`
- Network: allow

### Rust (`rust.star`)

**`rust_safe`**: cargo check, clippy, test, doc, bench
- `rx` on `$PWD` with `follow_worktrees=True`
- Full on `$PWD/target/**` (build artifacts)
- Read+execute `~/.cargo/**`, `~/.rustup/**`
- Full `$TMPDIR`
- Network: deny

**`rust_full`**: + cargo add, cargo install, cargo update
- `FULL` on `$PWD` with `follow_worktrees=True`
- Full `~/.cargo/**`, `~/.rustup/**`
- Full `$TMPDIR`
- Network: allow (crates.io, github.com)

### Go (`go.star`)

**`go_safe`**: go vet, go test, go build
- `rx` on `$PWD` with `follow_worktrees=True`
- Full on Go module cache (`~/go/**`, `~/.cache/go-build/**`)
- Full `$TMPDIR`
- Network: deny

**`go_full`**: + go get, go mod tidy, go install
- `FULL` on `$PWD`
- Full Go caches
- Full `$TMPDIR`
- Network: allow (proxy.golang.org, github.com)

### Node (`node.star`)

**`node_full`** (single variant):
- Full on `$PWD` (includes `node_modules/`, lockfiles)
- Full `~/.npm/**`, `~/.config/npm/**`, `~/.bun/**`
- Full `$TMPDIR`
- Network: allow (registry.npmjs.org, github.com)

### Python (`python.star`)

**`python_full`** (single variant):
- Full on `$PWD` (includes venvs, `.pyc` files)
- Full `~/.local/**`, `~/.cache/pip/**`, `~/.virtualenvs/**`
- Full `$TMPDIR`
- Network: allow (pypi.org, files.pythonhosted.org, github.com)

### Ruby (`ruby.star`)

**`ruby_full`** (single variant):
- Full on `$PWD`
- Full `~/.gem/**`, `~/.bundle/**`, `~/.rbenv/**`
- Full `$TMPDIR`
- Network: allow (rubygems.org, github.com)

### Java/JVM (`java.star`)

**`java_full`** (single variant):
- Full on `$PWD`
- Full `~/.gradle/**`, `~/.m2/**`
- Full `$TMPDIR`
- Network: allow (repo.maven.apache.org, plugins.gradle.org, github.com)

### Docker (`docker.star`)

**`docker_safe`**: docker ps, images, inspect, logs
- `rx` on `$PWD`
- Read `~/.docker/config.json`
- Full `$TMPDIR`
- Network: allow (Docker daemon communication)

**`docker_full`**: + docker build, run, compose, push
- Full on `$PWD`
- Read `~/.docker/**`
- Full `$TMPDIR`
- Network: allow

### Swift (`swift.star`)

**`swift_full`** (single variant):
- Full on `$PWD`
- Full `~/.swiftpm/**`, `~/Library/Developer/**`
- Full `$TMPDIR`
- Network: allow (github.com)

### .NET (`dotnet.star`)

**`dotnet_full`** (single variant):
- Full on `$PWD`
- Full `~/.nuget/**`, `~/.dotnet/**`
- Full `$TMPDIR`
- Network: allow (api.nuget.org, github.com)

### Shell/Make (`make.star`)

**`make_full`** (single variant):
- Full on `$PWD`
- Full `$TMPDIR`
- Network: deny

## Init Flow

### Current flow

```
clash init -> agent select -> write hardcoded default_policy.star -> open TUI
```

### New flow

```
clash init -> agent select -> ask to scan -> detect -> confirm -> generate policy -> open TUI
```

### Step 1: Agent selection (unchanged)

### Step 2: Ask permission to scan

```
Would you like clash to scan your project and command history
to recommend sandboxes? (y/n)
```

If no, fall through to the existing posture prompt (strict/balanced/permissive) and generate a basic policy.

### Step 3: Detection (if yes)

Two signal sources run together:

**File detection** — scan `$PWD` for project markers:

| Marker | Ecosystem |
|--------|-----------|
| `Cargo.toml` | Rust |
| `go.mod` | Go |
| `package.json` | Node |
| `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile` | Python |
| `Gemfile` | Ruby |
| `build.gradle`, `pom.xml`, `build.gradle.kts` | Java/JVM |
| `Dockerfile`, `docker-compose.yml`, `compose.yml` | Docker |
| `Package.swift` | Swift |
| `*.csproj`, `*.sln`, `*.fsproj` | .NET |
| `Makefile`, `CMakeLists.txt`, `justfile` | Make |
| `.git/` | Git |

Only scan `$PWD` root level (no recursion). For `.csproj`/`.sln`/`.fsproj`, glob `$PWD/*.{csproj,sln,fsproj}` (root level only).

**History mining** — reuse `from_trace.rs` infrastructure to find recent audit/trace logs and extract observed binaries. Map binaries to ecosystems:

| Binary | Ecosystem |
|--------|-----------|
| `cargo`, `rustc`, `rustup` | Rust |
| `go` | Go |
| `node`, `npm`, `npx`, `bun`, `deno`, `yarn`, `pnpm` | Node |
| `python`, `python3`, `pip`, `pip3`, `uv`, `poetry` | Python |
| `ruby`, `gem`, `bundle`, `rails` | Ruby |
| `gradle`, `gradlew`, `mvn`, `mvnw`, `java`, `javac` | Java/JVM |
| `docker`, `docker-compose`, `podman` | Docker |
| `swift`, `swiftc`, `xcodebuild` | Swift |
| `dotnet`, `msbuild` | .NET |
| `make`, `cmake`, `just` | Make |
| `git` | Git |

The union of both signals determines the recommendation.

### Step 4: Confirm detections

```
Detected ecosystems:

  * Git        (found .git/, observed: git)
  * Rust       (found Cargo.toml, observed: cargo, rustc)
  * Docker     (found Dockerfile)

Include these sandboxes in your policy? (y/n)
```

If yes, generate with all detected sandboxes. If no, fall through to posture prompt.

### Step 5: Generate policy

Use the codegen AST to produce a `policy.star` that:
- Loads `builtin.star` (always)
- Loads `sandboxes.star` for git + intent presets
- Loads each detected ecosystem's `.star` file
- Generates `settings()` with `ask()` default and a reasonable default sandbox
- Generates a `policy()` with mode-based routing:
  - Plan mode: `_safe` variants where available, `_full` otherwise
  - Edit/default mode: `_full` variants
  - Unrestricted: `workspace`
- Each ecosystem's routing rules are composed into the policy

### Step 6: Open TUI (unchanged)

User can review and tweak the generated policy.

### Integration with existing init paths

- `clash init` — new flow above
- `clash init --import` — existing settings import, but also runs detection and adds sandbox `load()` statements to the generated policy
- `clash init --no-import` — unchanged (hooks only, no policy)

## Generated Policy Example

When init detects Rust + Git + Docker:

```starlark
load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "readonly", "workspace", "git_safe", "git_full")
load("@clash//rust.star", "rust_safe", "rust_full")
load("@clash//docker.star", "docker_safe", "docker_full")

policy("default",
    {
        mode("plan"): {
            glob("**"): allow(sandbox=readonly),
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_safe)
                },
                ("cargo", "rustc", "rustup"): {
                    glob("**"): allow(sandbox=rust_safe)
                },
                ("docker", "docker-compose", "podman"): {
                    glob("**"): allow(sandbox=docker_safe)
                },
            }
        },
        (mode("edit"), mode("default")): {
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_full)
                },
                ("cargo", "rustc", "rustup"): {
                    glob("**"): allow(sandbox=rust_full)
                },
                ("docker", "docker-compose", "podman"): {
                    glob("**"): allow(sandbox=docker_full)
                },
            }
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=workspace),
        },
    },
)
```

Single-variant ecosystems use the same sandbox in both plan and edit modes.

## Ecosystem Registry

A Rust data structure drives detection, binary mapping, and codegen:

```rust
struct EcosystemDef {
    name: &'static str,
    star_file: &'static str,
    binaries: &'static [&'static str],
    markers: &'static [&'static str],
    safe_sandbox: Option<&'static str>,
    full_sandbox: &'static str,
}
```

This single registry is the source of truth for:
- File detection (markers)
- History mining (binary -> ecosystem lookup)
- Codegen (which sandboxes to load, which binaries to route)

## Routing Rules

Each `.star` file exports sandbox definitions and a convenience `when()` rule:

```starlark
rust_safe = sandbox(name="rust_safe", ...)
rust_full = sandbox(name="rust_full", ...)

# Convenience rule for manual use
rust = when({"Bash": {("cargo", "rustc", "rustup"): allow(sandbox=rust_full)}})
```

The generated policy does not use the convenience rules — it composes its own mode-aware routing from the registry data.

## Files Modified

- **`clash_starlark/stdlib/sandboxes.star`** — Rename `git_ro` -> `git_safe`, `git_rw` -> `git_full`
- **`clash_starlark/stdlib/rust.star`** — Rewrite: `rust_dev` -> `rust_safe` + `rust_full`
- **`clash_starlark/stdlib/python.star`** — Rewrite: `python_dev` -> `python_full`
- **`clash_starlark/stdlib/node.star`** — Rewrite: `node_dev` -> `node_full`
- **`clash/src/default_policy.star`** — Update `git_ro`/`git_rw` -> `git_safe`/`git_full`
- **`clash/src/cmd/init.rs`** — Add detection + confirmation flow, dynamic codegen
- **`clash/src/cmd/from_trace.rs`** — Extract binary-mining into reusable function
- **`clash/src/cmd/import_settings.rs`** — Add ecosystem detection to generated policy

## New Files

- **`clash_starlark/stdlib/go.star`** — `go_safe`, `go_full`
- **`clash_starlark/stdlib/java.star`** — `java_full`
- **`clash_starlark/stdlib/ruby.star`** — `ruby_full`
- **`clash_starlark/stdlib/docker.star`** — `docker_safe`, `docker_full`
- **`clash_starlark/stdlib/swift.star`** — `swift_full`
- **`clash_starlark/stdlib/dotnet.star`** — `dotnet_full`
- **`clash_starlark/stdlib/make.star`** — `make_full`
- **`clash/src/ecosystem.rs`** — `EcosystemDef` registry + detection + binary mapping

## Testing

- Unit tests for each `.star` file (compile + sandbox resolution)
- Unit tests for ecosystem detection (marker files, binary mapping)
- Unit tests for codegen output (detected ecosystems -> valid Starlark)
- Update existing tests referencing `git_ro`/`git_rw`
- Clester e2e tests for new sandboxes
