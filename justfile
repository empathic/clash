set unstable
set script-interpreter := ['uv', 'run', '--script']

plugin_target := "./target/clash-dev"
plugin_dir := plugin_target + "/clash-plugin/"
wt_root := "../clash-wt"

default:
    @just -l

# Build clash and launch Claude Code with the plugin for local development.
# Builds to a temp dir and prepends it to PATH so the dev binary is found
# before any system-installed version, without polluting ~/.cargo/bin.
dev *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --bin clash
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    cp target/debug/clash "$tmpdir/"
    echo "clash dev binary: $tmpdir/clash"
    PATH="$tmpdir:$PATH" claude --plugin-dir ./clash-plugin --debug-file /tmp/clash-debug --allow-dangerously-skip-permissions {{ARGS}}

clean-configs:
    -rm -rf ~/.clash
    -rm -rf .clash

clean-config: clean-configs

# Install clash system-wide: binary to ~/.cargo/bin, plugin via Claude marketplace.
install: 
    @just -q uninstall
    cargo install --path clash
    claude plugin marketplace add ./
    claude plugin install clash

uninstall:
    -claude plugin uninstall clash
    -claude plugin marketplace remove clash
    -rm ~/.local/bin/clash
    -rm ~/.cargo/bin/clash

check:
    cargo fmt
    cargo test
    cargo clippy
    @just clester

# Run clester end-to-end tests against clash
clester *ARGS:
    cargo build --bins
    ./target/debug/clester run clester/tests/scripts/ {{ARGS}}

# Run clester with verbose output
clester-verbose:
    just clester -v

# Validate clester test scripts without executing
clester-validate:
    cargo build --bin clester
    ./target/debug/clester validate clester/tests/scripts/

# Run a single clester test script
clester-run SCRIPT:
    cargo build --bins
    ./target/debug/clester run {{SCRIPT}}

# Full CI check: unit tests + end-to-end tests
ci:
    just check
    just clester

clash *ARGS:
    cargo run -p clash -- {{ARGS}}

# Prepare a release: bump versions, freeze site docs, commit on a release branch.
# Usage: just release 0.4.0
[script]
release VERSION:
    import re, subprocess, sys, tomllib
    from pathlib import Path

    new_version = "{{VERSION}}".lstrip("v")
    tag = f"v{new_version}"
    branch = f"release/{tag}"
    root = Path(".")
    root_toml = root / "Cargo.toml"

    # Ensure we're on a clean working tree
    if subprocess.run(["git", "diff", "--quiet"]).returncode != 0 \
       or subprocess.run(["git", "diff", "--cached", "--quiet"]).returncode != 0:
        print("Error: working tree is not clean", file=sys.stderr)
        sys.exit(1)

    # Create release branch from current HEAD
    subprocess.run(["git", "checkout", "-b", branch], check=True)

    # Read workspace members
    root_data = tomllib.loads(root_toml.read_text())
    members = root_data["workspace"]["members"]

    # Bump each member's [package] version
    old_version = None
    for member in members:
        member_toml = root / member / "Cargo.toml"
        if not member_toml.exists():
            continue
        data = tomllib.loads(member_toml.read_text())
        ver = data.get("package", {}).get("version")
        if ver is None or ver == new_version:
            continue
        if old_version is None:
            old_version = ver
        text = member_toml.read_text()
        new_text = re.sub(
            r'^(version\s*=\s*)"' + re.escape(ver) + r'"',
            rf'\g<1>"{new_version}"',
            text, count=1, flags=re.MULTILINE,
        )
        if new_text != text:
            member_toml.write_text(new_text)
            print(f"  {member}: {ver} → {new_version}")

    if old_version is None:
        print("No versions changed — already up to date?", file=sys.stderr)
        sys.exit(1)

    # Bump workspace dependency versions in root Cargo.toml
    text = root_toml.read_text()
    root_toml.write_text(text.replace(
        f'version = "{old_version}"',
        f'version = "{new_version}"',
    ))
    print(f"  workspace deps: {old_version} → {new_version}")

    # Validate
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version=1"],
        capture_output=True,
    )
    if result.returncode != 0:
        print("cargo metadata failed!", file=sys.stderr)
        print(result.stderr.decode(), file=sys.stderr)
        sys.exit(1)

    # Freeze site docs
    subprocess.run(["bun", "run", "freeze", tag], cwd="site", check=True)

    # Commit, push, and create PR
    subprocess.run(["git", "add", "-A"], check=True)
    subprocess.run(["git", "commit", "-m", f"chore: release {tag}"], check=True)
    subprocess.run(["git", "push", "-u", "origin", branch], check=True)
    subprocess.run([
        "gh", "pr", "create",
        "--title", f"chore: release {tag}",
        "--body", f"Version bump and frozen docs for {tag}",
    ], check=True)

fix:
    cargo fix --allow-dirty

# Run the site dev server
site:
    cd site && bun run dev

# Launch a Claude session for a GitHub issue in a new tmux window.
# Usage: just work 123
#        just work https://github.com/empathic/clash/issues/123
#        just work 123 plugin=true
work issue:
    #!/usr/bin/env bash
    set -euo pipefail

    # Extract issue number from URL or use as-is
    input="{{issue}}"
    if [[ "$input" == http* ]]; then
        id=$(echo "$input" | grep -oE '[0-9]+$')
    else
        id="$input"
    fi

    branch="gh-$id"
    dir="{{wt_root}}/$branch"

    # Create worktree + branch
    git worktree add -b "eliot/$branch" "$dir" >&2 || true

    # Write the prompt to a temp file to avoid shell escaping issues
    prompt_file=$(mktemp)
    cat > "$prompt_file" <<PROMPT
    Look up GitHub issue #$id using \`gh issue view $id\`. Read the issue description, understand the requirements. /improve-as-expert execute on issue #$id.
    PROMPT

    # Launch Claude in a new tmux window
    tmux new-window -n "$branch" -c "$dir" \
        "claude --dangerously-skip-permissions < $prompt_file"

# Remove all worktrees under clash-wt/ and prune
wt-clean:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -d "{{wt_root}}" ]; then
        for dir in "{{wt_root}}"/*; do
            [ -d "$dir" ] && git worktree remove "$dir" && echo "Removed $dir" || true
        done
    fi
    git worktree prune
