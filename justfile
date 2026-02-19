
plugin_target := "./target/clash-dev"
plugin_dir := plugin_target + "/clash-plugin/"
wt_root := "../clash-wt"

default:
    @just -l

# Build clash and launch Claude Code with the plugin for local development.
# The symlink lets hooks.json find the binary at ${CLAUDE_PLUGIN_ROOT}/bin/clash.
dev *ARGS:
    @just -q uninstall
    cargo install --path clash
    claude --plugin-dir ./clash-plugin --debug-file /tmp/clash-debug --allow-dangerously-skip-permissions {{ARGS}}

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

fix:
    cargo fix --allow-dirty

# Bump all crate versions, commit, tag, and push to trigger a release.
# Usage: just release 0.4.0
release version:
    #!/usr/bin/env bash
    set -euo pipefail

    new="{{version}}"

    # Validate semver format
    if ! [[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "error: version must be semver (e.g., 0.4.0), got: $new" >&2
        exit 1
    fi

    # Detect current version from clash/Cargo.toml
    old=$(grep '^version' clash/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    if [ "$old" = "$new" ]; then
        echo "error: version $new is already the current version" >&2
        exit 1
    fi

    echo "Bumping $old → $new"

    # Update all Cargo.toml files (perl -pi works on both macOS and Linux)
    for f in clash/Cargo.toml clash_notify/Cargo.toml claude_settings/Cargo.toml clester/Cargo.toml; do
        perl -pi -e "s/^version = \"$old\"/version = \"$new\"/" "$f"
        echo "  updated $f"
    done

    # Update workspace dependency versions
    perl -pi -e "s/version = \"$old\"/version = \"$new\"/g" Cargo.toml
    echo "  updated Cargo.toml (workspace deps)"

    # Regenerate lockfile
    cargo check --quiet 2>/dev/null
    echo "  updated Cargo.lock"

    # Commit and tag
    git add -A '*.toml' Cargo.lock
    git commit -m "chore: bump package versions to v$new"
    git tag "v$new"

    echo ""
    echo "Created commit and tag v$new."
    echo "To trigger the release, push the tag:"
    echo ""
    echo "  git push origin main --follow-tags"
    echo ""

# Launch a Claude session for a Linear issue in a new tmux window.
# Usage: just work EMP-123
#        just work https://linear.app/empathic/issue/EMP-123/title-slug
#        just work EMP-123 plugin=true
work issue plugin="":
    #!/usr/bin/env bash
    set -euo pipefail

    # Extract issue ID from URL or use as-is
    input="{{issue}}"
    if [[ "$input" == http* ]]; then
        id=$(echo "$input" | grep -oE '[A-Z]+-[0-9]+')
    else
        id="$input"
    fi

    branch=$(echo "$id" | tr '[:upper:]' '[:lower:]')
    dir="{{wt_root}}/$branch"

    # Create worktree + branch
    git worktree add -b "claude/$branch" "$dir" >&2 || true

    # Build plugin args if requested
    plugin_args=""
    if [ -n "{{plugin}}" ]; then
        just build-plugin >&2
        plugin_args="--plugin-dir {{plugin_dir}}"
    fi

    # Launch Claude in a new tmux window
    tmux new-window -n "$branch" -c "$dir" \
        "claude $plugin_args --dangerously-skip-permissions \
        'Look up Linear issue $id using the linear MCP server. Read the issue description, understand the requirements. /improve-as-expert execute on $id.'"

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
