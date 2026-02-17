
plugin_target := "./target/clash-dev"
plugin_dir := plugin_target + "/clash-plugin/"
wt_root := "../clash-wt"

default:
    @just -l

build-plugin-in target_dir:
    #!/usr/bin/env bash
    cargo build --bins 
    base={{target_dir}}
    rm -rf {{target_dir}}
    plugin="$base/clash-plugin"
    mkdir -p "$plugin/bin"
    cp -r clash-plugin/. "$plugin"
    cp target/debug/clash "$plugin/bin/clash"
    echo $plugin

build-plugin: (build-plugin-in plugin_target)

dev *ARGS:
    just build-plugin
    claude --plugin-dir {{plugin_dir}} --debug-file /tmp/clash-debug --allow-dangerously-skip-permissions {{ARGS}}

install: uninstall
    just build-plugin
    claude plugin marketplace add ./
    claude plugin install clash
    cargo install

uninstall:
    -claude plugin uninstall clash
    -claude plugin marketplace remove clash
    -rm ~/.local/bin/clash

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
