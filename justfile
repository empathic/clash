
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
    cp -r clash-plugin/ $plugin
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

uninstall:
    -claude plugin uninstall clash
    -claude plugin marketplace remove clash

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

# Create a new worktree for a Claude Code session. Prints path to stdout.
# Usage: just wt-new NAME [BRANCH]
wt-new name branch="":
    #!/usr/bin/env bash
    set -euo pipefail
    dir="{{wt_root}}/{{name}}"
    if [ -n "{{branch}}" ]; then
        git worktree add "$dir" "{{branch}}" >&2
    else
        git worktree add -b "claude/{{name}}" "$dir" >&2
    fi
    echo "$dir"

# List all worktrees
wt-list:
    git worktree list

# Remove a worktree (preserves the branch)
wt-rm name:
    git worktree remove "{{wt_root}}/{{name}}"

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