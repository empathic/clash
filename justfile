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
# Usage: just release 0.5.1
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail

    new_version="{{VERSION}}"
    tag="v$new_version"
    branch="release/$tag"

    # Ensure clean working tree
    git diff --quiet && git diff --cached --quiet || { echo "Error: working tree is not clean" >&2; exit 1; }

    # Create release branch
    git checkout -b "$branch"

    # Bump all workspace crate versions + inter-crate dependency references
    cargo workspaces version custom "$new_version" --no-git-commit --yes

    # Freeze site docs
    cd site && bun run freeze "$tag" && cd ..

    # Commit, push, and create PR
    git add -A
    git commit -m "chore: release ${tag}"
    git push -u origin "$branch"
    gh pr create --title "chore: release ${tag}" --body "Version bump and frozen docs for ${tag}"

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
