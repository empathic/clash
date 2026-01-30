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
build-plugin: (build-plugin-in "/tmp/clash-dev")
dev:
    just build-plugin
    claude --plugin-dir /tmp/clash-dev/clash-plugin/ --debug-file /tmp/clash-debug --allow-dangerously-skip-permissions

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