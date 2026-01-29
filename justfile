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