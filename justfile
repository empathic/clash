default:
    @just -l

build-plugin-in target_dir:
    #!/usr/bin/env bash
    cargo build --bins 
    base={{target_dir}}
    plugin="$base/clash-plugin"
    cp -r clash-plugin $base
    mkdir -p "$plugin/bin"
    cp target/debug/clash "$plugin/bin/clash"
    echo $plugin
build-plugin: (build-plugin-in "/tmp/clash-dev")
dev:
    claude --plugin-dir $(just build-plugin ) --debug-file /tmp/clash-debug --allow-dangerously-skip-permissions