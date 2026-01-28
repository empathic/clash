default:
    @just -l

build-plugin target_dir:
    #!/usr/bin/env bash
    cargo build --bins 
    base={{target_dir}}
    plugin="$base/clash-plugin"
    cp -r clash-plugin $base
    mkdir -p "$plugin/bin"
    cp target/debug/clash "$plugin/bin/clash"
    echo $plugin

dev:
    claude --plugin-dir $(just build-plugin /tmp/clash-dev)