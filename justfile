ALL_OS := "apple-darwin"
ALL_ARCH := "x86_64 aarch64"

default:
    @just -l

build-for target:
    cargo build --target {{target}}

build-all:
    #!/usr/bin/env bash
    for arch in {{ALL_ARCH}}; do
        for os in {{ALL_OS}}; do
            target="$arch-$os"
            just build-for $target
            just copy-to-plugin $target
        done
    done

copy-to-plugin target:
    cp target/{{target}}/debug/clash clash-plugin/bin/clash.{{target}}

