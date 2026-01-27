#!/bin/bash
# Build clash binaries for all supported platforms
# Requires: cargo, cross (for cross-compilation)
#
# Install cross with: cargo install cross
# Or use cargo-zigbuild: cargo install cargo-zigbuild

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$(dirname "$SCRIPT_DIR")"
CLASH_DIR="$(dirname "$PLUGIN_DIR")/clash"
BIN_DIR="$PLUGIN_DIR/bin"

# Targets to build
TARGETS=(
    "aarch64-apple-darwin:darwin-arm64"
    "x86_64-apple-darwin:darwin-x86_64"
    "x86_64-unknown-linux-gnu:linux-x86_64"
)

echo "Building clash from: $CLASH_DIR"
echo "Output directory: $BIN_DIR"
echo ""

# Check if we're in the right place
if [ ! -f "$CLASH_DIR/Cargo.toml" ]; then
    echo "Error: Could not find clash Cargo.toml at $CLASH_DIR/Cargo.toml" >&2
    exit 1
fi

mkdir -p "$BIN_DIR"

# Determine build tool
if command -v cross &> /dev/null; then
    BUILD_TOOL="cross"
elif command -v cargo-zigbuild &> /dev/null; then
    BUILD_TOOL="cargo zigbuild"
else
    BUILD_TOOL="cargo"
    echo "Warning: Neither 'cross' nor 'cargo-zigbuild' found."
    echo "Only building for the current platform."
    echo "Install cross (cargo install cross) for cross-compilation."
    echo ""
fi

build_target() {
    local target="$1"
    local output_name="$2"

    echo "Building for $target..."

    if [ "$BUILD_TOOL" = "cargo" ]; then
        # Native build only - check if this is our target
        CURRENT_TARGET="$(rustc -vV | grep host | cut -d' ' -f2)"
        if [ "$target" != "$CURRENT_TARGET" ]; then
            echo "  Skipping $target (current platform is $CURRENT_TARGET)"
            return 0
        fi
        cargo build --release --manifest-path "$CLASH_DIR/Cargo.toml" -p clash
        cp "$CLASH_DIR/../target/release/clash" "$BIN_DIR/clash-$output_name"
    else
        $BUILD_TOOL build --release --manifest-path "$CLASH_DIR/Cargo.toml" -p clash --target "$target"
        cp "$CLASH_DIR/../target/$target/release/clash" "$BIN_DIR/clash-$output_name"
    fi

    echo "  Built: $BIN_DIR/clash-$output_name"
}

for entry in "${TARGETS[@]}"; do
    target="${entry%%:*}"
    output_name="${entry##*:}"
    build_target "$target" "$output_name" || true
done

echo ""
echo "Build complete. Binaries:"
ls -la "$BIN_DIR"/clash-* 2>/dev/null || echo "  (none built)"
