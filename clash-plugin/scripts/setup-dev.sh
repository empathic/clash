#!/bin/bash
# Set up local development symlinks for clash plugin
# This creates a symlink from bin/clash-dev to the cargo build output

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$(dirname "$PLUGIN_DIR")")"
BIN_DIR="$PLUGIN_DIR/bin"

# Path to the cargo release binary
CARGO_BINARY="$REPO_ROOT/target/release/clash"

echo "Setting up local development symlinks..."
echo "  Plugin dir: $PLUGIN_DIR"
echo "  Cargo binary: $CARGO_BINARY"
echo ""

# Build the binary first if it doesn't exist
if [ ! -f "$CARGO_BINARY" ]; then
    echo "Building clash with cargo..."
    cargo build --release -p clash --manifest-path "$REPO_ROOT/third_party/clash/Cargo.toml"
fi

# Create symlink
SYMLINK="$BIN_DIR/clash-dev"
if [ -L "$SYMLINK" ]; then
    echo "Removing existing symlink..."
    rm "$SYMLINK"
elif [ -f "$SYMLINK" ]; then
    echo "Error: $SYMLINK exists but is not a symlink" >&2
    exit 1
fi

ln -s "$CARGO_BINARY" "$SYMLINK"
echo "Created symlink: $SYMLINK -> $CARGO_BINARY"
echo ""
echo "Development setup complete!"
echo "The plugin will now use your local cargo build."
echo ""
echo "To rebuild after changes:"
echo "  cargo build --release -p clash"
