#!/bin/bash
set -euo pipefail

# Already installed?
if command -v dotslash &>/dev/null; then
  exit 0
fi

INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    URL="https://github.com/facebook/dotslash/releases/latest/download/dotslash-macos.tar.gz"
    ;;
  Linux)
    case "$ARCH" in
      x86_64)  URL="https://github.com/facebook/dotslash/releases/latest/download/dotslash-ubuntu-22.04.x86_64.tar.gz" ;;
      aarch64) URL="https://github.com/facebook/dotslash/releases/latest/download/dotslash-ubuntu-22.04.aarch64.tar.gz" ;;
      *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

echo "Installing dotslash to $INSTALL_DIR..." >&2
curl -fsSL "$URL" | tar xz -C "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/dotslash"

# Make it available for the rest of this Claude Code session
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo "PATH=\"$INSTALL_DIR:\$PATH\"" >> "$CLAUDE_ENV_FILE"
fi

echo "dotslash installed to $INSTALL_DIR/dotslash" >&2
