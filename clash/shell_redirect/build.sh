#!/bin/bash
# Build script for shell_redirect library

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building shell_redirect library..."

if [[ "$(uname)" == "Darwin" ]]; then
    OUTPUT="libshell_redirect.dylib"
    cc -dynamiclib -O2 -o "$OUTPUT" shell_redirect.c
else
    OUTPUT="libshell_redirect.so"
    cc -shared -fPIC -O2 -o "$OUTPUT" shell_redirect.c -ldl
fi

echo "Built: $OUTPUT"
echo ""
echo "Usage:"
echo "  source shell_redirect.sh /path/to/your/shell"
echo "  shell_redirect_run /path/to/your/shell some_command"
