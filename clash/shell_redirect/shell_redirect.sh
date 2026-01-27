#!/bin/bash
# Shell Redirect - Intercepts calls to /bin/bash, /bin/sh, /bin/zsh
# and redirects them to a binary of your choosing.
#
# Usage:
#   source shell_redirect.sh /path/to/your/binary
#   # Now run any command - shell calls will be redirected
#
#   # Or run a single command with redirection:
#   shell_redirect_run /path/to/your/binary your_command args...
#
#   # To disable:
#   shell_redirect_disable

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDIRECT_LIB="$SCRIPT_DIR/libshell_redirect"

# Detect platform and set extension
if [[ "$(uname)" == "Darwin" ]]; then
    REDIRECT_LIB="${REDIRECT_LIB}.dylib"
else
    REDIRECT_LIB="${REDIRECT_LIB}.so"
fi

# Compile the shared library if it doesn't exist or source is newer
shell_redirect_compile() {
    local src="$SCRIPT_DIR/shell_redirect.c"

    if [[ ! -f "$REDIRECT_LIB" ]] || [[ "$src" -nt "$REDIRECT_LIB" ]]; then
        echo "Compiling shell redirect library..." >&2
        if [[ "$(uname)" == "Darwin" ]]; then
            cc -dynamiclib -o "$REDIRECT_LIB" "$src" -ldl 2>/dev/null || \
            cc -dynamiclib -o "$REDIRECT_LIB" "$src"
        else
            cc -shared -fPIC -o "$REDIRECT_LIB" "$src" -ldl
        fi

        if [[ $? -ne 0 ]]; then
            echo "Error: Failed to compile shell redirect library" >&2
            return 1
        fi
        echo "Compiled successfully: $REDIRECT_LIB" >&2
    fi
}

# Enable shell redirection for current shell and subprocesses
shell_redirect_enable() {
    local target="$1"

    if [[ -z "$target" ]]; then
        echo "Usage: shell_redirect_enable /path/to/binary" >&2
        return 1
    fi

    if [[ ! -x "$target" ]]; then
        echo "Error: Target binary '$target' is not executable" >&2
        return 1
    fi

    shell_redirect_compile || return 1

    # Convert to absolute path
    target="$(cd "$(dirname "$target")" && pwd)/$(basename "$target")"

    export SHELL_REDIRECT_TARGET="$target"

    if [[ "$(uname)" == "Darwin" ]]; then
        export DYLD_INSERT_LIBRARIES="$REDIRECT_LIB"
    else
        export LD_PRELOAD="$REDIRECT_LIB"
    fi

    echo "Shell redirection enabled: /bin/{bash,sh,zsh} -> $target" >&2
}

# Disable shell redirection
shell_redirect_disable() {
    unset SHELL_REDIRECT_TARGET

    if [[ "$(uname)" == "Darwin" ]]; then
        unset DYLD_INSERT_LIBRARIES
    else
        unset LD_PRELOAD
    fi

    echo "Shell redirection disabled" >&2
}

# Run a single command with shell redirection
shell_redirect_run() {
    local target="$1"
    shift

    if [[ -z "$target" ]] || [[ $# -eq 0 ]]; then
        echo "Usage: shell_redirect_run /path/to/binary command [args...]" >&2
        return 1
    fi

    if [[ ! -x "$target" ]]; then
        echo "Error: Target binary '$target' is not executable" >&2
        return 1
    fi

    shell_redirect_compile || return 1

    # Convert to absolute path
    target="$(cd "$(dirname "$target")" && pwd)/$(basename "$target")"

    if [[ "$(uname)" == "Darwin" ]]; then
        SHELL_REDIRECT_TARGET="$target" \
        DYLD_INSERT_LIBRARIES="$REDIRECT_LIB" \
        "$@"
    else
        SHELL_REDIRECT_TARGET="$target" \
        LD_PRELOAD="$REDIRECT_LIB" \
        "$@"
    fi
}

# If script is sourced with an argument, enable redirection immediately
if [[ "${BASH_SOURCE[0]}" != "$0" ]] && [[ -n "$1" ]]; then
    shell_redirect_enable "$1"
fi

# If script is executed directly, show usage
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "Shell Redirect - Intercept shell calls and redirect to custom binary"
    echo ""
    echo "Usage:"
    echo "  source $0 /path/to/your/binary   # Enable for current session"
    echo "  shell_redirect_enable /path/to/binary"
    echo "  shell_redirect_disable"
    echo "  shell_redirect_run /path/to/binary command [args...]"
    echo ""
    echo "This will redirect calls to /bin/bash, /bin/sh, /bin/zsh"
    echo "(and their /usr/bin counterparts) to your specified binary."
    echo ""
    echo "Works for:"
    echo "  - execve, execv, execvp (execution)"
    echo "  - stat, lstat (file info)"
    echo "  - open, access (file access)"
    echo "  - readlink, realpath (path resolution)"
fi
