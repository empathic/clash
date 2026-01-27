# Shell Redirect

A library that intercepts system calls to redirect `/bin/bash`, `/bin/sh`, and `/bin/zsh` to a custom shell binary. Works for subprocesses and child processes.

## How It Works

Uses `DYLD_INSERT_LIBRARIES` (macOS) or `LD_PRELOAD` (Linux) to intercept:

- **Execution**: `execv`, `execve`, `execvp`, `posix_spawn`, `posix_spawnp`
- **File info**: `stat`, `lstat`, `fstatat`
- **File access**: `open`, `openat`, `access`, `faccessat`
- **Path resolution**: `readlink`, `realpath`

When any process tries to execute or access `/bin/bash`, `/bin/sh`, `/bin/zsh` (or `/usr/bin/*` variants), the library transparently redirects to your specified binary.

## Building

```bash
./build.sh
```

This creates `libshell_redirect.dylib` (macOS) or `libshell_redirect.so` (Linux).

## Usage

### Option 1: Source the wrapper script

```bash
source shell_redirect.sh /path/to/your/shell

# Now run any command - shell calls will be redirected
some_command

# Disable when done
shell_redirect_disable
```

### Option 2: Run a single command with redirection

```bash
source shell_redirect.sh
shell_redirect_run /path/to/your/shell some_command --args
```

### Option 3: Set environment variables directly

```bash
export SHELL_REDIRECT_TARGET=/path/to/your/shell
export DYLD_INSERT_LIBRARIES=/path/to/libshell_redirect.dylib  # macOS
# or
export LD_PRELOAD=/path/to/libshell_redirect.so  # Linux

some_command
```

## Using with Claude Code

Use the included `claude_shell` wrapper:

```bash
./claude_shell /path/to/your/shell
./claude_shell /path/to/your/shell --resume  # pass args to claude
```

This handles all the environment setup and works around node's exec chain.

## Debug Mode

To see interception logs, edit `shell_redirect.c` and set:

```c
#define DEBUG_REDIRECT 1
```

Then rebuild. You'll see messages like:

```
[shell_redirect] Library loaded, pid=12345, target=/path/to/shell
[shell_redirect] posix_spawn: /bin/zsh -> /path/to/shell
```

## Caveats

1. **macOS SIP**: System binaries with SIP protection won't load the library. Launch from a non-system parent process.

2. **Hardened binaries**: Some signed binaries strip `DYLD_INSERT_LIBRARIES`. Use the bash wrapper approach which sets the env vars before launching node.

3. **Target shell compatibility**: Your replacement shell must accept the same arguments as bash/zsh. Notably, it must handle `-c <command>` where the command is passed as a separate argv entry (POSIX style).

## Files

- `shell_redirect.c` - The interposition library source
- `shell_redirect.sh` - Bash helper functions for sourcing
- `claude_shell` - Standalone wrapper for running Claude Code
- `build.sh` - Build script
- `libshell_redirect.dylib` / `.so` - Compiled library (after building)
