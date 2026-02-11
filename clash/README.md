# Clash

Make working with agents more fun and less frustrating

## Feature Ideas


| Feature | Status | 
|---|---|
| Extensible Permissions System | experiment in progress (eliot) |
| Stack based context management | idea |
| Data interop for hopping agents | idea |
| Integration with knowledge bases | idea |

## Usage

```
clash install          # install clash hooks (backs up existing settings)
clash uninstall        # restore settings from backup
clash enter            # enter a subshell with hooks installed; restores on exit
clash status           # show clash installation status at each settings level
```

### Settings levels

Clash operates on Claude Code's hierarchical settings system. Use `--level`
to target a specific level:

| Level | File | Description |
|-------|------|-------------|
| `user` | `~/.claude/settings.json` | Personal defaults |
| `project-local` (default) | `.claude/settings.local.json` | Project-specific, not version controlled |
| `project` | `.claude/settings.json` | Project-specific, version controlled |

```
clash install --level user
clash enter --level project
```

### Enter mode

`clash enter` spawns a subshell with hooks installed. When you exit the
subshell, the original settings are restored from backup automatically.

```
$ clash enter
Starting shell: /bin/zsh
# ... do work with clash hooks active ...
$ exit
# settings restored
```

## Building

```
cargo build -p clash
```

## Experiments

The `shell_redirect/` directory contains an experimental approach using
`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` to intercept shell execution.
This does not work on macOS due to SIP. See
[shell_redirect/README.md](shell_redirect/README.md) for details.