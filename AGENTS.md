
## Rust
* All dependencies should be managed in the workspace Cargo.toml file.

## Platforms
* OS: linux + macos
* ARCH: amd64 + arm64

## Testing
* `just check` for unit tests and linting
* `just clester` for end-to-end tests (runs clester against clash binary)
* `just ci` for full CI (check + clester)
* End-to-end test scripts are YAML files in `clester/tests/scripts/`
* The `clester` crate is the end-to-end test harness; see its source for script format

## Worktrees
This repo uses git worktrees to run parallel Claude Code sessions in isolation.

**Layout:**
```
/Users/eliot/code/empathic/
├── clash/                    # Main repo (stays on main)
└── clash-wt/                 # Worktree root
    ├── fix-auth/             # branch: claude/fix-auth
    └── ...
```

**If you are running inside a worktree** (`clash-wt/<name>/`):
* You are on a branch (typically `claude/<name>`). Commit freely.
* `just dev`, `just check`, etc. all work — each worktree has its own `./target/`.
* To create a PR, push your branch and use `gh pr create` as usual.
* Do NOT modify files in the main `clash/` directory.

**Recipes:** `just wt-new NAME`, `just wt-list`, `just wt-rm NAME`, `just wt-clean`

## Development
* Always check the documentation after your changes to ensure they are logically consistent with what you have done. This should be the last step after you have validated your changes work.
* ALWAYS update the relevant documentation (readme/comments) when changes have a public facing impact.
