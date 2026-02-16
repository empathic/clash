
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

## Running clash
* `clash` is an installed binary on the user's PATH. ALWAYS run it directly as `clash` (e.g., `clash status`, `clash policy list`).
* NEVER use `cargo run --bin clash` to run clash. That is for building/testing the crate, not for invoking the tool.
* Skills reference `clash` commands — execute them exactly as written.

## Development
* Always check the documentation after your changes to ensure they are logically consistent with what you have done. This should be the last step after you have validated your changes work.
* ALWAYS update the relevant documentation (readme/comments) when changes have a public facing impact.
* Prefer to "comment through context", whether that be debug logs, anyhow::Context instead of comments unless your code comments are explaining difficult to understand code
* If you are corrected by a person when using a skill, or told you should have used the skill, then modify the plugin definition for clash to ensure this doesn't happen again.


## Policy Model
* Clash uses a capability-based policy language with s-expression syntax
* Three capability domains: `exec` (commands), `fs` (filesystem), `net` (network)
* Policy source: `clash/src/policy/v2/` — parse, compile, eval, IR
* Rules are `(effect (capability ...))` forms, e.g. `(deny (exec "git" "push" *))`
* The policy speaks in capabilities, not Claude Code tool names — the eval layer maps tools to capabilities
* See `docs/policy-grammar.md` for the formal grammar

## Layout
- *clash* Clash binary + library
- *clash-plugin* Claude plugin refered to by the .claude-plugin definitions
- *clash_notify* Helper crate for extended notifications outside of the terminal
- *claude_settings* Helper crate for interacting with a user's ".claude" settings directories
- *docs* Project level documentation
- *plans* Markdown files used to collaborate on plans that may span mulitple PRs. A place for human and agent multi-turn communication
  - *active* Currently in progress plans
  - *history* Plans that are either complete or abandoned