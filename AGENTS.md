
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

## Commits

* All commits MUST follow the [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/) specification.
* Commit message structure: `<type>[optional scope]: <description>` with optional body and footer(s).
* Common types: `feat` (new feature), `fix` (bug fix), `docs` (documentation), `refactor`, `test`, `chore`, `ci`, `style`, `perf`, `build`.
* A scope MAY be provided in parentheses after the type, e.g. `feat(parser): add array parsing`.
* Breaking changes MUST be indicated by appending `!` after the type/scope or by including a `BREAKING CHANGE:` footer.
* The description MUST immediately follow the colon and space after the type/scope prefix.
* A body MAY be provided after a blank line following the description, for additional context.
* Footer(s) MAY be provided after a blank line following the body.

## Policy Model

* Clash uses a capability-based policy language with s-expression syntax
* Three capability domains: `exec` (commands), `fs` (filesystem), `net` (network)
* Policy source: `clash/src/policy/v2/` — parse, compile, eval, IR
* Rules are `(effect (capability ...))` forms, e.g. `(deny (exec "git" "push" *))`
* The policy speaks in capabilities, not Claude Code tool names — the eval layer maps tools to capabilities
* See `docs/policy-grammar.md` for the formal grammar

## Backwards Compatibility

* All backwards-incompatible changes to the policy language MUST bump the version number in `clash/src/policy/version.rs` (`CURRENT_VERSION`)
* Each version bump MUST include deprecation entries in `all_deprecations()` describing what changed
* Auto-fix functions SHOULD be provided when possible so `clash policy upgrade` can migrate users automatically
* The `(version N)` declaration in policy files allows clash to detect outdated syntax and guide users to upgrade

## Layout

- *clash* Clash binary + library
* *clash-plugin* Claude plugin refered to by the .claude-plugin definitions
* *clash_notify* Helper crate for extended notifications outside of the terminal
* *claude_settings* Helper crate for interacting with a user's ".claude" settings directories
* *docs* Project level documentation
