
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
* Available CLI commands: `clash init`, `clash uninstall`, `clash status`, `clash fmt`, `clash policy list`, `clash policy validate`, `clash policy check`, `clash policy show`, `clash policy allow`, `clash policy deny`, `clash policy remove`, `clash policy migrate`, `clash explain`, `clash doctor`, `clash update`, `clash launch`, `clash lsp`, `clash lsp install --editor <vscode|neovim|helix|zed>`, `clash shell`, `clash sandbox exec`, `clash sandbox test`, `clash sandbox check`, `clash sandbox create`, `clash sandbox delete`, `clash sandbox list`, `clash sandbox add-rule`, `clash sandbox remove-rule`. `clash box` is a shorthand alias for `clash sandbox`.
* `clash policy allow <hash>` and `clash policy deny <hash>` accept a short audit hash (3–7 hex chars) displayed in the `clash shell` prompt to quickly create rules for previously seen commands. Use `--broad` to widen the match with a glob on trailing arguments, and `-y`/`--yes` to skip the confirmation dialog.
* Multi-agent commands accept `--agent <name>` (claude, gemini, codex, amazonq, opencode, copilot): `clash hook --agent gemini pre-tool-use`, `clash init --agent gemini`, `clash doctor --agent gemini`. Defaults to `claude`.

## Development

* Always check the documentation after your changes to ensure they are logically consistent with what you have done. This should be the last step after you have validated your changes work.
* ALWAYS update the relevant documentation (readme/comments) when changes have a public facing impact.
* Prefer to "comment through context", whether that be debug logs or anyhow::Context, instead of comments — unless your code comments are explaining difficult-to-understand code
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

* Clash uses a capability-based policy language with Starlark (.star) as the primary format, compiled to JSON IR
* Three capability domains: `exec` (commands), `fs` (filesystem), `net` (network)
* Policy source: `clash-policy/src/` — parse, compile, eval, IR (extracted crate; `clash::policy` re-exports it)
* Rules are JSON objects with an `effect` and a capability matcher, e.g. `{ "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }`
* The policy speaks in capabilities, not Claude Code tool names — the eval layer maps tools to capabilities
* Policy files use `.json` or `.star` extension (`.json` preferred when both exist)
* The `clash-starlark` crate evaluates `.star` files → JSON using Starlark (a Python-like config language)
* Starlark policies use top-level `settings()`, `sandbox()`, and `policy()` registration calls (no `main()` function)

## Site

* The `site/` directory is an Eleventy 3.0.0 static site
* Use **bun** (not npm/node) for all site tooling: `bun install`, `bun run build`, `bun run dev`
* Build output goes to `site/_site`
* Preview deploys to Cloudflare Pages (`clash-site` project) on PRs touching `site/**`

## Layout

* *clash* Clash binary + library (includes `src/agents/` for multi-agent protocol adapters, `src/policy_gen/` for shared policy generation definitions)
* *clash-policy* Policy language: parsing, IR, compilation, and evaluation (extracted from `clash` to break circular dep with `clash-lsp`)
* *clash_starlark* Starlark policy evaluator — compiles `.star` files to JSON policy format
* *clash-plugin* Claude Code plugin (hooks.json, .claude-plugin definitions)
* *clash-gemini-ext* Gemini CLI extension package
* *clash-codex* Codex CLI hook configuration
* *clash-amazonq* Amazon Q CLI agent hook configuration
* *clash-opencode* OpenCode TypeScript plugin
* *clash-copilot* Copilot CLI hook configuration
* *clash_notify* Helper crate for extended notifications outside of the terminal
* *claude_settings* Helper crate for interacting with a user's ".claude" settings directories
* *clash-brush-parser* Shell command parser
* *clash-brush-core* Sandboxed shell core engine
* *clash-brush-builtins* Shell built-in commands
* *clash-brush-interactive* Interactive shell (REPL)
* *docs* Project level documentation
