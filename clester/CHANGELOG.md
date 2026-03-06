# Changelog

## [0.4.0](https://github.com/empathic/clash/compare/v0.3.6...v0.4.0) (2026-03-06)


### ⚠ BREAKING CHANGES

* **policy:** `(sandbox ...)` blocks are removed in version 3. Use `(match ctx.http.domain ...)` and `(match ctx.fs.path ...)` instead. Run `clash policy upgrade` to auto-migrate.

### Features

* **policy:** add eq predicate for when guards ([#237](https://github.com/empathic/clash/issues/237)) ([395f3d0](https://github.com/empathic/clash/commit/395f3d0d45e3d6f6e53be80dd804a82734a39b4b)), closes [#219](https://github.com/empathic/clash/issues/219)
* **policy:** add mcp invocation type and ctx.mcp.* observables ([#242](https://github.com/empathic/clash/issues/242)) ([cf91bfb](https://github.com/empathic/clash/commit/cf91bfb84c95547a0a2b5039fe39a1a807a23862)), closes [#217](https://github.com/empathic/clash/issues/217)
* **policy:** derive sandbox constraints from decision tree ([#243](https://github.com/empathic/clash/issues/243)) ([ac20a05](https://github.com/empathic/clash/commit/ac20a0573e1689a2f5c4fafc9a59d221f9188f69))
* **policy:** replace (default ...) with (use ...) + body-level effects ([#215](https://github.com/empathic/clash/issues/215)) ([7379981](https://github.com/empathic/clash/commit/7379981b04d57217f90a09a494993620ed08dbbd))
* Starlark policy DSL with pure-Starlark builders ([#249](https://github.com/empathic/clash/issues/249)) ([5f48b82](https://github.com/empathic/clash/commit/5f48b82b7f48db99e6bf3996e88d7075809ed67c))
