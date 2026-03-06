# Changelog

## [0.4.0](https://github.com/empathic/clash/compare/v0.3.6...v0.4.0) (2026-03-06)


### ⚠ BREAKING CHANGES

* **policy:** `(sandbox ...)` blocks are removed in version 3. Use `(match ctx.http.domain ...)` and `(match ctx.fs.path ...)` instead. Run `clash policy upgrade` to auto-migrate.

### Features

* fix some UX nits in TUI ([#212](https://github.com/empathic/clash/issues/212)) ([1b3b578](https://github.com/empathic/clash/commit/1b3b578096fd08e9bce94bb2c1dc21a276edb497))
* **policy:** add agent invocation type and ctx.agent.name observable ([#236](https://github.com/empathic/clash/issues/236)) ([02ec5eb](https://github.com/empathic/clash/commit/02ec5ebdd0593a296d0cb20708aebf176b73a3e5)), closes [#218](https://github.com/empathic/clash/issues/218)
* **policy:** add eq predicate for when guards ([#237](https://github.com/empathic/clash/issues/237)) ([395f3d0](https://github.com/empathic/clash/commit/395f3d0d45e3d6f6e53be80dd804a82734a39b4b)), closes [#219](https://github.com/empathic/clash/issues/219)
* **policy:** add mcp invocation type and ctx.mcp.* observables ([#242](https://github.com/empathic/clash/issues/242)) ([cf91bfb](https://github.com/empathic/clash/commit/cf91bfb84c95547a0a2b5039fe39a1a807a23862)), closes [#217](https://github.com/empathic/clash/issues/217)
* **policy:** add mcp invocation type and enforce :ask context restriction ([#241](https://github.com/empathic/clash/issues/241)) ([43bf7ad](https://github.com/empathic/clash/commit/43bf7ad6aebf98d5fb83e900fc0d14642ac05a65))
* **policy:** add nullable ? accessors for dynamic ctx fields ([#239](https://github.com/empathic/clash/issues/239)) ([9d97b32](https://github.com/empathic/clash/commit/9d97b328e8fc7ea8ae0a373c429b6e33ff079bb8)), closes [#221](https://github.com/empathic/clash/issues/221)
* **policy:** adopt ctx.* namespace for observables ([#234](https://github.com/empathic/clash/issues/234)) ([c174ad8](https://github.com/empathic/clash/commit/c174ad8b18c3062a5152ca22b1ccabb3b4821dca)), closes [#216](https://github.com/empathic/clash/issues/216)
* **policy:** derive sandbox constraints from decision tree ([#243](https://github.com/empathic/clash/issues/243)) ([ac20a05](https://github.com/empathic/clash/commit/ac20a0573e1689a2f5c4fafc9a59d221f9188f69))
* **policy:** enforce forward reference prohibition ([#235](https://github.com/empathic/clash/issues/235)) ([46c6eff](https://github.com/empathic/clash/commit/46c6eff5765b4451e58921a065b8baa8c744a6e2))
* **policy:** enforce forward reference prohibition (validation rule 9) ([46c6eff](https://github.com/empathic/clash/commit/46c6eff5765b4451e58921a065b8baa8c744a6e2)), closes [#225](https://github.com/empathic/clash/issues/225)
* **policy:** replace (default ...) with (use ...) + body-level effects ([#215](https://github.com/empathic/clash/issues/215)) ([7379981](https://github.com/empathic/clash/commit/7379981b04d57217f90a09a494993620ed08dbbd))
* **policy:** upgrade def to bind arbitrary expressions ([#233](https://github.com/empathic/clash/issues/233)) ([35d2867](https://github.com/empathic/clash/commit/35d2867f41b26dc88ccf223d471e1ad07559a0c3))
* **policy:** validate ctx references against versioned schema ([#223](https://github.com/empathic/clash/issues/223)) ([851f819](https://github.com/empathic/clash/commit/851f819ffd572a267b1931fe028bc398f7f94829))
* **policy:** validate ctx references against versioned schema ([#238](https://github.com/empathic/clash/issues/238)) ([851f819](https://github.com/empathic/clash/commit/851f819ffd572a267b1931fe028bc398f7f94829))
* **policy:** validate non-overlapping sibling dimensions ([#240](https://github.com/empathic/clash/issues/240)) ([0fe3c5a](https://github.com/empathic/clash/commit/0fe3c5ab64d00cc9e34582d2c082d39997e7a483)), closes [#226](https://github.com/empathic/clash/issues/226)
* Starlark policy DSL with pure-Starlark builders ([#249](https://github.com/empathic/clash/issues/249)) ([5f48b82](https://github.com/empathic/clash/commit/5f48b82b7f48db99e6bf3996e88d7075809ed67c))
