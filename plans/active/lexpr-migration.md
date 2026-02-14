# Plan: Replace hand-rolled s-expr parser with lexpr

## Summary
Replace `sexpr.rs` (hand-written tokenizer/tree parser, ~200 LOC) with the `lexpr` crate.
Keep our `SExpr` type as a thin wrapper; `parse_sexpr.rs` and `edit.rs` stay unchanged.

## Syntax change
Bare `.` is the Scheme dotted-pair separator and can't be an unquoted atom in lexpr.
**Fix:** quote all path/pattern atoms — `(subpath .)` → `(subpath ".")`. Affects ~44 occurrences in tests, 1 in `default_policy.sexp`, plus `convert_filter_to_sexpr` output.

## Phase 1: Add lexpr, rewrite sexpr.rs internals

Replace the `tokenize()` + `TreeParser` implementation in `sexpr.rs` with:
1. Parse input with `lexpr::Parser` (iterates multiple top-level forms)
2. Convert each `lexpr::Value` → our existing `SExpr` enum (Atom/Str/List with Span)
3. Keep the `SExpr` type, `Span`, `ParseError`, and all public API unchanged
4. Symbols → `SExpr::Atom`, Strings → `SExpr::Str`, proper lists → `SExpr::List`
5. Numbers → convert to `SExpr::Atom(to_string)` for backward compat
6. Delete `Token`, `tokenize()`, `TreeParser`, `is_atom_char()`

Note: lexpr doesn't expose byte-offset spans, so `Span` values will be synthetic (0,0). This is fine — spans are only used for error context in `parse_sexpr.rs` error helpers, and lexpr's own errors cover parse-level issues.

## Phase 2: Quote bare `.` everywhere

1. `default_policy.sexp` line 18: `(subpath .)` → `(subpath ".")`
2. `convert_filter_to_sexpr()` in `edit.rs`: output `"."` instead of bare `.`
3. All test strings in `compile.rs`, `permissions.rs`, `parse_sexpr.rs`, `edit.rs`, `sexpr.rs`
4. Doc comments/error messages referencing `(subpath .)`
5. `builtin_*.sexp` files — check if any use bare `.` (likely not, they use `~/.clash`)

## Phase 3: Update sexpr.rs tests

Rewrite tests to match new behavior:
- The `parse_nested_list` test uses `(subpath .)` → quote it
- Other tests should still pass since atoms like `*`, `~/path` work in lexpr

## Verification
- `just check` — all unit tests + clippy
- `just clester` — e2e tests
