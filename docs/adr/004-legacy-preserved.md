# ADR-004: Legacy Format Preservation

## Status

Accepted

## Context

Clash evolved from Claude Code's simple permission format:

```json
{
  "permissions": {
    "allow": ["Bash(git:*)", "Read(**/*.rs)"],
    "deny": ["Read(.env)"]
  }
}
```

This was extended to a richer YAML format with (entity, verb, noun) triples, named constraints, profile expressions, and boolean composition. Later, a "new format" was added with profile-based rules and inline cap-scoped filesystem constraints.

The question: should we break backward compatibility with the legacy formats?

## Decision

Preserve backward compatibility with all previous formats:

1. **Legacy `permissions` format**: desugared into `Statement`s at parse time by `legacy.rs`
2. **Old YAML format** (flat rules + named constraints): parsed and compiled directly
3. **New profile-based format**: detected by `default:` being a YAML mapping

At compile time, all formats are unified into `CompiledProfileRule` — a single IR type evaluated by a single code path. The format detection and conversion happens in the parsing/compilation pipeline, not at evaluation time.

## Consequences

**Positive:**
- Existing users don't need to rewrite their policies
- Migration can happen incrementally — old and new formats are functionally equivalent
- The unified IR means there's only one evaluation code path to test and maintain
- Format auto-detection means users don't need to declare which format they're using

**Negative:**
- Three input formats means three parsers to maintain
- Legacy format has limited expressiveness (no entity dimension, no constraints, no profiles)
- The `Statement` AST type and `LegacyPermissions` type exist solely for backward compatibility
- Testing must cover all three formats to prevent regressions
