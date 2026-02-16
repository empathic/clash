# ADR-004: Legacy Format Preservation

## Status

**Superseded** (2026-02). Legacy formats have been removed. v2 s-expression format is the only policy format.

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

## Original Decision

Preserve backward compatibility with all previous formats. At compile time, all formats are unified into `CompiledProfileRule` — a single IR type evaluated by a single code path.

## Superseded By

The v2 policy language replaces all previous formats with a single s-expression syntax. The legacy YAML formats, EVN triples, named constraints, profile expressions, and `CompiledProfileRule` IR have been removed.

Rationale:
- Three input formats meant three parsers to maintain and test
- Legacy formats could not express capability-level rules (exec/fs/net)
- The unified IR required complex translation layers
- v2's s-expression format is simpler, has compile-time conflict detection, and round-trips cleanly

Users migrating from v1 should rewrite their policies in v2 format. See the [Policy Writing Guide](../policy-guide.md) for examples.
