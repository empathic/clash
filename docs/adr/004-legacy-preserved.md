# ADR-004: Legacy Format Removal

## Status

Superseded — legacy runtime support removed; `clash migrate` retained for one-time conversion.

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

The original decision was to preserve backward compatibility with all previous formats and support an `engine_mode` setting (Policy, Legacy, Auto) to select between them at runtime.

## Decision

Remove runtime support for the legacy format and the `engine_mode` setting. The policy engine now always loads from `~/.clash/policy.yaml`. Two policy YAML formats remain:

1. **Flat rules format**: `default:` as a scalar, top-level `rules:` list with optional named constraints and profiles
2. **Profile-based format**: `default:` as a mapping with `permission` and `profile`, plus `profiles:` definitions

Users who still have Claude Code permission rules can run `clash migrate` to generate a `policy.yaml` file from their existing settings. The `legacy.rs` desugaring code is retained solely for this migration path.

## Consequences

**Positive:**
- Simpler runtime: no `EngineMode` enum, no auto-detection of legacy Claude settings
- Test scripts use `policy_raw:` directly, making the tested policy explicit
- One fewer code path to maintain at evaluation time

**Negative:**
- Users who relied on `engine_mode: legacy` or `engine_mode: auto` must run `clash migrate` and switch to `policy.yaml`
