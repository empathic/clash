# ADR-002: Deny-Overrides Precedence

## Status

Accepted

## Context

When multiple rules match a request, we need a deterministic way to resolve conflicts. A request might match both `allow bash git *` and `deny bash git push --force`. The result must be unambiguous.

Common resolution strategies:

1. **First-match** (firewall-style): the first matching rule wins. Requires careful rule ordering. Fragile — adding a rule in the wrong position changes behavior.
2. **Most-specific** (XACML-style): more specific patterns override less specific ones. Hard to define "more specific" for glob patterns and boolean constraint expressions.
3. **Deny-overrides**: deny always wins, regardless of rule order. Simple, predictable, secure by default.

## Decision

Use strict deny-overrides precedence:

```
deny > ask > allow > delegate > default
```

If any matching rule says `deny`, the result is `deny` — regardless of how many `allow` rules also match. Rule order in the document has no effect on the outcome.

## Consequences

**Positive:**
- Deterministic and order-independent — rearranging rules never changes behavior
- Secure by default — adding a deny rule can never be overridden by an allow rule
- Easy to reason about — "is there ANY deny rule that matches?" is the only question
- Testable with property-based tests (monotonicity: adding a deny rule never produces a less restrictive result)

**Negative:**
- Cannot express "deny everything except X" as a deny + allow pair — need negation patterns (`deny * write !~/project/**`)
- Cannot have a targeted allow that overrides a broader deny — must restructure the deny rule to be more specific
- Makes the `delegate` effect lowest priority, which means you can't delegate a decision that another rule denies

## Amendment: Specificity-Based Ordering (v2, 2026-02)

The strict deny-overrides model is preserved across capability domains, but within a domain v2 uses **specificity-based first-match** instead of collecting all matches. Rules are sorted at compile time (most specific first) and the first matching rule wins. Conflicts (same specificity, different effects, overlapping matchers) are rejected at compile time.

This means:

```
(deny  (exec "git" "push" *))    ; more specific — checked first
(allow (exec "git" *))           ; less specific — checked second
```

`git push` hits the deny. `git status` skips the deny (no match) and hits the allow. Deny still always wins when both domains match (cross-domain resolution: deny > ask > allow).
