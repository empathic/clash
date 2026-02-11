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

## Amendment: Constraint Specificity (2026-02)

The strict deny-overrides model is preserved, but among non-deny rules we now apply **constraint specificity**: a rule with active inline constraints (url, args, pipe, redirect) beats a rule without constraints, regardless of effect level. This allows patterns like:

```yaml
allow webfetch *:
  url: ["github.com"]    # constrained allow — wins for github.com
ask webfetch *:          # unconstrained ask — wins for everything else
```

Deny is unaffected — it always wins regardless of constraint specificity. This amendment resolves the limitation that a targeted allow could never override a broader ask.
