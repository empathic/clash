# ADR-001: Entity-Verb-Noun Triples

## Status

Accepted

## Context

We need a permission model that can express fine-grained access control for AI agent tool use. The model must support:

- Different agents and users with different permissions
- Different actions (read, write, execute)
- Different resources (file paths, command strings)
- Negation (deny specific paths, deny specific entities)
- Composition (combine constraints with boolean logic)

Alternative models considered:

1. **Flat allow/deny lists** (Claude Code's legacy format): `Bash(git:*)`, `Read(.env)`. Simple but no entity dimension, no composition, no constraints.
2. **RBAC**: Role-based access control. Heavy for this use case — roles don't map well to individual tool invocations.
3. **ABAC/XACML**: Attribute-based access control. Powerful but complex — policy language becomes a programming language.

## Decision

Use **(entity, verb, noun)** triples as the fundamental unit of policy. Each statement declares `effect(entity, verb, noun)` where:

- **Entity**: who is making the request (agent, user, service)
- **Verb**: what action (read, write, edit, execute, delegate)
- **Noun**: what resource (file path, command string, glob pattern)

This maps directly to tool invocations: *who* is calling *what tool* on *what resource*.

## Consequences

**Positive:**
- Natural mapping to tool calls — every tool invocation has an actor, an action, and a target
- Entity dimension enables per-agent policies (trust claude but not untrusted agents)
- Negation on entity and noun slots enables "everyone except" and "everything except" patterns
- Simple mental model: each rule is a sentence ("allow agent:claude to execute git commands")

**Negative:**
- Verbs are fixed to tool types — custom verbs require the new-format arbitrary verb strings
- Noun semantics vary by verb (file path for read/write, command string for execute) — the same noun pattern means different things in different contexts
- Entity hierarchy is shallow (type + optional name) — no nested groups or inheritance
