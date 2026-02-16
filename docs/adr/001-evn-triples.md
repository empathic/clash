# ADR-001: Entity-Verb-Noun Triples

## Status

**Superseded** by v2 capability-based policy language (2026-02).

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

## Superseded By

The v2 policy language replaces EVN triples with **capability-based rules** using s-expression syntax. Instead of (entity, verb, noun) mapping to tools, v2 uses three capability domains:

- **exec** — command execution (binary + arguments)
- **fs** — filesystem operations (read/write/create/delete + path)
- **net** — network access (domain)

This decouples policy from tool names and provides compile-time conflict detection through specificity-based ordering. See [policy-semantics.md](../policy-semantics.md) for the v2 evaluation model.

## Consequences

**Positive (original):**
- Natural mapping to tool calls — every tool invocation has an actor, an action, and a target
- Entity dimension enables per-agent policies (trust claude but not untrusted agents)
- Simple mental model: each rule is a sentence ("allow agent:claude to execute git commands")

**Negative (motivating v2):**
- Verbs are tied to tool types — "block git push" requires knowing which tool runs it
- Noun semantics vary by verb (file path for read/write, command string for execute)
- No compile-time conflict detection — ambiguous rule orderings resolved at runtime
- Entity hierarchy is shallow (type + optional name) — no nested groups or inheritance
