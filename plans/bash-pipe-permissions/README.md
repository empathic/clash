# Bash Pipe Permissions: Per-Segment Permission Checking

## Problem

Currently, a bash command like `cat file.txt | grep hello` is passed as a single
opaque string to the permission system. A rule like `deny * bash cat *` would NOT
deny this command because the full string `"cat file.txt | grep hello"` doesn't
match the pattern `cat *` (the `| grep hello` suffix prevents the match).

This is a security gap: denied commands can be smuggled through pipelines.

## Solution

Parse bash command strings into their constituent segments (pipeline stages,
`&&`/`||`/`;` compound commands) and check each segment independently. If **any**
segment is denied, the entire command is denied.

## Library Choice: `brush-parser`

- **Crate**: `brush-parser` v0.3.0
- **License**: MIT
- **Status**: Actively maintained (part of the brush shell project)
- **Why**: Full POSIX + bash-compatible shell parser with proper AST. Produces
  `Pipeline { seq: Vec<Command> }`, `AndOrList` for `&&`/`||`, and `CompoundList`
  for `;`-separated commands. Hand-written tokenizer + PEG parser.
- **Alternatives considered**:
  - `conch-parser`: Archived since May 2022
  - `yash-syntax`: GPLv3 (license incompatible)
  - `shell-words`: Only does word splitting, not pipeline-aware

## AST Structure (from brush-parser)

```
Program → Vec<CompleteCommand>
CompleteCommand = CompoundList → Vec<CompoundListItem>
CompoundListItem → (AndOrList, SeparatorOperator)
AndOrList → first: Pipeline + additional: Vec<And(Pipeline) | Or(Pipeline)>
Pipeline → seq: Vec<Command>
Command → Simple(SimpleCommand) | Compound(...) | Function(...) | ExtendedTest(...)
SimpleCommand → prefix + word_or_name + suffix
```

For `cat file.txt | grep hello && echo done`:
```
CompoundList
  └─ CompoundListItem
      └─ AndOrList
          ├─ first: Pipeline { seq: [Simple("cat file.txt"), Simple("grep hello")] }
          └─ additional: [And(Pipeline { seq: [Simple("echo done")] })]
```

Extracted segments: `["cat file.txt", "grep hello", "echo done"]`

## Evaluation Strategy

For each bash command:

1. **Parse** the command string using `brush-parser`
2. **Extract** all atomic command segments by walking the AST
3. **Evaluate** each segment independently against the policy
4. **Combine** results using existing precedence: **deny > ask > allow**

Rules:
- If ANY segment is denied → whole command is **denied**
- If ANY segment is ask (and none denied) → whole command is **ask**
- Only if ALL segments are allowed → whole command is **allowed**
- If parsing fails → fall back to evaluating the whole command as-is (current behavior)

## Scope

### In scope (this PR)
- Pipeline splitting (`|`)
- Compound operator splitting (`&&`, `||`, `;`)
- Graceful fallback on parse failure
- Unit tests + end-to-end tests

### Future work
- Subshell/command-substitution extraction: `$(command)`, backticks
- Process substitution: `<(command)`, `>(command)`
- Redirect-based file permission checks: `> file` → write check on `file`

## Files to Modify

| File | Change |
|------|--------|
| `Cargo.toml` (workspace) | Add `brush-parser` dependency |
| `clash/Cargo.toml` | Add `brush-parser` dependency |
| `clash/src/shell.rs` (new) | Shell command parsing and segment extraction |
| `clash/src/permissions.rs` | Use shell splitting for per-segment evaluation |
| `clash/src/main.rs` | Add `mod shell;` |
| `clester/tests/scripts/` | Add pipe permission test scripts |

## Implementation

### Phase 1: Shell parsing module (`clash/src/shell.rs`)

```rust
/// Extract individual command segments from a shell command string.
/// Returns the original command in a Vec if parsing fails (graceful fallback).
pub fn extract_command_segments(command: &str) -> Vec<String>
```

Walk the AST recursively:
- `CompoundList` → recurse into each `CompoundListItem`
- `AndOrList` → recurse into `first` pipeline + each `additional` pipeline
- `Pipeline` → recurse into each `Command` in `seq`
- `Command::Simple` → reconstruct command string from words
- `Command::Compound` → recurse into inner compound command
- Other → use Display to get string representation

### Phase 2: Integration (`clash/src/permissions.rs`)

Change `check_permission_policy` to:
1. For Bash tool: call `extract_command_segments(command)`
2. Evaluate each segment as `(entity, Verb::Execute, segment)`
3. Combine with deny > ask > allow precedence
4. Return the most restrictive result

### Phase 3: Tests

Unit tests for `extract_command_segments`:
- Simple command: `"ls -la"` → `["ls -la"]`
- Pipeline: `"cat f.txt | grep hello"` → `["cat f.txt", "grep hello"]`
- AND: `"make && make install"` → `["make", "make install"]`
- OR: `"test -f x || echo missing"` → `["test -f x", "echo missing"]`
- Mixed: `"cat f | grep x && echo done"` → `["cat f", "grep x", "echo done"]`
- Quoted pipe: `"echo 'hello | world'"` → `["echo 'hello | world'"]`
- Parse failure fallback: preserves original command

End-to-end tests:
- Denied command in pipeline blocks whole pipeline
- Allowed commands in pipeline allowed
- Mixed allow/deny in pipeline → deny wins
