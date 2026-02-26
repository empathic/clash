# Policy Grammar Specification

Formal grammar for clash policy documents. Policies use an s-expression syntax with capability-based rules.

---

## File Format

Policy files use the `.policy` extension and contain s-expressions. Comments start with `;`.

```
; This is a comment
(default deny "main")

(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
```

---

## Top-Level Forms

```ebnf
document        = top_level*
top_level       = version_decl | default_decl | policy_decl

version_decl    = "(" "version" INTEGER ")"
default_decl    = "(" "default" effect QUOTED_STRING ")"
policy_decl     = "(" "policy" QUOTED_STRING policy_item* ")"

policy_item     = include | rule
include         = "(" "include" QUOTED_STRING ")"
rule            = "(" effect cap_matcher keyword_args* ")"
keyword_args    = ":sandbox" ( QUOTED_STRING | rule+ )
```

Policy names, include targets, and keyword argument values must be quoted strings. Bare atoms are reserved for language keywords.

### Version Declaration

The optional `(version N)` form declares the policy language version. `N` must be a positive integer. If omitted, version 1 is assumed.

```
(version 1)
(default deny "main")

(policy "main"
  (allow (exec "git" *)))
```

---

## Capability Matchers

Rules target one of four capability domains: exec, fs, net, or tool.

```ebnf
cap_matcher     = exec_matcher | fs_matcher | net_matcher | tool_matcher

exec_matcher    = "(" "exec" pattern? args_spec ")"
args_spec       = pattern*                         ; positional (default)
                | ":has" pattern+                  ; orderless set-membership
fs_matcher      = "(" "fs" op_pattern? path_filter? ")"
net_matcher     = "(" "net" pattern? ")"
tool_matcher    = "(" "tool" pattern? ")"
```

### Exec Matcher

Matches command execution. The first pattern matches the binary name. Arguments can be matched positionally (default) or in any order using `:has`.

> **Scope:** Exec matching applies to the top-level command that Claude Code invokes. Child processes spawned by the command are not matched against exec rules. See [policy-semantics.md](./policy-semantics.md#capability-model) for details.

#### Positional matching (default)

Subsequent patterns match positional arguments left-to-right.

```
(exec)                        ; match any command
(exec "git")                  ; match git with any args
(exec "git" *)                ; same — * is explicit any
(exec "git" "push" *)         ; match git push with any trailing args
(exec "git" "push" "origin")  ; match git push origin exactly
```

#### Orderless matching (`:has`)

The `:has` keyword switches to set-membership matching for the remaining patterns: each pattern must match at least one argument, regardless of position. Extra unmatched arguments are always allowed.

`:has` can appear after positional arguments, enabling mixed matching: fixed subcommands followed by order-independent flags.

```
;; Pure orderless:
(exec "git" :has "push")                ; args contain "push" somewhere
(exec "git" :has "push" "--force")      ; args contain both "push" AND "--force"
(exec "git" :has "push" /--force/)      ; "push" literal + regex match

;; Mixed positional + orderless:
(exec "git" "push" :has "--force")      ; arg[0]="push", remaining contain "--force"
(exec "git" "push" :has "--force" "--no-verify")  ; subcommand + two required flags
```

For example, `(exec "git" "push" :has "--force")` matches:
- `git push --force`
- `git push --force origin`
- `git push origin --force main`

But does not match:
- `git push origin` (missing `--force`)
- `git --force push` (arg[0] is `--force`, not `push`)
- `git pull --force` (arg[0] is `pull`, not `push`)

#### Transparent prefix commands

When evaluating Bash commands, Clash automatically strips well-known "transparent prefix" commands to find the real command being executed. This ensures that policy rules evaluate against the actual command, not the wrapper.

Recognized transparent prefixes:

| Command | Description | Flags handled |
|---------|-------------|---------------|
| `time` | Execution timer | `-p`, `-f FILE`, `-o FILE` |
| `command` | Bash builtin (bypass functions) | `-p` (not `-v`/`-V` query modes) |
| `nice` | Priority adjustment | `-n VALUE` |
| `nohup` | Ignore HUP signal | (none) |
| `timeout` | Execution time limit | `-s SIGNAL`, `-k DURATION` + mandatory DURATION arg |

For example, with the policy `(deny (exec "git" "push" *))`:

```
git push origin main              ; denied — matches git push
time git push origin main         ; denied — time stripped, matches git push
nice -n 10 git push origin main   ; denied — nice stripped, matches git push
timeout 30 git push origin main   ; denied — timeout stripped, matches git push
```

Prefixes can be chained and combined with environment variables:

```
time nice -n 19 env FOO=bar cargo build   ; evaluates as: cargo build
```

Commands like `sudo`, `xargs`, and `strace` are **not** treated as transparent prefixes because they fundamentally change the execution context or command semantics.

### Fs Matcher

Matches filesystem operations. Optional operation filter and path filter.

```
(fs)                                  ; match any fs operation
(fs read)                             ; match reads only
(fs write (subpath (env PWD)))        ; match writes under CWD
(fs (or read write) (subpath "/tmp")) ; match reads or writes under /tmp
```

### Net Matcher

Matches network access by domain.

```
(net)                          ; match any network access
(net "github.com")             ; match github.com exactly
(net /.*\.example\.com/)       ; match example.com subdomains
```

### Tool Matcher

Matches agent tools by name. Applies to Claude Code tools that don't map to exec/fs/net (e.g. Skill, Task, AskUserQuestion, EnterPlanMode).

```
(tool)                         ; match any agent tool
(tool "Skill")                 ; match the Skill tool exactly
(tool (or "Skill" "Task"))     ; match Skill or Task
```

---

## Patterns

General-purpose patterns used for matching strings (binary names, arguments, domains).

```ebnf
pattern         = "*"                          ; wildcard — matches anything
                | QUOTED_STRING                ; exact string match
                | "/" REGEX "/"                ; regex match
                | "(" "or" pattern+ ")"        ; match any of
                | "(" "not" pattern ")"        ; negation
```

### Examples

```
*                              ; matches anything
"git"                          ; matches "git" exactly
/^cargo-.*/                    ; matches cargo-build, cargo-test, etc.
(or "github.com" "crates.io") ; matches either domain
(not "secret")                 ; matches anything except "secret"
```

---

## Operation Patterns

Used in `(fs ...)` to filter by filesystem operation kind.

```ebnf
op_pattern      = "*"                          ; any operation
                | fs_op                        ; single operation
                | "(" "or" fs_op+ ")"          ; multiple operations

fs_op           = "read" | "write" | "create" | "delete"
```

---

## Path Filters

Used in `(fs ...)` to constrain which paths match.

```ebnf
path_filter     = "(" "subpath" ":worktree"? path_expr ")"  ; recursive subtree match
                | QUOTED_STRING                ; exact path match
                | "/" REGEX "/"                ; regex on resolved path
                | "(" "or" path_filter+ ")"    ; match any of
                | "(" "not" path_filter ")"    ; negation

path_expr       = QUOTED_STRING                ; static path
                | "(" "env" ENV_NAME ")"       ; environment variable (resolved at compile time)
                | "(" "join" path_expr path_expr+ ")"  ; concatenate resolved parts
```

### Subpath Matching

`(subpath path)` matches the path itself and any path beneath it:

```
(subpath "/home/user/project")
  matches: /home/user/project
  matches: /home/user/project/src/main.rs
  rejects: /home/user/other
```

### Worktree-Aware Subpath

Adding `:worktree` before the path expression causes the compiler to detect git worktrees and automatically extend access to the backing repository's git directories:

```
(subpath :worktree (env PWD))
```

When the resolved path is inside a git worktree, this expands at compile time to an `or` covering the original path plus the worktree-specific git directory and the shared common directory. When the path is not inside a worktree, it behaves identically to a plain `(subpath ...)`.

This is primarily useful for CWD rules — without `:worktree`, git operations (commit, push, etc.) would be denied because they write to the backing repository's `.git/` directory, which lives outside the worktree.

### Environment Variables

`(env NAME)` is resolved at compile time to the value of the environment variable:

```
(subpath (env PWD))              ; expands to the current working directory
(subpath :worktree (env PWD))    ; same, plus git worktree dirs if applicable
(subpath (env HOME))             ; expands to the user's home directory
```

### Path Concatenation

`(join expr1 expr2 ...)` concatenates two or more path expressions. Each part is resolved individually and the results are concatenated:

```
(subpath (join (env HOME) "/.clash"))   ; expands to e.g. /home/user/.clash
(subpath (join (env HOME) "/.claude"))  ; expands to e.g. /home/user/.claude
```

`join` can be nested:

```
(subpath (join (join (env HOME) "/.config") "/clash"))
```

---

## Internal Policies

Clash embeds internal policies that are always active. These provide sensible defaults for Clash self-management and Claude workspace access. Internal policy names use the `__internal_*__` naming convention (e.g. `__internal_clash__`, `__internal_claude__`).

Internal policies are automatically included in the active policy via `(include ...)`. They appear in `clash policy list` and `clash policy show` output with a `[builtin]` tag.

### Overriding Internal Policies

To override an internal policy, define a policy with the same name in your policy file:

```
; Override the built-in Claude workspace policy with custom rules
(policy "__internal_claude__"
  (allow (fs read (subpath (join (env HOME) "/.claude"))))
  (deny  (fs write (subpath (join (env HOME) "/.claude")))))
```

When a user-defined policy shares the name of an internal policy, the user's version completely replaces the built-in one.

---

## Effects

```ebnf
effect          = "allow" | "deny" | "ask"
```

| Effect | Meaning |
|--------|---------|
| `allow` | Permit the action without prompting |
| `deny` | Block the action |
| `ask` | Prompt the user for confirmation |

---

## Keyword Arguments

Keywords are atoms starting with `:`. They appear in three positions:

- **Inside exec matchers:** `:has` (see [Exec Matcher](#exec-matcher) above)
- **Inside subpath filters:** `:worktree` (see [Worktree-Aware Subpath](#worktree-aware-subpath) above)
- **After capability matchers:** `:sandbox` (see below)

### `:sandbox`

The `:sandbox` keyword on exec rules defines the kernel-level sandbox for matching commands. It accepts either a named policy reference or inline rules.

#### Named sandbox

Reference a named policy whose rules define the sandbox:

```
(policy "cargo-env"
  (allow (fs read (subpath (env PWD))))
  (allow (net)))

(policy "main"
  (allow (exec "cargo" *) :sandbox "cargo-env"))
```

#### Inline sandbox

Define sandbox rules directly on the exec rule, without a separate named policy:

```
(allow (exec "clash" "bug" *) :sandbox (allow (net *)))
```

Multiple inline rules are supported:

```
(allow (exec "cargo" *) :sandbox
  (allow (net *))
  (allow (fs read (subpath (env PWD)))))
```

Inline sandbox rules cannot have nested `:sandbox` annotations.

When the exec rule matches, the sandbox's fs/net rules are used to build a kernel-level sandbox for the spawned process. See the [sandbox section](./policy-guide.md#sandbox-policies) in the policy guide.

---

## Policy Composition

Policies can include other policies using `(include "name")`:

```
(policy "cwd-access"
  (allow (fs read (subpath (env PWD)))))

(policy "main"
  (include "cwd-access")
  (allow (exec "git" *)))
```

Include is resolved at compile time by inlining the referenced policy's rules. Circular includes are detected and rejected.

---

## Default Declaration

Every policy file should have a `(default effect "name")` form that specifies:
- The default effect when no rule matches a request
- The name of the active policy to evaluate

```
(default deny "main")    ; default deny, evaluate the "main" policy
(default ask "main")     ; default ask, evaluate the "main" policy
```

If no default declaration is present, the compiler uses `deny` with the policy named `main`.

---

## Lexical Rules

```ebnf
QUOTED_STRING   = '"' (CHAR | ESCAPE)* '"'
ESCAPE          = '\\' ('"' | '\\')
REGEX           = '/' (CHAR_NO_SLASH)* '/'
INTEGER         = [0-9]+
ENV_NAME        = [A-Z_][A-Z0-9_]*
KEYWORD         = ':' ATOM                     ; e.g. :sandbox
COMMENT         = ';' (any char)* NEWLINE
WHITESPACE      = ' ' | '\t' | '\n' | '\r'
```

Whitespace and comments are ignored between tokens.
