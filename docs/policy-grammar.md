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
top_level       = version_decl | default_decl | use_decl | policy_decl | def_decl

version_decl    = "(" "version" INTEGER ")"
default_decl    = "(" "default" effect QUOTED_STRING ")"          ; deprecated in v2
use_decl        = "(" "use" QUOTED_STRING ")"                     ; v2 only
policy_decl     = "(" "policy" QUOTED_STRING policy_item* ")"
def_decl        = "(" "def" ATOM expression ")"                  ; v2 only, any expression

; v1 policy items
policy_item     = include | rule                                  ; v1
                | include | when_block | sandbox_block | effect_kw ; v2

include         = "(" "include" QUOTED_STRING ")"
rule            = "(" effect cap_matcher keyword_args* ")"        ; v1 only
keyword_args    = ":sandbox" ( QUOTED_STRING | rule+ )
```

> **Version 2 restriction:** Flat rules (`(allow ...)`, `(deny ...)`, `(ask ...)`) are not valid as policy items in version 2. Use `(when ...)` blocks instead. See [Version 2 Syntax](#version-2-syntax) below.

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
net_matcher     = "(" "net" pattern? path_filter? ")"
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

Matches network access by domain, optionally scoped to URL paths.

```
(net)                                        ; match any network access
(net "github.com")                           ; match github.com exactly
(net "localhost")                            ; match localhost only
(net "github.com" (subpath "/owner/repo"))   ; match github.com under /owner/repo
(net /.*\.example\.com/ (regex "/api/.*"))   ; match example.com subdomains under /api/
```

Path filters on net rules use the same syntax as filesystem path filters (`subpath`, `literal`, `regex`, `or`, `not`) but match against the URL path of the request rather than a filesystem path. Path filtering is enforced at the policy evaluation layer; the kernel sandbox proxy only performs domain-level filtering.

#### Localhost-only network access

When all allowed net domains are loopback addresses (`"localhost"`, `"127.0.0.1"`, `"::1"`), Clash automatically uses a lightweight localhost-only sandbox mode. This is enforced directly at the kernel level without spawning an HTTP proxy, making it more efficient than domain-filtered networking. On macOS, Seatbelt restricts connections to localhost at the kernel level. On Linux, enforcement is advisory (seccomp cannot filter connect destinations).

```
(allow (net "localhost"))   ; localhost-only — no proxy overhead
```

### Tool Matcher

Matches agent tools by name. Applies to Claude Code tools that don't map to exec/fs/net (e.g. Skill, Task, AskUserQuestion, EnterPlanMode, ExitPlanMode). Interactive tools (AskUserQuestion, EnterPlanMode, ExitPlanMode) get passthrough treatment when allowed — Clash defers to Claude Code's native UI instead of auto-approving.

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

## Use Declaration (v2)

The `(use "name")` form selects the entry policy to evaluate. It replaces the policy-naming role of `(default ...)` in v2.

```
(version 2)
(use "main")

(policy "main"
  (when (command "git" *) :allow)
  :deny)
```

The fallback effect is expressed as a bare effect keyword (`:deny`, `:allow`, `:ask`) at the end of the policy body. Because policy bodies use first-match semantics, a trailing `:deny` fires only when nothing above it matched.

If no `(use ...)` is present, the compiler falls back to `(default ...)`, then to `"main"`.

## Default Declaration (deprecated in v2)

> **Deprecated in v2:** Use `(use "name")` to select the entry policy and a bare effect in the policy body for the fallback. Run `clash policy upgrade` to auto-migrate.

The `(default effect "name")` form specifies:
- The default effect when no rule matches a request
- The name of the active policy to evaluate

```
(default deny "main")    ; default deny, evaluate the "main" policy
(default ask "main")     ; default ask, evaluate the "main" policy
```

If no default declaration is present, the compiler uses `deny` with the policy named `main`.

---

## Version 2 Syntax

Version 2 (`(version 2)`) replaces flat rules with structured blocks. Flat rules (`(allow ...)`, `(deny ...)`, `(ask ...)`) are **not valid** as policy items in version 2 — use `(when ...)` blocks instead.

Use `clash policy upgrade` to automatically transform a v1 policy to v2 syntax.

### Grammar

```ebnf
; v2 policy items (inside a policy body)
policy_item_v2  = include | when_block | match_block | sandbox_block | effect_kw

when_block      = "(" "when" when_guard when_body+ ")"
when_guard      = "(" "command" pattern? args_spec ")"
                | "(" "tool" pattern? ")"
                | "(" observable pattern ")"
                | "(" observable path_filter ")"        ; for ctx.fs.path
when_body       = effect_kw                             ; inline effect
                | sandbox_block                         ; nested sandbox
                | when_block                            ; nested when

effect_kw       = ":allow" | ":deny" | ":ask"

sandbox_block   = "(" "sandbox" sandbox_item+ ")"
sandbox_item    = rule                                  ; flat capability rule
                | sandbox_match_block                   ; observable dispatch

match_block     = "(" "match" observable match_arm+ ")"     ; policy level (allows :ask)
sandbox_match_block = "(" "match" observable sandbox_match_arm+ ")"  ; sandbox level (no :ask)
observable      = "command" | "tool"
                | "ctx.http.domain" | "ctx.http.method" | "ctx.http.port" | "ctx.http.path"
                | "ctx.fs.action" | "ctx.fs.path" | "ctx.fs.exists"
                | "ctx.process.command" | "ctx.process.args"
                | "ctx.tool.name" | "ctx.tool.args" | ctx_tool_arg_field
                | "ctx.state"
                | "[" observable observable+ "]"         ; tuple
ctx_tool_arg_field = "ctx.tool.args." FIELD_NAME "?"  ; nullable dynamic field accessor
match_arm       = arm_pattern effect_kw
sandbox_match_arm = arm_pattern sandbox_effect_kw
sandbox_effect_kw = ":allow" | ":deny"
arm_pattern     = pattern | path_filter                 ; scalar observable
                | exec_arm_pattern                      ; command observable
                | "[" arm_element+ "]"                  ; tuple observable
exec_arm_pattern = "(" pattern? args_spec ")"           ; like exec_matcher sans "exec"

def_decl        = "(" "def" ATOM expression ")"

expression      = "[" QUOTED_STRING* "]"                 ; bracket list (expands to or-pattern)
                | pattern                                ; general pattern
                | when_block                             ; compound when block
                | match_block                            ; compound match block
                | sandbox_block                          ; compound sandbox block
```

### `when` blocks

A `when` block gates its body on an observable guard. The guard tests a single observable value against a pattern. All observables are supported as guards.

The body contains one or more items: an effect keyword (`:allow`, `:deny`, `:ask`), a `(sandbox ...)` block, or a nested `(when ...)` block.

```
; Allow all git commands
(when (command "git" *) :allow)

; Deny git push with --force
(when (command "git" "push" :has "--force") :deny)

; Allow the Read tool
(when (tool "Read") :allow)

; Allow multiple tools
(when (tool (or "Read" "Glob" "Grep")) :allow)

; Guard on HTTP domain
(when (ctx.http.domain "github.com") :allow)

; Guard on filesystem action
(when (ctx.fs.action "read") :allow)

; Guard on filesystem path
(when (ctx.fs.path (subpath (env PWD))) :allow)

; Allow with a sandbox
(when (command "cargo" *)
  :allow
  (sandbox
    (allow (fs read (subpath (env PWD))))
    (allow (net))))
```

When the body is a single effect keyword, it renders on one line: `(when (command "git" *) :allow)`. Multi-item bodies are indented.

### `sandbox` blocks

A `sandbox` block defines kernel-level restrictions for commands matched by a parent `(when (command ...) ...)` block. Sandbox items are capability grants — they use the same `(allow (fs ...))` / `(allow (net ...))` syntax as v1 flat rules.

Sandbox blocks can also contain `(match ...)` blocks for observable-based dispatch.

```
(when (command *)
  :allow
  (sandbox
    (allow (fs (or read write) (subpath (env PWD))))
    (allow (net "github.com"))
    (match ctx.http.domain
      "crates.io" :allow
      "github.com" :allow
      *           :deny)))
```

### `match` blocks

A `match` block dispatches on a runtime observable value. It contains alternating pattern/effect pairs. Match blocks can appear both at policy level and inside sandbox blocks.

At **policy level**, match arms may use `:allow`, `:deny`, or `:ask` effects. Inside **sandbox blocks**, only `:allow` and `:deny` are valid (`:ask` is rejected).

#### Observables

| Observable | Type | Description |
|-----------|------|-------------|
| `command` | exec | Command execution (binary + args) |
| `tool` | string | Agent tool name |
| `ctx.http.domain` | string | Domain of an HTTP request |
| `ctx.http.method` | string | HTTP method (GET, POST, etc.) |
| `ctx.http.port` | int | Destination port |
| `ctx.http.path` | string | URL path |
| `ctx.fs.action` | string | Filesystem operation: `"read"`, `"write"`, `"create"`, `"delete"` |
| `ctx.fs.path` | path | Filesystem path being accessed |
| `ctx.fs.exists` | bool | Whether the target file exists |
| `ctx.process.command` | string | Executable name |
| `ctx.process.args` | [string] | Argument list |
| `ctx.tool.name` | string | Tool name |
| `ctx.tool.args` | {string?} | Tool arguments (dynamic, nullable) |
| `ctx.tool.args.<field>?` | string? | Nullable accessor for a specific tool argument field; absent field short-circuits the enclosing `match` |
| `ctx.state` | string | Agent state |

#### Scalar match

Match a single observable against patterns:

```
(match ctx.http.domain
  "github.com" :allow
  "crates.io"  :allow
  *            :deny)

(match ctx.fs.action
  "read"  :allow
  "write" :deny)

(match ctx.fs.path
  (subpath (env PWD)) :allow
  *                   :deny)
```

#### Command match

Match command execution with exec-style arm patterns:

```
(match command
  ("git" "push" :has "--force") :deny
  ("git" *)                    :allow
  ("cargo" *)                  :allow
  *                            :ask)
```

Each arm pattern uses the same syntax as exec matchers (binary + positional args or `:has`).

#### Tool match

Match agent tools by name:

```
(match tool
  (or "Read" "Glob" "Grep") :allow
  "WebFetch"                 :ask
  *                          :deny)
```

#### Tuple match

Match multiple observables simultaneously using bracket syntax:

```
(match [ctx.fs.action ctx.fs.path]
  ["read"  (subpath (env PWD))]   :allow
  ["write" (subpath (env PWD))]   :allow
  ["read"  *]                     :deny
  [*       *]                     :deny)
```

Tuple patterns use `[...]` brackets and must have one element per observable in the tuple.

#### Pattern types in match arms

- String literals: `"github.com"`, `"read"`
- Wildcards: `*`
- Combinators: `(or "read" "write")`, `(not "delete")`
- Path filters (for `fs.path`): `(subpath (env PWD))`, `(subpath "/tmp")`
- Regex: `/.*\.example\.com/`
- Exec patterns (for `command`): `("git" "push" *)`, `("cargo" :has "--release")`

### `def` declarations

A `def` declaration binds a name to any expression. When the name is referenced in a policy body, the bound expression is spliced in and parsed in context. Definitions are top-level forms.

Values may be bracket lists (backwards compatible), patterns, or compound forms like `match` and `when` blocks:

```
; Bracket list — expands to (or ...) pattern in pattern context
(def builders ["cargo" "make" "cmake" "ninja"])

; Compound pattern
(def github-domains (or "github.com" "api.github.com"))

; Compound match block — spliced into policy/when body
(def github-net
  (match proxy.domain
    "github.com" :allow))

(policy "main"
  (when (command builders *) :allow)   ; builders → Or(["cargo", ...])
  (when (command "curl" *)
    github-net))                        ; spliced as match block
```

The name is a bare atom matching `[a-zA-Z][a-zA-Z0-9\-]*`. The value is any valid s-expression.

### Effect keywords

In v2 contexts (when bodies, match arms), effects use keyword syntax:

| Keyword | Effect |
|---------|--------|
| `:allow` | Permit the action |
| `:deny` | Block the action |
| `:ask` | Prompt the user |

### Complete v2 example

```
(version 2)
(use "main")
(def builders ["cargo" "make" "cmake"])

(policy "main"
  ; Allow git, deny force-push
  (when (command "git" "push" :has "--force") :deny)
  (when (command "git" *) :allow)

  ; Allow build tools with filesystem + network sandbox
  (when (command builders *)
    :allow
    (sandbox
      (allow (fs (or read write) (subpath (env PWD))))
      (match ctx.http.domain
        "crates.io"  :allow
        "github.com" :allow
        *            :deny)))

  ; Dispatch on tool name at policy level
  (match tool
    (or "Read" "Glob" "Grep")      :allow
    (or "WebFetch" "WebSearch")    :allow
    *                              :deny)

  ; Guard on HTTP domain
  (when (ctx.http.domain "github.com") :allow)

  :deny)                             ; fallback for unmatched requests
```

### Upgrading from v1 to v2

Run `clash policy upgrade` to automatically transform v1 flat rules to v2 structured syntax. The transformation:

| v1 flat rule | v2 equivalent |
|-------------|--------------|
| `(allow (exec "git" *))` | `(when (command "git" *) :allow)` |
| `(deny (exec "git" "push" *))` | `(when (command "git" "push" *) :deny)` |
| `(allow (tool "Agent"))` | `(when (tool "Agent") :allow)` |
| `(allow (fs read (subpath X)))` | `(when (tool (or "Read" "Glob" "Grep")) :allow)` + sandbox |
| `(allow (net "github.com"))` | `(when (tool (or "WebFetch" "WebSearch")) :allow)` + sandbox |

Filesystem and network allow rules also generate sandbox entries inside a `(when (command *) (sandbox ...))` block, so that sandboxed commands inherit the appropriate kernel-level capabilities.

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
