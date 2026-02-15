# Policy Grammar Specification

Formal grammar for clash policy documents. Policies use an s-expression syntax with capability-based rules.

---

## File Format

Policy files use the `.policy` extension and contain s-expressions. Comments start with `;`.

```
; This is a comment
(default deny main)

(policy main
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
```

---

## Top-Level Forms

```ebnf
document        = top_level*
top_level       = default_decl | policy_decl

default_decl    = "(" "default" effect policy_name ")"
policy_decl     = "(" "policy" policy_name policy_item* ")"

policy_item     = include | rule
include         = "(" "include" policy_name ")"
rule            = "(" effect cap_matcher ")"
```

---

## Capability Matchers

Rules target one of three capability domains: exec, fs, or net.

```ebnf
cap_matcher     = exec_matcher | fs_matcher | net_matcher

exec_matcher    = "(" "exec" pattern? pattern* ")"
fs_matcher      = "(" "fs" op_pattern? path_filter? ")"
net_matcher     = "(" "net" pattern? ")"
```

### Exec Matcher

Matches command execution. The first pattern matches the binary name, subsequent patterns match positional arguments.

```
(exec)                        ; match any command
(exec "git")                  ; match git with any args
(exec "git" *)                ; same — * is explicit any
(exec "git" "push" *)         ; match git push with any trailing args
(exec "git" "push" "origin")  ; match git push origin exactly
```

### Fs Matcher

Matches filesystem operations. Optional operation filter and path filter.

```
(fs)                                  ; match any fs operation
(fs read)                             ; match reads only
(fs write (subpath (env CWD)))        ; match writes under CWD
(fs (or read write) (subpath "/tmp")) ; match reads or writes under /tmp
```

### Net Matcher

Matches network access by domain.

```
(net)                          ; match any network access
(net "github.com")             ; match github.com exactly
(net /.*\.example\.com/)       ; match example.com subdomains
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
path_filter     = "(" "subpath" path_expr ")"  ; recursive subtree match
                | QUOTED_STRING                ; exact path match
                | "/" REGEX "/"                ; regex on resolved path
                | "(" "or" path_filter+ ")"    ; match any of
                | "(" "not" path_filter ")"    ; negation

path_expr       = QUOTED_STRING                ; static path
                | "(" "env" ENV_NAME ")"       ; environment variable (resolved at compile time)
```

### Subpath Matching

`(subpath path)` matches the path itself and any path beneath it:

```
(subpath "/home/user/project")
  matches: /home/user/project
  matches: /home/user/project/src/main.rs
  rejects: /home/user/other
```

### Environment Variables

`(env NAME)` is resolved at compile time to the value of the environment variable:

```
(subpath (env CWD))    ; expands to the current working directory
(subpath (env HOME))   ; expands to the user's home directory
```

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

## Policy Composition

Policies can include other policies using `(include name)`:

```
(policy cwd-access
  (allow (fs read (subpath (env CWD)))))

(policy main
  (include cwd-access)
  (allow (exec "git" *)))
```

Include is resolved at compile time by inlining the referenced policy's rules. Circular includes are detected and rejected.

---

## Default Declaration

Every policy file should have a `(default effect name)` form that specifies:
- The default effect when no rule matches a request
- The name of the active policy to evaluate

```
(default deny main)    ; default deny, evaluate the "main" policy
(default ask main)     ; default ask, evaluate the "main" policy
```

If no default declaration is present, the compiler uses `deny` with the policy named `main`.

---

## Lexical Rules

```ebnf
QUOTED_STRING   = '"' (CHAR | ESCAPE)* '"'
ESCAPE          = '\\' ('"' | '\\')
REGEX           = '/' (CHAR_NO_SLASH)* '/'
ENV_NAME        = [A-Z_][A-Z0-9_]*
COMMENT         = ';' (any char)* NEWLINE
WHITESPACE      = ' ' | '\t' | '\n' | '\r'
```

Whitespace and comments are ignored between tokens.
