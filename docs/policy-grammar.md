# Policy Grammar Specification

Formal grammar for clash policy documents in **s-expression** format.

---

## Top-Level Structure

```ebnf
document        = form*

form            = default_form
                | profile_form
                | comment
```

---

## Default Declaration

Sets the default effect and active profile.

```ebnf
default_form    = "(" "default" effect_str profile_name ")"
```

Examples:

```scheme
(default deny main)
(default ask main)
```

---

## Profile Definition

```ebnf
profile_form    = "(" "profile" profile_name body* ")"

body            = include_form
                | rule_form
                | sandbox_form
```

### Include

```ebnf
include_form    = "(" "include" profile_name+ ")"
```

Merges rules from parent profiles. Circular includes are detected at parse time.

### Rule

```ebnf
rule_form       = "(" effect_str verb_str noun_pattern constraint* ")"

effect_str      = "allow" | "deny" | "ask"
verb_str        = "bash" | "read" | "write" | "edit" | "*" | identifier
noun_pattern    = "*" | quoted_string | identifier

constraint      = fs_constraint
                | args_constraint
                | pipe_constraint
                | redirect_constraint
                | url_constraint
                | network_constraint
```

Examples:

```scheme
(allow read *)
(deny bash "git push*")
(ask bash "git commit*")
(allow bash "cargo *"
  (fs (read+execute (subpath .))
      (write+create (subpath ./target)))
  (network allow))
```

### Filesystem Constraint

```ebnf
fs_constraint   = "(" "fs" fs_entry+ ")"
fs_entry        = "(" cap_expr filter_expr ")"
```

### Sandbox Block

Profile-level sandbox declaration for OS-enforced restrictions on bash commands:

```ebnf
sandbox_form    = "(" "sandbox" sandbox_entry+ ")"
sandbox_entry   = "(" "fs" cap_expr filter_expr ")"
                | "(" "network" ("allow" | "deny") ")"
```

Example:

```scheme
(sandbox
  (fs read execute (subpath .))
  (fs write create (subpath "./target"))
  (network deny))
```

---

## Cap Expression

```ebnf
cap_expr        = cap_term ('+' cap_term)*

cap_term        = "read" | "write" | "create" | "delete" | "execute"
                | "all" | "full"
```

The `+` operator combines capabilities. `all` and `full` are shorthand for all five capabilities.

Examples:

| Expression | Result |
|-----------|--------|
| `read` | READ |
| `read+write` | READ \| WRITE |
| `full` | READ \| WRITE \| CREATE \| DELETE \| EXECUTE |

---

## Filter Expression

Used in `fs` entries for filesystem constraints. Supports boolean operators.

```ebnf
filter_expr     = or_expr
or_expr         = and_expr ("or" and_expr)*
and_expr        = unary ("and" unary)*
unary           = "(" "not" filter_expr ")" | atom
atom            = "(" "subpath" path ")"
                | "(" "literal" path ")"
                | "(" "regex" pattern ")"
                | "(" filter_expr ")"
```

**Precedence**: `not` > `and` > `or`

### Filter Functions

| Function | Semantics |
|----------|-----------|
| `(subpath path)` | Resolved path must be under `path` (prefix match on normalized absolute path) |
| `(literal path)` | Resolved path must equal `path` exactly |
| `(regex pattern)` | Resolved path must match the regex `pattern` |

Path resolution: relative paths are resolved against the current working directory. `.` resolves to cwd.

Examples:

```scheme
(subpath .)                               ; anything under cwd
(or (subpath "~/.ssh") (subpath "~/.aws")) ; either location
(and (subpath .) (not (subpath "./.git"))) ; cwd except .git
```

---

## Shell Constraints

For bash rules, restrict command structure:

```ebnf
args_constraint     = "(" "args" arg_spec+ ")"
arg_spec            = quoted_string              (* require arg *)
                    | "(" "not" quoted_string ")" (* forbid arg *)

pipe_constraint     = "(" "pipe" ("allow" | "deny") ")"
redirect_constraint = "(" "redirect" ("allow" | "deny") ")"
url_constraint      = "(" "url" quoted_string+ ")"
network_constraint  = "(" "network" ("allow" | "deny") ")"
```

Example:

```scheme
(allow bash "git *"
  (args "--no-force" (not "--hard"))
  (pipe deny)
  (redirect deny))
```

---

## Pattern Syntax

Used for noun slots.

```ebnf
pattern         = "*"                  (* wildcard: matches anything *)
                | glob_pattern         (* contains *, **, or ? *)
                | exact_string         (* everything else *)
```

### Glob Matching

Policy globs differ from filesystem globs: `*` matches any character **including `/`**. This is because patterns apply to both file paths and command strings.

```
git *           matches "git status", "git commit -m 'fix'"
**/*.rs         matches "src/main.rs", "a/b/c.rs"
```

Glob-to-regex conversion: `.` → `\.`, `**` → `.*`, `*` → `.*`, `?` → `.`

---

## Effect Values

```ebnf
effect_str      = "allow" | "deny" | "ask"
```

---

## Verb / Tool Values

Known tool keywords map to canonical verbs:

| Tool keyword | Verb |
|-------------|------|
| `bash` | Execute |
| `read` | Read |
| `write` | Write |
| `edit` | Edit |
| `*` | Any |
| any other name | Named (matched by string) |

Arbitrary tool names (e.g., `task`, `glob`, `websearch`) are matched against the lowercased tool name from Claude Code.

---

## Comments

Line comments start with `;`:

```scheme
; This is a comment
(allow read *)  ; inline comment
```

---

## Legacy Permission Patterns

From Claude Code's `permissions` format (used by `clash migrate`):

```ebnf
legacy_pattern  = tool_name "(" arg ")"    (* tool with argument *)
                | tool_name                  (* tool without argument *)

arg             = prefix ":*"               (* prefix pattern: "git:*" → "git *" *)
                | glob_pattern              (* glob: "**/*.rs" *)
                | exact_string              (* exact: ".env" *)
```

Tool names: `Bash`, `Read`, `Write`, `Edit` (capitalized, mapped via `Verb::from_tool_name`).
