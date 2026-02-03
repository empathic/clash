# Policy Grammar Specification

Formal grammar for clash policy documents. Two formats are supported: **legacy** (flat rules + named constraints) and **new** (profile-based with inline constraints). The parser auto-detects format based on whether `default:` is a scalar or mapping.

---

## Format Detection

```
if default is YAML mapping → new format
if default is YAML scalar or absent → legacy format
```

---

## Legacy Format (YAML Document)

```ebnf
document        = default_decl?
                  constraints_decl?
                  profiles_decl?
                  permissions_decl?
                  rules_decl?

default_decl    = "default:" effect_str

constraints_decl = "constraints:" NEWLINE
                   (INDENT constraint_name ":" constraint_def)*

profiles_decl   = "profiles:" NEWLINE
                  (INDENT profile_name ":" profile_expr_str)*

permissions_decl = "permissions:" NEWLINE
                   ("allow:" string_list)?
                   ("deny:" string_list)?
                   ("ask:" string_list)?

rules_decl      = "rules:" NEWLINE
                  (rule_sequence | rule_mapping)

rule_sequence   = ("- " rule_str)*
rule_mapping    = (rule_str ":" (constraint_value | "[]" | null))*
```

### Constraint Definition

```ebnf
constraint_def  = (fs_field | caps_field | network_field
                  | pipe_field | redirect_field
                  | forbid_args_field | require_args_field)*

fs_field        = "fs:" filter_expr_str
caps_field      = "caps:" cap_expr
network_field   = "network:" ("allow" | "deny")
pipe_field      = "pipe:" ("true" | "false")
redirect_field  = "redirect:" ("true" | "false")
forbid_args_field  = "forbid-args:" string_list
require_args_field = "require-args:" string_list
```

---

## New Format (YAML Document)

```ebnf
document        = "default:" NEWLINE
                    INDENT "permission:" effect_str NEWLINE
                    INDENT "profile:" profile_name
                  ("profiles:" NEWLINE
                    (INDENT profile_name ":" profile_def)*)?

profile_def     = ("include:" (profile_name | profile_name_list))?
                  ("rules:" NEWLINE
                    (INDENT new_rule_key ":" inline_constraints?)*)?

new_rule_key    = effect_str SPACE verb_str SPACE noun_pattern
                  (* trailing ":" is stripped *)

inline_constraints = (fs_cap_scoped | args_field
                     | network_field | pipe_field | redirect_field)*

fs_cap_scoped   = "fs:" NEWLINE
                  (INDENT cap_expr ":" filter_expr_str)*

args_field      = "args:" arg_spec_list
arg_spec_list   = "[" (arg_spec ("," arg_spec)*)? "]"
arg_spec        = "!" STRING        (* Forbid *)
                | STRING            (* Require *)
```

---

## Compact Rule String (PEG Grammar)

Used in legacy format `rules:` lists. Defined in `rule.pest`:

```peg
rule            = SOI ~ effect ~ sep ~ entity ~ sep ~ tool ~ sep ~ pattern ~ EOI

effect          = "allow" | "deny" | "ask" | "delegate"

entity          = negation? ~ entity_value
negation        = "!"
entity_value    = wildcard | typed_entity | identifier
typed_entity    = identifier ~ ":" ~ (wildcard | identifier)
wildcard        = "*"
identifier      = (ASCII_ALPHANUMERIC | "_" | "-" | ".")+

tool            = "bash" | "read" | "write" | "edit" | "*"

pattern         = ANY+

sep             = (" " | "\t")+
```

### Entity Insertion

When the second token (after effect) is a known tool keyword (`bash`, `read`, `write`, `edit`), the entity `agent` is automatically inserted. This means:

```
allow bash git *       →  allow agent bash git *
deny read .env         →  deny agent read .env
```

### Constraint Suffix

A rule string may have a ` : ` suffix binding a profile expression:

```
allow agent bash git * : strict-git & safe-io
```

The `:` must be preceded by a space. The parser scans backwards from end to find the separator, distinguishing it from entity type colons (`agent:claude`).

---

## Pattern Syntax

Used for entity and noun slots.

```ebnf
pattern         = "!" match_expr      (* negated *)
                | match_expr           (* positive *)

match_expr      = "*"                  (* wildcard: matches anything *)
                | type ":" name        (* typed entity: agent:claude *)
                | type ":*"            (* typed wildcard: agent:* *)
                | glob_pattern         (* contains *, **, or ? *)
                | exact_string         (* everything else *)
```

### Glob Matching

Policy globs differ from filesystem globs: `*` matches any character **including `/`**. This is because patterns apply to both file paths and command strings.

```
git *           matches "git status", "git commit -m 'test'"
**/*.rs         matches "src/main.rs", "a/b/c.rs"
```

Glob-to-regex conversion: `.` → `\.`, `**` → `.*`, `*` → `.*`, `?` → `.`

---

## Filter Expression Grammar

Used in `fs:` fields for filesystem constraints. Recursive descent parser with precedence.

```ebnf
filter_expr     = or_expr
or_expr         = and_expr ("|" and_expr)*
and_expr        = unary ("&" unary)*
unary           = "!" unary | atom
atom            = "subpath(" path ")"
                | "literal(" path ")"
                | "regex(" pattern ")"
                | "(" filter_expr ")"
```

**Precedence**: `!` > `&` > `|`

### Filter Functions

| Function | Semantics |
|----------|-----------|
| `subpath(path)` | Resolved path must be under `path` (prefix match on normalized absolute path) |
| `literal(path)` | Resolved path must equal `path` exactly |
| `regex(pattern)` | Resolved path must match the regex `pattern` |

Path resolution: relative paths are resolved against the current working directory. `.` resolves to cwd. `..` components are handled lexically (no filesystem access).

---

## Profile Expression Grammar

Used for constraint bindings on rules and named profiles.

```ebnf
profile_expr    = or_expr
or_expr         = and_expr ("|" and_expr)*
and_expr        = unary ("&" unary)*
unary           = "!" unary | atom
atom            = identifier | "(" profile_expr ")"
```

**Precedence**: `!` > `&` > `|`

An identifier resolves first as a named profile (composite), then as a named constraint (primitive). Unknown references cause the constraint to fail closed.

---

## Cap Expression

Used in new-format `fs:` keys for capability-scoped filesystem constraints.

```ebnf
cap_expr        = cap_name ("+" cap_name)*
cap_name        = "read" | "write" | "create" | "delete" | "execute"
```

Example: `read + write` matches the `READ | WRITE` capability bitfield.

---

## Effect Values

```ebnf
effect_str      = "allow" | "deny" | "ask" | "delegate"
```

---

## Verb / Tool Values

Legacy format uses tool keywords that map to verbs:

| Tool keyword | Verb |
|-------------|------|
| `bash` | Execute |
| `read` | Read |
| `write` | Write |
| `edit` | Edit |
| `*` | Any |

New format accepts arbitrary verb strings (e.g., `safe-read`). The verb string is matched against the raw tool name.

---

## Legacy Permission Patterns

From Claude Code's `permissions` format:

```ebnf
legacy_pattern  = tool_name "(" arg ")"    (* tool with argument *)
                | tool_name                  (* tool without argument *)

arg             = prefix ":*"               (* prefix pattern: "git:*" → "git *" *)
                | glob_pattern              (* glob: "**/*.rs" *)
                | exact_string              (* exact: ".env" *)
```

Tool names: `Bash`, `Read`, `Write`, `Edit` (capitalized, mapped via `Verb::from_tool_name`).
