; Starlark tree-sitter highlight queries.
; Adapted from Helix editor's runtime/queries/python/highlights.scm
; (https://github.com/helix-editor/helix/blob/master/runtime/queries/python/highlights.scm)
; Helix is MIT/Apache-2.0 licensed. Starlark inherits Python's grammar.

; -------
; Punctuation
; -------

["," "." ":" ";"] @punctuation.delimiter
["(" ")" "[" "]" "{" "}"] @punctuation.bracket

; -------
; Operators
; -------

[
  "-"
  "-="
  "!="
  "*"
  "**"
  "**="
  "*="
  "/"
  "//"
  "//="
  "/="
  "&"
  "&="
  "%"
  "%="
  "^"
  "^="
  "+"
  "+="
  "<"
  "<<"
  "<<="
  "<="
  "="
  "=="
  ">"
  ">="
  ">>"
  ">>="
  "|"
  "|="
  "~"
] @operator

; -------
; Variables
; -------

(identifier) @variable

(attribute attribute: (identifier) @variable.member)

(parameters (identifier) @variable.parameter)
(parameters (default_parameter name: (identifier) @variable.parameter))

(keyword_argument name: (identifier) @variable.parameter)

; -------
; Keywords
; -------

[
  "and"
  "or"
  "not"
  "in"
  "not in"
] @keyword.operator

[
  "pass"
] @keyword

[
  "if"
  "elif"
  "else"
] @keyword.control.conditional

[
  "def"
] @keyword.function

"return" @keyword.control.return

[
  "for"
  "while"
  "break"
  "continue"
] @keyword.control.repeat

(for_statement "in" @keyword.control.repeat)
(for_in_clause "in" @keyword.control.repeat)

"load" @keyword.control.import

; -------
; Types
; -------

((identifier) @type
 (#match? @type "^[A-Z]"))

; -------
; Functions
; -------

(function_definition name: (identifier) @function)

(call function: (identifier) @function)

(call function: (attribute attribute: (identifier) @function.method))

; Builtin functions
((call function: (identifier) @function.builtin)
 (#any-of? @function.builtin
  "abs" "all" "any" "bool" "dict" "dir" "enumerate" "fail"
  "filter" "getattr" "hasattr" "hash" "int" "len" "list" "map"
  "max" "min" "print" "range" "repr" "reversed" "select" "sorted"
  "str" "struct" "tuple" "type" "zip"))

; -------
; Constants
; -------

((identifier) @constant
 (#match? @constant "^_*[A-Z][A-Z\\d_]*$"))

[
  (true)
  (false)
] @constant.builtin.boolean

(none) @constant.builtin

(integer) @constant.numeric.integer
(float) @constant.numeric.float

; -------
; Strings
; -------

(comment) @comment

(string) @string
(escape_sequence) @constant.character.escape
