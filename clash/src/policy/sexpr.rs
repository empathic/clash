//! S-expression parser backed by the `lexpr` crate.
//!
//! Parses s-expression source into our [`SExpr`] tree, preserving byte-offset
//! spans for error reporting.

use std::fmt;

/// A byte-offset span in the source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// A generic s-expression node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SExpr {
    /// An unquoted atom (e.g. `allow`, `bash`, `*`, `subpath`).
    Atom(String, Span),
    /// A quoted string (e.g. `"git push*"`).
    Str(String, Span),
    /// A parenthesized list of sub-expressions.
    List(Vec<SExpr>, Span),
}

impl SExpr {
    /// Return the span of this node.
    pub fn span(&self) -> Span {
        match self {
            SExpr::Atom(_, s) | SExpr::Str(_, s) | SExpr::List(_, s) => *s,
        }
    }

    /// Return the string value of an atom or quoted string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            SExpr::Atom(s, _) | SExpr::Str(s, _) => Some(s),
            SExpr::List(_, _) => None,
        }
    }

    /// Return the children of a list node.
    pub fn as_list(&self) -> Option<&[SExpr]> {
        match self {
            SExpr::List(children, _) => Some(children),
            _ => None,
        }
    }

    /// Check if this is an atom with the given value (case-insensitive).
    pub fn is_atom(&self, name: &str) -> bool {
        matches!(self, SExpr::Atom(s, _) if s.eq_ignore_ascii_case(name))
    }
}

/// A parse error with position information.
#[derive(Debug, Clone)]
pub struct ParseError {
    pub message: String,
    pub offset: usize,
    /// Line number (1-based).
    pub line: usize,
    /// Column number (1-based).
    pub col: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Sentinel symbol used to escape standalone `.` atoms, which lexpr reserves
/// for dotted-pair syntax. Converted back to `"."` after parsing.
const DOT_PLACEHOLDER: &str = "__CLASH_DOT__";

/// Replace standalone `.` tokens with a placeholder symbol so lexpr does not
/// interpret them as dotted-pair separators. A standalone `.` is one preceded
/// and followed by whitespace or parentheses (i.e. not part of a larger atom
/// like `~/.clash`).
fn escape_dots(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;
    // Track whether we are inside a quoted string to avoid mangling string contents.
    let mut in_string = false;

    while i < len {
        let b = bytes[i];

        if in_string {
            if b == b'\\' && i + 1 < len {
                out.push(b as char);
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            out.push(b as char);
            i += 1;
            continue;
        }

        if b == b'"' {
            in_string = true;
            out.push(b as char);
            i += 1;
            continue;
        }

        if b == b'.' {
            // Check if this is a standalone dot (not part of a larger atom).
            let prev_ok =
                i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b'\n' | b'\r' | b'(' | b')');
            let next_ok =
                i + 1 >= len || matches!(bytes[i + 1], b' ' | b'\t' | b'\n' | b'\r' | b'(' | b')');
            if prev_ok && next_ok {
                out.push_str(DOT_PLACEHOLDER);
                i += 1;
                continue;
            }
        }

        out.push(b as char);
        i += 1;
    }
    out
}

/// Pre-computed index mapping line numbers to byte offsets of line starts.
struct LineIndex {
    /// line_starts[i] is the byte offset where line (i+1) begins.
    line_starts: Vec<usize>,
}

impl LineIndex {
    fn new(input: &str) -> Self {
        let mut line_starts = vec![0]; // line 1 starts at offset 0
        for (i, ch) in input.char_indices() {
            if ch == '\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    /// Convert a lexpr Position (1-based line, 0-based column byte offset) to
    /// an absolute byte offset in the source.
    fn to_byte_offset(&self, pos: &lexpr::parse::Position) -> usize {
        let line = pos.line(); // 1-based
        let col = pos.column(); // 0-based byte offset from last \n
        if line == 0 || line > self.line_starts.len() {
            return 0;
        }
        self.line_starts[line - 1] + col
    }
}

/// Convert a lexpr `Datum::Ref` into our `SExpr`.
fn ref_to_sexpr(r: lexpr::datum::Ref<'_>, idx: &LineIndex) -> Result<SExpr, ParseError> {
    let lspan = r.span();
    let span = Span {
        start: idx.to_byte_offset(&lspan.start()),
        end: idx.to_byte_offset(&lspan.end()),
    };

    match r.value() {
        lexpr::Value::Symbol(s) => {
            let name = if &**s == DOT_PLACEHOLDER {
                ".".to_string()
            } else {
                s.to_string()
            };
            Ok(SExpr::Atom(name, span))
        }
        lexpr::Value::String(s) => Ok(SExpr::Str(s.to_string(), span)),
        lexpr::Value::Null => Ok(SExpr::List(vec![], span)),
        lexpr::Value::Cons(_) => {
            let iter = r.list_iter().expect("Cons should be iterable");
            let mut children = Vec::new();
            for child in iter {
                children.push(ref_to_sexpr(child, idx)?);
            }
            Ok(SExpr::List(children, span))
        }
        lexpr::Value::Number(n) => Ok(SExpr::Atom(n.to_string(), span)),
        lexpr::Value::Bool(b) => Ok(SExpr::Atom(if *b { "#t" } else { "#f" }.into(), span)),
        lexpr::Value::Char(c) => Ok(SExpr::Atom(c.to_string(), span)),
        lexpr::Value::Keyword(k) => Ok(SExpr::Atom(format!(":{k}"), span)),
        other => {
            let start = lspan.start();
            Err(ParseError {
                message: format!("unsupported s-expression value: {other:?}"),
                offset: span.start,
                line: start.line(),
                col: start.column() + 1,
            })
        }
    }
}

/// Parse an s-expression source string into a list of top-level expressions.
pub fn parse(input: &str) -> Result<Vec<SExpr>, ParseError> {
    let escaped = escape_dots(input);
    let idx = LineIndex::new(&escaped);
    let options = lexpr::parse::Options::new();
    let mut parser = lexpr::parse::Parser::from_str_custom(&escaped, options);
    let mut exprs = Vec::new();

    for datum_result in parser.datum_iter() {
        let datum = datum_result.map_err(|e| {
            // lexpr errors are opaque; extract what we can from Display
            let msg = e.to_string();
            // Try to find a position from the error message, fall back to end of input
            ParseError {
                message: msg,
                offset: input.len(),
                line: 1,
                col: 1,
            }
        })?;
        exprs.push(ref_to_sexpr(datum.as_ref(), &idx)?);
    }

    Ok(exprs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty() {
        assert_eq!(parse("").unwrap(), vec![]);
        assert_eq!(parse("  \n  ").unwrap(), vec![]);
        assert_eq!(parse("; just a comment\n").unwrap(), vec![]);
    }

    #[test]
    fn parse_atom() {
        let exprs = parse("hello").unwrap();
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].as_str(), Some("hello"));
    }

    #[test]
    fn parse_simple_list() {
        let exprs = parse("(allow bash *)").unwrap();
        assert_eq!(exprs.len(), 1);
        let children = exprs[0].as_list().unwrap();
        assert_eq!(children.len(), 3);
        assert!(children[0].is_atom("allow"));
        assert!(children[1].is_atom("bash"));
        assert!(children[2].is_atom("*"));
    }

    #[test]
    fn parse_nested_list() {
        let exprs = parse("(allow (fs read) (subpath .))").unwrap();
        assert_eq!(exprs.len(), 1);
        let children = exprs[0].as_list().unwrap();
        assert_eq!(children.len(), 3);
        // (fs read)
        let fs = children[1].as_list().unwrap();
        assert_eq!(fs.len(), 2);
        assert!(fs[0].is_atom("fs"));
        assert!(fs[1].is_atom("read"));
    }

    #[test]
    fn parse_quoted_string() {
        let exprs = parse(r#"(deny bash "git push*")"#).unwrap();
        let children = exprs[0].as_list().unwrap();
        assert_eq!(children[2].as_str(), Some("git push*"));
        // Quoted strings are SExpr::Str
        assert!(matches!(&children[2], SExpr::Str(_, _)));
    }

    #[test]
    fn parse_comments() {
        let input = r#"
; This is a policy file
(default (permission deny) (profile main))
; Another comment
(profile main
  ; inner comment
  (allow bash *))
"#;
        let exprs = parse(input).unwrap();
        assert_eq!(exprs.len(), 2);
    }

    #[test]
    fn parse_escape_sequences() {
        let exprs = parse(r#""hello \"world\" \n""#).unwrap();
        assert_eq!(exprs[0].as_str(), Some("hello \"world\" \n"));
    }

    #[test]
    fn error_unterminated_string() {
        let err = parse(r#""unterminated"#).unwrap_err();
        assert!(!err.message.is_empty());
        assert_eq!(err.line, 1);
    }

    #[test]
    fn error_unmatched_paren() {
        let err = parse("(hello").unwrap_err();
        assert!(!err.message.is_empty());
    }

    #[test]
    fn error_extra_rparen() {
        let err = parse(")").unwrap_err();
        assert!(!err.message.is_empty());
    }

    #[test]
    fn parse_complex_policy() {
        let input = r#"
(default (permission deny) (profile main))

(profile cwd-read
  (allow (fs read) (subpath .)))

(profile main
  (include cwd-read)
  (allow (fs read write) (subpath .))
  (allow (fs read) (subpath "~/.clash"))
  (sandbox
    (fs full (subpath .))
    (network deny))
  (allow bash *)
  (deny bash "git push*")
  (ask bash "git commit*"))
"#;
        let exprs = parse(input).unwrap();
        assert_eq!(exprs.len(), 3); // default, profile cwd-read, profile main
    }

    #[test]
    fn span_tracking() {
        let input = "(hello)";
        let exprs = parse(input).unwrap();
        let span = exprs[0].span();
        assert_eq!(span.start, 0);
        assert_eq!(span.end, 7);
    }

    #[test]
    fn parse_glob_patterns() {
        let exprs = parse("(allow bash *--force*)").unwrap();
        let children = exprs[0].as_list().unwrap();
        assert_eq!(children[2].as_str(), Some("*--force*"));
    }

    #[test]
    fn parse_path_atoms() {
        let exprs = parse("(subpath ~/.clash/policy)").unwrap();
        let children = exprs[0].as_list().unwrap();
        assert_eq!(children[1].as_str(), Some("~/.clash/policy"));
    }
}
