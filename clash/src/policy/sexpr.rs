//! S-expression parser backed by the `lexpr` crate.
//!
//! Parses s-expression source into our [`SExpr`] tree, preserving byte-offset
//! spans for error reporting. Supports `/pattern/` regex literals via
//! pre-processing.

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
    /// A `/pattern/` regex literal.
    Regex(String, Span),
    /// A parenthesized list of sub-expressions.
    List(Vec<SExpr>, Span),
}

impl SExpr {
    /// Return the span of this node.
    pub fn span(&self) -> Span {
        match self {
            SExpr::Atom(_, s) | SExpr::Str(_, s) | SExpr::Regex(_, s) | SExpr::List(_, s) => *s,
        }
    }

    /// Return the string value of an atom or quoted string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            SExpr::Atom(s, _) | SExpr::Str(s, _) => Some(s),
            _ => None,
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

/// Sentinel prefix used to encode `/pattern/` regex literals as strings before
/// passing to lexpr, then converted back to `SExpr::Regex` after parsing.
const REGEX_PREFIX: &str = "__CLASH_REGEX__";

/// Sentinel symbol used to escape standalone `.` atoms.
const DOT_PLACEHOLDER: &str = "__CLASH_DOT__";

/// Pre-process the input to handle `/pattern/` regex literals and standalone dots.
///
/// Regex literals are converted to `"__CLASH_REGEX__pattern"` strings, and
/// standalone `.` atoms are replaced with a placeholder symbol.
fn preprocess(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len + 64);
    let mut i = 0;
    let mut in_string = false;
    let mut in_comment = false;

    while i < len {
        let b = bytes[i];

        // Handle comments (skip to end of line)
        if in_comment {
            out.push(b as char);
            if b == b'\n' {
                in_comment = false;
            }
            i += 1;
            continue;
        }

        if !in_string && b == b';' {
            in_comment = true;
            out.push(b as char);
            i += 1;
            continue;
        }

        // Handle quoted strings (pass through)
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

        // Handle `/pattern/` regex literals
        if b == b'/' {
            // Check if preceded by whitespace/paren (i.e. start of a token)
            let prev_ok =
                i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b'\n' | b'\r' | b'(' | b')');
            if prev_ok {
                // Scan for closing `/`
                if let Some(end) = find_closing_slash(bytes, i + 1) {
                    let pattern = &input[i + 1..end];
                    out.push('"');
                    out.push_str(REGEX_PREFIX);
                    // Escape any quotes or backslashes in the pattern for the string
                    for ch in pattern.chars() {
                        if ch == '"' || ch == '\\' {
                            out.push('\\');
                        }
                        out.push(ch);
                    }
                    out.push('"');
                    i = end + 1;
                    continue;
                }
            }
        }

        // Handle standalone dots
        if b == b'.' {
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

/// Find the closing `/` for a regex literal, handling `\/` escapes.
fn find_closing_slash(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // skip escaped char
            continue;
        }
        if bytes[i] == b'/' {
            // Make sure this is followed by a delimiter
            let next_ok = i + 1 >= bytes.len()
                || matches!(bytes[i + 1], b' ' | b'\t' | b'\n' | b'\r' | b')' | b'(');
            if next_ok {
                return Some(i);
            }
        }
        if bytes[i] == b'\n' {
            return None; // regex can't span lines
        }
        i += 1;
    }
    None
}

/// Pre-computed index mapping line numbers to byte offsets of line starts.
struct LineIndex {
    line_starts: Vec<usize>,
}

impl LineIndex {
    fn new(input: &str) -> Self {
        let mut line_starts = vec![0];
        for (i, ch) in input.char_indices() {
            if ch == '\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    fn to_byte_offset(&self, pos: &lexpr::parse::Position) -> usize {
        let line = pos.line();
        let col = pos.column();
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
        lexpr::Value::String(s) => {
            let s_str = s.to_string();
            if let Some(pattern) = s_str.strip_prefix(REGEX_PREFIX) {
                Ok(SExpr::Regex(pattern.to_string(), span))
            } else {
                Ok(SExpr::Str(s_str, span))
            }
        }
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
    let escaped = preprocess(input);
    let idx = LineIndex::new(&escaped);
    let options = lexpr::parse::Options::new();
    let mut parser = lexpr::parse::Parser::from_str_custom(&escaped, options);
    let mut exprs = Vec::new();

    for datum_result in parser.datum_iter() {
        let datum = datum_result.map_err(|e| {
            let msg = e.to_string();
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
        assert!(matches!(&children[2], SExpr::Str(_, _)));
    }

    #[test]
    fn parse_regex_literal() {
        let exprs = parse(r#"(deny (net /.*\.evil\.com/))"#).unwrap();
        let children = exprs[0].as_list().unwrap();
        let net = children[1].as_list().unwrap();
        assert!(matches!(&net[1], SExpr::Regex(p, _) if p == r".*\.evil\.com"));
    }

    #[test]
    fn parse_regex_in_context() {
        let input = r#"(allow (fs read /.*\.rs$/))"#;
        let exprs = parse(input).unwrap();
        let children = exprs[0].as_list().unwrap();
        let fs = children[1].as_list().unwrap();
        assert!(matches!(&fs[2], SExpr::Regex(p, _) if p == r".*\.rs$"));
    }

    #[test]
    fn parse_comments() {
        let input = r#"
; This is a policy file
(default deny main)
; Another comment
(policy main
  ; inner comment
  (allow (exec "git" *)))
"#;
        let exprs = parse(input).unwrap();
        assert_eq!(exprs.len(), 2);
    }

    #[test]
    fn parse_path_atoms() {
        let exprs = parse("(subpath ~/.clash/policy)").unwrap();
        let children = exprs[0].as_list().unwrap();
        assert_eq!(children[1].as_str(), Some("~/.clash/policy"));
    }

    #[test]
    fn error_unterminated_string() {
        let err = parse(r#""unterminated"#).unwrap_err();
        assert!(!err.message.is_empty());
    }

    #[test]
    fn error_unmatched_paren() {
        let err = parse("(hello").unwrap_err();
        assert!(!err.message.is_empty());
    }
}
