//! Hand-written tokenizer and generic s-expression tree parser.
//!
//! Tokens: `(`, `)`, `;` comments (to EOL), `"quoted strings"`, unquoted atoms.
//! Atoms may contain: alphanumeric, `*`, `.`, `-`, `_`, `/`, `~`, `!`, `+`, `?`, `@`, `:`.

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

/// Compute (line, col) from a byte offset. Both are 1-based.
fn offset_to_line_col(input: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;
    for (i, ch) in input.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

fn make_error(input: &str, offset: usize, message: impl Into<String>) -> ParseError {
    let (line, col) = offset_to_line_col(input, offset);
    ParseError {
        message: message.into(),
        offset,
        line,
        col,
    }
}

/// Characters allowed in unquoted atoms.
fn is_atom_char(ch: char) -> bool {
    ch.is_alphanumeric()
        || matches!(
            ch,
            '*' | '.' | '-' | '_' | '/' | '~' | '!' | '+' | '?' | '@' | ':' | '#' | '$'
        )
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    LParen(usize),
    RParen(usize),
    Atom(String, Span),
    Str(String, Span),
}

fn tokenize(input: &str) -> Result<Vec<Token>, ParseError> {
    let mut tokens = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let ch = bytes[i] as char;

        // Skip whitespace.
        if ch.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Skip comments (`;` to end of line).
        if ch == ';' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Parentheses.
        if ch == '(' {
            tokens.push(Token::LParen(i));
            i += 1;
            continue;
        }
        if ch == ')' {
            tokens.push(Token::RParen(i));
            i += 1;
            continue;
        }

        // Quoted string.
        if ch == '"' {
            let start = i;
            i += 1; // skip opening quote
            let mut value = String::new();
            loop {
                if i >= bytes.len() {
                    return Err(make_error(input, start, "unterminated string literal"));
                }
                let c = bytes[i] as char;
                if c == '\\' && i + 1 < bytes.len() {
                    // Escape sequence.
                    let next = bytes[i + 1] as char;
                    match next {
                        '"' | '\\' => {
                            value.push(next);
                            i += 2;
                        }
                        'n' => {
                            value.push('\n');
                            i += 2;
                        }
                        't' => {
                            value.push('\t');
                            i += 2;
                        }
                        _ => {
                            value.push('\\');
                            value.push(next);
                            i += 2;
                        }
                    }
                    continue;
                }
                if c == '"' {
                    i += 1; // skip closing quote
                    break;
                }
                value.push(c);
                i += 1;
            }
            tokens.push(Token::Str(value, Span { start, end: i }));
            continue;
        }

        // Atom.
        if is_atom_char(ch) {
            let start = i;
            while i < bytes.len() && is_atom_char(bytes[i] as char) {
                i += 1;
            }
            let value = input[start..i].to_string();
            tokens.push(Token::Atom(value, Span { start, end: i }));
            continue;
        }

        return Err(make_error(
            input,
            i,
            format!("unexpected character '{}'", ch),
        ));
    }

    Ok(tokens)
}

// ---------------------------------------------------------------------------
// Tree parser
// ---------------------------------------------------------------------------

struct TreeParser {
    tokens: Vec<Token>,
    pos: usize,
}

impl TreeParser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn parse_expr(&mut self, input: &str) -> Result<SExpr, ParseError> {
        if self.at_end() {
            let offset = input.len();
            return Err(make_error(input, offset, "unexpected end of input"));
        }

        match &self.tokens[self.pos] {
            Token::LParen(start) => {
                let start = *start;
                self.pos += 1; // consume '('
                let mut children = Vec::new();
                loop {
                    if self.at_end() {
                        return Err(make_error(
                            input,
                            start,
                            "unclosed parenthesis (no matching ')')",
                        ));
                    }
                    if matches!(&self.tokens[self.pos], Token::RParen(_)) {
                        let end_offset = match &self.tokens[self.pos] {
                            Token::RParen(o) => *o + 1,
                            _ => unreachable!(),
                        };
                        self.pos += 1; // consume ')'
                        return Ok(SExpr::List(
                            children,
                            Span {
                                start,
                                end: end_offset,
                            },
                        ));
                    }
                    children.push(self.parse_expr(input)?);
                }
            }
            Token::RParen(offset) => Err(make_error(
                input,
                *offset,
                "unexpected ')' without matching '('",
            )),
            Token::Atom(value, span) => {
                let expr = SExpr::Atom(value.clone(), *span);
                self.pos += 1;
                Ok(expr)
            }
            Token::Str(value, span) => {
                let expr = SExpr::Str(value.clone(), *span);
                self.pos += 1;
                Ok(expr)
            }
        }
    }
}

/// Parse an s-expression source string into a list of top-level expressions.
pub fn parse(input: &str) -> Result<Vec<SExpr>, ParseError> {
    let tokens = tokenize(input)?;
    let mut parser = TreeParser::new(tokens);
    let mut exprs = Vec::new();

    while !parser.at_end() {
        exprs.push(parser.parse_expr(input)?);
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
(default deny main)
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
        assert!(err.message.contains("unterminated"));
        assert_eq!(err.line, 1);
    }

    #[test]
    fn error_unmatched_paren() {
        let err = parse("(hello").unwrap_err();
        assert!(err.message.contains("unclosed parenthesis"));
    }

    #[test]
    fn error_extra_rparen() {
        let err = parse(")").unwrap_err();
        assert!(err.message.contains("unexpected ')'"));
    }

    #[test]
    fn parse_complex_policy() {
        let input = r#"
(default deny main)

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
