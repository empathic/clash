//! Boolean expression tokenizer and recursive-descent parsers.
//!
//! Shared infrastructure for parsing filter expressions (`subpath(.) & !literal(.env)`)
//! and profile expressions (`sandboxed & safe-io`).

use tracing::{Level, instrument};

use super::error::PolicyParseError;
use super::{FilterExpr, ProfileExpr};

// ---------------------------------------------------------------------------
// Shared tokenizer for boolean expressions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ExprToken {
    And,           // &
    Or,            // |
    Not,           // !
    LParen,        // (
    RParen,        // )
    Ident(String), // identifier or function call like subpath(./src)
}

/// Tokenize an expression string into tokens.
/// Handles function-call syntax like `subpath(./src)` as a single Ident token.
pub(crate) fn tokenize_expr(input: &str) -> Result<Vec<ExprToken>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' => i += 1,
            '&' => {
                tokens.push(ExprToken::And);
                i += 1;
            }
            '|' => {
                tokens.push(ExprToken::Or);
                i += 1;
            }
            '!' => {
                tokens.push(ExprToken::Not);
                i += 1;
            }
            '(' => {
                tokens.push(ExprToken::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(ExprToken::RParen);
                i += 1;
            }
            _ => {
                // Read an identifier, possibly including a function call like subpath(./src)
                let start = i;
                // Read the identifier part
                while i < chars.len()
                    && !matches!(chars[i], ' ' | '\t' | '&' | '|' | '!' | '(' | ')')
                {
                    i += 1;
                }
                let word = &input[start..i];

                // Check if this is a function call (next non-space char is '(')
                let mut peek = i;
                while peek < chars.len() && (chars[peek] == ' ' || chars[peek] == '\t') {
                    peek += 1;
                }
                if peek < chars.len()
                    && chars[peek] == '('
                    && matches!(word, "subpath" | "literal" | "regex")
                {
                    // Consume the '(' and everything up to the matching ')'
                    i = peek + 1; // skip '('
                    let arg_start = i;
                    let mut depth = 1;
                    while i < chars.len() && depth > 0 {
                        match chars[i] {
                            '(' => depth += 1,
                            ')' => depth -= 1,
                            _ => {}
                        }
                        if depth > 0 {
                            i += 1;
                        }
                    }
                    if depth != 0 {
                        return Err(format!("unclosed parenthesis in {}()", word));
                    }
                    let arg = input[arg_start..i].trim();
                    i += 1; // skip closing ')'
                    tokens.push(ExprToken::Ident(format!("{}({})", word, arg)));
                } else {
                    tokens.push(ExprToken::Ident(word.to_string()));
                }
            }
        }
    }
    Ok(tokens)
}

// ---------------------------------------------------------------------------
// Filter expression recursive descent
// ---------------------------------------------------------------------------

/// Parse a filter expression string like `subpath(.) & !literal(.env)`.
///
/// Grammar (precedence: `!` > `&` > `|`):
///   expr     = or_expr
///   or_expr  = and_expr ( '|' and_expr )*
///   and_expr = unary ( '&' unary )*
///   unary    = '!' unary | atom
///   atom     = 'subpath(' path ')' | 'literal(' path ')' | 'regex(' pattern ')' | '(' expr ')'
#[instrument(level = Level::TRACE)]
pub fn parse_filter_expr(input: &str) -> Result<FilterExpr, PolicyParseError> {
    let input = input.trim();
    let tokens = tokenize_expr(input).map_err(PolicyParseError::InvalidFilter)?;
    let mut pos = 0;
    let result = parse_filter_or(&tokens, &mut pos)?;
    if pos != tokens.len() {
        return Err(PolicyParseError::InvalidFilter(format!(
            "unexpected token at position {}: {:?}",
            pos,
            tokens.get(pos)
        )));
    }
    Ok(result)
}

/// Parse a profile expression string like `sandboxed & safe-io`.
///
/// Grammar (precedence: `!` > `&` > `|`):
///   expr     = or_expr
///   or_expr  = and_expr ( '|' and_expr )*
///   and_expr = unary ( '&' unary )*
///   unary    = '!' unary | atom
///   atom     = identifier | '(' expr ')'
#[instrument(level = Level::TRACE)]
pub fn parse_profile_expr(input: &str) -> Result<ProfileExpr, PolicyParseError> {
    let input = input.trim();
    let tokens = tokenize_expr(input).map_err(PolicyParseError::InvalidProfile)?;
    let mut pos = 0;
    let result = parse_profile_or(&tokens, &mut pos)?;
    if pos != tokens.len() {
        return Err(PolicyParseError::InvalidProfile(format!(
            "unexpected token at position {}: {:?}",
            pos,
            tokens.get(pos)
        )));
    }
    Ok(result)
}

// -- Filter expression recursive descent --

fn parse_filter_or(tokens: &[ExprToken], pos: &mut usize) -> Result<FilterExpr, PolicyParseError> {
    let mut left = parse_filter_and(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == ExprToken::Or {
        *pos += 1;
        let right = parse_filter_and(tokens, pos)?;
        left = FilterExpr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_filter_and(tokens: &[ExprToken], pos: &mut usize) -> Result<FilterExpr, PolicyParseError> {
    let mut left = parse_filter_unary(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == ExprToken::And {
        *pos += 1;
        let right = parse_filter_unary(tokens, pos)?;
        left = FilterExpr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_filter_unary(
    tokens: &[ExprToken],
    pos: &mut usize,
) -> Result<FilterExpr, PolicyParseError> {
    if *pos < tokens.len() && tokens[*pos] == ExprToken::Not {
        *pos += 1;
        let inner = parse_filter_unary(tokens, pos)?;
        return Ok(FilterExpr::Not(Box::new(inner)));
    }
    parse_filter_atom(tokens, pos)
}

fn parse_filter_atom(
    tokens: &[ExprToken],
    pos: &mut usize,
) -> Result<FilterExpr, PolicyParseError> {
    if *pos >= tokens.len() {
        return Err(PolicyParseError::InvalidFilter(
            "unexpected end of expression".into(),
        ));
    }
    match &tokens[*pos] {
        ExprToken::LParen => {
            *pos += 1;
            let expr = parse_filter_or(tokens, pos)?;
            if *pos >= tokens.len() || tokens[*pos] != ExprToken::RParen {
                return Err(PolicyParseError::InvalidFilter(
                    "expected closing ')'".into(),
                ));
            }
            *pos += 1;
            Ok(expr)
        }
        ExprToken::Ident(s) => {
            let expr = parse_filter_function(s)?;
            *pos += 1;
            Ok(expr)
        }
        other => Err(PolicyParseError::InvalidFilter(format!(
            "unexpected token: {:?}",
            other
        ))),
    }
}

/// Parse a filter function call like `subpath(./src)`, `literal(.env)`, `regex(.*\.rs$)`,
/// or the wildcard `*` (equivalent to `subpath(/)`).
fn parse_filter_function(s: &str) -> Result<FilterExpr, PolicyParseError> {
    if s == "*" {
        Ok(FilterExpr::Subpath("/".to_string()))
    } else if let Some(arg) = s.strip_prefix("subpath(").and_then(|s| s.strip_suffix(')')) {
        Ok(FilterExpr::Subpath(arg.to_string()))
    } else if let Some(arg) = s.strip_prefix("literal(").and_then(|s| s.strip_suffix(')')) {
        Ok(FilterExpr::Literal(arg.to_string()))
    } else if let Some(arg) = s.strip_prefix("regex(").and_then(|s| s.strip_suffix(')')) {
        Ok(FilterExpr::Regex(arg.to_string()))
    } else {
        Err(PolicyParseError::InvalidFilter(format!(
            "expected *, subpath(), literal(), or regex(), got '{}'",
            s
        )))
    }
}

// -- Profile expression recursive descent --

fn parse_profile_or(
    tokens: &[ExprToken],
    pos: &mut usize,
) -> Result<ProfileExpr, PolicyParseError> {
    let mut left = parse_profile_and(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == ExprToken::Or {
        *pos += 1;
        let right = parse_profile_and(tokens, pos)?;
        left = ProfileExpr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_profile_and(
    tokens: &[ExprToken],
    pos: &mut usize,
) -> Result<ProfileExpr, PolicyParseError> {
    let mut left = parse_profile_unary(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == ExprToken::And {
        *pos += 1;
        let right = parse_profile_unary(tokens, pos)?;
        left = ProfileExpr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_profile_unary(
    tokens: &[ExprToken],
    pos: &mut usize,
) -> Result<ProfileExpr, PolicyParseError> {
    if *pos < tokens.len() && tokens[*pos] == ExprToken::Not {
        *pos += 1;
        let inner = parse_profile_unary(tokens, pos)?;
        return Ok(ProfileExpr::Not(Box::new(inner)));
    }
    parse_profile_atom(tokens, pos)
}

fn parse_profile_atom(
    tokens: &[ExprToken],
    pos: &mut usize,
) -> Result<ProfileExpr, PolicyParseError> {
    if *pos >= tokens.len() {
        return Err(PolicyParseError::InvalidProfile(
            "unexpected end of expression".into(),
        ));
    }
    match &tokens[*pos] {
        ExprToken::LParen => {
            *pos += 1;
            let expr = parse_profile_or(tokens, pos)?;
            if *pos >= tokens.len() || tokens[*pos] != ExprToken::RParen {
                return Err(PolicyParseError::InvalidProfile(
                    "expected closing ')'".into(),
                ));
            }
            *pos += 1;
            Ok(expr)
        }
        ExprToken::Ident(s) => {
            let expr = ProfileExpr::Ref(s.to_string());
            *pos += 1;
            Ok(expr)
        }
        other => Err(PolicyParseError::InvalidProfile(format!(
            "unexpected token: {:?}",
            other
        ))),
    }
}
