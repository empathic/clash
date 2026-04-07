//! Document formatting via clash_starlark's canonicalizer.
//!
//! Parses the source into the codegen AST, runs `canonicalize`, and re-emits.
//! Returns `None` if parsing fails (we'd rather leave the buffer alone than
//! mangle it on a syntax error — diagnostics already cover the parse error).

use clash_starlark::codegen::{canonicalize::canonicalize, parse, serialize};

/// Canonicalize a `.star` source. Returns the new text, or `None` if it
/// can't be parsed.
pub fn format(source: &str) -> Option<String> {
    let mut stmts = parse(source).ok()?;
    canonicalize(&mut stmts).ok()?;
    Some(serialize(&stmts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_a_simple_policy() {
        let src = "policy(\"test\", {\"Bash\": allow()})\n";
        let formatted = format(src).expect("expected canonicalized output");
        // Round-tripping a canonical input should produce the same canonical text
        // (or close to it). The strong invariant: format() is idempotent.
        let twice = format(&formatted).unwrap();
        assert_eq!(formatted, twice, "format must be idempotent");
    }

    #[test]
    fn idempotent_on_minimal_input() {
        let src = "x = 1\n";
        let once = format(src).unwrap();
        let twice = format(&once).unwrap();
        assert_eq!(once, twice);
    }
}
