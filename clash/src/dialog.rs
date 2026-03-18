//! Interactive prompt helpers wrapping [`dialoguer`].
//!
//! Centralises the confirm/select patterns used by `clash init`, `clash uninstall`,
//! and `clash update` so each callsite gets consistent error messages and
//! non-interactive fallback behaviour.

use anyhow::{Context, Result};

use crate::claude::tools::ToolDef;
use crate::style;

/// Trait for enum types that can be presented in a [`select`] menu.
pub trait SelectItem: Sized {
    fn label(&self) -> &str;
    fn description(&self) -> &str;
    fn variants() -> &'static [Self];
}

/// Declare an enum that implements [`SelectItem`] for use with [`select`].
///
/// ```ignore
/// select_enum! {
///     Scope {
///         User    => ("User",    "global default policy"),
///         Project => ("Project", "policy scoped to this repo"),
///     }
/// }
/// let scope = dialog::select::<Scope>("Pick a scope")?;
/// ```
#[macro_export]
macro_rules! select_enum {
    ($vis:vis $name:ident { $( $variant:ident => ($label:expr, $desc:expr) ),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug)]
        $vis enum $name { $( $variant ),+ }

        #[allow(unused_imports)]
        use $crate::dialog::SelectItem as _;

        impl $crate::dialog::SelectItem for $name {
            fn label(&self) -> &str {
                match self { $( Self::$variant => $label ),+ }
            }
            fn description(&self) -> &str {
                match self { $( Self::$variant => $desc ),+ }
            }
            fn variants() -> &'static [Self] {
                &[ $( Self::$variant ),+ ]
            }
        }
    };
}

/// Free-text input prompt. Returns the trimmed string the user typed.
pub fn input(prompt: &str) -> Result<String> {
    dialoguer::Input::new()
        .with_prompt(prompt)
        .interact_text()
        .context("failed to read input (hint: pass the value as an argument for non-interactive mode)")
}

/// Yes/no confirmation prompt.
///
/// If `yes_flag` is `true` the prompt is skipped and `true` is returned,
/// enabling non-interactive (`--yes`) mode. On interaction failure (e.g. no
/// TTY) returns `false` so the caller can treat it as a cancellation.
pub fn confirm(prompt: &str, yes_flag: bool) -> Result<bool> {
    if yes_flag {
        return Ok(true);
    }
    dialoguer::Confirm::new()
        .with_prompt(prompt)
        .default(true)
        .interact()
        .context("failed to read confirmation (hint: pass --yes for non-interactive mode)")
}

/// Single-choice selection menu for [`SelectItem`] enums.
///
/// Renders each variant as `bold(label)  — dim(description)` and returns
/// a static reference to the selected variant.
pub fn select<T: SelectItem>(prompt: &str) -> Result<&'static T> {
    let variants = T::variants();
    let formatted: Vec<String> = variants
        .iter()
        .map(|v| {
            format!(
                "{}  {}",
                style::bold(v.label()),
                style::dim(&format!("— {}", v.description()))
            )
        })
        .collect();

    dialoguer::Select::new()
        .with_prompt(prompt)
        .items(&formatted)
        .default(0)
        .interact()
        .map(|idx| &variants[idx])
        .context(
            "failed to read selection (hint: pass the value as an argument for non-interactive mode)",
        )
}

/// Prompt the user for each required parameter of a tool.
///
/// Walks the tool's param schema, prompts for every required field, parses
/// the input according to `schema_type`, and returns a JSON object ready
/// for policy evaluation or `ToolInput::parse`.
///
/// Params whose names appear in `skip` are silently excluded from the form.
pub fn form_with_skip(tool: &ToolDef, skip: &[&str]) -> Result<serde_json::Value> {
    let mut map = serde_json::Map::new();
    for param in tool.params.iter().filter(|p| p.required && !skip.contains(&p.name)) {
        let prompt = format!(
            "{}  {}",
            style::bold(param.name),
            style::dim(&format!("— {}", param.description))
        );
        let raw = input(&prompt)?;
        let value = match param.schema_type {
            "number" => {
                let n: serde_json::Number = raw
                    .parse()
                    .with_context(|| format!("{}: expected a number", param.name))?;
                serde_json::Value::Number(n)
            }
            "boolean" => {
                let b: bool = raw
                    .parse()
                    .with_context(|| format!("{}: expected true or false", param.name))?;
                serde_json::Value::Bool(b)
            }
            _ => serde_json::Value::String(raw),
        };
        map.insert(param.name.to_string(), value);
    }
    Ok(serde_json::Value::Object(map))
}

/// Prompt the user for each required parameter of a tool (no skips).
///
/// Convenience wrapper around [`form_with_skip`] with an empty skip list.
pub fn form(tool: &ToolDef) -> Result<serde_json::Value> {
    form_with_skip(tool, &[])
}

/// Prompt only for the named parameters (ignoring `required` flag).
///
/// Useful when only a subset of fields are meaningful for the caller's context.
pub fn form_only(tool: &ToolDef, only: &[&str]) -> Result<serde_json::Value> {
    let mut map = serde_json::Map::new();
    for param in tool.params.iter().filter(|p| only.contains(&p.name)) {
        let prompt = format!(
            "{}  {}",
            style::bold(param.name),
            style::dim(&format!("— {}", param.description))
        );
        let raw = input(&prompt)?;
        if raw.is_empty() {
            continue;
        }
        let value = match param.schema_type {
            "number" => {
                let n: serde_json::Number = raw
                    .parse()
                    .with_context(|| format!("{}: expected a number", param.name))?;
                serde_json::Value::Number(n)
            }
            "boolean" => {
                let b: bool = raw
                    .parse()
                    .with_context(|| format!("{}: expected true or false", param.name))?;
                serde_json::Value::Bool(b)
            }
            _ => serde_json::Value::String(raw),
        };
        map.insert(param.name.to_string(), value);
    }
    Ok(serde_json::Value::Object(map))
}

#[cfg(test)]
mod tests {
    use super::*;

    select_enum! {
        Color {
            Red   => ("red",   "a warm color"),
            Green => ("green", "a cool color"),
            Blue  => ("blue",  "a calm color"),
        }
    }

    #[test]
    fn select_enum_labels() {
        assert_eq!(Color::Red.label(), "red");
        assert_eq!(Color::Green.label(), "green");
        assert_eq!(Color::Blue.label(), "blue");
    }

    #[test]
    fn select_enum_descriptions() {
        assert_eq!(Color::Red.description(), "a warm color");
        assert_eq!(Color::Green.description(), "a cool color");
        assert_eq!(Color::Blue.description(), "a calm color");
    }

    #[test]
    fn select_enum_variants_returns_all_in_order() {
        let variants = Color::variants();
        assert_eq!(variants.len(), 3);
        assert!(matches!(variants[0], Color::Red));
        assert!(matches!(variants[1], Color::Green));
        assert!(matches!(variants[2], Color::Blue));
    }

    #[test]
    fn select_enum_is_copy() {
        let c = Color::Red;
        let c2 = c; // Copy
        assert_eq!(c.label(), c2.label());
    }

    #[test]
    fn select_enum_is_debug() {
        let s = format!("{:?}", Color::Green);
        assert_eq!(s, "Green");
    }

    #[test]
    fn confirm_skips_prompt_when_yes_flag_set() {
        assert!(confirm("unused", true).unwrap());
    }
}
