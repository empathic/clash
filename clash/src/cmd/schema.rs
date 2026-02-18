use anyhow::Result;

use crate::style;

/// Handle `clash policy schema`.
pub fn run(json: bool) -> Result<()> {
    let schema = crate::schema::policy_schema();

    if json {
        println!("{}", serde_json::to_string_pretty(&schema)?);
    } else {
        println!("{}", style::header("Policy Schema"));
        println!("{}\n", style::dim("─────────────"));

        for section in &schema.sections {
            println!("{}:", style::bold(section.key));
            println!("  {}\n", section.description);
            print_fields(&section.fields, 2);
            println!();
        }

        println!("{}", style::bold("Rule Syntax:"));
        println!(
            "  {}: {}\n",
            style::cyan("Format"),
            schema.rule_syntax.format
        );
        println!(
            "  {}: {}",
            style::cyan("Effects"),
            schema.rule_syntax.effects.join(", ")
        );
        println!(
            "  {}: {}",
            style::cyan("Fs ops"),
            schema.rule_syntax.fs_operations.join(", ")
        );
        println!("\n  {}:", style::bold("Capability domains"));
        print_fields(&schema.rule_syntax.domains, 4);
        println!("\n  {}:", style::bold("Patterns"));
        print_fields(&schema.rule_syntax.patterns, 4);
        println!("\n  {}:", style::bold("Path filters"));
        print_fields(&schema.rule_syntax.path_filters, 4);
    }
    Ok(())
}

fn print_fields(fields: &[crate::schema::SchemaField], indent: usize) {
    let pad = " ".repeat(indent);
    for f in fields {
        let req = if f.required {
            format!(" {}", style::yellow("(required)"))
        } else {
            String::new()
        };
        let default_str = match &f.default {
            Some(v) => format!(" {}", style::dim(&format!("[default: {}]", v))),
            None => String::new(),
        };
        let values_str = match &f.values {
            Some(vals) => format!(" {}", style::dim(&format!("({})", vals.join("|")))),
            None => String::new(),
        };
        println!(
            "{}{}: {}{}{}{} {} {}",
            pad,
            style::cyan(f.key),
            style::magenta(f.type_name),
            values_str,
            default_str,
            req,
            style::dim("—"),
            f.description
        );
        if let Some(ref sub) = f.fields {
            print_fields(sub, indent + 2);
        }
    }
}
