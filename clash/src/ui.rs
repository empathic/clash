//! Terminal output helpers — everything that talks to stdout/stderr.
//!
//! `style` handles *how things look* (colors, boldness).
//! `display` handles *pure formatting* (decision rendering, JSON serialization).
//! `ui` handles *step reporting* (✓/✗/~/· glyphs), structural output (banners,
//! sections), and complex table rendering (sandbox matrix).

use std::collections::HashMap;

use crate::policy::sandbox_types::SandboxPolicy;
use crate::style;

// ---------------------------------------------------------------------------
// Step reporting
// ---------------------------------------------------------------------------

/// `✓` — a step completed successfully.
pub fn success(msg: &str) {
    println!("{} {}", style::green_bold("✓"), msg);
}

/// `·` — informational skip; nothing needed to be done.
pub fn skip(msg: &str) {
    println!("{} {}", style::dim("·"), msg);
}

/// `!` — completed with a caveat (written to stderr).
pub fn warn(msg: &str) {
    eprintln!("{} {}", style::err_yellow("!"), msg);
}

/// `✗` — a step failed (written to stderr).
pub fn fail(msg: &str) {
    eprintln!("{} {}", style::err_red_bold("✗"), msg);
}

/// `~` — an operation is underway.
pub fn progress(msg: &str) {
    println!("{} {}", style::cyan("~"), msg);
}

/// Plain informational text — no glyph, no styling.
pub fn info(msg: &str) {
    println!("{msg}");
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

/// Print the clash banner followed by a blank line.
pub fn banner() {
    println!("{}", style::banner());
    println!();
}

/// Print a section header and its underline divider.
///
/// The divider length matches the visible header text.
pub fn section(title: &str) {
    println!("{}", style::header(title));
    println!("{}", style::dim(&"─".repeat(title.len())));
}

/// Print the banner then a section header (common pattern in status/doctor/uninstall).
pub fn banner_section(title: &str) {
    banner();
    section(title);
    println!();
}

// ---------------------------------------------------------------------------
// Policy display
// ---------------------------------------------------------------------------

/// Print sandboxes as a compact matrix: paths down the left, sandbox names across the top.
pub fn print_sandbox_table(sandboxes: &HashMap<String, SandboxPolicy>) {
    use crate::policy::sandbox_types::{NetworkPolicy, RuleEffect};

    let mut names: Vec<&str> = sandboxes.keys().map(|s| s.as_str()).collect();
    names.sort();

    // Collect unique path labels, then sort by specificity (general first).
    let mut paths: Vec<String> = Vec::new();
    for name in &names {
        for rule in &sandboxes[*name].rules {
            let suffix = match rule.path_match {
                crate::policy::sandbox_types::PathMatch::Subpath => "/**",
                crate::policy::sandbox_types::PathMatch::Literal => "",
                crate::policy::sandbox_types::PathMatch::Regex => " (re)",
            };
            let key = format!("{}{}", rule.path, suffix);
            if !paths.contains(&key) {
                paths.push(key);
            }
        }
    }
    paths.sort_by_key(|p| {
        let stripped = p.strip_suffix("/**").unwrap_or(p);
        stripped.matches('/').count() + stripped.matches('$').count()
    });

    // Collect unique network domains across sandboxes.
    let mut domains: Vec<String> = Vec::new();
    for name in &names {
        if let NetworkPolicy::AllowDomains(ds) = &sandboxes[*name].network {
            for d in ds {
                if !domains.contains(d) {
                    domains.push(d.clone());
                }
            }
        }
    }

    let col_w = names.iter().map(|n| n.len()).max().unwrap_or(5).max(5);
    let domain_max = domains.iter().map(|d| d.len()).max().unwrap_or(0);
    let path_w = paths
        .iter()
        .map(|p| p.len())
        .max()
        .unwrap_or(7)
        .max(domain_max)
        .max(7);

    // Header row.
    let hdr: Vec<String> = names.iter().map(|n| lpad(&style::cyan(n), col_w)).collect();
    println!("  {} {}", rpad("", path_w), hdr.join(" "));

    // Default row.
    let def: Vec<String> = names
        .iter()
        .map(|n| lpad(&style::dim(&sandboxes[*n].default.short()), col_w))
        .collect();
    println!(
        "  {} {}",
        rpad(&style::dim("default"), path_w),
        def.join(" ")
    );

    // Network row.
    let net: Vec<String> = names
        .iter()
        .map(|n| {
            let s = match &sandboxes[*n].network {
                NetworkPolicy::Deny => style::red("deny"),
                NetworkPolicy::Allow => style::green("allow"),
                NetworkPolicy::Localhost => style::yellow("localhost"),
                NetworkPolicy::AllowDomains(_) => style::yellow("proxy"),
            };
            lpad(&s, col_w)
        })
        .collect();
    println!("  {} {}", rpad(&style::dim("net"), path_w), net.join(" "));

    // Domain rows.
    for domain in &domains {
        let cells: Vec<String> = names
            .iter()
            .map(|n| {
                let cell = match &sandboxes[*n].network {
                    NetworkPolicy::Allow => style::green("allow"),
                    NetworkPolicy::AllowDomains(ds) if ds.iter().any(|d| d == domain) => {
                        style::green("allow")
                    }
                    _ => style::dim("·····"),
                };
                lpad(&cell, col_w)
            })
            .collect();
        println!(
            "  {} {}",
            rpad(&style::dim(domain), path_w),
            cells.join(" ")
        );
    }

    // Path rows.
    for path in &paths {
        let cells: Vec<String> = names
            .iter()
            .map(|n| {
                let matched = sandboxes[*n].rules.iter().find(|r| {
                    let suffix = match r.path_match {
                        crate::policy::sandbox_types::PathMatch::Subpath => "/**",
                        crate::policy::sandbox_types::PathMatch::Literal => "",
                        crate::policy::sandbox_types::PathMatch::Regex => " (re)",
                    };
                    format!("{}{}", r.path, suffix) == *path
                });
                let cell = match matched {
                    Some(r) => {
                        let s = r.caps.short();
                        match r.effect {
                            RuleEffect::Allow => style::green(&s),
                            RuleEffect::Deny => style::red(&s),
                        }
                    }
                    None => style::dim("·····"),
                };
                lpad(&cell, col_w)
            })
            .collect();
        println!("  {} {}", rpad(&style::dim(path), path_w), cells.join(" "));
    }
}

// ---------------------------------------------------------------------------
// Alignment helpers (used by print_sandbox_table)
// ---------------------------------------------------------------------------

fn rpad(s: &str, width: usize) -> String {
    console::pad_str(s, width, console::Alignment::Left, None).into_owned()
}

fn lpad(s: &str, width: usize) -> String {
    console::pad_str(s, width, console::Alignment::Right, None).into_owned()
}
