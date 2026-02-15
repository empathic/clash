//! Interactive policy configuration wizard.
//!
//! Not yet implemented. The `clash policy setup` command currently prints
//! guidance directing users to `clash allow` and `clash deny` commands.

use anyhow::Result;

/// Print setup guidance. Full interactive wizard is not yet implemented.
pub fn run() -> Result<()> {
    println!("Policy setup");
    println!("============\n");
    println!("Quick start — unlock capabilities as you need them:\n");
    println!("  clash allow edit     Allow Claude to edit files in this project");
    println!("  clash allow bash     Allow Claude to run commands");
    println!("  clash allow web      Allow Claude to search the web and fetch URLs");
    println!("  clash allow read     Allow Claude to read files in this project");
    println!();
    println!("Fine-grained rules (s-expression syntax):\n");
    println!("  clash allow '(exec \"git\" *)'           Allow all git commands");
    println!("  clash deny  '(exec \"git\" \"push\" *)'    Block git push");
    println!("  clash allow '(net \"github.com\")'       Allow github.com access");
    println!();
    println!("Manage rules:\n");
    println!("  clash policy list    Show all rules in the active policy");
    println!("  clash policy show    Show policy summary and decision tree");
    println!();
    println!(
        "Policy file: {}",
        crate::settings::ClashSettings::policy_file()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "~/.clash/policy.sexpr".into())
    );
    println!("Grammar:     docs/policy-grammar.md");
    Ok(())
}
