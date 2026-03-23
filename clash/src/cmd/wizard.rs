//! Interactive policy builder wizard.
//!
//! Walks the user through creating a policy by example: pick a tool, fill in
//! args, choose a generalization level, assign an effect. Accumulates rules
//! and emits a compiled `policy.json`.

use anyhow::{Context, Result};
use serde_json::json;

use crate::claude::tools;
use crate::dialog::{self, SelectItem, form_only, select};
use crate::policy::compile;
use crate::settings::{self, ClashSettings, SandboxPreset};
use crate::style;
use crate::{select_enum, ui};

// ---------------------------------------------------------------------------
// Select enums
// ---------------------------------------------------------------------------

select_enum! {
    Start {
        Guided => ("guided", "Follow the interactive policy builder"),
        Manual => ("manual", "Create a blank policy to edit yourself"),
    }
}

select_enum! {
    pub DefaultEffect {
        Ask   => ("ask",   "Prompt the user for each unknown action (recommended)"),
        Deny  => ("deny",  "Block anything not explicitly allowed (strict)"),
        Allow => ("allow", "Allow anything not explicitly denied (permissive)"),
    }
}

select_enum! {
    Effect {
        Allow => ("allow", "Let this action run"),
        Deny  => ("deny",  "Block this action"),
        Ask   => ("ask",   "Prompt the user each time"),
    }
}

select_enum! {
    Tools {
        Bash      => ("Bash",      "Run shell commands"),
        Read      => ("Read",      "Read a file from disk"),
        Write     => ("Write",     "Write a file to disk"),
        Edit      => ("Edit",      "Edit a file in place"),
        Glob      => ("Glob",      "Find files by pattern"),
        Grep      => ("Grep",      "Search file contents"),
        WebFetch  => ("WebFetch",  "Fetch a URL"),
        WebSearch => ("WebSearch", "Search the web"),
        Agent     => ("Agent",     "Spawn a sub-agent"),
    }
}

// ---------------------------------------------------------------------------
// Specificity levels — static data per tool category
// ---------------------------------------------------------------------------

/// A generalization level the user can choose for a rule.
struct SpecLevel {
    /// Human label for the select menu.
    label: String,
    /// What this level matches (shown as description).
    description: String,
    /// Concrete examples of commands that would match.
    examples: Vec<String>,
    /// What this level does NOT catch.
    caveat: String,
    /// The match tree nodes this level generates (tool_name condition is added by the caller).
    nodes: Vec<serde_json::Value>,
}

/// Generate specificity levels for a Bash command.
///
/// Given args like `["git", "push", "origin", "main"]`, produces levels from
/// most specific (exact command) to least specific (any bash command).
fn bash_specificity(args: &[String]) -> Vec<SpecLevel> {
    let mut levels = Vec::new();

    if args.len() == 1 {
        let bin = &args[0];

        // Level: exactly this binary with no arguments
        levels.push(SpecLevel {
            label: format!("Exactly: {}", bin),
            description: format!("Only matches `{}` with no arguments", bin),
            examples: vec![bin.to_string()],
            caveat: format!("Won't match `{} --help` or `{} foo`", bin, bin),
            nodes: vec![condition_terminal(
                json!({"positional_arg": 0}),
                literal(bin),
                vec![],
                true,
            )],
        });

        // Level: any invocation of this binary
        levels.push(SpecLevel {
            label: format!("Any `{}` command", bin),
            description: format!("Matches any invocation of `{}`", bin),
            examples: vec![
                format!("{}", bin),
                format!("{} --help", bin),
                format!("{} foo bar", bin),
            ],
            caveat: "Won't match other binaries".into(),
            nodes: vec![condition(
                json!({"positional_arg": 0}),
                literal(bin),
                vec![],
            )],
        });
    } else if args.len() >= 2 {
        let bin = &args[0];
        let all_args: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();
        let full_cmd = args.join(" ");

        // Level: exact command (all args, deepest is terminal)
        let exact_nodes = build_arg_chain_terminal(&all_args, 1);

        levels.push(SpecLevel {
            label: format!("Exactly: {}", full_cmd),
            description: format!("Only matches `{}`", full_cmd),
            examples: vec![full_cmd.clone()],
            caveat: "Won't match the same command with different or extra arguments".into(),
            nodes: vec![condition_terminal(
                json!({"positional_arg": 0}),
                literal(bin),
                exact_nodes,
                all_args.is_empty(),
            )],
        });

        // Level: binary + first arg (subcommand)
        let first_arg = &all_args[0];
        levels.push(SpecLevel {
            label: format!("Any `{} {}` command", bin, first_arg),
            description: format!(
                "Matches `{} {}` with any additional arguments",
                bin, first_arg
            ),
            examples: vec![
                format!("{} {}", bin, first_arg),
                format!("{} {} --flag", bin, first_arg),
                format!("{} {} foo bar", bin, first_arg),
            ],
            caveat: format!("Won't match `{}` with a different subcommand", bin),
            nodes: vec![condition(
                json!({"positional_arg": 0}),
                literal(bin),
                vec![condition(
                    json!({"positional_arg": 1}),
                    literal(first_arg),
                    vec![],
                )],
            )],
        });

        // Level: any command with this binary
        levels.push(SpecLevel {
            label: format!("Any `{}` command", bin),
            description: format!("Matches any invocation of `{}`", bin),
            examples: vec![
                format!("{} --help", bin),
                format!("{} status", bin),
                full_cmd.clone(),
            ],
            caveat: "Won't match other binaries".into(),
            nodes: vec![condition(
                json!({"positional_arg": 0}),
                literal(bin),
                vec![],
            )],
        });
    }

    // Level: any bash command
    levels.push(SpecLevel {
        label: "Any Bash command".into(),
        description: "Matches every shell command".into(),
        examples: vec!["git push".into(), "npm install".into(), "rm -rf /".into()],
        caveat: "This is very broad — consider restricting by binary".into(),
        nodes: vec![], // no inner conditions, just tool_name + decision
    });

    levels
}

/// Generate specificity levels for filesystem tools (Read, Write, Edit).
fn fs_specificity(tool_name: &str, path: &str) -> Vec<SpecLevel> {
    let mut levels = Vec::new();

    // Level: exact path
    levels.push(SpecLevel {
        label: format!("Exactly: {}", path),
        description: format!("Only matches {} on `{}`", tool_name, path),
        examples: vec![format!("{} {}", tool_name, path)],
        caveat: "Won't match any other file path".into(),
        nodes: vec![condition(json!("fs_path"), literal(path), vec![])],
    });

    // Level: directory prefix (if path has a parent)
    if let Some(parent) = std::path::Path::new(path).parent() {
        let parent_str = parent.to_string_lossy();
        if !parent_str.is_empty() && parent_str != "/" {
            levels.push(SpecLevel {
                label: format!("Anything under: {}/", parent_str),
                description: format!("Matches {} on any file in `{}/`", tool_name, parent_str),
                examples: vec![
                    format!("{} {}/foo.rs", tool_name, parent_str),
                    format!("{} {}/sub/bar.rs", tool_name, parent_str),
                ],
                caveat: format!("Won't match files outside `{}/`", parent_str),
                nodes: vec![condition(
                    json!("fs_path"),
                    json!({"prefix": {"literal": parent_str}}),
                    vec![],
                )],
            });
        }
    }

    // Level: any invocation of this tool
    levels.push(SpecLevel {
        label: format!("Any {} operation", tool_name),
        description: format!("Matches every {} invocation", tool_name),
        examples: vec![
            format!("{} /any/file", tool_name),
            format!("{} ./relative/path", tool_name),
        ],
        caveat: "This is very broad — the sandbox will still restrict paths".into(),
        nodes: vec![],
    });

    levels
}

/// Generate specificity levels for network tools (WebFetch).
fn net_specificity(tool_name: &str, url: &str) -> Vec<SpecLevel> {
    let mut levels = Vec::new();

    // Extract domain from URL
    let domain = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url);

    // Level: exact URL
    levels.push(SpecLevel {
        label: format!("Exactly: {}", url),
        description: format!("Only matches requests to `{}`", url),
        examples: vec![url.to_string()],
        caveat: "Won't match different URLs on the same domain".into(),
        nodes: vec![condition(json!("net_domain"), literal(domain), vec![])],
    });

    // Level: any URL on this domain
    if domain != url {
        levels.push(SpecLevel {
            label: format!("Any request to {}", domain),
            description: format!("Matches any URL on `{}`", domain),
            examples: vec![
                format!("https://{}/api/v1", domain),
                format!("https://{}/other/path", domain),
            ],
            caveat: "Won't match other domains".into(),
            nodes: vec![condition(json!("net_domain"), literal(domain), vec![])],
        });
    }

    // Level: any network request
    levels.push(SpecLevel {
        label: format!("Any {} request", tool_name),
        description: "Matches any network request".into(),
        examples: vec![
            "https://example.com".into(),
            "https://api.github.com".into(),
        ],
        caveat: "Very broad — allows all network access for this tool".into(),
        nodes: vec![],
    });

    levels
}

/// Generate specificity levels for search tools (Glob, Grep).
fn search_specificity(tool_name: &str, pattern: &str) -> Vec<SpecLevel> {
    vec![
        SpecLevel {
            label: format!("Exactly: {}", pattern),
            description: format!("Only matches `{}` with pattern `{}`", tool_name, pattern),
            examples: vec![format!("{} {}", tool_name, pattern)],
            caveat: "Won't match different patterns".into(),
            nodes: vec![condition(
                json!({"named_arg": "pattern"}),
                literal(pattern),
                vec![],
            )],
        },
        SpecLevel {
            label: format!("Any {} search", tool_name),
            description: format!("Matches any {} invocation", tool_name),
            examples: vec![
                format!("{} *.rs", tool_name),
                format!("{} **/*.ts", tool_name),
            ],
            caveat: "Allows searching with any pattern".into(),
            nodes: vec![],
        },
    ]
}

/// Generate specificity levels for any tool based on its name and args.
fn specificity_levels(tool_name: &str, tool_input: &serde_json::Value) -> Vec<SpecLevel> {
    match tool_name {
        "Bash" => {
            let command = tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args: Vec<String> = command.split_whitespace().map(String::from).collect();
            bash_specificity(&args)
        }
        "Read" | "Write" | "Edit" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            fs_specificity(tool_name, path)
        }
        "Glob" => {
            let pattern = tool_input
                .get("pattern")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            search_specificity(tool_name, pattern)
        }
        "Grep" => {
            let pattern = tool_input
                .get("pattern")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            search_specificity(tool_name, pattern)
        }
        "WebFetch" => {
            let url = tool_input.get("url").and_then(|v| v.as_str()).unwrap_or("");
            net_specificity(tool_name, url)
        }
        "WebSearch" => {
            // WebSearch has no meaningful specificity — it's just "any search"
            vec![SpecLevel {
                label: "Any web search".into(),
                description: "Matches any WebSearch invocation".into(),
                examples: vec!["WebSearch: rust async patterns".into()],
                caveat: "Allows all web searches".into(),
                nodes: vec![],
            }]
        }
        "Agent" => {
            vec![SpecLevel {
                label: "Any sub-agent".into(),
                description: "Matches any Agent invocation".into(),
                examples: vec!["Agent: research task".into()],
                caveat: "Allows spawning any sub-agent".into(),
                nodes: vec![],
            }]
        }
        _ => {
            vec![SpecLevel {
                label: format!("Any {} invocation", tool_name),
                description: format!("Matches all {} calls", tool_name),
                examples: vec![],
                caveat: "Broad match".into(),
                nodes: vec![],
            }]
        }
    }
}

// ---------------------------------------------------------------------------
// JSON IR helpers
// ---------------------------------------------------------------------------

/// Build a literal pattern value.
fn literal(s: &str) -> serde_json::Value {
    json!({"literal": {"literal": s}})
}

/// Build a condition node.
fn condition(
    observe: serde_json::Value,
    pattern: serde_json::Value,
    children: Vec<serde_json::Value>,
) -> serde_json::Value {
    condition_terminal(observe, pattern, children, false)
}

/// Build a condition node with an explicit `terminal` flag.
fn condition_terminal(
    observe: serde_json::Value,
    pattern: serde_json::Value,
    children: Vec<serde_json::Value>,
    terminal: bool,
) -> serde_json::Value {
    let mut cond = json!({
        "observe": observe,
        "pattern": pattern,
        "children": children
    });
    if terminal {
        // Safety: `cond` is constructed via `json!({...})` above, always an object.
        cond.as_object_mut()
            .expect("json!({}) always produces an object")
            .insert("terminal".into(), json!(true));
    }
    json!({ "condition": cond })
}

/// Build a decision node.
fn decision(effect: &str, sandbox: Option<&str>) -> serde_json::Value {
    match effect {
        "deny" => json!({"decision": "deny"}),
        "allow" => json!({"decision": {"allow": sandbox}}),
        "ask" => json!({"decision": {"ask": sandbox}}),
        _ => json!({"decision": {"ask": sandbox}}),
    }
}

/// Build a nested chain of positional_arg conditions from arg index `start`.
/// The innermost level has an empty children vec (placeholder for decision).
#[allow(dead_code)]
fn build_arg_chain(args: &[&str], start: usize) -> Vec<serde_json::Value> {
    if start >= args.len() {
        return vec![]; // decision placeholder
    }
    let inner = build_arg_chain(args, start + 1);
    vec![condition(
        json!({"positional_arg": start as i32}),
        literal(args[start - 1]),
        inner,
    )]
}

/// Like `build_arg_chain`, but marks the deepest positional arg as `terminal`.
fn build_arg_chain_terminal(args: &[&str], start: usize) -> Vec<serde_json::Value> {
    if start >= args.len() {
        return vec![]; // decision placeholder
    }
    let is_last = start + 1 >= args.len();
    let inner = build_arg_chain_terminal(args, start + 1);
    vec![condition_terminal(
        json!({"positional_arg": start as i32}),
        literal(args[start - 1]),
        inner,
        is_last,
    )]
}

/// Insert a decision node into the deepest empty children array of a node tree.
fn insert_decision(nodes: &mut Vec<serde_json::Value>, decision_node: serde_json::Value) {
    if nodes.is_empty() {
        nodes.push(decision_node);
        return;
    }
    // Find the deepest condition's children
    if let Some(last) = nodes.last_mut()
        && let Some(cond) = last.get_mut("condition")
        && let Some(children) = cond.get_mut("children")
        && let Some(arr) = children.as_array_mut()
    {
        if arr.is_empty() {
            arr.push(decision_node);
        } else {
            insert_decision(arr, decision_node);
        }
        return;
    }
    nodes.push(decision_node);
}

// ---------------------------------------------------------------------------
// Accumulated rule
// ---------------------------------------------------------------------------

/// A rule built interactively by the wizard.
struct WizardRule {
    /// Human-readable summary for display.
    summary: String,
    /// The complete tree node (tool_name condition wrapping specificity + decision).
    node: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn wiz() -> Result<()> {
    match select::<Start>("How would you like to onboard?")? {
        Start::Manual => {
            let policy_path = ClashSettings::policy_file()?;
            let policy_path = policy_path.with_extension("json");
            let dir = policy_path
                .parent()
                .context("policy file path has no parent directory")?;
            std::fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;

            let policy = json!({
                "schema_version": 5,
                "default_effect": "ask",
                "includes": [{"path": "@clash//builtin.star"}],
                "sandboxes": {},
                "tree": []
            });
            std::fs::write(&policy_path, serde_json::to_string_pretty(&policy)?)?;

            ui::success(&format!(
                "Blank policy written to {}",
                policy_path.display()
            ));
            ui::info("");
            ui::info("Edit it directly or use these commands:");
            ui::info(&format!(
                "  {} — add allow/deny rules",
                style::bold("clash policy allow/deny")
            ));
            ui::info(&format!(
                "  {} — validate your policy",
                style::bold("clash policy validate")
            ));
            ui::info(&format!(
                "  {} — test a command against your policy",
                style::bold("clash explain")
            ));
            Ok(())
        }
        Start::Guided => guided(),
    }
}

// ---------------------------------------------------------------------------
// Guided flow
// ---------------------------------------------------------------------------

fn guided() -> Result<()> {
    ui::info("");
    ui::section("How Clash Works");
    ui::info("Clash evaluates every tool call Claude makes against your policy.");
    ui::info(
        "You'll build your policy by providing example commands and deciding what should happen.\n",
    );

    // Step 1: Default effect
    ui::section("Step 1: Default Behavior");
    ui::info("When a command doesn't match any rule, what should happen?\n");
    let default_effect = select::<DefaultEffect>("Default for unmatched commands")?;
    ui::success(&format!("Default: {}\n", default_effect.label()));

    // Step 2: Default sandbox
    let sandbox_result = step2_sandbox_interactive()?;

    // Step 3: Rule builder loop
    ui::section("Step 3: Build Rules");
    ui::info("Now let's define rules for specific commands.");
    ui::info("Enter an example command, then choose how broadly to match it.\n");

    let mut rules: Vec<WizardRule> = Vec::new();

    loop {
        match build_rule(&sandbox_result.name)? {
            Some(rule) => {
                ui::success(&format!("Rule added: {}", rule.summary));
                rules.push(rule);

                // Show running list
                if rules.len() > 1 {
                    ui::info("");
                    ui::info(&format!("{} rules so far:", rules.len()));
                    for (i, r) in rules.iter().enumerate() {
                        ui::info(&format!("  {}. {}", i + 1, r.summary));
                    }
                }
                ui::info("");
            }
            None => {
                ui::skip("Skipped (no rule added)");
            }
        }

        if !dialog::confirm("Add another rule?", false)? {
            break;
        }
        ui::info("");
    }

    // Step 4: Emit policy
    ui::info("");
    ui::section("Writing Policy");

    let policy_path = ClashSettings::policy_file()?;
    let policy_path = policy_path.with_extension("json");
    let dir = policy_path
        .parent()
        .context("policy file path has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let tree: Vec<serde_json::Value> = rules.into_iter().map(|r| r.node).collect();

    let policy = json!({
        "schema_version": 5,
        "default_effect": default_effect.label(),
        "default_sandbox": &sandbox_result.name,
        "includes": [{"path": "@clash//builtin.star"}],
        "sandboxes": {
            (&sandbox_result.name): &sandbox_result.sandbox_json,
        },
        "tree": tree,
    });

    let json_str = serde_json::to_string_pretty(&policy)?;
    std::fs::write(&policy_path, &json_str)?;

    ui::success(&format!("Policy written to {}", policy_path.display()));
    ui::info("");
    ui::info("Next steps:");
    ui::info(&format!(
        "  {} — see your policy in action",
        style::bold("clash status")
    ));
    ui::info(&format!(
        "  {} — test a command",
        style::bold("clash explain bash \"git push\"")
    ));
    ui::info(&format!(
        "  {} — add more rules later",
        style::bold("clash policy allow/deny")
    ));

    Ok(())
}

/// Interactive rule builder: tool → args → specificity → effect → WizardRule.
fn build_rule(default_sandbox: &str) -> Result<Option<WizardRule>> {
    let tool = select::<Tools>("Tool")?;
    let tool_name = tool.label();
    let tool_def = tools::lookup(tool_name).expect("all Tools variants are known tools");

    // Only prompt for fields relevant to policy matching
    let relevant_fields: &[&str] = match tool_name {
        "Bash" => &["command"],
        "Read" | "Write" | "Edit" => &["file_path"],
        "Glob" => &["pattern"],
        "Grep" => &["pattern", "path"],
        "WebFetch" => &["url"],
        "WebSearch" => &["query"],
        "Agent" => &["subagent_type"],
        _ => &[],
    };

    let tool_input = form_only(tool_def, relevant_fields)?;

    // Generate specificity levels
    let levels = specificity_levels(tool_name, &tool_input);
    if levels.is_empty() {
        ui::warn("Could not determine specificity levels for this input");
        return Ok(None);
    }

    // Display levels with examples
    ui::info("");
    ui::section("How broadly should this rule match?");
    ui::info("Each level matches more commands. Examples show what would be affected:\n");

    let items: Vec<(String, String)> = levels
        .iter()
        .map(|l| {
            let mut desc = l.description.clone();
            if !l.examples.is_empty() {
                desc.push_str(&format!(
                    " (e.g. {})",
                    l.examples
                        .iter()
                        .take(2)
                        .map(|e| format!("`{}`", e))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            (l.label.clone(), desc)
        })
        .collect();

    // Add special options at the end
    let mut all_items = items;
    let custom_idx = all_items.len();
    all_items.push((
        "Custom pattern".into(),
        "Write your own regex or advanced pattern".into(),
    ));
    let back_idx = all_items.len();
    all_items.push(("Back".into(), "Go back and pick a different tool".into()));

    let formatted: Vec<String> = all_items
        .iter()
        .map(|(name, desc)| format!("{} — {}", name, desc))
        .collect();

    let level_idx = dialoguer::Select::new()
        .with_prompt("Match level")
        .items(&formatted)
        .default(0)
        .interact()
        .context("failed to read selection")?;

    // Back → return None to skip this rule
    if level_idx == back_idx {
        return Ok(None);
    }

    let (inner_nodes, summary_label) = if level_idx == custom_idx {
        custom_pattern_flow(tool_name, &tool_input)?
    } else {
        let chosen = &levels[level_idx];
        ui::info(&format!(
            "\n{} {}",
            style::dim("Note:"),
            style::dim(&chosen.caveat)
        ));
        (chosen.nodes.clone(), chosen.label.clone())
    };

    ui::info("");

    // Choose effect
    let effect = select::<Effect>("What should happen?")?;

    // Build the tree node
    let sandbox_ref = if effect.label() != "deny" {
        Some(default_sandbox)
    } else {
        None
    };

    let decision_node = decision(effect.label(), sandbox_ref);

    let mut final_nodes = inner_nodes;
    insert_decision(&mut final_nodes, decision_node);

    // Wrap in tool_name condition
    let node = condition(json!("tool_name"), literal(tool_name), final_nodes);

    let summary = format!("{}: {} → {}", tool_name, summary_label, effect.label());

    Ok(Some(WizardRule { summary, node }))
}

// ---------------------------------------------------------------------------
// Step 2: Sandbox selection
// ---------------------------------------------------------------------------

struct SandboxResult {
    name: String,
    sandbox_json: serde_json::Value,
}

/// Step 2 (preset): Pick from presets with a preview table.
#[allow(dead_code)]
fn step2_sandbox_preset() -> Result<SandboxResult> {
    ui::section("Step 2: Default Sandbox");
    ui::info("Sandboxes restrict what resources (files, network) commands can access.");
    ui::info("Here's what each preset allows:\n");

    preview_all_sandbox_presets();
    ui::info("");

    ui::info("Choose a preset to start — you can customize later.\n");
    let preset = select::<SandboxPreset>("Default sandbox")?;
    ui::success(&format!("Sandbox: {}\n", preset.label()));

    Ok(SandboxResult {
        name: preset.label().to_string(),
        sandbox_json: preset_to_sandbox(preset.label()),
    })
}

select_enum! {
    NetworkAccess {
        Deny      => ("deny",      "No network access (most secure)"),
        Allow     => ("allow",     "Full network access"),
        Localhost => ("localhost", "Only localhost connections"),
    }
}

select_enum! {
    FsAccess {
        ReadWrite => ("read + write + create", "Read, write, and create files"),
        ReadOnly  => ("read",                  "Read only"),
        None      => ("deny",                  "No access"),
    }
}

/// Step 2 (interactive): Build a sandbox by answering questions.
fn step2_sandbox_interactive() -> Result<SandboxResult> {
    ui::section("Step 2: Default Sandbox");
    ui::info("Sandboxes restrict what files and network access commands have.");
    ui::info("Let's build one by answering a few questions.\n");

    let name = "default".to_string();

    // Network access
    ui::info("");
    let network = select::<NetworkAccess>("Network access for commands")?;
    ui::success(&format!("Network: {}", network.label()));

    // Project directory access
    ui::info("");
    ui::info("What access should commands have to your project directory ($PWD)?");
    let cwd_access = select::<FsAccess>("Project directory ($PWD)")?;
    ui::success(&format!("$PWD: {}", cwd_access.label()));

    // Home directory access
    ui::info("");
    ui::info("What about your home directory ($HOME)?");
    let home_access = select::<FsAccess>("Home directory ($HOME)")?;
    ui::success(&format!("$HOME: {}", home_access.label()));

    // Temp directory — always allow read+write+create
    ui::info("");
    ui::skip("$TMPDIR: read + write + create (always allowed)");

    // Build sandbox JSON
    let mut rules = Vec::new();

    if cwd_access.label() != "deny" {
        rules.push(json!({
            "effect": "allow",
            "caps": cwd_access.label(),
            "path": "$PWD",
            "path_match": "subpath"
        }));
    }

    if home_access.label() != "deny" {
        rules.push(json!({
            "effect": "allow",
            "caps": home_access.label(),
            "path": "$HOME",
            "path_match": "subpath"
        }));
    }

    rules.push(json!({
        "effect": "allow",
        "caps": "read + write + create",
        "path": "$TMPDIR",
        "path_match": "subpath"
    }));

    // Default caps: read + execute for everything else
    let default_caps = match (cwd_access.label(), home_access.label()) {
        ("deny", "deny") => "read",
        _ => "read + execute",
    };

    let sandbox_json = json!({
        "default": default_caps,
        "rules": rules,
        "network": network.label()
    });

    // Show what we built
    ui::info("");
    ui::section("Sandbox preview");
    match serde_json::from_value::<crate::policy::sandbox_types::SandboxPolicy>(
        sandbox_json.clone(),
    ) {
        Ok(sandbox) => {
            let mut map = std::collections::HashMap::new();
            map.insert(name.clone(), sandbox);
            ui::print_sandbox_table(&map);
        }
        Err(e) => ui::warn(&format!("Could not preview: {e}")),
    }
    ui::info("");

    Ok(SandboxResult { name, sandbox_json })
}

// ---------------------------------------------------------------------------
// Sandbox preview
// ---------------------------------------------------------------------------

/// Compile every sandbox preset and display them side-by-side in a capability table.
fn preview_all_sandbox_presets() {
    use crate::policy::sandbox_types::SandboxPolicy;
    use std::collections::HashMap;

    let mut all_sandboxes: HashMap<String, SandboxPolicy> = HashMap::new();

    for preset in SandboxPreset::variants() {
        match settings::compile_default_policy_to_json_with_preset(preset.label()) {
            Ok(json) => match compile::compile_to_tree(&json) {
                Ok(compiled) => {
                    if let Some((_name, sandbox)) = compiled.sandboxes.into_iter().next() {
                        all_sandboxes.insert(preset.label().to_string(), sandbox);
                    }
                }
                Err(e) => ui::warn(&format!("Could not compile {}: {e}", preset.label())),
            },
            Err(e) => ui::warn(&format!("Could not preview {}: {e}", preset.label())),
        }
    }

    if !all_sandboxes.is_empty() {
        ui::print_sandbox_table(&all_sandboxes);
    }
}

// ---------------------------------------------------------------------------
// Custom pattern flow
// ---------------------------------------------------------------------------

select_enum! {
    PatternType {
        Regex   => ("regex",   "Match using a regular expression"),
        Prefix  => ("prefix",  "Match any path or command starting with a value"),
        AnyOf   => ("any_of",  "Match any of several exact values"),
        Not     => ("not",     "Match anything EXCEPT a specific value"),
    }
}

/// Walk the user through building a custom pattern.
///
/// Returns (inner_nodes, summary_label) just like the specificity levels.
fn custom_pattern_flow(
    tool_name: &str,
    _tool_input: &serde_json::Value,
) -> Result<(Vec<serde_json::Value>, String)> {
    ui::info("");
    let pat_type = select::<PatternType>("Pattern type")?;

    // Ask which observable to match on
    let observe = pick_observable(tool_name)?;

    let (pattern_json, summary) = match pat_type {
        PatternType::Regex => {
            let expr = dialog::input("Regex pattern")?;
            let pattern = json!({"regex": expr});
            let summary = format!("regex({})", expr);
            (pattern, summary)
        }
        PatternType::Prefix => {
            let value = dialog::input("Prefix value")?;
            let pattern = json!({"prefix": {"literal": value}});
            let summary = format!("prefix({})", value);
            (pattern, summary)
        }
        PatternType::AnyOf => {
            ui::info("Enter values one per line. Empty line to finish.\n");
            let mut values = Vec::new();
            loop {
                let v = dialog::input(&format!("Value {} (empty to finish)", values.len() + 1))?;
                if v.is_empty() {
                    break;
                }
                values.push(v);
            }
            if values.is_empty() {
                anyhow::bail!("at least one value is required for any_of");
            }
            let patterns: Vec<serde_json::Value> = values
                .iter()
                .map(|v| json!({"literal": {"literal": v}}))
                .collect();
            let pattern = json!({"any_of": patterns});
            let summary = format!("any_of({})", values.join(", "));
            (pattern, summary)
        }
        PatternType::Not => {
            let value = dialog::input("Value to exclude")?;
            let pattern = json!({"not": {"literal": {"literal": value}}});
            let summary = format!("not({})", value);
            (pattern, summary)
        }
    };

    let nodes = vec![condition(observe.0, pattern_json, vec![])];
    Ok((nodes, format!("custom: {} on {}", summary, observe.1)))
}

/// Ask the user which observable to match on, appropriate to the tool type.
fn pick_observable(tool_name: &str) -> Result<(serde_json::Value, String)> {
    match tool_name {
        "Bash" => {
            select_enum! {
                BashObservable {
                    Binary     => ("binary",     "The command binary (arg 0)"),
                    FirstArg   => ("subcommand", "The first argument / subcommand (arg 1)"),
                    AnyArg     => ("any_arg",    "Scan all arguments (matches if any arg matches)"),
                }
            }
            let obs = select::<BashObservable>("What should the pattern match against?")?;
            let json = match obs {
                BashObservable::Binary => json!({"positional_arg": 0}),
                BashObservable::FirstArg => json!({"positional_arg": 1}),
                BashObservable::AnyArg => json!("has_arg"),
            };
            Ok((json, obs.label().to_string()))
        }
        "Read" | "Write" | "Edit" => Ok((json!("fs_path"), "fs_path".into())),
        "Glob" | "Grep" => Ok((json!({"named_arg": "pattern"}), "pattern".into())),
        "WebFetch" => Ok((json!("net_domain"), "domain".into())),
        _ => Ok((json!("tool_name"), "tool_name".into())),
    }
}

// ---------------------------------------------------------------------------
// Sandbox preset → JSON
// ---------------------------------------------------------------------------

/// Convert a sandbox preset name into a SandboxPolicy JSON value.
///
/// These match the presets defined in `clash_starlark/stdlib/sandboxes.star`.
fn preset_to_sandbox(preset: &str) -> serde_json::Value {
    match preset {
        "dev" => json!({
            "default": "read + execute",
            "rules": [
                {
                    "effect": "allow",
                    "caps": "read + write + create",
                    "path": "$PWD",
                    "path_match": "subpath"
                },
                {
                    "effect": "allow",
                    "caps": "read + write + create",
                    "path": "$TMPDIR",
                    "path_match": "subpath"
                },
                {
                    "effect": "allow",
                    "caps": "read",
                    "path": "$HOME",
                    "path_match": "subpath"
                }
            ],
            "network": "deny"
        }),
        "dev_network" => json!({
            "default": "read + execute",
            "rules": [
                {
                    "effect": "allow",
                    "caps": "read + write + create",
                    "path": "$PWD",
                    "path_match": "subpath"
                },
                {
                    "effect": "allow",
                    "caps": "read + write + create",
                    "path": "$TMPDIR",
                    "path_match": "subpath"
                },
                {
                    "effect": "allow",
                    "caps": "read",
                    "path": "$HOME",
                    "path_match": "subpath"
                }
            ],
            "network": "allow"
        }),
        "read_only" => json!({
            "default": "read + execute",
            "rules": [
                {
                    "effect": "allow",
                    "caps": "read + write + create",
                    "path": "$TMPDIR",
                    "path_match": "subpath"
                }
            ],
            "network": "deny"
        }),
        "restricted" => json!({
            "default": "read",
            "rules": [
                {
                    "effect": "allow",
                    "caps": "read + write + create",
                    "path": "$TMPDIR",
                    "path_match": "subpath"
                }
            ],
            "network": "deny"
        }),
        "unrestricted" => json!({
            "default": "read + write + create + delete + execute",
            "rules": [],
            "network": "allow"
        }),
        _ => json!({
            "default": "read + execute",
            "rules": [],
            "network": "deny"
        }),
    }
}
