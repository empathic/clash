//! Transactional policy editor — line-oriented protocol for pipe/interactive use.
//!
//! `clash policy shell` provides a REPL and pipe-friendly interface for
//! accumulating policy mutations in memory, then applying them atomically.

use std::io::{BufRead, Write as IoWrite};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};

use crate::policy::Effect;
use crate::policy::ast::{PolicyItem, Rule, TopLevel};
use crate::policy::edit;
use crate::settings::{ClashSettings, PolicyLevel};
use crate::style;
use crate::wizard::describe_rule;

/// Minimal policy source used when creating a new policy file.
const MINIMAL_POLICY: &str = "(default deny \"main\")\n(policy \"main\")\n";

// ---------------------------------------------------------------------------
// Command types
// ---------------------------------------------------------------------------

/// Parsed shell command.
#[derive(Debug)]
pub enum ShellCommand {
    Add {
        policy: Option<String>,
        rule_text: String,
    },
    Remove {
        policy: Option<String>,
        rule_text: String,
    },
    Create {
        policy: String,
    },
    Default {
        effect: Effect,
        policy: Option<String>,
    },
    Use {
        policy: String,
    },
    Show,
    Rules {
        policy: Option<String>,
    },
    Test {
        tool: String,
        args: Vec<String>,
    },
    Diff,
    Apply,
    Abort,
    Help {
        command: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a single line into a ShellCommand.
pub fn parse_command(line: &str) -> Result<ShellCommand> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        bail!("empty or comment line");
    }

    let (verb, rest) = match line.find(|c: char| c.is_whitespace()) {
        Some(i) => (&line[..i], line[i..].trim_start()),
        None => (line, ""),
    };

    match verb {
        "add" => parse_add_remove(rest, true),
        "remove" => parse_add_remove(rest, false),
        "create" => {
            if rest.is_empty() {
                bail!("create requires a policy name");
            }
            Ok(ShellCommand::Create {
                policy: rest.to_string(),
            })
        }
        "default" => parse_default(rest),
        "use" => {
            if rest.is_empty() {
                bail!("use requires a policy name");
            }
            Ok(ShellCommand::Use {
                policy: rest.to_string(),
            })
        }
        "show" => Ok(ShellCommand::Show),
        "rules" => Ok(ShellCommand::Rules {
            policy: if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            },
        }),
        "test" => parse_test(rest),
        "diff" => Ok(ShellCommand::Diff),
        "apply" => Ok(ShellCommand::Apply),
        "abort" => Ok(ShellCommand::Abort),
        "help" => Ok(ShellCommand::Help {
            command: if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            },
        }),
        _ => bail!("unknown command: {verb}"),
    }
}

/// Parse `add` or `remove` — detect optional policy name prefix.
///
/// If rest starts with `(` or contains `:` (shortcut syntax), it targets the
/// current policy. Otherwise, the first word is treated as a policy name.
fn parse_add_remove(rest: &str, is_add: bool) -> Result<ShellCommand> {
    if rest.is_empty() {
        bail!("{} requires a rule", if is_add { "add" } else { "remove" });
    }

    // Direct s-expr or effect:verb shortcut → no policy prefix
    if rest.starts_with('(') || rest.contains(':') {
        return if is_add {
            Ok(ShellCommand::Add {
                policy: None,
                rule_text: rest.to_string(),
            })
        } else {
            Ok(ShellCommand::Remove {
                policy: None,
                rule_text: rest.to_string(),
            })
        };
    }

    // Check if first word is a policy name (followed by `(` or `effect:verb`)
    if let Some(i) = rest.find(|c: char| c.is_whitespace()) {
        let first_word = &rest[..i];
        let after = rest[i..].trim_start();
        if after.starts_with('(') || after.contains(':') {
            return if is_add {
                Ok(ShellCommand::Add {
                    policy: Some(first_word.to_string()),
                    rule_text: after.to_string(),
                })
            } else {
                Ok(ShellCommand::Remove {
                    policy: Some(first_word.to_string()),
                    rule_text: after.to_string(),
                })
            };
        }
    }

    // Fallback: treat the whole thing as rule text targeting current policy
    if is_add {
        Ok(ShellCommand::Add {
            policy: None,
            rule_text: rest.to_string(),
        })
    } else {
        Ok(ShellCommand::Remove {
            policy: None,
            rule_text: rest.to_string(),
        })
    }
}

/// Parse `default <effect> [<policy>]`.
fn parse_default(rest: &str) -> Result<ShellCommand> {
    if rest.is_empty() {
        bail!("default requires an effect (allow, deny, ask)");
    }
    let parts: Vec<&str> = rest.splitn(2, char::is_whitespace).collect();
    let effect = parse_effect(parts[0])?;
    let policy = parts.get(1).map(|s| s.trim().to_string());
    Ok(ShellCommand::Default { effect, policy })
}

/// Parse `test <tool> <args...>`.
fn parse_test(rest: &str) -> Result<ShellCommand> {
    if rest.is_empty() {
        bail!("test requires a tool name and arguments");
    }
    let parts: Vec<&str> = rest.split_whitespace().collect();
    Ok(ShellCommand::Test {
        tool: parts[0].to_string(),
        args: parts[1..].iter().map(|s| s.to_string()).collect(),
    })
}

fn parse_effect(s: &str) -> Result<Effect> {
    match s {
        "allow" => Ok(Effect::Allow),
        "deny" => Ok(Effect::Deny),
        "ask" => Ok(Effect::Ask),
        _ => bail!("unknown effect: {s} (expected allow, deny, ask)"),
    }
}

// ---------------------------------------------------------------------------
// Shell Session
// ---------------------------------------------------------------------------

/// In-memory policy editing session.
pub struct ShellSession {
    /// Current (modified) source.
    pub source: String,
    /// Original source (for diff).
    pub original_source: String,
    /// Current policy block context.
    pub current_policy: String,
    /// File path to write to on apply.
    pub path: PathBuf,
    /// Policy level being edited.
    pub level: PolicyLevel,
    /// Dry-run mode (no writes).
    pub dry_run: bool,
    /// Whether we're in interactive (TTY) mode.
    pub interactive: bool,
}

impl ShellSession {
    /// Create a new session for the given scope.
    pub fn new(scope: Option<&str>, dry_run: bool, interactive: bool) -> Result<Self> {
        let level = match scope {
            Some(s) => s.parse::<PolicyLevel>().context("invalid --scope value")?,
            None => ClashSettings::default_scope(),
        };

        let (path, source) = match load_source(level) {
            Ok(ps) => ps,
            Err(_) if level == PolicyLevel::Project || level == PolicyLevel::Session => {
                let path = ClashSettings::policy_file_for_level(level)?;
                (path, MINIMAL_POLICY.to_string())
            }
            Err(e) => return Err(e),
        };

        // Normalize through parse→serialize so original and edited sources share
        // the same baseline formatting, producing clean diffs.
        let source = edit::normalize(&source)?;

        let current_policy = edit::active_policy(&source)?;

        Ok(ShellSession {
            original_source: source.clone(),
            source,
            current_policy,
            path,
            level,
            dry_run,
            interactive,
        })
    }

    /// Execute a single command against the in-memory state.
    pub fn execute(&mut self, cmd: ShellCommand) -> Result<ShellOutput> {
        match cmd {
            ShellCommand::Add { policy, rule_text } => self.exec_add(policy, &rule_text),
            ShellCommand::Remove { policy, rule_text } => self.exec_remove(policy, &rule_text),
            ShellCommand::Create { policy } => self.exec_create(&policy),
            ShellCommand::Default { effect, policy } => self.exec_default(effect, policy),
            ShellCommand::Use { policy } => self.exec_use(&policy),
            ShellCommand::Show => self.exec_show(),
            ShellCommand::Rules { policy } => self.exec_rules(policy),
            ShellCommand::Test { tool, args } => self.exec_test(&tool, &args),
            ShellCommand::Diff => self.exec_diff(),
            ShellCommand::Apply => self.exec_apply(),
            ShellCommand::Abort => Ok(ShellOutput::Exit { applied: false }),
            ShellCommand::Help { command } => Ok(self.exec_help(command)),
        }
    }

    // -- Mutations --

    fn exec_add(&mut self, policy: Option<String>, rule_text: &str) -> Result<ShellOutput> {
        let policy_name = policy.unwrap_or_else(|| self.current_policy.clone());
        let rules = parse_rule_text(rule_text)?;
        let mut added = Vec::new();

        for rule in &rules {
            // Auto-create policy block if needed
            if self.find_policy(&policy_name).is_err() {
                let block = format!("(policy \"{policy_name}\")\n");
                self.source = edit::ensure_policy_block(&self.source, &policy_name, &block)?;
            }

            let before = self.source.clone();
            self.source = edit::add_rule(&self.source, &policy_name, rule)?;
            if self.source != before {
                added.push(rule.clone());
            }
        }

        // Validate
        self.validate()?;

        if added.is_empty() {
            Ok(ShellOutput::Message(if self.interactive {
                format!("  {} No changes (rules already exist).", style::dim("·"))
            } else {
                "No changes (rules already exist).".into()
            }))
        } else {
            let lines: Vec<String> = added
                .iter()
                .map(|r| {
                    if self.interactive {
                        format!(
                            "  {} {}",
                            style::green_bold("+"),
                            style::green(&describe_rule(r))
                        )
                    } else {
                        format!("+ {r}")
                    }
                })
                .collect();
            Ok(ShellOutput::Message(lines.join("\n")))
        }
    }

    fn exec_remove(&mut self, policy: Option<String>, rule_text: &str) -> Result<ShellOutput> {
        let policy_name = policy.unwrap_or_else(|| self.current_policy.clone());

        let before = self.source.clone();
        self.source = edit::remove_rule(&self.source, &policy_name, rule_text)?;

        self.validate()?;

        if self.source == before {
            Ok(ShellOutput::Message(if self.interactive {
                format!("  {} No changes (rule not found).", style::dim("·"))
            } else {
                "No changes (rule not found).".into()
            }))
        } else if self.interactive {
            Ok(ShellOutput::Message(format!(
                "  {} {}",
                style::red_bold("-"),
                style::red(&format!("Removed: {rule_text}"))
            )))
        } else {
            Ok(ShellOutput::Message(format!("- {rule_text}")))
        }
    }

    fn exec_create(&mut self, policy_name: &str) -> Result<ShellOutput> {
        let block = format!("(policy \"{policy_name}\")\n");
        let before = self.source.clone();
        self.source = edit::ensure_policy_block(&self.source, policy_name, &block)?;

        self.validate()?;

        if self.source == before {
            Ok(ShellOutput::Message(if self.interactive {
                format!(
                    "  {} Policy block {} already exists.",
                    style::dim("·"),
                    style::cyan(&format!("\"{policy_name}\""))
                )
            } else {
                format!("Policy block \"{policy_name}\" already exists.")
            }))
        } else {
            Ok(ShellOutput::Message(if self.interactive {
                format!(
                    "  {} Created policy block {}.",
                    style::green_bold("+"),
                    style::cyan(&format!("\"{policy_name}\""))
                )
            } else {
                format!("Created policy block \"{policy_name}\".")
            }))
        }
    }

    fn exec_default(&mut self, effect: Effect, policy: Option<String>) -> Result<ShellOutput> {
        let policy_name = policy.unwrap_or_else(|| self.current_policy.clone());
        self.source = edit::set_default(&self.source, effect, &policy_name)?;

        self.validate()?;

        Ok(ShellOutput::Message(if self.interactive {
            format!(
                "  {} Default set to {} (policy: {}).",
                style::green_bold("✓"),
                style::effect(&effect.to_string()),
                style::cyan(&format!("\"{policy_name}\""))
            )
        } else {
            format!("Default set to {effect} (policy: \"{policy_name}\").")
        }))
    }

    fn exec_use(&mut self, policy_name: &str) -> Result<ShellOutput> {
        // Validate block exists (or will exist)
        if self.find_policy(policy_name).is_err() {
            bail!(
                "policy block \"{policy_name}\" does not exist — use `create {policy_name}` first"
            );
        }
        self.current_policy = policy_name.to_string();
        Ok(ShellOutput::Message(if self.interactive {
            format!(
                "  Switched to policy {}.",
                style::cyan(&format!("\"{policy_name}\""))
            )
        } else {
            format!("Switched to policy \"{policy_name}\".")
        }))
    }

    // -- Queries --

    fn exec_show(&self) -> Result<ShellOutput> {
        let top_levels = crate::policy::parse::parse(&self.source)?;
        let mut output = String::new();

        for tl in &top_levels {
            match tl {
                TopLevel::Default { effect, policy } => {
                    if self.interactive {
                        output.push_str(&format!(
                            "  {}: {} (policy: {})\n",
                            style::bold("Default"),
                            style::effect(&effect.to_string()),
                            style::cyan(&format!("\"{policy}\""))
                        ));
                    } else {
                        output
                            .push_str(&format!("  Default: {} (policy: \"{}\")\n", effect, policy));
                    }
                }
                TopLevel::Policy { name, body } => {
                    if self.interactive {
                        let marker = if *name == self.current_policy {
                            format!(" {}", style::yellow("*"))
                        } else {
                            String::new()
                        };
                        output.push_str(&format!(
                            "\n  {} {}{}\n",
                            style::bold("Policy"),
                            style::cyan(&format!("\"{name}\"")),
                            marker,
                        ));
                    } else {
                        let marker = if *name == self.current_policy {
                            " *"
                        } else {
                            ""
                        };
                        output.push_str(&format!("\n  Policy \"{name}\"{marker}\n"));
                    }
                    if body.is_empty() {
                        output.push_str(&format!(
                            "    {}\n",
                            if self.interactive {
                                style::dim("(empty)")
                            } else {
                                "(empty)".into()
                            }
                        ));
                    }
                    for item in body {
                        match item {
                            PolicyItem::Rule(r) => {
                                if self.interactive {
                                    output.push_str(&format!(
                                        "    {} {} {}\n",
                                        style::effect(&format!("{:<5}", r.effect)),
                                        r.matcher,
                                        style::dim(&format!("— {}", describe_rule(r)))
                                    ));
                                } else {
                                    output.push_str(&format!("    {r}\n"));
                                }
                            }
                            PolicyItem::Include(name) => {
                                if self.interactive {
                                    output.push_str(&format!(
                                        "    {} {}\n",
                                        style::dim("include"),
                                        style::cyan(&format!("\"{name}\""))
                                    ));
                                } else {
                                    output.push_str(&format!("    (include \"{name}\")\n"));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(ShellOutput::Message(output.trim_end().to_string()))
    }

    fn exec_rules(&self, policy: Option<String>) -> Result<ShellOutput> {
        let policy_name = policy.unwrap_or_else(|| self.current_policy.clone());
        let top_levels = crate::policy::parse::parse(&self.source)?;

        let mut output = String::new();
        for tl in &top_levels {
            if let TopLevel::Policy { name, body } = tl
                && *name == policy_name
            {
                for item in body {
                    if let PolicyItem::Rule(r) = item {
                        if self.interactive {
                            output.push_str(&format!(
                                "  {} {} {}\n",
                                style::effect(&format!("{:<5}", r.effect)),
                                r.matcher,
                                style::dim(&format!("— {}", describe_rule(r)))
                            ));
                        } else {
                            output.push_str(&format!("{r}\n"));
                        }
                    }
                }
            }
        }

        if output.is_empty() {
            output = if self.interactive {
                format!(
                    "  {} No rules in policy {}.",
                    style::dim("·"),
                    style::cyan(&format!("\"{policy_name}\""))
                )
            } else {
                format!("No rules in policy \"{policy_name}\".")
            };
        }

        Ok(ShellOutput::Message(output.trim_end().to_string()))
    }

    fn exec_test(&self, tool: &str, args: &[String]) -> Result<ShellOutput> {
        // Build tool_name and tool_input from CLI-style arguments
        let (tool_name, input_field) = match tool.to_lowercase().as_str() {
            "bash" => ("Bash", "command"),
            "read" => ("Read", "file_path"),
            "write" => ("Write", "file_path"),
            "edit" => ("Edit", "file_path"),
            _ => {
                let field = match tool {
                    "Bash" => "command",
                    "Read" | "Write" | "Edit" | "NotebookEdit" => "file_path",
                    "Glob" | "Grep" => "pattern",
                    "WebFetch" => "url",
                    "WebSearch" => "query",
                    _ => "command",
                };
                (tool, field)
            }
        };

        let noun = args.join(" ");
        let tool_input = serde_json::json!({ input_field: noun });
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        // Compile the current (pending) source
        let tree = crate::policy::compile_policy(&self.source)
            .context("failed to compile pending policy")?;
        let decision = tree.evaluate(tool_name, &tool_input, &cwd);

        let effect_str = decision.effect.to_string();
        let mut output = if self.interactive {
            format!(
                "  {} {} {}",
                style::effect(&effect_str),
                style::dim("—"),
                style::bold(tool_name)
            )
        } else {
            effect_str.clone()
        };

        if !args.is_empty() && self.interactive {
            output.push_str(&format!(" {}", style::dim(&args.join(" "))));
        }

        if let Some(ref reason) = decision.reason {
            if self.interactive {
                output.push_str(&format!("\n  {} {reason}", style::dim("Reason:")));
            } else {
                output.push_str(&format!(" ({reason})"));
            }
        }

        if !decision.trace.matched_rules.is_empty() {
            let first = &decision.trace.matched_rules[0];
            if self.interactive {
                output.push_str(&format!(
                    "\n  {} {}",
                    style::dim("Matched:"),
                    first.description
                ));
            } else {
                output.push_str(&format!(" matched: {}", first.description));
            }
        }

        // If testing bash with no specific command and interactive, offer to drop into
        // a sandboxed shell session so the user can explore the sandbox interactively
        if self.interactive
            && tool_name == "Bash"
            && args.is_empty()
            && decision.effect == Effect::Allow
            && let Some(ref sandbox_policy) = decision.sandbox
        {
            output.push_str(&format!(
                "\n  {} Sandbox policy attached — launching interactive shell...",
                style::bold("⬡")
            ));
            println!("{output}");
            println!();

            let cwd_path = std::env::current_dir().unwrap_or_default();
            match crate::sandbox::spawn_sandboxed_shell(sandbox_policy, &cwd_path) {
                Ok(status) => {
                    let exit_msg = if status.success() {
                        format!(
                            "\n  {} Sandboxed shell exited successfully.",
                            style::green_bold("✓")
                        )
                    } else {
                        format!(
                            "\n  {} Sandboxed shell exited with {}.",
                            style::yellow_bold("!"),
                            status
                        )
                    };
                    return Ok(ShellOutput::Message(exit_msg));
                }
                Err(e) => {
                    return Ok(ShellOutput::Message(format!(
                        "\n  {} Failed to launch sandboxed shell: {e}",
                        style::red_bold("✗")
                    )));
                }
            }
        }

        Ok(ShellOutput::Message(output))
    }

    /// Diff fragments between original and current source.
    ///
    /// Uses `grouped_ops` with a context radius of 3 so only hunks around
    /// actual changes are shown, not the entire file.
    fn diff_string(&self) -> String {
        let diff = similar::TextDiff::from_lines(&self.original_source, &self.source);
        let mut output = String::new();
        let groups = diff.grouped_ops(3);

        for (idx, group) in groups.iter().enumerate() {
            if idx > 0 {
                output.push_str("...\n");
            }
            for op in group {
                for change in diff.iter_changes(op) {
                    let sign = match change.tag() {
                        similar::ChangeTag::Delete => "-",
                        similar::ChangeTag::Insert => "+",
                        similar::ChangeTag::Equal => " ",
                    };
                    output.push_str(sign);
                    output.push_str(change.value());
                    if !change.value().ends_with('\n') {
                        output.push('\n');
                    }
                }
            }
        }
        output
    }

    /// Colorize a diff string for interactive display.
    fn colorize_diff(raw: &str) -> String {
        raw.lines()
            .map(|line| {
                if line.starts_with('+') {
                    format!("{}\n", style::green(line))
                } else if line.starts_with('-') {
                    format!("{}\n", style::red(line))
                } else if line == "..." {
                    format!("{}\n", style::dim(line))
                } else {
                    format!("{line}\n")
                }
            })
            .collect()
    }

    fn exec_diff(&self) -> Result<ShellOutput> {
        if self.source == self.original_source {
            return Ok(ShellOutput::Message("No changes.".into()));
        }

        let raw = self.diff_string();
        if self.interactive {
            Ok(ShellOutput::Message(
                Self::colorize_diff(&raw).trim_end().to_string(),
            ))
        } else {
            Ok(ShellOutput::Message(raw.trim_end().to_string()))
        }
    }

    /// Show the pending diff and ask the user to confirm before writing.
    /// Returns `true` if the user confirmed, `false` otherwise.
    fn confirm_apply(&self) -> Result<bool> {
        let raw = self.diff_string();
        println!();
        println!("{}", Self::colorize_diff(&raw).trim_end());
        println!();
        let (added, removed) = self.count_changes();
        print!(
            "  Write to {}? ({} added, {} removed) [y/N] ",
            style::dim(&self.path.display().to_string()),
            added,
            removed
        );
        std::io::stdout().flush()?;

        let mut answer = String::new();
        // Read from /dev/tty so this works even if stdin is partially consumed
        let tty = std::fs::File::open("/dev/tty");
        if let Ok(tty) = tty {
            let mut reader = std::io::BufReader::new(tty);
            reader.read_line(&mut answer)?;
        } else {
            std::io::stdin().lock().read_line(&mut answer)?;
        }
        let answer = answer.trim().to_lowercase();
        Ok(answer == "y" || answer == "yes")
    }

    fn exec_apply(&mut self) -> Result<ShellOutput> {
        if self.dry_run {
            return Ok(ShellOutput::DryRun(self.source.clone()));
        }

        if self.source == self.original_source {
            return Ok(ShellOutput::Exit { applied: false });
        }

        if self.interactive && !self.confirm_apply()? {
            return Ok(ShellOutput::Exit { applied: false });
        }

        self.write()?;

        let (added, removed) = self.count_changes();
        let msg = format!(
            "Wrote {} ({} added, {} removed)",
            self.path.display(),
            added,
            removed
        );
        Ok(ShellOutput::ApplyAndExit { message: msg })
    }

    fn exec_help(&self, command: Option<String>) -> ShellOutput {
        let msg = if let Some(cmd) = command {
            if self.interactive {
                match cmd.as_str() {
                    "add" => format!(
                        "{} {} — Add a rule. Rule is (effect (matcher)) or effect:verb.\n  Example: add (allow (exec \"cargo\" *))",
                        style::cyan("add"),
                        style::dim("[<policy>] <rule>")
                    ),
                    "remove" => format!(
                        "{} {} — Remove a rule by its text.\n  Example: remove (deny (exec \"npm\" *))",
                        style::cyan("remove"),
                        style::dim("[<policy>] <rule-text>")
                    ),
                    "create" => format!(
                        "{} {} — Create a new empty policy block.\n  Example: create sandbox",
                        style::cyan("create"),
                        style::dim("<policy>")
                    ),
                    "default" => format!(
                        "{} {} — Change the default effect.\n  Example: default deny main",
                        style::cyan("default"),
                        style::dim("<effect> [<policy>]")
                    ),
                    "use" => format!(
                        "{} {} — Switch current policy context.\n  Example: use sandbox",
                        style::cyan("use"),
                        style::dim("<policy>")
                    ),
                    "show" => format!(
                        "{} — Display the full policy with pending changes.",
                        style::cyan("show")
                    ),
                    "rules" => format!(
                        "{} {} — List rules in a policy block.",
                        style::cyan("rules"),
                        style::dim("[<policy>]")
                    ),
                    "test" => format!(
                        "{} {} — Test if a tool invocation is allowed/denied.\n  Example: test bash cargo build",
                        style::cyan("test"),
                        style::dim("<tool> <args...>")
                    ),
                    "diff" => format!(
                        "{} — Show pending changes as a unified diff.",
                        style::cyan("diff")
                    ),
                    "apply" => {
                        format!("{} — Write changes to disk and exit.", style::cyan("apply"))
                    }
                    "abort" => format!("{} — Discard changes and exit.", style::cyan("abort")),
                    _ => format!(
                        "Unknown command: {}. Type {} for a list.",
                        style::red(&cmd),
                        style::cyan("help")
                    ),
                }
            } else {
                match cmd.as_str() {
                    "add" => "add [<policy>] <rule> — Add a rule. Rule is (effect (matcher)) or effect:verb.\n  Example: add (allow (exec \"cargo\" *))".into(),
                    "remove" => "remove [<policy>] <rule-text> — Remove a rule by its text.\n  Example: remove (deny (exec \"npm\" *))".into(),
                    "create" => "create <policy> — Create a new empty policy block.\n  Example: create sandbox".into(),
                    "default" => "default <effect> [<policy>] — Change the default effect.\n  Example: default deny main".into(),
                    "use" => "use <policy> — Switch current policy context.\n  Example: use sandbox".into(),
                    "show" => "show — Display the full policy with pending changes.".into(),
                    "rules" => "rules [<policy>] — List rules in a policy block.".into(),
                    "test" => "test <tool> <args...> — Test if a tool invocation is allowed/denied.\n  Example: test bash cargo build".into(),
                    "diff" => "diff — Show pending changes as a unified diff.".into(),
                    "apply" => "apply — Write changes to disk and exit.".into(),
                    "abort" => "abort — Discard changes and exit.".into(),
                    _ => format!("Unknown command: {cmd}. Type 'help' for a list."),
                }
            }
        } else if self.interactive {
            fn cmd_line(name: &str, args: &str, desc: &str) -> String {
                format!(
                    "  {:<28} {}",
                    format!("{} {}", style::cyan(name), style::dim(args)),
                    desc
                )
            }
            let lines = [
                style::bold("Commands:"),
                cmd_line("add", "[<policy>] <rule>", "Add a rule"),
                cmd_line("remove", "[<policy>] <rule>", "Remove a rule"),
                cmd_line("create", "<policy>", "Create a policy block"),
                cmd_line("default", "<effect> [<policy>]", "Change the default"),
                cmd_line("use", "<policy>", "Switch context"),
                cmd_line("show", "", "Display policy"),
                cmd_line("rules", "[<policy>]", "List rules"),
                cmd_line("test", "<tool> <args...>", "Test a tool invocation"),
                cmd_line("diff", "", "Show pending changes"),
                cmd_line("apply", "", "Write and exit"),
                cmd_line("abort", "", "Discard and exit"),
                cmd_line("help", "[<command>]", "Show help"),
                String::new(),
                format!(
                    "{}: {} or {} (e.g. {})",
                    style::bold("Rules"),
                    style::dim("(effect (matcher))"),
                    style::dim("effect:verb"),
                    style::cyan("allow:bash")
                ),
                format!("Lines starting with {} are comments.", style::dim("#")),
            ];
            lines.join("\n")
        } else {
            "Commands:\n  \
             add [<policy>] <rule>      Add a rule\n  \
             remove [<policy>] <rule>   Remove a rule\n  \
             create <policy>            Create a policy block\n  \
             default <effect> [<policy>] Change the default\n  \
             use <policy>               Switch context\n  \
             show                       Display policy\n  \
             rules [<policy>]           List rules\n  \
             test <tool> <args...>      Test a tool invocation\n  \
             diff                       Show pending changes\n  \
             apply                      Write and exit\n  \
             abort                      Discard and exit\n  \
             help [<command>]           Show help\n\n\
             Rules: (effect (matcher)) or effect:verb (e.g. allow:bash)\n\
             Lines starting with # are comments."
                .into()
        };
        ShellOutput::Message(msg)
    }

    // -- Helpers --

    fn find_policy(&self, name: &str) -> Result<()> {
        let top_levels = crate::policy::parse::parse(&self.source)?;
        for tl in &top_levels {
            if let TopLevel::Policy { name: pname, .. } = tl
                && pname == name
            {
                return Ok(());
            }
        }
        bail!("policy block not found: {name}")
    }

    fn validate(&self) -> Result<()> {
        crate::policy::compile_policy(&self.source).context("pending policy failed validation")?;
        Ok(())
    }

    fn write(&self) -> Result<()> {
        // Validate before writing
        crate::policy::compile_policy(&self.source)
            .context("modified policy failed to compile — not writing")?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory: {}", parent.display()))?;
        }
        std::fs::write(&self.path, &self.source)
            .with_context(|| format!("failed to write policy file: {}", self.path.display()))?;
        Ok(())
    }

    fn count_changes(&self) -> (usize, usize) {
        let diff = similar::TextDiff::from_lines(&self.original_source, &self.source);
        let mut added = 0;
        let mut removed = 0;
        for change in diff.iter_all_changes() {
            match change.tag() {
                similar::ChangeTag::Insert => added += 1,
                similar::ChangeTag::Delete => removed += 1,
                similar::ChangeTag::Equal => {}
            }
        }
        (added, removed)
    }

    // -- Mode runners --

    /// Run in pipe mode: parse all lines, fail-fast, apply atomically.
    pub fn run_pipe<R: BufRead>(&mut self, reader: R) -> Result<()> {
        let lines: Vec<String> = reader.lines().collect::<std::io::Result<_>>()?;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let cmd = parse_command(trimmed)
                .with_context(|| format!("line {}: {trimmed}", line_num + 1))?;

            // Pipe mode ignores apply/abort — auto-applies at end
            if matches!(cmd, ShellCommand::Apply | ShellCommand::Abort) {
                continue;
            }

            let output = self
                .execute(cmd)
                .with_context(|| format!("line {}: {trimmed}", line_num + 1))?;

            match output {
                ShellOutput::Message(msg) => {
                    if !msg.is_empty() {
                        println!("{msg}");
                    }
                }
                ShellOutput::DryRun(source) => {
                    print!("{source}");
                    return Ok(());
                }
                ShellOutput::Exit { .. } | ShellOutput::ApplyAndExit { .. } => return Ok(()),
            }
        }

        // Auto-apply at end of pipe
        if self.dry_run {
            print!("{}", self.source);
        } else if self.source != self.original_source {
            self.write()?;
            let (added, removed) = self.count_changes();
            println!(
                "{} Wrote {} policy ({} added, {} removed)",
                style::shield(),
                style::cyan(&self.level.to_string()),
                added,
                removed,
            );
        } else {
            println!("No changes.");
        }

        Ok(())
    }

    /// Run a single inline command (from -c flag).
    pub fn run_command(&mut self, stmt: &str) -> Result<()> {
        let cmd = parse_command(stmt)?;
        let output = self.execute(cmd)?;

        if let ShellOutput::Message(msg) = output
            && !msg.is_empty()
        {
            println!("{msg}");
        }

        // Auto-apply
        if self.dry_run {
            print!("{}", self.source);
        } else if self.source != self.original_source {
            self.write()?;
            let (added, removed) = self.count_changes();
            println!(
                "{} Wrote {} policy ({} added, {} removed)",
                style::shield(),
                style::cyan(&self.level.to_string()),
                added,
                removed,
            );
        }

        Ok(())
    }

    /// Extract all policy block names from the current source.
    pub fn extract_policy_names(&self) -> Vec<String> {
        let Ok(top_levels) = crate::policy::parse::parse(&self.source) else {
            return vec![self.current_policy.clone()];
        };
        top_levels
            .iter()
            .filter_map(|tl| {
                if let TopLevel::Policy { name, .. } = tl {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Run interactive REPL mode with reedline (line editing, history, tab completion).
    pub fn run_interactive(&mut self) -> Result<()> {
        use crate::shell_complete::{CompletionState, ShellCompleter, ShellPrompt};
        use reedline::{
            ColumnarMenu, DefaultHinter, Emacs, FileBackedHistory, KeyCode, KeyModifiers,
            MenuBuilder, Reedline, ReedlineEvent, ReedlineMenu, Signal, default_emacs_keybindings,
        };

        // Welcome banner
        println!(
            "{} {} policy editor {}",
            style::shield(),
            style::bold("clash"),
            style::dim(&format!("({})", self.level))
        );
        println!(
            "  Editing {} — type {} for commands, {} to save.\n",
            style::cyan(&format!("\"{}\"", self.current_policy)),
            style::cyan("help"),
            style::cyan("apply")
        );

        // Shared completion state
        let state = Arc::new(Mutex::new(CompletionState {
            policy_names: self.extract_policy_names(),
            current_policy: self.current_policy.clone(),
        }));

        let completer = Box::new(ShellCompleter::new(Arc::clone(&state)));
        let prompt = ShellPrompt::new(Arc::clone(&state));

        // Completion menu
        let menu = Box::new(
            ColumnarMenu::default()
                .with_name("completion_menu")
                .with_columns(4),
        );

        // Keybindings: Tab triggers completion menu
        let mut keybindings = default_emacs_keybindings();
        keybindings.add_binding(
            KeyModifiers::NONE,
            KeyCode::Tab,
            ReedlineEvent::UntilFound(vec![
                ReedlineEvent::Menu("completion_menu".to_string()),
                ReedlineEvent::MenuNext,
            ]),
        );
        keybindings.add_binding(
            KeyModifiers::SHIFT,
            KeyCode::BackTab,
            ReedlineEvent::MenuPrevious,
        );

        let edit_mode = Box::new(Emacs::new(keybindings));

        // History
        let history_path = crate::settings::ClashSettings::settings_dir()
            .map(|d| d.join("shell_history"))
            .ok();
        let history: Option<Box<FileBackedHistory>> =
            history_path.and_then(|p| FileBackedHistory::with_file(500, p).ok().map(Box::new));

        // Hinter (fish-style ghost text from history)
        let hinter = Box::new(
            DefaultHinter::default()
                .with_style(nu_ansi_term::Style::new().fg(nu_ansi_term::Color::DarkGray)),
        );

        // Build reedline
        let mut line_editor = Reedline::create()
            .with_completer(completer)
            .with_menu(ReedlineMenu::EngineCompleter(menu))
            .with_edit_mode(edit_mode)
            .with_hinter(hinter);

        if let Some(h) = history {
            line_editor = line_editor.with_history(h);
        }

        loop {
            match line_editor.read_line(&prompt) {
                Ok(Signal::Success(line)) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }

                    let cmd = match parse_command(trimmed) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("  {}: {e}", style::red("error"));
                            continue;
                        }
                    };

                    let output = match self.execute(cmd) {
                        Ok(o) => o,
                        Err(e) => {
                            eprintln!("  {}: {e}", style::red("error"));
                            continue;
                        }
                    };

                    // Refresh completion state after each command
                    if let Ok(mut s) = state.lock() {
                        s.policy_names = self.extract_policy_names();
                        s.current_policy = self.current_policy.clone();
                    }

                    match output {
                        ShellOutput::Message(msg) => {
                            if !msg.is_empty() {
                                println!("{msg}");
                            }
                        }
                        ShellOutput::DryRun(source) => {
                            print!("{source}");
                        }
                        ShellOutput::Exit { applied: false } => {
                            println!(
                                "  {} Aborted (no changes written).",
                                style::yellow_bold("!")
                            );
                            return Ok(());
                        }
                        ShellOutput::Exit { applied: true } | ShellOutput::ApplyAndExit { .. } => {
                            if let ShellOutput::ApplyAndExit { message } = output {
                                println!("{} {message}", style::green_bold("✓"));
                            }
                            return Ok(());
                        }
                    }
                }
                Ok(Signal::CtrlC) => {
                    println!(
                        "  {} Aborted (no changes written).",
                        style::yellow_bold("!")
                    );
                    return Ok(());
                }
                Ok(Signal::CtrlD) => {
                    println!();
                    // Drop the line editor so history is flushed before exiting
                    drop(line_editor);
                    return self.apply_and_exit();
                }
                Err(e) => {
                    eprintln!("  {}: {e}", style::red("error"));
                    return Ok(());
                }
            }
        }
    }

    fn apply_and_exit(&mut self) -> Result<()> {
        if self.source == self.original_source {
            println!("No changes.");
            return Ok(());
        }

        if self.dry_run {
            print!("{}", self.source);
            return Ok(());
        }

        if self.interactive && !self.confirm_apply()? {
            println!(
                "  {} Aborted (no changes written).",
                style::yellow_bold("!")
            );
            return Ok(());
        }

        self.write()?;
        let (added, removed) = self.count_changes();
        println!(
            "{} Wrote {} ({} added, {} removed)",
            style::green_bold("✓"),
            self.path.display(),
            added,
            removed,
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shell output
// ---------------------------------------------------------------------------

/// Output from a shell command execution.
#[derive(Debug)]
pub enum ShellOutput {
    /// A message to display.
    Message(String),
    /// Dry-run: print the policy source and stop.
    DryRun(String),
    /// Exit the shell.
    Exit { applied: bool },
    /// Apply changes and exit.
    ApplyAndExit { message: String },
}

// ---------------------------------------------------------------------------
// Rule parsing (reuses main.rs logic)
// ---------------------------------------------------------------------------

/// Parse a rule text: either full s-expr `(effect (matcher))` or `effect:verb` shortcut.
fn parse_rule_text(text: &str) -> Result<Vec<Rule>> {
    // Full s-expr with effect: (allow (exec "git" *))
    if text.starts_with('(') {
        let full = format!("(policy \"_\" {text})");
        let top_levels = crate::policy::parse::parse(&full).context("failed to parse rule")?;
        match top_levels.into_iter().next() {
            Some(TopLevel::Policy { mut body, .. }) => {
                let rules: Vec<Rule> = body
                    .drain(..)
                    .filter_map(|item| match item {
                        PolicyItem::Rule(r) => Some(r),
                        _ => None,
                    })
                    .collect();
                if rules.is_empty() {
                    bail!("no rule parsed from: {text}");
                }
                Ok(rules)
            }
            _ => bail!("unexpected parse result for: {text}"),
        }
    } else if let Some((effect_str, verb)) = text.split_once(':') {
        // effect:verb shortcut (allow:bash, deny:web, etc.)
        let effect = parse_effect(effect_str)?;
        parse_bare_verb(effect, verb)
    } else {
        bail!(
            "invalid rule: {text}\n\
             Expected: (effect (matcher ...)) or effect:verb"
        )
    }
}

/// Parse a bare verb into AST rules — mirrors `parse_cli_rule` in main.rs.
fn parse_bare_verb(effect: Effect, verb: &str) -> Result<Vec<Rule>> {
    use crate::policy::ast::*;

    match verb {
        "bash" => Ok(vec![
            Rule {
                effect,
                matcher: CapMatcher::Exec(ExecMatcher {
                    bin: Pattern::Any,
                    args: vec![],
                    has_args: vec![],
                }),
                sandbox: None,
            },
            Rule {
                effect,
                matcher: CapMatcher::Fs(FsMatcher {
                    op: OpPattern::Or(vec![FsOp::Read, FsOp::Write, FsOp::Create, FsOp::Delete]),
                    path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()))),
                }),
                sandbox: None,
            },
        ]),
        "edit" => Ok(vec![Rule {
            effect,
            matcher: CapMatcher::Fs(FsMatcher {
                op: OpPattern::Or(vec![FsOp::Write, FsOp::Create]),
                path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()))),
            }),
            sandbox: None,
        }]),
        "read" => Ok(vec![Rule {
            effect,
            matcher: CapMatcher::Fs(FsMatcher {
                op: OpPattern::Single(FsOp::Read),
                path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()))),
            }),
            sandbox: None,
        }]),
        "web" => Ok(vec![Rule {
            effect,
            matcher: CapMatcher::Net(NetMatcher {
                domain: Pattern::Any,
            }),
            sandbox: None,
        }]),
        "tool" => Ok(vec![Rule {
            effect,
            matcher: CapMatcher::Tool(ToolMatcher { name: Pattern::Any }),
            sandbox: None,
        }]),
        other => bail!(
            "unknown verb: {other}\n\
             Supported verbs: bash, edit, read, web, tool"
        ),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_source(level: PolicyLevel) -> Result<(PathBuf, String)> {
    let path = ClashSettings::policy_file_for_level(level)?;
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read policy file: {}", path.display()))?;
    Ok((path, source))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_add_sexpr() {
        let cmd = parse_command("add (allow (exec \"cargo\" *))").unwrap();
        assert!(matches!(cmd, ShellCommand::Add { policy: None, .. }));
    }

    #[test]
    fn parse_add_shortcut() {
        let cmd = parse_command("add allow:bash").unwrap();
        assert!(matches!(cmd, ShellCommand::Add { policy: None, .. }));
    }

    #[test]
    fn parse_add_with_policy() {
        let cmd = parse_command("add sandbox (allow (exec \"cargo\" *))").unwrap();
        assert!(matches!(
            cmd,
            ShellCommand::Add {
                policy: Some(ref p),
                ..
            } if p == "sandbox"
        ));
    }

    #[test]
    fn parse_remove() {
        let cmd = parse_command("remove (deny (exec \"npm\" *))").unwrap();
        assert!(matches!(cmd, ShellCommand::Remove { policy: None, .. }));
    }

    #[test]
    fn parse_default_cmd() {
        let cmd = parse_command("default allow main").unwrap();
        assert!(matches!(
            cmd,
            ShellCommand::Default {
                effect: Effect::Allow,
                policy: Some(ref p)
            } if p == "main"
        ));
    }

    #[test]
    fn parse_test_cmd() {
        let cmd = parse_command("test bash cargo build").unwrap();
        assert!(matches!(cmd, ShellCommand::Test { .. }));
        if let ShellCommand::Test { tool, args } = cmd {
            assert_eq!(tool, "bash");
            assert_eq!(args, vec!["cargo", "build"]);
        }
    }

    #[test]
    fn parse_use_cmd() {
        let cmd = parse_command("use sandbox").unwrap();
        assert!(matches!(cmd, ShellCommand::Use { .. }));
    }

    #[test]
    fn parse_comment_ignored() {
        assert!(parse_command("# this is a comment").is_err());
    }

    #[test]
    fn parse_empty_line_ignored() {
        assert!(parse_command("").is_err());
    }

    #[test]
    fn parse_unknown_command() {
        assert!(parse_command("foobar something").is_err());
    }

    #[test]
    fn parse_rule_text_sexpr() {
        let rules = parse_rule_text("(allow (exec \"cargo\" *))").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].effect, Effect::Allow);
    }

    #[test]
    fn parse_rule_text_shortcut() {
        let rules = parse_rule_text("allow:bash").unwrap();
        assert_eq!(rules.len(), 2); // exec + fs rules
    }

    #[test]
    fn parse_rule_text_invalid() {
        assert!(parse_rule_text("garbage").is_err());
    }
}
