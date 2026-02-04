//! Sandbox policy generation from profile constraints.
//!
//! Walks profile expression trees to collect `fs`, `caps`, and `network`
//! from referenced constraints, then generates sandbox rules for the
//! kernel-level sandbox (macOS Seatbelt / Linux Landlock).

use super::eval::resolve_path;
use super::ir::{CompiledFilterExpr, CompiledPolicy};
use super::*;
use crate::policy::sandbox_types::{
    Cap, NetworkPolicy, PathMatch, RuleEffect, SandboxPolicy, SandboxRule,
};

impl CompiledPolicy {
    /// Generate a sandbox policy from the profiles of matched allow statements.
    ///
    /// Walks each profile expression tree collecting `fs`, `caps`, and `network`
    /// from referenced constraints. Then generates sandbox rules from the `fs` filters.
    ///
    /// Composition rules:
    /// - `caps`: intersection (most restrictive wins)
    /// - `network`: deny wins over allow
    /// - `fs` rules: all collected into one sandbox rule list
    /// - No `fs` in any constraint → no sandbox generated
    pub(crate) fn generate_sandbox_from_profiles(
        &self,
        profiles: &[&ProfileExpr],
        cwd: &str,
    ) -> Option<SandboxPolicy> {
        let mut all_fs: Vec<(&CompiledFilterExpr, RuleEffect)> = Vec::new();
        let mut merged_caps: Option<Cap> = None;
        let mut merged_network = NetworkPolicy::Allow;

        for profile in profiles {
            self.collect_profile_sandbox_parts(
                profile,
                &mut all_fs,
                &mut merged_caps,
                &mut merged_network,
            );
        }

        // No fs constraints → no sandbox
        if all_fs.is_empty() {
            return None;
        }

        // Determine final caps for sandbox rules.
        // If no explicit caps were specified, use all caps.
        let final_caps = merged_caps.unwrap_or(Cap::all());

        // Generate sandbox rules from collected fs expressions.
        let mut rules = Vec::new();
        for (fs_expr, effect) in &all_fs {
            filter_to_sandbox_rules(fs_expr, *effect, final_caps, cwd, &mut rules);
        }

        // If all generated rules are Deny (from negation-only filters like
        // `!subpath($HOME/.ssh)`), the intent is "allow everything except these
        // paths". Grant the full requested caps as the default so writes/creates
        // aren't blocked. When there are explicit Allow rules, keep the
        // restrictive default so only allowlisted paths are writable.
        let default = if rules.iter().all(|r| r.effect == RuleEffect::Deny) {
            final_caps
        } else {
            Cap::READ | Cap::EXECUTE
        };

        Some(SandboxPolicy {
            default,
            rules,
            network: merged_network,
        })
    }

    /// Walk a profile expression tree collecting sandbox-relevant parts
    /// (fs filters, caps, network) from referenced constraints.
    fn collect_profile_sandbox_parts<'a>(
        &'a self,
        expr: &ProfileExpr,
        fs_exprs: &mut Vec<(&'a CompiledFilterExpr, RuleEffect)>,
        caps: &mut Option<Cap>,
        network: &mut NetworkPolicy,
    ) {
        match expr {
            ProfileExpr::Ref(name) => {
                // First check if it's a named profile (composite) — recurse
                if let Some(profile_expr) = self.profiles.get(name) {
                    self.collect_profile_sandbox_parts(profile_expr, fs_exprs, caps, network);
                    return;
                }
                // Then check if it's a named constraint (primitive)
                if let Some(constraint) = self.constraints.get(name) {
                    if let Some(ref fs) = constraint.fs {
                        fs_exprs.push((fs, RuleEffect::Allow));
                    }
                    if let Some(c) = constraint.caps {
                        // Intersection: most restrictive wins
                        *caps = Some(caps.map_or(c, |existing| existing & c));
                    }
                    if let Some(n) = constraint.network {
                        // Deny wins over allow
                        if n == NetworkPolicy::Deny {
                            *network = NetworkPolicy::Deny;
                        }
                    }
                }
            }
            ProfileExpr::And(a, b) => {
                self.collect_profile_sandbox_parts(a, fs_exprs, caps, network);
                self.collect_profile_sandbox_parts(b, fs_exprs, caps, network);
            }
            ProfileExpr::Or(a, b) => {
                self.collect_profile_sandbox_parts(a, fs_exprs, caps, network);
                self.collect_profile_sandbox_parts(b, fs_exprs, caps, network);
            }
            ProfileExpr::Not(inner) => {
                // For Not, we collect fs with flipped effect
                let mut inner_fs: Vec<(&CompiledFilterExpr, RuleEffect)> = Vec::new();
                self.collect_profile_sandbox_parts(inner, &mut inner_fs, caps, network);
                for (fs, effect) in inner_fs {
                    let flipped = match effect {
                        RuleEffect::Allow => RuleEffect::Deny,
                        RuleEffect::Deny => RuleEffect::Allow,
                    };
                    fs_exprs.push((fs, flipped));
                }
            }
        }
    }
}

/// Walk a `CompiledFilterExpr` tree and produce sandbox rules.
///
/// | FilterExpr          | SandboxRule                                              |
/// |---------------------|----------------------------------------------------------|
/// | Subpath(".")        | Allow <caps> in <resolved-cwd>, Subpath                  |
/// | Literal(".env")     | Allow <caps> in <resolved-path>, Literal                 |
/// | Regex(...)          | Allow <caps> matching <pattern>, Regex (macOS only)      |
/// | Not(inner)          | Flip effect: Allow↔Deny                                  |
/// | And(a, b) / Or(a,b) | Collect rules from both sides                            |
pub(crate) fn filter_to_sandbox_rules(
    expr: &CompiledFilterExpr,
    effect: RuleEffect,
    caps: Cap,
    cwd: &str,
    rules: &mut Vec<SandboxRule>,
) {
    match expr {
        CompiledFilterExpr::Subpath(base) => {
            let resolved = resolve_path(base, cwd);
            rules.push(SandboxRule {
                effect,
                caps,
                path: resolved.to_string_lossy().into_owned(),
                path_match: PathMatch::Subpath,
            });
        }
        CompiledFilterExpr::Literal(path) => {
            let resolved = resolve_path(path, cwd);
            rules.push(SandboxRule {
                effect,
                caps,
                path: resolved.to_string_lossy().into_owned(),
                path_match: PathMatch::Literal,
            });
        }
        CompiledFilterExpr::Regex(regex) => {
            rules.push(SandboxRule {
                effect,
                caps,
                path: regex.to_string(),
                path_match: PathMatch::Regex,
            });
        }
        CompiledFilterExpr::And(a, b) | CompiledFilterExpr::Or(a, b) => {
            filter_to_sandbox_rules(a, effect, caps, cwd, rules);
            filter_to_sandbox_rules(b, effect, caps, cwd, rules);
        }
        CompiledFilterExpr::Not(inner) => {
            let flipped = match effect {
                RuleEffect::Allow => RuleEffect::Deny,
                RuleEffect::Deny => RuleEffect::Allow,
            };
            filter_to_sandbox_rules(inner, flipped, caps, cwd, rules);
        }
    }
}
