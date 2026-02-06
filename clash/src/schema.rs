//! Self-describing schema for policy.yaml configuration.
//!
//! Provides a structured representation of every configurable section, field,
//! type, and default value in the policy format. Used by `clash policy schema`
//! to make the CLI self-documenting.

use serde::Serialize;

/// A single field in a configuration section.
#[derive(Debug, Clone, Serialize)]
pub struct SchemaField {
    /// YAML key name.
    pub key: &'static str,
    /// Human-readable type (e.g. "bool", "integer", "string", "enum", "object").
    #[serde(rename = "type")]
    pub type_name: &'static str,
    /// What this field does.
    pub description: &'static str,
    /// Default value, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    /// Valid values for enum types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<&'static str>>,
    /// Whether this field is required (no default).
    pub required: bool,
    /// Nested fields for object types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<SchemaField>>,
}

/// A top-level section of the policy.yaml.
#[derive(Debug, Clone, Serialize)]
pub struct SchemaSection {
    /// YAML key name (e.g. "default", "notifications").
    pub key: &'static str,
    /// What this section configures.
    pub description: &'static str,
    /// Fields in this section.
    pub fields: Vec<SchemaField>,
}

/// Description of the rule syntax.
#[derive(Debug, Clone, Serialize)]
pub struct RuleSyntax {
    /// Format string showing rule structure.
    pub format: &'static str,
    /// Available effects.
    pub effects: Vec<&'static str>,
    /// Available verbs (tool types).
    pub verbs: Vec<&'static str>,
    /// Available constraint types on rules.
    pub constraints: Vec<SchemaField>,
    /// Filter functions for filesystem constraints.
    pub fs_filters: Vec<SchemaField>,
    /// Filesystem capability names.
    pub capabilities: Vec<&'static str>,
}

/// Complete schema output.
#[derive(Debug, Clone, Serialize)]
pub struct PolicySchema {
    pub sections: Vec<SchemaSection>,
    pub rule_syntax: RuleSyntax,
}

// ---------------------------------------------------------------------------
// Schema registry — the single source of truth for all settings
// ---------------------------------------------------------------------------

/// Build the complete policy schema.
pub fn policy_schema() -> PolicySchema {
    PolicySchema {
        sections: vec![
            default_section(),
            notifications_section(),
            audit_section(),
            profiles_section(),
        ],
        rule_syntax: rule_syntax(),
    }
}

fn default_section() -> SchemaSection {
    SchemaSection {
        key: "default",
        description: "Default behavior when no policy rule matches a request",
        fields: vec![
            SchemaField {
                key: "permission",
                type_name: "enum",
                description: "Effect applied when no rule matches",
                default: Some(serde_json::json!("ask")),
                values: Some(vec!["ask", "allow", "deny"]),
                required: true,
                fields: None,
            },
            SchemaField {
                key: "profile",
                type_name: "string",
                description: "Name of the active profile to evaluate",
                default: None,
                values: None,
                required: true,
                fields: None,
            },
        ],
    }
}

fn notifications_section() -> SchemaSection {
    SchemaSection {
        key: "notifications",
        description: "How you get notified about permission prompts",
        fields: vec![
            SchemaField {
                key: "desktop",
                type_name: "bool",
                description: "Enable desktop notifications for permission prompts",
                default: Some(serde_json::json!(false)),
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "desktop_timeout_secs",
                type_name: "integer",
                description: "Seconds to wait for a response on desktop notification prompts",
                default: Some(serde_json::json!(120)),
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "zulip",
                type_name: "object",
                description: "Zulip bot for remote permission resolution — posts ask prompts to a Zulip stream and polls for approve/deny replies",
                default: None,
                values: None,
                required: false,
                fields: Some(vec![
                    SchemaField {
                        key: "server_url",
                        type_name: "string",
                        description: "Zulip server URL (e.g. https://your-org.zulipchat.com)",
                        default: None,
                        values: None,
                        required: true,
                        fields: None,
                    },
                    SchemaField {
                        key: "bot_email",
                        type_name: "string",
                        description: "Bot email address for API authentication",
                        default: None,
                        values: None,
                        required: true,
                        fields: None,
                    },
                    SchemaField {
                        key: "bot_api_key",
                        type_name: "string",
                        description: "Bot API key for authentication",
                        default: None,
                        values: None,
                        required: true,
                        fields: None,
                    },
                    SchemaField {
                        key: "stream",
                        type_name: "string",
                        description: "Zulip stream (channel) to post permission requests to",
                        default: None,
                        values: None,
                        required: true,
                        fields: None,
                    },
                    SchemaField {
                        key: "topic",
                        type_name: "string",
                        description: "Topic within the stream for permission messages",
                        default: Some(serde_json::json!("permissions")),
                        values: None,
                        required: false,
                        fields: None,
                    },
                    SchemaField {
                        key: "timeout_secs",
                        type_name: "integer",
                        description: "Seconds to wait for a Zulip response before giving up",
                        default: Some(serde_json::json!(120)),
                        values: None,
                        required: false,
                        fields: None,
                    },
                ]),
            },
        ],
    }
}

fn audit_section() -> SchemaSection {
    SchemaSection {
        key: "audit",
        description: "Audit logging — records every policy decision to a JSON Lines file",
        fields: vec![
            SchemaField {
                key: "enabled",
                type_name: "bool",
                description: "Enable audit logging",
                default: Some(serde_json::json!(false)),
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "path",
                type_name: "string",
                description: "Path to the audit log file",
                default: Some(serde_json::json!("~/.clash/audit.jsonl")),
                values: None,
                required: false,
                fields: None,
            },
        ],
    }
}

fn profiles_section() -> SchemaSection {
    SchemaSection {
        key: "profiles",
        description: "Named profiles containing policy rules — the active profile (set in default.profile) is evaluated on each request",
        fields: vec![
            SchemaField {
                key: "include",
                type_name: "list",
                description: "Parent profile(s) to inherit rules from",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "rules",
                type_name: "mapping",
                description: "Policy rules in 'effect verb noun' format (e.g. 'deny bash git push*')",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
        ],
    }
}

fn rule_syntax() -> RuleSyntax {
    RuleSyntax {
        format: "effect verb noun",
        effects: vec!["allow", "deny", "ask"],
        verbs: vec!["bash", "read", "write", "edit", "*"],
        constraints: vec![
            SchemaField {
                key: "fs",
                type_name: "mapping",
                description: "Filesystem constraints — keys are capability expressions, values are filter expressions",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "args",
                type_name: "list",
                description: "Argument restrictions — prefix with ! to forbid (e.g. '!--force'), otherwise requires at least one match",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "network",
                type_name: "enum",
                description: "Network access policy for sandboxed bash commands",
                default: Some(serde_json::json!("allow")),
                values: Some(vec!["allow", "deny"]),
                required: false,
                fields: None,
            },
            SchemaField {
                key: "pipe",
                type_name: "bool",
                description: "Whether pipe operators (|) are allowed in bash commands",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "redirect",
                type_name: "bool",
                description: "Whether I/O redirects (>, <, >>) are allowed in bash commands",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
        ],
        fs_filters: vec![
            SchemaField {
                key: "subpath(path)",
                type_name: "function",
                description: "Match files under a directory (e.g. subpath(~/.ssh), subpath(.))",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "literal(path)",
                type_name: "function",
                description: "Match an exact file path",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "regex(pattern)",
                type_name: "function",
                description: "Match paths by regular expression (e.g. regex(\\.env$))",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
        ],
        capabilities: vec!["read", "write", "create", "delete", "execute", "full"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_serializes_to_json() {
        let schema = policy_schema();
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(!json.is_empty());
        // Verify it's valid JSON by parsing it back.
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn schema_has_all_sections() {
        let schema = policy_schema();
        let keys: Vec<&str> = schema.sections.iter().map(|s| s.key).collect();
        assert!(keys.contains(&"default"), "missing 'default' section");
        assert!(
            keys.contains(&"notifications"),
            "missing 'notifications' section"
        );
        assert!(keys.contains(&"audit"), "missing 'audit' section");
        assert!(keys.contains(&"profiles"), "missing 'profiles' section");
    }

    #[test]
    fn notifications_section_includes_zulip() {
        let schema = policy_schema();
        let notif = schema
            .sections
            .iter()
            .find(|s| s.key == "notifications")
            .unwrap();
        let zulip = notif.fields.iter().find(|f| f.key == "zulip").unwrap();
        assert_eq!(zulip.type_name, "object");
        let zulip_fields = zulip.fields.as_ref().unwrap();
        let zulip_keys: Vec<&str> = zulip_fields.iter().map(|f| f.key).collect();
        assert!(zulip_keys.contains(&"server_url"));
        assert!(zulip_keys.contains(&"bot_email"));
        assert!(zulip_keys.contains(&"bot_api_key"));
        assert!(zulip_keys.contains(&"stream"));
        assert!(zulip_keys.contains(&"topic"));
        assert!(zulip_keys.contains(&"timeout_secs"));
    }

    #[test]
    fn notification_field_count_matches_config_struct() {
        // NotificationConfig has 3 fields: desktop, desktop_timeout_secs, zulip
        let schema = policy_schema();
        let notif = schema
            .sections
            .iter()
            .find(|s| s.key == "notifications")
            .unwrap();
        assert_eq!(
            notif.fields.len(),
            3,
            "NotificationConfig field count mismatch — did you add a field to the struct without updating the schema?"
        );
    }

    #[test]
    fn zulip_field_count_matches_config_struct() {
        // ZulipConfig has 6 fields: server_url, bot_email, bot_api_key, stream, topic, timeout_secs
        let schema = policy_schema();
        let notif = schema
            .sections
            .iter()
            .find(|s| s.key == "notifications")
            .unwrap();
        let zulip = notif.fields.iter().find(|f| f.key == "zulip").unwrap();
        let zulip_fields = zulip.fields.as_ref().unwrap();
        assert_eq!(
            zulip_fields.len(),
            6,
            "ZulipConfig field count mismatch — did you add a field to the struct without updating the schema?"
        );
    }

    #[test]
    fn audit_field_count_matches_config_struct() {
        // AuditConfig has 2 fields: enabled, path
        let schema = policy_schema();
        let audit = schema.sections.iter().find(|s| s.key == "audit").unwrap();
        assert_eq!(
            audit.fields.len(),
            2,
            "AuditConfig field count mismatch — did you add a field to the struct without updating the schema?"
        );
    }

    #[test]
    fn rule_syntax_has_all_effects_and_verbs() {
        let schema = policy_schema();
        assert_eq!(schema.rule_syntax.effects, vec!["allow", "deny", "ask"]);
        assert_eq!(
            schema.rule_syntax.verbs,
            vec!["bash", "read", "write", "edit", "*"]
        );
    }

    #[test]
    fn rule_syntax_has_all_constraint_types() {
        let schema = policy_schema();
        let constraint_keys: Vec<&str> = schema
            .rule_syntax
            .constraints
            .iter()
            .map(|c| c.key)
            .collect();
        assert!(constraint_keys.contains(&"fs"));
        assert!(constraint_keys.contains(&"args"));
        assert!(constraint_keys.contains(&"network"));
        assert!(constraint_keys.contains(&"pipe"));
        assert!(constraint_keys.contains(&"redirect"));
    }

    #[test]
    fn rule_syntax_has_all_capabilities() {
        let schema = policy_schema();
        assert_eq!(
            schema.rule_syntax.capabilities,
            vec!["read", "write", "create", "delete", "execute", "full"]
        );
    }
}
