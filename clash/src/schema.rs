//! Self-describing schema for the policy format.
//!
//! Provides a structured representation of the s-expression policy
//! language and companion YAML configuration. Used by `clash policy schema`
//! to make the CLI self-documenting.

use serde::Serialize;

/// A single field in a configuration section.
#[derive(Debug, Clone, Serialize)]
pub struct SchemaField {
    /// Key or syntax name.
    pub key: &'static str,
    /// Human-readable type (e.g. "bool", "integer", "string", "enum", "form").
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

/// A top-level section of the configuration.
#[derive(Debug, Clone, Serialize)]
pub struct SchemaSection {
    /// Section key.
    pub key: &'static str,
    /// What this section configures.
    pub description: &'static str,
    /// Fields in this section.
    pub fields: Vec<SchemaField>,
}

/// Description of the s-expression rule syntax.
#[derive(Debug, Clone, Serialize)]
pub struct RuleSyntax {
    /// Format string showing rule structure.
    pub format: &'static str,
    /// Available effects.
    pub effects: Vec<&'static str>,
    /// Capability domains.
    pub domains: Vec<SchemaField>,
    /// Pattern types used in matchers.
    pub patterns: Vec<SchemaField>,
    /// Path filter types for fs rules.
    pub path_filters: Vec<SchemaField>,
    /// Filesystem operation names.
    pub fs_operations: Vec<&'static str>,
}

/// Complete schema output.
#[derive(Debug, Clone, Serialize)]
pub struct PolicySchema {
    pub sections: Vec<SchemaSection>,
    pub rule_syntax: RuleSyntax,
}

// ---------------------------------------------------------------------------
// Schema registry
// ---------------------------------------------------------------------------

/// Build the complete policy schema.
pub fn policy_schema() -> PolicySchema {
    PolicySchema {
        sections: vec![policy_section(), notifications_section(), audit_section()],
        rule_syntax: rule_syntax(),
    }
}

fn policy_section() -> SchemaSection {
    SchemaSection {
        key: "policy",
        description: "S-expression policy file (policy.sexpr) — defines rules using (effect (capability ...)) forms",
        fields: vec![
            SchemaField {
                key: "(default effect \"policy-name\")",
                type_name: "form",
                description: "Sets the default effect (allow/deny/ask) and names the active policy",
                default: Some(serde_json::json!("(default deny \"main\")")),
                values: None,
                required: true,
                fields: None,
            },
            SchemaField {
                key: "(policy \"name\" ...rules)",
                type_name: "form",
                description: "A named policy block containing rules and (include ...) directives",
                default: None,
                values: None,
                required: true,
                fields: None,
            },
            SchemaField {
                key: "(include \"other-policy\")",
                type_name: "form",
                description: "Import rules from another policy block by name",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
        ],
    }
}

fn notifications_section() -> SchemaSection {
    SchemaSection {
        key: "notifications",
        description: "How you get notified about permission prompts (configured in companion policy.yaml)",
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
        description: "Audit logging — records every policy decision to a JSON Lines file (configured in companion policy.yaml)",
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

fn rule_syntax() -> RuleSyntax {
    RuleSyntax {
        format: "(effect (capability ...))",
        effects: vec!["allow", "deny", "ask"],
        domains: vec![
            SchemaField {
                key: "exec",
                type_name: "capability",
                description: "Command execution: (exec [binary] [args...]). Matches Bash tool invocations.",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "fs",
                type_name: "capability",
                description: "Filesystem access: (fs [operation] [path-filter]). Matches Read, Write, Edit, Glob, Grep tools.",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "net",
                type_name: "capability",
                description: "Network access: (net [domain-pattern]). Matches WebFetch and WebSearch tools.",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
        ],
        patterns: vec![
            SchemaField {
                key: "*",
                type_name: "pattern",
                description: "Wildcard — matches anything",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "\"literal\"",
                type_name: "pattern",
                description: "Exact string match (quoted)",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "/regex/",
                type_name: "pattern",
                description: "Regular expression match",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "(or p1 p2 ...)",
                type_name: "combinator",
                description: "Match any of the listed patterns",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "(not p)",
                type_name: "combinator",
                description: "Negate a pattern",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
        ],
        path_filters: vec![
            SchemaField {
                key: "(subpath expr)",
                type_name: "filter",
                description: "Recursive subtree match. expr can be \"path\" or (env VAR).",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "\"path\"",
                type_name: "filter",
                description: "Exact file path match (quoted)",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
            SchemaField {
                key: "/regex/",
                type_name: "filter",
                description: "Regex match on resolved path",
                default: None,
                values: None,
                required: false,
                fields: None,
            },
        ],
        fs_operations: vec!["read", "write", "create", "delete"],
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
        assert!(keys.contains(&"policy"), "missing 'policy' section");
        assert!(
            keys.contains(&"notifications"),
            "missing 'notifications' section"
        );
        assert!(keys.contains(&"audit"), "missing 'audit' section");
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
    fn rule_syntax_has_all_effects() {
        let schema = policy_schema();
        assert_eq!(schema.rule_syntax.effects, vec!["allow", "deny", "ask"]);
    }

    #[test]
    fn rule_syntax_has_all_domains() {
        let schema = policy_schema();
        let domain_keys: Vec<&str> = schema.rule_syntax.domains.iter().map(|d| d.key).collect();
        assert!(domain_keys.contains(&"exec"));
        assert!(domain_keys.contains(&"fs"));
        assert!(domain_keys.contains(&"net"));
    }

    #[test]
    fn rule_syntax_has_all_fs_operations() {
        let schema = policy_schema();
        assert_eq!(
            schema.rule_syntax.fs_operations,
            vec!["read", "write", "create", "delete"]
        );
    }
}
