use serde::Deserialize;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Configuration types (parsed from policy.yaml root-level `notifications:` key)
// ---------------------------------------------------------------------------

/// Top-level notification configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NotificationConfig {
    /// Enable desktop notifications for permission prompts and idle events.
    #[serde(default)]
    pub desktop: bool,

    /// Zulip bot configuration for remote permission resolution.
    #[serde(default)]
    pub zulip: Option<ZulipConfig>,
}

/// Zulip bot configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ZulipConfig {
    /// Zulip server URL (e.g., "https://your-org.zulipchat.com").
    pub server_url: String,
    /// Bot email address.
    pub bot_email: String,
    /// Bot API key.
    pub bot_api_key: String,
    /// Stream (channel) to post messages to.
    pub stream: String,
    /// Topic within the stream.
    #[serde(default = "default_topic")]
    pub topic: String,
    /// Timeout in seconds to wait for a Zulip response on permission requests.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_topic() -> String {
    "permissions".into()
}

fn default_timeout() -> u64 {
    120
}

// ---------------------------------------------------------------------------
// Desktop notifications (cross-platform)
// ---------------------------------------------------------------------------

/// Send a desktop notification. Errors are logged but never propagated.
pub fn send_desktop_notification(title: &str, message: &str) {
    info!(title, message, "Sending desktop notification");

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::time::Duration;

        match notify_rust::Notification::new()
            .auto_icon()
            .action("allow", "allow")
            .action("deny", "deny")
            .summary(title)
            .timeout(Duration::from_secs(10))
            .body(message)
            .show()
        {
            Ok(_resp) => {}
            Err(e) => warn!(error = %e, "Failed to send desktop notification"),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (title, message);
        warn!("Desktop notifications not supported on this platform");
    }
}

// ---------------------------------------------------------------------------
// Zulip bot client
// ---------------------------------------------------------------------------

/// Details of a permission request, passed to external resolvers.
pub struct PermissionRequest {
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub session_id: String,
    pub cwd: String,
}

/// Response from an external permission resolver.
pub enum PermissionResponse {
    Approve,
    Deny(String),
}

/// Synchronous Zulip API client.
pub struct ZulipClient<'a> {
    config: &'a ZulipConfig,
}

impl<'a> ZulipClient<'a> {
    pub fn new(config: &'a ZulipConfig) -> Self {
        Self { config }
    }

    /// Send a permission request to Zulip and poll for a user response.
    ///
    /// Returns `Some(PermissionResponse)` if a user responds before the timeout,
    /// or `None` if the timeout elapses without a response.
    pub fn resolve_permission(
        &self,
        request: &PermissionRequest,
    ) -> anyhow::Result<Option<PermissionResponse>> {
        let message = format_permission_message(request);
        let msg_id = self.send_message(&message)?;

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(self.config.timeout_secs);
        let poll_interval = std::time::Duration::from_secs(2);

        while start.elapsed() < timeout {
            std::thread::sleep(poll_interval);

            match self.check_for_response(msg_id) {
                Ok(Some(response)) => return Ok(Some(response)),
                Ok(None) => continue,
                Err(e) => {
                    warn!(error = %e, "Error polling Zulip for response");
                    // Keep polling despite transient errors.
                    continue;
                }
            }
        }

        info!(
            timeout_secs = self.config.timeout_secs,
            "Zulip permission request timed out"
        );
        Ok(None)
    }

    // -- internal helpers --

    /// Post a message to the configured stream/topic. Returns the message ID.
    fn send_message(&self, content: &str) -> anyhow::Result<u64> {
        let url = format!(
            "{}/api/v1/messages",
            self.config.server_url.trim_end_matches('/')
        );
        let auth_header = format!(
            "Basic {}",
            base64_auth(&self.config.bot_email, &self.config.bot_api_key)
        );

        let resp = ureq::post(&url)
            .set("Authorization", &auth_header)
            .send_form(&[
                ("type", "stream"),
                ("to", &self.config.stream),
                ("topic", &self.config.topic),
                ("content", content),
            ])?;

        let body = resp.into_string()?;
        let json: serde_json::Value = serde_json::from_str(&body)?;

        let msg_id = json["id"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Zulip API did not return a message id: {}", body))?;

        info!(msg_id, stream = %self.config.stream, topic = %self.config.topic, "Sent Zulip message");
        Ok(msg_id)
    }

    /// Poll for new messages in the topic after `after_msg_id`.
    fn check_for_response(&self, after_msg_id: u64) -> anyhow::Result<Option<PermissionResponse>> {
        let url = format!(
            "{}/api/v1/messages",
            self.config.server_url.trim_end_matches('/')
        );
        let auth_header = format!(
            "Basic {}",
            base64_auth(&self.config.bot_email, &self.config.bot_api_key)
        );

        let narrow = serde_json::json!([
            {"operator": "stream", "operand": &self.config.stream},
            {"operator": "topic", "operand": &self.config.topic},
        ]);

        let resp = ureq::get(&url)
            .set("Authorization", &auth_header)
            .query("anchor", &after_msg_id.to_string())
            .query("num_before", "0")
            .query("num_after", "100")
            .query("narrow", &narrow.to_string())
            .call()?;

        let body = resp.into_string()?;
        let json: serde_json::Value = serde_json::from_str(&body)?;

        if let Some(messages) = json["messages"].as_array() {
            for msg in messages {
                // Skip our own bot messages.
                let sender_email = msg["sender_email"].as_str().unwrap_or("");
                if sender_email == self.config.bot_email {
                    continue;
                }

                // Skip the anchor message itself and anything before it.
                let msg_id = msg["id"].as_u64().unwrap_or(0);
                if msg_id <= after_msg_id {
                    continue;
                }

                let content = msg["content"].as_str().unwrap_or("").to_lowercase();
                let content = content.trim();

                if content.contains("approve")
                    || content.contains("allow")
                    || content == "yes"
                    || content == "y"
                {
                    info!(
                        sender = sender_email,
                        msg_id, "Permission approved via Zulip"
                    );
                    return Ok(Some(PermissionResponse::Approve));
                }

                if content.contains("deny")
                    || content.contains("reject")
                    || content == "no"
                    || content == "n"
                {
                    let reason = format!("Denied via Zulip by {}", sender_email);
                    info!(sender = sender_email, msg_id, "Permission denied via Zulip");
                    return Ok(Some(PermissionResponse::Deny(reason)));
                }
            }
        }

        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format a permission request as a Zulip-friendly markdown message.
fn format_permission_message(request: &PermissionRequest) -> String {
    let tool_detail = match request.tool_name.as_str() {
        "Bash" => {
            let command = request.tool_input["command"]
                .as_str()
                .unwrap_or("(unknown)");
            format!("**Command:** `{}`", command)
        }
        "Read" | "Write" | "Edit" => {
            let path = request.tool_input["file_path"]
                .as_str()
                .unwrap_or("(unknown)");
            format!("**File:** `{}`", path)
        }
        _ => {
            format!(
                "**Input:**\n```json\n{}\n```",
                serde_json::to_string_pretty(&request.tool_input).unwrap_or_default()
            )
        }
    };

    format!(
        "**Permission Request**\n\n\
         **Tool:** {}\n\
         {}\n\
         **CWD:** `{}`\n\
         **Session:** `{}`\n\n\
         Reply **approve** or **deny**.",
        request.tool_name, tool_detail, request.cwd, request.session_id,
    )
}

/// Base64-encode `email:api_key` for HTTP Basic auth.
fn base64_auth(email: &str, api_key: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", email, api_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_permission_message_bash() {
        let req = PermissionRequest {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({"command": "rm -rf /tmp/test"}),
            session_id: "sess-123".into(),
            cwd: "/home/user/project".into(),
        };
        let msg = format_permission_message(&req);
        assert!(msg.contains("**Tool:** Bash"));
        assert!(msg.contains("**Command:** `rm -rf /tmp/test`"));
        assert!(msg.contains("**Session:** `sess-123`"));
        assert!(msg.contains("approve"));
        assert!(msg.contains("deny"));
    }

    #[test]
    fn test_format_permission_message_read() {
        let req = PermissionRequest {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({"file_path": "/etc/passwd"}),
            session_id: "sess-456".into(),
            cwd: "/home/user".into(),
        };
        let msg = format_permission_message(&req);
        assert!(msg.contains("**Tool:** Read"));
        assert!(msg.contains("**File:** `/etc/passwd`"));
    }

    #[test]
    fn test_format_permission_message_unknown_tool() {
        let req = PermissionRequest {
            tool_name: "CustomTool".into(),
            tool_input: serde_json::json!({"key": "value"}),
            session_id: "sess-789".into(),
            cwd: "/tmp".into(),
        };
        let msg = format_permission_message(&req);
        assert!(msg.contains("**Tool:** CustomTool"));
        assert!(msg.contains("**Input:**"));
    }

    #[test]
    fn test_base64_auth() {
        let encoded = base64_auth("bot@example.com", "secret123");
        // base64("bot@example.com:secret123")
        assert!(!encoded.is_empty());

        // Decode and verify
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            "bot@example.com:secret123"
        );
    }

    #[test]
    fn test_notification_config_defaults() {
        let config: NotificationConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.desktop);
        assert!(config.zulip.is_none());
    }

    #[test]
    fn test_notification_config_full() {
        let json = r#"{
            "desktop": true,
            "zulip": {
                "server_url": "https://chat.example.com",
                "bot_email": "bot@example.com",
                "bot_api_key": "abc123",
                "stream": "clash",
                "topic": "perms",
                "timeout_secs": 60
            }
        }"#;
        let config: NotificationConfig = serde_json::from_str(json).unwrap();
        assert!(config.desktop);
        let zulip = config.zulip.unwrap();
        assert_eq!(zulip.server_url, "https://chat.example.com");
        assert_eq!(zulip.bot_email, "bot@example.com");
        assert_eq!(zulip.bot_api_key, "abc123");
        assert_eq!(zulip.stream, "clash");
        assert_eq!(zulip.topic, "perms");
        assert_eq!(zulip.timeout_secs, 60);
    }

    #[test]
    fn test_zulip_config_defaults() {
        let json = r#"{
            "server_url": "https://chat.example.com",
            "bot_email": "bot@example.com",
            "bot_api_key": "abc123",
            "stream": "clash"
        }"#;
        let config: ZulipConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.topic, "permissions");
        assert_eq!(config.timeout_secs, 120);
    }
}
