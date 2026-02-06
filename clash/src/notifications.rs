use serde::Deserialize;
use tracing::{info, warn};

fn default_timeout_secs() -> u64 {
    120
}

// ---------------------------------------------------------------------------
// Configuration types (parsed from policy.yaml root-level `notifications:` key)
// ---------------------------------------------------------------------------

/// Top-level notification configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationConfig {
    /// Enable desktop notifications for permission prompts and idle events.
    #[serde(default)]
    pub desktop: bool,

    /// Timeout in seconds for interactive desktop notification prompts.
    #[serde(default = "default_timeout_secs")]
    pub desktop_timeout_secs: u64,

    /// Zulip bot configuration for remote permission resolution.
    #[serde(default)]
    pub zulip: Option<ZulipConfig>,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            desktop: false,
            desktop_timeout_secs: default_timeout_secs(),
            zulip: None,
        }
    }
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
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_topic() -> String {
    "permissions".into()
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

// ---------------------------------------------------------------------------
// Keyword constants for approval/denial matching
// ---------------------------------------------------------------------------

/// Keywords that trigger approval when found anywhere in the message (substring match).
const APPROVE_KEYWORDS: &[&str] = &["approve", "allow"];
/// Keywords that trigger approval only when they are the entire message (exact match).
const APPROVE_EXACT: &[&str] = &["yes", "y"];

/// Keywords that trigger denial when found anywhere in the message (substring match).
const DENY_KEYWORDS: &[&str] = &["deny", "reject"];
/// Keywords that trigger denial only when they are the entire message (exact match).
const DENY_EXACT: &[&str] = &["no", "n"];

/// Check whether `content` (already lowercased and trimmed) is an approval response.
fn is_approval_response(content: &str) -> bool {
    APPROVE_KEYWORDS.iter().any(|kw| content.contains(kw)) || APPROVE_EXACT.contains(&content)
}

/// Check whether `content` (already lowercased and trimmed) is a denial response.
fn is_denial_response(content: &str) -> bool {
    DENY_KEYWORDS.iter().any(|kw| content.contains(kw)) || DENY_EXACT.contains(&content)
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

    /// Return the `Authorization` header value for HTTP Basic auth.
    fn auth_header(&self) -> String {
        format!(
            "Basic {}",
            base64_auth(&self.config.bot_email, &self.config.bot_api_key)
        )
    }

    /// Return the Zulip messages API endpoint URL.
    fn messages_url(&self) -> String {
        format!(
            "{}/api/v1/messages",
            self.config.server_url.trim_end_matches('/')
        )
    }

    /// Post a message to the configured stream/topic. Returns the message ID.
    fn send_message(&self, content: &str) -> anyhow::Result<u64> {
        let url = self.messages_url();
        let auth_header = self.auth_header();

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
        let url = self.messages_url();
        let auth_header = self.auth_header();

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

                if is_approval_response(content) {
                    info!(
                        sender = sender_email,
                        msg_id, "Permission approved via Zulip"
                    );
                    return Ok(Some(PermissionResponse::Approve));
                }

                if is_denial_response(content) {
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
    let noun = crate::permissions::extract_noun(&request.tool_name, &request.tool_input);

    let tool_detail = match request.tool_name.as_str() {
        "Bash" => format!("**Command:** `{}`", noun),
        "Read" | "Write" | "Edit" => format!("**File:** `{}`", noun),
        _ => format!("**Resource:** `{}`", noun),
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
        assert!(msg.contains("**Resource:** `customtool`"));
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

    // -----------------------------------------------------------------------
    // HTTP integration tests using mockito
    // -----------------------------------------------------------------------

    /// Create a ZulipConfig pointing at the given mock server URL.
    fn mock_zulip_config(server_url: &str, timeout_secs: u64) -> ZulipConfig {
        ZulipConfig {
            server_url: server_url.to_string(),
            bot_email: "bot@example.com".to_string(),
            bot_api_key: "test-api-key".to_string(),
            stream: "test-stream".to_string(),
            topic: "permissions".to_string(),
            timeout_secs,
        }
    }

    /// Create a sample permission request for tests.
    fn sample_permission_request() -> PermissionRequest {
        PermissionRequest {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({"command": "ls -la"}),
            session_id: "test-session-123".into(),
            cwd: "/tmp/test".into(),
        }
    }

    #[test]
    fn test_send_message_returns_message_id() {
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 120);
        let client = ZulipClient::new(&config);

        let mock = server
            .mock("POST", "/api/v1/messages")
            .match_header(
                "Authorization",
                mockito::Matcher::Regex("^Basic .+".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id": 42, "result": "success"}"#)
            .create();

        let msg_id = client.send_message("Hello, world!").unwrap();
        assert_eq!(msg_id, 42);
        mock.assert();
    }

    #[test]
    fn test_send_message_propagates_http_error() {
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 120);
        let client = ZulipClient::new(&config);

        let mock = server
            .mock("POST", "/api/v1/messages")
            .with_status(401)
            .with_body(r#"{"result": "error", "msg": "Invalid API key"}"#)
            .create();

        let result = client.send_message("Hello");
        assert!(result.is_err());
        mock.assert();
    }

    #[test]
    fn test_send_message_errors_on_missing_id() {
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 120);
        let client = ZulipClient::new(&config);

        let mock = server
            .mock("POST", "/api/v1/messages")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result": "success"}"#)
            .create();

        let result = client.send_message("Hello");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("did not return a message id"),
            "unexpected error: {}",
            err_msg
        );
        mock.assert();
    }

    #[test]
    fn test_check_for_response_approve() {
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 120);
        let client = ZulipClient::new(&config);

        let mock = server
            .mock("GET", "/api/v1/messages")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("anchor".to_string(), "100".to_string()),
                mockito::Matcher::UrlEncoded("num_before".to_string(), "0".to_string()),
                mockito::Matcher::UrlEncoded("num_after".to_string(), "100".to_string()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "result": "success",
                    "messages": [
                        {
                            "id": 101,
                            "sender_email": "user@example.com",
                            "content": "approve"
                        }
                    ]
                })
                .to_string(),
            )
            .create();

        let response = client.check_for_response(100).unwrap();
        assert!(response.is_some());
        assert!(matches!(response.unwrap(), PermissionResponse::Approve));
        mock.assert();
    }

    #[test]
    fn test_check_for_response_deny() {
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 120);
        let client = ZulipClient::new(&config);

        let mock = server
            .mock("GET", "/api/v1/messages")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("anchor".to_string(), "100".to_string()),
                mockito::Matcher::UrlEncoded("num_before".to_string(), "0".to_string()),
                mockito::Matcher::UrlEncoded("num_after".to_string(), "100".to_string()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "result": "success",
                    "messages": [
                        {
                            "id": 101,
                            "sender_email": "user@example.com",
                            "content": "deny"
                        }
                    ]
                })
                .to_string(),
            )
            .create();

        let response = client.check_for_response(100).unwrap();
        assert!(response.is_some());
        match response.unwrap() {
            PermissionResponse::Deny(reason) => {
                assert!(
                    reason.contains("user@example.com"),
                    "deny reason should include sender: {}",
                    reason
                );
            }
            PermissionResponse::Approve => panic!("Expected Deny, got Approve"),
        }
        mock.assert();
    }

    #[test]
    fn test_check_for_response_no_relevant_messages() {
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 120);
        let client = ZulipClient::new(&config);

        // Return messages, but only from the bot itself (should be skipped)
        // and messages at or before the anchor (should be skipped).
        let mock = server
            .mock("GET", "/api/v1/messages")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "result": "success",
                    "messages": [
                        {
                            "id": 100,
                            "sender_email": "bot@example.com",
                            "content": "Permission Request..."
                        },
                        {
                            "id": 99,
                            "sender_email": "user@example.com",
                            "content": "approve"
                        }
                    ]
                })
                .to_string(),
            )
            .create();

        let response = client.check_for_response(100).unwrap();
        assert!(response.is_none());
        mock.assert();
    }

    #[test]
    fn test_check_for_response_empty_messages() {
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 120);
        let client = ZulipClient::new(&config);

        let mock = server
            .mock("GET", "/api/v1/messages")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "result": "success",
                    "messages": []
                })
                .to_string(),
            )
            .create();

        let response = client.check_for_response(100).unwrap();
        assert!(response.is_none());
        mock.assert();
    }

    #[test]
    fn test_check_for_response_skips_bot_messages() {
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 120);
        let client = ZulipClient::new(&config);

        // Bot message with "approve" should be ignored; only user messages count.
        let mock = server
            .mock("GET", "/api/v1/messages")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "result": "success",
                    "messages": [
                        {
                            "id": 101,
                            "sender_email": "bot@example.com",
                            "content": "approve"
                        }
                    ]
                })
                .to_string(),
            )
            .create();

        let response = client.check_for_response(100).unwrap();
        assert!(response.is_none());
        mock.assert();
    }

    #[test]
    fn test_check_for_response_ignores_irrelevant_content() {
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 120);
        let client = ZulipClient::new(&config);

        // A user message that doesn't match any approve/deny keywords.
        let mock = server
            .mock("GET", "/api/v1/messages")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "result": "success",
                    "messages": [
                        {
                            "id": 101,
                            "sender_email": "user@example.com",
                            "content": "What is this about?"
                        }
                    ]
                })
                .to_string(),
            )
            .create();

        let response = client.check_for_response(100).unwrap();
        assert!(response.is_none());
        mock.assert();
    }

    #[test]
    fn test_check_for_response_various_approve_keywords() {
        // Test all the different approval keywords: "approve", "allow", "yes", "y"
        for keyword in &["approve", "allow", "yes", "y"] {
            let mut server = mockito::Server::new();
            let config = mock_zulip_config(&server.url(), 120);
            let client = ZulipClient::new(&config);

            let mock = server
                .mock("GET", "/api/v1/messages")
                .match_query(mockito::Matcher::Any)
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    serde_json::json!({
                        "result": "success",
                        "messages": [
                            {
                                "id": 101,
                                "sender_email": "user@example.com",
                                "content": keyword
                            }
                        ]
                    })
                    .to_string(),
                )
                .create();

            let response = client.check_for_response(100).unwrap();
            assert!(
                matches!(response, Some(PermissionResponse::Approve)),
                "keyword '{}' should be recognized as approval",
                keyword
            );
            mock.assert();
        }
    }

    #[test]
    fn test_check_for_response_various_deny_keywords() {
        // Test all the different denial keywords: "deny", "reject", "no", "n"
        for keyword in &["deny", "reject", "no", "n"] {
            let mut server = mockito::Server::new();
            let config = mock_zulip_config(&server.url(), 120);
            let client = ZulipClient::new(&config);

            let mock = server
                .mock("GET", "/api/v1/messages")
                .match_query(mockito::Matcher::Any)
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    serde_json::json!({
                        "result": "success",
                        "messages": [
                            {
                                "id": 101,
                                "sender_email": "user@example.com",
                                "content": keyword
                            }
                        ]
                    })
                    .to_string(),
                )
                .create();

            let response = client.check_for_response(100).unwrap();
            assert!(
                matches!(response, Some(PermissionResponse::Deny(_))),
                "keyword '{}' should be recognized as denial",
                keyword
            );
            mock.assert();
        }
    }

    #[test]
    fn test_resolve_permission_timeout() {
        // Use timeout_secs=0 so resolve_permission returns None immediately
        // without entering the polling loop.
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 0);
        let client = ZulipClient::new(&config);

        let mock_post = server
            .mock("POST", "/api/v1/messages")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id": 42, "result": "success"}"#)
            .create();

        let request = sample_permission_request();
        let result = client.resolve_permission(&request).unwrap();
        assert!(result.is_none(), "Expected None (timeout), got a response");
        mock_post.assert();
    }

    #[test]
    fn test_resolve_permission_approve_end_to_end() {
        // Use timeout_secs=10 to allow one poll cycle (sleep 2s then poll).
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 10);
        let client = ZulipClient::new(&config);

        // Mock the initial POST to send the message.
        let mock_post = server
            .mock("POST", "/api/v1/messages")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id": 42, "result": "success"}"#)
            .create();

        // Mock the GET poll to return an approval.
        let mock_get = server
            .mock("GET", "/api/v1/messages")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "result": "success",
                    "messages": [
                        {
                            "id": 43,
                            "sender_email": "reviewer@example.com",
                            "content": "approve"
                        }
                    ]
                })
                .to_string(),
            )
            .create();

        let request = sample_permission_request();
        let result = client.resolve_permission(&request).unwrap();
        assert!(matches!(result, Some(PermissionResponse::Approve)));
        mock_post.assert();
        mock_get.assert();
    }

    #[test]
    fn test_resolve_permission_deny_end_to_end() {
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 10);
        let client = ZulipClient::new(&config);

        let mock_post = server
            .mock("POST", "/api/v1/messages")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id": 42, "result": "success"}"#)
            .create();

        let mock_get = server
            .mock("GET", "/api/v1/messages")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "result": "success",
                    "messages": [
                        {
                            "id": 43,
                            "sender_email": "reviewer@example.com",
                            "content": "deny"
                        }
                    ]
                })
                .to_string(),
            )
            .create();

        let request = sample_permission_request();
        let result = client.resolve_permission(&request).unwrap();
        match result {
            Some(PermissionResponse::Deny(reason)) => {
                assert!(reason.contains("reviewer@example.com"));
            }
            other => panic!("Expected Some(Deny), got {:?}", other.map(|_| "something")),
        }
        mock_post.assert();
        mock_get.assert();
    }

    #[test]
    fn test_resolve_permission_send_failure() {
        let mut server = mockito::Server::new();
        let config = mock_zulip_config(&server.url(), 10);
        let client = ZulipClient::new(&config);

        // The POST fails, so resolve_permission should propagate the error.
        let mock_post = server
            .mock("POST", "/api/v1/messages")
            .with_status(500)
            .with_body(r#"{"result": "error", "msg": "Internal error"}"#)
            .create();

        let request = sample_permission_request();
        let result = client.resolve_permission(&request);
        assert!(result.is_err());
        mock_post.assert();
    }
}
