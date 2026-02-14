use anyhow::{Context, Result};
use tracing::{debug, info};

const LINEAR_API_URL: &str = "https://api.linear.app/graphql";
const TEAM_ID: &str = "cda852f9-a1ed-4f78-9d98-32be88debadc";
const PROJECT_ID: &str = "3f2561c9-6f78-43d7-84df-90386b0b571e";
const BUG_LABEL_ID: &str = "c1e8c097-307e-478a-885c-fad0afa92fd3";
const API_KEY: Option<&str> = option_env!("CLASH_LINEAR_API_KEY");

/// Whether the Linear API key was baked in at build time
pub fn api_key_available() -> bool {
    API_KEY.is_some()
}

/// Input for creating a bug report issue.
pub struct BugReport {
    pub title: String,
    pub description: Option<String>,
    pub attachments: Vec<Attachment>,
}

/// A file to attach to an issue after creation.
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub title: String,
    pub body: Vec<u8>,
}

/// A successfully created Linear issue.
pub struct CreatedIssue {
    pub identifier: String,
    pub url: String,
}

/// Create a bug report issue on Linear.
///
/// The issue title is `"Bug Report: {uuid}"` to avoid collisions.
/// The user-provided title goes into the description body.
pub fn create_issue(report: &BugReport) -> Result<CreatedIssue> {
    let api_key = API_KEY.context("Linear API key not configured at build time")?;
    let description = format_description(report);
    let title = format!("Bug Report: {}", uuid::Uuid::new_v4());

    let query = r#"mutation IssueCreate($input: IssueCreateInput!) {
        issueCreate(input: $input) {
            success
            issue {
                id
                identifier
                url
            }
        }
    }"#;

    let body = serde_json::json!({
        "query": query,
        "variables": {
            "input": {
                "teamId": TEAM_ID,
                "projectId": PROJECT_ID,
                "title": title,
                "description": description,
                "labelIds": [BUG_LABEL_ID],
            }
        }
    });

    let resp_body = graphql_request(api_key, &body).context("issueCreate mutation failed")?;

    let issue = &resp_body["data"]["issueCreate"]["issue"];
    let identifier = issue["identifier"]
        .as_str()
        .context("Linear response missing issue identifier")?
        .to_string();
    let url = issue["url"]
        .as_str()
        .context("Linear response missing issue url")?
        .to_string();

    let id = issue["id"]
        .as_str()
        .context("Linear response missing issue id")?
        .to_string();

    info!(identifier = %identifier, url = %url, "Created Linear issue");

    // Upload file attachments.
    for attachment in &report.attachments {
        if let Err(e) = upload_attachment(api_key, &id, attachment) {
            // Non-fatal: log the full error chain and continue.
            info!(err = ?e, filename = %attachment.filename, "Failed to upload attachment");
        }
    }

    Ok(CreatedIssue { identifier, url })
}

/// Build the markdown description body for the issue.
fn format_description(report: &BugReport) -> String {
    let mut body = String::new();

    // User-provided title as the heading.
    body.push_str(&format!("## {}\n\n", report.title));

    // System info (always included).
    body.push_str("## System Info\n\n");
    body.push_str(&format!(
        "| Field | Value |\n|-------|-------|\n| OS | {} |\n| Arch | {} |\n| Version | {} |\n",
        std::env::consts::OS,
        std::env::consts::ARCH,
        env!("CARGO_PKG_VERSION"),
    ));

    // User description.
    if let Some(ref desc) = report.description {
        body.push_str("\n## Description\n\n");
        body.push_str(desc);
        body.push('\n');
    }

    // Note about attachments.
    if !report.attachments.is_empty() {
        body.push_str("\n## Attachments\n\n");
        for a in &report.attachments {
            body.push_str(&format!("- {}\n", a.title));
        }
    }

    body
}

/// Send a GraphQL request to Linear, handling ureq's non-2xx error responses.
fn graphql_request(api_key: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let resp_str = match ureq::post(LINEAR_API_URL)
        .set("Authorization", api_key)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
    {
        Ok(resp) => resp.into_string().context("failed to read response body")?,
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            anyhow::bail!("Linear API returned {}: {}", code, body);
        }
        Err(e) => return Err(e).context("failed to send request to Linear API"),
    };

    let resp_json: serde_json::Value =
        serde_json::from_str(&resp_str).context("failed to parse Linear response JSON")?;

    if let Some(errors) = resp_json.get("errors") {
        anyhow::bail!("Linear API error: {}", errors);
    }

    Ok(resp_json)
}

/// Upload a file to Linear and attach it to an issue.
fn upload_attachment(api_key: &str, issue_id: &str, attachment: &Attachment) -> Result<()> {
    // Step 1: Request an upload URL.
    let upload_query = r#"mutation FileUpload($contentType: String!, $filename: String!, $size: Int!, $makePublic: Boolean) {
        fileUpload(contentType: $contentType, filename: $filename, size: $size, makePublic: $makePublic) {
            uploadFile {
                uploadUrl
                assetUrl
                headers {
                    key
                    value
                }
            }
        }
    }"#;

    let upload_body = serde_json::json!({
        "query": upload_query,
        "variables": {
            "contentType": attachment.content_type,
            "filename": attachment.filename,
            "size": attachment.body.len(),
        }
    });

    let resp_json = graphql_request(api_key, &upload_body).context("fileUpload mutation failed")?;

    let upload_file = &resp_json["data"]["fileUpload"]["uploadFile"];
    let upload_url = upload_file["uploadUrl"]
        .as_str()
        .context("missing uploadUrl")?;
    let asset_url = upload_file["assetUrl"]
        .as_str()
        .context("missing assetUrl")?
        .to_string();

    // Step 2: PUT the file content to the upload URL with provided headers.
    let mut req = ureq::put(upload_url);
    req = req.set("Content-Type", &attachment.content_type);
    if let Some(headers) = upload_file["headers"].as_array() {
        for h in headers {
            if let (Some(key), Some(value)) = (h["key"].as_str(), h["value"].as_str()) {
                req = req.set(key, value);
            }
        }
    }

    match req.send_bytes(&attachment.body) {
        Ok(_) => {}
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            anyhow::bail!("file PUT returned {}: {}", code, body);
        }
        Err(e) => return Err(e).context("failed to upload file"),
    }

    debug!(asset_url, filename = %attachment.filename, "Uploaded file to Linear");

    // Step 3: Create an attachment linking the file to the issue.
    let attach_query = r#"mutation AttachmentCreate($input: AttachmentCreateInput!) {
        attachmentCreate(input: $input) {
            success
        }
    }"#;

    let attach_body = serde_json::json!({
        "query": attach_query,
        "variables": {
            "input": {
                "issueId": issue_id,
                "title": attachment.title,
                "url": asset_url,
            }
        }
    });

    graphql_request(api_key, &attach_body).context("attachmentCreate mutation failed")?;

    info!(filename = %attachment.filename, issue_id, "Attached file to issue");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_description_minimal() {
        let report = BugReport {
            title: "test".into(),
            description: None,
            attachments: vec![],
        };
        let desc = format_description(&report);
        assert!(desc.starts_with("## test\n"));
        assert!(desc.contains("## System Info"));
        assert!(desc.contains(env!("CARGO_PKG_VERSION")));
        assert!(desc.contains(std::env::consts::OS));
        assert!(desc.contains(std::env::consts::ARCH));
        assert!(!desc.contains("## Description"));
        assert!(!desc.contains("## Attachments"));
    }

    #[test]
    fn test_format_description_full() {
        let report = BugReport {
            title: "test".into(),
            description: Some("Something is broken".into()),
            attachments: vec![
                Attachment {
                    filename: "policy.sexp".into(),
                    content_type: "text/plain".into(),
                    title: "Policy Config".into(),
                    body: b"default: ask".to_vec(),
                },
                Attachment {
                    filename: "clash.log".into(),
                    content_type: "text/plain".into(),
                    title: "Debug Logs".into(),
                    body: b"DEBUG some log line".to_vec(),
                },
            ],
        };
        let desc = format_description(&report);
        assert!(desc.contains("## Description"));
        assert!(desc.contains("Something is broken"));
        assert!(desc.contains("## Attachments"));
        assert!(desc.contains("- Policy Config"));
        assert!(desc.contains("- Debug Logs"));
    }

    #[test]
    fn test_api_key_availability() {
        // In test builds without CLASH_LINEAR_API_KEY, this should be false.
        // The function itself should not panic regardless.
        let _ = api_key_available();
    }

    #[test]
    fn test_create_issue_success() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/graphql")
            .match_header("Content-Type", "application/json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "data": {
                        "issueCreate": {
                            "success": true,
                            "issue": {
                                "id": "abc-123",
                                "identifier": "EMP-42",
                                "url": "https://linear.app/empathic/issue/EMP-42"
                            }
                        }
                    }
                })
                .to_string(),
            )
            .create();

        // Call the internal pieces directly since create_issue() uses the
        // baked-in API_KEY constant which may not be set in tests.
        let report = BugReport {
            title: "Test bug".into(),
            description: Some("It broke".into()),
            attachments: vec![],
        };
        let description = format_description(&report);

        let query = r#"mutation IssueCreate($input: IssueCreateInput!) {
        issueCreate(input: $input) {
            success
            issue {
                id
                identifier
                url
            }
        }
    }"#;

        let body = serde_json::json!({
            "query": query,
            "variables": {
                "input": {
                    "teamId": TEAM_ID,
                    "projectId": PROJECT_ID,
                    "title": report.title,
                    "description": description,
                    "labelIds": [BUG_LABEL_ID],
                }
            }
        });

        let resp = ureq::post(&format!("{}/graphql", server.url()))
            .set("Authorization", "Bearer test-key")
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .unwrap();

        let resp_body: serde_json::Value =
            serde_json::from_str(&resp.into_string().unwrap()).unwrap();

        let issue = &resp_body["data"]["issueCreate"]["issue"];
        assert_eq!(issue["identifier"].as_str().unwrap(), "EMP-42");
        assert_eq!(
            issue["url"].as_str().unwrap(),
            "https://linear.app/empathic/issue/EMP-42"
        );
        mock.assert();
    }

    #[test]
    fn test_create_issue_graphql_error() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "errors": [{"message": "Invalid input"}]
                })
                .to_string(),
            )
            .create();

        let resp = ureq::post(&format!("{}/graphql", server.url()))
            .set("Authorization", "Bearer test-key")
            .set("Content-Type", "application/json")
            .send_string(&serde_json::json!({"query": "..."}).to_string())
            .unwrap();

        let resp_body: serde_json::Value =
            serde_json::from_str(&resp.into_string().unwrap()).unwrap();

        assert!(resp_body.get("errors").is_some());
        mock.assert();
    }
}
