use std::time::Duration;

use tracing::{info, warn};

use crate::PromptResponse;

/// Fire-and-forget desktop notification using notify-rust.
pub fn notify(title: &str, body: &str) {
    info!(title, body, "Sending desktop notification (Linux)");

    match notify_rust::Notification::new()
        .auto_icon()
        .summary(title)
        .timeout(Duration::from_secs(10))
        .body(body)
        .show()
    {
        Ok(_) => {}
        Err(e) => warn!(error = %e, "Failed to send desktop notification"),
    }
}

/// Interactive notifications are not supported on Linux.
///
/// Sends a fire-and-forget notification and returns `Unavailable` so the
/// caller can fall through to Zulip or the terminal.
pub fn prompt(title: &str, body: &str, _timeout: Duration) -> PromptResponse {
    notify(title, body);
    PromptResponse::Unavailable
}
