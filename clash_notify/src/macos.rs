use std::sync::Once;
use std::time::Duration;

use mac_notification_sys::{MainButton, Notification, NotificationResponse};
use tracing::{info, warn};

use crate::PromptResponse;

static INIT: Once = Once::new();

/// Set the bundle identifier so macOS shows notifications under a recognisable
/// app name. Defaults to Terminal if we can't find our own bundle.
pub fn init() {
    INIT.call_once(|| {
        let bundle = mac_notification_sys::get_bundle_identifier_or_default("Terminal");
        if let Err(e) = mac_notification_sys::set_application(&bundle) {
            warn!(error = %e, "Failed to set notification bundle identifier");
        }
    });
}

/// Fire-and-forget desktop notification.
pub fn notify(title: &str, body: &str) {
    init();
    info!(title, body, "Sending desktop notification (macOS)");

    let result = Notification::new()
        .title(title)
        .message(body)
        .asynchronous(true)
        .send();

    if let Err(e) = result {
        warn!(error = %e, "Failed to send desktop notification");
    }
}

/// Interactive notification with Approve/Deny buttons.
///
/// Blocks the current thread until the user responds. A watchdog thread
/// ensures we never block forever — if the timeout elapses, the process
/// exits so Claude Code can fall through to the terminal prompt.
///
/// The notification MUST run on the calling (main) thread because macOS
/// delivers click events via the main thread's run loop.
pub fn prompt(title: &str, body: &str, timeout: Duration) -> PromptResponse {
    init();
    info!(
        title,
        body,
        timeout_secs = timeout.as_secs(),
        "Sending interactive notification (macOS)"
    );

    // Watchdog: if the notification daemon hangs, force-exit so the hook
    // subprocess dies and Claude Code falls through to the terminal prompt.
    // This is safe because we run inside a short-lived hook subprocess.
    let timeout_dur = timeout;
    std::thread::spawn(move || {
        std::thread::sleep(timeout_dur);
        warn!("Interactive notification watchdog triggered, force-exiting");
        std::process::exit(1);
    });

    // Run on the main thread so macOS delivers click events properly.
    let result = Notification::new()
        .title(title)
        .message(body)
        .main_button(MainButton::SingleAction("Approve"))
        .close_button("Deny")
        .send();

    match result {
        Ok(response) => map_response(response),
        Err(e) => {
            warn!(error = %e, "Notification send failed");
            PromptResponse::TimedOut
        }
    }
}

fn map_response(response: NotificationResponse) -> PromptResponse {
    match response {
        NotificationResponse::ActionButton(_) => PromptResponse::Approved,
        NotificationResponse::Click => PromptResponse::Approved,
        NotificationResponse::CloseButton(_) => PromptResponse::Denied,
        NotificationResponse::None => PromptResponse::TimedOut,
        NotificationResponse::Reply(_) => PromptResponse::TimedOut,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_response_action_button() {
        assert_eq!(
            map_response(NotificationResponse::ActionButton("Approve".into())),
            PromptResponse::Approved,
        );
    }

    #[test]
    fn test_map_response_click() {
        assert_eq!(
            map_response(NotificationResponse::Click),
            PromptResponse::Approved,
        );
    }

    #[test]
    fn test_map_response_close_button() {
        assert_eq!(
            map_response(NotificationResponse::CloseButton("Deny".into())),
            PromptResponse::Denied,
        );
    }

    #[test]
    fn test_map_response_none() {
        assert_eq!(
            map_response(NotificationResponse::None),
            PromptResponse::TimedOut,
        );
    }

    #[test]
    fn test_map_response_reply() {
        assert_eq!(
            map_response(NotificationResponse::Reply("something".into())),
            PromptResponse::TimedOut,
        );
    }
}
