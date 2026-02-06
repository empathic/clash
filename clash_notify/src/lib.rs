use std::time::Duration;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

/// Response from an interactive desktop notification prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptResponse {
    Approved,
    Denied,
    TimedOut,
    /// Platform doesn't support interactive notifications.
    Unavailable,
}

/// One-time initialization. On macOS, sets the bundle identifier used for
/// notifications. Safe to call multiple times (subsequent calls are no-ops).
pub fn init() {
    #[cfg(target_os = "macos")]
    macos::init();
}

/// Fire-and-forget desktop notification. Errors are logged but never propagated.
pub fn notify(title: &str, body: &str) {
    #[cfg(target_os = "macos")]
    macos::notify(title, body);

    #[cfg(target_os = "linux")]
    linux::notify(title, body);

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (title, body);
        tracing::warn!("Desktop notifications not supported on this platform");
    }
}

/// Interactive notification with Approve/Deny buttons.
///
/// Blocks until the user responds or the timeout elapses. A thread-level
/// timeout guard ensures we never block forever even if the notification
/// daemon is unresponsive.
pub fn prompt(title: &str, body: &str, timeout: Duration) -> PromptResponse {
    #[cfg(target_os = "macos")]
    {
        macos::prompt(title, body, timeout)
    }

    #[cfg(target_os = "linux")]
    {
        linux::prompt(title, body, timeout)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (title, body, timeout);
        PromptResponse::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_response_debug() {
        // Ensure the enum derives work.
        assert_eq!(format!("{:?}", PromptResponse::Approved), "Approved");
        assert_eq!(format!("{:?}", PromptResponse::Denied), "Denied");
        assert_eq!(format!("{:?}", PromptResponse::TimedOut), "TimedOut");
        assert_eq!(format!("{:?}", PromptResponse::Unavailable), "Unavailable");
    }

    #[test]
    fn prompt_response_eq() {
        assert_eq!(PromptResponse::Approved, PromptResponse::Approved);
        assert_ne!(PromptResponse::Approved, PromptResponse::Denied);
    }
}
