# Zulip Bot Notifications

## Goal

Build a notification and external permission resolution system for clash. This includes:
1. Cross-platform desktop notifications (macOS + Linux)
2. Zulip bot integration for remote permission resolution
3. Configuration via `policy.yaml`

## Architecture

### Notification Flow

Two hook types are relevant:

- **Notification hook** (`permission_prompt`, `idle_prompt`): Informational events.
  We send desktop notifications here to alert the user.

- **PermissionRequest hook**: Decision-required events. When the policy evaluates to
  "ask", and Zulip is configured, we send a message to Zulip and poll for a response.
  If approved/denied via Zulip, we return the decision. If timeout, we fall through
  to let the terminal handle it.

### Desktop Notifications

Cross-platform via conditional compilation:
- macOS: `mac-notification-sys` (already a dependency)
- Linux: `notify-rust` via D-Bus/XDG notifications

Graceful failure: if no desktop environment is available, notification errors are
logged but don't block execution.

### Zulip Bot

The bot uses Zulip's REST API:
1. **Send message**: `POST /api/v1/messages` to a configured stream/topic
2. **Poll for response**: `GET /api/v1/messages` with anchor after our sent message
3. **Parse response**: Look for "approve"/"deny" keywords from non-bot users

Authentication: HTTP Basic auth with `bot_email:bot_api_key`.

### Configuration

Root-level `notifications:` key in `policy.yaml`:

```yaml
notifications:
  desktop: true
  zulip:
    server_url: "https://your-org.zulipchat.com"
    bot_email: "clash-bot@your-org.zulipchat.com"
    bot_api_key: "your-api-key"
    stream: "clash-permissions"
    topic: "requests"
    timeout_secs: 120

default: ask
rules:
  - allow bash git *
```

The notification config is parsed separately from the policy rules. The existing
policy parser silently ignores unknown keys (serde default behavior), so adding
`notifications:` to the YAML is backwards-compatible.

## Dependencies

- `ureq` v2: Synchronous HTTP client for Zulip API calls
- `base64` v0.22: Base64 encoding for HTTP Basic auth
- `notify-rust` v4: Linux desktop notifications (Linux-only dependency)

## Files Modified

- `Cargo.toml` (workspace): Add new dependencies
- `clash/Cargo.toml`: Wire up dependencies
- `clash/src/notifications.rs`: Full implementation (was empty placeholder)
- `clash/src/settings.rs`: Parse notification config from policy.yaml
- `clash/src/main.rs`: Wire up Notification + PermissionRequest handlers
- `clash/examples/policy.yaml`: Add notifications config example

## Status

- [x] Plan created
- [x] Dependencies added
- [x] Desktop notification library
- [x] Zulip bot client
- [x] Settings integration
- [x] Hook handler wiring
- [x] Example config
