//! Clash library — permission enforcement for Claude Code.
//!
//! This crate provides the core building blocks for evaluating tool permissions,
//! enforcing sandbox policies, and integrating with Claude Code's hook system.
//!
//! # Modules
//!
//! - [`hooks`] — Input/output types for the Claude Code hook protocol.
//! - [`permissions`] — Policy-based permission evaluation for tool invocations.
//! - [`handlers`] — Pre-built hook handlers that wire permissions, notifications,
//!   and session validation together.
//! - [`settings`] — Loading and resolving clash configuration and policy files.
//! - [`sandbox`] — Platform-specific (Linux/macOS) sandbox enforcement backends.
//! - [`audit`] — Structured audit logging of policy decisions.
//! - [`notifications`] — Desktop notifications and Zulip integration.
//!
//! # Example
//!
//! ```no_run
//! use clash::hooks::ToolUseHookInput;
//! use clash::permissions::check_permission;
//! use clash::settings::ClashSettings;
//!
//! let settings = ClashSettings::load_or_create().unwrap();
//! let input = ToolUseHookInput::from_reader(std::io::stdin().lock()).unwrap();
//! let output = check_permission(&input, &settings).unwrap();
//! output.write_stdout().unwrap();
//! ```

pub mod audit;
pub mod handlers;
pub mod hooks;
pub mod notifications;
pub mod permissions;
pub mod sandbox;
pub mod settings;
