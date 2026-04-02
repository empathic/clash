//! Import permissions from a coding agent's settings and generate a Clash policy.

use anyhow::Result;

use crate::agents::AgentKind;

/// Import settings from the agent and generate a Clash policy.
pub fn run(agent: Option<AgentKind>) -> Result<()> {
    let _agent = match agent {
        Some(a) => a,
        None => *crate::dialog::select::<AgentKind>("Which coding agent are you using?")?,
    };

    // TODO: implement in subsequent tasks
    anyhow::bail!("import not yet implemented — use `clash init --no-import` for now")
}
