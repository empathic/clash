/**
 * Clash plugin for OpenCode.
 *
 * Bridges OpenCode's plugin API to Clash's CLI hook interface.
 * Place this file in ~/.opencode/plugins/
 */

import type { Plugin } from "@opencode-ai/plugin"
import { execSync } from "child_process"

const ClashPlugin: Plugin = async ({ directory }) => {
  // Use a stable session ID derived from OpenCode's own session.
  // Falls back to a random ID if sessionID isn't available yet.
  let sessionId = ""

  // Fire session-start so clash initializes session state (audit log, traces).
  try {
    execSync("clash hook --agent opencode session-start", {
      input: JSON.stringify({
        session_id: sessionId,
        cwd: directory,
        hook_event_name: "session.start",
      }),
      encoding: "utf-8",
      timeout: 10000,
    })
  } catch {
    // Non-fatal: clash may not be on PATH yet
  }

  return {
    "tool.execute.before": async (input, output) => {
      // Use OpenCode's session ID once available.
      if (!sessionId && input.sessionID) {
        sessionId = `opencode-${input.sessionID}`
      }

      const hookInput = JSON.stringify({
        tool: input.tool,
        args: output.args,
        session_id: sessionId,
        directory,
        hook_event_name: "tool.execute.before",
      })

      try {
        const result = execSync(
          "clash hook --agent opencode pre-tool-use",
          {
            input: hookInput,
            encoding: "utf-8",
            timeout: 10000,
          }
        )

        const decision = JSON.parse(result)
        if (decision.action === "deny") {
          throw new Error(
            `Clash policy denied: ${decision.reason || "blocked by policy"}`
          )
        }
        if (decision.args) {
          Object.assign(output.args, decision.args)
        }
      } catch (e: any) {
        if (e.message?.startsWith("Clash policy denied:")) {
          throw e
        }
        // Non-fatal: let the tool execute if clash fails
        console.error(`[clash] hook error: ${e.message}`)
      }
    },
    "tool.execute.after": async (input, _output) => {
      const hookInput = JSON.stringify({
        tool: input.tool,
        args: input.args,
        session_id: sessionId,
        directory,
        hook_event_name: "tool.execute.after",
      })

      try {
        execSync("clash hook --agent opencode post-tool-use", {
          input: hookInput,
          encoding: "utf-8",
          timeout: 10000,
        })
      } catch {
        // Post-tool is advisory, don't fail
      }
    },
  }
}

export default ClashPlugin
