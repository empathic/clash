/**
 * Clash plugin for OpenCode.
 *
 * Bridges OpenCode's JS plugin API to Clash's CLI hook interface.
 * Place this file in .opencode/plugins/ or ~/.config/opencode/plugins/
 */

import type { Plugin } from "@opencode-ai/plugin"
import { execSync } from "child_process"

export const ClashPlugin: Plugin = async ({ directory }) => {
  return {
    tool: {
      execute: {
        before: async (input, output) => {
          const hookInput = JSON.stringify({
            tool: input.tool,
            args: output.args,
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
        after: async (input, _output) => {
          const hookInput = JSON.stringify({
            tool: input.tool,
            args: input,
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
      },
    },
  }
}
