import { execFile } from "node:child_process";
import { promisify } from "node:util";
import * as vscode from "vscode";

const exec = promisify(execFile);

export interface ClashLocation {
  command: string;
  version: string;
}

/**
 * Locate the clash binary, honoring `clashPolicy.binaryPath` if set.
 * Throws a user-facing error if clash is missing or unrunnable.
 */
export async function findClash(): Promise<ClashLocation> {
  const config = vscode.workspace.getConfiguration("clashPolicy");
  const command = config.get<string>("binaryPath") || "clash";

  try {
    const { stdout } = await exec(command, ["--version"]);
    return { command, version: stdout.trim() };
  } catch (err) {
    throw new Error(
      `Could not run \`${command} --version\`. Install clash from ` +
      `https://github.com/empathic/clash or set \`clashPolicy.binaryPath\` ` +
      `in settings. (${(err as Error).message})`
    );
  }
}
