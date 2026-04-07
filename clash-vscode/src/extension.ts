import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";
import { findClash } from "./findClash";

let client: LanguageClient | undefined;

export async function activate(context: vscode.ExtensionContext) {
  let location;
  try {
    location = await findClash();
  } catch (err) {
    void vscode.window.showErrorMessage((err as Error).message);
    return;
  }

  const serverOptions: ServerOptions = {
    command: location.command,
    args: ["lsp"],
    transport: TransportKind.stdio,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "clash-policy" },
    ],
    synchronize: {
      fileEvents: vscode.workspace.createFileSystemWatcher("**/*.star"),
    },
  };

  client = new LanguageClient(
    "clashPolicy",
    "Clash Policy",
    serverOptions,
    clientOptions,
  );

  context.subscriptions.push({ dispose: () => client?.stop() });
  await client.start();
}

export function deactivate(): Thenable<void> | undefined {
  return client?.stop();
}
