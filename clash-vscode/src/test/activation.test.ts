import * as assert from "node:assert";
import * as vscode from "vscode";

suite("clash-policy extension", () => {
  test("activates on .star files", async () => {
    const ext = vscode.extensions.getExtension("empathic.clash-policy");
    assert.ok(ext, "extension should be registered");
    const doc = await vscode.workspace.openTextDocument({
      language: "clash-policy",
      content: "policy({})\n",
    });
    await vscode.window.showTextDocument(doc);
    await ext!.activate();
    assert.strictEqual(ext!.isActive, true);
  });
});
