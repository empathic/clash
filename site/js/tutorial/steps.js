/**
 * Tutorial step definitions for the Clash interactive tutorial.
 * Each step has a title, sidebar content (HTML), and tasks to complete.
 *
 * Commands use real Starlark syntax — they're evaluated by the actual
 * Clash policy engine compiled to WASM.
 */

export const STEPS = [
  {
    id: 'welcome',
    title: 'Welcome',
    content: `
      <p>This tutorial teaches you the two core concepts in Clash:</p>
      <ul>
        <li><strong>Tool rules</strong> &mdash; control <em>whether</em> something is allowed to run</li>
        <li><strong>Sandboxes</strong> &mdash; control <em>what it can touch</em> when it runs</li>
      </ul>
      <p>Type commands in the terminal, or <strong>click</strong> the highlighted commands to auto-type them.</p>
      <p class="step-note">This tutorial runs the <strong>real Clash policy engine</strong> compiled to WebAssembly. The Starlark syntax you learn here is the same syntax you'll use in your <code>policy.star</code> files.</p>
    `,
    tasks: [],
  },
  {
    id: 'no-policy',
    title: 'The Problem: No Policy',
    content: `
      <p>When an AI agent calls a tool, Clash makes a permission decision. With no rules defined, <strong>everything defaults to &ldquo;ask&rdquo;</strong> &mdash; you'd click approve hundreds of times per session.</p>
      <p>Let's see what that looks like:</p>
    `,
    tasks: [
      {
        instruction: 'Test a git command through the Bash tool:',
        command: 'test Bash "git status"',
      },
      {
        instruction: 'Now test the Glob tool (searches files by pattern):',
        command: 'test Glob "**/*.rs"',
      },
    ],
  },
  {
    id: 'tool-rules',
    title: 'Tool Rules: Control What Runs',
    content: `
      <p>Tool rules decide <strong>whether</strong> a tool call is allowed. They use Clash's Starlark DSL.</p>
      <p><code>exe()</code> matches shell commands by binary name. The effect &mdash; <code>.allow()</code>, <code>.deny()</code>, or <code>.ask()</code> &mdash; is the decision.</p>
      <p>More specific rules automatically match first.</p>
    `,
    tasks: [
      {
        instruction: 'Allow all git commands:',
        command: 'exe("git").allow()',
      },
      {
        instruction: 'Test git status &mdash; it should be allowed now:',
        command: 'test Bash "git status"',
      },
      {
        instruction: 'Block git push (specific args match before general):',
        command: 'exe("git", args=["push"]).deny()',
      },
      {
        instruction: 'Verify git push is blocked:',
        command: 'test Bash "git push origin main"',
      },
    ],
  },
  {
    id: 'capabilities',
    title: 'Different Tools, Different Domains',
    content: `
      <p><code>Glob</code> isn't a shell command &mdash; it's a Claude tool that reads the filesystem directly. Clash maps each tool to a <strong>capability domain</strong>:</p>
      <div class="capability-map">
        <div class="cap-row"><span class="cap-tool">Bash</span><span class="cap-arrow">&rarr;</span><span class="cap-domain cap-exec">exec</span></div>
        <div class="cap-row"><span class="cap-tool">Glob, Read, Grep</span><span class="cap-arrow">&rarr;</span><span class="cap-domain cap-fs">fs read</span></div>
        <div class="cap-row"><span class="cap-tool">Write, Edit</span><span class="cap-arrow">&rarr;</span><span class="cap-domain cap-fs">fs write</span></div>
        <div class="cap-row"><span class="cap-tool">WebFetch</span><span class="cap-arrow">&rarr;</span><span class="cap-domain cap-net">net</span></div>
      </div>
      <p>Use <code>cwd()</code> to write filesystem rules for the project directory:</p>
    `,
    tasks: [
      {
        instruction: 'Allow reading files under the project:',
        command: 'cwd().allow(read=True)',
      },
      {
        instruction: 'Test Glob &mdash; it should find your Rust files:',
        command: 'test Glob "**/*.rs"',
      },
    ],
  },
  {
    id: 'sandboxes',
    title: 'Sandboxes: Control What It Touches',
    content: `
      <p>Tool rules decide <em>whether</em> git runs. But once it runs, it has access to <strong>everything</strong> &mdash; your SSH keys, secrets, the entire network.</p>
      <p>Sandboxes are <strong>kernel-enforced restrictions</strong> on what a process can actually touch. They're inherited by child processes and can't be escaped.</p>
    `,
    tasks: [
      {
        instruction: 'Test git &mdash; notice &ldquo;no sandbox&rdquo; warning:',
        command: 'test Bash "git status"',
      },
      {
        instruction: 'Create a sandbox: project files only, no network:',
        command: 'sandbox("git_box", default=deny(), fs=[cwd().allow(read=True, write=True)], net=deny())',
      },
      {
        instruction: 'Attach the sandbox to the git rule:',
        command: 'exe("git").sandbox(git_box).allow()',
      },
      {
        instruction: 'Test git again &mdash; see what the sandbox restricts:',
        command: 'test Bash "git status"',
      },
    ],
  },
  {
    id: 'playground',
    title: 'The Full Picture',
    content: `
      <p>You now understand Clash's two core concepts:</p>
      <div class="summary-cards">
        <div class="summary-card summary-card--rules">
          <strong>Tool rules</strong>
          <span>What's allowed to run</span>
          <code>allow / deny / ask</code>
        </div>
        <div class="summary-card summary-card--sandbox">
          <strong>Sandboxes</strong>
          <span>What it can touch</span>
          <code>fs paths, network</code>
        </div>
      </div>
      <p>You're now in <strong>playground mode</strong>. Everything you type is real Starlark &mdash; the same language used in <code>policy.star</code> files.</p>
      <ul class="playground-commands">
        <li><code>show</code> &mdash; see current rules</li>
        <li><code>source</code> &mdash; see the generated Starlark</li>
        <li><code>reset</code> &mdash; clear everything</li>
        <li><code>help</code> &mdash; list all commands</li>
      </ul>
    `,
    tasks: [],
  },
];
