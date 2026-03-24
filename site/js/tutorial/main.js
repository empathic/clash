/**
 * Main orchestrator for the Clash interactive tutorial.
 * Uses the real Clash policy engine compiled to WASM — Starlark evaluation,
 * match-tree compilation, and permission checking all run in the browser.
 */

import init, {
  evaluate_starlark,
  check_permission,
  format_rules,
} from './wasm/clash_wasm.js';
import { TutorialTerminal } from './terminal.js';
import { VirtualFS } from './virtual-fs.js';
import { STEPS } from './steps.js';

// ── WASM-backed policy engine ───────────────────────────────────

const ENV = { PWD: '/project', HOME: '/home/user', TMPDIR: '/tmp' };

class WasmEngine {
  constructor() {
    this.rules = [];
    this.sandboxDefs = []; // { name, expr }
    this.compiledJson = null;
    this.lastError = null;
  }

  addRule(ruleExpr) {
    this.rules.push(ruleExpr);
    const result = this._compile();
    if (!result.ok) this.rules.pop();
    return result;
  }

  addSandbox(name, expr) {
    this.sandboxDefs.push({ name, expr });
    const result = this._compile();
    if (!result.ok) this.sandboxDefs.pop();
    return result;
  }

  /**
   * Update the most recent rule for a given binary to use a sandbox.
   * Used when the tutorial asks the user to attach a sandbox to an existing rule.
   */
  updateExeRuleSandbox(binary, sandboxName) {
    for (let i = this.rules.length - 1; i >= 0; i--) {
      const r = this.rules[i];
      if (r.startsWith(`exe("${binary}")`) && !r.includes('.sandbox(')) {
        // Replace .allow()/.deny()/.ask() with .sandbox(name).effect()
        this.rules[i] = r.replace(/\.(allow|deny|ask)\(\)/, `.sandbox(${sandboxName}).$1()`);
        const result = this._compile();
        if (!result.ok) {
          this.rules[i] = r; // Revert on failure
        }
        return result;
      }
    }
    return { ok: false, error: `No exe("${binary}") rule found to update` };
  }

  test(toolName, toolInput) {
    if (!this.compiledJson) {
      return {
        effect: 'ask',
        reason: 'no rules matched, default: ask',
        sandbox: null,
        sandbox_policy: null,
        trace: ['No rules matched. Defaulting to ask.'],
      };
    }
    try {
      const resultJson = check_permission(
        this.compiledJson,
        toolName,
        JSON.stringify(toolInput),
        JSON.stringify(ENV),
      );
      return JSON.parse(resultJson);
    } catch (e) {
      return { effect: 'ask', reason: e.message, trace: [e.message] };
    }
  }

  getFormattedRules() {
    if (!this.compiledJson) return ['No rules defined. Default: ask'];
    try {
      return JSON.parse(format_rules(this.compiledJson));
    } catch (_) {
      return this.rules.map((r, i) => `${i + 1}. ${r}`);
    }
  }

  getSource() {
    return this._buildStarlark();
  }

  reset() {
    this.rules = [];
    this.sandboxDefs = [];
    this.compiledJson = null;
    this.lastError = null;
  }

  _buildStarlark() {
    const imports = [
      'allow', 'ask', 'cmd', 'deny', 'exe', 'tool', 'policy',
      'sandbox', 'cwd', 'home', 'tempdir', 'path', 'domains', 'regex',
    ];
    let src = `load("@clash//std.star", ${imports.map(i => `"${i}"`).join(', ')})\n\n`;

    for (const sb of this.sandboxDefs) {
      src += `${sb.name} = ${sb.expr}\n`;
    }

    src += '\ndef main():\n';
    if (this.rules.length === 0) {
      src += '    return policy(default=ask(), rules=[])\n';
    } else {
      src += '    return policy(default=ask(), rules=[\n';
      for (const rule of this.rules) {
        src += `        ${rule},\n`;
      }
      src += '    ])\n';
    }
    return src;
  }

  _compile() {
    const source = this._buildStarlark();
    try {
      this.compiledJson = evaluate_starlark(source);
      this.lastError = null;
      return { ok: true };
    } catch (e) {
      this.lastError = e.message || e.toString();
      return { ok: false, error: this.lastError };
    }
  }
}

// ── Tutorial ────────────────────────────────────────────────────

class Tutorial {
  constructor() {
    this.fs = new VirtualFS();
    this.engine = new WasmEngine();
    this.terminal = null;
    this.currentStep = 0;
    this.currentTask = 0;
    this.sidebarEl = document.getElementById('tutorial-sidebar');
    this.terminalEl = document.getElementById('tutorial-terminal');
    this.stepDotsEl = document.getElementById('step-dots');
  }

  async init() {
    this.terminal = new TutorialTerminal(this.terminalEl);
    await this.terminal.init();
    this.terminal.onCommand(cmd => this.handleCommand(cmd));

    this.renderStepDots();
    this.goToStep(0);

    this.terminal.writeBold('Clash Interactive Tutorial');
    this.terminal.writeInfo('Powered by the real Clash policy engine (compiled to WebAssembly)');
    this.terminal.writeMuted('Type commands below, or click the highlighted commands in the sidebar.');
    this.terminal.writeMuted('Type "help" for available commands.\r\n');
    this.terminal.startReadLoop();
  }

  renderStepDots() {
    this.stepDotsEl.innerHTML = STEPS.map((step, i) =>
      `<button class="step-dot${i === 0 ? ' active' : ''}" data-step="${i}" title="${step.title}">${i + 1}</button>`
    ).join('');

    this.stepDotsEl.addEventListener('click', e => {
      const dot = e.target.closest('.step-dot');
      if (dot) this.goToStep(parseInt(dot.dataset.step));
    });
  }

  goToStep(index) {
    if (index < 0 || index >= STEPS.length) return;
    this.currentStep = index;
    this.currentTask = 0;
    const step = STEPS[index];

    this.stepDotsEl.querySelectorAll('.step-dot').forEach((dot, i) => {
      dot.classList.toggle('active', i === index);
      dot.classList.toggle('completed', i < index);
    });

    let html = `<div class="step-header">
      <span class="step-label">Step ${index + 1} of ${STEPS.length}</span>
      <h2 class="step-title">${step.title}</h2>
    </div>`;
    html += `<div class="step-content">${step.content}</div>`;

    if (step.tasks.length > 0) {
      html += '<div class="step-tasks">';
      step.tasks.forEach((task, i) => {
        html += `
          <div class="task${i === 0 ? ' active' : ''}" data-task="${i}">
            <div class="task-status"><span class="task-dot"></span></div>
            <div class="task-body">
              <p class="task-instruction">${task.instruction}</p>
              <button class="task-command" data-command="${this._escapeAttr(task.command)}">${this._escapeHtml(task.command)}</button>
            </div>
          </div>`;
      });
      html += '</div>';
    }

    html += '<div class="step-nav">';
    if (index > 0) {
      html += `<button class="step-btn step-btn-prev" data-dir="prev">&larr; Previous</button>`;
    }
    if (index < STEPS.length - 1) {
      html += `<button class="step-btn step-btn-next" data-dir="next">Next &rarr;</button>`;
    }
    html += '</div>';

    this.sidebarEl.innerHTML = html;

    this.sidebarEl.querySelectorAll('.task-command').forEach(btn => {
      btn.addEventListener('click', () => {
        this.terminal.focus();
        this.terminal.typeCommand(btn.dataset.command);
      });
    });

    this.sidebarEl.querySelectorAll('.step-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        if (btn.dataset.dir === 'next') this.goToStep(index + 1);
        else this.goToStep(index - 1);
      });
    });
  }

  advanceTask() {
    const step = STEPS[this.currentStep];
    if (!step.tasks.length) return;

    const tasks = this.sidebarEl.querySelectorAll('.task');
    if (this.currentTask < tasks.length) {
      tasks[this.currentTask].classList.add('completed');
      tasks[this.currentTask].classList.remove('active');
    }

    this.currentTask++;

    if (this.currentTask < tasks.length) {
      tasks[this.currentTask].classList.add('active');
    } else if (this.currentStep < STEPS.length - 1) {
      const nextBtn = this.sidebarEl.querySelector('.step-btn-next');
      if (nextBtn) nextBtn.classList.add('pulse');
    }
  }

  async handleCommand(cmd) {
    const trimmed = cmd.trim();
    if (!trimmed) { this.terminal.promptInline(); return; }

    if (trimmed === 'help') {
      this._showHelp();
    } else if (trimmed === 'show') {
      this._showRules();
    } else if (trimmed === 'source') {
      this._showSource();
    } else if (trimmed === 'reset') {
      this.engine.reset();
      this.terminal.writeSuccess('✓ All rules and sandboxes cleared.');
    } else if (trimmed === 'clear') {
      this.terminal.clear();
    } else if (trimmed.startsWith('test ')) {
      this._handleTest(trimmed.slice(5));
    } else {
      // Treat as a Starlark expression (rule or sandbox definition)
      this._handleStarlarkExpr(trimmed);
    }
  }

  // ── Command Handlers ──────────────────────────────────────────

  _handleTest(args) {
    const match = args.match(/^(\w+)\s+"(.+)"$/);
    if (!match) {
      this.terminal.writeError('Usage: test <ToolName> "<input>"');
      return;
    }

    const [, toolName, input] = match;
    const toolInput = toolName === 'Bash' ? { command: input } :
                      toolName === 'Glob' ? { pattern: input, path: '/project' } :
                      toolName === 'Read' ? { file_path: input } :
                      toolName === 'Write' ? { file_path: input } :
                      { input };

    const result = this.engine.test(toolName, toolInput);

    this.terminal.writeln('');
    this.terminal.writeBold(`Tool: ${toolName}`);

    if (toolName === 'Bash') {
      this.terminal.writeln(`Command: ${input}`);
    } else if (toolName === 'Glob') {
      this.terminal.writeln(`Pattern: ${input}`);
      this.terminal.writeln('Path: /project');
    }

    // Show trace
    if (result.trace && result.trace.length > 0) {
      this.terminal.writeln('');
      for (const line of result.trace) {
        if (line.includes('matched')) {
          this.terminal.writeSuccess(`  ${line}`);
        } else if (line.includes('skipped')) {
          this.terminal.writeMuted(`  ${line}`);
        } else if (line.includes('Defaulting')) {
          this.terminal.writeWarning(`  ${line}`);
        } else {
          const effect = result.effect;
          if (effect === 'allow') this.terminal.writeSuccess(`  ${line}`);
          else if (effect === 'deny') this.terminal.writeError(`  ${line}`);
          else this.terminal.writeWarning(`  ${line}`);
        }
      }
    }

    // Show sandbox details
    if (result.sandbox_policy) {
      const sbp = result.sandbox_policy;
      this.terminal.writeln('');
      this.terminal.writeBold(`Sandbox: ${result.sandbox}`);
      if (sbp.rules && sbp.rules.length > 0) {
        for (const rule of sbp.rules) {
          const caps = Array.isArray(rule.caps) ? rule.caps.join(', ') : String(rule.caps);
          this.terminal.writeln(`  ├── fs: ${rule.path} (${caps})`);
        }
      }
      const netStr = typeof sbp.network === 'string' ? sbp.network : JSON.stringify(sbp.network);
      this.terminal.writeln(`  └── network: ${netStr}`);

      // Show file access examples for sandbox
      this.terminal.writeln('');
      this.terminal.writeln('Process can access:');
      const examples = [
        { path: '/project/.git/HEAD', label: '/project/.git/HEAD' },
        { path: '/project/src/main.rs', label: '/project/src/main.rs' },
        { path: '/home/user/.ssh/id_rsa', label: '~/.ssh/id_rsa' },
        { path: '/home/user/.gitconfig', label: '~/.gitconfig' },
      ];
      for (const ex of examples) {
        const inside = sbp.rules && sbp.rules.some(r => {
          const rpath = r.path.replace('$PWD', '/project').replace('$HOME', '/home/user');
          return ex.path === rpath || ex.path.startsWith(rpath + '/');
        });
        if (inside) {
          this.terminal.writeSuccess(`  ✓ ${ex.label}`);
        } else {
          this.terminal.writeError(`  ✗ ${ex.label} (outside sandbox)`);
        }
      }
      if (netStr === 'deny' || netStr === '"deny"') {
        this.terminal.writeError('  ✗ network (denied by sandbox)');
      }
    } else if (result.effect === 'allow' && toolName === 'Bash') {
      this.terminal.writeln('');
      this.terminal.writeWarning('⚠  No sandbox — process has full system access.');
    }

    // Show Glob results when allowed
    if (toolName === 'Glob' && result.effect === 'allow') {
      const matches = this.fs.glob(input);
      if (matches.length > 0) {
        this.terminal.writeln('');
        this.terminal.writeln('Found:');
        matches.forEach(m => this.terminal.writeSuccess(`  ${m}`));
      }
    }

    this.advanceTask();
  }

  _handleStarlarkExpr(expr) {
    // Sandbox definition: sandbox("name", ...)
    if (expr.startsWith('sandbox(')) {
      const nameMatch = expr.match(/^sandbox\(\s*"([^"]+)"/);
      if (!nameMatch) {
        this.terminal.writeError('Sandbox name must be a string. Example: sandbox("mybox", ...)');
        return;
      }
      const name = nameMatch[1];
      const result = this.engine.addSandbox(name, expr);
      if (result.ok) {
        this.terminal.writeSuccess(`✓ Sandbox created: ${name}`);
        this.advanceTask();
      } else {
        this.terminal.writeError(`Error: ${result.error}`);
      }
      return;
    }

    // Sandbox attachment: exe("binary").sandbox(name).effect()
    // Check if this is updating an existing rule
    const attachMatch = expr.match(/^exe\("([^"]+)"\)\.sandbox\((\w+)\)\.(allow|deny|ask)\(\)$/);
    if (attachMatch) {
      const [, binary, sandboxName, effect] = attachMatch;
      // Try to update an existing rule first
      const updateResult = this.engine.updateExeRuleSandbox(binary, sandboxName);
      if (updateResult.ok) {
        this.terminal.writeSuccess(`✓ Rule updated: ${effect} exec ${binary} (sandbox: ${sandboxName})`);
        this.advanceTask();
        return;
      }
      // If no existing rule, add as new
    }

    // Generic rule expression — add directly and let Starlark validate
    const result = this.engine.addRule(expr);
    if (result.ok) {
      this.terminal.writeSuccess(`✓ Rule added: ${expr}`);
      this.advanceTask();
    } else {
      this.terminal.writeError(`Error: ${result.error}`);
    }
  }

  // ── Display Helpers ───────────────────────────────────────────

  _showHelp() {
    this.terminal.writeln('');
    this.terminal.writeBold('Add rules (real Starlark syntax):');
    this.terminal.writeln('  exe("binary").allow()            Allow a command');
    this.terminal.writeln('  exe("bin", args=["a"]).deny()    Deny specific args');
    this.terminal.writeln('  cwd().allow(read=True)           Allow fs reads in project');
    this.terminal.writeln('  tool("Glob").allow()             Allow a specific tool');
    this.terminal.writeln('  sandbox("name", default=deny(),  Create a sandbox');
    this.terminal.writeln('    fs=[cwd().allow(read=True)],');
    this.terminal.writeln('    net=deny())');
    this.terminal.writeln('  exe("bin").sandbox(name).allow() Attach sandbox to rule');
    this.terminal.writeln('');
    this.terminal.writeBold('Test & inspect:');
    this.terminal.writeln('  test Bash "command"               Test a Bash tool call');
    this.terminal.writeln('  test Glob "pattern"               Test a Glob tool call');
    this.terminal.writeln('  show                              Show current rules');
    this.terminal.writeln('  source                            Show generated Starlark');
    this.terminal.writeln('  reset                             Clear all rules');
    this.terminal.writeln('  clear                             Clear terminal');
  }

  _showRules() {
    this.terminal.writeln('');
    const lines = this.engine.getFormattedRules();
    this.terminal.writeBold('Rules (first match wins):');
    for (const line of lines) {
      if (line.includes('allow')) {
        this.terminal.writeln(`  \x1b[32m${line}\x1b[0m`);
      } else if (line.includes('deny')) {
        this.terminal.writeln(`  \x1b[31m${line}\x1b[0m`);
      } else if (line.includes('ask') || line.includes('Default')) {
        this.terminal.writeln(`  \x1b[33m${line}\x1b[0m`);
      } else {
        this.terminal.writeln(`  ${line}`);
      }
    }

    const sandboxes = this.engine.sandboxDefs;
    if (sandboxes.length > 0) {
      this.terminal.writeln('');
      this.terminal.writeBold('Sandboxes:');
      for (const sb of sandboxes) {
        this.terminal.writeln(`  ${sb.name}: ${sb.expr.slice(0, 60)}${sb.expr.length > 60 ? '...' : ''}`);
      }
    }
  }

  _showSource() {
    this.terminal.writeln('');
    this.terminal.writeBold('Generated Starlark policy:');
    const source = this.engine.getSource();
    for (const line of source.split('\n')) {
      this.terminal.writeln(`  \x1b[36m${line}\x1b[0m`);
    }
  }

  _escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  _escapeAttr(str) {
    return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
  }
}

// ── Initialize ──────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  try {
    // Initialize WASM module
    await init();

    // Start tutorial
    const tutorial = new Tutorial();
    await tutorial.init();
  } catch (err) {
    console.error('Tutorial init failed:', err);
    const el = document.getElementById('tutorial-terminal');
    if (el) {
      el.innerHTML = `<p style="color:#c23b22;padding:1rem;font-family:monospace;">
        Failed to load tutorial: ${err.message || err}<br><br>
        Check the browser console for details.
      </p>`;
    }
  }
});
