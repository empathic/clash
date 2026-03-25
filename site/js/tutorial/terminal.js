/**
 * xterm.js wrapper for the Clash interactive tutorial.
 * Uses local-echo addon for readline-like line editing (cursor movement,
 * history, word deletion, etc.).
 */

const XTERM_CDN = 'https://cdn.jsdelivr.net/npm/@xterm/xterm/+esm';
const FIT_CDN = 'https://cdn.jsdelivr.net/npm/@xterm/addon-fit/+esm';
const LOCAL_ECHO_CDN = 'https://cdn.jsdelivr.net/npm/local-echo/+esm';

const THEME = {
  background: '#1b2d1b',
  foreground: '#b8e6c8',
  cursor: '#2d8a4e',
  cursorAccent: '#1b2d1b',
  selectionBackground: 'rgba(45, 138, 78, 0.3)',
  selectionForeground: '#d8f0d8',
  black: '#1a2e1a',
  red: '#c23b22',
  green: '#2d8a4e',
  yellow: '#d4a017',
  blue: '#7ec8e3',
  magenta: '#d4a8e6',
  cyan: '#7cc88e',
  white: '#b8e6c8',
  brightBlack: '#4a6b4a',
  brightRed: '#e05040',
  brightGreen: '#5cb870',
  brightYellow: '#e8b830',
  brightBlue: '#90d8f0',
  brightMagenta: '#e0baf0',
  brightCyan: '#98e8a8',
  brightWhite: '#d8f0d8',
};

const PROMPT = 'clash> ';

export class TutorialTerminal {
  constructor(container) {
    this.container = container;
    this._onCommand = null;
    this.term = null;
    this.fitAddon = null;
    this.localEcho = null;
    this._reading = false;
  }

  async init() {
    const [{ Terminal }, { FitAddon }, localEchoModule] = await Promise.all([
      import(XTERM_CDN),
      import(FIT_CDN),
      import(LOCAL_ECHO_CDN),
    ]);

    const LocalEchoController = localEchoModule.default || localEchoModule.LocalEchoController;

    this.term = new Terminal({
      theme: THEME,
      fontFamily: '"JetBrains Mono", ui-monospace, monospace',
      fontSize: 14,
      lineHeight: 1,
      cursorBlink: true,
      cursorStyle: 'bar',
      scrollback: 1000,
      convertEol: true,
    });

    this.fitAddon = new FitAddon();
    this.term.loadAddon(this.fitAddon);
    this.term.open(this.container);

    // Shim xterm v5 API for local-echo (which expects v3/v4 .on() style)
    if (!this.term.on) {
      const disposables = {};
      this.term.on = (event, handler) => {
        switch (event) {
          case 'data': disposables[event] = this.term.onData(handler); break;
          case 'key': disposables[event] = this.term.onKey(handler); break;
          case 'resize': disposables[event] = this.term.onResize(handler); break;
        }
      };
      this.term.off = (event) => {
        if (disposables[event]) { disposables[event].dispose(); delete disposables[event]; }
      };
    }

    this.localEcho = new LocalEchoController(this.term, { historySize: 100 });

    await new Promise(r => setTimeout(r, 50));
    this.fitAddon.fit();

    const ro = new ResizeObserver(() => {
      try { this.fitAddon.fit(); } catch (_) { /* ignore resize errors */ }
    });
    ro.observe(this.container);

    this.term.focus();
  }

  onCommand(callback) {
    this._onCommand = callback;
  }

  write(text) {
    this.term.write(text);
  }

  writeln(text = '') {
    this.term.writeln(text);
  }

  writeSuccess(text) {
    this.term.writeln(`\x1b[32m${text}\x1b[0m`);
  }

  writeError(text) {
    this.term.writeln(`\x1b[31m${text}\x1b[0m`);
  }

  writeWarning(text) {
    this.term.writeln(`\x1b[33m${text}\x1b[0m`);
  }

  writeInfo(text) {
    this.term.writeln(`\x1b[36m${text}\x1b[0m`);
  }

  writeMuted(text) {
    this.term.writeln(`\x1b[90m${text}\x1b[0m`);
  }

  writeBold(text) {
    this.term.writeln(`\x1b[1m${text}\x1b[0m`);
  }

  /** Start the read loop — prompts for input and dispatches commands. */
  async startReadLoop() {
    while (true) {
      try {
        const input = await this.localEcho.read(PROMPT);
        const command = input.trim();
        if (command && this._onCommand) {
          await this._onCommand(command);
        }
      } catch (_) {
        // read() rejects on Ctrl+C / abort — just re-prompt
      }
    }
  }

  /** Write output then re-prompt (for use outside the read loop). */
  prompt() {
    // No-op — the read loop handles prompting automatically
  }

  promptInline() {
    // No-op — the read loop handles prompting automatically
  }

  clear() {
    this.term.clear();
  }

  focus() {
    this.term.focus();
  }

  setInputEnabled(_enabled) {
    // local-echo manages this internally
  }

  async typeCommand(cmd, charDelay = 25) {
    // Abort any current read, type the command visually, then submit
    try { this.localEcho.abortRead(); } catch (_) { /* no active read */ }

    // Small delay for the abort to settle
    await new Promise(r => setTimeout(r, 50));

    // Print prompt + animated typing
    this.term.write(PROMPT);
    for (const ch of cmd) {
      this.term.write(ch);
      await new Promise(r => setTimeout(r, charDelay));
    }
    await new Promise(r => setTimeout(r, 80));
    this.term.writeln('');

    // Execute the command
    if (this._onCommand) {
      await this._onCommand(cmd);
    }

    // Add to local-echo history
    this.localEcho.history.push(cmd);
  }
}
