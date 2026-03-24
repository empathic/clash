/* tslint:disable */
/* eslint-disable */

/**
 * Check a tool invocation against a compiled policy.
 *
 * Arguments:
 * - `policy_json`: the v5 JSON policy document (from `evaluate_starlark`)
 * - `tool_name`: the tool being invoked (e.g. "Bash", "Glob", "Read")
 * - `tool_input_json`: the tool's input as JSON (e.g. `{"command": "git status"}`)
 * - `env_json`: environment variables as JSON (e.g. `{"PWD": "/project", "HOME": "/home/user"}`)
 *
 * Returns a JSON string with the decision:
 * ```json
 * {
 *   "effect": "allow",
 *   "reason": "result: allow",
 *   "sandbox": "sandbox_name",
 *   "sandbox_policy": { ... },
 *   "trace": ["Rule 'ToolName=Bash' matched — action allowed", ...]
 * }
 * ```
 */
export function check_permission(policy_json: string, tool_name: string, tool_input_json: string, env_json: string): string;

/**
 * Evaluate a Starlark policy source and return the compiled JSON policy document.
 *
 * The source should define a `main()` function that returns a policy value.
 * Standard library modules (`@clash//std.star`, `@clash//rust.star`, etc.)
 * are available via `load()`.
 */
export function evaluate_starlark(source: string): string;

/**
 * Format the rules in a compiled policy as human-readable lines.
 */
export function format_rules(policy_json: string): string;

/**
 * Set up panic hook for better WASM error messages.
 */
export function start(): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly check_permission: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly evaluate_starlark: (a: number, b: number) => [number, number, number, number];
    readonly format_rules: (a: number, b: number) => [number, number, number, number];
    readonly start: () => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
