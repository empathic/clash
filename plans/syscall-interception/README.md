# Syscall Interception for Runtime Enforcement

## Problem Statement

Clash currently enforces permissions at the **tool invocation layer** — it inspects the
tool name and arguments (e.g., the command string for Bash, the file path for Read/Write)
and decides allow/deny/ask **before** Claude Code executes anything. This means enforcement
is based on what the command *says* it will do, not what it *actually does*.

A `Bash(git status)` rule allows the string `git status`, but that command could:
- Read files outside the working directory
- Write to unexpected locations via subprocesses
- Make network connections
- Execute other binaries

The goal is to enforce what processes **actually do** at the syscall level, enabling
policies like:

```yaml
allow: read + write in $CWD/**
deny: network
deny: write outside $CWD
```

This research initially targeted Linux only, but macOS can be supported via
Apple's Seatbelt (`sandbox-exec`) without building an Endpoint Security extension.
The two platforms have different enforcement mechanisms but a compatible capability
surface, enabling a single cross-platform API.

---

## Linux Syscall Interception Mechanisms

### 1. Landlock LSM

**What it is:** A stackable Linux Security Module (since kernel 5.13) that allows
unprivileged processes to restrict their own filesystem and network access. Restrictions
are inherited by all child processes and can never be removed once applied.

**How it works:**
1. Create a ruleset defining allowed access rights
2. Add rules mapping paths to access rights (read, write, execute, etc.)
3. Call `landlock_restrict_self()` to apply — affects current thread + all descendants
4. `exec` the child process — it inherits all restrictions automatically

**Capabilities:**
- Filesystem: read, write, execute, make_dir, remove, truncate, refer (link/rename across dirs)
- Network: bind TCP, connect TCP (since kernel 6.4)
- Scoped: abstract unix sockets, signals (since ABI v6)

**Strengths:**
- **No root required** — unprivileged processes can self-sandbox
- **Kernel-enforced** — no TOCTOU races, enforcement happens at LSM hook level
- **Irrevocable** — once applied, restrictions can only be made stricter, never relaxed
- **Zero overhead for allowed operations** — kernel checks happen inline at access points
- **Child process inheritance** — automatic, guaranteed
- **Well-supported Rust crate** — `landlock` crate with ergonomic API

**Limitations:**
- Cannot distinguish between different programs — all processes in the sandbox get the
  same restrictions
- Cannot make per-syscall decisions (it's access-control, not syscall filtering)
- Cannot restrict read access granularly in current implementations (Codex notes this as TODO)
- Network filtering is TCP-only (UDP, ICMP not restricted)
- Requires kernel 5.13+ (filesystem), 6.4+ (network)
- No dynamic policy updates — must be set before exec

**Verdict:** Best fit for **baseline filesystem and network sandboxing**. This is the
primary mechanism and should be the foundation of any enforcement system.

---

### 2. seccomp-BPF

**What it is:** In-kernel syscall filtering using BPF programs. Can allow, deny, trap, or
log individual syscalls based on syscall number and register arguments.

**How it works:**
1. Install a BPF filter program via `seccomp(SECCOMP_SET_MODE_FILTER)`
2. Filter runs in-kernel on every syscall, inspecting syscall number + first 6 args
3. Returns an action: ALLOW, KILL, ERRNO, TRAP, LOG, or USER_NOTIF

**Strengths:**
- **Very fast** — BPF runs in kernel, near-zero overhead for allowed syscalls
- **Syscall-granular** — can block entire syscall classes (e.g., no `socket`, no `ptrace`)
- **No TOCTOU for register args** — BPF cannot dereference pointers, so what it checks
  is exactly what the kernel uses
- **Irrevocable + inherited** by child processes

**Limitations:**
- **Cannot inspect pointer arguments** — cannot see file paths passed to `openat()`,
  cannot see command strings passed to `execve()`
- **Cannot make path-based decisions** — only sees raw register values
- **Static policy** — set at install time, no dynamic updates

**Verdict:** Excellent complement to Landlock for **syscall surface reduction** (blocking
dangerous syscalls entirely: `ptrace`, `mount`, `reboot`, etc.) and **network isolation**
(blocking `socket` for non-AF_UNIX domains). Not useful alone for path-based enforcement.

---

### 3. seccomp User Notification (seccomp-unotify)

**What it is:** Extension to seccomp (since Linux 5.0) where `SECCOMP_RET_USER_NOTIF`
forwards a syscall to a supervisor process in userspace, which can inspect the target's
memory, make policy decisions, and optionally emulate the syscall.

**How it works:**
1. Install seccomp filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER` flag
2. Filter returns `SECCOMP_RET_USER_NOTIF` for syscalls of interest
3. Supervisor reads notification from listener fd (gets pid, syscall number, args)
4. Supervisor reads target's memory via `/proc/PID/mem` to inspect pointer args (paths, etc.)
5. Supervisor responds: allow (CONTINUE), deny (error code), or emulate (ADDFD)

**Strengths:**
- **Can inspect pointer arguments** — reads target memory to see actual file paths,
  command strings, etc.
- **Dynamic decisions** — supervisor can consult external policy, prompt user, etc.
- **Can emulate syscalls** — inject file descriptors (ADDFD since 5.9), useful for
  redirecting opens to different paths

**Limitations:**
- **EXPLICITLY NOT FOR SECURITY POLICY** — the Linux kernel documentation and maintainers
  (Christian Brauner) state unambiguously: "the seccomp user-space notification mechanism
  can not be used to implement a security policy." It is designed for *emulation*, not
  *enforcement*.
- **Inherent TOCTOU race** — between when the supervisor reads the target's memory and
  when the kernel actually executes the syscall, another thread in the target can modify
  the arguments. `SECCOMP_ADDFD_FLAG_SEND` (5.14+) mitigates this for fd-returning
  syscalls only.
- **Performance overhead** — every intercepted syscall requires context switches to/from
  the supervisor process
- **Complexity** — supervisor must handle concurrent notifications, PID reuse races, etc.
- **Bypassable** — if the filter allows `seccomp()` or `prctl()`, target can install a
  higher-priority filter that overrides USER_NOTIF

**Verdict:** **Not recommended as a security mechanism.** Useful for syscall *emulation*
(container runtimes, compatibility layers) but the TOCTOU issues make it unsuitable for
enforcement. The kernel docs are explicit about this.

---

### 4. ptrace

**What it is:** The classic process tracing mechanism. A tracer process can intercept
every syscall entry/exit of a tracee, inspect and modify registers and memory.

**How it works:**
1. Fork child, call `PTRACE_TRACEME` in child
2. Parent uses `PTRACE_SYSCALL` to stop child at every syscall entry/exit
3. Parent reads registers to see syscall number + args
4. Parent reads child memory to see pointer args
5. Parent can modify registers to change syscall or return value

**Strengths:**
- **Full visibility** — can see everything, modify everything
- **Mature** — well-understood, decades of usage (strace, gdb)

**Limitations:**
- **Very slow** — 2+ context switches per syscall (4 if inspecting entry+exit)
- **TOCTOU vulnerable** — same memory inspection races as seccomp-unotify
- **Single tracer** — only one process can ptrace a target at a time
- **Can be used to escape seccomp** — seccomp docs warn that ptrace can bypass filters
- **Fragile** — signal handling interactions, group-stop complexity

**Verdict:** **Not recommended for production enforcement.** Performance cost is
prohibitive, and the TOCTOU issues make it unsuitable for security policy. Fine for
debugging/tracing tools only.

---

### 5. eBPF/LSM Hooks

**What it is:** Since Linux 5.7, eBPF programs can be attached to LSM hooks, enabling
dynamic, programmable security policy enforcement in the kernel.

**How it works:**
1. Write eBPF programs that attach to LSM hooks (e.g., `file_open`, `bprm_check_security`,
   `socket_create`)
2. Load programs via `bpf()` syscall
3. Programs run in-kernel at the LSM hook points, can allow or deny operations
4. Can use BPF maps for dynamic policy lookup

**Strengths:**
- **Kernel-enforced** — no TOCTOU issues, decisions happen at the right kernel layer
- **Dynamic** — policies can be loaded/updated at runtime via BPF maps
- **Path-aware** — LSM hooks provide resolved paths, not raw pointer arguments
- **Very fast** — near-zero overhead, runs in kernel JIT-compiled
- **Flexible** — can implement arbitrary policy logic, per-cgroup, per-container

**Limitations:**
- **Requires CAP_BPF / CAP_SYS_ADMIN** — not unprivileged, needs root
- **Complex** — writing correct eBPF programs is non-trivial, verifier constraints
- **Kernel version dependent** — needs 5.7+ with BPF LSM enabled (`CONFIG_BPF_LSM=y`)
  and LSM boot param including "bpf" (not enabled by default on many distros)
- **Limited Rust support** — eBPF programs are typically written in C, loaded via
  libbpf; Rust wrappers exist (aya, libbpf-rs) but BPF LSM specifically is less mature
- **Portability concerns** — BPF program behavior can vary across kernel versions

**Verdict:** **Most powerful option but requires elevated privileges.** Ideal for
system-wide enforcement but not suitable for unprivileged per-user sandboxing. Could be
an optional "enhanced mode" for environments where root is available.

---

## macOS Seatbelt (sandbox-exec)

### What it is

Apple's Seatbelt is a kernel-level sandbox enforced via MACF (Mandatory Access
Control Framework). Processes are sandboxed by applying a **Sandbox Profile**
written in SBPL (Sandbox Profile Language) — a Scheme-like DSL. Profiles can be
applied via `sandbox-exec -p <profile>` or programmatically via `sandbox_init()`.

### SBPL Profile Language

```scheme
(version 1)
(deny default)                              ; deny everything by default

;; Filesystem
(allow file-read*
    (subpath "/usr")
    (subpath "/System")
    (subpath "/Library")
    (subpath (param "PROJECT_DIR")))         ; parameterized paths

(allow file-write*
    (subpath (param "PROJECT_DIR"))
    (literal "/dev/null"))

;; Process
(allow process-exec
    (subpath "/usr/bin")
    (subpath "/usr/local/bin"))

;; Network — deny by default via (deny default), or explicitly:
(deny network*)                              ; block all network
;; or allow selectively:
;; (allow network* (remote ip "localhost:*"))
```

### Capabilities and Limitations

**What Seatbelt can enforce:**
- File read/write/execute by path (literal, subpath, regex)
- Network access (all-or-nothing, or by remote address)
- Process execution
- Mach/IPC services
- Sysctl access
- Signal delivery

**What it cannot do (vs. Landlock+seccomp):**
- No per-syscall filtering (it operates at MACF operation level, not syscall level)
- No fine-grained socket domain filtering (AF_UNIX vs AF_INET) in SBPL
- Profiles are static once applied — cannot be tightened at runtime
- `sandbox-exec` is marked deprecated (still works, but Apple doesn't document it)
- Cannot restrict by file descriptor or inode — path-based only

**What it CAN do that Linux mechanisms struggle with:**
- Path-based read restrictions are first-class (Landlock can too, but Codex hasn't
  implemented read restrictions yet)
- Mach IPC and XPC restrictions (no Linux equivalent)
- Regex path matching in the kernel

### Child Process Inheritance

Like Landlock, Seatbelt restrictions are inherited by all child processes and
cannot be removed. A sandboxed `bash` spawning `python` spawning `curl` — all
inherit the same profile restrictions.

### How Codex Uses Seatbelt

OpenAI Codex generates an SBPL profile at runtime by:
1. Starting with `(deny default)` base
2. Injecting writable paths as parameters (`WRITABLE_ROOT_0`, `WRITABLE_ROOT_1`, etc.)
3. Protecting `.git` and `.codex` as read-only even within writable roots
4. Optionally including a network policy from `seatbelt_network_policy.sbpl`
5. Executing via `sandbox-exec -p <generated_profile> -- <command>`

---

## Cross-Platform Sandbox API

### Design Principle

The API exposes **high-level capabilities** — read, write, create, delete, execute,
network — not syscalls, LSM hooks, or SBPL operations. Each platform backend maps
these capabilities to its own enforcement primitives. Users never think about Landlock
rights or Seatbelt operations.

Both Landlock and Seatbelt have the granularity to support this:

| Capability | Linux (Landlock) | macOS (Seatbelt) |
|---|---|---|
| `read` | `ReadFile + ReadDir` | `file-read*` |
| `write` | `WriteFile + Truncate` | `file-write-data` |
| `create` | `MakeReg + MakeDir + MakeSym + MakeFifo + MakeSock + MakeChar + MakeBlock` | `file-write-create` |
| `delete` | `RemoveFile + RemoveDir` | `file-write-unlink` |
| `execute` | `Execute` | `process-exec` |
| `network` | seccomp blocks `socket()` for non-AF_UNIX | `(deny network*)` |

The abstraction is a list of **capability rules** applied to paths.

### Proposed API

```rust
use bitflags::bitflags;

bitflags! {
    /// High-level filesystem capabilities.
    /// Each backend maps these to its own enforcement primitives.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Cap: u8 {
        const READ    = 0b0000_0001;
        const WRITE   = 0b0000_0010;
        const CREATE  = 0b0000_0100;
        const DELETE  = 0b0000_1000;
        const EXECUTE = 0b0001_0000;
    }
}

/// A sandbox policy is a list of capability rules applied to paths,
/// plus a network policy. Platform backends compile this to their
/// native enforcement (Landlock+seccomp, Seatbelt SBPL, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Default capabilities for paths not matched by any rule.
    /// Typical default: READ | EXECUTE (can read and run, but not modify).
    pub default: Cap,

    /// Ordered list of rules. First match wins (like a firewall).
    pub rules: Vec<SandboxRule>,

    /// Network access policy.
    pub network: NetworkPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRule {
    /// The path this rule applies to. Supports $CWD, $HOME, $TMPDIR.
    pub path: String,

    /// Whether to include all descendants (true) or just this exact path.
    #[serde(default = "default_true")]
    pub recursive: bool,

    /// The capabilities granted (allow rule) or denied (deny rule).
    pub caps: Cap,

    /// Whether this rule grants or revokes capabilities.
    pub effect: RuleEffect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkPolicy {
    /// No network access. Unix domain sockets still allowed where possible.
    Deny,
    /// Unrestricted network access.
    Allow,
}
```

### Policy YAML Syntax

The user-facing policy expresses capabilities directly:

```yaml
sandbox:
  # Default: can read and execute, but not write/create/delete
  default: read + execute

  rules:
    # Working directory: full access
    - allow read + write + create + delete in $CWD

    # But protect .git from writes and deletes
    - deny write + delete + create in $CWD/.git

    # Prevent reading secrets
    - deny read in $CWD/.env
    - deny read in $HOME/.ssh

    # Allow writing to temp
    - allow write + create + delete in /tmp
    - allow write + create + delete in $TMPDIR

    # Specific tool needs: cargo/npm caches
    - allow write + create + delete in $HOME/.cargo/registry
    - allow write + create + delete in $HOME/.npm

  network: deny
```

This directly answers the user's examples:
- "no child process can read X" → `deny read in X`
- "child procs can write but not delete" → `allow read + write + create in $CWD` (omit `delete`)

### Capability Compilation

Each backend compiles `Cap` flags to its native primitives:

```
Cap::READ
    ├─ Linux  → Landlock: AccessFs::ReadFile | AccessFs::ReadDir
    └─ macOS  → SBPL: (allow file-read-data) (allow file-read-metadata)

Cap::WRITE
    ├─ Linux  → Landlock: AccessFs::WriteFile | AccessFs::Truncate
    └─ macOS  → SBPL: (allow file-write-data)

Cap::CREATE
    ├─ Linux  → Landlock: AccessFs::MakeReg | AccessFs::MakeDir | AccessFs::MakeSym
    │                      | AccessFs::MakeFifo | AccessFs::MakeSock
    └─ macOS  → SBPL: (allow file-write-create)

Cap::DELETE
    ├─ Linux  → Landlock: AccessFs::RemoveFile | AccessFs::RemoveDir
    └─ macOS  → SBPL: (allow file-write-unlink)

Cap::EXECUTE
    ├─ Linux  → Landlock: AccessFs::Execute
    └─ macOS  → SBPL: (allow process-exec)

NetworkPolicy::Deny
    ├─ Linux  → seccomp: block socket() for non-AF_UNIX domains
    │           seccomp: block connect, bind, listen, sendto, etc.
    └─ macOS  → SBPL: (deny network*)

NetworkPolicy::Allow
    ├─ Linux  → no seccomp network filter
    └─ macOS  → SBPL: (allow network*)
```

### Platform Backend Trait

```rust
/// Platform-specific sandbox enforcement.
/// Each platform compiles SandboxPolicy to its native mechanism.
pub trait SandboxBackend {
    /// Apply the sandbox policy and exec the command.
    /// Does not return on success (replaces the process via execvp).
    fn exec_sandboxed(
        policy: &SandboxPolicy,
        cwd: &Path,
        command: &[String],
    ) -> Result<!, SandboxError>;

    /// Check whether this platform supports sandboxing.
    fn is_supported() -> SupportLevel;
}

pub enum SupportLevel {
    Full,
    Partial { missing: Vec<String> },
    Unsupported { reason: String },
}
```

The backend implementations are internal — users never interact with Landlock
or Seatbelt directly. They write capability rules, and the backend does the
right thing.

### Unified CLI

The sandbox is a subcommand of `clash` itself — no separate binary:

```
# Apply sandbox and exec a command:
clash sandbox exec --policy <json> --cwd /project -- bash -c "npm test"

# Launch Claude Code with clash managing hooks + sandbox:
clash launch [-- claude-code-args...]

# Test sandbox enforcement interactively:
clash sandbox test --policy <json> --cwd /project -- ls -la /etc
```

This works because the sandbox setup (Landlock/seccomp/Seatbelt) is applied to the
current process and then `execvp` replaces it. The `clash` binary is already on PATH
via the plugin, so the PreToolUse hook can rewrite Bash commands to:

```
clash sandbox exec --policy '...' --cwd $CWD -- bash -c "git status"
```

Internally:
- **Linux**: resolves paths → builds Landlock ruleset from Cap flags → installs
  seccomp network filter → sets `NO_NEW_PRIVS` → `execvp`
- **macOS**: resolves paths → generates SBPL profile from Cap flags → applies
  via `sandbox_init()` FFI → `execvp`

### Platform-Specific Behavior

The capability model is deliberately simple. Where platforms differ, the backend
does the best it can:

| Behavior | Linux | macOS |
|---|---|---|
| `network: deny` | AF_UNIX still allowed (tools need socketpair for IPC) | All sockets blocked (may need macOS-specific workaround) |
| Dangerous syscall blocking | seccomp blocks ptrace, mount, reboot, kexec, module_load | `(deny default)` covers most; backends add safe defaults |
| Mach IPC | N/A | Backend always allows `sysctl-read` + `mach-lookup` (tools break without these) |
| Dynamic tightening | Landlock can stack restrictions | Profile is static once applied |

These are backend details — the user's policy YAML is the same on both platforms.

---

## Recommended Architecture

### Approach: Layered Defense (Landlock + seccomp-BPF)

This is the same approach used by OpenAI Codex CLI, the `hakoniwa` crate, Google's
Sandbox2, and various container runtimes. It's battle-tested and well-understood.

### Unified CLI

Clash is a single binary with multiple roles:

```
clash launch           — start Claude Code with clash managing hooks + sandbox
clash hook pre-tool-use  — existing: evaluate intent policy
clash hook post-tool-use — existing: informational
clash sandbox exec     — new: apply sandbox and exec a command
clash sandbox test     — new: test sandbox interactively
clash migrate          — existing: convert legacy permissions
```

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│  $ clash launch                                          │
│  (starts Claude Code with clash registered as hook)      │
│                                                          │
│  Claude Code calls: clash hook pre-tool-use              │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  clash hook pre-tool-use                            │ │
│  │                                                     │ │
│  │  1. Receive tool input from stdin                   │ │
│  │  2. Evaluate intent policy (allow/deny/ask)         │ │
│  │  3. If allowed + sandbox policy exists:             │ │
│  │     rewrite command via updated_input to:           │ │
│  │     "clash sandbox exec --policy ... -- <cmd>"      │ │
│  │  4. Return allow + updated_input                    │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  Claude Code executes the rewritten command:             │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  clash sandbox exec --policy <json> -- bash -c ...  │ │
│  │                                                     │ │
│  │  1. Parse sandbox policy from --policy              │ │
│  │  2. Apply Landlock rules (Linux) or SBPL (macOS)    │ │
│  │  3. Apply seccomp-BPF filter (Linux only)           │ │
│  │  4. Drop privileges (no_new_privs)                  │ │
│  │  5. execvp(target_command)                          │ │
│  │                                                     │ │
│  │  ← restrictions inherited by all descendants →      │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Two Enforcement Layers, One Binary

**Layer 1: Intent Policy** (existing `clash hook pre-tool-use`)

Decides *whether* a tool runs. Uses the existing statement-based policy engine
(`allow * bash git *`, `deny * bash rm -rf *`). Returns allow/deny/ask.

**Layer 2: Capability Sandbox** (new `clash sandbox exec`)

Limits *what the command can actually do* once running. Kernel-enforced,
irrevocable, inherited by all child processes.

Both layers are enforced by the same `clash` binary in different invocation modes.
The hook rewrites the command so that Claude Code unknowingly runs it through the
sandbox. This uses the existing `updated_input` field in the hook protocol — no
changes to Claude Code required.

### `clash launch`

The `launch` subcommand is the user-facing entry point:

```bash
# Start Claude Code with clash enforcement
clash launch

# Pass args through to claude
clash launch -- --model sonnet --verbose

# Launch with a specific policy file
clash launch --policy ./strict-policy.yaml
```

`clash launch` does:
1. Ensures hooks are registered (sets up the hook config pointing to itself)
2. Loads and validates the sandbox policy
3. Spawns Claude Code as a child process with the right hook environment
4. Exits when Claude Code exits

### Policy Mapping

The clash policy file gains a `sandbox:` section alongside the existing `rules:`.
The two layers are complementary:

```yaml
default: ask

rules:
  # Layer 1: intent-based rules (existing clash policy engine)
  - allow * bash git *
  - deny * bash rm -rf *

# Layer 2: capability-based sandbox (new, kernel-enforced)
sandbox:
  default: read + execute

  rules:
    - allow read + write + create + delete in $CWD
    - deny write + delete + create in $CWD/.git
    - deny read in $CWD/.env
    - allow write + create + delete in /tmp

  network: deny
```

Intent rules decide *whether* a tool runs. Sandbox rules limit *what it can
actually do* once running. Both layers apply — a command must pass the intent
check AND operates within the sandbox.

---

## Implementation Plan

### Phase 1: Capability Types + Linux Backend

**Goal:** Define `Cap`, `SandboxPolicy`, `SandboxRule` and implement Linux enforcement.

1. Add `Cap` bitflags, `SandboxPolicy`, `SandboxRule`, `SandboxBackend` trait to
   a new `sandbox` module in `claude_settings` (shared types) or `clash` (if
   clash-specific)
2. Add `clash sandbox exec` and `clash sandbox test` subcommands to `clash/src/main.rs`
3. Implement `LinuxSandbox` backend (behind `#[cfg(target_os = "linux")]`):
   - Map `Cap` flags → Landlock `AccessFs` bitflags
   - `landlock` crate for filesystem access control
   - `seccompiler` (pure Rust) for network filtering via seccomp
   - `PR_SET_NO_NEW_PRIVS` for privilege escalation prevention
4. Add `landlock` + `seccompiler` as Linux-only dependencies in `clash/Cargo.toml`
5. Test on Linux with common commands (git, npm, cargo, python, etc.)

### Phase 2: macOS Seatbelt Backend

**Goal:** Implement macOS enforcement via the same `Cap`/`SandboxPolicy` API.

1. Implement `MacOSSandbox` backend (behind `#[cfg(target_os = "macos")]`):
   - Map `Cap` flags → SBPL operations (`file-read*`, `file-write-data`,
     `file-write-create`, `file-write-unlink`, `process-exec`)
   - Generate SBPL profile string from `SandboxPolicy`
   - Apply via `sandbox_init()` FFI (preferred) or `sandbox-exec -p` (fallback)
2. Handle macOS-specific needs:
   - Always allow `sysctl-read`, `mach-lookup` (tools won't function without these)
   - `process-fork` must be allowed for subprocesses
   - Test Seatbelt-specific edge cases (dyld, signed binaries, etc.)
3. `clash sandbox exec` now works on both platforms — same subcommand, different backend
4. Test on macOS with same command suite

### Phase 3: Policy Language + Hook Integration

**Goal:** Parse `sandbox:` YAML and wire up the hook to rewrite commands.

1. Add `sandbox:` section to policy.yaml schema
2. Parse capability expressions (`read + write + create`)
3. Implement policy-to-`SandboxPolicy` compilation
4. Modify `check_permission` in `permissions.rs`: when allowing a Bash tool and
   a sandbox policy exists, set `updated_input` to rewrite the command as
   `clash sandbox exec --policy '...' --cwd $CWD -- <original command>`
5. Environment variable expansion (`$CWD`, `$HOME`, `$TMPDIR`)

### Phase 4: `clash launch`

**Goal:** Provide a single command to start Claude Code with full enforcement.

1. Add `clash launch` subcommand
2. Generate/validate hook configuration pointing to `clash hook pre-tool-use` etc.
3. Spawn Claude Code as a child process with hook env set up
4. Pass through args to Claude Code
5. Support `--policy <file>` to override default policy path

### Phase 5: Testing

**Goal:** End-to-end testing on both platforms.

1. Unit tests for `Cap` → Landlock/SBPL compilation
2. `clash sandbox test` subcommand for interactive testing
3. Add clester tests for sandbox behavior via hook integration
4. Test common tool invocations work under sandbox on both platforms
5. Test that violations are properly blocked and reported
6. Graceful degradation: older kernels, containerized environments, etc.
7. Platform-specific edge case testing (macOS: `uv`/`cargo` Mach IPC needs,
   Linux: `/proc` access for tools, nested container environments)

---

## Rust Crate Ecosystem

| Crate | Purpose | Notes |
|-------|---------|-------|
| [`landlock`](https://crates.io/crates/landlock) | Landlock LSM bindings | Official, maintained by Landlock authors. Ergonomic API, best-effort compat mode. |
| [`libseccomp`](https://crates.io/crates/libseccomp) | seccomp-BPF bindings | Wraps libseccomp C library. v0.4.0, supports user notification API. |
| [`seccompiler`](https://crates.io/crates/seccompiler) | Pure Rust seccomp-BPF | From AWS Firecracker. No C dependency, but lower-level. |
| [`hakoniwa`](https://crates.io/crates/hakoniwa) | Full isolation framework | Combines namespaces + landlock + seccomp. LGPL-3.0. |
| [`extrasafe`](https://crates.io/crates/extrasafe) | Ergonomic seccomp | High-level rule groups (e.g., "allow networking", "allow filesystem read"). |
| [`seccomp-stream`](https://crates.io/crates/seccomp-stream) | Async seccomp-unotify | Tokio adapter for notification fd. Niche use case. |

**Recommended for clash:**
- `landlock` — primary filesystem/network enforcement
- `libseccomp` or `seccompiler` — syscall filtering (seccompiler avoids the C dependency
  which is nice for the Rust-only build, but libseccomp is more feature-complete)

---

## Comparison with OpenAI Codex CLI

OpenAI's Codex CLI uses exactly this Landlock + seccomp approach. Key details from their
implementation:

- **Landlock ABI V5** for filesystem access control
- **Default-deny for writes**, allow-list for writable paths (CWD + /tmp + /dev/null)
- **Default-allow for reads** across filesystem (with plans to restrict)
- **seccomp for network**: blocks `socket()` except AF_UNIX domain
- **Helper binary**: `codex-linux-sandbox` applies restrictions before exec
- **Architecture**: x86_64 and aarch64 only for seccomp
- **Graceful degradation**: `BestEffort` compatibility level for older kernels
- **Rust implementation**: native bindings, no runtime overhead

Clash can take the same approach with tighter policy integration since clash already has
a policy engine.

---

## Security Considerations

### What This Approach Prevents
- Process writes to files outside allowed paths
- Network access when policy says "no network"
- Privilege escalation via setuid/ptrace/mount
- Subprocess escape from sandbox (restrictions are inherited + irrevocable)

### What This Approach Does NOT Prevent
- **Information exfiltration via allowed channels** — if a process can write to $CWD, it
  can encode secrets into files that Claude Code then reads
- **Resource exhaustion** — Landlock/seccomp don't limit CPU/memory (use cgroups for that)
- **Covert channels** — timing attacks, /proc information leaks, etc.
- **Kernel exploits** — if the kernel has a bug, sandbox can be escaped
- **Symlink/hardlink attacks within allowed paths** — Landlock handles this at the inode
  level but complex path traversals can still be tricky

### TOCTOU Safety
Landlock enforces at the LSM hook level, which is the same point where the kernel resolves
paths and checks permissions. There is no gap between "check" and "use" — the check IS
the use decision. This is fundamentally different from ptrace or seccomp-unotify approaches
where there's a time gap between inspecting arguments and the kernel acting on them.

### Kernel Version Requirements
- Landlock filesystem: Linux 5.13+ (2021)
- Landlock network: Linux 6.4+ (2023)
- seccomp-BPF: Linux 3.17+ (2014)
- Minimum practical target: **Linux 5.13** (Ubuntu 21.10+, Debian 12+, RHEL 9+)

---

## Open Questions

1. **Integration point**: How does clash tell Claude Code to use the sandbox wrapper?
   - Does Claude Code support custom command wrappers via settings/hooks?
   - Should clash evolve to manage execution itself (plugin model)?
   - Can the PreToolUse hook response modify the command to include the wrapper?

2. **Per-command sandbox variation**: Should different commands get different sandboxes?
   - `git push` needs network; `git status` doesn't
   - This might require the policy to express per-command sandbox overrides
   - Or: network is controlled at the intent layer (allow/deny the tool use), sandbox
     is a uniform baseline

3. **Read restrictions**: Landlock can restrict reads, but many tools need broad read
   access (compilers, linters, etc.). Should read restrictions be opt-in only?

4. **Graceful degradation**: What happens on kernels without Landlock or without
   `sandbox-exec`?
   - Fail open (warn but allow execution)? Dangerous.
   - Fail closed (block execution)? Frustrating.
   - Configurable per policy?

5. **Performance impact**: Landlock adds near-zero overhead for allowed operations, but
   what about the sandbox helper process setup cost (fork + exec)?

6. **Testing**: How to test sandbox behavior in CI? Docker containers may not have
   Landlock support depending on host kernel and Docker seccomp profile. macOS CI runners
   may have different Seatbelt behavior.

7. **macOS `sandbox-exec` deprecation**: Apple has marked `sandbox-exec` as deprecated
   but has not removed it. Codex still uses it. Alternatives:
   - Call `sandbox_init()` / `sandbox_init_with_parameters()` directly via FFI
   - These are private API but stable in practice (used by every macOS app sandbox)
   - Long-term: Apple may provide a public replacement, but as of 2025 has not

8. **Seatbelt SBPL profile complexity**: Some tools (cargo, python, node) need access
   to Mach services, `sysctl-read`, and other macOS-specific operations. The baseline
   SBPL profile needs careful tuning — too restrictive breaks tools, too permissive
   defeats the purpose. OpenAI Codex solved this by iterating on real-world failures.

9. **Network granularity gap**: On Linux, seccomp can allow AF_UNIX while blocking
   AF_INET/AF_INET6. Seatbelt's `(deny network*)` blocks everything including Unix
   domain sockets. This matters for tools using socketpair for IPC. May need
   macOS-specific exceptions.
