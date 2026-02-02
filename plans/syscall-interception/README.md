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

The key insight is that **Landlock+seccomp and Seatbelt have a compatible capability
surface**, even though their enforcement mechanisms differ completely. Both support:

| Capability | Linux (Landlock + seccomp) | macOS (Seatbelt) |
|---|---|---|
| Restrict writable paths | Landlock `AccessFs::from_all(abi)` on allowed paths | `(allow file-write* (subpath ...))` |
| Allow reads broadly | Landlock `AccessFs::from_read(abi)` on `/` | `(allow file-read* (subpath "/"))` |
| Restrict reads to paths | Landlock read rules on specific paths | `(allow file-read* (subpath ...))` |
| Block network | seccomp blocks `socket()` for non-AF_UNIX | `(deny network*)` |
| Allow network | Don't install seccomp network filter | `(allow network*)` |
| Block dangerous syscalls | seccomp blocklist (ptrace, mount, etc.) | `(deny default)` covers most of these |
| Allow process execution | Landlock execute access on paths | `(allow process-exec (subpath ...))` |
| Child inheritance | Automatic + irrevocable | Automatic + irrevocable |
| No privilege escalation | `PR_SET_NO_NEW_PRIVS` | Implicit in Seatbelt |

The abstraction is a **platform-agnostic sandbox policy** that compiles down to either
Landlock+seccomp rules or an SBPL profile.

### Proposed API

```rust
/// Platform-agnostic sandbox policy.
///
/// Compiles to Landlock+seccomp on Linux, SBPL profile on macOS.
/// Describes the maximum capabilities a sandboxed process tree may have.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Filesystem access rules. Evaluated as allow-list against a default-deny
    /// for writes and (optionally) reads.
    pub filesystem: FilesystemPolicy,

    /// Network access policy.
    pub network: NetworkPolicy,

    /// Additional platform-agnostic restrictions.
    pub restrictions: Restrictions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    /// Paths the sandbox may write to. Everything else is read-only (or denied).
    /// Supports environment variable expansion ($CWD, $HOME, $TMPDIR).
    pub writable_paths: Vec<SandboxPath>,

    /// Paths the sandbox may read from. If empty, reads are unrestricted.
    /// When non-empty, acts as an allow-list (default-deny for reads).
    pub readable_paths: Vec<SandboxPath>,

    /// Paths the sandbox may execute binaries from.
    /// Defaults to system paths (/usr/bin, /usr/local/bin, etc.) if empty.
    pub executable_paths: Vec<SandboxPath>,

    /// Paths that are always denied (overrides writable/readable).
    /// Use for protecting sensitive files within otherwise-allowed directories.
    /// e.g., deny write to .git/** even though $CWD is writable.
    pub denied_paths: Vec<DeniedPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPath {
    /// The path, possibly with environment variables ($CWD, $HOME, $TMPDIR).
    pub path: String,
    /// Whether to include all descendants (subpath) or just this exact path.
    pub recursive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeniedPath {
    pub path: SandboxPath,
    /// Which access to deny: read, write, or both.
    pub deny: DenyAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DenyAccess {
    Read,
    Write,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkPolicy {
    /// No network access (default). AF_UNIX still allowed on Linux.
    Deny,
    /// Full network access.
    Allow,
    /// Allow only specific targets (future: TCP connect to host:port).
    AllowSpecific(Vec<NetworkTarget>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTarget {
    pub host: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Restrictions {
    /// Block ptrace, mount, and other dangerous syscalls.
    /// On macOS, covered by (deny default). On Linux, via seccomp.
    pub block_dangerous_syscalls: bool,

    /// Set NO_NEW_PRIVS on Linux. Always true on macOS (implicit).
    pub no_new_privs: bool,
}
```

### Policy YAML Syntax

The user-facing YAML maps directly to `SandboxPolicy`:

```yaml
sandbox:
  filesystem:
    writable:
      - $CWD          # working directory (recursive by default)
      - /tmp
      - $TMPDIR
    readable: []       # empty = unrestricted reads
    executable:
      - /usr/bin
      - /usr/local/bin
      - /opt/homebrew/bin    # macOS homebrew
      - /nix                 # nix users
    deny:
      - path: $CWD/.git
        access: write        # protect .git from writes
      - path: $CWD/.env
        access: read         # prevent reading secrets

  network: deny              # or: allow, or list of host:port

  restrictions:
    block_dangerous_syscalls: true
    no_new_privs: true
```

### Compilation Targets

The `SandboxPolicy` compiles to platform-specific enforcement:

```
SandboxPolicy
    │
    ├─── Linux: compile_to_landlock_seccomp()
    │    │
    │    ├── Landlock ruleset
    │    │   ├── AccessFs::from_read(abi) on readable paths (or /)
    │    │   ├── AccessFs::from_all(abi) on writable paths
    │    │   └── AccessFs::Execute on executable paths
    │    │
    │    ├── seccomp-BPF filter
    │    │   ├── Block socket() for non-AF_UNIX (if network=deny)
    │    │   ├── Block ptrace, mount, reboot, etc.
    │    │   └── Allow everything else
    │    │
    │    └── prctl(PR_SET_NO_NEW_PRIVS)
    │
    └─── macOS: compile_to_sbpl()
         │
         └── SBPL profile string
             ├── (version 1)
             ├── (deny default)
             ├── (allow file-read* ...) for readable paths
             ├── (allow file-write* ...) for writable paths
             ├── (allow process-exec ...) for executable paths
             ├── (deny network*) or (allow network*)
             └── (param ...) for variable expansion
```

### Platform Backend Trait

```rust
/// Platform-specific sandbox enforcement backend.
pub trait SandboxBackend {
    /// Apply the sandbox policy and exec the command.
    /// This function does not return on success (replaces the process).
    fn exec_sandboxed(
        policy: &SandboxPolicy,
        cwd: &Path,
        command: &[String],
    ) -> Result<!, SandboxError>;

    /// Check if the current platform/kernel supports this backend.
    fn is_supported() -> SupportLevel;
}

pub enum SupportLevel {
    /// Full support for all policy features.
    Full,
    /// Partial support (e.g., filesystem but not network on older Linux).
    Partial { unsupported: Vec<String> },
    /// Not supported on this platform/kernel.
    Unsupported { reason: String },
}

// Platform implementations:

#[cfg(target_os = "linux")]
pub struct LinuxSandbox;

#[cfg(target_os = "linux")]
impl SandboxBackend for LinuxSandbox {
    fn exec_sandboxed(
        policy: &SandboxPolicy,
        cwd: &Path,
        command: &[String],
    ) -> Result<!, SandboxError> {
        // 1. set_no_new_privs()
        // 2. install_seccomp_filter(policy)
        // 3. install_landlock_rules(policy, cwd)
        // 4. execvp(command)
        todo!()
    }

    fn is_supported() -> SupportLevel {
        // Check kernel version, Landlock ABI, seccomp support
        todo!()
    }
}

#[cfg(target_os = "macos")]
pub struct MacOSSandbox;

#[cfg(target_os = "macos")]
impl SandboxBackend for MacOSSandbox {
    fn exec_sandboxed(
        policy: &SandboxPolicy,
        cwd: &Path,
        command: &[String],
    ) -> Result<!, SandboxError> {
        // 1. Compile SandboxPolicy → SBPL string
        // 2. Write to temp file or pass via -p
        // 3. exec sandbox-exec -p <profile> -- <command>
        todo!()
    }

    fn is_supported() -> SupportLevel {
        // Check that /usr/bin/sandbox-exec exists
        todo!()
    }
}
```

### SBPL Profile Generation

The macOS backend generates an SBPL profile from `SandboxPolicy`:

```rust
fn compile_to_sbpl(policy: &SandboxPolicy, cwd: &Path) -> String {
    let mut profile = String::from("(version 1)\n(deny default)\n");

    // Readable paths
    if policy.filesystem.readable_paths.is_empty() {
        // Unrestricted reads
        profile += "(allow file-read*)\n";
    } else {
        for path in &policy.filesystem.readable_paths {
            let resolved = resolve_sandbox_path(path, cwd);
            profile += &format!("(allow file-read* (subpath \"{}\"))\n", resolved);
        }
    }

    // Writable paths
    for path in &policy.filesystem.writable_paths {
        let resolved = resolve_sandbox_path(path, cwd);
        profile += &format!("(allow file-write* (subpath \"{}\"))\n", resolved);
    }
    profile += "(allow file-write* (literal \"/dev/null\"))\n";

    // Denied paths (override allows)
    for denied in &policy.filesystem.denied_paths {
        let resolved = resolve_sandbox_path(&denied.path, cwd);
        match denied.deny {
            DenyAccess::Write => {
                profile += &format!("(deny file-write* (subpath \"{}\"))\n", resolved);
            }
            DenyAccess::Read => {
                profile += &format!("(deny file-read* (subpath \"{}\"))\n", resolved);
            }
            DenyAccess::ReadWrite => {
                profile += &format!("(deny file-read* (subpath \"{}\"))\n", resolved);
                profile += &format!("(deny file-write* (subpath \"{}\"))\n", resolved);
            }
        }
    }

    // Executable paths
    for path in &policy.filesystem.executable_paths {
        let resolved = resolve_sandbox_path(path, cwd);
        profile += &format!("(allow process-exec (subpath \"{}\"))\n", resolved);
    }
    // Always allow process-fork for subprocesses
    profile += "(allow process-fork)\n";

    // Network
    match &policy.network {
        NetworkPolicy::Deny => {
            profile += "(deny network*)\n";
        }
        NetworkPolicy::Allow => {
            profile += "(allow network*)\n";
        }
        NetworkPolicy::AllowSpecific(targets) => {
            for target in targets {
                let port = target.port.map(|p| format!(":{}", p)).unwrap_or_default();
                profile += &format!(
                    "(allow network* (remote ip \"{}:{}\"))\n",
                    target.host, port
                );
            }
        }
    }

    // Seatbelt-specific: allow sysctl-read, mach-lookup for basic process
    // operation (many tools need these to function)
    profile += "(allow sysctl-read)\n";
    profile += "(allow mach-lookup)\n";

    profile
}
```

### Capability Gaps Between Platforms

Not everything maps 1:1. The abstraction must handle these differences:

| Feature | Linux | macOS | Cross-Platform Handling |
|---|---|---|---|
| AF_UNIX socket filtering | seccomp allows AF_UNIX specifically | Seatbelt allows all sockets or none | On macOS, `network: deny` blocks less granularly. Document the difference. |
| Per-syscall blocklist | seccomp-BPF filter | Not possible in SBPL | `block_dangerous_syscalls` is best-effort on macOS — `(deny default)` covers most. |
| Regex path matching | Not in Landlock (glob only in policy, resolved to paths) | Native SBPL `(regex #"...")` | Use resolved paths in both. Policy layer does glob matching pre-resolution. |
| Mach IPC filtering | N/A on Linux | Seatbelt `(deny mach*)` | macOS-specific — not in cross-platform API, but backend can add defaults. |
| File descriptor restrictions | seccomp can block specific fd-related syscalls | Not in SBPL | Linux-specific enhancement, not in shared API. |
| Dynamic tightening | Landlock can stack (add more restrictions) | Cannot modify profile after apply | Shared API assumes one-shot apply before exec. Landlock stacking is backend-internal. |

### Helper Binary Design

The `clash-sandbox` binary is the single entry point on both platforms:

```
clash-sandbox --policy '{"filesystem":...}' --cwd /project -- bash -c "npm test"
```

Internally:
- On Linux: applies Landlock + seccomp directly, then `execvp`
- On macOS: generates SBPL profile, writes to temp file, then `exec sandbox-exec -p <profile> -- <command>`

Or alternatively on macOS, use `sandbox_init()` directly from Rust via FFI to
avoid the temp file and the deprecated `sandbox-exec` binary.

---

## Recommended Architecture

### Approach: Layered Defense (Landlock + seccomp-BPF)

This is the same approach used by OpenAI Codex CLI, the `hakoniwa` crate, Google's
Sandbox2, and various container runtimes. It's battle-tested and well-understood.

```
┌──────────────────────────────────────────────────────┐
│                    Claude Code                        │
│                                                       │
│  ┌─────────────────────────────────────────────────┐  │
│  │            Clash (hook process)                  │  │
│  │                                                  │  │
│  │  1. Receive PreToolUse hook input                │  │
│  │  2. Evaluate policy (existing logic)             │  │
│  │  3. If allowed → compute sandbox policy          │  │
│  │  4. Return allow + sandbox instructions          │  │
│  └──────────┬──────────────────────────────────────┘  │
│             │                                         │
│             ▼                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │         clash-sandbox (helper binary)            │  │
│  │                                                  │  │
│  │  1. Parse sandbox policy from args/env           │  │
│  │  2. Apply Landlock rules (filesystem + network)  │  │
│  │  3. Apply seccomp-BPF filter (syscall blocklist) │  │
│  │  4. Drop privileges (no_new_privs)               │  │
│  │  5. execvp(target_command)                       │  │
│  │                                                  │  │
│  │  ← restrictions inherited by all descendants →   │  │
│  └─────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

### How It Integrates With Clash

Currently, clash operates as a **hook** — it receives tool invocations from Claude Code,
evaluates policy, and returns allow/deny/ask. It does not control *how* commands are
executed. Enforcement happens in two complementary layers:

#### Layer 1: Policy Evaluation (existing)
The current clash policy engine continues to work as-is. It decides whether a tool
invocation is allowed based on tool name and arguments. This is the "intent" layer.

#### Layer 2: Runtime Sandbox (new)
When a Bash tool invocation is allowed, clash can additionally specify **sandbox
constraints** that Claude Code should apply to the actual process execution. This is the
"enforcement" layer.

There are two integration models:

**Model A: Sandbox Helper Binary (recommended)**

Clash provides a `clash-sandbox` binary. When a Bash tool use is allowed, clash's hook
response tells Claude Code to execute the command via the sandbox helper instead of
directly:

```
# Instead of executing:
bash -c "git status"

# Claude Code would execute:
clash-sandbox --read-only / --writable $CWD --no-network -- bash -c "git status"
```

This requires Claude Code to support a "wrapper command" mechanism in its hook response,
or clash registers itself as the command executor.

**Model B: Hook-Based Sandbox Setup (alternative)**

If Claude Code supports `PostToolUse` hooks that run in the same process context before
the tool executes, clash could set up Landlock/seccomp in-process. However, this is
unlikely given Claude Code's architecture — hooks are separate processes.

**Model C: Plugin-Managed Execution (future)**

Clash evolves from a hook-based tool into a plugin that manages command execution itself.
The plugin receives tool invocations and handles the full lifecycle: policy check, sandbox
setup, execution, and result capture.

### Policy Mapping

The policy language would extend to support resource-level constraints:

```yaml
default: ask

rules:
  # Existing: intent-based rules
  - allow * bash git *
  - deny * bash rm -rf *

  # New: resource-based sandbox constraints
  sandbox:
    filesystem:
      - read: /**                    # Read anywhere
      - write: $CWD/**              # Write only in working directory
      - write: /tmp/**              # Write to tmp
      - execute: /usr/bin/**        # Execute system binaries
      - execute: /usr/local/bin/**

    network:
      deny: all                     # No network by default
      # or:
      # allow: tcp connect to 443   # HTTPS only

    syscalls:
      deny:
        - ptrace                    # No debugging other processes
        - mount                     # No filesystem mounting
        - reboot                    # Obviously
        - kexec_load
        - init_module
        - delete_module
```

### Sandbox Policy Compilation

At startup or policy load time, compile the YAML policy into concrete enforcement parameters:

```rust
struct SandboxPolicy {
    /// Landlock filesystem rules
    filesystem: Vec<FilesystemRule>,
    /// Landlock network rules
    network: NetworkPolicy,
    /// seccomp-BPF blocked syscalls
    blocked_syscalls: Vec<Syscall>,
    /// Whether to set NO_NEW_PRIVS
    no_new_privs: bool,
}

struct FilesystemRule {
    path: PathBuf,
    access: LandlockAccess, // read, write, execute, etc.
}

enum NetworkPolicy {
    DenyAll,
    AllowUnixOnly,
    AllowSpecific(Vec<NetworkRule>),
}
```

---

## Implementation Plan

### Phase 1: Cross-Platform Sandbox Types + Linux Backend

**Goal:** Define the platform-agnostic `SandboxPolicy` and implement Linux enforcement.

1. Create `clash-sandbox/` crate in workspace
2. Define `SandboxPolicy`, `FilesystemPolicy`, `NetworkPolicy`, `SandboxBackend` trait
3. Implement `LinuxSandbox` backend:
   - `landlock` crate for filesystem access control
   - `seccompiler` (pure Rust) for syscall + network filtering
   - `PR_SET_NO_NEW_PRIVS` for privilege escalation prevention
4. CLI: `clash-sandbox --policy <json> --cwd <path> -- <command> [args...]`
5. Test on Linux with common commands (git, npm, cargo, python, etc.)

### Phase 2: macOS Seatbelt Backend

**Goal:** Implement macOS enforcement via the same `SandboxPolicy` API.

1. Implement `MacOSSandbox` backend:
   - `compile_to_sbpl()` — generate SBPL profile string from `SandboxPolicy`
   - Apply via `sandbox_init()` FFI (preferred) or `sandbox-exec -p` (fallback)
2. Handle macOS-specific needs:
   - Always allow `sysctl-read`, `mach-lookup` (tools won't function without these)
   - `process-fork` must be allowed for subprocesses
   - Test Seatbelt-specific edge cases (dyld, signed binaries, etc.)
3. Test on macOS with same command suite

### Phase 3: Policy Language Extension

**Goal:** Extend the clash policy YAML to express sandbox constraints.

1. Add `sandbox:` section to policy.yaml schema
2. Implement policy-to-`SandboxPolicy` compilation
3. Per-rule sandbox overrides (e.g., `git push` needs network, `git status` doesn't)
4. Environment variable expansion (`$CWD`, `$HOME`, `$TMPDIR`)
5. Denied path overrides (`.git` write-protection, `.env` read-protection)

### Phase 4: Integration & Testing

**Goal:** End-to-end testing with Claude Code on both platforms.

1. Add clester tests for sandbox behavior
2. Test common tool invocations work under sandbox on both platforms
3. Test that violations are properly blocked and reported
4. Performance benchmarking (sandbox setup overhead)
5. Graceful degradation: older kernels, containerized environments, etc.
6. Platform-specific edge case testing (macOS: `uv`/`cargo` Mach IPC needs,
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
