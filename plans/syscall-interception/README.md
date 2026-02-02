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

This research targets **Linux only**. macOS would require an Endpoint Security
extension (kernel extension replacement), which is a separate effort.

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

### Phase 1: Landlock Filesystem Sandboxing

**Goal:** Restrict Bash tool invocations to read/write only within allowed paths.

1. Add `landlock` crate as dependency
2. Create `clash-sandbox` binary in a new `clash-sandbox/` crate
3. Implement Landlock ruleset builder from policy config
4. CLI: `clash-sandbox --policy <json> -- <command> [args...]`
5. Apply Landlock before exec, ensuring:
   - Read access: everywhere by default (or restricted per policy)
   - Write access: `$CWD` + configured paths only
   - Execute access: system paths (`/usr`, `/bin`, etc.)
6. Set `PR_SET_NO_NEW_PRIVS` to prevent privilege escalation
7. Integration: modify hook response to wrap commands with sandbox

**Key decision:** How does the sandbox helper get invoked? Options:
- Claude Code's `sandbox` settings field already supports custom sandbox commands
- Clash hook response could modify the command to include the wrapper
- Clash plugin could manage execution directly

### Phase 2: seccomp Syscall Filtering

**Goal:** Block dangerous syscalls that have no legitimate use in tool execution.

1. Add `libseccomp` crate as dependency
2. Define default syscall blocklist (ptrace, mount, reboot, kexec, module loading, etc.)
3. Apply seccomp-BPF filter after Landlock but before exec
4. Network isolation: block `socket()` for non-AF_UNIX domains
5. Make blocklist configurable via policy

### Phase 3: Policy Language Extension

**Goal:** Extend the clash policy language to express sandbox constraints.

1. Add `sandbox:` section to policy.yaml schema
2. Implement policy-to-sandbox compilation
3. Per-rule sandbox overrides (e.g., `git push` needs network, `git status` doesn't)
4. Environment variable expansion (`$CWD`, `$HOME`, etc.)

### Phase 4: Integration & Testing

**Goal:** End-to-end testing with Claude Code.

1. Add clester tests for sandbox behavior
2. Test common tool invocations work under sandbox
3. Test that violations are properly blocked and reported
4. Performance benchmarking
5. Graceful degradation when kernel doesn't support Landlock

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

4. **Graceful degradation**: What happens on kernels without Landlock?
   - Fail open (warn but allow execution)? Dangerous.
   - Fail closed (block execution)? Frustrating.
   - Configurable per policy?

5. **Performance impact**: Landlock adds near-zero overhead for allowed operations, but
   what about the sandbox helper process setup cost (fork + exec)?

6. **Testing**: How to test sandbox behavior in CI? Docker containers may not have
   Landlock support depending on host kernel and Docker seccomp profile.
