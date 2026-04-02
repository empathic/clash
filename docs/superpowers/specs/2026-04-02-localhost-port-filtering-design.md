# Localhost Port Filtering

Add port-level restrictions to the sandbox `localhost` network mode, enforced via macOS Seatbelt.

## Starlark API

New `localhost()` function in `std.star`:

```starlark
# All ports (backward-compatible, same as net = "localhost")
net = localhost()

# Specific ports only
net = localhost(ports = [8080, 3000])
```

`localhost()` returns a struct that `sandbox()` recognizes as a network specifier. When `ports` is omitted or empty, behavior is identical to the existing `net = "localhost"` string form.

## JSON IR

Extend `NetworkPolicy` serialization with a map variant:

```json
// Existing (all ports)
"network": "localhost"

// New (specific ports)
"network": {"localhost": [8080, 3000]}
```

In Rust, add a variant to `NetworkPolicy`:

```rust
pub enum NetworkPolicy {
    Deny,
    Allow,
    Localhost,                    // existing — all ports
    LocalhostPorts(Vec<u16>),    // new — specific ports
    AllowDomains(Vec<String>),
}
```

Serde deserialization: `{"localhost": [8080]}` maps to `LocalhostPorts(vec![8080])`.

## Seatbelt Compilation (macOS)

`Localhost` (existing):
```scheme
(allow network-outbound (remote ip "localhost:*"))
(deny network*)
```

`LocalhostPorts([8080, 3000])` (new):
```scheme
(allow network-outbound (remote tcp "localhost:8080"))
(allow network-outbound (remote tcp "localhost:3000"))
(deny network*)
```

Uses `tcp` instead of `ip` since port filtering requires specifying the protocol. TCP covers HTTP/HTTPS use cases.

## Linux

No change to seccomp/Landlock enforcement. `LocalhostPorts` is treated identically to `Localhost` at the kernel level (advisory). Port enforcement via the HTTP proxy is out of scope for this change.

## Files to Change

| File | Change |
|------|--------|
| `clash_starlark/stdlib/std.star` | Add `localhost()` function, handle in `sandbox()` net processing |
| `clash_starlark/src/when.rs` | Serialize `localhost(ports=...)` to `{"localhost": [...]}` JSON |
| `clash/src/policy/sandbox_types.rs` | Add `LocalhostPorts(Vec<u16>)` variant, serde support |
| `clash/src/sandbox/macos.rs` | Generate port-specific Seatbelt rules for `LocalhostPorts` |
| `clash/src/sandbox/linux.rs` | Map `LocalhostPorts` to same behavior as `Localhost` |
| `docs/policy-guide.md` | Document `localhost(ports=...)` syntax |

## Non-Goals

- Port ranges (e.g., `8080-8090`) — add later if needed
- UDP port filtering — add later if needed
- Linux kernel-level port enforcement — requires eBPF, out of scope
