# Localhost Port Filtering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add port-level filtering to the sandbox `localhost` network mode, enforced via macOS Seatbelt.

**Architecture:** New `localhost()` Starlark function returns a struct recognized by `sandbox()`. Threads through JSON IR as `{"localhost": [8080, 3000]}` to a new `LocalhostPorts(Vec<u16>)` variant in `NetworkPolicy`. Seatbelt compilation emits `(allow network-outbound (remote tcp "localhost:<port>"))` per port. Linux treats it identically to `Localhost` (advisory).

**Tech Stack:** Rust, Starlark, macOS Seatbelt SBPL

---

### Task 1: Add `LocalhostPorts` variant to `NetworkPolicy` enum

**Files:**
- Modify: `clash/src/policy/sandbox_types.rs:278-354` (NetworkPolicy enum, Serialize, Deserialize impls)

- [ ] **Step 1: Write failing test for `LocalhostPorts` serde round-trip**

Add to the existing `mod tests` block in `sandbox_types.rs` (after the `test_network_policy_localhost_serde` test at line 814):

```rust
#[test]
fn test_network_policy_localhost_ports_serde() {
    let policy = NetworkPolicy::LocalhostPorts(vec![8080, 3000]);
    let json = serde_json::to_string(&policy).unwrap();
    assert_eq!(json, r#"{"localhost":[8080,3000]}"#);
    let deserialized: NetworkPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, NetworkPolicy::LocalhostPorts(vec![8080, 3000]));
}

#[test]
fn test_network_policy_localhost_ports_empty_is_localhost() {
    // Empty ports list deserializes to plain Localhost
    let json = r#"{"localhost":[]}"#;
    let deserialized: NetworkPolicy = serde_json::from_str(json).unwrap();
    assert_eq!(deserialized, NetworkPolicy::Localhost);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash test_network_policy_localhost_ports -- --nocapture`
Expected: compilation error — `LocalhostPorts` variant doesn't exist yet.

- [ ] **Step 3: Add `LocalhostPorts` variant and update Serialize/Deserialize**

In `sandbox_types.rs`, add the variant to the enum (after `Localhost` at line 288):

```rust
/// Allow only localhost connections on specific ports. Enforced at kernel
/// level on macOS (Seatbelt restricts to specific TCP ports) and advisory
/// on Linux (same as Localhost — seccomp cannot filter by port).
LocalhostPorts(Vec<u16>),
```

Update `Serialize` impl (after the `Localhost` arm at line 300):

```rust
NetworkPolicy::LocalhostPorts(ports) => {
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(Some(1))?;
    map.serialize_entry("localhost", ports)?;
    map.end()
}
```

Update `Deserialize` impl — modify the `visit_map` method (at line 336) to handle both `"allow_domains"` and `"localhost"` keys:

```rust
fn visit_map<A: de::MapAccess<'de>>(
    self,
    mut map: A,
) -> Result<NetworkPolicy, A::Error> {
    let key: String = map
        .next_key()?
        .ok_or_else(|| de::Error::custom("expected allow_domains or localhost key"))?;
    match key.as_str() {
        "allow_domains" => {
            let domains: Vec<String> = map.next_value()?;
            Ok(NetworkPolicy::AllowDomains(domains))
        }
        "localhost" => {
            let ports: Vec<u16> = map.next_value()?;
            if ports.is_empty() {
                Ok(NetworkPolicy::Localhost)
            } else {
                Ok(NetworkPolicy::LocalhostPorts(ports))
            }
        }
        _ => Err(de::Error::unknown_field(&key, &["allow_domains", "localhost"])),
    }
}
```

Also update the `expecting` method (line 320) to include the new format:

```rust
fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
    formatter.write_str(
        r#""deny", "allow", "localhost", {"localhost": [ports]}, or {"allow_domains": [...]}"#,
    )
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p clash test_network_policy_localhost_ports -- --nocapture`
Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add clash/src/policy/sandbox_types.rs
git commit -m "feat: add LocalhostPorts variant to NetworkPolicy"
```

---

### Task 2: Generate port-specific Seatbelt rules

**Files:**
- Modify: `clash/src/sandbox/macos.rs:182-201` (network section of `compile_to_sbpl`)

- [ ] **Step 1: Write failing test for port-specific SBPL output**

Add to the existing `mod tests` in `macos.rs` (after `sbpl_localhost_same_as_allow_domains` test at line 555):

```rust
#[test]
fn sbpl_localhost_ports_emits_per_port_rules() {
    let policy = SandboxPolicy {
        default: Cap::READ | Cap::EXECUTE,
        rules: vec![],
        network: NetworkPolicy::LocalhostPorts(vec![8080, 3000]),
        doc: None,
    };
    let profile = compile_to_sbpl(&policy, "/tmp");
    assert!(
        profile.contains(r#"(allow network-outbound (remote tcp "localhost:8080"))"#),
        "should allow TCP to localhost:8080\nprofile:\n{profile}"
    );
    assert!(
        profile.contains(r#"(allow network-outbound (remote tcp "localhost:3000"))"#),
        "should allow TCP to localhost:3000\nprofile:\n{profile}"
    );
    assert!(
        profile.contains("(deny network*)"),
        "should deny all other network\nprofile:\n{profile}"
    );
    // Should NOT contain the wildcard localhost rule
    assert!(
        !profile.contains("localhost:*"),
        "should not contain wildcard localhost rule\nprofile:\n{profile}"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash sbpl_localhost_ports -- --nocapture`
Expected: FAIL — the `LocalhostPorts` arm is not handled in `compile_to_sbpl`.

- [ ] **Step 3: Add `LocalhostPorts` arm to `compile_to_sbpl`**

In `macos.rs`, update the network match block (line 183). Replace the existing `Localhost | AllowDomains` arm with three separate arms:

```rust
// Network
match &policy.network {
    NetworkPolicy::Deny => {
        p += "(deny network*)\n";
    }
    NetworkPolicy::Allow => {
        p += "(allow network*)\n";
    }
    NetworkPolicy::LocalhostPorts(ports) => {
        // Allow only specific TCP ports on localhost.
        // Uses (remote tcp) instead of (remote ip) because port filtering
        // requires specifying the transport protocol.
        for port in ports {
            p += &format!(
                "(allow network-outbound (remote tcp \"localhost:{}\"))\n",
                port
            );
        }
        p += "(deny network*)\n";
    }
    NetworkPolicy::Localhost | NetworkPolicy::AllowDomains(_) => {
        p += "(allow network-outbound (remote ip \"localhost:*\"))\n";
        p += "(deny network*)\n";
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clash sbpl_localhost_ports -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Run all macos sandbox tests to check for regressions**

Run: `cargo test -p clash sandbox::macos -- --nocapture`
Expected: all existing tests still pass.

- [ ] **Step 6: Commit**

```bash
git add clash/src/sandbox/macos.rs
git commit -m "feat: generate port-specific Seatbelt rules for LocalhostPorts"
```

---

### Task 3: Handle `LocalhostPorts` on Linux

**Files:**
- Modify: `clash/src/sandbox/linux.rs:36-56` (network policy match)

- [ ] **Step 1: Add `LocalhostPorts` arm to the network match**

In `linux.rs`, the match at line 36 needs a new arm. Add it after the `Localhost` arm (line 40):

```rust
NetworkPolicy::LocalhostPorts(_) => {
    // Port-level filtering is not enforceable via seccomp (can't inspect
    // connect() sockaddr). Same advisory behavior as Localhost.
    install_seccomp_advisory_network_filter()?;
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p clash`
Expected: compiles without warnings.

- [ ] **Step 3: Commit**

```bash
git add clash/src/sandbox/linux.rs
git commit -m "feat: handle LocalhostPorts on Linux (advisory, same as Localhost)"
```

---

### Task 4: Add `localhost()` function to Starlark stdlib

**Files:**
- Modify: `clash_starlark/stdlib/std.star:596-646` (network builders section)

- [ ] **Step 1: Add the `localhost()` function**

Add after the `domain()` function (line 645) in the network builders section:

```python
def localhost(ports = None):
    """Build a localhost network specifier, optionally restricted to specific ports.

    Usage:
        net = localhost()              # all ports (same as net = "localhost")
        net = localhost(ports=[8080])  # only port 8080
    """
    if ports == None or len(ports) == 0:
        return struct(_is_localhost=True, _ports=[])
    for p in ports:
        if type(p) != "int":
            fail("localhost() ports must be integers, got: " + type(p))
        if p < 1 or p > 65535:
            fail("localhost() port out of range (1-65535): " + str(p))
    return struct(_is_localhost=True, _ports=ports)
```

- [ ] **Step 2: Update `sandbox()` to recognize the localhost struct**

In the `sandbox()` function's net handling (line 729), add a check for the `_is_localhost` struct before the existing checks:

```python
    net_policy = None
    net_domain_names = []
    if net != None:
        if hasattr(net, "_is_localhost"):
            if len(net._ports) > 0:
                net_policy = {"_localhost_ports": net._ports}
            else:
                net_policy = "localhost"
        elif hasattr(net, "_is_effect"):
            net_policy = _unwrap_effect(net)
        elif type(net) == "string":
            net_policy = net  # "allow" or "deny"
        elif type(net) == "list":
```

The rest of the list/domains handling stays the same.

- [ ] **Step 3: Update `_sandbox_to_json` to emit the new JSON format**

In `_sandbox_to_json` (line 834), update the net serialization:

```python
    net = "deny"
    if sb._net_policy != None:
        if type(sb._net_policy) == "dict" and "_localhost_ports" in sb._net_policy:
            net = {"localhost": sb._net_policy["_localhost_ports"]}
        elif type(sb._net_policy) == "string":
            net = sb._net_policy
        elif type(sb._net_policy) == "list":
            # Use stored domain names extracted during sandbox() construction
            domain_names = (
                sb._net_domain_names if hasattr(sb, "_net_domain_names") else []
            )
            if domain_names:
                net = {"allow_domains": domain_names}
            else:
                net = "localhost"
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p clash_starlark`
Expected: compiles.

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/std.star
git commit -m "feat: add localhost() function to Starlark stdlib"
```

---

### Task 5: Update Rust-side Starlark→JSON conversion

**Files:**
- Modify: `clash_starlark/src/when.rs:640-670` (`convert_net_policy` function)

- [ ] **Step 1: Update `convert_net_policy` to handle the localhost struct**

The `convert_net_policy` function reads `_net_policy` from the sandbox struct. When `localhost(ports=[8080])` is used, `_net_policy` will be a dict `{"_localhost_ports": [8080]}`. Update the function to handle this:

```rust
fn convert_net_policy<'v>(sb: Value<'v>, heap: &'v Heap) -> anyhow::Result<JsonValue> {
    let net_policy = sb.get_attr("_net_policy", heap).ok().flatten();

    match net_policy {
        None => Ok(json!("deny")),
        Some(v) if v.is_none() => Ok(json!("deny")),
        Some(v) if v.unpack_str().is_some() => Ok(json!(v.unpack_str().unwrap())),
        Some(v) if DictRef::from_value(v).is_some() => {
            // Dict — check for _localhost_ports key
            let dict = DictRef::from_value(v).unwrap();
            let key = heap.alloc_str("_localhost_ports");
            if let Some(ports_val) = dict.get(key.to_value()).ok().flatten() {
                if let Some(ports_list) = ListRef::from_value(ports_val) {
                    let ports: Vec<u16> = ports_list
                        .iter()
                        .filter_map(|item| item.unpack_i32().map(|n| n as u16))
                        .collect();
                    if ports.is_empty() {
                        return Ok(json!("localhost"));
                    }
                    return Ok(json!({"localhost": ports}));
                }
            }
            Ok(json!("deny"))
        }
        Some(v) if ListRef::from_value(v).is_some() => {
            // List of domain rules — check for stored domain names
            let domain_names = sb
                .get_attr("_net_domain_names", heap)
                .ok()
                .flatten()
                .and_then(|v| {
                    ListRef::from_value(v).map(|list| {
                        list.iter()
                            .filter_map(|item| item.unpack_str().map(|s| s.to_string()))
                            .collect::<Vec<String>>()
                    })
                })
                .unwrap_or_default();

            if domain_names.is_empty() {
                Ok(json!("localhost"))
            } else {
                Ok(json!({"allow_domains": domain_names}))
            }
        }
        _ => Ok(json!("deny")),
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p clash_starlark`
Expected: compiles.

- [ ] **Step 3: Commit**

```bash
git add clash_starlark/src/when.rs
git commit -m "feat: serialize localhost(ports=...) to JSON IR in when.rs"
```

---

### Task 6: Integration test — end-to-end Starlark→JSON→Seatbelt

**Files:**
- Modify: `clash_starlark/src/lib.rs` (add integration test)

- [ ] **Step 1: Write integration test for localhost(ports=...)**

Add to the `mod tests` block in `lib.rs`:

```rust
#[test]
fn test_sandbox_localhost_ports() {
    let doc = eval_to_doc(
        r#"
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "localhost")

_box = sandbox(
    name = "local_only",
    default = deny(),
    net = localhost(ports = [8080, 3000]),
)

settings(default = deny())
policy("test",
    rules = when({"Bash": {"curl": allow(sandbox = _box)}}),
)
"#,
    );
    let sandboxes = doc["sandboxes"].as_object().unwrap();
    let sb = &sandboxes["local_only"];
    let network = &sb["network"];
    assert_eq!(network, &json!({"localhost": [8080, 3000]}));
}

#[test]
fn test_sandbox_localhost_no_ports() {
    let doc = eval_to_doc(
        r#"
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "localhost")

_box = sandbox(
    name = "local_only",
    default = deny(),
    net = localhost(),
)

settings(default = deny())
policy("test",
    rules = when({"Bash": {"curl": allow(sandbox = _box)}}),
)
"#,
    );
    let sandboxes = doc["sandboxes"].as_object().unwrap();
    let sb = &sandboxes["local_only"];
    assert_eq!(sb["network"], json!("localhost"));
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p clash_starlark test_sandbox_localhost -- --nocapture`
Expected: both tests pass. If they fail, debug the Starlark→JSON pipeline.

- [ ] **Step 3: Also verify the full round-trip — JSON deserializes to the right NetworkPolicy**

Run: `cargo test -p clash test_network_policy -- --nocapture`
Expected: all NetworkPolicy serde tests pass.

- [ ] **Step 4: Commit**

```bash
git add clash_starlark/src/lib.rs
git commit -m "test: add integration tests for localhost(ports=...) end-to-end"
```

---

### Task 7: Export `localhost` from Starlark stdlib

**Files:**
- Modify: `clash_starlark/stdlib/std.star` (ensure `localhost` is in the module's exported symbols)

- [ ] **Step 1: Verify `localhost` is loadable**

Check how other functions like `domains`, `domain`, `sandbox` are exported. In Starlark, all top-level `def` statements are automatically available via `load()`. The `localhost()` function defined in Task 4 should already be loadable as `load("@clash//std.star", "localhost")`.

- [ ] **Step 2: Write a minimal Starlark snippet to confirm**

This is already covered by the integration tests in Task 6 — they use `load("@clash//std.star", ..., "localhost")`. If those tests pass, export works.

- [ ] **Step 3: No commit needed — this is a verification step**

---

### Task 8: Update documentation

**Files:**
- Modify: `docs/policy-guide.md:331-344` (sandbox network restrictions section)

- [ ] **Step 1: Update the network restrictions section**

Replace the content at lines 331-344 with:

```markdown
### Sandbox network restrictions

Sandbox network access has five modes:

- `net = allow()` -- sandbox **allows** all network access (no restrictions)
- `net = localhost()` -- sandbox allows **localhost-only** connections on any port, enforced at the kernel level without a proxy
- `net = localhost(ports=[8080])` -- sandbox allows **localhost connections only on specified ports**, enforced at the kernel level on macOS (advisory on Linux)
- Domain list -- sandbox allows network access **only to listed domains** via a local HTTP proxy
- No net rule -- sandbox **denies** all network access

**Localhost-only mode**: `localhost()` (or `localhost(ports=[...])`) restricts connections to the loopback interface. On macOS, Seatbelt blocks non-localhost connections at the kernel level. On Linux, enforcement is advisory (seccomp cannot filter connect destinations).

**Port filtering**: `localhost(ports=[8080, 3000])` restricts connections to specific TCP ports on localhost. On macOS, Seatbelt emits per-port rules using `(remote tcp "localhost:<port>")`. On Linux, port filtering is not enforceable via seccomp and behaves the same as `localhost()` (advisory). `localhost()` with no arguments allows all ports.

**Domain filtering**: Domain-specific net rules are enforced using a local HTTP proxy. The OS sandbox restricts the process to localhost-only connections, and clash starts a proxy that checks each request against the domain allowlist. Programs that respect `HTTP_PROXY`/`HTTPS_PROXY` environment variables (curl, cargo, npm, pip, etc.) are filtered; programs that bypass the proxy can still reach any host on Linux (advisory enforcement). On macOS, Seatbelt blocks non-localhost connections at the kernel level.

Subdomain matching is supported: `"github.com"` also permits `api.github.com`.
```

- [ ] **Step 2: Commit**

```bash
git add docs/policy-guide.md
git commit -m "docs: document localhost(ports=...) port filtering"
```

---

### Task 9: Manual smoke test

- [ ] **Step 1: Write a test policy file**

Create a temporary `.star` file (don't commit):

```starlark
load("@clash//std.star", "allow", "deny", "ask", "when", "policy", "settings", "sandbox", "localhost")

settings(default = ask())

sandbox(
    name = "local_only",
    default = deny(),
    net = localhost(ports = [8080]),
)

policy("curl-local-only",
    rules = [
        when({"Bash": {"curl": allow(sandbox = "local_only")}}),
        when({("Read", "Write", "Edit", "Glob", "Grep"): allow()}),
    ],
)
```

- [ ] **Step 2: Verify the policy compiles**

Run: `clash compile <path-to-test-policy.star>`
Expected: JSON output with `"network": {"localhost": [8080]}` in the sandbox.

- [ ] **Step 3: If possible, test curl with a local server**

Start a server on port 8080, apply the policy, and verify:
- `curl http://localhost:8080` — should succeed
- `curl http://localhost:9090` — should be blocked by Seatbelt
- `curl http://example.com` — should be blocked by Seatbelt

- [ ] **Step 4: Clean up test policy file**
