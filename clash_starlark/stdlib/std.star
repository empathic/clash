# Clash standard library — all DSL builders.
#
# Emits v5 match tree nodes using minimal Rust primitives.
# Rust globals available: _mt_node, _mt_condition, _mt_pattern, _mt_prefix,
# _mt_policy, allow, deny, ask

# ---------------------------------------------------------------------------
# Pattern helpers
# ---------------------------------------------------------------------------

def _pattern(value):
    """Convert a value to a matcher pattern.

    - None          → wildcard
    - "foo"         → literal
    - ["a", "b"]    → any_of
    - regex("...")  → regex
    """
    return _mt_pattern(value)

def regex(pattern):
    """Create a regex pattern."""
    return struct(_regex = pattern)

# ---------------------------------------------------------------------------
# Match tree node builders (pure Starlark over _mt_condition / _mt_node)
# ---------------------------------------------------------------------------

def _mt_exe(pattern):
    """Build ToolName=Bash → PosArg(0)=pattern."""
    inner = _mt_condition({"positional_arg": 0}, pattern)
    bash_pat = _mt_pattern("Bash")
    return _mt_condition("tool_name", bash_pat).on([inner])

def _mt_tool(pattern):
    """Build ToolName=pattern."""
    return _mt_condition("tool_name", pattern)

def _mt_hook(pattern):
    """Build HookType=pattern."""
    return _mt_condition("hook_type", pattern)

def _mt_agent(pattern):
    """Build AgentName=pattern."""
    return _mt_condition("agent_name", pattern)

def _mt_arg(n, pattern):
    """Build PosArg(n)=pattern."""
    return _mt_condition({"positional_arg": n}, pattern)

def _mt_has_arg(pattern):
    """Build HasArg=pattern."""
    return _mt_condition("has_arg", pattern)

def _mt_named(name, pattern):
    """Build NamedArg(name)=pattern."""
    return _mt_condition({"named_arg": name}, pattern)

def _mt_field(path, pattern):
    """Build NestedField(path)=pattern."""
    return _mt_condition({"nested_field": path}, pattern)

def _mt_fs_op(pattern):
    """Build FsOp=pattern."""
    return _mt_condition("fs_op", pattern)

def _mt_fs_path(pattern):
    """Build FsPath=pattern."""
    return _mt_condition("fs_path", pattern)

def _mt_net_domain(pattern):
    """Build NetDomain=pattern."""
    return _mt_condition("net_domain", pattern)

def _mt_allow(sandbox):
    """Build an allow decision node."""
    if sandbox != None:
        return _mt_node({"decision": {"allow": sandbox}})
    return _mt_node({"decision": {"allow": None}})

def _mt_deny():
    """Build a deny decision node."""
    return _mt_node({"decision": "deny"})

def _mt_ask(sandbox):
    """Build an ask decision node."""
    if sandbox != None:
        return _mt_node({"decision": {"ask": sandbox}})
    return _mt_node({"decision": {"ask": None}})

def _mt_not(pattern):
    """Build a negated pattern."""
    return _mt_node({"not": pattern})

def _mt_or(patterns):
    """Build an any_of pattern."""
    return _mt_node({"any_of": patterns})

# ---------------------------------------------------------------------------
# Exec / tool builders
# ---------------------------------------------------------------------------

def exe(name = None, args = None):
    """Build an exec rule.

    Usage:
        exe("git").allow()
        exe("git", args=["push"]).deny()
        exe("cargo").sandbox(my_sandbox).allow()
        exe(["cargo", "rustc"]).allow()
        exe().deny()  # deny all exec
    """
    node = _mt_exe(_pattern(name))

    if args != None:
        node = _exe_with_args(name, args)

    return _with_sandbox_support(node)

def _exe_with_args(name, args):
    """Build an exe node with positional args already nested."""
    pat = _pattern(name)
    result = _mt_exe(pat)
    if len(args) > 0:
        # Build nested chain: arg(n, ...) wrapping the innermost
        innermost = _mt_arg(len(args), _pattern(args[len(args) - 1]))
        for i in range(len(args) - 2, -1, -1):
            innermost = _mt_arg(i + 1, _pattern(args[i])).on([innermost])
        result = _mt_exe(pat).on([innermost])
    return result

def tool(name = None):
    """Build a tool rule.

    Usage:
        tool().allow()
        tool("WebSearch").deny()
        tool(["Read", "Glob", "Grep"]).allow()
    """
    return _with_sandbox_support(_mt_tool(_pattern(name)))

# ---------------------------------------------------------------------------
# Filesystem path builders
# ---------------------------------------------------------------------------

_VALID_EFFECTS = ["allow", "deny", "ask"]

def _validate_effect(name, value):
    """Validate that an effect is allow, deny, or ask."""
    if value != None and value not in _VALID_EFFECTS:
        fail("invalid effect '{}' for {}, must be allow, deny, or ask".format(value, name))

def _fs_nodes(path_value, read = None, write = None, execute = None, allow_all = False):
    """Build match tree nodes for filesystem access.

    Returns a list of condition nodes that match on FsOp and FsPath.
    """
    _validate_effect("read", read)
    _validate_effect("write", write)
    _validate_effect("execute", execute)

    if allow_all:
        read = allow
        write = allow
        execute = allow

    nodes = []

    if read != None:
        node = _mt_fs_op(_pattern("read")).on([
            _mt_fs_path(_mt_prefix(path_value)).on([
                _effect_decision(read),
            ]),
        ])
        nodes.append(node)

    if write != None:
        node = _mt_fs_op(_pattern("write")).on([
            _mt_fs_path(_mt_prefix(path_value)).on([
                _effect_decision(write),
            ]),
        ])
        nodes.append(node)

    return nodes

def _effect_decision(effect):
    """Create a decision node from an effect string."""
    if effect == allow:
        return _mt_allow(None)
    elif effect == deny:
        return _mt_deny()
    elif effect == ask:
        return _mt_ask(None)
    else:
        fail("unknown effect: " + str(effect))

def _caps_list(read, write, execute, allow_all):
    """Compute a sandbox caps list from permission kwargs."""
    if allow_all:
        return ["read", "write", "create", "delete", "execute"]
    parts = []
    if read == allow:
        parts.append("read")
    if write == allow:
        parts.extend(["write", "create"])
    if execute == allow:
        parts.append("execute")
    return parts

def _path_entry(path_value, worktree = False, read = None, write = None,
                execute = None, allow_all = False, _children = None,
                _extra_sandbox_rules = None):
    """Internal: build a path entry struct with .child() and ._nodes."""
    if _children == None:
        _children = []

    _read = read
    _write = write
    _execute = execute
    _allow_all = allow_all

    _nodes = _fs_nodes(path_value, read, write, execute, allow_all)
    for c in _children:
        _nodes.extend(c)

    # Build sandbox rules (path + caps pairs for sandbox-exec compilation).
    _sandbox_rules = list(_extra_sandbox_rules or [])
    _caps = _caps_list(read, write, execute, allow_all)
    if len(_caps) > 0:
        _sandbox_rules.append({"path_value": path_value, "caps": _caps})

    def child(name, read = None, write = None, execute = None, allow_all = False):
        # For child paths, join with the parent
        # We create a struct with the joined path info for _mt_prefix
        child_path = struct(_join = [path_value, name])
        child_nodes = _fs_nodes(child_path, read, write, execute, allow_all)
        child_caps = _caps_list(read, write, execute, allow_all)
        child_sb_rules = list(_sandbox_rules)
        if len(child_caps) > 0:
            child_sb_rules.append({"path_value": child_path, "caps": child_caps})
        return _path_entry(
            path_value, worktree, _read, _write, _execute, _allow_all,
            _children + [child_nodes],
            child_sb_rules,
        )

    return struct(child = child, _nodes = _nodes, _is_path = True, _path_value = path_value,
                  _sandbox_rules = _sandbox_rules)

def cwd(follow_worktrees = False, read = None, write = None,
        execute = None, allow_all = False):
    """Build a CWD path entry.

    Usage:
        cwd(read=allow, write=allow)
        cwd(follow_worktrees=True, allow_all=True)
    """
    return _path_entry(struct(_env = "PWD"), follow_worktrees, read, write, execute, allow_all)

def home(read = None, write = None, execute = None, allow_all = False):
    """Build a HOME path entry.

    Usage:
        home().child(".ssh", read=allow)
        home().child(".cargo", allow_all=True)
    """
    return _path_entry(struct(_env = "HOME"), False, read, write, execute, allow_all)

def tempdir(read = None, write = None, execute = None, allow_all = False):
    """Build a TMPDIR path entry.

    Usage:
        tempdir(allow_all=True)
    """
    return _path_entry(struct(_env = "TMPDIR"), False, read, write, execute, allow_all)

def path(path_str = None, env = None, read = None, write = None,
         execute = None, allow_all = False):
    """Build a path entry for an arbitrary path or env var.

    Usage:
        path("/usr/local/bin", read=allow, execute=allow)
        path(env="CARGO_HOME", read=allow, write=allow)
    """
    if path_str != None and env != None:
        fail("path() takes either a path string or env=, not both")
    if path_str == None and env == None:
        fail("path() requires either a path string or env= argument")
    path_value = struct(_env = env) if env != None else path_str
    return _path_entry(path_value, False, read, write, execute, allow_all)

# ---------------------------------------------------------------------------
# Network builders
# ---------------------------------------------------------------------------

def _domain_pattern(name):
    """Convert a domain string to a matcher pattern."""
    if name == "*":
        return _pattern(None)  # wildcard
    if name.startswith("*."):
        suffix = name[2:]
        escaped = ""
        for c in suffix.elems():
            if c in ".+*?^${}()|[]\\":
                escaped += "\\" + c
            else:
                escaped += c
        return _pattern(regex("(^|.*\\.)" + escaped))
    return _pattern(name)

def domains(mapping):
    """Build net rules from a {domain: effect} dict.

    Usage:
        domains({"github.com": allow, "*.npmjs.org": allow})
    """
    nodes = []
    for domain_name, effect in mapping.items():
        node = _mt_net_domain(_domain_pattern(domain_name)).on([
            _effect_decision(effect),
        ])
        nodes.append(struct(_node = node, _domain_name = domain_name))
    return nodes

def domain(name, effect):
    """Build a single net rule.

    Usage:
        domain("github.com", allow)
    """
    node = _mt_net_domain(_domain_pattern(name)).on([
        _effect_decision(effect),
    ])
    return [struct(_node = node, _domain_name = name)]

# ---------------------------------------------------------------------------
# Sandbox builder
# ---------------------------------------------------------------------------

def _make_sandbox(name, default, fs_rules, net_policy, net_domain_names = None):
    """Create a sandbox struct."""
    if net_domain_names == None:
        net_domain_names = []
    def _merge(other):
        merged_default = deny if (default == deny or other._default == deny) else default
        merged_domains = net_domain_names + (other._net_domain_names if hasattr(other, "_net_domain_names") else [])
        return _make_sandbox(name, merged_default, fs_rules + other._fs_rules, net_policy or other._net_policy, merged_domains)

    return struct(
        _name = name,
        _default = default,
        _fs_rules = fs_rules,
        _net_policy = net_policy,
        _net_domain_names = net_domain_names,
        _is_sandbox = True,
        merge = _merge,
    )

def sandbox(name = None, default = "deny", fs = None, net = None):
    """Build a sandbox definition.

    Usage:
        sandbox(
            "example",
            default=deny,
            fs=[cwd(read=allow), home().child(".ssh", read=allow)],
            net=allow,
        )
    """
    if name == None:
        fail("sandbox name is required")

    fs_rules = []
    if fs != None:
        for entry in fs:
            if hasattr(entry, "_is_path"):
                # Path entry — collect sandbox rules from it
                if hasattr(entry, "_sandbox_rules"):
                    fs_rules.extend(entry._sandbox_rules)
            else:
                fail("sandbox fs= entries must be path values (cwd, home, tempdir, path)")

    net_policy = None
    net_domain_names = []
    if net != None:
        if type(net) == "string":
            net_policy = net  # "allow" or "deny"
        elif type(net) == "list":
            # domains() returns a list of structs with _node and _domain_name
            net_domains = []
            for entry in net:
                if type(entry) == "list":
                    for sub in entry:
                        if hasattr(sub, "_domain_name"):
                            net_domain_names.append(sub._domain_name)
                            net_domains.append(sub._node if hasattr(sub, "_node") else sub)
                        else:
                            net_domains.append(sub)
                else:
                    if hasattr(entry, "_domain_name"):
                        net_domain_names.append(entry._domain_name)
                        net_domains.append(entry._node if hasattr(entry, "_node") else entry)
                    else:
                        net_domains.append(entry)
            net_policy = net_domains
        else:
            fail("sandbox net= must be an effect string or a list of domain entries")

    return _make_sandbox(name, default, fs_rules, net_policy, net_domain_names)

# ---------------------------------------------------------------------------
# Sandbox support for rule builders (exe, tool)
# ---------------------------------------------------------------------------

def _with_sandbox_support(node):
    """Wrap a match tree node with .sandbox() and .also() support."""

    def _allow():
        result = node.allow()
        return struct(_node = result, _sandbox = None)

    def _deny():
        result = node.deny()
        return struct(_node = result, _sandbox = None)

    def _ask():
        result = node.ask()
        return struct(_node = result, _sandbox = None)

    def _set_sandbox(sb):
        return _with_sandbox_and_node(node, sb)

    return struct(
        allow = _allow,
        deny = _deny,
        ask = _ask,
        sandbox = _set_sandbox,
        on = node.on,
        _node = node,
        _sandbox = None,
    )

def _with_sandbox_and_node(node, sb):
    """Create a rule builder with sandbox attached."""
    def _allow():
        result = node.allow(sandbox = sb._name)
        return struct(_node = result, _sandbox = sb)
    def _deny():
        result = node.deny()
        return struct(_node = result, _sandbox = sb)
    def _ask():
        result = node.ask(sandbox = sb._name)
        return struct(_node = result, _sandbox = sb)
    def _set_sandbox(new_sb):
        return _with_sandbox_and_node(node, new_sb)

    return struct(
        allow = _allow,
        deny = _deny,
        ask = _ask,
        sandbox = _set_sandbox,
        on = node.on,
        _node = node,
        _sandbox = sb,
    )

# ---------------------------------------------------------------------------
# Policy wrapper
# ---------------------------------------------------------------------------

def policy(default = "deny", rules = None):
    """Build a policy.

    Usage:
        policy(default=deny, rules=[
            cwd(read=allow, write=allow),
            exe("git", args=["push"]).deny(),
            exe("git").allow(),
            domains({"github.com": allow}),
        ])
    """
    if rules == None:
        rules = []

    flat_nodes = []
    sandbox_list = []
    _seen_sandboxes = {}

    for item in rules:
        if hasattr(item, "_is_path"):
            # Path entry → expand to fs match tree nodes
            flat_nodes.extend(item._nodes)
        elif type(item) == "list":
            # domains() returns a list
            for sub in item:
                if hasattr(sub, "_node"):
                    _collect_node(sub, flat_nodes, sandbox_list, _seen_sandboxes)
                else:
                    flat_nodes.append(sub)
        elif hasattr(item, "_node"):
            # Rule builder (from exe/tool with sandbox support)
            _collect_node(item, flat_nodes, sandbox_list, _seen_sandboxes)
        else:
            flat_nodes.append(item)

    return _mt_policy(default = default, sandboxes = sandbox_list, rules = flat_nodes)

def _collect_node(item, flat_nodes, sandbox_list, seen):
    """Extract a node and its sandbox from a rule builder."""
    flat_nodes.append(item._node if hasattr(item, "_node") else item)
    if hasattr(item, "_sandbox") and item._sandbox != None:
        sb = item._sandbox
        if sb._name not in seen:
            seen[sb._name] = True
            sandbox_list.append(_sandbox_to_json(sb))

def _sandbox_to_json(sb):
    """Convert a sandbox struct to JSON-compatible dict for _mt_policy."""
    rules = []
    for r in sb._fs_rules:
        pv = r["path_value"]
        path_str = _resolve_path_value(pv)
        caps = r.get("caps", ["read", "write", "create"])
        rules.append({
            "effect": "allow",
            "caps": caps,
            "path": path_str,
            "path_match": "subpath",
        })

    net = "deny"
    if sb._net_policy != None:
        if type(sb._net_policy) == "string":
            net = sb._net_policy
        elif type(sb._net_policy) == "list":
            # Use stored domain names extracted during sandbox() construction
            domain_names = sb._net_domain_names if hasattr(sb, "_net_domain_names") else []
            if domain_names:
                net = {"allow_domains": domain_names}
            else:
                net = "localhost"

    # deny default = read-only (can read system files and execute binaries)
    # allow default = full access
    if sb._default == deny:
        default_caps = ["read", "execute"]
    else:
        default_caps = ["read", "write", "create", "delete", "execute"]

    return {
        "name": sb._name,
        "default": default_caps,
        "rules": rules,
        "network": net,
    }

def _resolve_path_value(pv):
    """Convert a path value struct to a $ENV string for sandbox rules."""
    if type(pv) == "string":
        return pv
    if type(pv) == "struct":
        if hasattr(pv, "_env"):
            return "$" + pv._env
        if hasattr(pv, "_join"):
            parts = []
            for p in pv._join:
                parts.append(_resolve_path_value(p))
            return "/".join(parts)
    return str(pv)
