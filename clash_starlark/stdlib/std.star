# Clash standard library — all DSL builders.
#
# Emits v5 match tree nodes using minimal Rust primitives.
# Rust globals available: _mt_node, _mt_condition, _mt_pattern, _mt_prefix,
# _mt_literal, _mt_policy, allow, deny, ask

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

def _fs_nodes(path_pattern, read = None, write = None):
    """Build match tree nodes for filesystem access.

    path_pattern: a MatchTreeNode from _mt_prefix, _mt_literal, or _mt_pattern.
    read/write: effect values (allow/deny/ask) or None to skip.
    """
    nodes = []

    if read != None:
        node = _mt_fs_op(_pattern("read")).on([
            _mt_fs_path(path_pattern).on([
                _effect_decision(read),
            ]),
        ])
        nodes.append(node)

    if write != None:
        node = _mt_fs_op(_pattern("write")).on([
            _mt_fs_path(path_pattern).on([
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

def _caps_from_bools(read, write, execute, all_ops):
    """Compute sandbox caps list from boolean flags."""
    if all_ops:
        return ["read", "write", "create", "delete", "execute"]
    parts = []
    if read:
        parts.append("read")
    if write:
        parts.extend(["write", "create"])
    if execute:
        parts.append("execute")
    return parts

def _make_path_pattern(path_value, match_type):
    """Create the appropriate FsPath pattern for the given match type."""
    if match_type == "literal":
        return _mt_literal(path_value)
    elif match_type == "regex":
        return _mt_pattern(path_value)
    else:
        return _mt_prefix(path_value)

def _path_match(path_value, worktree = False, match_type = "literal"):
    """A path selector — use .child()/.file()/.recurse()/.match() to refine, then .allow()/.deny()/.ask() to decide."""

    def child(name):
        """Select a subdirectory (subpath match)."""
        child_path = struct(_join = [path_value, name])
        return _path_match(child_path, worktree, "subpath")

    def file(name):
        """Select a specific file (exact match)."""
        file_path = struct(_join = [path_value, name])
        return _path_match(file_path, worktree, "literal")

    def recurse():
        """Switch to subpath (recursive) matching — matches this path and everything below it."""
        return _path_match(path_value, worktree, "subpath")

    def match(pat):
        """Select paths by regex pattern."""
        return _path_match(pat, worktree, "regex")

    def _resolve(effect, read, write, execute, all):
        all_ops = (read == None and write == None and execute == None)
        _read = effect if (read or all_ops) else None
        _write = effect if (write or all_ops) else None

        path_pat = _make_path_pattern(path_value, match_type)
        nodes = _fs_nodes(path_pat, _read, _write)

        sandbox_rules = []
        if effect == allow or effect == deny:
            caps = _caps_from_bools(
                read or all_ops,
                write or all_ops,
                execute or all_ops,
                all_ops,
            )
            if len(caps) > 0:
                sandbox_rules.append({
                    "effect": "allow" if effect == allow else "deny",
                    "path_value": path_value,
                    "caps": caps,
                    "match_type": match_type,
                })

        return struct(
            _is_path = True,
            _nodes = nodes,
            _path_value = path_value,
            _sandbox_rules = sandbox_rules,
        )

    def _allow(read = None, write = None, execute = None, all=None):
        return _resolve(allow, read, write, execute, all)

    def _deny(read = None, write = None, execute = None, all=None):
        return _resolve(deny, read, write, execute, all)

    def _ask(read = None, write = None, execute = None, all=None):
        return _resolve(ask, read, write, execute, all)

    return struct(child = child, file = file, recurse = recurse, match = match,
                  allow = _allow, deny = _deny, ask = _ask)

def cwd(follow_worktrees = False):
    """Build a CWD path match.

    Usage:
        cwd().allow(read=True, write=True)
        cwd(follow_worktrees=True).allow()
        cwd().child("src").allow(read=True)
    """
    return _path_match(struct(_env = "PWD"), follow_worktrees)

def home():
    """Build a HOME path match (literal by default, use .recurse() for recursive).

    Usage:
        home().child(".ssh").allow(read=True)
        home().child(".cargo").recurse().allow()
        home().recurse().allow(read=True)
    """
    return _path_match(struct(_env = "HOME"), False)

def tempdir():
    """Build a TMPDIR path match (recursive by default).

    Usage:
        tempdir().allow()
    """
    return _path_match(struct(_env = "TMPDIR"), False)

def path(path_str = None, env = None):
    """Build a path match for an arbitrary path or env var.

    Usage:
        path("/usr/local/bin").allow(read=True, execute=True)
        path(env="CARGO_HOME").allow(read=True, write=True)
    """
    if path_str != None and env != None:
        fail("path() takes either a path string or env=, not both")
    if path_str == None and env == None:
        fail("path() requires either a path string or env= argument")
    path_value = struct(_env = env) if env != None else path_str
    return _path_match(path_value, False)

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
        merged_default = default if other._default == None else other._default 
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
            fs=[cwd().allow(read=True), home().child(".ssh").allow(read=True)],
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

def _expand_children(children):
    """Expand a list of children, flattening path entries into their nodes."""
    expanded = []
    for child in children:
        if hasattr(child, "_is_path"):
            expanded.extend(child._nodes)
        elif hasattr(child, "_node"):
            expanded.append(child._node)
        else:
            expanded.append(child)
    return expanded

def _with_sandbox_support(node):
    """Wrap a match tree node with .sandbox(), .on(), and decision support."""

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

    def _on(children):
        expanded = _expand_children(children)
        result = node.on(expanded)
        return _with_sandbox_support(result)

    return struct(
        allow = _allow,
        deny = _deny,
        ask = _ask,
        sandbox = _set_sandbox,
        on = _on,
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
    def _on(children):
        expanded = _expand_children(children)
        result = node.on(expanded)
        return _with_sandbox_and_node(result, sb)

    return struct(
        allow = _allow,
        deny = _deny,
        ask = _ask,
        sandbox = _set_sandbox,
        on = _on,
        _node = node,
        _sandbox = sb,
    )

# ---------------------------------------------------------------------------
# Policy wrapper
# ---------------------------------------------------------------------------

def policy(default = "deny", rules = None, default_sandbox = None):
    """Build a policy.

    Usage:
        policy(default=deny, rules=[
            cwd().allow(read=True, write=True),
            exe("git", args=["push"]).deny(),
            exe("git").allow(),
            tool("Glob").on([
                cwd().child("src").allow(read=True),
            ]),
        ], default_sandbox=sandbox(
            name="default",
            default=deny,
            fs=[cwd().allow(read=True)],
        ))
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

    # Convert default_sandbox to JSON if provided
    default_sandbox_json = None
    if default_sandbox != None:
        if not hasattr(default_sandbox, "_is_sandbox"):
            fail("default_sandbox must be a sandbox() value")
        default_sandbox_json = _sandbox_to_json(default_sandbox)
        # Also register it in the sandbox map if not already seen
        if default_sandbox._name not in _seen_sandboxes:
            _seen_sandboxes[default_sandbox._name] = True
            sandbox_list.append(default_sandbox_json)

    return _mt_policy(default = default, sandboxes = sandbox_list, rules = flat_nodes, default_sandbox = default_sandbox_json)

def _collect_node(item, flat_nodes, sandbox_list, seen):
    """Extract a node and its sandbox from a rule builder."""
    flat_nodes.append(item._node if hasattr(item, "_node") else item)
    if hasattr(item, "_sandbox") and item._sandbox != None:
        sb = item._sandbox
        if sb._name not in seen:
            seen[sb._name] = True
            sandbox_list.append(_sandbox_to_json(sb))

# macOS system directories required for basic command execution.
# Programs need to read shared libraries, frameworks, dyld caches, and
# device nodes to function. These are auto-injected into every sandbox
# with default=deny so users don't need to declare them manually.
# On Linux (Landlock), non-existent paths are harmlessly ignored.
_SYSTEM_READ_PATHS = [
    "/",
    "/usr", "/bin", "/sbin",
    "/System", "/Library",
    "/dev", "/etc",
    "/private/etc", "/private/var/db/dyld",
    "/private/var/folders",
    "/var/select", "/var/run",
]

def _sandbox_to_json(sb):
    """Convert a sandbox struct to JSON-compatible dict for _mt_policy."""
    rules = []
    for r in sb._fs_rules:
        pv = r["path_value"]
        path_str = _resolve_path_value(pv)
        caps = r.get("caps", ["read", "write", "create"])
        rules.append({
            "effect": r.get("effect", "allow"),
            "caps": caps,
            "path": path_str,
            "path_match": r.get("match_type", "subpath"),
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

    # deny default = execute-only; auto-inject system path reads so
    # basic commands can load shared libraries and frameworks.
    # allow default = full access (no system paths needed).
    if sb._default == deny:
        default_caps = ["execute"]
        for sys_path in _SYSTEM_READ_PATHS:
            # "/" gets literal match (read the directory itself, not all children);
            # everything else gets subpath match (recursive read).
            match_type = "literal" if sys_path == "/" else "subpath"
            rules.append({
                "effect": "allow",
                "caps": ["read", "execute"],
                "path": sys_path,
                "path_match": match_type,
            })
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
