# Clash standard library — all DSL builders.
#
# Emits v5 match tree nodes using minimal Rust primitives.
# Rust globals available: _mt_node, _mt_condition, _mt_pattern, _mt_prefix,
# _mt_literal, _mt_policy, _ALLOW, _DENY, _ASK, _OS, _ARCH

# ---------------------------------------------------------------------------
# Platform constants — re-export from Rust for use in policy files
# ---------------------------------------------------------------------------

OS = _OS      # e.g. "macos", "linux"
ARCH = _ARCH  # e.g. "aarch64", "x86_64"

# ---------------------------------------------------------------------------
# Effect constructors
# ---------------------------------------------------------------------------


def _parse_caps_string(caps):
    """Parse a shorthand capability string like 'rwcdx' into individual booleans."""
    return struct(
        read="r" in caps,
        write="w" in caps,
        create="c" in caps,
        delete="d" in caps,
        execute="x" in caps,
    )


def allow(caps=None, sandbox=None, read=None, write=None, create=None, delete=None, execute=None):
    """Create an allow effect, optionally with a sandbox and capabilities.

    Capabilities can be specified as a shorthand string or keyword args:
        allow("rwc")                         # read + write + create
        allow(read=True, write=True)         # read + write (+ create implied)
        allow()                              # all capabilities
    """
    if caps != None:
        parsed = _parse_caps_string(caps)
        read, write, create, delete, execute = parsed.read, parsed.write, parsed.create, parsed.delete, parsed.execute
    return struct(_effect=_ALLOW, _sandbox=sandbox, _is_effect=True,
                  _read=read, _write=write, _create=create, _delete=delete, _execute=execute)


def deny(caps=None, sandbox=None, read=None, write=None, create=None, delete=None, execute=None):
    """Create a deny effect, optionally with a sandbox and capabilities."""
    if caps != None:
        parsed = _parse_caps_string(caps)
        read, write, create, delete, execute = parsed.read, parsed.write, parsed.create, parsed.delete, parsed.execute
    return struct(_effect=_DENY, _sandbox=sandbox, _is_effect=True,
                  _read=read, _write=write, _create=create, _delete=delete, _execute=execute)


def ask(caps=None, sandbox=None, read=None, write=None, create=None, delete=None, execute=None):
    """Create an ask effect, optionally with a sandbox and capabilities."""
    if caps != None:
        parsed = _parse_caps_string(caps)
        read, write, create, delete, execute = parsed.read, parsed.write, parsed.create, parsed.delete, parsed.execute
    return struct(_effect=_ASK, _sandbox=sandbox, _is_effect=True,
                  _read=read, _write=write, _create=create, _delete=delete, _execute=execute)


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
    return struct(_regex=pattern)


# ---------------------------------------------------------------------------
# Match tree node builders (pure Starlark over _mt_condition / _mt_node)
# ---------------------------------------------------------------------------


def _cond(observe, pattern, doc=None):
    """Build a condition node, only passing doc when non-None."""
    if doc != None:
        return _mt_condition(observe, pattern, doc=doc)
    return _mt_condition(observe, pattern)


def _mt_tool(pattern, doc=None):
    """Build ToolName=pattern."""
    return _cond("tool_name", pattern, doc=doc)


def _mt_hook(pattern, doc=None):
    """Build HookType=pattern."""
    return _cond("hook_type", pattern, doc=doc)


def _mt_agent(pattern, doc=None):
    """Build AgentName=pattern."""
    return _cond("agent_name", pattern, doc=doc)


def _mt_mode(pattern, doc=None):
    """Build Mode=pattern."""
    return _cond("mode", pattern, doc=doc)


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
# Tool builders
# ---------------------------------------------------------------------------


def tool(name=None, doc=None):
    """Build a tool rule.

    Usage:
        tool().allow()
        tool("WebSearch").deny()
        tool(["Read", "Glob", "Grep"]).allow()
        tool("WebSearch", doc="No external searches").deny()
    """
    return _with_sandbox_support(_mt_tool(_pattern(name), doc=doc))


# ---------------------------------------------------------------------------
# Typed match keys — used in match() dicts to distinguish observables
# ---------------------------------------------------------------------------


def Mode(name):
    """Typed key for match() dicts — matches Claude Code's permission mode.

    Usage:
        match({Mode("plan"): {Tool("Read"): allow()}})
    """
    return struct(_match_key="mode", _match_value=name)


def Tool(name):
    """Typed key for match() dicts — matches tool name (explicit alternative to raw strings).

    Usage:
        match({Tool("Bash"): {"git": allow()}})
    """
    return struct(_match_key="tool", _match_value=name)


# ---------------------------------------------------------------------------
# Dict-based match tree builder
# ---------------------------------------------------------------------------


def _collect_effect_sandbox(eff, sandboxes, seen):
    """Collect sandbox from an effect descriptor if present."""
    if eff._sandbox != None:
        sb = eff._sandbox
        if sb._name not in seen:
            seen[sb._name] = True
            sandboxes.append(_sandbox_to_json(sb))


def _match_build_tree(tree, arg_index, sandboxes, seen):
    """Recursively build match tree nodes from a dict tree."""
    nodes = []
    for key, value in tree.items():
        keys = key if type(key) == "tuple" else (key,)
        for k in keys:
            pat = _pattern(k)
            cond = _mt_arg(arg_index, pat)

            if type(value) == "dict":
                children = _match_build_tree(value, arg_index + 1, sandboxes, seen)
                nodes.append(cond.on(children))
            elif hasattr(value, "_is_effect"):
                decision = _effect_to_decision(value)
                nodes.append(cond.on([decision]))
                _collect_effect_sandbox(value, sandboxes, seen)
            else:
                fail("match() values must be effect descriptors or dicts")
    return nodes


def _match_tool_key(name, value, result, sandboxes, seen):
    """Process a tool-level key (string or Tool() value) in match()."""
    pat = _pattern(name)
    tool_cond = _mt_tool(pat)

    if type(value) == "dict":
        children = _match_build_tree(value, 0, sandboxes, seen)
        node = tool_cond.on(children)
    elif hasattr(value, "_is_effect"):
        decision = _effect_to_decision(value)
        node = tool_cond.on([decision])
        _collect_effect_sandbox(value, sandboxes, seen)
    else:
        fail("match() values must be effect descriptors or dicts")

    result.append(struct(_node=node, _sandbox=None))


def _match_build_tool_level(tree, sandboxes, seen):
    """Build tool-level nodes from a dict inside a Mode() key."""
    nodes = []
    for key, value in tree.items():
        keys = key if type(key) == "tuple" else (key,)
        for k in keys:
            if hasattr(k, "_match_key") and k._match_key == "tool":
                name = k._match_value
            else:
                name = k  # raw string = tool name
            pat = _pattern(name)
            tool_cond = _mt_tool(pat)

            if type(value) == "dict":
                children = _match_build_tree(value, 0, sandboxes, seen)
                nodes.append(tool_cond.on(children))
            elif hasattr(value, "_is_effect"):
                decision = _effect_to_decision(value)
                nodes.append(tool_cond.on([decision]))
                _collect_effect_sandbox(value, sandboxes, seen)
            else:
                fail("match() values inside Mode() must be effect descriptors or dicts")
    return nodes


def _match_dispatch_key(key, value, result, sandboxes, seen):
    """Dispatch a single match() key based on its type."""
    if hasattr(key, "_match_key"):
        if key._match_key == "mode":
            cond = _mt_mode(_pattern(key._match_value))
            if type(value) == "dict":
                children = _match_build_tool_level(value, sandboxes, seen)
                node = cond.on(children)
            elif hasattr(value, "_is_effect"):
                node = cond.on([_effect_to_decision(value)])
                _collect_effect_sandbox(value, sandboxes, seen)
            else:
                fail("Mode() value must be a dict of tools or an effect")
            result.append(struct(_node=node, _sandbox=None))
        elif key._match_key == "tool":
            _match_tool_key(key._match_value, value, result, sandboxes, seen)
    else:
        # Raw string = tool name (backwards compat)
        _match_tool_key(key, value, result, sandboxes, seen)


def match(tree):
    """Build rules from a nested dict tree.

    Keys can be:
      - Raw strings: tool names (backwards compatible)
      - Tool("Bash"): explicit tool matcher
      - Mode("plan"): mode matcher (children are tool-level)
      - Tuples of the above: match multiple

    Returns a list of rule nodes for use in policy(rules=[...]).

    Usage:
        match({
            Mode("plan"): {
                Tool("Read"): allow(),
                Tool("ExitPlanMode"): allow(),
            },
            Tool("Bash"): {"git": allow()},
            "WebSearch": deny(),
        })
    """
    sandboxes = []
    seen = {}
    result = []

    for key, value in tree.items():
        keys = key if type(key) == "tuple" else (key,)
        for k in keys:
            _match_dispatch_key(k, value, result, sandboxes, seen)

    # Attach collected sandboxes to the first node for policy() to extract
    if result and sandboxes:
        first = result[0]
        result[0] = struct(_node=first._node, _sandbox=None, _cmd_sandboxes=sandboxes)

    return result


# ---------------------------------------------------------------------------
# Filesystem path builders
# ---------------------------------------------------------------------------


def _fs_nodes(path_pattern, read=None, write=None):
    """Build match tree nodes for filesystem access.

    path_pattern: a MatchTreeNode from _mt_prefix, _mt_literal, or _mt_pattern.
    read/write: effect values (allow/deny/ask) or None to skip.
    """
    nodes = []

    if read != None:
        node = _mt_fs_op(_pattern("read")).on(
            [
                _mt_fs_path(path_pattern).on(
                    [
                        _effect_decision(read),
                    ]
                ),
            ]
        )
        nodes.append(node)

    if write != None:
        node = _mt_fs_op(_pattern("write")).on(
            [
                _mt_fs_path(path_pattern).on(
                    [
                        _effect_decision(write),
                    ]
                ),
            ]
        )
        nodes.append(node)

    return nodes


def _unwrap_effect(effect):
    """Extract the effect string from an effect descriptor or raw string."""
    if hasattr(effect, "_is_effect"):
        return effect._effect
    return effect


def _effect_decision(effect):
    """Create a decision node from an effect string or descriptor."""
    e = _unwrap_effect(effect)
    if e == _ALLOW:
        return _mt_allow(None)
    elif e == _DENY:
        return _mt_deny()
    elif e == _ASK:
        return _mt_ask(None)
    else:
        fail("unknown effect: " + str(e))


def _effect_to_decision(eff):
    """Convert an effect descriptor struct to a match tree decision node."""
    sandbox_name = eff._sandbox._name if eff._sandbox != None else None
    if eff._effect == _ALLOW:
        return _mt_allow(sandbox_name)
    elif eff._effect == _DENY:
        return _mt_deny()
    elif eff._effect == _ASK:
        return _mt_ask(sandbox_name)
    else:
        fail("unknown effect: " + str(eff._effect))


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


def _caps_from_effect(eff):
    """Compute sandbox caps list from an effect descriptor with capability fields."""
    has_caps_string = (
        eff._read != None or eff._write != None or eff._create != None or
        eff._delete != None or eff._execute != None
    )
    if not has_caps_string:
        return ["read", "write", "create", "delete", "execute"]
    caps = []
    if eff._read:
        caps.append("read")
    if eff._write:
        caps.append("write")
    if eff._create:
        caps.append("create")
    if eff._delete:
        caps.append("delete")
    if eff._execute:
        caps.append("execute")
    return caps


# ---------------------------------------------------------------------------
# Sandbox path matchers (for dict-based fs= API)
# ---------------------------------------------------------------------------


def literal(path_str):
    """Explicit PathMatch::Literal marker for sandbox fs dicts."""
    return struct(_matcher_type="literal", _path=path_str, _is_sandbox_matcher=True)


def subpath(path_str, follow_worktrees=False):
    """Explicit PathMatch::Subpath marker for sandbox fs dicts."""
    return struct(_matcher_type="subpath", _path=path_str,
                  _follow_worktrees=follow_worktrees, _is_sandbox_matcher=True)


def _process_fs_dict(fs_dict, parent_path=None):
    """Convert a dict-based fs spec to a flat list of sandbox rules.

    Keys:
      - bare string with dict value → literal path join, recurse into children
      - bare string with decision value → subpath match (path + all descendants)
      - literal("...") → PathMatch::Literal
      - regex("...") → PathMatch::Regex
      - subpath("...") → PathMatch::Subpath (explicit)

    Values:
      - allow/deny/ask effect → terminal rule
      - dict → nested children (path segments concatenate)
    """
    rules = []
    for key, value in fs_dict.items():
        # Determine path, match_type, follow_worktrees from key type
        if hasattr(key, "_is_sandbox_matcher"):
            key_path = key._path
            explicit_type = key._matcher_type
            follow_wt = hasattr(key, "_follow_worktrees") and key._follow_worktrees
        elif hasattr(key, "_regex"):
            key_path = key._regex
            explicit_type = "regex"
            follow_wt = False
        else:
            # bare string
            key_path = key
            explicit_type = None
            follow_wt = False

        # Join with parent path
        if parent_path != None:
            full_path = parent_path + "/" + key_path
        else:
            full_path = key_path

        if type(value) == "dict":
            # Nested dict → recurse (bare string becomes literal join point)
            rules.extend(_process_fs_dict(value, full_path))
        elif hasattr(value, "_is_effect"):
            # Terminal decision
            match_type = explicit_type if explicit_type != None else "subpath"
            caps = _caps_from_effect(value)
            rule = {
                "effect": value._effect,
                "path_value": full_path,
                "caps": caps,
                "match_type": match_type,
            }
            if follow_wt:
                rule["follow_worktrees"] = True
            rules.append(rule)
        else:
            fail("sandbox fs values must be allow/deny/ask effects or nested dicts")
    return rules


def _make_path_pattern(path_value, match_type):
    """Create the appropriate FsPath pattern for the given match type."""
    if match_type == "literal":
        return _mt_literal(path_value)
    elif match_type == "regex":
        return _mt_pattern(path_value)
    else:
        return _mt_prefix(path_value)


def _path_match(path_value, worktree=False, match_type="literal"):
    """A path selector — use .child()/.file()/.recurse()/.match() to refine, then .allow()/.deny()/.ask() to decide."""

    def child(name):
        """Select a subdirectory (subpath match)."""
        child_path = struct(_join=[path_value, name])
        return _path_match(child_path, worktree, "subpath")

    def file(name):
        """Select a specific file (exact match)."""
        file_path = struct(_join=[path_value, name])
        return _path_match(file_path, worktree, "literal")

    def recurse():
        """Switch to subpath (recursive) matching — matches this path and everything below it."""
        return _path_match(path_value, worktree, "subpath")

    def match(pat):
        """Select paths by regex pattern."""
        return _path_match(pat, worktree, "regex")

    def _resolve(effect, read, write, execute, all, doc=None):
        all_ops = read == None and write == None and execute == None
        _read = effect if (read or all_ops) else None
        _write = effect if (write or all_ops) else None

        path_pat = _make_path_pattern(path_value, match_type)
        nodes = _fs_nodes(path_pat, _read, _write)

        sandbox_rules = []
        if effect == _ALLOW or effect == _DENY:
            caps = _caps_from_bools(
                read or all_ops,
                write or all_ops,
                execute or all_ops,
                all_ops,
            )
            if len(caps) > 0:
                rule = {
                    "effect": "allow" if effect == _ALLOW else "deny",
                    "path_value": path_value,
                    "caps": caps,
                    "match_type": match_type,
                }
                if worktree:
                    rule["follow_worktrees"] = True
                if doc != None:
                    rule["doc"] = doc
                sandbox_rules.append(rule)

        return struct(
            _is_path=True,
            _nodes=nodes,
            _path_value=path_value,
            _sandbox_rules=sandbox_rules,
        )

    def _allow(read=None, write=None, execute=None, all=None, doc=None):
        return _resolve(_ALLOW, read, write, execute, all, doc=doc)

    def _deny(read=None, write=None, execute=None, all=None, doc=None):
        return _resolve(_DENY, read, write, execute, all, doc=doc)

    def _ask(read=None, write=None, execute=None, all=None, doc=None):
        return _resolve(_ASK, read, write, execute, all, doc=doc)

    return struct(
        child=child,
        file=file,
        recurse=recurse,
        match=match,
        allow=_allow,
        deny=_deny,
        ask=_ask,
    )


def cwd(follow_worktrees=False):
    """Build a CWD path match.

    Usage:
        cwd().allow(read=True, write=True)
        cwd(follow_worktrees=True).allow()
        cwd().child("src").allow(read=True)
    """
    return _path_match(struct(_env="PWD"), follow_worktrees)


def home():
    """Build a HOME path match (literal by default, use .recurse() for recursive).

    Usage:
        home().child(".ssh").allow(read=True)
        home().child(".cargo").recurse().allow()
        home().recurse().allow(read=True)
    """
    return _path_match(struct(_env="HOME"), False)


def tempdir():
    """Build a TMPDIR path match (recursive by default).

    Usage:
        tempdir().allow()
    """
    return _path_match(struct(_env="TMPDIR"), False)


def path(path_str=None, env=None):
    """Build a path match for an arbitrary path or env var.

    Usage:
        path("/usr/local/bin").allow(read=True, execute=True)
        path(env="CARGO_HOME").allow(read=True, write=True)
    """
    if path_str != None and env != None:
        fail("path() takes either a path string or env=, not both")
    if path_str == None and env == None:
        fail("path() requires either a path string or env= argument")
    path_value = struct(_env=env) if env != None else path_str
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
        node = _mt_net_domain(_domain_pattern(domain_name)).on(
            [
                _effect_decision(effect),
            ]
        )
        nodes.append(struct(_node=node, _domain_name=domain_name))
    return nodes


def domain(name, effect):
    """Build a single net rule.

    Usage:
        domain("github.com", allow)
    """
    node = _mt_net_domain(_domain_pattern(name)).on(
        [
            _effect_decision(effect),
        ]
    )
    return [struct(_node=node, _domain_name=name)]


# ---------------------------------------------------------------------------
# Sandbox builder
# ---------------------------------------------------------------------------


def _make_sandbox(name, default, fs_rules, net_policy, net_domain_names=None, doc=None):
    """Create a sandbox struct."""
    if net_domain_names == None:
        net_domain_names = []

    def _update(other):
        updated_default = default if other._default == None else other._default
        updated_domains = net_domain_names + (
            other._net_domain_names if hasattr(other, "_net_domain_names") else []
        )
        return _make_sandbox(
            name,
            updated_default,
            fs_rules + other._fs_rules,
            net_policy or other._net_policy,
            updated_domains,
            doc=doc,
        )

    return struct(
        _name=name,
        _default=default,
        _fs_rules=fs_rules,
        _net_policy=net_policy,
        _net_domain_names=net_domain_names,
        _is_sandbox=True,
        _doc=doc,
        update=_update,
    )


def sandbox(name=None, default="deny", fs=None, net=None, doc=None):
    """Build a sandbox definition.

    Usage:
        sandbox("example", default=deny(),
            fs={
                "$PWD": allow("rwc"),
                "$HOME": {".ssh": allow("r")},
            },
            net=allow(),
        )
    """
    if name == None:
        fail("sandbox name is required")

    # Accept effect descriptors for default and net
    default = _unwrap_effect(default)

    # System rules: allow reading root but deny access to user home directories.
    _user_homes = "/Users" if OS == "macos" else "/home"
    _system_rules = [
        {"effect": _ALLOW, "path_value": "/", "caps": ["read"], "match_type": "subpath"},
        {"effect": _DENY, "path_value": _user_homes, "caps": ["read", "write", "create", "delete", "execute"], "match_type": "subpath"},
    ]

    fs_rules = []
    if fs == None:
        fs_rules = _system_rules
    elif type(fs) == "dict":
        # New dict-based API
        fs_rules = _process_fs_dict(fs) + _system_rules
    elif type(fs) == "list":
        # Legacy builder-based API
        fs += [path("/").recurse().allow(read=True), path(_user_homes).recurse().deny()]
        for entry in fs:
            if hasattr(entry, "_is_path"):
                if hasattr(entry, "_sandbox_rules"):
                    fs_rules.extend(entry._sandbox_rules)
            else:
                fail("sandbox fs= entries must be path values (cwd, home, tempdir, path)")
    else:
        fail("sandbox fs= must be a dict or list")

    net_policy = None
    net_domain_names = []
    if net != None:
        if hasattr(net, "_is_effect"):
            net_policy = _unwrap_effect(net)
        elif type(net) == "string":
            net_policy = net  # "allow" or "deny"
        elif type(net) == "list":
            # domains() returns a list of structs with _node and _domain_name
            net_domains = []
            for entry in net:
                if type(entry) == "list":
                    for sub in entry:
                        if hasattr(sub, "_domain_name"):
                            net_domain_names.append(sub._domain_name)
                            net_domains.append(
                                sub._node if hasattr(sub, "_node") else sub
                            )
                        else:
                            net_domains.append(sub)
                else:
                    if hasattr(entry, "_domain_name"):
                        net_domain_names.append(entry._domain_name)
                        net_domains.append(
                            entry._node if hasattr(entry, "_node") else entry
                        )
                    else:
                        net_domains.append(entry)
            net_policy = net_domains
        else:
            fail("sandbox net= must be an effect string or a list of domain entries")

    return _make_sandbox(name, default, fs_rules, net_policy, net_domain_names, doc=doc)


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


def _merge_sandboxes(*sandboxes):
    """Merge multiple sandboxes into one, combining fs rules and net policies."""
    if len(sandboxes) == 0:
        fail("sandbox() requires at least one sandbox argument")
    merged = sandboxes[0]
    for i in range(1, len(sandboxes)):
        merged = merged.update(sandboxes[i])
    return merged


def _with_sandbox_support(node):
    """Wrap a match tree node with .sandbox(), .on(), and decision support."""

    def _allow():
        result = node.allow()
        return struct(_node=result, _sandbox=None)

    def _deny():
        result = node.deny()
        return struct(_node=result, _sandbox=None)

    def _ask():
        result = node.ask()
        return struct(_node=result, _sandbox=None)

    def _set_sandbox(*sandboxes):
        return _with_sandbox_and_node(node, _merge_sandboxes(*sandboxes))

    def _on(children):
        expanded = _expand_children(children)
        result = node.on(expanded)
        return _with_sandbox_support(result)

    return struct(
        allow=_allow,
        deny=_deny,
        ask=_ask,
        sandbox=_set_sandbox,
        on=_on,
        _node=node,
        _sandbox=None,
    )


def _with_sandbox_and_node(node, sb):
    """Create a rule builder with sandbox attached."""

    def _allow():
        result = node.allow(sandbox=sb._name)
        return struct(_node=result, _sandbox=sb)

    def _deny():
        result = node.deny()
        return struct(_node=result, _sandbox=sb)

    def _ask():
        result = node.ask(sandbox=sb._name)
        return struct(_node=result, _sandbox=sb)

    def _set_sandbox(*sandboxes):
        return _with_sandbox_and_node(node, _merge_sandboxes(*sandboxes))

    def _on(children):
        expanded = _expand_children(children)
        result = node.on(expanded)
        return _with_sandbox_and_node(result, sb)

    return struct(
        allow=_allow,
        deny=_deny,
        ask=_ask,
        sandbox=_set_sandbox,
        on=_on,
        _node=node,
        _sandbox=sb,
    )


# ---------------------------------------------------------------------------
# Policy wrapper
# ---------------------------------------------------------------------------


def policy(default="deny", rules=None, default_sandbox=None):
    """Build a policy.

    Usage:
        policy(default=deny(), rules=[
            match({"Bash": {"git": {"push": deny()}}}),
            match({"Bash": {"git": allow()}}),
            match({("Read", "Glob", "Grep"): allow()}),
        ], default_sandbox=sandbox(
            name="default",
            default=deny(),
            fs={"$PWD": allow("r")},
        ))
    """
    default = _unwrap_effect(default)

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

    return _mt_policy(
        default=default,
        sandboxes=sandbox_list,
        rules=flat_nodes,
        default_sandbox=default_sandbox_json,
    )


def _collect_node(item, flat_nodes, sandbox_list, seen):
    """Extract a node and its sandbox from a rule builder."""
    flat_nodes.append(item._node if hasattr(item, "_node") else item)
    if hasattr(item, "_sandbox") and item._sandbox != None:
        sb = item._sandbox
        if sb._name not in seen:
            seen[sb._name] = True
            sandbox_list.append(_sandbox_to_json(sb))
    # match() attaches pre-built sandbox JSON via _cmd_sandboxes
    if hasattr(item, "_cmd_sandboxes"):
        for sb_json in item._cmd_sandboxes:
            name = sb_json.get("name", "")
            if name not in seen:
                seen[name] = True
                sandbox_list.append(sb_json)


def _sandbox_to_json(sb):
    """Convert a sandbox struct to JSON-compatible dict for _mt_policy."""
    rules = []
    for r in sb._fs_rules:
        pv = r["path_value"]
        path_str = _resolve_path_value(pv)
        caps = r.get("caps", ["read", "write", "create"])
        rule_dict = {
            "effect": r.get("effect", "allow"),
            "caps": caps,
            "path": path_str,
            "path_match": r.get("match_type", "subpath"),
        }
        if r.get("follow_worktrees", False):
            rule_dict["follow_worktrees"] = True
        doc_val = r.get("doc", None)
        if doc_val != None:
            rule_dict["doc"] = doc_val
        rules.append(rule_dict)

    net = "deny"
    if sb._net_policy != None:
        if type(sb._net_policy) == "string":
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

    # deny default = execute-only; auto-inject system path reads so
    # basic commands can load shared libraries and frameworks.
    # allow default = full access (no system paths needed).
    if sb._default == _DENY:
        default_caps = ["execute"]
    else:
        default_caps = ["read", "write", "create", "delete", "execute"]

    result = {
        "name": sb._name,
        "default": default_caps,
        "rules": rules,
        "network": net,
    }
    if hasattr(sb, "_doc") and sb._doc != None:
        result["doc"] = sb._doc
    return result


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
