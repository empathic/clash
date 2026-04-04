# Clash standard library — all DSL builders.
#
# Emits v5 match tree nodes using minimal Rust primitives.
# Rust globals available: _mt_node, _mt_condition, _mt_pattern, _mt_prefix,
# _mt_literal, _ALLOW, _DENY, _ASK, _OS, _ARCH,
# _register_settings

# ---------------------------------------------------------------------------
# Platform constants — re-export from Rust for use in policy files
# ---------------------------------------------------------------------------

OS = _OS      # e.g. "macos", "linux"
ARCH = _ARCH  # e.g. "aarch64", "x86_64"
FULL = "rwcdx"
RO = "rx"
RW = "rwcx"

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


def glob(pattern):
    """Create a glob pattern for matching.

    - glob("*")            → wildcard (match anything)
    - glob("$HOME/*")      → direct children of $HOME
    - glob("$HOME/**/*")   → $HOME and all descendants (recursive)
    - glob("$HOME/**")     → same as /**/*
    """
    if pattern in ("*", "**"):
        return struct(_glob="*", _glob_type="wildcard")
    if pattern.endswith("/**/*"):
        return struct(_glob=pattern[:-5], _glob_type="recursive")
    if pattern.endswith("/**"):
        return struct(_glob=pattern[:-3], _glob_type="recursive")
    if pattern.endswith("/*"):
        return struct(_glob=pattern[:-2], _glob_type="children")
    fail("glob() pattern must end with /*, /**, or /**/* (got: " + pattern + ")")


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
# Mode key builder
# ---------------------------------------------------------------------------


def mode(name=None, doc=None):
    """Build a mode matcher. Usable as a dict key in policy() or as a builder.

    Usage (dict key):
        policy("default", {
            mode("plan"): allow(sandbox=plan_box),
        })

    Usage (builder):
        mode("plan").allow(sandbox=plan_box)
    """
    return struct(_match_key="mode", _match_value=name, _doc=doc)


# ---------------------------------------------------------------------------
# Typed match keys — used in when() dicts to distinguish observables
# ---------------------------------------------------------------------------


def Mode(name):
    """Typed key for when() dicts — matches Claude Code's permission mode.

    Usage:
        when({Mode("plan"): {Tool("Read"): allow()}})
    """
    return struct(_match_key="mode", _match_value=name)


def Tool(name):
    """Typed key for when() dicts — matches tool name (explicit alternative to raw strings).

    Usage:
        when({Tool("Bash"): {"git": allow()}})
    """
    return struct(_match_key="tool", _match_value=name)


# ---------------------------------------------------------------------------
# when() and policy() — thin wrappers around Rust-native implementations
# ---------------------------------------------------------------------------


def when(tree):
    """Build rules from a nested dict tree.

    Keys can be raw strings (tool names), Tool("Bash"), Mode("plan"),
    or tuples thereof. Values are effects (allow/deny/ask) or nested dicts.
    """
    return _when_impl(tree)


def policy(name, rules_or_dict=None, default="deny", rules=None, default_sandbox=None):
    """Register a named policy.

    Usage (dict form):
        policy("default", {
            mode("plan"): allow(sandbox=plan_box),
            mode("edit"): allow(sandbox=edit_box),
        })

    Usage (rules form):
        policy("default", rules=[
            when({"Bash": {"git": {"push": deny()}}}),
            when({("Read", "Glob", "Grep"): allow()}),
        ])
    """
    _policy_impl(name, rules_or_dict, default=_unwrap_effect(default), rules=rules, default_sandbox=default_sandbox)


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
      - bare string with decision value → literal match (exact path only)
      - glob("...") → PathMatch::Subpath (prefix/recursive match)
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
        elif hasattr(key, "_glob"):
            key_path = key._glob
            if key._glob_type == "wildcard":
                key_path = "/"
                explicit_type = "subpath"
            elif key._glob_type == "recursive":
                explicit_type = "subpath"
            elif key._glob_type == "children":
                explicit_type = "child_of"
            else:
                fail("unknown glob type: " + key._glob_type)
            follow_wt = False
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
            match_type = explicit_type if explicit_type != None else "literal"
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
    elif match_type == "child_of":
        return _mt_child_of(path_value)
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


# ---------------------------------------------------------------------------
# Policy wrapper
# ---------------------------------------------------------------------------


def settings(default="deny", default_sandbox=None, on_sandbox_violation=None, harness_defaults=None):
    """Register policy settings.

    Usage:
        settings(default=ask(), default_sandbox="dev")
        settings(default=deny(), on_sandbox_violation="workaround")
        settings(default=allow(), harness_defaults=False)
    """
    default = _unwrap_effect(default)
    ds = None
    if default_sandbox != None:
        if hasattr(default_sandbox, "_is_sandbox"):
            ds = default_sandbox._name
        elif type(default_sandbox) == "string":
            ds = default_sandbox
        else:
            fail("default_sandbox must be a sandbox name string or sandbox() value")
    _register_settings(default=default, default_sandbox=ds, on_sandbox_violation=on_sandbox_violation, harness_defaults=harness_defaults)



def _sandbox_to_json(sb):
    """Convert a sandbox struct to a JSON-compatible dict."""
    rules = []
    for r in sb._fs_rules:
        pv = r["path_value"]
        path_str = _resolve_path_value(pv)
        caps = r.get("caps", ["read", "write", "create"])
        rule_dict = {
            "effect": r.get("effect", "allow"),
            "caps": caps,
            "path": path_str,
            "path_match": r.get("match_type", "literal"),
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
