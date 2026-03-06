# Clash standard library — all DSL builders.
#
# Rust globals available: rule(), _policy(), import_json(), allow, deny, ask

# ---------------------------------------------------------------------------
# Pattern helpers
# ---------------------------------------------------------------------------

def _pattern(value):
    """Convert a value to a matcher pattern.

    - None          → {"any": null}
    - "foo"         → {"literal": "foo"}
    - ["a", "b"]    → {"or": [{"literal": "a"}, {"literal": "b"}]}
    - regex("...")  → {"regex": "..."}
    """
    if value == None:
        return {"any": None}
    if type(value) == "list":
        return {"or": [_pattern(v) for v in value]}
    if type(value) == "struct" and hasattr(value, "_regex"):
        return {"regex": value._regex}
    return {"literal": value}

def regex(pattern):
    """Create a regex pattern for use in exe() or tool()."""
    return struct(_regex = pattern)

# ---------------------------------------------------------------------------
# Finalizer helpers
# ---------------------------------------------------------------------------

def _finalizers(build_rule, _sandbox = None):
    """Create allow/deny/ask finalizer methods and a sandbox setter for a rule builder."""
    def _allow():
        r = build_rule("allow")
        return r.sandbox(_sandbox) if _sandbox else r
    def _deny():
        r = build_rule("deny")
        return r.sandbox(_sandbox) if _sandbox else r
    def _ask():
        r = build_rule("ask")
        return r.sandbox(_sandbox) if _sandbox else r
    def _set_sandbox(sb):
        return _finalizers(build_rule, sb)
    return struct(allow = _allow, deny = _deny, ask = _ask, sandbox = _set_sandbox)

# ---------------------------------------------------------------------------
# Exec / tool builders
# ---------------------------------------------------------------------------

def _exe_builder(bins, args_pat = None, _sandbox = None):
    """Internal: build an exe builder with composable .also() chaining."""
    def _build_exec():
        if len(bins) == 1:
            bin_pat = bins[0]
        else:
            bin_pat = {"or": bins}
        _exec = {"bin": bin_pat}
        if args_pat != None:
            _exec["args"] = args_pat
        return _exec

    def _build(effect):
        r = rule({"rule": {"effect": effect, "exec": _build_exec()}})
        return r.sandbox(_sandbox) if _sandbox else r

    def _also(other):
        return _exe_builder(bins + other._bins, args_pat, _sandbox)

    def _set_sandbox(sb):
        return _exe_builder(bins, args_pat, sb)

    def _allow():
        return _build("allow")
    def _deny():
        return _build("deny")
    def _ask():
        return _build("ask")

    return struct(
        allow = _allow, deny = _deny, ask = _ask,
        sandbox = _set_sandbox, also = _also,
        _bins = bins,
    )

def exe(name = None, args = None):
    """Build an exec rule.

    Usage:
        exe("git").allow()
        exe("git", args=["push"]).deny()
        exe("cargo").sandbox(my_sandbox).allow()
        exe(["cargo", "rustc"]).sandbox(my_sandbox).allow()
        exe("cargo").also(exe("rustc")).sandbox(my_sandbox).allow()
        exe().deny()  # deny all exec
    """
    if type(name) == "list":
        bins = [_pattern(n) for n in name]
    else:
        bins = [_pattern(name)]

    args_pat = None
    if args != None:
        args_pat = [_pattern(a) for a in args] + [{"any": None}]

    return _exe_builder(bins, args_pat)

def tool(name = None):
    """Build a tool rule.

    Usage:
        tool().allow()
        tool("WebSearch").deny()
        tool(regex("mcp__.*")).ask()
    """
    def _build(effect):
        return rule({"rule": {"effect": effect, "tool": {"name": _pattern(name)}}})

    return _finalizers(_build)

# ---------------------------------------------------------------------------
# Filesystem path builders
# ---------------------------------------------------------------------------

_VALID_EFFECTS = ["allow", "deny", "ask"]

def _validate_effect(name, value):
    """Validate that an effect is allow, deny, or ask."""
    if value != None and value not in _VALID_EFFECTS:
        fail("invalid effect '{}' for {}, must be allow, deny, or ask".format(value, name))

def _emit_fs_rules(path_expr, worktree, read, write, execute, allow_all):
    """Emit fs rule dicts for a path with given permissions."""
    _validate_effect("read", read)
    _validate_effect("write", write)
    _validate_effect("execute", execute)

    if allow_all:
        read = allow
        write = allow
        execute = allow

    # Map permissions to (op_name, effect) pairs
    ops = []
    if read != None:
        ops.append(("read", read))
    if write != None:
        ops.append(("write", write))
        ops.append(("create", write))
    if execute != None:
        ops.append(("delete", execute))

    if len(ops) == 0:
        return []

    # Build subpath expression
    subpath = {"path": path_expr}
    if worktree:
        subpath["worktree"] = True
    path_filter = {"subpath": subpath}

    # Group by effect
    groups = {}
    for op, eff in ops:
        if eff not in groups:
            groups[eff] = []
        groups[eff].append(op)

    rules = []
    for eff in [allow, deny, ask]:
        if eff not in groups:
            continue
        effect_ops = groups[eff]
        if len(effect_ops) == 1:
            op_pattern = {"single": effect_ops[0]}
        else:
            op_pattern = {"or": effect_ops}
        rules.append(rule({
            "rule": {
                "effect": eff,
                "fs": {"op": op_pattern, "path": path_filter},
            },
        }))

    return rules

def _path_entry(path_expr, worktree = False, read = None, write = None,
                execute = None, allow_all = False, _children = None):
    """Internal: build a path entry struct with .child() and ._rules."""
    if _children == None:
        _children = []

    # Capture parent perms for child() closure
    _read = read
    _write = write
    _execute = execute
    _allow_all = allow_all

    # Compute all rules: own + children
    _rules = _emit_fs_rules(path_expr, worktree, read, write, execute, allow_all)
    for c in _children:
        _rules.extend(c)

    def child(name, read = None, write = None, execute = None, allow_all = False):
        child_path = {"join": [path_expr, {"static": name}]}
        child_rules = _emit_fs_rules(child_path, False, read, write, execute, allow_all)
        return _path_entry(
            path_expr, worktree, _read, _write, _execute, _allow_all,
            _children + [child_rules],
        )

    return struct(child = child, _rules = _rules, _is_path = True)

def cwd(follow_worktrees = False, read = None, write = None,
        execute = None, allow_all = False):
    """Build a CWD path entry.

    Usage:
        cwd(read=allow, write=allow)
        cwd(follow_worktrees=True, allow_all=True)
    """
    return _path_entry({"env": "PWD"}, follow_worktrees, read, write, execute, allow_all)

def home(read = None, write = None, execute = None, allow_all = False):
    """Build a HOME path entry.

    Usage:
        home().child(".ssh", read=allow)
        home().child(".cargo", allow_all=True)
    """
    return _path_entry({"env": "HOME"}, False, read, write, execute, allow_all)

def tempdir(read = None, write = None, execute = None, allow_all = False):
    """Build a TMPDIR path entry.

    Usage:
        tempdir(allow_all=True)
    """
    return _path_entry({"env": "TMPDIR"}, False, read, write, execute, allow_all)

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
    path_expr = {"static": path_str} if path_str != None else {"env": env}
    return _path_entry(path_expr, False, read, write, execute, allow_all)

# ---------------------------------------------------------------------------
# Network builders
# ---------------------------------------------------------------------------

def _domain_pattern(name):
    """Convert a domain string to a matcher pattern."""
    if name == "*":
        return {"any": None}
    if name.startswith("*."):
        # Wildcard subdomain → regex matching the suffix
        suffix = name[2:]
        # Escape regex special chars in the suffix
        escaped = ""
        for c in suffix.elems():
            if c in ".+*?^${}()|[]\\":
                escaped += "\\" + c
            else:
                escaped += c
        return {"regex": "(^|.*\\.)" + escaped}
    return {"literal": name}

def domains(mapping):
    """Build net rules from a {domain: effect} dict.

    Usage:
        domains({"github.com": allow, "*.npmjs.org": allow})
    """
    rules = []
    for domain, effect in mapping.items():
        rules.append(rule({
            "rule": {
                "effect": effect,
                "net": {"domain": _domain_pattern(domain)},
            },
        }))
    return rules

def domain(name, effect):
    """Build a single net rule.

    Usage:
        domain("github.com", allow)
    """
    return [rule({
        "rule": {
            "effect": effect,
            "net": {"domain": _domain_pattern(name)},
        },
    })]

# ---------------------------------------------------------------------------
# Sandbox builder
# ---------------------------------------------------------------------------

def sandbox(default = "deny", fs = None, net = None):
    """Build a sandbox definition.

    Usage:
        sandbox(
            default=deny,
            fs=[cwd(read=allow), home().child(".ssh", read=allow)],
            net=allow,
        )
        sandbox(default=deny, net=[domains({"github.com": allow})])
    """
    body = []

    if fs != None:
        for entry in fs:
            if hasattr(entry, "_rules"):
                # Path entry — expand its rules
                body.extend([{"rule": r.json["rule"]} for r in entry._rules])
            else:
                fail("sandbox fs= entries must be path values (cwd, home, tempdir, path)")

    if net != None:
        if type(net) == "string":
            # Simple effect: allow/deny/ask all network
            body.append({"rule": {"effect": net, "net": {"domain": {"any": None}}}})
        elif type(net) == "list":
            for entry in net:
                if type(entry) == "list":
                    # domains() returns a list of RuleValues
                    body.extend([{"rule": r.json["rule"]} for r in entry])
                else:
                    fail("sandbox net= list entries must be domains() results")
        else:
            fail("sandbox net= must be an effect string or a list of domain entries")

    return {"default": default, "body": body}

# ---------------------------------------------------------------------------
# Policy wrapper
# ---------------------------------------------------------------------------

def policy(default = "deny", rules = None):
    """Build a policy. Flattens path entries and nested lists.

    Usage:
        policy(default=deny, rules=[
            cwd(read=allow, write=allow),
            home().child(".ssh", read=allow),
            exe("git").allow(),
            tool().allow(),
        ])
    """
    if rules == None:
        rules = []

    flat = []
    for item in rules:
        if hasattr(item, "_rules"):
            # Path entry — expand its rules
            flat.extend(item._rules)
        elif type(item) == "list":
            flat.extend(item)
        else:
            flat.append(item)

    return _policy(default = default, rules = flat)
