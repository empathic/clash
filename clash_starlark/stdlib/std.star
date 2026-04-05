# Clash standard library — all DSL builders.
#
# Rust globals available: _ALLOW, _DENY, _ASK, _OS, _ARCH,
# _register_settings, _from_claude_settings, _merge, _policy_impl

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
# Typed match keys — used in policy dicts to distinguish observables
# ---------------------------------------------------------------------------


def Mode(name):
    """Typed key for policy dicts — matches Claude Code's permission mode.

    Usage:
        policy("name", {Mode("plan"): {Tool("Read"): allow()}})
    """
    return struct(_match_key="mode", _match_value=name)


def Tool(name):
    """Typed key for policy dicts — matches tool name (explicit alternative to raw strings).

    Usage:
        policy("name", {Tool("Bash"): {"git": allow()}})
    """
    return struct(_match_key="tool", _match_value=name)


# ---------------------------------------------------------------------------
# merge() and policy() — thin wrappers around Rust-native implementations
# ---------------------------------------------------------------------------


def merge(*dicts):
    """Deep-merge policy dicts. Rightmost wins at leaf conflicts."""
    return _merge(*dicts)


def policy(name, rules_or_dict=None, default="deny", default_sandbox=None):
    """Register a named policy.

    Usage:
        policy("default", {
            mode("plan"): allow(sandbox=plan_box),
            mode("edit"): allow(sandbox=edit_box),
        })

        policy("default", merge(
            {mode("plan"): allow(sandbox=plan_box)},
            from_claude_settings(),
        ))
    """
    _policy_impl(name, rules_or_dict, default=_unwrap_effect(default), default_sandbox=default_sandbox)


# ---------------------------------------------------------------------------
# Filesystem path builders
# ---------------------------------------------------------------------------


def _unwrap_effect(effect):
    """Extract the effect string from an effect descriptor or raw string."""
    if hasattr(effect, "_is_effect"):
        return effect._effect
    return effect


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


def domains(mapping):
    """Build net rules from a {domain: effect} dict.

    Usage:
        domains({"github.com": allow, "*.npmjs.org": allow})
    """
    entries = []
    for domain_name, _effect in mapping.items():
        entries.append(struct(_domain_name=domain_name))
    return entries


def domain(name, effect):
    """Build a single net rule.

    Usage:
        domain("github.com", allow)
    """
    return [struct(_domain_name=name)]


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
            # domains() returns a list of structs with _domain_name
            for entry in net:
                if type(entry) == "list":
                    for sub in entry:
                        if hasattr(sub, "_domain_name"):
                            net_domain_names.append(sub._domain_name)
                else:
                    if hasattr(entry, "_domain_name"):
                        net_domain_names.append(entry._domain_name)
            net_policy = net_domain_names
        else:
            fail("sandbox net= must be an effect string or a list of domain entries")

    return _make_sandbox(name, default, fs_rules, net_policy, net_domain_names, doc=doc)


# ---------------------------------------------------------------------------
# Sandbox support for rule builders (exe, tool)
# ---------------------------------------------------------------------------


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
