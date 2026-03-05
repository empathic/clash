def _pattern(value):
    """Convert a value to a matcher pattern.

    - None          → {"any": null}     (match anything)
    - "foo"         → {"literal": "foo"} (exact match)
    - regex("...")  → {"regex": "..."}   (regex match)
    """
    if value == None:
        return {"any": None}
    if type(value) == "struct" and hasattr(value, "_regex"):
        return {"regex": value._regex}
    return {"literal": value}

def _patterns(values):
    """Convert a list of values to a single matcher pattern (or-ing multiple)."""
    pats = [_pattern(v) for v in values]
    if len(pats) == 1:
        return pats[0]
    return {"or": pats}

def regex(pattern):
    """Create a regex pattern for use in exe() or tool().

    Usage:
        exe(regex("cargo.*")).allow()
        tool(regex("mcp__.*")).deny()
    """
    return struct(_regex = pattern)

def _finalizers(build_rule):
    """Create allow/deny/ask finalizer methods for a rule builder."""
    def _allow():
        return build_rule("allow")
    def _deny():
        return build_rule("deny")
    def _ask():
        return build_rule("ask")
    return struct(allow = _allow, deny = _deny, ask = _ask)

def exe(name = None, args = None):
    """Build an exec rule for a single binary.

    Usage:
        exe("git").allow()
        exe("git", args=["push"]).deny()
        exe(regex("cargo.*")).allow().sandbox(my_sandbox)
        exe().deny()  # deny all exec
    """
    _exec = {"bin": _pattern(name)}
    if args != None:
        _args = [_pattern(a) for a in args]
        _args.append({"any": None})
        _exec["args"] = _args

    def _build(effect):
        return rule({"rule": {"effect": effect, "exec": _exec}})

    return _finalizers(_build)

def tool(name = None):
    """Build a tool rule.

    Usage:
        tool().allow()                    # allow all tools
        tool("WebSearch").deny()          # deny specific tool
        tool(regex("mcp__.*")).ask()      # ask for all MCP tools
    """
    def _build(effect):
        return rule({"rule": {"effect": effect, "tool": {"name": _pattern(name)}}})

    return _finalizers(_build)

def match_exes(exe_list):
    """Build an exec rule matching multiple binaries.

    Usage:
        match_exes(["rustc", "cargo"]).allow().sandbox(rust_sandbox)
        match_exes(["git", regex("gh.*")]).ask()
    """
    _exec = {"bin": _patterns(exe_list)}

    def _build(effect):
        return rule({"rule": {"effect": effect, "exec": _exec}})

    return _finalizers(_build)
