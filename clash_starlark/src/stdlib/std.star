def exe(name, args = None):
    """Build an exec rule for a single binary.

    Usage:
        exe("git").allow()
        exe("git", args=["push"]).deny()
        exe("cargo").allow().sandbox(my_sandbox)
    """
    _exec = {"bin": {"literal": name}}
    if args != None:
        _args = [{"literal": a} for a in args]
        _args.append({"any": None})
        _exec["args"] = _args

    def _allow():
        return rule({"rule": {"effect": "allow", "exec": _exec}})

    def _deny():
        return rule({"rule": {"effect": "deny", "exec": _exec}})

    def _ask():
        return rule({"rule": {"effect": "ask", "exec": _exec}})

    return struct(allow = _allow, deny = _deny, ask = _ask)

def tool(name = None):
    """Build a tool rule.

    Usage:
        tool().allow()           # allow all tools
        tool("WebSearch").deny() # deny specific tool
    """
    _name = {"any": None} if name == None else {"literal": name}

    def _allow():
        return rule({"rule": {"effect": "allow", "tool": {"name": _name}}})

    def _deny():
        return rule({"rule": {"effect": "deny", "tool": {"name": _name}}})

    def _ask():
        return rule({"rule": {"effect": "ask", "tool": {"name": _name}}})

    return struct(allow = _allow, deny = _deny, ask = _ask)

def match_exes(exe_list):
    """Build an exec rule matching multiple binaries.

    Usage:
        match_exes(["rustc", "cargo"]).allow().sandbox(rust_sandbox)
    """
    bins = [{"literal": b} for b in exe_list]
    bin_pattern = {"or": bins} if len(bins) > 1 else bins[0]
    _exec = {"bin": bin_pattern}

    def _allow():
        return rule({"rule": {"effect": "allow", "exec": _exec}})

    def _deny():
        return rule({"rule": {"effect": "deny", "exec": _exec}})

    def _ask():
        return rule({"rule": {"effect": "ask", "exec": _exec}})

    return struct(allow = _allow, deny = _deny, ask = _ask)
