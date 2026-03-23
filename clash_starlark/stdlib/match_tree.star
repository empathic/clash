# Clash match tree DSL — tree-shaped policy builders.
#
# Rust globals available: _mt_node, _mt_condition, _mt_pattern, _mt_prefix,
# _mt_policy, _ALLOW, _DENY, _ASK

# ---------------------------------------------------------------------------
# Pattern helpers (reuse from std.star concepts)
# ---------------------------------------------------------------------------

def _mt_pat(value):
    """Convert a value to a match tree pattern.

    - None          → wildcard
    - "foo"         → literal
    - ["a", "b"]    → any_of
    - regex("...")  → regex
    """
    return _mt_pattern(value)

def mt_regex(pattern):
    """Create a regex pattern for match tree."""
    return struct(_regex = pattern)

# ---------------------------------------------------------------------------
# Condition builders — each returns a MatchTreeNode with .on()/.allow()/.deny()/.ask()
# ---------------------------------------------------------------------------

def exe(name = None):
    """Match a Bash command by binary name.

    Usage:
        exe("git").on([
            has_arg("--force").deny(),
            allow(),
        ])
        exe("cargo").allow(sandbox="cwd_access")
    """
    inner = _mt_condition({"positional_arg": 0}, _mt_pat(name))
    bash_pat = _mt_pattern("Bash")
    return _mt_condition("tool_name", bash_pat).on([inner])

def tool(name = None):
    """Match a tool by name.

    Usage:
        tool("Read").allow()
        tool().allow()
    """
    return _mt_condition("tool_name", _mt_pat(name))

def hook(name = None):
    """Match a hook type.

    Usage:
        hook("PreToolUse").on([...])
    """
    return _mt_condition("hook_type", _mt_pat(name))

def agent(name = None):
    """Match an agent by name.

    Usage:
        agent("code-review").allow()
    """
    return _mt_condition("agent_name", _mt_pat(name))

def arg(n, pattern = None):
    """Match a positional argument.

    Usage:
        arg(1, "push").deny()
    """
    return _mt_condition({"positional_arg": n}, _mt_pat(pattern))

def has_arg(pattern = None):
    """Match if any argument matches (orderless scan).

    Usage:
        has_arg("--force").deny()
    """
    return _mt_condition("has_arg", _mt_pat(pattern))

def named(name, pattern = None):
    """Match a named tool argument.

    Usage:
        named("file_path", regex(".*\\.env")).deny()
    """
    return _mt_condition({"named_arg": name}, _mt_pat(pattern))

def field(path, pattern = None):
    """Match a nested field in tool_input JSON.

    Usage:
        field(["command", "args"], "sensitive").deny()
    """
    return _mt_condition({"nested_field": path}, _mt_pat(pattern))

# ---------------------------------------------------------------------------
# Decision nodes
# ---------------------------------------------------------------------------

def allow(sandbox = None):
    """Create an allow decision node.

    Usage:
        allow()
        allow(sandbox="cwd_access")
    """
    if sandbox != None:
        return _mt_node({"decision": {"allow": sandbox}})
    return _mt_node({"decision": {"allow": None}})

def deny():
    """Create a deny decision node."""
    return _mt_node({"decision": "deny"})

def ask(sandbox = None):
    """Create an ask decision node.

    Usage:
        ask()
        ask(sandbox="cwd_access")
    """
    if sandbox != None:
        return _mt_node({"decision": {"ask": sandbox}})
    return _mt_node({"decision": {"ask": None}})

# ---------------------------------------------------------------------------
# Pattern combinators
# ---------------------------------------------------------------------------

def or_pat(*args):
    """Match if any pattern matches.

    Usage:
        exe(or_pat("cargo", "rustc")).allow()
    """
    return _mt_node({"any_of": [_mt_pat(a) for a in args]})

def not_pat(pattern):
    """Match if the pattern does NOT match.

    Usage:
        exe(not_pat("rm")).allow()
    """
    return _mt_node({"not": _mt_pat(pattern)})

# ---------------------------------------------------------------------------
# Policy wrapper
# ---------------------------------------------------------------------------

def policy(default = "deny", sandboxes = None, rules = None):
    """Build a match tree policy.

    Usage:
        policy(
            sandboxes = [cwd_sb],
            rules = [
                exe("git").on([
                    has_arg("--force").deny(),
                    allow(sandbox="cwd_access"),
                ]),
                tool().allow(),
            ],
        )
    """
    return _mt_policy(default = default, sandboxes = sandboxes, rules = rules)
