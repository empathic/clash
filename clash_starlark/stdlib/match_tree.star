# Clash match tree DSL — tree-shaped policy builders.
#
# Rust globals available: _mt_exe, _mt_tool, _mt_hook, _mt_agent, _mt_arg,
# _mt_has_arg, _mt_named, _mt_field, _mt_allow, _mt_deny, _mt_ask,
# _mt_pattern, _mt_not, _mt_or, _mt_policy

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
    return _mt_exe(_mt_pat(name))

def tool(name = None):
    """Match a tool by name.

    Usage:
        tool("Read").allow()
        tool().allow()
    """
    return _mt_tool(_mt_pat(name))

def hook(name = None):
    """Match a hook type.

    Usage:
        hook("PreToolUse").on([...])
    """
    return _mt_hook(_mt_pat(name))

def agent(name = None):
    """Match an agent by name.

    Usage:
        agent("code-review").allow()
    """
    return _mt_agent(_mt_pat(name))

def arg(n, pattern = None):
    """Match a positional argument.

    Usage:
        arg(1, "push").deny()
    """
    return _mt_arg(n, _mt_pat(pattern))

def has_arg(pattern = None):
    """Match if any argument matches (orderless scan).

    Usage:
        has_arg("--force").deny()
    """
    return _mt_has_arg(_mt_pat(pattern))

def named(name, pattern = None):
    """Match a named tool argument.

    Usage:
        named("file_path", regex(".*\\.env")).deny()
    """
    return _mt_named(name, _mt_pat(pattern))

def field(path, pattern = None):
    """Match a nested field in tool_input JSON.

    Usage:
        field(["command", "args"], "sensitive").deny()
    """
    return _mt_field(path, _mt_pat(pattern))

# ---------------------------------------------------------------------------
# Decision nodes
# ---------------------------------------------------------------------------

def allow(sandbox = None):
    """Create an allow decision node.

    Usage:
        allow()
        allow(sandbox="cwd_access")
    """
    return _mt_allow(sandbox)

def deny():
    """Create a deny decision node."""
    return _mt_deny()

def ask(sandbox = None):
    """Create an ask decision node.

    Usage:
        ask()
        ask(sandbox="cwd_access")
    """
    return _mt_ask(sandbox)

# ---------------------------------------------------------------------------
# Pattern combinators
# ---------------------------------------------------------------------------

def or_pat(*args):
    """Match if any pattern matches.

    Usage:
        exe(or_pat("cargo", "rustc")).allow()
    """
    return _mt_or([_mt_pat(a) for a in args])

def not_pat(pattern):
    """Match if the pattern does NOT match.

    Usage:
        exe(not_pat("rm")).allow()
    """
    return _mt_not(_mt_pat(pattern))

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
