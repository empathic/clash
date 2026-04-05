# Claude Code compatibility — dynamic settings import.
#
# Usage:
#   load("@clash//claude_compat.star", "from_claude_settings")
#   policy("main", rules = [...] + from_claude_settings(user=True, project=True))

from_claude_settings = _from_claude_settings
