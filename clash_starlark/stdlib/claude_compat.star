# Claude Code compatibility — dynamic settings import.
#
# Returns a policy dict that can be deep-merged with user rules:
#
#   load("@clash//claude_compat.star", "from_claude_settings")
#   policy("main", merge(
#       from_claude_settings(),
#       { "Bash": allow(), "Read": allow() },
#   ))

from_claude_settings = _from_claude_settings
