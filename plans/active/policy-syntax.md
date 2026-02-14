(deny *) ; explicitly deny anything that isn't explicitly allowed

(allow (fs read) (subdir cwd))
(allow (fs read write) (subpath "~/.clash")) 
(allow (fs read write) (subpath "~/.claude"))
(allow (network (domain "github.com"))) ; any path at github.com
(allow (tool *)) ; allow all tools 
(include (claude-settings)) ; compile effecitve settings from all of claude's settings files

(when (agent (name "*subagent")))


