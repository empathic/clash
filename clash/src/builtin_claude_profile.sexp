; Built-in __claude_internal__ profile.
;
; Always allows Claude Code meta-tools that don't interact with the
; user's filesystem or system (e.g. AskUserQuestion, ExitPlanMode).
; Most are allow (pure workflow tools), but some warrant ask.
;
; Users can override by defining a profile named __claude_internal__
; in their policy.

(ask askuserquestion *)
(ask exitplanmode *)
(allow enterplanmode *)
(allow taskcreate *)
(allow taskupdate *)
(allow tasklist *)
(allow taskget *)
(allow taskoutput *)
(allow taskstop *)
(allow skill *)
(allow sendmessage *)
(allow teammate *)
