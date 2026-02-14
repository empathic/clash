; Clash policy — deny-all default for new users.
;
; Everything is blocked except reading files in your project.
; Use "clash policy allow edit", "clash policy allow bash", or
; "clash policy allow web" to unlock capabilities as you need them.
;
; Run "clash policy setup" for interactive configuration.
;
; Note: clash always injects two built-in profiles:
;   __clash_internal__ — allows clash to read/write its own config
;   __claude_internal__ — allows Claude Code meta-tools (AskUserQuestion,
;                         ExitPlanMode, task management, etc.)

(default (permission deny) (profile main))

(profile cwd-read
  (allow read *
    (fs (read (subpath .)))))

(profile main
  (include cwd-read)
  ; Add rules here with "clash policy allow <verb>" or "clash policy setup"
  )
