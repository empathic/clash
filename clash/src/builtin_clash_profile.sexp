; Built-in __clash_internal__ profile.
;
; Principle: read operations are allowed; mutations require human consent (ask).
;
; The --dry-run rules use (args (require "--dry-run")) which makes them *constrained*.
; Specificity-aware precedence ensures constrained-allow beats unconstrained-ask,
; so `add-rule --dry-run` is allowed while `add-rule` (without it) triggers ask.
;
; Users can override by defining a profile named __clash_internal__
; in their policy.

(allow read *
  (fs (read (subpath "~/.clash"))))

(allow bash "*clash policy show*")
(allow bash "*clash policy schema*")

(allow bash "*clash policy add-rule*"
  (args (require "--dry-run")))
(allow bash "*clash policy remove-rule*"
  (args (require "--dry-run")))

(ask bash "*clash policy add-rule*"
  (fs (all (subpath "~/.clash"))))
(ask bash "*clash policy remove-rule*"
  (fs (all (subpath "~/.clash"))))

(ask bash "*clash init*"
  (fs (all (subpath "~/.clash"))))
(ask bash "*clash migrate*"
  (fs (all (subpath "~/.clash"))))
