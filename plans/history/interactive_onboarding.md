# Problem
New users of clash may start without any understanding of clash or how sandboxing techniques work
in general. We need to get them to a useful config and usage of clash without overloading them or breaking their trust.

The current onboarding workflow through the /onboarding skill does not accomplish this. I believe we need onboarding to happen outside of claude or any other codeing agent due to the non-determanistic nature of agent skills.

## Axioms
- A user's trust must never be violated. If they believe clash will do something, it must do that thing
- All user's arrive at clash with a different level of technical understanding. We should never assume
knowledge not needed to get to the current step. i.e. The user has opened the commandline and typed in
`clash init` so we can trust they know how to enter commands, but we can't trust they understand what stdin or stdout are.
- A productive use of clash is one where a user trusts clash and will allow clash to do enforcement rather than prompting the user for permission.
- If we overload a user with context, they will stop using clash. Learning about clash should be progressive and should be earned by providing utility to the user.
- Most users will not read walls of text or documentation. In depth explinations should be available, but never the first touchpoint for education.

## Design

### Default posture: deny-all

The default policy after `clash init` should deny everything except:
- The two `__*_internal__` built-in profiles (clash config access, Claude meta-tools)
- `allow read *` scoped to the current working directory

Claude can read code but cannot edit, write, run commands, or fetch URLs. The user sees clash actively blocking actions on first use, which builds trust ("this thing is real").

### Onboarding happens at runtime, not at init

`clash init` is minimal:
1. Set up the deny-all default policy
2. One short explanation: "Clash is set up. Everything except reading files is blocked. As you use Claude, clash will show you how to allow what you need."
3. Plant the seed: "Clash has two tools: **deny** blocks specific dangerous actions, **allow** grants broad access within safe boundaries. You'll see both as you go."
4. Optional accelerator: "Want to unlock common tools for your project now?" If yes, ask about project ecosystem and unlock a sensible set. If no, done.

The real onboarding is the denial messages. Each denied action is a micro-onboarding moment.

### Denial messages serve two audiences

When clash denies an action, the message must serve:
- **The user** — concise, non-scary, actionable. What happened and what to do about it.
- **The agent** — structured context so Claude can explain the situation conversationally and help the user resolve it, rather than just parroting a command.

### Progressive trust: deny → allow specific → allow broad

Users learn the deny/allow-with-capabilities distinction through experience, not explanation:

**Phase 1 — "Clash is a blocklist" (init)**
Everything denied. User sees clash blocking things. Trust is built. Mental model: clash prevents bad things.

**Phase 2 — "Let me allow what I need" (first few sessions)**
Denial messages suggest specific allows: `clash allow 'bash cargo test*'`, `clash allow 'edit *' --fs 'write: subpath(.)'`. User builds policy from real needs. Still thinking command-by-command — that's fine.

**Phase 3 — "I can allow broadly and still be safe" (the aha moment)**
After the user has accumulated several specific rules, clash suggests consolidation: "You've allowed 5 individual commands. You could replace them all with `allow bash *` scoped to your project — same safety, less friction." The user now understands that allows are about scope/boundaries, not specific commands.

The goal is for users to eventually feel safe with `allow bash *` because they understand the filesystem/network sandbox underneath makes it safe. But this understanding is earned, not assumed.

### Visibility gap: sandbox enforcement feedback

Clash needs to understand what sandbox enforcements users are actually hitting to guide them toward better policies (especially the Phase 2 → 3 transition). There is a visibility gap:

**What clash CAN see:**
- Policy-level decisions (audit log) — which tool invocations were allowed/denied/asked at the rule level
- Claude session transcripts — tool results that contain error messages from sandboxed commands

**What clash CANNOT see:**
- Seatbelt enforcement details. Once clash hands off to `sandbox-exec` via `execvp`, clash is no longer running. Seatbelt denials surface as cryptic `EPERM`/`EACCES` errors to the sandboxed process. Clash never learns what path or operation was blocked.
- macOS system logs contain seatbelt denial records (`os_log`), but parsing them is fragile and platform-specific.

**Consequence:** If a user has `allow bash cargo *` with `fs: write: subpath(./target)` and cargo tries to write to `~/.cargo/registry`, seatbelt blocks it. Nobody — not clash, not Claude, not the user — connects the error to the sandbox. The user just sees a confusing build failure.

**Potential approaches:**
1. **Audit log analysis** — clash already records policy decisions. Sufficient for detecting "user has N specific bash rules, suggest consolidation." Does not help with sandbox-too-tight problems.
2. **Transcript analysis** — parse Claude session transcripts for "permission denied" / "operation not permitted" patterns following sandboxed commands. Indirect but requires no kernel access. Could power suggestions like "cargo failed — your sandbox may be too restrictive for the cargo toolchain."
3. **System log parsing** — after a sandboxed command fails, query `log show` for recent seatbelt denials. Gives real enforcement details (path, operation) but is macOS-specific and fragile.
4. **Subprocess model** — instead of `execvp` (process replacement), run the sandboxed command as a child process so clash stays alive and can observe exit codes, stderr, and correlate with system logs. This is a larger architectural change.

Which approach (or combination) to pursue is an open question. For the initial onboarding implementation, audit log analysis (#1) may be sufficient since Phase 1-2 are driven by policy-level denials, not sandbox enforcement. Transcript and system log analysis become important for Phase 3.

## Proposed improvements

### 1. Concrete first-session walkthrough

The plan describes phases but never walks through what actually happens. This is the most
important UX surface — if the first denied action feels bad, nothing else matters.

**Scenario: User asks Claude to fix a bug**

```
User: "fix the bug in main.rs"

Claude reads main.rs             → allowed (cwd read is permitted)
Claude identifies the fix
Claude tries Edit on main.rs     → DENIED by clash
```

**What the user sees in their terminal (stderr):**
```
clash: blocked edit on src/main.rs
  Claude can read files but can't edit them yet.
  To allow editing in this project: clash allow editing
  (run "clash help allow" for more options)
```

**What Claude receives (additional_context):**
```
clash: denied tool=Edit path=src/main.rs reason=default-deny
The user has a deny-all policy and has not yet allowed editing.
This is likely the user's first session with clash.
Suggest the user run: clash allow editing
Do NOT suggest raw rule syntax. Do NOT retry the edit.
Explain briefly that clash blocked this to protect their project,
and they can unlock editing with one command.
```

**What Claude says to the user:**
> "Clash blocked me from editing the file — it's protecting your project until you
> tell it what I'm allowed to do. To let me edit files in this project, run:
> `clash allow editing`
> Then I can apply the fix."

**What happens after the user runs `clash allow editing`:**
```
clash: allowed — Claude can now edit files in /Users/you/project
  (files outside this directory are still protected)
```

User returns to Claude, Claude retries the edit, it works. Trust moment: clash
protected them, they unlocked what they needed, Claude completed the task.

Key principles in this walkthrough:
- The terminal message is 3 lines. No syntax. No jargon.
- The agent context is directive — it tells Claude what to say and what NOT to do.
- The suggested command (`clash allow editing`) is a **preset**, not raw rule syntax.
- The confirmation after allowing tells the user the *scope* of what they just unlocked.

### 2. Presets: a simpler vocabulary for the first unlock

Phase 2 currently suggests commands like `clash allow 'edit *' --fs 'write: subpath(.)'`.
That's asking the user to learn rule syntax at the moment of maximum frustration.

Instead, clash should offer **presets** — named bundles that map to common capability grants:

- `clash allow editing` → `allow edit *` + `allow write *` scoped to cwd
- `clash allow commands` → `allow bash *` scoped to cwd filesystem
- `clash allow reading` → `allow read *` (already default, but exists for completeness)
- `clash allow web` → `allow webfetch *` + `allow websearch *`

Presets are the Phase 2 vocabulary. The user doesn't need to understand rule syntax to
build a useful policy. Each preset:
- Has a one-word name that describes the *capability*, not the mechanism
- Defaults to cwd-scoped sandbox constraints (safe by design)
- Prints a plain-English confirmation of what was unlocked and what's still protected

The full rule syntax (`clash policy add-rule ...`) is the Phase 3 vocabulary — available
when the user wants fine-grained control, but never required.

Presets also solve the init-time accelerator: "Want to unlock common tools now?"
becomes a simple checklist of presets rather than ecosystem-specific questions.

### 3. The `--dangerously-skip-permissions` question

With deny-all default, users who don't run with `--dangerously-skip-permissions` will
experience double prompting: clash denies an action, AND Claude's built-in permission
system also gates it. This is confusing — "which system am I trusting?"

Options:
- (a) `clash init` automatically configures Claude Code to use skip-permissions
  (writes to `.claude/settings.json`). The user never sees double prompting.
- (b) `clash init` tells the user to set the flag themselves and explains why.
- (c) clash detects when the flag is NOT set and adjusts its behavior (e.g., uses
  `ask` instead of `deny` for the default, since Claude's own system will also prompt).

Recommendation: option (a) for new users. Clash is taking ownership of the permission
model — it should configure Claude Code accordingly rather than asking the user to
understand the interaction between two permission systems. For existing users, option (b)
with a clear explanation.

### 4. Existing user upgrade path

The plan focuses on new users. What about someone who already has a policy?

- `clash init` when a policy exists should NOT overwrite it.
- A separate command — `clash reset` or `clash onboard` — lets existing users opt into
  the new deny-all flow if they want to start fresh.
- On upgrade, if clash detects the old default policy template, it could suggest:
  "Your policy uses the old defaults. Run `clash onboard` to try the new guided setup."
- Otherwise: existing policies continue to work unchanged. No surprise changes.

### 5. Scope: what ships first

**v1 (minimum shippable):**
- New deny-all default policy template
- `clash init` deterministic CLI flow (no agent involvement)
- Improved denial messages (human-readable + agent-readable context)
- 3-4 presets (`editing`, `commands`, `web`)
- `clash init` auto-configures `--dangerously-skip-permissions`

**v2 (next iteration):**
- Optional accelerator during init (preset checklist)
- Phase 3 consolidation suggestions (audit log analysis to detect "too many specific rules")
- Existing user upgrade path (`clash onboard` for re-onboarding)

**v3 (future):**
- Visibility gap solutions (transcript analysis, system log parsing)
- Smart preset suggestions based on project detection (Cargo.toml → suggest rust presets)
- Phase 3 automatic sandbox tuning

### 6. Phase 2 → Phase 3 transition mechanism (deferred to v2)

The consolidation suggestion requires:
- Audit log analysis to count rules per verb category (e.g., "user has 4 bash rules")
- A trigger threshold (start with 4+ rules in the same verb category)
- A presentation surface — most likely a message during `clash status` or at session start:
  "You have 6 individual command rules. Run `clash simplify` to consolidate them into
  a single sandboxed rule."
- A `clash simplify` command that shows the proposed consolidation, explains the
  capability/constraint model, and asks for confirmation.

This is explicitly deferred from v1. Phase 2 (presets) is sufficient for a first release.
Phase 3 becomes valuable once we have data on how users actually build their policies.

### 7. Denial message format specification

**Terminal output (stderr, seen by user):**
```
clash: blocked <verb> on <noun-summary>
  <one-sentence explanation in plain English>
  To allow this: clash allow <preset-name>
  (run "clash help allow" for more options)
```

Rules:
- Max 4 lines. Never more.
- First line is always `clash: blocked <what happened>`.
- Second line explains WHY in terms of outcomes, not mechanisms.
  Good: "Claude can't edit files yet."
  Bad: "No rule matched for verb=edit noun=src/main.rs, default effect is deny."
- Third line is always an actionable command. Prefer presets over raw syntax.
- Fourth line is an escape hatch to more detail, for power users.

**Agent context (additional_context in hook response):**
```
clash: denied tool=<tool> input_summary=<truncated> reason=<reason-code>
<Plain English description of the situation and the user's policy state>
Suggested resolution: <preset command or rule command>
Instructions: <what the agent should say and should NOT do>
```

The agent context is longer and more directive than the terminal output. It:
- Tells Claude the user's policy state (new user? has some rules? power user?)
- Suggests what to recommend (preset for new users, rule syntax for experienced users)
- Includes negative instructions ("Do NOT retry the tool. Do NOT suggest workarounds.")
- Adapts based on how many denials have occurred this session (first denial gets a
  warmer explanation; fifth denial gets a shorter one with a link to `clash allow --help`)

## Execution plan (v1)

### Workstreams and task DAG

```
WS1: Default policy ──────────┐
  T1: Draft deny-all template  │
  T2: Draft init CLI output    │
  T3: Implement new template   ├──→ WS5: Testing
  T4: Auto bypass_permissions  │      T14: Unit tests (presets)
                               │      T15: Unit tests (denial msgs)
WS2: Presets ─────────────────┤      T16: Clester e2e (init flow)
  T5: Define preset specs      │      T17: Manual walkthrough doc
  T6: CLI command `allow <p>`  │
  T7: Preset expansion logic   │
  T8: Confirmation messages    │
  T9: `clash presets` list cmd ├──→ WS5
                               │
WS3: Denial messages ─────────┤
  T10: Onboarding state store  │
  T11: Terminal message format │
  T12: Agent context format    │
  T13: Adaptive messaging      ├──→ WS5
```

**Parallelism:** WS1, WS2, and WS3 can start in parallel. Within each:
- WS1: T1 → T2 → T3 + T4 (T3 and T4 are independent)
- WS2: T5 → T6 → T7 → T8 + T9
- WS3: T10 → T11 + T12 → T13
- WS5: starts after all others complete

### WS1: New deny-all default policy

**T1: Draft the deny-all policy template**

Replace `default_policy.yaml` with a minimal deny-all template:
```yaml
default:
  permission: deny
  profile: main

profiles:
  main:
    include: [cwd-read]
  cwd-read:
    rules:
      allow read *:
        fs:
          read: subpath(.)
```

The built-in `__clash_internal__` and `__claude_internal__` profiles are injected
automatically by the compiler (`compile.rs:20-27`). No need to include them here.

This template intentionally has NO deny rules — the default permission is deny, so
explicit denials aren't needed yet. Deny rules become meaningful in Phase 2-3 when
the user has allow rules and wants to carve out exceptions.

Files: `clash/src/default_policy.yaml`

**T2: Draft all init CLI output text**

Write the exact strings the user sees during `clash init`. Every word matters.

```
Clash initialized.

What happens now:
  - Claude can read files in this project
  - Everything else (editing, commands, web access) is blocked
  - When Claude hits a block, you'll see how to allow it

Run "clash allow --help" to see what you can unlock.
```

No jargon. No mention of policies, profiles, YAML, rules, or sandboxing.
"Blocked" instead of "denied." "Allow" instead of "configure."

Files: `clash/src/main.rs` (run_init function, lines 719-749)

**T3: Implement the new template**

- Replace the content of `default_policy.yaml`
- Update `run_init()` to print the new output text from T2
- Ensure `--force` still works for re-initialization

Files: `clash/src/default_policy.yaml`, `clash/src/main.rs`

**T4: Auto-configure bypass_permissions**

`clash init` should call `set_bypass_permissions()` by default (not just with `--bypass-permissions` flag).
Currently the flag is optional (`clash/src/main.rs:193-203`). Change behavior:
- Default: always set bypass_permissions=true on init
- Add `--no-bypass` flag for users who explicitly don't want this
- Print: "Configured Claude Code to use clash as the sole permission handler."

If setting bypass_permissions fails (e.g., can't write to ~/.claude/settings.json),
warn but don't fail init. The policy is still useful even with double-prompting.

Files: `clash/src/main.rs` (run_init, set_bypass_permissions)

### WS2: Presets system

**T5: Define preset specifications**

Each preset maps to one or more policy rules with sensible defaults:

| Preset | Rules added | Scope |
|--------|------------|-------|
| `editing` | `allow edit *`, `allow write *` | `fs: { write + create: subpath(.) }` |
| `commands` | `allow bash *` | `fs: { full: subpath(.) }` |
| `web` | `allow webfetch *`, `allow websearch *` | (no fs constraint) |

Design decisions:
- Presets always scope to cwd where applicable (safe by default)
- `editing` includes both `edit` and `write` tools (users don't distinguish these)
- `commands` is the broadest preset — allows any bash but sandboxed to project dir
- Presets are additive — running `clash allow editing` twice is idempotent
- Presets do NOT add deny rules — those come from explicit user choices later

Presets should be defined as data, not code. A `presets.rs` module with a static
list of PresetDef structs, so adding new presets doesn't require changing the CLI parser.

Files: new `clash/src/presets.rs`

**T6: New `clash allow <preset>` CLI command**

Add a top-level `allow` subcommand (NOT under `policy`):

```
clash allow <PRESET>       Apply a named preset
clash allow --list         List available presets
clash allow --help         Show help with examples
```

This is separate from `clash policy add-rule` which is the power-user interface.
`clash allow` is the onboarding interface.

Clap definition:
```rust
/// Allow a category of actions (editing, commands, web)
Allow {
    /// Preset name to apply
    preset: Option<String>,
    /// List available presets
    #[arg(long)]
    list: bool,
}
```

Files: `clash/src/main.rs` (Commands enum, dispatch)

**T7: Preset expansion logic**

When the user runs `clash allow editing`:
1. Look up preset by name in the preset registry
2. For each rule in the preset, call the existing `edit::add_rule()` function
3. If all rules already exist (idempotent), say so
4. Write the updated policy to disk

Error handling:
- Unknown preset name → "Unknown preset 'X'. Run `clash allow --list` to see options."
- Policy file missing → "No policy found. Run `clash init` first."
- Policy file malformed → "Could not parse your policy. Run `clash policy show` to check it."

Every error message must be actionable. Never just say "error" — always say what to do.

Files: `clash/src/presets.rs`, `clash/src/main.rs`

**T8: Preset confirmation messages**

After applying a preset, print a confirmation that describes the OUTCOME:

```
clash allow editing:
  "Claude can now edit files in /Users/you/project.
   Files outside this directory are still protected."

clash allow commands:
  "Claude can now run commands in /Users/you/project.
   Commands can only access files in this directory."

clash allow web:
  "Claude can now search the web and fetch URLs."
```

Each confirmation:
- States what was ENABLED (positive framing)
- States what is still PROTECTED (safety reassurance)
- Uses absolute paths so the user knows exactly what scope means

Files: `clash/src/presets.rs`

**T9: `clash allow --list` command**

List available presets with short descriptions:

```
Available presets:
  editing    Allow Claude to edit files in this project
  commands   Allow Claude to run commands in this project
  web        Allow Claude to search the web and fetch URLs

Usage: clash allow <preset>
```

Files: `clash/src/presets.rs`, `clash/src/main.rs`

### WS3: Improved denial messages

**T10: Onboarding state store**

Clash needs to know basic facts about the user's history to adapt messaging:
- Is this a new user (just ran init, no rules added)?
- How many rules has the user added?
- How many denials has the user seen this session?

Storage options:
- **Session-level:** count denials in memory (already have session audit log).
  Parse the session audit file at `$TMPDIR/clash-<session-id>/audit.jsonl` to count
  denials so far.
- **Persistent:** store onboarding milestones in `~/.clash/state.json`:
  `{ "initialized_at": "...", "rules_added": 5, "presets_applied": ["editing"] }`

For v1, session-level denial counting (from audit log) + rule count (from policy
file) is sufficient. No need for a separate state file yet.

Files: `clash/src/permissions.rs`, `clash/src/audit.rs`

**T11: Terminal denial message format**

Replace the current verbose trace output with a 4-line format for denials:

```
clash: blocked <verb> on <summary>
  <one-sentence plain English explanation>
  To allow this: clash allow <preset>
  (run "clash allow --help" for more options)
```

The third line should suggest the most relevant preset, not raw rule syntax.
Mapping: edit/write denials → `clash allow editing`, bash denials → `clash allow commands`,
webfetch/websearch → `clash allow web`.

If no preset applies (rare edge case), fall back to the specific rule:
`clash policy add-rule "allow <verb> <noun>"`

Implementation: modify `ir.rs::render_human()` to produce this format when
the decision is a deny. Keep the current verbose trace for `--verbose` or
`/clash:explain`.

Files: `clash/src/policy/ir.rs`

**T12: Agent context format**

The `additional_context` field sent to Claude should be structured and directive:

```
clash: denied tool=<tool> input=<truncated>
reason: <reason-code> (default-deny | explicit-deny | constraint-fail)
user_state: <new | has-presets | experienced>
rule_count: <N>
session_denials: <N>

<Plain English: what happened and why>

Suggested action: clash allow <preset>
Agent instructions:
- Explain briefly that clash blocked this to protect the project
- Suggest the user run the command above
- Do NOT retry the tool call
- Do NOT suggest workarounds or alternative approaches
- If this is the user's first denial, be warm and reassuring
- If this is the 3rd+ denial, be brief and direct
```

This gives Claude everything it needs to be a good guide without inventing
its own explanation of clash internals.

Files: `clash/src/policy/ir.rs`, `clash/src/permissions.rs`

**T13: Adaptive messaging**

Denial messages should adapt based on context:

| Context | Terminal message | Agent instructions |
|---------|-----------------|-------------------|
| First denial ever | Full 4-line format | "Be warm, explain clash briefly" |
| 2nd-3rd denial | Full 4-line format | "Be concise, user knows the drill" |
| 4th+ denial | 3-line (drop help line) | "Be very brief, suggest `clash allow --list`" |
| After preset applied | Shouldn't fire for that category | If it does: "This may be a scope issue" |

Session denial count comes from the audit log (T10).
Whether presets have been applied comes from the policy file (check for preset-generated rules).

Files: `clash/src/permissions.rs`, `clash/src/policy/ir.rs`

### WS5: Testing

**T14: Unit tests for presets**
- Each preset expands to the correct rules
- Presets are idempotent (applying twice doesn't duplicate)
- Unknown preset names produce clear errors
- Preset confirmation messages are correct

Files: `clash/src/presets.rs`

**T15: Unit tests for denial messages**
- New format produces exactly 4 lines (or 3 for adaptive)
- Agent context includes all required fields
- Preset suggestions map correctly (edit denial → "clash allow editing")
- Verbose mode still shows full trace

Files: `clash/src/policy/ir.rs`, `clash/src/permissions.rs`

**T16: Clester e2e tests for init flow**
- `clash init` creates deny-all policy
- `clash init` sets bypass_permissions
- `clash allow editing` adds correct rules
- Deny-all policy blocks edit/bash/web tools
- After `clash allow editing`, edit tools pass

Files: `clester/tests/scripts/`

**T17: Manual walkthrough document**
- Step-by-step script for testing the full first-session experience
- Covers: init → start Claude → hit denial → apply preset → succeed
- Used for user testing, not automated testing

Files: `docs/` or `plans/`

## Needs validation

Things to experiment with and test with real users:

- [ ] **Frustration cliff:** How many denials can a user hit before they give up vs. engage? Is deny-all too aggressive for a first session, or does the trust payoff justify it?
- [ ] **Denial message format:** What level of detail is right? Too terse and users don't know what to do. Too verbose and they stop reading. What's the right balance for the human-readable vs agent-readable parts?
- [ ] **Phase 2 → Phase 3 transition:** When should clash suggest consolidating specific rules into broad+constrained ones? After 3 rules? 5? Based on pattern detection? Or only when the user asks?
- [ ] **Optional accelerator uptake:** Do users take the "unlock common tools now?" option during init, or do they skip it? If most people skip it, is the deny-all first session experience good enough on its own?
- [ ] **Agent guidance quality:** When Claude sees a denial and tries to help the user resolve it, does it give good advice? Does it explain the capability/constraint model well, or does it confuse things?
- [ ] **"allow bash *" comfort level:** How long does it take users to feel safe with broad allows? Is Phase 3 reachable in one session, or does it take multiple sessions of building trust?
- [ ] **Init explanation retention:** Does the one-sentence "deny blocks actions, allow grants access within boundaries" seed actually help when Phase 3 arrives, or is it forgotten immediately?
- [ ] **Sandbox-too-tight detection:** When sandboxed commands fail due to seatbelt enforcement (not policy denial), can users and Claude figure out that the sandbox is the cause? Or do they chase phantom bugs? Which feedback approach (transcript analysis, system log parsing, subprocess model) is worth the investment?

## Open questions and deferred decisions

Things Karthy Cantierra wanted to include but couldn't justify for v1:

### Preset revocation
There's no `clash revoke editing` or `clash deny editing` to undo a preset. If a user
regrets `clash allow commands`, their only option is manually editing the policy YAML or
running `clash policy remove-rule` for each rule the preset added. For v1 this is
acceptable — presets are intentionally safe (cwd-scoped), so regretting one is unlikely.
But for v2, presets should be reversible. Implementation note: presets could tag the rules
they add (e.g., with a YAML comment `# preset:editing`) so `clash revoke editing` knows
which rules to remove.

### Network sandboxing in presets
The `commands` preset allows `bash *` scoped to cwd filesystem, but doesn't address
network access. A sandboxed bash command can still make network calls (curl, wget, npm
install fetching packages). This is probably fine for v1 since the filesystem sandbox
is the primary safety mechanism, but some users may expect `commands` to also restrict
network. Worth revisiting when we have user feedback.

### Deny-all interaction with MCP tools — RESOLVED
MCP tools ARE covered. Unknown tools (including MCP) get `verb_str = tool_name.to_lowercase()`
via the `resolve_verb()` fallback and hit the default deny like everything else. The `*`
verb wildcard matches all verb strings including MCP tool names. No trust violation.

### The "retry after allow" flow
The walkthrough assumes the user runs `clash allow editing` in a separate terminal, then
returns to Claude and Claude retries the edit. But Claude Code may not automatically retry
a denied tool call. The agent context could instruct Claude to "try again after the user
has updated their policy" — but does Claude Code support this flow? If not, the user may
need to re-state their request, which adds friction. Need to test the actual Claude Code
behavior when a denied tool is later allowed mid-session.

### Denial messages for explicit deny rules vs default deny
The v1 terminal message format is designed for the "default deny" case (user hasn't
allowed this category yet). But once users add explicit deny rules (e.g., `deny bash
git push*`), the denial message should be different: "This action is blocked by a rule
you set" vs "This action isn't allowed yet." The current plan doesn't distinguish these
two cases. T11/T12 should handle both — the reason code (`default-deny` vs
`explicit-deny`) is available from the decision trace, but the terminal and agent
messages need different templates for each.

### Presets and the `--fs` scope resolution — RESOLVED
`subpath(.)` is stored as literal `.` in YAML and resolved at eval time using the current
cwd. This means the scope changes depending on where Claude is launched from.
**Decision:** Presets must resolve `.` to an absolute path at write time. `clash allow editing`
from `/Users/me/project` should write `subpath(/Users/me/project)`, not `subpath(.)`.
This is implemented in T7 (preset expansion logic).

### Session start messaging for deny-all users
The current session start handler (`handlers.rs:244-277`) reports policy status to Claude.
With deny-all, this message should tell Claude about the user's onboarding state so Claude
can proactively mention it: "I notice your clash policy is very restrictive — if I can't
do something, I'll let you know how to unlock it." This isn't in the current task list.
Could be added to T12 (agent context format) or as a separate change to `handle_session_start`.