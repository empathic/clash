# clester

End-to-end testing tool for clash. Simulates Claude Code hook invocations and CLI commands against the clash binary, then asserts on the results.

## Quick Start

```bash
just clester          # run all e2e tests
just clester -v       # verbose (show stdout/stderr)
just ci               # full CI (unit tests + clippy + e2e)
```

## Writing Tests

Test scripts are YAML files in `clester/tests/scripts/`. Each script defines an isolated test environment (policy, settings), a sequence of steps (hook invocations or CLI commands), and expected outcomes.

### Minimal Example

```yaml
meta:
  name: git commands are allowed

clash:
  policy_sexpr: |
    (default deny "main")
    (policy "main"
      (allow (exec "git" *)))

steps:
  - name: git status is allowed
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: git status
    expect:
      decision: allow

  - name: npm is denied
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: npm install
    expect:
      decision: deny
```

## Script Format

### `meta`

Required. Test metadata.

```yaml
meta:
  name: human-readable test name    # required
  description: optional details     # optional
```

### `clash`

Optional. Configures the clash policy for the test. Use `policy_sexpr` for s-expression policies (current format).

```yaml
clash:
  policy_sexpr: |
    (default deny "main")
    (policy "main"
      (allow (exec "git" *))
      (deny (exec "git" "push" *))
      (allow (fs read (subpath "/tmp")))
      (allow (net "github.com")))
```

### `settings`

Optional. Configures Claude Code settings files at user, project, and project-local levels.

```yaml
settings:
  user:                        # ~/.claude/settings.json
    permissions:
      allow: ["Bash(git:*)"]
      deny: ["Read(.env)"]
  project:                     # .claude/settings.json
    permissions:
      deny: ["Bash(rm:*)"]
  project_local:               # .claude/settings.local.json
    permissions:
      allow: ["Bash(npm:*)"]
```

### `steps`

Required. An ordered list of steps. Each step is either a **hook step** (simulates a Claude Code hook invocation) or a **command step** (runs a clash CLI command). Every step must have exactly one of `hook` or `command`.

## Step Types

### Hook Steps

Simulate Claude Code calling clash via hooks. Use these to test policy evaluation — whether a given tool invocation would be allowed, denied, or asked.

```yaml
- name: descriptive step name
  hook: pre-tool-use              # hook type (see below)
  tool_name: Bash                 # Claude Code tool name
  tool_input:                     # tool-specific input
    command: git status
  expect:
    decision: allow               # expected policy decision
```

**Hook types:**

| Hook | Purpose |
|------|---------|
| `pre-tool-use` | Evaluate policy before a tool runs (returns allow/deny/ask) |
| `post-tool-use` | Notify after a tool runs (informational, no decision) |
| `permission-request` | Handle a permission prompt (returns allow/deny/ask) |
| `notification` | Handle a notification event (informational) |

**Tool names and inputs:**

```yaml
# Bash — command execution
tool_name: Bash
tool_input:
  command: git status

# Read — file reading
tool_name: Read
tool_input:
  file_path: /etc/passwd

# Write — file writing
tool_name: Write
tool_input:
  file_path: /tmp/output.txt
  content: hello world

# Edit — file editing
tool_name: Edit
tool_input:
  file_path: /tmp/file.txt
  old_string: foo
  new_string: bar

# WebFetch — HTTP requests
tool_name: WebFetch
tool_input:
  url: "https://github.com"

# WebSearch — web search
tool_name: WebSearch
tool_input:
  query: "test query"
```

### Command Steps

Run clash CLI commands directly. Use these to test interactive policy modification — adding, removing, or inspecting rules mid-test.

```yaml
- name: add an allow rule
  command: policy allow '(exec "npm" *)'
  expect:
    exit_code: 0
```

The `command` value is the arguments to `clash` (not including `clash` itself). It's parsed with shell-style quoting, so single quotes work for s-expressions.

**Common commands:**

```yaml
# Add rules
command: policy allow '(exec "npm" *)'
command: policy deny '(exec "git" "push" *)'
command: policy allow '(fs read (subpath "/tmp"))'

# Remove rules
command: policy remove '(allow (exec "npm" *))'

# Preview without persisting
command: policy allow '(exec "npm" *)' --dry-run

# Inspect the policy
command: policy list
command: policy explain bash "git push"
command: status
```

## Assertions

Every step has an `expect` block. All fields are optional — only specified fields are checked.

```yaml
expect:
  decision: allow           # expected policy decision: "allow", "deny", or "ask"
  exit_code: 0              # expected process exit code (default: not checked)
  no_decision: true         # expect no hook-specific output (for post-tool-use/notification)
  reason_contains: "policy" # substring match on the decision reason
  stdout_contains: "(allow" # substring match on stdout
  stderr_contains: "warning" # substring match on stderr
```

| Field | Use with | Purpose |
|-------|----------|---------|
| `decision` | hook steps | Check the policy decision (allow/deny/ask) |
| `exit_code` | both | Check the process exit code |
| `no_decision` | hook steps | Verify no decision was returned (informational hooks) |
| `reason_contains` | hook steps | Substring match on the decision reason |
| `stdout_contains` | command steps | Substring match on stdout |
| `stderr_contains` | command steps | Substring match on stderr |

## Patterns

### Testing static policies

Set up a policy and verify tool invocations are evaluated correctly:

```yaml
clash:
  policy_sexpr: |
    (default deny "main")
    (policy "main"
      (allow (exec "git" *))
      (deny (fs read "/etc/passwd")))

steps:
  - name: git is allowed
    hook: pre-tool-use
    tool_name: Bash
    tool_input: { command: git status }
    expect: { decision: allow }

  - name: reading /etc/passwd is denied
    hook: pre-tool-use
    tool_name: Read
    tool_input: { file_path: "/etc/passwd" }
    expect: { decision: deny }
```

### Testing interactive policy changes

Modify the policy mid-test and verify the changes take effect:

```yaml
clash:
  policy_sexpr: |
    (default deny "main")
    (policy "main"
      (allow (exec "git" *)))

steps:
  # Baseline
  - name: npm is denied
    hook: pre-tool-use
    tool_name: Bash
    tool_input: { command: npm install }
    expect: { decision: deny }

  # Modify policy
  - name: allow npm
    command: policy allow '(exec "npm" *)'
    expect: { exit_code: 0 }

  # Verify change took effect
  - name: npm is now allowed
    hook: pre-tool-use
    tool_name: Bash
    tool_input: { command: npm install }
    expect: { decision: allow }
```

### Testing dry-run (no side effects)

Verify that `--dry-run` previews changes without persisting them:

```yaml
steps:
  - name: dry-run shows the new rule
    command: policy allow '(exec "npm" *)' --dry-run
    expect:
      exit_code: 0
      stdout_contains: "(allow (exec \"npm\" *))"

  - name: npm is still denied (dry-run didn't persist)
    hook: pre-tool-use
    tool_name: Bash
    tool_input: { command: npm install }
    expect: { decision: deny }
```

### Testing deny overrides allow

Verify that deny rules take precedence:

```yaml
clash:
  policy_sexpr: |
    (default deny "main")
    (policy "main"
      (allow (exec "git" *)))

steps:
  - name: git push is allowed (baseline)
    hook: pre-tool-use
    tool_name: Bash
    tool_input: { command: git push origin main }
    expect: { decision: allow }

  - name: deny git push
    command: policy deny '(exec "git" "push" *)'
    expect: { exit_code: 0 }

  - name: git push is now denied
    hook: pre-tool-use
    tool_name: Bash
    tool_input: { command: git push origin main }
    expect: { decision: deny }

  - name: git status is still allowed
    hook: pre-tool-use
    tool_name: Bash
    tool_input: { command: git status }
    expect: { decision: allow }
```

## How It Works

Each test script runs in an isolated environment:

```
/tmp/clester-XXXXX/
├── home/                  <- $HOME for the test
│   ├── .claude/
│   │   └── settings.json  <- from settings.user
│   └── .clash/
│       └── policy.sexpr   <- from clash.policy_sexpr
└── project/               <- cwd for the test
    ├── .claude/
    │   ├── settings.json  <- from settings.project
    │   └── settings.local.json
    └── .git/              <- so clash finds the project root
```

- `HOME` is set to the temp `home/` directory, so clash reads/writes `$HOME/.clash/policy.sexpr` in isolation.
- `CLASH_CONFIG` and `CLASH_POLICY_FILE` are removed to prevent system config from leaking in.
- Command steps that modify the policy (e.g., `policy allow`) write to the same `policy.sexpr` file that subsequent hook steps read from — this is how interactive policy changes are tested.
- The temp directory is cleaned up when the test finishes.

## Running

```bash
# Run all tests
just clester

# Run a single test
./target/debug/clester run clester/tests/scripts/v2_basic.yaml

# Run with verbose output
just clester -v

# Validate scripts without executing
./target/debug/clester validate clester/tests/scripts/
```
