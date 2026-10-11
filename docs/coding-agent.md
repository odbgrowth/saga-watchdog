# Coding-agent guide

[Back to the overview](../README.md)

Use this mode to start a command under SAGA in a Git project. Follow the
[quick start](../README.md#quick-start) first. The child starts
in the Git project root, even when SAGA is invoked from a subdirectory. Relative
file targets in `check` and `emit` are also relative to that root.

This guide is generic: everything here applies to any CLI agent. Agents that
expose structured pre-action events add a deep integration on top:
[Claude Code](claude-code.md), [Codex CLI](codex.md) and
[Gemini CLI](gemini-cli.md).

## How it works

```text
project policy (loaded once)
              |
              v
    SAGA Watchdog process
    + deterministic rules
    + escalation counters
    + filesystem observer
    + local integration socket
    + local JSONL event log
              |
       starts and signals
              |
              v
       agent process group
        Codex / Claude / CLI
```

The agent is the reasoning plane. Project policy is the control plane. The
supervisor applies that policy to the events it can see. On supported Unix
systems it signals its own process group, first gracefully, then forcibly after
the configured grace period.

### Generic supervision

Works for any CLI agent you can start as a command: Claude Code, Codex, a
local agent, a shell. SAGA owns the process group, enforces the runtime
budget, observes the filesystem and the Git branch, and accepts `check` and
`emit` requests from cooperating tools. Nothing inside the agent is
instrumented; SAGA sees effects, not tool calls.

### Deep integrations

Some agents expose structured events before a tool call executes. A thin
adapter maps those events onto the same canonical event types and the same
socket, so the policy engine can refuse a supported action before it happens.
The adapter contains no rules of its own. Claude Code, Codex CLI and Gemini
CLI have such adapters; see the [Claude Code guide](claude-code.md), the
[Codex guide](codex.md) and the [Gemini CLI guide](gemini-cli.md). They are
optional and do not change how generic supervision works.

## Example: a protected write

In a disposable project, run a shell under Watchdog and modify a normal file:

```sh
saga-watchdog run -- bash
set +m # Keep demo shell jobs in the supervised process group.
printf 'hello\n' > normal.txt
```

A normal write is recorded without intervention. A write to
`.saga-watchdog.yaml` is policy tampering: the loaded policy stays unchanged and
enforce mode stops the run with the exact rule and reason. The write has already
happened; Watchdog does not revert it.

See the [acceptance demo](../examples/DEMO.md) for repeatable protected-write and
escalation scenarios.

## Commands

| Command | Purpose |
| --- | --- |
| `init` | Create an inspectable project configuration. |
| `validate` | Validate the project configuration. |
| `doctor` | Check project, configuration, state storage and OS capabilities. |
| `run -- <command> [args...]` | Start and supervise an agent. |
| `status [--run ID]` | Inspect the latest project run or a selected run. |
| `events [--run ID]` | Read the latest project's structured event log or a selected run. |
| `pause <run-id>` | Suspend an owned run's process group. |
| `resume <run-id>` | Explicitly resume a paused run and record the request. |
| `kill <run-id>` | Stop an owned run with graceful/forced termination. |
| `check` | Ask the running supervisor for a pre-action decision. |
| `emit` | Submit a post-action observation to the running supervisor. |
| `version` | Print the binary version. |

`check` and `emit` also accept `--run ID` to address a project run explicitly.
Control commands take the run ID positionally; flags belong to their command,
not before the command name. Coding-agent commands load `.saga-watchdog.yaml`
from the Git project root; Docker mode has its own `--config` option.

Exit codes: `0` means success, `2` means a configuration, command or integration error, `3` means a
denied check, and `125` means a watchdog stop, timeout or run-time failure.
An ordinary supervised exit returns the child's exit code. A child can itself
return these numbers, so inspect the summary when distinguishing causes.

Controls target Watchdog runs, not arbitrary system PIDs. Another terminal can
inspect a paused run and explicitly resume or kill it. Watchdog never
automatically resumes a paused run.

If Git metadata is deleted or corrupt, run controls and history commands from
the original project root. The inherited socket still lets `check` and `emit`
reach their supervisor when Git inspection is unavailable.

## Configuration

The smallest configuration loads the default coding-agent profile:

```yaml
version: 1
profile: coding-agent
mode: enforce
```

The schema is deliberately small and strict: unknown keys and invalid values are
errors. Inspect [examples/minimal.yaml](../examples/minimal.yaml) and
[examples/coding-agent.yaml](../examples/coding-agent.yaml) for supported settings.

Selected overrides look like this:

```yaml
version: 1
profile: coding-agent
mode: enforce
project:
  name: my-project
run:
  max_duration: 2h
  stop_grace_period: 5s
  unattended: false
git:
  protected_branches: [main, master]
  allow_protected: false
filesystem:
  delete_threshold: 100
  delete_window: 10s
escalation:
  window: 120s
  warn_after: 2
  pause_after: 3
  kill_after: 5
network:
  deny: [blocked.example.com]
tools:
  deny: [github/delete_repository, 'payments/*']
```

`network.deny` is an optional exact-hostname deny list, empty by default. Hostnames
are normalized from host or URL targets. It governs integration checks only;
there is no OS network enforcement and no default allow list. Other hosts are
allowed unless another rule, such as escalation, intervenes.

`tools.deny` is an optional deny list for cooperative `tool` events by their
canonical identifier: MCP tools as `server/tool`, other tools by name. Entries
are path-style globs, so `payments/*` denies every tool of one MCP server and
`*/drop_*` denies a tool name on any server. A match pauses the run
(`tool-denied`) and denies the check. Like `network.deny` it governs reported
events only; nothing is intercepted at the OS level.

The default profile includes:

| Setting | Default behavior |
| --- | --- |
| Protected branches | Refuse startup on `main` and `master`. |
| Policy file | Treat changes during a run as critical tampering (`policy-tamper`, kill). |
| Integration settings | When a deep integration is active, treat changes to the settings file that carries its blocking hook as tampering (`hook-tamper`, kill) and pause for changes to any sibling agent configuration file (`agent-config-modification`). |
| Git security files | Protect `.git/config`, `.git/hooks/**` and linked-worktree `.git` pointers. |
| CI workflows | Pause for changes under `.github/workflows/**`. |
| Secret-like files | Pause for writes to `.env`, `.env.*`, `credentials*`, `secrets*`, `*.pem` and `*.key` at any depth. |
| Generated trees | Ignore common dependency/build directories. |
| Deletion bursts | Pause after more than 100 distinct delete/rename paths in 10 seconds. |
| Run lifetime | Stop after 2 hours by default, with 5 seconds of termination grace. |
| Escalation | Count related events in a bounded sliding window. |

`filesystem.protect` and `filesystem.ignore` accept path patterns; supplying a
list replaces that profile list. Policy, Git security and CI paths remain
protected even when a broad ignore would match these mandatory paths. The
default ignores skip dependency/build trees and `.git/objects`. Deletion
detection counts distinct observed paths, including renames; it cannot prove
how many files were actually deleted.

Exact protected paths and their concrete ancestor prefixes remain watched.
A custom glob such as `generated/secure*/config.yml` can still lose filesystem
coverage when `generated/**` is ignored: the observer may prune an ancestor
before discovering the matching file. Remove or narrow overlapping ignores
when independent observation is required. Integration checks/reports still
evaluate matching protected paths inside an ignored tree.

Relative paths are resolved against the project, normalized, and checked for
containment. Protection rules check both the named path and its resolved target. This is policy matching, not a race-free OS file authorization
mechanism. Symlink targets outside the watched tree are not recursively watched.

## Observe and enforce

`mode: observe` records violations and their proposed decisions without applying
policy-driven pause or kill. Integration checks return `allowed: true` in this
mode, while preserving the policy's proposed action in their response and log.
Terminal messages use `WATCHDOG OBSERVE` and say which action would have been
taken. Use this mode to understand a project's normal activity before enabling
enforcement.

`mode: enforce` applies the rule's warning, pause or kill action. Administrative
stop requests, process cleanup, run-time errors and the configured maximum run
duration still apply. The maximum duration is an explicit run budget, including
in observe mode. Changing
the YAML on disk does not switch an active run's mode; start a new run to load a
new policy.

`run.unattended: true` is for runs nobody is watching, such as `claude -p` in
a script or CI. A pause then records the decision and marks the run paused,
but does not stop the process group: there is no operator to resume it, and a
stopped process would simply wait until the run budget kills it. Enforcement
continues through the pre-action path instead: every later `check` is denied
with `run-paused` until an explicit `resume`, so a hooked agent cannot act and
ends on its own. Kill decisions and the run budget are unchanged. An explicit
`saga-watchdog pause` still stops the process group, and `resume` continues
it. Without a preventive hook a pause cannot restrain the agent in this mode;
SAGA warns at startup.

## Escalation detection

The detector uses event sequences and a sliding time window, not a risk score or
a guess at the agent's motives. Repeated denials, attempts at alternate targets,
and credential/tool requests following a denial contribute to the documented
thresholds. Counters expire with the window.

The detector counts explicit denied/blocked results and policy-denied actions.
After a denial, credential/tool attempts and related network/Git attempts can
also contribute. Such a follow-up counts once per distinct target within the
window: repeating the same allowed tool or host is ordinary work, a different
one is an alternative target. A repeated denial always counts. Unrelated
normal events do not justify a claim about intent.

A single reported denial is logged. Under the default thresholds, the second
related event warns, the third pauses, and the fifth kills. Strong policy-tamper
rules can stop a run immediately. Each decision includes a stable rule ID and a
plain-language reason.

Events are only as complete as the sources providing them. Core mode cannot
notice unreported network or credential attempts.

## Running Codex

```sh
saga-watchdog run -- codex
```

Watchdog does not change Codex's approvals or sandbox settings. Keep those
controls enabled as appropriate. Starting an existing CLI under Watchdog enables
filesystem observation and process supervision; it does not automatically
instrument that CLI's internal tools or network requests.

## Running Claude Code, Codex CLI or Gemini CLI

```sh
saga-watchdog run -- claude
saga-watchdog run -- codex
saga-watchdog run -- gemini
```

Without further setup the same generic boundary applies: the agent's own
permissions remain separate and SAGA sees effects, not tool calls. Install
the optional hook with `saga-watchdog claude|codex|gemini setup` to have file
edits, shell commands, web fetches and MCP tool calls checked by this policy
before they execute. The [Claude Code guide](claude-code.md), the
[Codex guide](codex.md) and the [Gemini CLI guide](gemini-cli.md) document
each hook contract, tool mapping and fail-closed scope. When a hook is
configured, the file that carries it (`.claude/settings.json`,
`.codex/hooks.json`, `.gemini/settings.json`) is protected for the run like
the policy file (rule `hook-tamper`, kill), and a change to a sibling agent
configuration file pauses the run (`agent-config-modification`). Only a hook
that can block counts as active: a disabled, background or post-action-only
entry protects nothing, is not treated as a control, and is reported by
`saga-watchdog <agent> doctor`.

## What Watchdog can see

| Source | Evidence | Boundary |
| --- | --- | --- |
| Process supervisor | Child exit, elapsed time and its own pause/kill actions | Signals cover the owned process group. |
| Filesystem observer | Covered create/write/rename/delete notifications | After the change; no reliable attribution to a process. |
| Git awareness | Startup repository/branch/dirty state/remote names, plus periodic branch checks | Does not turn Git into a transaction guard. |
| Integration socket | Structured actions reported by a wrapper or tool | Producer reports are not independent OS evidence. |
| Deep integration (agent hook) | Supported tool calls before execution, with tool and agent identifiers | Only tools that pass through the hook; still a producer report. |

A change from your editor can trigger the same rule as an agent change.
Filesystem notifications can be coalesced or lost, and ignored directories have
no core change coverage.

## What Watchdog cannot see

Core mode does not intercept syscalls, raw network connections, file reads,
credential lookups, container activity or every descendant process. It has no
Falco, Tetragon, eBPF, kernel firewall, sandbox or EDR component. It does not inspect
prompts, source contents or chain-of-thought.

An allowed preflight check does not prove the later action used the same target,
nor does it force an uncooperative tool to ask first. Future privileged or
brokered adapters can extend evidence coverage; they are not implemented.

## Security model

Process separation is useful, but the same OS user can often signal the
supervisor, modify its disk files, reach its socket or alter its logs. The
immutable in-memory policy is not a hardened privilege boundary.

Local operator controls cannot authenticate that their caller is a human.
A same-user process can potentially request resume or kill. Resume records an
audit event and keeps the original policy; it is not an authority grant.

Process-group termination covers descendants that stay in the group.
A descendant that creates a new session/group, launches a remote job or delegates
to another service may escape it. Interactive shell job control can also place
commands into separate process groups; the demo disables it with `set +m`.
Watchdog is not proof of containment. A forcibly killed or crashed supervisor
cannot deliver stop signals; child processes may continue running. Handled
interrupts and ordinary run errors trigger cleanup, but SIGKILL cannot be caught.

Use least-privilege credentials and OS isolation for stronger boundaries.
Read [SECURITY.md](../SECURITY.md) for disclosure guidance and the full scope.

## Events and local storage

Each run stores `run.json`, `events.jsonl` and `summary.json` under:

- Linux: `$XDG_STATE_HOME/saga-watchdog`, or `~/.local/state/saga-watchdog`.
- macOS: `~/Library/Application Support/saga-watchdog`.
- Override: `SAGA_WATCHDOG_STATE_DIR` selects the state root explicitly.

The state root must be outside the watched project to avoid audit-log feedback.

Within that root, a hash of the project path and the unique run ID identify the
run directory. Watchdog streams JSON Lines rather than keeping an event database.
Run metadata records the loaded configuration-file hash; the final summary shows
the stop reason, counters and run exit code. The process-exit event records the
child's exit code separately.

An event has a small canonical shape:

```json
{
  "id": "event-id",
  "timestamp": "2026-09-29T10:00:00Z",
  "project_id": "project-id",
  "run_id": "run-id",
  "source": "filesystem",
  "type": "file",
  "action": "write",
  "target": ".github/workflows/deploy.yml",
  "result": "observed",
  "severity": "high",
  "rule_id": "ci-workflow-modification"
}
```

Optional `metadata` contains a small allowlist of diagnostic fields; arbitrary
producer metadata and complex values are discarded. Every event carries
`decision`, `reason` and `mode`. Integration events may add bounded lineage
identifiers supplied by the producer: `producer`, `tool_name`, `agent_id`,
`agent_type`, `tool_use_id` and `session_id`. They support correlation and
never influence a decision. Do not use metadata to transport application
payloads or secrets.

Integration file targets that arrive as absolute paths inside the project are
evaluated as submitted and recorded by their project-relative name. The run
record (`run.json`) lists the settings files protected for an active deep
integration under `controls`.

Logs are local and append-only from Watchdog's perspective. They are not
tamper-proof against the OS user. Metadata is conservatively redacted; producers
must send identifiers rather than raw secrets. The child's terminal output is
not captured or redacted by Watchdog.

No analytics, usage tracking, cloud uploads, prompt collection or source-code
uploads are enabled by the core.

## Reviewing a run with report

`saga-watchdog report [--run ID] [--json]` summarizes one run from its
recorded state and audit log: status and how it ended, counts of checks,
reports and observed changes, decisions by rule, every call denied before
execution, pre-action coverage per producer, and a timeline of policy pauses,
kills and operator controls. It is a reading of the audit trail, not new
evidence.

```text
SAGA Watchdog report
Run       run_1791750152041_1b29a4be64890a2c0a5a716e3c7a3c89
Status    killed by watchdog
Hooks     .claude/settings.json
Ended by  human-stop: explicit control request

Counts    events 7; checks 2 (allowed 1, denied 1); reports 1; observed changes 0; warnings 0; pauses 1; kills 1

Decisions by rule
  network-denied               pause     1  last: blocked.example

Pre-action coverage
  codex                checks    2  reports    0

WARNING   .claude/settings.json carried the Claude Code hook but no pre-action check arrived from it; ...
```

The warning is the one gap the audit trail can show for a preventive hook:
the file carried it, but the agent never asked. Typical causes are a hook the
agent has not trusted yet, a disabled hook, or `saga-watchdog` missing from
the agent's PATH. `--json` prints the same aggregates for scripts.

## Integrating tools with check and emit

The child inherits `SAGA_WATCHDOG_RUN_ID` and `SAGA_WATCHDOG_SOCKET`. The latter
points to a local Unix-domain socket. A wrapper should ask before an action and
honor the returned exit status:

```sh
if saga-watchdog check --type network --action connect --target api.example.com; then
  # Perform only the checked action here.
  :
else
  # Stop and report the blocker; do not seek a new route or credential.
  exit 1
fi
```

Send post-action observations separately. An `emit` request requires an explicit
observed result: `allowed`, `denied`, `blocked`, `failed`, or `success`.

```sh
saga-watchdog emit --type network --action connect \
  --target blocked-a.example --result denied
```

A socket client sends one JSON request per connection, followed by a newline:

```json
{"operation":"check","event":{"type":"network","action":"connect","target":"api.example.com"}}
{"operation":"emit","event":{"type":"network","action":"connect","target":"blocked-a.example","result":"denied"}}
```

A response contains `allowed` and the policy `decision`; protocol errors include
an `error` string. For example, an enforced protected-path decision has this shape:

```json
{"allowed":false,"decision":{"action":"pause","rule_id":"rule-id","reason":"human-readable reason","severity":"high"}}
```

In enforce mode, a pause/kill decision denies a check (exit `3`); allow/warn
continues (exit `0`). Observe mode returns `allowed: true` (exit `0`) even when
the decision records a proposed pause/kill. Transport/protocol failures remain
errors. Use `allowed` or the CLI exit status to decide whether to proceed.

An event may also carry optional bounded identifiers, each at most 128
printable ASCII bytes without spaces: `producer`, `tool`, `agent_id`,
`agent_type`, `call_id` and `session_id`. They are recorded as metadata for
correlation only. Any other field is rejected.

These are two independent example connections, not a policy update protocol.
The supervisor assigns decisions and severity. Clients cannot supply policy
overrides, thresholds, rule decisions, free-form metadata, timestamps or
trusted event sources. Requests may include `run_id`; lifecycle controls use a separate local
control socket. Both endpoints are recorded in the private run manifest.

Network checks only evaluate the configured policy; they do not establish a
connection or install a firewall. An integration must fail closed when a check
cannot reach the supervisor. Never pass passwords, bearer tokens, cookies,
authorization headers, prompts or file contents as targets or metadata.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Startup refuses `main`/`master` | Create a work branch, or explicitly adjust the reviewed project policy before starting. |
| Configuration is invalid | Run `validate`; remove unknown keys and use the examples. |
| Run pauses during an edit | Inspect `events` and the printed rule; resume explicitly only after reviewing the change. |
| `check`/`emit` cannot connect | Run from the supervised process environment and confirm the run is still active. |
| Normal generated files create noise | Review the ignore configuration before the next run. |
| Expected event is absent | Check coverage, ignored paths and watcher errors; core mode does not see file reads or raw network activity. |
| State storage is not writable | Run `doctor` and correct the indicated directory permissions. |
| Windows supervision fails | Run a Linux build in WSL; native Windows is not supported. |
