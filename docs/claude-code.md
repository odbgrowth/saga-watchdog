# Claude Code guide

[Back to the overview](../README.md) · [Coding-agent guide](coding-agent.md) · [Demo](../examples/claude-code.md)

## 1. Purpose

Claude Code exposes structured hook events before and after each tool call.
SAGA uses them to evaluate supported actions **before they execute**, with the
same policy engine, path rules and audit log that supervise every other CLI
agent. A protected write such as `.env` is refused before the file changes
instead of being noticed afterwards.

The integration is optional. Without it, `saga-watchdog run -- claude` still
provides process supervision and post-action observation, exactly like Codex
or any other command.

## 2. Architecture

```text
Claude Code proposes a tool call
        |
        v
PreToolUse hook  -->  saga-watchdog claude hook   (thin adapter, no rules)
                              |
                              v
                 SAGA_WATCHDOG_SOCKET  (existing local Unix socket)
                              |
                              v
                 supervisor + policy engine        (the only decision maker)
                              |
                    allow / warn / pause / kill
                              |
                              v
                 exit 0 = Claude continues its normal permission flow
                 exit 2 = tool call blocked, reason shown to Claude
```

Independently of that path, the supervisor keeps observing the filesystem,
the Git branch and the process after each action. The adapter contains no
policy of its own: there is no Claude-specific rule set, risk score or
allowlist. The same `.saga-watchdog.yaml` governs Claude, Codex, the
filesystem observer and the generic `check` command.

## 3. Prerequisites

- Linux or macOS, Git, Go 1.26 or newer, `saga-watchdog` on `PATH`.
- Claude Code **2.1.295 or newer**. That release added `onFailure: "block"`,
  which lets Claude Code itself block a tool call when the hook is missing,
  crashes or times out. On older versions the adapter still fails closed for
  every case it controls, but Claude Code treats a hook crash or timeout as
  non-blocking.
- A project with a reviewed `.saga-watchdog.yaml` (`saga-watchdog init`).

Run `saga-watchdog claude doctor` to check all of this.

## 4. Claude Code hook contract SAGA relies on

Verified against the official hooks reference and Claude Code 2.1.296 on
2026-10-10. Re-check the reference after upgrading Claude Code.

| Contract | What SAGA uses |
| --- | --- |
| Events | `PreToolUse` (check), `PostToolUse` and `PostToolUseFailure` (report), `ConfigChange` (settings tampering). |
| Input | JSON on stdin with `hook_event_name`, `session_id`, `cwd`, `tool_name`, `tool_input`, `tool_use_id`; `agent_id` and `agent_type` only inside subagents; `source` and `file_path` on `ConfigChange`. `file_path` is optional in the contract; SAGA refuses a `ConfigChange` without it instead of guessing a path from the hook's working directory. |
| Fields read from `tool_input` | `file_path` (Write, Edit, MultiEdit), `notebook_path` (NotebookEdit), `url` (WebFetch). Nothing else is read. File paths arrive absolute. |
| Blocking | Exit code 2 blocks a `PreToolUse` tool call or a `ConfigChange`; stderr is shown to Claude. Exit 0 with no output leaves the call to Claude's normal permission flow. Exit 2 wins even if another hook answers `allow`. |
| Failure default | A hook that times out, crashes or prints malformed JSON is non-blocking unless the hook sets `onFailure: "block"`. SAGA sets it on `PreToolUse` and `ConfigChange`. |
| Matchers | A plain `A\|B` list matches tool names exactly; `mcp__.*` is a regex for every MCP tool (`mcp__<server>__<tool>`). |
| Settings files | `.claude/settings.json` (project, shareable), `.claude/settings.local.json` (project, gitignored), `~/.claude/settings.json` (user). Edits to these files are picked up live during a session. |
| Permission modes | `PreToolUse` hooks run in every permission mode, including `bypassPermissions`. |
| Trust | Hooks from settings files run only after the workspace trust dialog is accepted; `claude -p` trusts the folder automatically. `disableAllHooks` in a settings file turns hooks off. |

SAGA never emits `permissionDecision: "allow"`. It can tighten Claude's
behaviour, never loosen it.

## 5. Installation

```sh
go install github.com/odbgrowth/saga-watchdog/cmd/saga-watchdog@main
export PATH="$(go env GOPATH)/bin:$PATH"
cd /path/to/your/project
git switch -c agent/my-task
saga-watchdog init
saga-watchdog doctor
```

## 6. Hook setup

Project-local configuration is the default. `setup` merges the SAGA hooks
into `.claude/settings.json`; existing keys, permissions and hooks are kept,
and a second run changes nothing.

```sh
saga-watchdog claude setup            # .claude/settings.json, shareable
saga-watchdog claude setup --local    # .claude/settings.local.json, gitignored
saga-watchdog claude doctor
```

To inspect the configuration first, or to install it by hand:

```sh
saga-watchdog claude config
```

This prints four hook groups, each running `saga-watchdog claude hook` with a
10 second timeout:

| Event | Matcher | `onFailure` |
| --- | --- | --- |
| `PreToolUse` | `Write\|Edit\|MultiEdit\|NotebookEdit\|Bash\|WebFetch\|mcp__.*` | `block` |
| `PostToolUse` | same | not applicable (cannot block) |
| `PostToolUseFailure` | same | not applicable |
| `ConfigChange` | `project_settings\|local_settings` | `block` |

`setup` refuses to touch a settings file that is not a JSON object (including
`null`), is a symlink, sits in a symlinked `.claude` directory, or has a
`hooks` value that is not an object. Fix those by hand and run it again.
User-level `~/.claude/settings.json` is never modified. `doctor` counts the
hook as preventive only when it is a synchronous command hook with the
expected matcher and `onFailure: "block"`; a background (`async`) hook cannot
block and is reported as not preventive.

Prefer the project file. Claude Code saves "always allow" permission rules
to `.claude/settings.local.json` during a session. With the hook in the
project file that save pauses the run for review; with `--local` it rewrites
the file that carries the hook and stops the run as tampering. Choose those
rules before starting a supervised run, or accept the pause.

Open `/hooks` inside Claude Code to confirm the entries are loaded.

## 7. Starting Claude under SAGA

```sh
saga-watchdog run -- claude
```

The startup banner shows `Hooks    claude-code via .claude/settings.json`
when the integration is detected. The supervised child receives
`SAGA_WATCHDOG_SOCKET` and `SAGA_WATCHDOG_RUN_ID`; the hook uses both and
rejects any other run.

Starting `claude` **without** `saga-watchdog run` while the hook is installed
blocks every matched tool call, by design (see section 13).

## 8. Pre-action control

Each matched tool call becomes one `check` request. The supervisor evaluates
it, records an audit event and answers:

| Policy decision | Claude Code outcome |
| --- | --- |
| `allow` | Tool call continues through Claude's own permission flow. |
| `warn` | Tool call continues; a warning is shown to the operator. |
| `pause` | Tool call blocked; the run's process group is paused until an operator runs `saga-watchdog resume <run-id>` or `kill <run-id>`. Further checks are denied while paused. |
| `kill` | Tool call blocked; the supervisor terminates the run. |

A blocked call shows Claude an actionable message:

```text
SAGA blocked this tool call
Rule: protected-path
Target: /path/to/project/.env
Reason: protected project path changed
Run run_... is paused until an operator inspects it: saga-watchdog status; saga-watchdog resume run_...
```

A pause stops the whole process group, including Claude and the hook that
is still answering. The denial is delivered when the operator resumes, and
the tool call stays blocked. SAGA never resumes a run on its own.

## 9. Post-action reporting

`PostToolUse` and `PostToolUseFailure` send an `emit` with `result: success`
or `result: failed`. These events are audit only: they correlate with the
earlier check through `tool_use_id`, and a `failed` result does not count as
a denial. Pre-action enforcement never depends on them.

## 10. Tool mapping

| Claude tool | SAGA event | Target | Notes |
| --- | --- | --- | --- |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | `file` / `write` | the path | Evaluated by the existing path engine: protected paths, policy and hook settings, Git and CI controls, traversal, symlinks, project-root escapes. Contents are never read. |
| `WebFetch` | `network` / `connect` | lowercase hostname | `network.deny` applies. Userinfo, path, query and fragment are discarded. |
| `Bash` | `process` / `execute` | `Bash` | The command text is never read. SAGA is not a shell interpreter; effects are seen by the filesystem observer afterwards. |
| `mcp__<server>__<tool>` | `tool` / `call` | `server/tool` | Arguments are discarded. |
| Any other matched tool | `tool` / `call` | tool name | Bounded identifier only; no capability is inferred from the name. |
| `ConfigChange` (project or local settings) | `file` / `write` | the settings file | Kill (`hook-tamper`) when that file carries the SAGA hook, like editing `.saga-watchdog.yaml`. Pause (`agent-config-modification`) for the sibling settings file, which can disable or loosen the hook; this includes Claude's own "always allow" save to `.claude/settings.local.json`. Exit 2 keeps the change from being applied. |

Tools outside the matcher (`Read`, `Glob`, `Grep`, `WebSearch`, `Agent`,
`AskUserQuestion`, ...) never reach SAGA. File reads are not monitored.

Escalation note: after a denial, a `tool` event with a target not yet seen in
the window counts as a related follow-up (second related event warns, third
pauses, fifth kills by default). `process` events for Bash do not. Adjust
`escalation` thresholds in the policy if MCP-heavy sessions trip this early.

## 11. Observe mode

With `mode: observe` in `.saga-watchdog.yaml`:

- every check returns allowed, so Claude is never blocked by policy;
- the audit event records the decision that enforce mode would have taken
  (`"decision": "pause"`, `"mode": "observe"`);
- the operator sees `SAGA Watchdog observe mode: would pause [protected-path] ...`.

Adapter and transport failures (section 13) still block in observe mode:
observe applies to policy decisions, not to a missing watchdog.

## 12. Enforce mode

With `mode: enforce`, pause and kill decisions block the tool call and act on
the process group. The policy is loaded once per run; editing the YAML during
a run is itself a kill-level tamper event. Start a new run to apply changes.

## 13. Fail-closed behaviour

Two layers, both required for the explicitly configured preventive hook:

| Failure | Claude Code (`onFailure: "block"`) | Adapter |
| --- | --- | --- |
| `saga-watchdog` not on PATH | blocks | n/a |
| Adapter crash or hook timeout (10 s) | blocks | n/a |
| `SAGA_WATCHDOG_SOCKET` / `SAGA_WATCHDOG_RUN_ID` unset (Claude started without SAGA) | n/a | exit 2 |
| Socket missing, stale or refusing (supervisor gone) | n/a | exit 2 after a bounded 1 s dial / 4 s I/O timeout |
| Run ID mismatch (socket from another run) | n/a | exit 2 |
| Response without a decision, or a protocol error | n/a | exit 2 |
| Hook input not JSON, over 16 MiB, or without a usable path or host | n/a | exit 2; the payload is never echoed |
| `ConfigChange` without `file_path` | n/a | exit 2; the settings change is not applied |
| Run paused | n/a | exit 2 (`run-paused`) until resumed |

The message in that case is:

```text
SAGA preventive check unavailable; tool call blocked
Reason: ...
Start the agent under supervision: saga-watchdog run -- claude
```

`PostToolUse` reports also return exit 2 when the supervisor is unreachable.
That is informational: the tool has already run.

## 14. Subagents

Hook events inside a subagent carry `agent_id` and `agent_type`. SAGA records
them as bounded metadata so main-agent and subagent calls stay
distinguishable in the audit log. The policy decision is identical for both:
a subagent receives no exemption and no additional trust. `parent_agent_id`
is not part of the documented hook input and is not recorded.

## 15. Audit examples

A blocked `.env` edit from a subagent, enforce mode:

```json
{"id":"evt_...","timestamp":"2026-10-10T13:49:27Z","project_id":"demo","run_id":"run_...","source":"integration","type":"file","action":"write","target":".env","result":"denied","severity":"high","rule_id":"protected-path","metadata":{"agent_id":"agent-7","agent_type":"reviewer","decision":"pause","mode":"enforce","producer":"claude-code","reason":"protected project path changed","session_id":"sess-1","tool_name":"Edit","tool_use_id":"toolu_5"}}
```

The same action in observe mode:

```json
{"source":"integration","type":"file","action":"write","target":".env","result":"allowed","severity":"high","rule_id":"protected-path","metadata":{"decision":"pause","mode":"observe","producer":"claude-code","tool_name":"Edit"}}
```

A hook configuration change attempted through the Edit tool:

```json
{"source":"integration","type":"file","action":"write","target":".claude/settings.json","result":"denied","severity":"critical","rule_id":"hook-tamper","metadata":{"decision":"kill","mode":"enforce","producer":"claude-code","tool_name":"Edit"}}
```

`run.json` lists the protected settings files under `controls`. Read a run
with `saga-watchdog status` and `saga-watchdog events`. Correlate a check,
its `PostToolUse` report and a later `filesystem` event through
`tool_use_id` and timestamps, but note: correlation does not prove
attribution. A filesystem event cannot identify which same-user process
wrote the file.

## 16. Troubleshooting

| Symptom | Action |
| --- | --- |
| Every tool call is blocked with "preventive check unavailable" | Claude was started without SAGA, or the run ended. Start it with `saga-watchdog run -- claude`, or remove the hook (section 19). |
| `claude doctor` reports no SAGA hook | Run `saga-watchdog claude setup`, then check `/hooks` inside Claude Code. |
| Hook does not fire | Accept the workspace trust dialog; check `disableAllHooks`; confirm `saga-watchdog` resolves on the `PATH` Claude inherits. |
| `claude doctor` warns that Claude Code predates 2.1.295 | Upgrade Claude Code. Until then a hook crash or timeout is non-blocking on Claude's side. |
| Run pauses on an expected edit | Inspect `saga-watchdog events`, then `resume` or `kill` the run explicitly. |
| Run pauses right after choosing "always allow" in a permission prompt | Claude saved a rule to `.claude/settings.local.json`; that change is held back and the run waits for review. Resume it, or choose those rules before starting a supervised run. If the hook lives in that file (`setup --local`), the save is hook tampering and stops the run; move the hook to `.claude/settings.json`. |
| Warnings about failure-escalation after a denial | Expected after related follow-ups; raise thresholds in `escalation` if needed. |
| `setup` refuses the settings file | The file is not a JSON object, is a symlink, or `hooks` is malformed. Fix by hand or print the snippet with `claude config`. |

Run Claude Code with `--debug` to see hook stdin, exit codes and stderr.

## 17. Upgrades

After upgrading Claude Code, run `saga-watchdog claude doctor` and skim the
official hooks reference for changes to the events, fields and exit-code
semantics in section 4. After upgrading SAGA, run `claude setup` again: it
is idempotent and reports whether the stored hooks changed.

## 18. Limitations

- A hook can only prevent actions that pass through that hook. Shell
  commands, their child processes, MCP server side effects, remote jobs and
  raw sockets are not interpreted; their file effects are observed after the
  fact.
- Only matched tools are checked. File reads are invisible.
- The adapter and the supervisor run as the same OS user as Claude. This is
  policy enforcement for a cooperating runtime, not a privilege boundary.
- Claude Code honours exit 2 and `onFailure: "block"` according to its
  documented contract; SAGA depends on that contract.
- User-level hooks in `~/.claude/settings.json` are outside the project and
  outside SAGA's filesystem observation and tamper protection.
- Correlation between a check, a report and a filesystem event is by
  identifier and time, not proof of attribution.

Read [SECURITY.md](../SECURITY.md) for the full threat model.

## 19. Disabling or uninstalling

Stop the supervised run, then remove the four `saga-watchdog claude hook`
groups from `.claude/settings.json` or `.claude/settings.local.json`, either
in an editor or through `/hooks` in Claude Code. Do not edit those files
while a supervised run is active: that is a hook-tamper event. Running
`claude` without the hook keeps generic supervision and observation when
started through `saga-watchdog run -- claude`.
