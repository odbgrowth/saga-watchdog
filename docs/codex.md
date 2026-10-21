# Codex CLI: preventive hooks

SAGA Watchdog can check supported Codex CLI tool calls before they execute.
The integration is a thin adapter from Codex hook events to the canonical SAGA
events evaluated by the same policy engine as every other source. It adds no
rules of its own.

Verified against Codex CLI 0.162.1 (`codex-rs/hooks`,
`codex-rs/core/src/tools/hook_names.rs`, `codex-rs/config/src/hook_config.rs`).
The Codex hook engine implements the Claude Code hook contract; the
[Claude Code guide](claude-code.md) explains the shared architecture, observe
and enforce modes and the audit format in depth. This guide covers what is
specific to Codex.

## 1. Hook contract SAGA relies on

- Codex loads `hooks.json` from the project's `.codex/` directory (project
  layer) and from `~/.codex/` (user layer), plus inline `[hooks]` tables in
  `config.toml`. SAGA writes only `.codex/hooks.json`.
- `PreToolUse` fires before a tool executes; `PostToolUse` after a tool
  produced output. There is no failure event.
- stdin carries `hook_event_name`, `session_id`, `turn_id`, `cwd`,
  `tool_name`, `tool_input`, `tool_use_id` and, inside a sub-agent,
  `agent_id` and `agent_type`.
- Tool names seen by hooks: `Bash` for every shell-like tool (`tool_input`
  holds `command`), `apply_patch` for file edits (`tool_input.command` holds
  the patch text), `spawn_agent` for sub-agent creation and `mcp__<server>__<tool>`
  for MCP tools. Hosted tools such as web search never reach a hook.
- Exit code 2 blocks the call and sends stderr to the model as the reason.
  Exit 0 with `{"systemMessage": "..."}` shows a note to the operator and
  allows the call. Any other exit code, a timeout or a hook that cannot start
  is reported as a failed hook and the call proceeds.
- A matcher with characters outside letters, digits, underscore and `|` is a
  regular expression. SAGA installs
  `^(Bash|apply_patch|spawn_agent|mcp__.*)$`.
- Codex fingerprints every non-managed hook. A new or changed project hook is
  **skipped until you accept it once** in the interactive startup review.
  `codex features list` must report `hooks` as enabled (it is, from the
  current stable builds).

## 2. Setup

```sh
cd my-project
saga-watchdog init                 # once per project
saga-watchdog codex setup          # writes .codex/hooks.json
codex                              # accept the new hook in the startup review, then exit
saga-watchdog codex doctor
saga-watchdog run -- codex
```

`saga-watchdog codex config` prints the hook configuration for manual
installation. `setup` merges into an existing `hooks.json` and preserves
other hooks. `remove` deletes only the SAGA entries; run it between runs,
never during one.

The hook runs `saga-watchdog codex hook`, so `saga-watchdog` must be on the
PATH Codex uses. Every run exports `SAGA_WATCHDOG_SOCKET` and
`SAGA_WATCHDOG_RUN_ID` to the agent; the adapter needs nothing else.

## 3. Tool mapping

| Codex tool | SAGA event | Target |
| --- | --- | --- |
| `apply_patch` | `file/write` or `file/delete`, one check per file | Each path named by a `*** Add File`, `*** Update File`, `*** Move to` or `*** Delete File` header, resolved against the hook `cwd` |
| `Bash` | `process/execute` | `Bash` |
| `spawn_agent` | `tool/call` | `spawn_agent` |
| `mcp__server__tool` | `tool/call` | `server/tool` |
| other | `tool/call` | the tool name |

Only the patch headers are read; hunk content is never retained or logged. A
patch that names a protected path is blocked as a whole, since the first
denied file blocks the call. A patch without file headers or with more than
256 files is refused. `PostToolUse` reports the same targets with
`result: success`.

Shell commands are not interpreted. A `Bash` call is recorded as a process
execution and its file effects are caught afterwards by the filesystem
observer, exactly as for Claude Code.

## 4. Decisions

| Policy decision | Codex sees | Run state |
| --- | --- | --- |
| allow | call proceeds | unchanged |
| warn | call proceeds with a `systemMessage` note | warning recorded |
| pause | exit 2 with rule, target and reason | paused until `saga-watchdog resume` (or denied-only with `run.unattended`) |
| kill | exit 2 | process group stopped |

Observe mode records the decision and allows every call.

## 5. Fail-closed scope

The adapter fails closed: an unreachable supervisor, a missing run ID, a
malformed response or an uninterpretable event returns exit 2. Codex itself
does not: a hook that cannot start, times out or crashes is logged as failed
and the call proceeds, and an untrusted project hook is skipped. Keep
`saga-watchdog` on PATH, accept the hook once interactively, and treat
`saga-watchdog codex doctor` as the pre-flight check. Headless `codex exec`
runs hooks that were accepted earlier; it cannot accept new ones. After a
run, `saga-watchdog report` warns when `.codex/hooks.json` carried the hook
but no pre-action check ever arrived from Codex.

`run.require_preventive_hook: true` makes `saga-watchdog run -- codex`
refuse to start unless `.codex/hooks.json` carries a blocking SAGA hook, the
hook command and `codex` are on `PATH` and `codex features list` reports
hooks enabled. It checks configuration, not behaviour: it cannot see whether
the hook was accepted in the startup review, and it does not make Codex fail
closed. The run banner says so: the adapter fails closed, Codex lets a call
proceed when the hook cannot start or times out.

## 6. Protected configuration

While a run is active, `.codex/hooks.json` is a control file: any change to
it stops the run (`hook-tamper`, kill), including removing the `.codex`
directory. A change to `.codex/config.toml` pauses the run
(`agent-config-modification`), because its inline hooks or feature flags can
disable the hook. A patch that names `.mcp.json`, `.vscode/mcp.json` or
`.vscode/tasks.json` pauses the run as well (`project-config-modification`).
User-level `~/.codex` is outside the project and outside SAGA's protection.

## 7. Limitations

- Only matched tools are checked before execution. Reads, hosted tools and
  anything outside the matcher are invisible before the fact.
- Codex cannot fail closed on an adapter failure (section 5).
- The hook contract is Codex's; a future Codex release can change it. The
  `PreToolUse` input and the exit-code semantics are the stable surface SAGA
  depends on.
- Everything in [SECURITY.md](../SECURITY.md) applies: same-user process
  separation is not a sandbox.
