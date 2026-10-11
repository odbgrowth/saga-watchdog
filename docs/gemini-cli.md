# Gemini CLI: preventive hooks

SAGA Watchdog can check supported Gemini CLI tool calls before they execute.
The integration is a thin adapter from Gemini CLI hook events to the
canonical SAGA events evaluated by the same policy engine as every other
source. It adds no rules of its own.

Verified against Gemini CLI 0.63.0 (`docs/hooks/reference.md`,
`packages/core/src/hooks`). The [Claude Code guide](claude-code.md) explains
the shared architecture, observe and enforce modes and the audit format in
depth. This guide covers what is specific to Gemini CLI.

## 1. Hook contract SAGA relies on

- Hooks live under the `hooks` key of `settings.json`. Project settings
  (`.gemini/settings.json`) take precedence over user and system settings.
  SAGA writes only the project file.
- `BeforeTool` fires before a tool executes and can block it; `AfterTool`
  fires afterwards with the `tool_response`, including an `error` when the
  tool failed.
- stdin carries `session_id`, `transcript_path`, `cwd`, `hook_event_name`,
  `timestamp`, `tool_name` and `tool_input`. There is no tool-call identifier.
- Tool names: `write_file` and `replace` (`tool_input.file_path`),
  `run_shell_command` (`command`), `web_fetch` (`url`, or a `prompt` with URLs
  written in prose), `google_web_search` (`query`), `invoke_agent`, and
  `mcp_<server>_<tool>` for MCP tools.
- Exit code 0 means stdout is parsed as JSON; `{"systemMessage": "..."}`
  shows a note and allows the call. Exit 2 blocks with stderr as the reason.
  Exit 1 is a warning and the call proceeds. A hook that cannot start or times
  out is logged and the call proceeds.
- The matcher is a regular expression tested without anchors. SAGA installs
  `^(write_file|replace|run_shell_command|web_fetch|google_web_search|invoke_agent|mcp_.*)$`.
- `hooksConfig.enabled: false` turns hooks off; `hooksConfig.disabled` lists
  hook names to skip. The SAGA hook is named `saga-watchdog`.
- Project hooks run only in a trusted folder. Gemini CLI fingerprints them
  and warns once about new or changed project hooks, then runs them.

## 2. Setup

```sh
cd my-project
saga-watchdog init                 # once per project
saga-watchdog gemini setup         # writes .gemini/settings.json
saga-watchdog gemini doctor
saga-watchdog run -- gemini
```

`saga-watchdog gemini config` prints the hook configuration for manual
installation. `setup` merges into an existing `settings.json` and preserves
every other key. `remove` deletes only the SAGA entries; run it between runs,
never during one.

The hook runs `saga-watchdog gemini hook`, so `saga-watchdog` must be on the
PATH Gemini CLI uses. Every run exports `SAGA_WATCHDOG_SOCKET` and
`SAGA_WATCHDOG_RUN_ID` to the agent; the adapter needs nothing else.

## 3. Tool mapping

| Gemini tool | SAGA event | Target |
| --- | --- | --- |
| `write_file`, `replace` | `file/write` | `file_path` |
| `run_shell_command` | `process/execute` | `run_shell_command` |
| `web_fetch` with `url` | `network/connect` | host of the URL |
| `web_fetch` with only a `prompt` | `tool/call` | `web_fetch` |
| `google_web_search` | `tool/call` | `google_web_search` |
| `invoke_agent` | `tool/call` | `invoke_agent` |
| `mcp_server_tool` | `tool/call` | `server/tool` |
| other | `tool/call` | the tool name |

Prompts, command text, MCP arguments and file contents are never read. A
prompt-only `web_fetch` is recorded as a tool call because the URLs it
contains are prose, not a field; use `tools.deny: [web_fetch]` to refuse the
tool altogether. `AfterTool` reports `result: success`, or `result: failed`
when the response carries an `error`.

## 4. Decisions

| Policy decision | Gemini CLI sees | Run state |
| --- | --- | --- |
| allow | call proceeds | unchanged |
| warn | call proceeds with a `systemMessage` note | warning recorded |
| pause | exit 2 with rule, target and reason | paused until `saga-watchdog resume` (or denied-only with `run.unattended`) |
| kill | exit 2 | process group stopped |

Observe mode records the decision and allows every call. Headless use is
`gemini -p "..."`; combine it with `run.unattended: true`.

## 5. Fail-closed scope

The adapter fails closed: an unreachable supervisor, a missing run ID, a
malformed response or an uninterpretable event returns exit 2. Gemini CLI
itself does not: a hook that cannot start, times out or exits 1 is logged and
the call proceeds, hooks are skipped in an untrusted folder, and
`hooksConfig` can switch them off. Keep `saga-watchdog` on PATH, trust the
project folder, and treat `saga-watchdog gemini doctor` as the pre-flight
check: it fails when the project settings disable the hook.

## 6. Protected configuration

While a run is active, `.gemini/settings.json` is a control file: any change
to it stops the run (`hook-tamper`, kill), including removing the `.gemini`
directory. User-level `~/.gemini/settings.json` is outside the project and
outside SAGA's protection.

## 7. Limitations

- Only matched tools are checked before execution. Reads and anything outside
  the matcher are invisible before the fact.
- Gemini CLI cannot fail closed on an adapter failure (section 5).
- The hook contract is Gemini CLI's; a future release can change it. The
  `BeforeTool` input and the exit-code semantics are the stable surface SAGA
  depends on.
- Everything in [SECURITY.md](../SECURITY.md) applies: same-user process
  separation is not a sandbox.
