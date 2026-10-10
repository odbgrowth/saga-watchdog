# Claude Code acceptance demo

[Back to the overview](../README.md) · [Claude Code guide](../docs/claude-code.md) · [Shell demo](DEMO.md)

This demo exercises the preventive Claude Code path without a model account:
a supervised shell plays Claude Code by piping the documented hook JSON into
`saga-watchdog claude hook`. The last section runs the real `claude` binary.
No credentials or customer data are involved; the "secret" strings below only
prove that nothing from a tool payload reaches the audit log.

Use Linux or macOS with the built binary on `PATH`.

## 1. Create the demo project

```sh
demo_dir="$(mktemp -d)"
cd "$demo_dir"
git init -b watchdog-demo
saga-watchdog init
saga-watchdog claude setup
saga-watchdog claude doctor
printf 'Demo project: %s\n' "$demo_dir"
```

`claude doctor` fails only on the `claude` executable check when Claude Code
is not installed; the hook configuration checks still pass.

## 2. A normal write is allowed

Start a supervised shell and define a helper that sends one hook event:

```sh
saga-watchdog run -- bash --noprofile --norc
set +m
h() { printf '%s' "$1" | saga-watchdog claude hook; echo "exit=$?"; }
h '{"hook_event_name":"PreToolUse","session_id":"demo","tool_name":"Write","tool_input":{"file_path":"'"$PWD"'/src/app.go","content":"package app // SECRET-BODY"},"tool_use_id":"toolu_1"}'
```

Expected: `exit=0` and no output. Claude would continue through its own
permission prompt.

## 3. A `.env` edit is blocked before execution

```sh
h '{"hook_event_name":"PreToolUse","session_id":"demo","tool_name":"Edit","tool_input":{"file_path":"'"$PWD"'/.env","old_string":"a","new_string":"SECRET-VALUE"},"tool_use_id":"toolu_2"}'
```

Expected: the shell is paused by the supervisor. In a second terminal:

```sh
cd /the/printed/demo/path
saga-watchdog status
saga-watchdog events | grep protected-path
saga-watchdog resume RUN_ID_FROM_STATUS
```

Back in the supervised shell the helper finishes with `exit=2` and the
message `SAGA blocked this tool call` naming the rule, target and reason.
No `.env` file was created: the check happened before the write.

Confirm that the audit log holds the path and identifiers but no payload:

```sh
saga-watchdog events | grep -c SECRET   # prints 0
```

## 4. Hook configuration is protected

```sh
h '{"hook_event_name":"PreToolUse","session_id":"demo","tool_name":"Write","tool_input":{"file_path":"'"$PWD"'/.claude/settings.json","content":"{}"},"tool_use_id":"toolu_3"}'
```

Expected: the supervisor stops the run with rule `hook-tamper`; the original
terminal shows the summary and `saga-watchdog status` reports the rule.

## 5. Watchdog unavailable: fail closed

Outside any supervised run, in the demo directory:

```sh
printf '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"x"}}' | saga-watchdog claude hook; echo "exit=$?"
```

Expected: `exit=2` with `SAGA preventive check unavailable; tool call blocked`.
The same happens when the socket is stale, the run ID does not match, or the
input is malformed.

## 6. Observe mode

With no run active, set `mode: observe` in `.saga-watchdog.yaml` and repeat
section 3. Expected: `exit=0`, a `systemMessage` JSON line saying
`observe mode: would pause [protected-path]`, and an audit event with
`"decision":"pause"` and `"mode":"observe"`.

## 7. With the real Claude Code

```sh
saga-watchdog run -- claude
```

Ask Claude to add a line to `.env`. Expected: the Edit is refused with the
SAGA message, the run pauses, and `saga-watchdog events` in another terminal
shows the denied event with `"producer":"claude-code"` and the `tool_use_id`.
Resume or kill the run explicitly.

The demo repository and run logs remain for inspection.
