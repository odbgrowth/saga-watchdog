# Acceptance demo

[Back to the overview](../README.md) · [Coding-agent guide](../docs/coding-agent.md)

Use Linux or macOS with the built binary on `PATH`. These commands create a
disposable Git repository. No model account or running agent is needed.

## 1. Create the demo project

```sh
demo_dir="$(mktemp -d)"
cd "$demo_dir"
git init -b watchdog-demo
saga-watchdog init
saga-watchdog doctor
printf 'Demo project: %s\n' "$demo_dir"
```

Keep the printed path for a second terminal. The branch is deliberately not
`main` or `master`.

## 2. A normal write and a policy change

Start a supervised shell:

```sh
saga-watchdog run -- bash --noprofile --norc
```

Inside that shell, disable job control so this demo's commands remain in the
original supervised process group:

```sh
set +m
printf 'hello\n' > normal.txt
```

Expected: the write is observed; the shell continues. Then, inside the same shell:

```sh
printf '\n# demo policy change\n' >> .saga-watchdog.yaml
```

Expected: the supervisor reports a policy-tamper rule and terminates the owned
group in enforce mode. The original terminal regains control and a run summary
shows the stop reason. The file change has already happened and remains on disk;
the running policy was never reloaded.

Inspect the audit log from the original terminal:

```sh
saga-watchdog status
saga-watchdog events
```

The appended comment leaves the YAML valid for the next run.

## 3. Reported escalation after denial

Start another supervised shell:

```sh
saga-watchdog run -- bash --noprofile --norc
```

Copy the new run ID from startup output. In the supervised shell, first run
`set +m` to disable job control, then submit these commands one at a time:

```sh
saga-watchdog emit --type network --action connect \
  --target blocked-a.example --result denied
saga-watchdog emit --type network --action connect \
  --target blocked-b.example --result denied
saga-watchdog emit --type network --action connect \
  --target blocked-c.example --result denied
```

With the default escalation thresholds, the first denial is recorded, the
second related event warns, and the third pauses the group. The third command
may itself be suspended because job control is disabled and it remains in that
group.

In a second terminal, change to the printed demo directory, inspect the event
log and explicitly resume the run:

```sh
cd /the/printed/demo/path
saga-watchdog status
saga-watchdog events
saga-watchdog resume RUN_ID_FROM_STARTUP
```

Use the actual run ID. Back in the supervised shell, while the 120-second
escalation window is still active:

```sh
saga-watchdog emit --type network --action connect \
  --target blocked-d.example --result denied
```

This reaches the pause threshold again. Resume from the second terminal, then
emit the fifth event:

```sh
saga-watchdog emit --type network --action connect \
  --target blocked-e.example --result denied
```

Expected: the fifth related event reaches the kill threshold. The final summary
and JSONL events state the escalation rule and count. If the window expired
while you were inspecting, the old events no longer contribute; start a fresh
run for a repeat.

These commands send reports through the integration socket. They do not create
network connections or prove that Watchdog can independently observe network
traffic.

## 4. Explicit controls

For a separate controls demonstration:

```sh
saga-watchdog run -- sleep 600
```

In the second terminal, use that run ID:

```sh
saga-watchdog pause RUN_ID_FROM_STARTUP
saga-watchdog resume RUN_ID_FROM_STARTUP
saga-watchdog kill RUN_ID_FROM_STARTUP
```

Expected: only the owned run is signalled, control requests are audited, and the
summary records termination. These are same-user local controls, not proof that
a human sent the request.

## 5. Observe mode

With no run active, change `mode: enforce` to `mode: observe` in
`.saga-watchdog.yaml`, then repeat the protected-write demo. Expected: the
proposed intervention and violation are recorded, but policy does not terminate
the shell. Type `exit` when finished.

The demo repository and local run logs remain for inspection. Remove them only
after every demo run has ended.
