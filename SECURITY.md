# Security policy

SAGA Watchdog is a local process supervisor with deterministic policy decisions.
It is not an operating-system sandbox. Read these boundaries before relying on it
for a sensitive workload.

## Reporting a vulnerability

Do not put exploitable security details, credentials, or private event logs in a
public issue or pull request.

Check the repository's [Security tab](https://github.com/odbgrowth/saga-watchdog/security)
for **Report a vulnerability**. If available, use that private reporting flow.

GitHub Private Vulnerability Reporting was disabled when checked on 2026-09-29.
**Maintainer TODO: enable and verify private reporting before publishing
v0.1.0.** Until then, open a public issue asking for a
private contact channel, with no exploit details. There is no invented reporting
email or promised response time.

A private report should include the affected version and OS, a minimal
reproduction, the expected policy decision, the observed behavior, and the
security impact. Redact all real secrets and unrelated project data.

## Supported versions

During v0.1 development, fixes target the current development branch. After the
first tagged release, only the latest v0.1.x patch release is supported. Older
patch releases should be upgraded; no backport or response-time commitment is
made. Windows process supervision is not supported.

## Security scope

The core is responsible for:

- Strict configuration parsing and immutable effective policy during a run.
- Deterministic decisions for events it receives.
- Observing covered filesystem changes and reporting watcher failures.
- Signalling the process group it creates on supported Unix systems.
- Separating integration observations from supervisor-owned policy decisions.
- Conservative local metadata storage and redaction.

Bypassing a promised core rule, signalling an unrelated run, executing code
through malformed local requests, or leaking secrets through a supported
redaction path is in scope.

## Known limitations

- Watchdog and the agent normally run as the same OS user. A hostile agent can
  potentially signal the supervisor, alter its on-disk configuration or logs,
  access local sockets, or change another same-user process. Process separation
  is not a tamper-resistant privilege boundary.
- A forcibly killed or crashed supervisor cannot deliver cleanup signals. Its
  child processes may continue running. There is no service manager or kernel
  containment mechanism that guarantees child death when Watchdog disappears.
- Pause, resume and kill are local operator controls. They cannot prove that the
  caller is a human rather than a same-user agent. A resume does not change the
  loaded policy or grant a new permission.
- Unix process-group signals reach processes that remain in the owned group.
  Descendants that detach into a new session/group, remote jobs, containers and
  separately scheduled jobs are not contained by this mechanism. Interactive
  shell job control can also place commands into separate process groups.
- Filesystem observation happens after changes. It cannot prevent or undo the
  first write, reliably attribute a write to the agent, observe every file read,
  or guarantee delivery of every filesystem event.
- Paths outside the project, ignored paths, symlink targets and OS-specific
  watcher behavior limit coverage. A path check is not a race-free filesystem
  authorization boundary.
- Network, credential and tool events sent through integrations are claims from
  the producer. A producer can omit, forge or replay them. A successful check
  does not execute or intercept the action.
- Core mode has no kernel network filter, syscall interception, eBPF, EDR,
  container isolation, or privileged monitor. It does not inspect model
  reasoning, prompts or chain-of-thought.
- Local JSONL logs are opened for append by Watchdog. They are not signed,
  externally anchored, or immutable against the same OS user.
- Redaction is conservative best effort, not a full secret scanner. Integrations
  must send identifiers rather than raw tokens, passwords, headers or content.
  Supervised programs write directly to their terminal; their output is outside
  Watchdog's structured-log redaction.

Use OS isolation and least-privilege credentials when hostile code or sensitive
data is involved. Do not treat absence of a Watchdog event as proof that an action
did not happen.
