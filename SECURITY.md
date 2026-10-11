# Security policy

SAGA Watchdog is a local, deterministic safety layer for AI agents: a process
supervisor with pre-action checks for cooperating runtimes, post-action
observation, and a separate read-only Docker observer. It is not an
operating-system sandbox. Read the threat model below before relying on it
for a sensitive workload.

## Reporting a vulnerability

Do not put exploitable security details, credentials, or private event logs in
a public issue or pull request.

Use [GitHub private vulnerability reporting](https://github.com/odbgrowth/saga-watchdog/security/advisories/new).
Reports are shared with repository maintainers rather than posted as public
issues. If the reporting form is unavailable, open an issue asking for a
private contact channel without including vulnerability details. No
response-time commitment is made.

A private report should include the affected commit and OS, a minimal
reproduction, the expected policy decision, the observed behaviour, and the
security impact. Redact all real secrets and unrelated project data.

## Supported versions

v0.3.0 is the current release. Fixes target `main` and ship in the next
tagged release; there is no maintained release branch or backport commitment.
Report issues against the latest release or `main`. Native Windows supervision
is unsupported.

## Trust boundaries

```text
AI model                     reasons; produces tool-call proposals
        |
AI-agent runtime             Claude Code, Codex, any CLI: executes tools,
        |                    owns its own permission system
agent-specific integration   agent hook -> saga-watchdog claude|codex|gemini hook
        |                    (producer evidence: a claim, not an observation)
SAGA Watchdog                policy engine, supervisor, observers, audit
        |
local OS user                the account SAGA, the agent and the hook share
        |
operating system / kernel    process groups, signals, filesystem, sockets
        |
external services            Git remotes, APIs, MCP servers, containers
```

SAGA controls the boundary between the agent runtime and the actions it
proposes **only where the runtime routes the action through a hook or a
cooperative `check` call**. It controls the lifecycle of the process group it
started. It observes, but does not control, the filesystem, the Git branch
and selected Docker containers. It does not control the model, the kernel,
the OS user, or external services.

## Evidence classes

- **Producer evidence** (`source: integration`): a hook or wrapper reports
  what the agent is about to do or has done. Useful, independently evaluated,
  but a claim from inside the supervised environment. `metadata.producer`
  names the claimant.
- **Runtime observation** (`source: filesystem`, `git`): independent of the
  agent's reports, after the fact, and unable to prove which same-user
  process acted.
- **Process evidence** (`source: supervisor`, `control`): exit codes,
  timeouts, operator requests.
- **Docker evidence**: container state, health, restarts and resource use.

Correlated events (a check, its post-action report, a filesystem change with
matching timestamps) are not independent confirmations of each other.

## What SAGA can prevent

For supported Claude Code, Codex CLI and Gemini CLI tool calls, SAGA blocks
the action **before execution** only when all of the following hold:

- the relevant agent hook fires for that tool;
- the SAGA hook is configured in the project's settings, loaded and, where
  the agent requires it, trusted;
- the event can be safely interpreted (a usable path or host);
- the SAGA supervisor for that run is reachable;
- the agent honours its documented blocking contract (exit code 2, and for
  Claude Code `onFailure: "block"`).

For generic `check` integrations the same holds for whatever wrapper calls
`check` and honours the answer. No other action is prevented. There is no
guaranteed isolation, complete containment or unbypassable control.

## Fail-closed scope

The deliberately configured agent hook fails closed on the SAGA side: a
missing or unreachable watchdog, a timeout, a run ID mismatch, a malformed
response or an uninterpretable event blocks the tool call. Only Claude Code
(2.1.295 or newer, `onFailure: "block"`) also blocks when the adapter itself
cannot start or times out; Codex CLI and Gemini CLI log such a failure and
let the call proceed, and both skip a project hook they do not trust. This
scope is intentional and narrow. Generic supervision of an arbitrary CLI is not turned into universal
fail-closed execution: an agent without a hook keeps running when the
supervisor cannot see an action, and observe mode allows policy violations by
design.

## Same-user boundary

In coding-agent mode, SAGA, the hook and the agent normally run as the same
Unix user. A sufficiently capable same-user process can potentially signal
the supervisor, alter its on-disk configuration, state or logs, reach its
sockets, or change another same-user process. SAGA detects and reacts to
tampering with `.saga-watchdog.yaml` and with the settings files that carry
the Claude hook, but process separation is not a tamper-resistant privilege
boundary.

For stronger isolation use OS mechanisms that fit your threat model:
separate user identities, containers, virtual machines, sandboxing and
network policies. Those are outside this project.

## Hook boundary

A hook can only prevent actions that pass through that hook. SAGA does not
intercept arbitrary syscalls, external processes, raw socket creation, every
possible side effect, or remote jobs started elsewhere. A Bash tool call is
recorded as a process execution; its command text is not interpreted and its
file effects are observed only afterwards. Tools outside the hook matcher,
including file reads, are invisible. User-level hooks in
`~/.claude/settings.json`, `~/.codex` and `~/.gemini/settings.json` are
outside the project and outside SAGA's protection.

## Filesystem boundary

Filesystem observation is post-action. The first write has already happened
before the watcher reports it; SAGA cannot roll it back. Observation cannot
reliably attribute a same-user write to the agent rather than another local
process, cannot see file reads, and cannot guarantee delivery of every
notification. Paths outside the project, ignored paths, symlink targets and
OS-specific watcher behaviour limit coverage. A path check is not a
race-free filesystem authorization boundary.

## Process boundary

Unix process-group signals reach processes that remain in the owned group.
Descendants that detach into a new session or group, remote jobs, containers
and separately scheduled work are not contained. A forcibly killed or crashed
supervisor cannot deliver cleanup signals. Pause, resume and kill are local
operator controls; they cannot prove that the caller is a human.

## Data minimization

SAGA records paths, hostnames, tool and agent identifiers, rule IDs, reasons
and counters. It never records prompts, chain-of-thought, model output, file
contents, replacement text, command text, URLs beyond the hostname, MCP
arguments, environment values, headers, cookies or credentials. Metadata is
an allowlist of bounded scalar keys; redaction is defense in depth, not a
secret scanner. Local JSONL logs are append-only from SAGA's perspective but
are not signed, anchored or immutable against the same OS user. A supervised
program's own terminal output is outside SAGA's redaction.

## Docker observer

The observer sends only GET requests, but access to a Docker socket is
administrative access, not an OS-enforced read-only capability. Keep its
service account and configuration outside the agent's authority. Observation
can miss events during connection gaps or queue overflow; polling restores
current state, not complete history. No container control or automatic
intervention is implemented.

## Security scope for reports

Bypassing a promised core rule, signalling an unrelated run, executing code
through malformed local requests, making a configured preventive hook
silently allow an action, or leaking secrets through a supported redaction
or metadata path is in scope. Do not treat the absence of a SAGA event as
proof that an action did not happen.
