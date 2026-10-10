# SAGA Watchdog

[![CI](https://github.com/odbgrowth/saga-watchdog/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/odbgrowth/saga-watchdog/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**SAGA Watchdog is a small, local and deterministic safety layer for AI
agents.** It can check supported actions before execution, supervise agent
processes while they run, and independently observe selected runtime changes
afterwards.

SAGA runs outside the reasoning model. It does not ask the AI whether its own
behaviour is safe. Policy is a handful of explicit rules over observable
events, evaluated by deterministic Go code with no LLM, no cloud service and
no database.

**Status:** development code on `main`. No tagged release or downloadable
binary has been published yet. Use a reviewed commit for a reproducible
deployment.

## Why it exists

Modern coding agents edit files, execute commands, invoke MCP tools, reach
external services, use credentials, create subagents, retry denied operations
and keep running for hours. Prompt instructions alone are not a security
boundary. SAGA adds an independent local control layer:

```text
1. PREVENT     supported agent tool calls
               -> deterministic policy check before execution

2. SUPERVISE   the process tree SAGA started
               -> runtime budget, pause / resume / stop

3. OBSERVE     filesystem, Git, integrations, Docker
               -> audit trail and escalation
```

Constrain before execution. Supervise during execution. Observe after
execution. Repeated pressure against a boundary escalates from warning to
pause to stop. A paused run stays paused until a human resumes or kills it.

The agent reasons. SAGA does not. It watches boundaries.

## Feature matrix

| Capability | Claude Code integration | Coding-agent supervisor | Docker observer |
| --- | ---: | ---: | ---: |
| Pre-action checks | Yes, matched tools | Cooperative `check` integrations | No |
| Filesystem observation | Post-action, via the supervisor | Yes, post-action | No |
| Git branch monitoring | Through the supervisor | Yes | No |
| Pause/kill owned process | Yes | Yes | No |
| Container lifecycle observation | No | No | Yes |
| Container health/resource observation | No | No | Yes |
| Raw syscall interception | No | No | No |
| Kernel network firewall | No | No | No |
| LLM safety decisions | No | No | No |

SAGA is not a sandbox, a firewall, a syscall interceptor or an EDR. It does
not read prompts, chain-of-thought, file contents or command text. When both
the agent and SAGA run as the same OS user, process separation is policy
enforcement for a cooperating runtime, not a hardened privilege boundary.
Read [SECURITY.md](SECURITY.md) before relying on it for sensitive work.

## Install

For Linux or macOS, install [Go 1.26 or newer](https://go.dev/dl/) and Git.
Use a Linux environment such as WSL on Windows; native Windows supervision and
Docker named pipes are unsupported.

```sh
go install github.com/odbgrowth/saga-watchdog/cmd/saga-watchdog@main
export PATH="$(go env GOPATH)/bin:$PATH"
saga-watchdog --help
```

If you set `GOBIN`, add that directory to `PATH` instead. For a reproducible
installation, replace `@main` with a reviewed commit hash.

## Quick start

```sh
cd my-project
git switch -c agent/my-task

saga-watchdog init
saga-watchdog doctor

saga-watchdog run -- claude
# Or any CLI agent: saga-watchdog run -- codex
```

The default policy refuses `main` and `master`, treats changes to
`.saga-watchdog.yaml` as tampering, pauses for Git security, CI workflow and
secret-like file changes, detects deletion bursts, escalates repeated denials
and stops a run after two hours. The policy stays fixed for the run. The
[coding-agent guide](docs/coding-agent.md) covers configuration, controls and
the generic `check`/`emit` integration; the [shell demo](examples/DEMO.md)
shows it working without any AI account.

## Preventive Claude Code checks

Claude Code exposes hook events before each tool call. Install the SAGA hook
once per project and start Claude under supervision:

```sh
saga-watchdog claude setup      # merges hooks into .claude/settings.json
saga-watchdog claude doctor
saga-watchdog run -- claude
```

From then on, Write, Edit, MultiEdit, NotebookEdit, Bash, WebFetch and MCP
tool calls are checked by the same policy engine before they execute:

```text
Write src/app.go           -> allowed
Edit .env                  -> blocked before execution, run paused
Edit .claude/settings.json -> blocked, run stopped (hook tampering)
Claude saves "always allow" -> settings change held back, run paused for review
SAGA not running           -> every matched call blocked (fail closed)
```

Each decision is recorded with a stable rule ID, the tool name and, where
Claude provides them, the tool-call, session and subagent identifiers. File
contents, command text, URLs beyond the host, MCP arguments and prompts are
never collected. Subagents receive no exemption.

Read the [Claude Code guide](docs/claude-code.md) for the verified hook
contract, tool mapping, observe mode, fail-closed behaviour and
troubleshooting, and the [Claude demo](examples/claude-code.md) for a
reproducible walkthrough.

## Observe an existing Docker agent

The Docker observer runs beside containers that already exist and never
controls them. Follow the [Docker guide](docs/docker-observer.md) to build and
copy the binary, select full container IDs and configure the service
account, then:

```sh
saga-watchdog docker validate --config /path/to/docker.yaml
saga-watchdog docker watch --config /path/to/docker.yaml --once
saga-watchdog docker watch --config /path/to/docker.yaml
```

Use [examples/docker-observer.yaml](examples/docker-observer.yaml) as the
template and the [systemd example](deploy/saga-watchdog-docker.service) to run
it as a separate Linux service. Docker socket access is administrative
authority even though the observer only sends read requests.

## What the results mean

- **Pre-action checks** are decisions over what the agent runtime reported it
  was about to do. They cover only tools that pass through a hook or a
  cooperative `check` call.
- **Observed file changes** are detected after they happen. SAGA cannot undo
  the first write or prove which same-user process made it.
- **Escalation** is a rule over the available events, not a claim about the
  agent's intent: for example, three related denied operations within 120
  seconds.
- **Process controls** cover the Unix process group SAGA created. A detached
  process or a remote job may be outside it.
- **Container health** depends on a Docker healthcheck. Resource metrics do
  not reveal AI decisions.

## Commands

```text
Project        init | validate | doctor
Run            run -- <command> | status | events | pause | resume | kill
Integrations   check | emit
Claude Code    claude config | setup [--local] | doctor | hook
Docker         docker validate | watch | status | events
```

Run `saga-watchdog --help` for arguments.

## Documentation and contributing

- [Coding-agent guide: supervision, observation, policy, check/emit](docs/coding-agent.md)
- [Claude Code guide: preventive hooks](docs/claude-code.md)
- [Docker observer guide](docs/docker-observer.md)
- [Shell demo](examples/DEMO.md) and [Claude Code demo](examples/claude-code.md)
- [Contributing, tests and release process](CONTRIBUTING.md)
- [Security policy, threat model and limitations](SECURITY.md)

Report ordinary bugs through [Issues](https://github.com/odbgrowth/saga-watchdog/issues).
Use [private reporting](https://github.com/odbgrowth/saga-watchdog/security/advisories/new)
for security vulnerabilities. Keep credentials and customer data out of public
reports.

## License

[Apache License 2.0](LICENSE).
