# SAGA Watchdog

[![CI](https://github.com/odbgrowth/saga-watchdog/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/odbgrowth/saga-watchdog/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Local supervision and observation for AI agents.**

SAGA Watchdog is a small Go command-line tool with two modes: it can supervise
an AI coding agent it starts, or observe containers that are already running.
It records local events and applies explicit rules to the activity its sources
can see. Policy decisions use deterministic code, without an LLM.

**Status:** development code is available on `main`. No tagged release or
downloadable binary has been published yet. Instructions below install the
current development version. Use a reviewed commit for a reproducible deployment.

## Choose a mode

| | Coding-agent supervisor | Docker observer |
| --- | --- | --- |
| Use it for | A CLI agent you start under SAGA | An existing container on a Docker host |
| Start | `saga-watchdog run -- COMMAND` | `saga-watchdog docker watch --config FILE` |
| Observes | Covered file changes, process state, Git branch and integration events | Selected container state, healthchecks, resources and lifecycle events |
| Can intervene | Warn, pause or stop the process group SAGA started | Observation only; leaves containers running |
| Configuration | `.saga-watchdog.yaml` in the Git project root | Separate YAML with full container IDs |
| Guide | [Coding agents](docs/coding-agent.md) | [Existing Docker agents](docs/docker-observer.md) |

The supervisor does not attach to arbitrary running processes. The Docker
observer does not inspect an agent's tool calls, API requests or reasoning.

## Install

For Linux or macOS, install [Go 1.26 or newer](https://go.dev/dl/) and Git.
Use a Linux environment such as WSL on Windows; native Windows supervision and
Docker named pipes are unsupported.

```sh
go install github.com/odbgrowth/saga-watchdog/cmd/saga-watchdog@main
export PATH="$(go env GOPATH)/bin:$PATH"
saga-watchdog --help
```

If you set `GOBIN`, add that directory to `PATH` instead. Development builds report
`saga-watchdog dev` with `saga-watchdog version`. For a reproducible installation,
replace `@main` with a reviewed commit hash. Go's
[module documentation](https://go.dev/ref/mod#go-install) explains version queries.

SAGA needs no cloud account or database. The agent you run may have its own
account requirements. Docker observation additionally requires access to a
local Docker Engine socket.

## Try the coding-agent supervisor

Run these commands in an existing Git project:

```sh
cd /path/to/your/project
git switch -c agent/my-task
saga-watchdog init
saga-watchdog doctor
```

Inspect the generated `.saga-watchdog.yaml`, then start your installed agent:

```sh
saga-watchdog run -- codex
# Or: saga-watchdog run -- claude
```

The default profile refuses `main` and `master`, watches policy and Git security
files, pauses for covered CI or secret-like file changes, and limits a run to
two hours. The policy stays fixed for that run. The child starts in the Git
project root. SAGA does not change the agent's own sandbox or approval settings.

Try the [shell-only demo](examples/DEMO.md) without an AI account, or read the
[coding-agent guide](docs/coding-agent.md) for configuration, controls and
`check`/`emit` integrations.

## Observe an existing Docker agent

Follow the [Docker installation guide](docs/docker-observer.md) to build and
copy the binary, select full container IDs and configure the service account.
Then validate and inspect once before enabling continuous observation:

```sh
saga-watchdog docker validate --config /path/to/docker.yaml
saga-watchdog docker watch --config /path/to/docker.yaml --once
saga-watchdog docker watch --config /path/to/docker.yaml
```

Use [examples/docker-observer.yaml](examples/docker-observer.yaml) as the
configuration template. Replace its container ID and state-directory values.
The commands above need permission to access the configured Docker socket and
state directory. The [systemd example](deploy/saga-watchdog-docker.service)
runs SAGA as a separate Linux service. Updating or stopping SAGA leaves the
selected containers running.

## What the results mean

- **Observed file changes:** detected after they happen; SAGA cannot undo the
  first write or reliably attribute it to the agent.
- **Reported tool/API events:** require an integration that calls `check` or
  `emit`. Without it, those attempts are invisible to SAGA.
- **Escalation:** repeated denials and related follow-up events can trigger
  configured thresholds. This is a rule over available events, not proof of
  the agent's intent.
- **Container health:** depends on a Docker healthcheck. A running container
  without one has unknown application health.
- **Process controls:** cover the Unix process group SAGA created. A detached
  process or remote job may be outside that group.

SAGA is not a sandbox, firewall or complete security boundary. The supervisor
normally shares an OS user with its child. Docker socket access is administrative
authority even though the observer itself sends only read requests.
Read the [security policy and limitations](SECURITY.md).

## Status, history and notifications

The coding supervisor provides `status` and `events` commands. Docker mode has
separate `docker status --config FILE` and `docker events --config FILE` commands,
with JSON status and retained JSONL history. See the corresponding guide for
storage, retention and freshness rules.

**Email notifications, a dashboard and automated Ansible deployment are not
implemented yet.** Current output is local terminal output and files. No prompts
or source contents are collected by SAGA; an agent's own terminal output is
outside SAGA's log redaction.

## Documentation and contributing

- [Coding-agent configuration, controls and integrations](docs/coding-agent.md)
- [Docker installation, operation and acceptance check](docs/docker-observer.md)
- [Reproducible shell demo](examples/DEMO.md)
- [Contributing, tests and release process](CONTRIBUTING.md)
- [Private vulnerability reporting and security boundaries](SECURITY.md)

Report ordinary bugs through [Issues](https://github.com/odbgrowth/saga-watchdog/issues).
Use [private reporting](https://github.com/odbgrowth/saga-watchdog/security/advisories/new)
for security vulnerabilities. Keep credentials and customer data out of public
reports.

## License

[Apache License 2.0](LICENSE).
