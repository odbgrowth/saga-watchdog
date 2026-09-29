# Observe existing company agents

The Docker observer runs beside existing containers. It never creates, starts,
pauses, restarts, stops or removes an agent. It requires neither a Git checkout
nor a session time limit. Stopping or updating SAGA leaves selected containers
running. This is the first runtime-observation step toward company deployments;
automatic intervention and tool/API authorization are not implemented here.

## What is visible

- Selected container state, restart count and the most recent OOM-killed flag.
- Available Docker healthcheck status. `health: none` means there is no
  healthcheck; a running container is not evidence that its application works.
- Raw memory usage including cache, memory limit, and CPU percentage calculated
  between samples. CPU is absent until there are two valid samples and can
  exceed 100% on multiple cores. Counter resets invalidate the sample.
- Live lifecycle, OOM and health events. Docker disconnections and reconnects
  are logged. Periodic inspection reconciles the present state after gaps.

No prompts, invoice contents, application logs, healthcheck output, environment
values or arbitrary Docker labels are written to SAGA's status/history. Docker
inspection responses can contain these fields; the client discards them. It
does not observe tool decisions, credential attempts or raw network traffic.
Application action checks need a separate integration.

## Prerequisites and installation

Start on a Linux host with Docker Engine and a local Unix socket. The client
negotiates API versions 1.41 through 1.56. Other versions outside this range fail
visibly. Local Unix sockets on macOS can be used for development; the systemd
example targets Linux. Native Windows named pipes, remote Docker endpoints,
Swarm/Kubernetes controllers and automatic replacement discovery are not
supported by this first adapter.

There is no published release containing this feature yet. On a development
machine with Go 1.26+, build from the branch/commit containing this change:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o saga-watchdog ./cmd/saga-watchdog
```

Choose `GOARCH=arm64` for an ARM server. Copy that binary to the pilot host;
Go and the source repository are not needed on the host. When this feature is
released, prefer its versioned archive and verify the published checksum.

One-time administrator setup on a Linux host (adjust an existing service account
instead of creating it again):

```sh
sudo install -m 0755 saga-watchdog /usr/local/bin/saga-watchdog
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin saga-watchdog
sudo usermod -aG docker saga-watchdog
sudo install -d -o root -g saga-watchdog -m 0750 /etc/saga-watchdog
sudo install -d -o saga-watchdog -g saga-watchdog -m 0700 /var/lib/saga-watchdog/docker
sudo install -o root -g saga-watchdog -m 0640 examples/docker-observer.yaml /etc/saga-watchdog/docker.yaml
```

Docker access is administrative access to its daemon. The code only sends GET
requests, but membership of the `docker` group is **not** an OS-enforced read-only
permission. Treat SAGA and this service account as trusted host administration.
Do not give the agent the Docker socket, the service account, or access to
SAGA's configuration/state. A read-only bind mount of a Docker socket does not
restrict which API methods its clients can send.

## Select the existing agent

Obtain the full ID of the intended container without restarting it:

```sh
docker inspect --format '{{.Id}}' YOUR_EXISTING_AGENT_CONTAINER
sudoedit /etc/saga-watchdog/docker.yaml
```

Replace `REPLACE_WITH_FULL_CONTAINER_ID` and choose a local display name. Configure
up to 32 targets with unique names and full 64-character IDs. Names and short
IDs are deliberately rejected as selectors. After a deployment replaces a
container, the old ID becomes `missing`; an identically named replacement is
never silently adopted. Verify its identity, update the configuration, then
restart SAGA. Agent containers remain untouched.

Configuration is loaded at startup. Changing it requires restarting SAGA, not
the agents. Unknown YAML keys, duplicate keys, aliases, nulls, invalid bounds and
`mode: enforce` are rejected. The configuration file must be regular and not
writable by group/others. Use a dedicated private state directory on a local
filesystem that supports file locking and atomic rename.

Test the configuration and connection first:

```sh
sudo -u saga-watchdog saga-watchdog docker validate --config /etc/saga-watchdog/docker.yaml
sudo -u saga-watchdog saga-watchdog docker watch --config /etc/saga-watchdog/docker.yaml --once
```

`validate` checks the file without connecting to Docker. `--once` writes and
prints a single observation, then exits; it is not ongoing monitoring. It exits
2 if a selected container is missing/unreachable or its requested stats failed.
An unhealthy container can be successfully observed: examine `health` and
`state` rather than treating exit 0 as an application health certificate.

## Run continuously

```sh
sudo install -m 0644 deploy/saga-watchdog-docker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now saga-watchdog-docker
sudo -u saga-watchdog saga-watchdog docker status --config /etc/saga-watchdog/docker.yaml
sudo -u saga-watchdog saga-watchdog docker events --config /etc/saga-watchdog/docker.yaml
```

`status` prints JSON from the last recorded observation. Inspect `observer`,
`event_stream`, each target's `availability`, `observed_at`, `health` and
`stats_error`. A failed request becomes unknown coverage, not a healthy state.
`observer: stale` is calculated by the status command if the heartbeat is older
than `2 × poll_interval + 3 × request_timeout` (35 seconds with defaults).
Stopped or failed observers are identified explicitly; their container fields
are historical observations. Reading `status.json` directly does not perform
this freshness calculation. `status` and `events` exit 0 when they successfully
read their data; that is not a health assertion.

State/health snapshots refresh at the configured polling interval, with bounded
request timeouts. Container requests run concurrently so one unavailable target
does not block all the others indefinitely. Event-stream status is separate from
inspection status: either source can be unavailable. Reconnection uses a bounded
backoff, at most 30 seconds. No complete replay or exactly-once event guarantee
is made; short-lived incidents during a gap can be missed. State/history contain
no interpretation of the agent's motives.

History is local JSONL: `events.jsonl` plus three rotated backups, each at most
10 MiB for the bounded event records. It preserves retained events across SAGA
restarts and records each observer session. `events` prints the retained files
oldest first; concurrent rotation can affect this snapshot. Retention is by
size, not age, and is not an immutable compliance archive. Resource samples are
in the current status, not an unbounded time-series database. There are no remote
notifications in this task.

Only one observer may use a state directory. Each status is bound to its loaded
configuration; a status query with changed configuration reports a mismatch
until SAGA has restarted. Journal/storage failure exits SAGA with an error;
systemd can restart it. A Docker outage is retried without exiting. Neither
case stops or restarts the agents.

To stop observing:

```sh
sudo systemctl disable --now saga-watchdog-docker
```

This stops only SAGA. Keep the configuration and history for inspection or a
later reinstall. Automated Ansible rollout and intervention rules are subsequent
tasks, not capabilities of this observer.

## Reproducible acceptance check

Unit/API tests cover filtering, identity mismatches, connection recovery, missing
targets, health coverage, redaction, bounded history, state locking and stale
status. The opt-in live test creates disposable containers, attaches SAGA,
restarts SAGA, induces a health failure, and replaces a fixture with another
container of the same name. It checks that SAGA never changes the fixture's
running/start-time/restart-count while attaching or shutting down, and never
adopts the replacement. Cleanup addresses only IDs the test created.

On a development machine with Docker and Go:

```sh
docker pull alpine:3.22
SAGA_DOCKER_TEST_SOCKET=/var/run/docker.sock \
SAGA_DOCKER_TEST_IMAGE=alpine:3.22 \
go test -count=1 -run TestDockerIntegration -v ./internal/dockerwatch
```

The image must already exist locally. The test does not pull or enumerate
workloads. Run it on a development/test Docker daemon; it requires container
creation/removal permissions. Ordinary `go test ./...` skips this opt-in check.

References: [Engine API](https://docs.docker.com/reference/api/engine/),
[events](https://docs.docker.com/reference/cli/docker/system/events/),
[stats](https://docs.docker.com/reference/cli/docker/container/stats/),
[Docker daemon privileges](https://docs.docker.com/engine/security/).
