# Observe existing company agents

[Back to the overview](../README.md)

The Docker observer runs beside existing containers. It never creates, starts,
pauses, restarts, stops or removes an agent. It requires neither a Git checkout
nor a session time limit. Stopping or updating SAGA leaves selected containers
running. Automatic intervention and tool/API authorization are not implemented
in this mode.

## What is visible

- Selected container state, restart count and the most recent OOM-killed flag.
- Available Docker healthcheck status. `health: none` means there is no
  healthcheck; a running container is not evidence that its application works.
- Raw memory usage including cache, memory limit, and CPU percentage calculated
  between samples. CPU is absent until there are two valid samples and can
  exceed 100% on multiple cores. Counter resets and a changed restart count
  invalidate the CPU baseline.
- Live lifecycle, OOM and health events. Docker disconnections and reconnects
  are logged. Periodic inspection reconciles the present state after gaps.

No prompts, invoice contents, application logs, healthcheck output, environment
values or arbitrary Docker labels are written to SAGA's status/history. Docker
inspection responses can contain these fields; the client discards them. It
does not observe tool decisions, credential attempts or raw network traffic.
Application action checks need a separate integration.

## Prerequisites and installation

Start on a Linux host with Docker Engine and a local Unix socket. The client
negotiates an API version in the supported range 1.41 through 1.56. Newer daemons
work if they still accept a version in this range; incompatible ranges fail
visibly. Local Unix sockets on macOS can be used for development; the systemd
example targets Linux. Native Windows named pipes, remote Docker endpoints,
Swarm/Kubernetes controllers and automatic replacement discovery are not
supported by this first adapter.

There is no published binary release yet. On a build machine with Git and Go
1.26 or newer, get the source from `main`. For repeatable deployments, check out
the reviewed commit you intend to deploy before building:

```sh
git clone --branch main --single-branch https://github.com/odbgrowth/saga-watchdog.git
cd saga-watchdog
git rev-parse HEAD
target_arch=amd64 # Use arm64 for an ARM server.
revision="$(git rev-parse --short=12 HEAD)"
CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" \
  go build -trimpath -ldflags "-X main.version=dev-$revision" \
  -o saga-watchdog ./cmd/saga-watchdog
tar -czf "saga-watchdog-linux-$target_arch.tar.gz" \
  saga-watchdog README.md SECURITY.md CONTRIBUTING.md LICENSE docs examples deploy
sha256sum "saga-watchdog-linux-$target_arch.tar.gz" > SHA256SUMS
```

On macOS, use `shasum -a 256` instead of `sha256sum`. Transfer the archive and
`SHA256SUMS` to the pilot host using your normal SSH/file-transfer process.
The archive includes the configuration and service files used below; copying
only the binary is not enough for these instructions. On the Linux pilot host,
from the directory containing those two transferred files:

```sh
sha256sum -c SHA256SUMS
mkdir saga-watchdog-install
tar -xzf saga-watchdog-linux-amd64.tar.gz -C saga-watchdog-install
cd saga-watchdog-install
./saga-watchdog version
```

Use the `arm64` archive name on an ARM server. The checksum detects transfer
errors; obtain it from your trusted build machine. Go and a Git checkout are
not needed on the pilot host. Run the remaining installation commands from this
extracted directory. These commands target a systemd-based Linux host with the
`docker` group, `useradd`, `usermod` and `sudo`, such as Ubuntu or Debian.

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
in the current status, not an unbounded time-series database. Email, webhooks and
a dashboard are not implemented; status and history are available locally.

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
later reinstall. For an update, build and transfer the reviewed replacement,
stop this SAGA service, replace its binary, and start the service again. Preserve
the configuration and state directory. This creates an observation gap but does
not stop the agents. Keep the previous binary for rollback.

Automated Ansible rollout and intervention rules are not implemented. The
systemd example still needs validation on your chosen Linux host; CI tests the
observer against Docker, not an installed systemd service.

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
