# Contributing

Keep changes small, deterministic and explainable. The security-critical core
should be understandable by one developer in a short sitting. Discuss larger
changes in an issue before adding a framework, a new service or a dependency.
Security reports belong in the [private reporting channel](SECURITY.md).

## Principles

- **One policy engine.** Rules live in `internal/policy`. An integration
  adapter translates events; it never decides. No adapter-specific rule sets,
  risk scores or allowlists.
- **Deterministic decisions.** The same policy, event and bounded state give
  the same result with a stable rule ID, severity and plain-English reason.
  No LLM, no probabilistic scoring, no intent detection.
- **Evidence classes stay distinct.** Producer reports, filesystem
  observations, process evidence and Docker evidence keep their `source`.
  Do not count correlated events as independent confirmations.
- **Fail closed only where configured.** A deliberately enabled preventive
  integration must never allow an action because SAGA was unavailable.
  Generic supervision does not become universal fail-closed execution.
- **Data minimization.** Record identifiers, paths and hostnames, never
  contents, prompts, command text, arguments, headers or credentials. New
  metadata keys go through the allowlist in `internal/event` and must be
  bounded scalars.
- **Boring over clever.** Standard library, plain JSON, local sockets, small
  data structures, bounded state.

## Build and test

Use Linux or macOS with Git and Go 1.26 or newer. From the repository root:

```sh
gofmt -w cmd internal
go vet ./...
go test ./...
go test -race ./...
go build -o saga-watchdog ./cmd/saga-watchdog
```

Tests are required for security behaviour: policy decisions, path
normalization and bypasses, protocol validation, fail-closed paths, data
minimization and lifecycle changes. Do not weaken an existing test to make a
new implementation pass; fix the implementation. CI runs on Linux and macOS,
with a live Docker acceptance test on Linux. Ordinary `go test ./...` skips
that live test unless explicitly configured; see the
[Docker guide](docs/docker-observer.md#reproducible-acceptance-check).

Run the [shell demo](examples/DEMO.md) and the
[Claude Code demo](examples/claude-code.md) for the coding-agent workflows.
Measure the pre-action path with
`SAGA_LATENCY=1 go test -run TestHookLatencyReport -v ./internal/integrations/claudecode`.

### CI jobs

The `CI` workflow runs these jobs in parallel:

- `Go (ubuntu-latest)` and `Go (macos-latest)`: formatting, the release
  reference check, `go vet`, `go test` and `go build`. The Linux job also runs
  `scripts/ci-gate_test.sh`, the self-test of the gate below.
- `Race (ubuntu-latest)` and `Race (macos-latest)`: `go test -race ./...`.
- `Docker acceptance (ubuntu-latest)`: the live Docker observer test against
  disposable containers.
- `ci-gate`: the one check that collects all the others. It needs the test,
  race and Docker acceptance jobs, runs even when one of them failed, and
  fails unless every one of them succeeded. A failed, cancelled, skipped or
  missing job turns it red. This matters because a skipped required check
  counts as passing for the merge, and a matrix with one red leg must never
  pass as green. `scripts/ci-gate.sh` decides; `scripts/ci-gate_test.sh`
  tests it against every result and checks that `ci.yml` keeps the gate wired
  up (the required jobs equal the `needs` of `ci-gate`, and it runs with
  `if: always()`). When you add a job to `ci.yml`, add it to both `needs` and
  `REQUIRED_JOBS` of `ci-gate`; the self-test fails otherwise.

Branch protection matches checks by name, so renaming `ci-gate` or the
`Go (...)` jobs means updating the ruleset on `main` as well.

`ci-gate` also writes a timing table to the run summary: queue time, duration
and result per job, the wall-clock time, the critical path (the longest job)
and the runner seconds (the sum of all job durations). The table is
informational; a problem while writing it never changes the result.

Concurrency: a new push to a pull request cancels the earlier run for that
pull request, and pull requests do not affect each other. A run that is in
progress on `main` or on a pushed `codex/**` branch is never cancelled by a
newer push.

The release workflow is separate and deliberately serial: it runs every check
on the exact commit it publishes.

Measured before the split (median of 20 successful `CI` runs): 102 s
wall-clock. The macOS job took 94 s, of which the Go toolchain download in
`setup-go` took 28 s, `go vet` 2 s, `go test` 23 s, `go test -race` 28 s,
build 2 s and 7 s waiting for a runner. The Ubuntu job took 59 s. Expected
after the split: about 65 to 70 s wall-clock. This is an expectation, not yet
a measurement.

Known limitation: the macOS runner has no Go toolchain cache, so `setup-go`
downloads the toolchain (about 28 s) in every macOS job. Splitting the work
into jobs pays that cost once per job, so it is the lower bound for the
macOS jobs. The extra jobs also add runner time in total, even though the
wall-clock time drops.

## Dependencies

Before adding a dependency, ask whether the standard library or an existing
dependency does the job clearly and safely. Web frameworks, agent SDKs,
policy engines, databases, message brokers, LLM clients, telemetry SDKs and
CLI frameworks need a justification in the pull request.

## Integrations

A new agent integration follows the existing shape: a thin adapter under
`internal/integrations/<agent>/` that parses the agent's structured events
with bounded, typed fields, maps them to the canonical event types (`file`,
`network`, `credential`, `tool`, `policy`, `git`, `process`), sends them
through the existing socket as `check` or `emit`, and translates the answer
back. Document which official agent contract the adapter relies on, with the
version it was verified against, and keep the generic coding-agent guide
independent of any one agent.

## Documentation

All documentation is English. Every documented capability must exist and
every important limitation must be visible. Avoid marketing language and
unsupported security claims. Update the README, the relevant guide and
`SECURITY.md` in the same pull request as a behaviour change.

## Compatibility

Configuration version 1 stays valid. Existing commands (`init`, `validate`,
`doctor`, `run`, `status`, `events`, `pause`, `resume`, `kill`, `check`,
`emit`, `docker ...`) keep working. Deep integrations stay optional; generic
supervision and the Docker observer work without them. Before submitting a
PR, check documentation links, run the relevant demos and target `main`.

## Project structure

```text
cmd/saga-watchdog/              CLI, supervision loop, agent and docker commands
internal/authority/             security context, persistent restrictions, agent instances
internal/config/                strict YAML and built-in profile
internal/event/                 event IDs, redaction and metadata allowlist
internal/policy/                rules, path checks and escalation counters
internal/gitinfo/               Git project and branch queries
internal/supervisor/            owned process lifecycle
internal/sources/               filesystem and local socket sources
internal/integrations/agenthook/   shared hook runner and settings handling
internal/integrations/claudecode/  Claude Code hook adapter
internal/integrations/codex/       Codex CLI hook adapter
internal/integrations/gemini/      Gemini CLI hook adapter
internal/store/                 coding-agent run metadata and JSONL
internal/dockerwatch/           Docker client, observation and bounded history
docs/                           operating guides
examples/                       configurations and demos
deploy/                         Linux service example
.github/workflows/              CI and release automation
```

There is no public Go API or plugin framework.

## Release process

Releases are tagged from `main`; development fixes land on `main` first.
Before tagging a release, maintainers should:

1. Verify that the `ci-gate` check is green on the intended commit: it
   covers the Linux and macOS tests, the race tests and the live Docker
   acceptance test. Try the installation and both demos from a clean
   environment.
2. Verify private vulnerability reporting and review the documented
   limitations.
3. Update the README's release status and installation instructions, and the
   supported-version policy in `SECURITY.md`. CI checks that the three
   references agree, and the Release workflow refuses to tag a version they
   do not name: `scripts/check-release-refs.sh vX.Y.Z` runs the same check.
4. Create a reviewed `vX.Y.Z` tag on the tested commit, or run the Release
   workflow manually (Actions, Release, "Run workflow") with that version:
   it creates the tag on the chosen ref before building.

Pushing such a tag triggers the [release workflow](https://github.com/odbgrowth/saga-watchdog/blob/main/.github/workflows/release.yml).
It runs the checks, then builds Linux and macOS archives for amd64 and arm64,
including documentation, examples and the Linux service file, and publishes
them with `SHA256SUMS` to
[GitHub Releases](https://github.com/odbgrowth/saga-watchdog/releases).
Checksums help detect corruption; they are not an independent signature.

A merge to `main` updates the source; it does not publish binary archives or
install SAGA anywhere.
