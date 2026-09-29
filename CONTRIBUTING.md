# Contributing

Keep changes small, deterministic and explainable. Discuss larger changes in an
issue before adding a framework, a new service or dependencies. Security reports
belong in the [private reporting channel](SECURITY.md).

## Build and test

Use Linux or macOS with Git and Go 1.26 or newer. From the repository root:

```sh
gofmt -w cmd internal
go vet ./...
go test ./...
go test -race ./...
go build -o saga-watchdog ./cmd/saga-watchdog
```

Add focused regression tests for policy, path, protocol and lifecycle changes.
CI runs on Linux and macOS, with a live Docker acceptance test on Linux. Ordinary
`go test ./...` skips that live test unless explicitly configured; see the
[Docker guide](docs/docker-observer.md#reproducible-acceptance-check).
Use the [shell demo](examples/DEMO.md) to check the coding-agent workflow.

Before submitting a PR, check documentation links, run the relevant examples
and update statements about implemented features. Target `main`. If a PR depends
on an unmerged branch, retarget it to `main` once that dependency merges.

## Project structure

```text
cmd/saga-watchdog/       CLI and supervision loop
internal/config/        strict YAML and built-in profile
internal/event/         event IDs and redaction
internal/policy/        rules, path checks and escalation counters
internal/gitinfo/       Git project and branch queries
internal/supervisor/    owned process lifecycle
internal/sources/       filesystem and local socket sources
internal/store/         coding-agent run metadata and JSONL
internal/dockerwatch/   Docker client, observation and bounded local history
docs/                   operating guides
examples/               configurations and shell demo
deploy/                 Linux service example
.github/workflows/      CI and release automation
```

There is no public Go API or plugin framework.

## Release process

There are currently no published releases. Development fixes target `main`.
Before the first release, maintainers should:

1. Verify Linux/macOS CI and the live Docker acceptance test on the intended
   commit. Try the installation and shell demo from a clean environment.
2. Verify private vulnerability reporting and review the documented limitations.
3. Update the README's development status and installation instructions, and
   the supported-version policy in `SECURITY.md`.
4. Create a reviewed `vX.Y.Z` tag on the tested commit.

Pushing such a tag triggers the [release workflow](https://github.com/odbgrowth/saga-watchdog/blob/main/.github/workflows/release.yml).
It runs the checks, then builds Linux and macOS archives for amd64 and arm64,
including documentation, examples and the Linux service file. It publishes
those archives and `SHA256SUMS` to
[GitHub Releases](https://github.com/odbgrowth/saga-watchdog/releases).
Checksums help detect corruption; they are not an independent signature or audit.

A merge to `main` updates the source; it does not publish binary archives or
install SAGA on a customer server.
