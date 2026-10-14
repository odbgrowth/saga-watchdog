# Authority across runs, sessions and agent instances

[Back to the overview](../README.md)

An agent must never gain authority by changing its model session, run, tool,
credential, endpoint, route, agent instance, runtime or host. A new technical
execution context is not a new security context. This guide describes how
SAGA Watchdog keeps security history across those changes, how it records
agent instances and replication, and what it cannot see.

## Invariants

1. **Failure never expands authority.** A denial never results in more
   credentials, tools, targets, endpoints, runtimes, agents or machines.
2. **Authority-expansion history survives model sessions.** A new model
   conversation, agent process or run does not erase unresolved restrictions.
3. **Security identity is not model session identity.** Security state is
   keyed by a trusted operator, project and authorization context. Session
   IDs, model names, process IDs and IP addresses never define it.
4. **Authority does not replicate.** If agent A holds capability X, agent B
   started by A does not. B starts with zero implicit authority: no grants,
   no allowances beyond the policy itself.
5. **Every agent instance requires provenance.** An instance without a
   complete trusted chain has provenance `unknown`, and unknown never implies
   trust.
6. **Cross-host execution is a privileged effect.** Starting code, an agent or
   an inference runtime on another host needs explicit authorization.
7. **Model output is never authority.** A model, child agent, memory entry or
   self-reported event cannot clear security history, approve itself, reset
   denial state, authorize another agent or widen permissions.

Restrictions propagate; authority does not.

## Security context

Persistent state belongs to one security context:

| Component | Source | Trusted because |
| --- | --- | --- |
| Operator | `SAGA_WATCHDOG_OPERATOR` when the operator invokes `saga-watchdog`, for example `human:onno` | Set by whoever runs the command; removed from the agent's environment |
| Project | Hash of the canonical project root, computed by Watchdog | Derived, never reported |
| Authorization context | `security_context.authorization_context` in `.saga-watchdog.yaml`, for example `dev-local` | The policy is fixed for a run and changing it during a run stops the run (`policy-tamper`) |

```yaml
security_context:
  authorization_context: dev-local
  retention: 24h          # pause-level restrictions
  serious_retention: 168h # kill-level restrictions
```

```sh
export SAGA_WATCHDOG_OPERATOR=human:onno
saga-watchdog doctor
saga-watchdog run -- claude
```

Same context means a potentially continuous authority trajectory. A
different operator, project or authorization context is a different context,
and nothing correlates across contexts. The authorization context name is not
security by itself; it only selects which restrictions apply. Switching it is
a deliberate operator decision that starts with a clean history, which is why
the agent cannot make that switch: the policy is protected during runs and no
event, socket request or child process can name a context.

When any component is missing, cross-run correlation is **disabled**, not
guessed. `saga-watchdog doctor`, the run banner, `status` and `report` say why:

```text
OK project identity demo (7c1e0f3a9b2d4e61)
! operator identity unavailable (set SAGA_WATCHDOG_OPERATOR=human:<name> when invoking saga-watchdog)
OK authorization context from policy: dev-local
! cross-run authority correlation disabled: operator identity unavailable: ...
```

Existing projects without `security_context` behave exactly as before.

## Persistent restrictions

In enforce mode with a complete context, every pause or kill decision of a
rule that denies a concrete target becomes a **restriction** that outlives
the run: `network-denied`, `network-unlisted`, `network-redirector`,
`tool-denied`, `tool-unlisted`, `protected-path`, `unsafe-path`,
`protected-branch`, `git-security-modification`, `ci-workflow-modification`,
`agent-config-modification`, `hook-tamper`, `policy-tamper`,
`unauthorized-agent-replication`, `cross-host-authority-expansion` and
`authority-self-clear`. Derived decisions (`failure-escalation`,
`run-paused`) and run lifecycle events do not create restrictions. Observe
mode records would-actions but persists nothing.

A restriction holds metadata only: rule, decision, event type, target, the
declared effects it belongs to, the run, event, instance, model session and
host that earned it, timestamps, an attempt count and the 8 most recent
trajectory steps; every step is also in the audit log. A target longer than
256 bytes, or with characters outside printable ASCII, is stored as a prefix
plus a SHA-256 digest of the whole, so it still matches exactly. Never
prompts, chain-of-thought, secrets or contents.

Storage is a JSON file per context in the project's private state directory,
next to its runs (`<state>/<project>/contexts/<context>.json`), written
atomically under a file lock so a parent run and a nested child run can share
it. It holds at most 256 unresolved restrictions. A full state evicts
nothing: a new restriction is refused, the refusal is audited and the run
stops, until expiry or an operator makes room. A file that cannot be read
safely stops the run from starting; it is never silently replaced. If the
state cannot be read or written during a run, the run stops and the event
that met the failure is denied (`authority-state-failed`).

Restrictions end only through:

- **Expiry**: `retention` for pause-level restrictions (default 24h),
  `serious_retention` for kill-level ones (default 7 days).
- **A trusted grant**: `saga-watchdog grant network <host>` or
  `grant tool <id>` resolves restrictions on exactly that target.
- **Operator clearing**: `saga-watchdog authority clear`.
- **A new trusted authorization context** or removing the project's state.

A denial first persisted as a pause and later enforced as a kill, directly or
by escalation, becomes a kill restriction with serious retention; the upgrade
is recorded as `escalated`. Each change is recorded in the context's audit
log. The record is committed together with the state change, so a clear or
expiry whose write fails is never reported as done, and a record the log
could not take stays with the state until the next update writes it.

## Rule: authority-expansion-after-denial

The rule continues a restriction when a later event, in any run of the same
context, is one of:

| Correlation | Example |
| --- | --- |
| Retry of the same target in a new run | `deploy.example.com` denied in run A, retried in run B |
| Alternate route to the same declared effect | `deploy.example.com` denied; `vercel/deploy` tool attempted |
| New agent instance, runtime, endpoint or host after a denial | Agent A denied, then starts agent B |

Each action counts once. A trusted hook's post-action report that mirrors an
allowed pre-action check of the same action within the escalation window is
not counted again; a report without such a check, for example after a
pre-hook failed open or a denied check, is counted.

Effects are how policy declares that different targets reach the same
restricted outcome. Without them only same-target retries and new instances
correlate; an unrelated package download never does.

```yaml
effects:
  production.deploy:
    - network:deploy.example.com
    - network:.vercel.com        # domain and subdomains
    - tool:vercel/*
    - tool:github/create_deployment
```

Decisions: a correlated attempt pauses the run. An authorized new instance in
a restricted context warns (the restrictions apply to it). Unauthorized
replication after a denial is the bypass itself and stops the run. Once a
restriction has seen `escalation.kill_after` attempts in total, including the
original denial, the next one stops the run. The reason names the original
restriction, rule, target, run and time.

Intent is never inferred. Only observable policy facts count, and only within
one trusted context.

## Clearing security state

```sh
saga-watchdog authority status
saga-watchdog authority clear --id rst_... --reason "reviewed: deploy key rotated"
saga-watchdog authority clear --all --reason "new release window"
saga-watchdog authority history
```

Clearing requires the operator identity and a reason, and every cleared
restriction is written to the context audit log as `authority_state.cleared`
with who, which context, the previous restriction, the reason and the time.
Expiry (`expired`), grants (`resolved`), new restrictions (`restricted`) and
trajectory steps (`correlated`) are recorded the same way.

An agent cannot clear its own history. The events socket accepts no clear
operation, and no event type can approve or reset state. Running
`saga-watchdog authority clear` from inside a supervised run is refused and
reported to that run, which pauses with `authority-self-clear`. That attempt
is itself a restriction.

## Agent instances and provenance

Every run is an agent instance. Its record (in `run.json`, the banner,
`status` and `report`) holds:

```json
{
  "instance_id": "agtinst_...",
  "parent_instance_id": "agtinst_...",
  "principal_id": "agent:claude",
  "operator_id": "human:onno",
  "project_id": "7c1e0f3a9b2d4e61",
  "authorization_context_id": "dev-local",
  "context_id": "ctx_...",
  "host_id": "host_3f9a...",
  "run_id": "run_...",
  "artifact_id": "sha256:...",
  "runtime_type": "agent",
  "authorized_by_rule": "replication.allow_agents",
  "provenance": "trusted"
}
```

`host_id` is a hash of the hostname: a label, not an attested machine
identity. `artifact_id` is the SHA-256 of the executable Watchdog started.
Provenance is `trusted` only for an instance Watchdog started itself in a
complete trusted context. Every instance known only from a report or a Docker
observation is `unknown`.

## Agent replication

Starting another autonomous agent or inference runtime is a separate security
effect. These events describe it:

| Event | Meaning |
| --- | --- |
| `agent.instance.start`, `agent.instance.stop`, `agent.instance.discovered` | An agent instance starts, stops or is found |
| `agent.replication.attempt` | An agent tries to create another agent |
| `runtime.deploy`, `runtime.copy`, `runtime.start` | A runtime is deployed, copied or started |
| `inference.endpoint.start`, `inference.endpoint.discovered` | A model server or endpoint starts or is found |
| `remote.execution.attempt` | Code is executed on another host |

They arrive from integrations through `check`/`emit`
(`--type agent --action instance.start --target codex --runtime-type agent
--host build-02`), from nested runs, and from the Docker observer. Nothing is
authorized unless trusted policy lists it:

```yaml
replication:
  same_host_workers: 2                  # worker instances per run
  allow_agents: [claude]                # agent runtimes by identifier (globs)
  inference_endpoints: ['127.0.0.1:8000']
  remote_hosts: [build-01]              # hosts where execution is authorized
```

| Situation | Default |
| --- | --- |
| Unauthorized same-host agent, worker beyond the budget, model server or runtime copy | Pause (`unauthorized-agent-replication`) |
| The same right after a denial | Stop the source run |
| Remote execution on an unlisted host | Pause (`cross-host-authority-expansion`) |
| Agent or runtime created on an unlisted host | Stop the source run (`cross-host-authority-expansion`) |
| Agent instance discovered without known provenance | Warn (`unattributed-agent-instance`) |
| Network traffic to another host | Not replication; network rules apply |

The worker budget counts worker instances, and `allow_agents` never adds
worker slots. Every allowed start check takes a slot, also for a name that
is already running; the report the supervisor pairs with that check
confirms its slot instead of taking another, and only such a paired report
from a trusted integration can release it. A start reported as `failed`, `denied` or `blocked`
did not happen and releases its slot. Only a successful stop report
(`emit --type agent --action instance.stop --result success`) of a counted
worker from a trusted integration frees a slot; the check before a stop, a
failed stop or a self-reported stop does not, so a self-reported worker
holds its slot until the run ends.
A failed report never frees the slot of a worker that already runs. A
worker that policy refused but that reports it started anyway occupies
budget too, until its successful stop. Watchdog tracks up to 256 workers by
name; a refused worker beyond that holds budget until the run ends. The
check of a start and its report also name one instance ID.
Stopping or discovering an instance never counts as an expansion.

Watchdog stops only the run it supervises. It has no remote kill capability.

Ordinary subprocesses are not replication. The supervisor does not classify
processes by executable name (`python`, `node`, `claude`, `codex`): a name is
not evidence, and nothing is stopped because of one. In-runtime subagents
(Claude Code's agent tool, Codex `spawn_agent`) share the run's hook,
restrictions and audit trail and are recorded as tool calls.

### Nested runs

`saga-watchdog run` started from inside a supervised run is a new agent
instance. Before it starts its agent it asks the supervising run, which
evaluates `agent.instance.start` against replication policy:

- Refused: the nested run exits with an error and the supervising run pauses
  (or stops, after a denial).
- Authorized: the supervising run assigns the child its instance ID and
  provenance. The child takes operator and authorization context from that
  trusted answer, never from its own environment, so it shares the context
  and every unresolved restriction. It starts with no grants.

Detection relies on the variables the supervisor sets for its agent. An agent
that removes them can start an unsupervised process; that is the same-user
limit described in [SECURITY.md](../SECURITY.md).

## Authority inheritance

A child agent does not inherit its parent's authority. Run-scoped grants,
allow decisions and tool permissions stay with the parent. The child is
governed by the project policy and by every restriction in the shared
context:

```text
Agent A: deploy.example.com denied     -> restriction in context
Agent A: grant network api.example.com -> A only
Agent A starts Agent B (authorized)
Agent B: deploy.example.com            -> denied (authority-expansion-after-denial)
Agent B: api.example.com               -> not granted to B
```

A new trusted authorization context is the only way to give the work a
different authority envelope, and only the operator can create one.

## Trust levels

Every coding-agent event carries `metadata.trust`:

| Trust | Source |
| --- | --- |
| `observed` | Supervisor, filesystem observer, Git, Docker |
| `trusted-integration` | A configured hook adapter, or a nested saga-watchdog |
| `self-reported` | Any other event on the integration socket |
| `operator` | Control requests: pause, resume, kill, grant |

Self-reported events add evidence. They never establish identity or context,
grant authority, clear state, authorize a child, mark provenance trusted or
resume a run. A kill decision from replication or trajectory evidence that is
only self-reported is capped at pause, and the restriction it leaves is a
pause-level one with pause-level retention.

## Cross-host visibility

A local Watchdog cannot see runtimes created on another machine. It knows
about remote execution only when an integration or a nested run reports it,
and network traffic to another host alone proves nothing. Reliable cross-host
detection needs another trusted signal: a host agent, a runtime integration,
an execution or network broker, or a future SAGA Control Plane.

## Answering the audit questions

For any persistent finding, `saga-watchdog authority status`,
`authority history`, the run's `report` and `events` answer:

- operator, project and authorization context: the context fields and ID;
- the original denial: restriction ID, rule, target, run, event and time;
- runs, model sessions, instances and hosts involved: each trajectory step;
- the alternative route: the correlation (`retry in a new run`,
  `alternate route to effect ...`, `new agent after denial`);
- the policy and why Watchdog intervened: rule ID and reason on the event;
- whether and by whom it was cleared: `authority_state.cleared` with `who`.

## Limitations

- **Same user.** State lives in the operator's private state directory. An
  agent running as the same OS user can delete or edit it, unset the
  variables that mark a nested run, or invoke the CLI with another context.
  This design makes the normal paths (new session, new run, child agent,
  nested run) keep history and makes clearing an audited operator act; it is
  not a tamper-proof boundary. Run agents as a separate OS user when that
  matters.
- **Evidence coverage.** Replication is visible only through nested runs,
  integrations and the Docker observer. Detached processes, remote shells and
  containers started outside those signals are invisible.
- **Effects are declared, not inferred.** Two targets correlate only when the
  policy says they reach the same effect.

## Future architecture (not implemented)

```text
Host Watchdog A
      |
      v
SAGA Control Plane
      |
      v
Host Watchdog B
```

A control plane could later add a global instance registry, fleet-wide
security contexts, signed workload identity and agent provenance, remote
attestation, distributed correlation, fast credential revocation, cross-host
containment and a global incident graph. None of this exists today.
