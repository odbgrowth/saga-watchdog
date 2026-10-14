package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
)

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestPoliciesAndPrecedence(t *testing.T) {
	for _, mode := range []string{"enforce", "observe"} {
		t.Run(mode, func(t *testing.T) {
			for _, test := range []struct{ target, action, rule string }{
				{"src/main.go", "allow", ""},
				{".saga-watchdog.yaml", "kill", "policy-tamper"},
				{".git/config", "pause", "git-security-modification"},
				{".git/hooks/pre-commit", "pause", "git-security-modification"},
				{".github/workflows/ci.yml", "pause", "ci-workflow-modification"},
				{".env", "pause", "protected-path"}, {"app/.env.production", "pause", "protected-path"},
				{"credentials-local", "pause", "protected-path"}, {"app/secrets.yaml", "pause", "protected-path"},
				{"../outside", "pause", "unsafe-path"},
				{"node_modules/package/.env", "pause", "protected-path"},
			} {
				cfg := config.Default()
				cfg.Mode = mode
				e := New(cfg, t.TempDir())
				d := e.Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: "write", Target: test.target})
				if d.Action != test.action || d.RuleID != test.rule {
					t.Errorf("%s: %+v, want %s/%s", test.target, d, test.action, test.rule)
				}
			}
		})
	}
	cfg := config.Default()
	cfg.Filesystem.Protect = nil
	cfg.Filesystem.Ignore = []string{"**"}
	e := New(cfg, t.TempDir())
	if got := e.Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: "delete", Target: config.Filename}); got.Action != "kill" {
		t.Fatalf("ignore or protect override hid policy tampering: %+v", got)
	}
}

func TestEscalationRepeatedDenials(t *testing.T) {
	e := New(config.Default(), t.TempDir())
	for i, want := range []string{"allow", "warn", "pause", "pause", "kill", "kill"} {
		d := e.Evaluate(event.Event{Timestamp: epoch.Add(time.Duration(i) * time.Second), Type: "network", Action: "connect", Target: "denied.example", Result: "denied"})
		if d.Action != want {
			t.Fatalf("denial %d: %+v, want %s", i+1, d, want)
		}
	}
	if len(e.denials) != config.Default().Escalation.KillAfter {
		t.Fatal("escalation memory is not bounded")
	}
}

func TestTargetHoppingAndCredentialSeeking(t *testing.T) {
	for _, kind := range []string{"network", "credential", "tool"} {
		t.Run(kind, func(t *testing.T) {
			e := New(config.Default(), t.TempDir())
			e.Evaluate(event.Event{Timestamp: epoch, Type: "network", Action: "connect", Target: "a", Result: "denied"})
			for i, want := range []string{"warn", "pause"} {
				d := e.Evaluate(event.Event{Timestamp: epoch.Add(time.Duration(i+1) * time.Second), Type: kind, Action: "attempt", Target: fmt.Sprintf("alternate-%d", i)})
				if d.Action != want {
					t.Fatalf("%s continuation: %+v, want %s", kind, d, want)
				}
			}
		})
	}
}

func TestEscalationWindowAndUnrelatedActions(t *testing.T) {
	e := New(config.Default(), t.TempDir())
	e.Evaluate(event.Event{Timestamp: epoch, Type: "network", Action: "connect", Target: "a", Result: "denied"})
	if d := e.Evaluate(event.Event{Timestamp: epoch.Add(time.Second), Type: "file", Action: "write", Target: "normal.go"}); d.Action != "allow" {
		t.Fatalf("unrelated file write escalated: %+v", d)
	}
	if d := e.Evaluate(event.Event{Timestamp: epoch.Add(120 * time.Second), Type: "credential", Action: "access", Target: "other"}); d.Action != "allow" {
		t.Fatalf("window did not expire: %+v", d)
	}
	if len(e.denials) != 0 {
		t.Fatal("expired history retained")
	}
	if d := e.Evaluate(event.Event{Timestamp: epoch.Add(121 * time.Second), Type: "network", Action: "connect", Target: "b", Result: "denied"}); d.Action != "allow" {
		t.Fatalf("first denial after expiry escalated: %+v", d)
	}
}

func TestMetadataCannotGrantAuthority(t *testing.T) {
	e := New(config.Default(), t.TempDir())
	d := e.Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: "write", Target: config.Filename, Result: "allowed", Severity: "info", RuleID: "allowed-by-model", Metadata: map[string]any{"authorized": true, "ignore_policy": true, "mode": "observe"}})
	if d.Action != "kill" || d.RuleID != "policy-tamper" || d.Severity != "critical" {
		t.Fatalf("producer overrode policy: %+v", d)
	}
}

func TestMassDeletionWindowAndDuplicates(t *testing.T) {
	cfg := config.Default()
	cfg.Filesystem.DeleteThreshold = 2
	e := New(cfg, t.TempDir())
	for _, target := range []string{"a", "a", "b", "node_modules/generated"} {
		if d := e.Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: "delete", Target: target}); d.Action != "allow" {
			t.Fatalf("duplicate/ignored/within-threshold removal escalated: %+v", d)
		}
	}
	if d := e.Evaluate(event.Event{Timestamp: epoch.Add(time.Second), Type: "file", Action: "rename", Target: "c"}); d.Action != "pause" || d.RuleID != "mass-deletion" {
		t.Fatalf("burst not detected: %+v", d)
	}
	if d := e.Evaluate(event.Event{Timestamp: epoch.Add(12 * time.Second), Type: "file", Action: "delete", Target: "d"}); d.Action != "allow" {
		t.Fatalf("deletion window did not expire: %+v", d)
	}
	if len(e.deletions) != 1 {
		t.Fatal("expired deletion history retained")
	}
}

func TestSnapshotAndNetworkPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.Network.Deny = []string{"production.example.com"}
	e := New(cfg, t.TempDir())
	cfg.Network.Deny[0] = "somewhere-else.example"
	cfg.Git.ProtectedBranches[0] = "somewhere-else"
	for _, target := range []string{"PRODUCTION.example.com", "https://production.example.com/private", "production.example.com:443", "production.example.com."} {
		// Independent engine for each check avoids expected denial escalation.
		instance := New(e.cfg, e.root)
		d := instance.Evaluate(event.Event{Timestamp: epoch, Type: "network", Action: "connect", Target: target})
		if d.Action != "pause" || d.RuleID != "network-denied" {
			t.Errorf("denied hostname alias %s: %+v", target, d)
		}
	}
	if d := e.Evaluate(event.Event{Timestamp: epoch, Type: "git", Action: "branch", Target: "main"}); d.Action != "pause" {
		t.Fatal("config mutation expanded effective Git policy")
	}
	if d := New(e.cfg, e.root).Evaluate(event.Event{Timestamp: epoch, Type: "network", Action: "connect", Target: "production.example.com.attacker.test"}); d.Action != "allow" {
		t.Fatal("network policy used suffix rather than exact matching")
	}
}

func TestRelatedFollowUpsCountOncePerTarget(t *testing.T) {
	e := New(config.Default(), t.TempDir())
	at := func(i int) time.Time { return epoch.Add(time.Duration(i) * time.Second) }
	if d := e.Evaluate(event.Event{Timestamp: at(0), Type: "network", Action: "connect", Target: "denied.example", Result: "denied"}); d.Action != "allow" || d.RuleID != "denial-observed" {
		t.Fatalf("first denial: %+v", d)
	}
	// Repeating the same allowed tool is ordinary work; it is counted once.
	for i, want := range []string{"warn", "allow", "allow"} {
		if d := e.Evaluate(event.Event{Timestamp: at(i + 1), Type: "tool", Action: "call", Target: "Bash"}); d.Action != want {
			t.Fatalf("repeated tool %d: %+v, want %s", i, d, want)
		}
	}
	// A different tool target is an alternative and counts.
	if d := e.Evaluate(event.Event{Timestamp: at(5), Type: "tool", Action: "call", Target: "mcp__github__search"}); d.Action != "pause" {
		t.Fatalf("alternate tool: %+v", d)
	}
	// Repeated allowed network use of one host after a network denial counts once.
	e = New(config.Default(), t.TempDir())
	e.Evaluate(event.Event{Timestamp: at(0), Type: "network", Action: "connect", Target: "a", Result: "denied"})
	for i, want := range []string{"warn", "allow", "pause"} {
		target := "b"
		if i == 2 {
			target = "c"
		}
		if d := e.Evaluate(event.Event{Timestamp: at(i + 1), Type: "network", Action: "connect", Target: target}); d.Action != want {
			t.Fatalf("network follow-up %d: %+v, want %s", i, d, want)
		}
	}
	// A repeated denial always counts.
	e = New(config.Default(), t.TempDir())
	for i, want := range []string{"allow", "warn", "pause"} {
		if d := e.Evaluate(event.Event{Timestamp: at(i), Type: "tool", Action: "call", Target: "same", Result: "denied"}); d.Action != want {
			t.Fatalf("repeated denial %d: %+v, want %s", i, d, want)
		}
	}
}

func TestToolDenyPatterns(t *testing.T) {
	cfg := config.Default()
	cfg.Tools.Deny = []string{"github/delete_repository", "payments/*", "*/drop_*"}
	for target, want := range map[string]string{
		"github/delete_repository": "pause", "payments/refund": "pause", "db/drop_table": "pause",
		"github/get_issue": "allow", "FooBar": "allow", "payments": "allow",
	} {
		d := New(cfg, t.TempDir()).Evaluate(event.Event{Timestamp: epoch, Type: "tool", Action: "call", Target: target})
		if d.Action != want || (want == "pause" && d.RuleID != "tool-denied") {
			t.Errorf("%s: %+v, want %s", target, d, want)
		}
	}
	if d := New(cfg, t.TempDir()).Evaluate(event.Event{Timestamp: epoch, Type: "process", Action: "execute", Target: "payments/refund"}); d.Action != "allow" {
		t.Fatalf("tools.deny applied to a non-tool event: %+v", d)
	}
}

func TestAllowListModesAndGrants(t *testing.T) {
	cfg := config.Default()
	cfg.Network.Mode, cfg.Network.Allow, cfg.Network.Deny = "allowlist", []string{"api.github.com", ".pypi.org"}, []string{"files.pypi.org"}
	cfg.Tools.Mode, cfg.Tools.Allow, cfg.Tools.Deny = "allowlist", []string{"github/*"}, []string{"github/delete_repository"}
	network := func(target string) event.Event {
		return event.Event{Timestamp: epoch, Type: "network", Action: "connect", Target: target}
	}
	tool := func(target string) event.Event {
		return event.Event{Timestamp: epoch, Type: "tool", Action: "call", Target: target}
	}
	for name, tc := range map[string]struct {
		ev   event.Event
		rule string
	}{
		"listed host":        {network("https://API.github.com/repos"), ""},
		"suffix apex":        {network("pypi.org"), ""},
		"suffix subdomain":   {network("mirror.pypi.org:443"), ""},
		"unlisted host":      {network("new.example"), "network-unlisted"},
		"lookalike":          {network("api.github.com.attacker.test"), "network-unlisted"},
		"deny wins":          {network("files.pypi.org"), "network-denied"},
		"listed tool":        {tool("github/get_issue"), ""},
		"unlisted tool":      {tool("payments/charge"), "tool-unlisted"},
		"denied listed tool": {tool("github/delete_repository"), "tool-denied"},
	} {
		t.Run(name, func(t *testing.T) {
			d := New(cfg, t.TempDir()).Evaluate(tc.ev)
			if tc.rule == "" && d.Action != "allow" {
				t.Fatalf("%+v", d)
			}
			if tc.rule != "" && (d.Action != "pause" || d.RuleID != tc.rule) {
				t.Fatalf("%+v", d)
			}
		})
	}
	e := New(cfg, t.TempDir())
	grant := func(typeID, target string) bool { _, ok := e.Grant(typeID, target); return ok }
	if !grant("network", "https://NEW.example/x") || !grant("tool", "payments/charge") || grant("file", "x") || grant("network", "") {
		t.Fatal("grant acceptance")
	}
	if added, ok := e.Grant("network", "new.example"); added || !ok {
		t.Fatalf("duplicate grant must be a successful no-op: %t %t", added, ok)
	}
	if d := e.Evaluate(network("new.example")); d.Action != "allow" {
		t.Fatalf("granted host still blocked: %+v", d)
	}
	if d := e.Evaluate(tool("payments/charge")); d.Action != "allow" {
		t.Fatalf("granted tool still blocked: %+v", d)
	}
	if d := e.Evaluate(network("www.new.example")); d.RuleID != "network-unlisted" {
		t.Fatalf("grant must be exact: %+v", d)
	}
	e.Grant("network", "files.pypi.org")
	if d := e.Evaluate(network("files.pypi.org")); d.RuleID != "network-denied" {
		t.Fatalf("grant overrode a deny entry: %+v", d)
	}
	for i := 0; i < maxGrants+5; i++ {
		e.Grant("tool", fmt.Sprintf("srv/tool%d", i))
	}
	if len(e.grants) > maxGrants {
		t.Fatalf("grants unbounded: %d", len(e.grants))
	}
	if _, ok := e.Grant("tool", "srv/late"); ok {
		t.Fatal("grant accepted beyond the bound")
	}
	if _, ok := e.Grant("tool", "srv/tool1"); !ok {
		t.Fatal("existing grant refused at the bound")
	}
	// A retry of the same host in URL form is a repeat, not an alternative target.
	e = New(cfg, t.TempDir())
	e.Evaluate(network("https://new.example/x"))
	if d := e.Evaluate(network("new.example")); d.RuleID != "network-unlisted" || !strings.Contains(d.Reason, "allow list") {
		t.Fatalf("repeat counted as alternative target: %+v", d)
	}
	// Denylist mode is unchanged: unlisted hosts and tools stay allowed.
	cfg.Network.Mode, cfg.Tools.Mode = "denylist", "denylist"
	if d := New(cfg, t.TempDir()).Evaluate(network("new.example")); d.Action != "allow" {
		t.Fatalf("%+v", d)
	}
}

func TestShellFollowUpAndRedirectors(t *testing.T) {
	cfg := config.Default()
	cfg.Network.Deny = []string{"blocked.example"}
	network := func(target string) event.Event {
		return event.Event{Timestamp: epoch, Type: "network", Action: "connect", Target: target}
	}
	shell := event.Event{Timestamp: epoch, Type: "process", Action: "execute", Target: "Bash"}
	e := New(cfg, t.TempDir())
	e.Evaluate(network("blocked.example")) // denial 1
	if d := e.Evaluate(shell); d.Action != "warn" || d.RuleID != "failure-escalation" {
		t.Fatalf("shell after a denial not counted: %+v", d)
	}
	if d := e.Evaluate(shell); d.Action != "allow" {
		t.Fatalf("second shell command counted again: %+v", d)
	}
	if d := e.Evaluate(event.Event{Timestamp: epoch, Type: "tool", Action: "call", Target: "other/tool"}); d.Action != "pause" || d.RuleID != "failure-escalation" {
		t.Fatalf("third signal did not pause: %+v", d)
	}
	// Tool or credential follow-ups do not make the shell eligible again; a
	// new genuine denial does.
	e = New(cfg, t.TempDir())
	e.Evaluate(network("blocked.example"))                                                        // denial 1
	e.Evaluate(shell)                                                                             // 2, counted
	e.Evaluate(event.Event{Timestamp: epoch, Type: "tool", Action: "call", Target: "other/tool"}) // 3, pause
	if d := e.Evaluate(shell); d.RuleID == "failure-escalation" {
		t.Fatalf("shell counted again without a new denial: %+v", d)
	}
	e.Evaluate(network("blocked.example")) // 4, new denial
	if d := e.Evaluate(shell); d.Action != "kill" || d.RuleID != "failure-escalation" {
		t.Fatalf("shell after a new denial not counted: %+v", d)
	}
	cfg.Escalation.ShellFollowUp = false
	e = New(cfg, t.TempDir())
	e.Evaluate(network("blocked.example"))
	if d := e.Evaluate(shell); d.Action != "allow" {
		t.Fatalf("shell counted with shell_follow_up disabled: %+v", d)
	}
	// A shell command without any prior denial is ordinary work.
	if d := New(config.Default(), t.TempDir()).Evaluate(shell); d.Action != "allow" || d.RuleID != "" {
		t.Fatalf("%+v", d)
	}

	for _, target := range []string{"bit.ly", "https://BIT.LY/3x", "api.bit.ly", "tinyurl.com", "t.co:443"} {
		if d := New(config.Default(), t.TempDir()).Evaluate(network(target)); d.Action != "pause" || d.RuleID != "network-redirector" {
			t.Errorf("%s: %+v", target, d)
		}
	}
	for _, target := range []string{"notbit.ly", "bit.ly.example.com", "example.com"} {
		if d := New(config.Default(), t.TempDir()).Evaluate(network(target)); d.Action != "allow" {
			t.Errorf("%s: %+v", target, d)
		}
	}
	allowed := config.Default()
	allowed.Network.Allow = []string{"bit.ly"}
	if d := New(allowed, t.TempDir()).Evaluate(network("bit.ly")); d.Action != "allow" {
		t.Fatalf("explicit allow did not override the redirector list: %+v", d)
	}
	e = New(config.Default(), t.TempDir())
	e.Grant("network", "bit.ly")
	if d := e.Evaluate(network("bit.ly")); d.Action != "allow" {
		t.Fatalf("grant did not override the redirector list: %+v", d)
	}
	off := config.Default()
	off.Network.DenyRedirectors = false
	if d := New(off, t.TempDir()).Evaluate(network("bit.ly")); d.Action != "allow" {
		t.Fatalf("%+v", d)
	}
	denied := config.Default()
	denied.Network.Allow, denied.Network.Deny = []string{"bit.ly"}, []string{"bit.ly"}
	if d := New(denied, t.TempDir()).Evaluate(network("bit.ly")); d.RuleID != "network-denied" {
		t.Fatalf("deny must win over allow: %+v", d)
	}
}

func TestReplicationRules(t *testing.T) {
	cfg := config.Default()
	cfg.Replication = config.Replication{SameHostWorkers: 1, AllowAgents: []string{"claude"}, InferenceEndpoints: []string{"127.0.0.1:8000"}, RemoteHosts: []string{"build-01"}}
	ev := func(typ, action, target, host string, remote bool, runtimeType string) event.Event {
		return event.Event{Timestamp: epoch, Type: typ, Action: action, Target: target, Metadata: map[string]any{"host_id": host, "remote": remote, "runtime_type": runtimeType}}
	}
	for name, tc := range map[string]struct {
		ev           event.Event
		action, rule string
	}{
		"authorized same-host worker":    {ev("agent", "instance.start", "test-runner", "host_l", false, "worker"), "allow", "replication.same_host_workers"},
		"unauthorized autonomous agent":  {ev("agent", "instance.start", "codex", "host_l", false, "agent"), "pause", "unauthorized-agent-replication"},
		"listed agent":                   {ev("agent", "replication.attempt", "claude", "host_l", false, "agent"), "allow", "replication.allow_agents"},
		"unauthorized model server":      {ev("inference", "endpoint.start", "0.0.0.0:8000", "host_l", false, "inference-endpoint"), "pause", "unauthorized-agent-replication"},
		"allowed inference endpoint":     {ev("inference", "endpoint.start", "127.0.0.1:8000", "host_l", false, "inference-endpoint"), "allow", "replication.inference_endpoints"},
		"runtime copy is replication":    {ev("runtime", "copy", "agent-bundle", "host_l", false, "agent"), "pause", "unauthorized-agent-replication"},
		"remote execution unauthorized":  {ev("remote", "execution.attempt", "deploy-agent", "build-02", true, "agent"), "pause", "cross-host-authority-expansion"},
		"remote execution authorized":    {ev("remote", "execution.attempt", "deploy-agent", "build-01", true, "agent"), "allow", "replication.remote_hosts"},
		"agent started on another host":  {ev("runtime", "start", "codex", "build-02", true, "agent"), "kill", "cross-host-authority-expansion"},
		"agent on an authorized host":    {ev("agent", "instance.start", "codex", "build-01", true, "agent"), "allow", "replication.remote_hosts"},
		"unattributed discovered agent":  {ev("agent", "instance.discovered", "rogue", "host_l", false, "agent"), "warn", "unattributed-agent-instance"},
		"local remote.execution is noop": {ev("remote", "execution.attempt", "x", "host_l", false, "agent"), "allow", ""},
	} {
		t.Run(name, func(t *testing.T) {
			d := New(cfg, t.TempDir()).Evaluate(tc.ev)
			got := d.RuleID
			if strings.HasPrefix(tc.rule, "replication.") {
				got = d.Authorization
			}
			if d.Action != tc.action || got != tc.rule {
				t.Fatalf("%+v", d)
			}
		})
	}
	// Remote network traffic alone is not replication.
	if d := New(cfg, t.TempDir()).Evaluate(event.Event{Timestamp: epoch, Type: "network", Action: "connect", Target: "build-02"}); d.Action != "allow" {
		t.Fatalf("network connection treated as replication: %+v", d)
	}
	// The worker budget is per run and per instance: a check and the report
	// that follows it name one worker, and only a stop of a counted worker
	// frees its slot.
	e := New(cfg, t.TempDir())
	worker := ev("agent", "instance.start", "test-runner", "host_l", false, "worker")
	other := ev("agent", "instance.start", "test-runner-2", "host_l", false, "worker")
	report := worker
	report.Result = "success"
	if first, second := e.Evaluate(worker), e.Evaluate(report); first.Action != "allow" || first.Authorization != "replication.same_host_workers" || second.Action != "allow" {
		t.Fatalf("post-action report of a counted worker counted again: %+v %+v", first, second)
	}
	stop := func(target, result string) event.Event {
		s := ev("agent", "instance.stop", target, "host_l", false, "worker")
		s.Result = result
		return s
	}
	e.Evaluate(stop("never-started", "success"))
	if d := e.Evaluate(other); d.RuleID != "unauthorized-agent-replication" {
		t.Fatalf("budget not enforced, or a stop of an uncounted worker freed a slot: %+v", d)
	}
	// Only a successful stop report frees the slot: not the pre-action check
	// of the stop, and not a stop that failed.
	e = New(cfg, t.TempDir())
	e.Evaluate(worker)
	for _, result := range []string{"", "failed", "denied", "blocked"} {
		e.Evaluate(stop("test-runner", result))
		if d := e.Evaluate(other); d.RuleID != "unauthorized-agent-replication" {
			t.Fatalf("stop with result %q freed a live worker's slot: %+v", result, d)
		}
	}
	e = New(cfg, t.TempDir())
	e.Evaluate(worker)
	e.Evaluate(stop("test-runner", "success"))
	if d := e.Evaluate(other); d.Action != "allow" {
		t.Fatalf("stopped worker slot not freed: %+v", d)
	}
	// A self-reported stop frees nothing; a trusted one does.
	e = New(cfg, t.TempDir())
	e.Evaluate(worker)
	claimed := stop("test-runner", "success")
	claimed.Metadata["trust"] = "self-reported"
	e.Evaluate(claimed)
	if d := e.Evaluate(other); d.RuleID != "unauthorized-agent-replication" {
		t.Fatalf("self-reported stop widened the budget: %+v", d)
	}
	claimed.Metadata["trust"] = "trusted-integration"
	e.Evaluate(claimed)
	if d := e.Evaluate(other); d.Authorization != "replication.same_host_workers" {
		t.Fatalf("trusted stop did not free the slot: %+v", d)
	}
	// A failed duplicate start of a worker that already runs keeps the running
	// worker's slot.
	for _, result := range []string{"failed", "denied", "blocked"} {
		e = New(cfg, t.TempDir())
		e.Evaluate(worker)
		e.Evaluate(report)
		e.Evaluate(worker)
		duplicate := worker
		duplicate.Result = result
		e.Evaluate(duplicate)
		if d := e.Evaluate(other); d.RuleID != "unauthorized-agent-replication" {
			t.Fatalf("%s duplicate start freed a running worker's slot: %+v", result, d)
		}
	}
	// A pre-action check marked by the supervisor is never a report, even when
	// a paused run records it as denied.
	e = New(cfg, t.TempDir())
	e.Evaluate(worker)
	e.Evaluate(report)
	pausedCheck := worker
	pausedCheck.Result = "denied"
	pausedCheck.Metadata = map[string]any{"host_id": "host_l", "remote": false, "runtime_type": "worker", "operation": "check"}
	e.Evaluate(pausedCheck)
	if d := e.Evaluate(other); d.RuleID != "unauthorized-agent-replication" {
		t.Fatalf("denied check released a running worker's slot: %+v", d)
	}
	e = New(cfg, t.TempDir())
	e.Evaluate(pausedCheck)
	if d := e.Evaluate(other); d.Authorization != "replication.same_host_workers" {
		t.Fatalf("a check denied by a paused run reserved a slot: %+v", d)
	}
	// A refused worker that starts anyway still occupies budget until its
	// successful stop.
	e = New(cfg, t.TempDir())
	e.Evaluate(worker)
	e.Evaluate(report)
	refused := other
	refused.Result = "success"
	if d := e.Evaluate(refused); d.RuleID != "unauthorized-agent-replication" {
		t.Fatalf("report of a refused worker: %+v", d)
	}
	e.Evaluate(stop("test-runner", "success"))
	third := ev("agent", "instance.start", "test-runner-3", "host_l", false, "worker")
	if d := e.Evaluate(third); d.Authorization == "replication.same_host_workers" {
		t.Fatalf("budget ignored a refused worker that runs: %+v", d)
	}
	e.Evaluate(stop("test-runner-2", "success"))
	if d := e.Evaluate(third); d.Authorization != "replication.same_host_workers" {
		t.Fatalf("slot not freed after the refused worker stopped: %+v", d)
	}
	// The usual refused flow: the check is refused, the report that follows
	// is escalated to kill after that denial, and the worker still counts.
	e = New(cfg, t.TempDir())
	e.Evaluate(worker)
	e.Evaluate(report)
	if d := e.Evaluate(other); d.RuleID != "unauthorized-agent-replication" {
		t.Fatalf("refused check: %+v", d)
	}
	if d := e.Evaluate(refused); d.Action != "kill" {
		t.Fatalf("report after the refusal: %+v", d)
	}
	e.Evaluate(stop("test-runner", "success"))
	if d := e.Evaluate(third); d.Authorization == "replication.same_host_workers" {
		t.Fatalf("a killed-but-running worker left the budget: %+v", d)
	}
	// Workers beyond the tracking bound hold budget for the rest of the run.
	e = New(cfg, t.TempDir())
	for i := range maxWorkers + 1 {
		started := ev("agent", "instance.start", fmt.Sprintf("w-%d", i), "host_l", false, "worker")
		started.Result = "success"
		e.Evaluate(started)
	}
	for i := range maxWorkers {
		e.Evaluate(stop(fmt.Sprintf("w-%d", i), "success"))
	}
	if d := e.Evaluate(third); d.Authorization == "replication.same_host_workers" {
		t.Fatalf("an untracked running worker left the budget: %+v", d)
	}
	// A start that did not happen holds no slot: an isolated failed or denied
	// report takes none, and a failed report after its check releases it.
	for _, result := range []string{"failed", "denied", "blocked"} {
		e = New(cfg, t.TempDir())
		isolated := other
		isolated.Result = result
		e.Evaluate(isolated)
		e.Evaluate(worker)
		failed := worker
		failed.Result = result
		e.Evaluate(failed)
		// The budget authorizes the next worker; the reported failures may
		// still escalate in-run, which is a separate concern.
		if d := e.Evaluate(ev("agent", "instance.start", "test-runner-3", "host_l", false, "worker")); d.Authorization != "replication.same_host_workers" {
			t.Fatalf("%s start kept a slot: %+v", result, d)
		}
	}
	// Unauthorized replication right after a denial is the bypass: kill.
	cfg.Network.Deny = []string{"prod.example.com"}
	e = New(cfg, t.TempDir())
	e.Evaluate(event.Event{Timestamp: epoch, Type: "network", Action: "connect", Target: "prod.example.com"})
	if d := e.Evaluate(ev("agent", "instance.start", "codex", "host_l", false, "agent")); d.Action != "kill" || d.RuleID != "unauthorized-agent-replication" {
		t.Fatalf("replication after denial: %+v", d)
	}
	// Stopping or discovering an instance after a denial reduces or reports
	// authority; it is not an alternative route.
	e = New(cfg, t.TempDir())
	e.Evaluate(event.Event{Timestamp: epoch, Type: "network", Action: "connect", Target: "prod.example.com"})
	for i := range 4 {
		if d := e.Evaluate(ev("agent", "instance.stop", fmt.Sprintf("w%d", i), "host_l", false, "worker")); d.Action != "allow" {
			t.Fatalf("stop after denial escalated: %+v", d)
		}
	}
	if Expansion("agent", "instance.stop") || Expansion("inference", "endpoint.discovered") || !Expansion("runtime", "copy") || !ReplicationType("agent") {
		t.Fatal("expansion classification")
	}
}

func TestEffectsAndSelfClear(t *testing.T) {
	cfg := config.Default()
	cfg.Effects = map[string][]string{"production.deploy": {"network:deploy.example.com", "network:.vercel.com", "tool:vercel/*"}, "secrets.read": {"file:secrets/**"}}
	e := New(cfg, t.TempDir())
	for target, want := range map[string]string{"https://deploy.example.com/v1": "production.deploy", "api.vercel.com": "production.deploy", "pypi.org": ""} {
		got := e.Effects(event.Event{Type: "network", Target: target})
		if (want == "" && len(got) != 0) || (want != "" && (len(got) != 1 || got[0] != want)) {
			t.Errorf("%s: %v", target, got)
		}
	}
	if got := e.Effects(event.Event{Type: "tool", Target: "vercel/deploy"}); len(got) != 1 {
		t.Fatalf("tool effect: %v", got)
	}
	if got := e.Effects(event.Event{Type: "file", Target: "secrets/prod/key.txt"}); len(got) != 1 || got[0] != "secrets.read" {
		t.Fatalf("file effect: %v", got)
	}
	// No event can clear or approve security state.
	for _, action := range []string{"clear", "reset", "approve"} {
		if d := e.Evaluate(event.Event{Timestamp: epoch, Type: "authority", Action: action, Target: "persistent-state"}); d.Action != "pause" || d.RuleID != "authority-self-clear" || !Persistable(d) {
			t.Fatalf("%s: %+v", action, d)
		}
	}
	if Persistable(Decision{Action: "pause", RuleID: "failure-escalation"}) || Persistable(Decision{Action: "warn", RuleID: "network-denied"}) {
		t.Fatal("derived or warning decisions must not persist")
	}
}

// An escalation that replaces a concrete denial names it for persistence,
// without adding it to the protocol.
func TestEscalationNamesTheReplacedDenial(t *testing.T) {
	cfg := config.Default()
	cfg.Network.Deny = []string{"deploy.example.com"}
	e := New(cfg, t.TempDir())
	var d Decision
	for range 5 {
		d = e.Evaluate(event.Event{Timestamp: epoch, Type: "network", Action: "connect", Target: "deploy.example.com"})
	}
	if d.RuleID != "failure-escalation" || d.Action != "kill" || d.Escalates != "network-denied" {
		t.Fatalf("%+v", d)
	}
	if b, _ := json.Marshal(d); strings.Contains(string(b), "network-denied") || strings.Contains(strings.ToLower(string(b)), "escalates") {
		t.Fatalf("escalated rule leaked into the protocol: %s", b)
	}
}
