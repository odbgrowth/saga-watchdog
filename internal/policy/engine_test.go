package policy

import (
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
