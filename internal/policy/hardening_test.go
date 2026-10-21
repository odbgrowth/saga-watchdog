package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
)

// Scenarios 8 to 13: repository files that make a tool or an editor execute
// something are reviewed, ordinary files are not, the stronger hook rule is
// preserved, and symlinks, renames, ancestors and ignore patterns do not
// bypass the match.
func TestProjectConfigurationChangesPause(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Filesystem.Ignore = []string{"**", ".vscode/**"}
	for _, target := range []string{".mcp.json", ".vscode/mcp.json", ".vscode/tasks.json", filepath.Join(root, ".vscode", "tasks.json")} {
		for _, action := range []string{"write", "create", "delete", "rename", "chmod"} {
			d := New(cfg, root).Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: action, Target: target})
			if d.Action != "pause" || d.RuleID != "project-config-modification" || !Persistable(d) {
				t.Errorf("%s %s: %+v, want pause/project-config-modification", action, target, d)
			}
		}
	}
	for _, target := range []string{"src/main.go", ".vscode/launch.json", ".vscode/settings.json", "mcp.json", "docs/.mcp.json"} {
		if d := New(config.Default(), root).Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: "write", Target: target}); d.Action != "allow" {
			t.Errorf("ordinary file %s escalated: %+v", target, d)
		}
	}
	// Removing or renaming the directory takes the files with it.
	for _, action := range []string{"delete", "rename"} {
		if d := New(cfg, root).Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: action, Target: ".vscode"}); d.Action != "pause" || d.RuleID != "project-config-modification" {
			t.Errorf("%s .vscode: %+v", action, d)
		}
	}
	if d := New(cfg, root).Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: "write", Target: ".vscode"}); d.Action != "allow" {
		t.Errorf("touching the directory entry escalated: %+v", d)
	}
	// An active hook keeps its stronger rule; project configuration stays a
	// review, not tampering.
	hooked := New(cfg, root, ".claude/settings.json")
	if d := hooked.Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: "write", Target: ".claude/settings.json"}); d.Action != "kill" || d.RuleID != "hook-tamper" {
		t.Fatalf("hook tamper weakened: %+v", d)
	}
	if d := hooked.Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: "write", Target: ".mcp.json"}); d.Action != "pause" || d.RuleID != "project-config-modification" {
		t.Fatalf("project config with an active hook: %+v", d)
	}
	// Ignore patterns cannot hide the files or their directory.
	for _, target := range []string{".mcp.json", ".vscode", ".vscode/mcp.json", ".vscode/tasks.json"} {
		if Ignored(target, []string{"**", ".vscode/**", "*.json"}) {
			t.Errorf("%s hidden by ignore", target)
		}
	}
	if !Ignored(".vscode/launch.json", []string{".vscode/**"}) {
		t.Fatal("ordinary editor file is not ignorable")
	}
	// Neither an alias of the file nor the file replaced by a symlink to an
	// ordinary file escapes the rule.
	if err := os.MkdirAll(filepath.Join(root, ".vscode"), 0700); err != nil {
		t.Fatal(err)
	}
	ordinary := filepath.Join(root, "ordinary.json")
	if err := os.WriteFile(ordinary, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ordinary, filepath.Join(root, ".mcp.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".vscode", "tasks.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, ".vscode", "tasks.json"), filepath.Join(root, "alias.json")); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{".mcp.json", "alias.json", filepath.Join(root, "alias.json")} {
		if d := New(cfg, root).Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: "write", Target: target}); d.Action != "pause" || d.RuleID != "project-config-modification" {
			t.Errorf("symlink %s escaped: %+v", target, d)
		}
	}
}

func hardened(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Load("../../examples/hardened-coding-agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Scenarios 14, 17 and 18 at the engine level, with the shipped hardened
// example: read-only tools are allowed, high-impact tools are refused before
// execution, alternative tools share a declared effect, ordinary calls do
// not escalate, and a shell execution is allowed without any claim of
// prevention.
func TestHardenedExampleRestrictsExternalSideEffects(t *testing.T) {
	cfg := hardened(t)
	tool := func(target string) event.Event {
		return event.Event{Timestamp: epoch, Type: "tool", Action: "call", Target: target}
	}
	for target, rule := range map[string]string{
		"github/get_issue": "", "github/list_pull_requests": "", "github/search_code": "", "filesystem/read_file": "",
		"github/create_repository": "tool-unlisted", "github/update_repository": "tool-unlisted", "npm/publish": "tool-unlisted",
		"slack/send_message": "tool-unlisted", "gmail/send_message": "tool-unlisted",
		"browser/submit_form": "tool-unlisted", "vercel/deploy": "tool-unlisted", "github/create_deployment": "tool-unlisted",
		"unknown/service":          "tool-unlisted",
		"github/delete_repository": "tool-denied", "payments/charge": "tool-denied",
	} {
		d := New(cfg, t.TempDir()).Evaluate(tool(target))
		if rule == "" && (d.Action != "allow" || d.RuleID != "") {
			t.Errorf("%s: %+v, want allow", target, d)
		}
		if rule != "" && (d.Action != "pause" || d.RuleID != rule || !Persistable(d)) {
			t.Errorf("%s: %+v, want pause/%s", target, d, rule)
		}
	}
	for target, rule := range map[string]string{"api.github.com": "", "files.pypi.org": "", "unapproved.example": "network-unlisted", "deploy.example.com": "network-denied", "bit.ly": "network-redirector"} {
		d := New(cfg, t.TempDir()).Evaluate(event.Event{Timestamp: epoch, Type: "network", Action: "connect", Target: "https://" + target + "/x"})
		if (rule == "" && d.Action != "allow") || (rule != "" && (d.Action != "pause" || d.RuleID != rule)) {
			t.Errorf("%s: %+v, want %q", target, d, rule)
		}
	}
	e := New(cfg, t.TempDir())
	for target, want := range map[string]string{"github/create_repository": "public.publish", "npm/publish": "public.publish", "slack/post_message": "external.message", "playwright/click": "external.form", "vercel/deploy": "production.deploy", "github/get_issue": ""} {
		got := e.Effects(tool(target))
		if (want == "" && len(got) != 0) || (want != "" && (len(got) != 1 || got[0] != want)) {
			t.Errorf("effects of %s: %v, want %q", target, got, want)
		}
	}
	if got := e.Effects(event.Event{Type: "network", Target: "https://deploy.example.com/api"}); len(got) != 1 || got[0] != "production.deploy" {
		t.Errorf("network effect: %v", got)
	}
	// Ordinary allowed calls never escalate, and a shell execution is only
	// recorded: no rule, no claim that anything was prevented.
	e = New(cfg, t.TempDir())
	for i, target := range []string{"github/get_issue", "github/list_issues", "filesystem/read_file", "github/search_code", "github/get_pull_request", "filesystem/list_directory"} {
		if d := e.Evaluate(tool(target)); d.Action != "allow" || d.RuleID != "" {
			t.Fatalf("allowed call %d (%s) escalated: %+v", i, target, d)
		}
	}
	for _, shell := range []string{"Bash", "run_shell_command"} {
		if d := e.Evaluate(event.Event{Timestamp: epoch, Type: "process", Action: "execute", Target: shell}); d.Action != "allow" || d.RuleID != "" {
			t.Fatalf("uncovered shell execution got a decision of its own: %+v", d)
		}
	}
	// A denied publication followed by another publication route is the
	// alternative-route pattern inside one run as well.
	e = New(cfg, t.TempDir())
	if d := e.Evaluate(tool("github/create_repository")); d.RuleID != "tool-unlisted" {
		t.Fatalf("%+v", d)
	}
	if d := e.Evaluate(tool("npm/publish")); d.Action != "pause" || d.RuleID != "tool-unlisted" {
		t.Fatalf("alternative publication route: %+v", d)
	}
	// The hardened protect list keeps the mandatory controls and adds its own.
	for target, rule := range map[string]string{".mcp.json": "project-config-modification", ".vscode/launch.json": "protected-path", ".devcontainer/devcontainer.json": "protected-path", "src/main.go": ""} {
		d := New(cfg, t.TempDir()).Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: "write", Target: target})
		if (rule == "" && d.Action != "allow") || (rule != "" && (d.Action != "pause" || d.RuleID != rule)) {
			t.Errorf("%s: %+v, want %q", target, d, rule)
		}
	}
}
