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
