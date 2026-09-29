package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
)

func TestControlsThroughAncestorsAndCustomProtection(t *testing.T) {
	for _, test := range []struct{ target, action, want string }{
		{".git", "write", "pause"}, {".github", "delete", "pause"},
		{".github", "rename", "pause"}, {".", "delete", "kill"},
	} {
		e := New(config.Default(), t.TempDir())
		if d := e.Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: test.action, Target: test.target}); d.Action != test.want {
			t.Errorf("%s %s: %+v, want %s", test.action, test.target, d, test.want)
		}
	}
	cfg := config.Default()
	cfg.Filesystem.Protect = []string{"vendor/reviewed.txt"}
	e := New(cfg, t.TempDir())
	if d := e.Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: "write", Target: "vendor/reviewed.txt"}); d.Action != "pause" {
		t.Fatalf("explicit protection hidden by ignore: %+v", d)
	}
	cfg.Git.ProtectedBranches = []string{"release/**"}
	if d := New(cfg, t.TempDir()).Evaluate(event.Event{Timestamp: epoch, Type: "git", Action: "branch-change", Target: "release/1.0"}); d.Action != "pause" {
		t.Fatalf("branch event/glob not protected: %+v", d)
	}
}

func TestRootAliasAndPolicySymlinkReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "real")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if got, err := Normalize(alias, filepath.Join(alias, "new.go")); err != nil || got != "new.go" {
		t.Fatalf("root alias lost containment: %s, %v", got, err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), filepath.Join(root, config.Filename)); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{config.Filename, filepath.Join(root, config.Filename), filepath.Join(alias, config.Filename)} {
		if d := New(config.Default(), alias).Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: "create", Target: target}); d.Action != "kill" {
			t.Fatalf("policy symlink replacement was not tampering: %+v", d)
		}
	}
}

func TestProtectedSymlinkNamesRetainTheirRules(t *testing.T) {
	for _, tc := range []struct{ path, rule string }{
		{".env", "protected-path"},
		{".git/config", "git-security-modification"},
		{".github/workflows/build.yml", "ci-workflow-modification"},
		{"settings/locked.yml", "protected-path"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			root := t.TempDir()
			ordinary := filepath.Join(root, "ordinary.txt")
			if err := os.WriteFile(ordinary, []byte("ordinary"), 0600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, filepath.FromSlash(tc.path))
			if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(ordinary, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			alias := filepath.Join(t.TempDir(), "project-alias")
			if err := os.Symlink(root, alias); err != nil {
				t.Fatal(err)
			}
			cfg := config.Default()
			cfg.Filesystem.Protect = append(cfg.Filesystem.Protect, "settings/locked.yml")
			cfg.Filesystem.Ignore = []string{"**"}
			for _, target := range []string{tc.path, link, filepath.Join(alias, filepath.FromSlash(tc.path))} {
				for _, action := range []string{"create", "write", "chmod"} {
					d := New(cfg, alias).Evaluate(event.Event{Timestamp: epoch, Type: "file", Action: action, Target: target})
					if d.Action != "pause" || d.RuleID != tc.rule {
						t.Errorf("%s %s: %+v, want pause/%s", action, target, d, tc.rule)
					}
				}
			}
		})
	}
}
