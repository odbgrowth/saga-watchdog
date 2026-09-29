package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeContainment(t *testing.T) {
	root := t.TempDir()
	for _, target := range []string{"src/main.go", "./src/main.go", filepath.Join(root, "src", "main.go")} {
		got, err := Normalize(root, target)
		if err != nil || got != "src/main.go" {
			t.Errorf("Normalize(%q) = %q, %v", target, got, err)
		}
	}
	for _, target := range []string{"", "../escape", "src/../../escape", "src/../main.go", "..\\escape", filepath.Join(root+"-sibling", "main.go"), "bad\x00path"} {
		if _, err := Normalize(root, target); err == nil {
			t.Errorf("unsafe target %q accepted", target)
		}
	}
}

func TestNormalizeSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, target := range []string{"escape", "escape/new/file", "escape/missing"} {
		if _, err := Normalize(root, target); err == nil {
			t.Errorf("symlink escape accepted: %s", target)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".saga-watchdog.yaml"), []byte("version: 1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, ".saga-watchdog.yaml"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	got, err := Normalize(root, "alias")
	if err != nil || got != ".saga-watchdog.yaml" {
		t.Fatalf("protected alias not resolved: %s, %v", got, err)
	}
	if err := os.Symlink(filepath.Join(outside, "missing"), filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	if _, err := Normalize(root, "dangling/new"); err == nil {
		t.Fatal("dangling symlink accepted")
	}
}

func TestGlobMatchingAndIgnores(t *testing.T) {
	for _, test := range []struct {
		pattern, target string
		want            bool
	}{
		{"**/.env", ".env", true}, {"**/.env", "app/.env", true},
		{".git/hooks/**", ".git/hooks", true}, {".git/hooks/**", ".git/hooks/pre-commit", true},
		{".git/hooks/**", ".git/hooks-elsewhere/x", false}, {".env.*", ".env.local", true},
		{"*.go", "src/main.go", false}, {"**/vendor/**", "a/vendor/b/c", true},
		{"a/**/c", "a/c", true}, {"a/**/c", "a/b/d/c", true}, {"a/**/c", "a/b/d", false},
	} {
		if got := Match(test.pattern, test.target); got != test.want {
			t.Errorf("Match(%s, %s)=%v, want %v", test.pattern, test.target, got, test.want)
		}
	}
	for _, target := range []string{".saga-watchdog.yaml", ".git", ".git/config", ".git/hooks/a", ".github", ".github/workflows/a.yml"} {
		if Ignored(target, []string{"**"}) {
			t.Errorf("control path or ancestor %s hidden by ignore", target)
		}
	}
	if !Ignored("node_modules/a/b", []string{"**/node_modules/**"}) || Ignored("src/main.go", []string{"**/node_modules/**"}) {
		t.Fatal("ordinary ignores are incorrect")
	}
}
