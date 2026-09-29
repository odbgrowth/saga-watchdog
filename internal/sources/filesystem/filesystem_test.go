package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
	"github.com/odbgrowth/saga-watchdog/internal/gitinfo"
)

func startFixture(t *testing.T, cfg config.Config) (string, *Source, chan event.Event, chan error, context.CancelFunc) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{".git/hooks", ".github/workflows", "vendor"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{config.Filename, ".git/config", ".github/workflows/ci.yml", "vendor/ignored.txt"} {
		writeFixture(t, root, name, "fixture\n")
	}
	ctx, cancel := context.WithCancel(context.Background())
	out, failures := make(chan event.Event, 256), make(chan error, 8)
	gitDir := filepath.Join(root, ".git")
	source, err := Start(ctx, gitinfo.Info{Root: root, GitDir: gitDir, CommonDir: gitDir}, cfg, out, failures)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := source.Close(); err != nil {
			t.Errorf("close watcher: %v", err)
		}
	})
	return root, source, out, failures, cancel
}

func writeFixture(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func awaitFile(t *testing.T, out <-chan event.Event, failures <-chan error, target string) event.Event {
	t.Helper()
	deadline := time.NewTimer(5*time.Second)
	defer deadline.Stop()
	for {
		select {
		case ev := <-out:
			if ev.Target == target {
				if ev.Source != "filesystem" || ev.Type != "file" || ev.Action == "" || ev.Timestamp.IsZero() {
					t.Fatalf("incomplete event: %+v", ev)
				}
				return ev
			}
		case err := <-failures:
			t.Fatalf("watcher failed: %v", err)
		case <-deadline.C:
			t.Fatalf("no event for %s", target)
		}
	}
}

func TestObservedNormalProtectedAndPolicyWrites(t *testing.T) {
	root, _, out, failures, _ := startFixture(t, config.Default())
	for _, target := range []string{"normal.go", ".github/workflows/ci.yml", ".git/config", config.Filename} {
		writeFixture(t, root, target, "changed\n")
		awaitFile(t, out, failures, target)
	}
}

func TestNewDirectoriesAndAtomicReplacement(t *testing.T) {
	root, _, out, failures, _ := startFixture(t, config.Default())
	if err := os.MkdirAll(filepath.Join(root, "new", "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	// Write immediately: either dynamic watches or the new-tree snapshot must
	// report files created before their directory's watch was installed.
	writeFixture(t, root, "new/nested/first.go", "package example\n")
	awaitFile(t, out, failures, "new/nested/first.go")
	writeFixture(t, root, ".policy-replacement", config.DefaultYAML)
	if err := os.Rename(filepath.Join(root, ".policy-replacement"), filepath.Join(root, config.Filename)); err != nil {
		t.Fatal(err)
	}
	awaitFile(t, out, failures, config.Filename)
	if err := os.Remove(filepath.Join(root, "new", "nested", "first.go")); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(5*time.Second)
	defer deadline.Stop()
	for {
		select {
		case ev := <-out:
			if ev.Target == "new/nested/first.go" && ev.Action == "delete" {
				return
			}
		case err := <-failures:
			t.Fatal(err)
		case <-deadline.C:
			t.Fatal("deletion not observed")
		}
	}
}

func TestIgnoredTreesAndMandatoryControls(t *testing.T) {
	root, _, out, failures, _ := startFixture(t, config.Default())
	writeFixture(t, root, "vendor/ignored.txt", "generated\n")
	writeFixture(t, root, "visible.txt", "marker\n")
	deadline := time.NewTimer(5*time.Second)
	defer deadline.Stop()
	observedMarker := false
	for !observedMarker {
		select {
		case ev := <-out:
			if ev.Target == "vendor/ignored.txt" {
				t.Fatal("generated tree was observed despite default ignore")
			}
			observedMarker = ev.Target == "visible.txt"
		case err := <-failures:
			t.Fatal(err)
		case <-deadline.C:
			t.Fatal("visible marker not observed")
		}
	}
	// A broad ignore cannot remove the policy or its mandatory Git/CI controls.
	cfg := config.Default()
	cfg.Filesystem.Protect = nil
	cfg.Filesystem.Ignore = []string{"**"}
	protectedRoot, _, protectedEvents, protectedFailures, _ := startFixture(t, cfg)
	for _, target := range []string{config.Filename, ".git/config", ".github/workflows/ci.yml"} {
		writeFixture(t, protectedRoot, target, "changed\n")
		awaitFile(t, protectedEvents, protectedFailures, target)
	}
}

func TestExplicitProtectionInsideIgnoredTree(t *testing.T) {
	cfg := config.Default()
	cfg.Filesystem.Protect = []string{"vendor/reviewed.txt"}
	root, _, out, failures, _ := startFixture(t, cfg)
	writeFixture(t, root, "vendor/reviewed.txt", "reviewed\n")
	awaitFile(t, out, failures, "vendor/reviewed.txt")
}

func TestCancellationClosesSource(t *testing.T) {
	_, source, _, _, cancel := startFixture(t, config.Default())
	cancel()
	select {
	case <-source.done:
	case <-time.After(5*time.Second):
		t.Fatal("watcher goroutine did not stop after cancellation")
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("repeated close must be harmless: %v", err)
	}
}
