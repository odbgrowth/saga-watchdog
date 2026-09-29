package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/event"
)

func storeFixture(t *testing.T) (string, *Store, Run) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "project")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAGA_WATCHDOG_STATE_DIR", filepath.Join(base, "state"))
	r := Run{ID: "run_20260929_fixture", Project: "fixture", Agent: "test-agent", Status: "running", Mode: "enforce", Started: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC), Warnings: 1}
	s, err := Create(root, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close audit log: %v", err)
		}
	})
	return root, s, r
}

func TestStateMustRemainOutsideProject(t *testing.T) {
	root, _, _ := storeFixture(t)
	for _, dir := range []string{root, filepath.Join(root, "state"), filepath.Join(root, "nested", "state")} {
		t.Setenv("SAGA_WATCHDOG_STATE_DIR", dir)
		if _, err := Prepare(root); err == nil {
			t.Errorf("accepted state inside project: %s", dir)
		}
	}
	out := t.TempDir()
	t.Setenv("SAGA_WATCHDOG_STATE_DIR", out)
	if _, err := Prepare(root); err != nil {
		t.Fatalf("outside state rejected: %v", err)
	}
}

func TestStateAliasCannotPlaceAuditFilesInsideProject(t *testing.T) {
	root, _, _ := storeFixture(t)
	alias := filepath.Join(t.TempDir(), "state-alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	t.Setenv("SAGA_WATCHDOG_STATE_DIR", alias)
	if _, err := Prepare(root); err == nil {
		t.Fatal("state symlink into watched project was accepted")
	}
}

func TestRunIDsRejectTraversalAndCreateDoesNotOverwrite(t *testing.T) {
	root, s, r := storeFixture(t)
	if !ValidID(r.ID) {
		t.Fatal("valid generated-style run ID rejected")
	}
	for _, id := range []string{"", "run_", "../run_escape", "run_../escape", "run_foo/bar", `run_foo\bar`, "/tmp/run_escape", "run_" + strings.Repeat("x", 100)} {
		if ValidID(id) {
			t.Errorf("unsafe run ID accepted: %q", id)
		}
		bad := r
		bad.ID = id
		if _, err := Create(root, bad); err == nil || !strings.Contains(err.Error(), "invalid run ID") {
			t.Errorf("Create(%q) did not reject invalid ID: %v", id, err)
		}
		if id != "" {
			if _, _, err := Locate(root, id); err == nil || !strings.Contains(err.Error(), "invalid run ID") {
				t.Errorf("Locate(%q) did not reject invalid ID: %v", id, err)
			}
		}
	}
	if err := s.Append(event.Event{ID: "existing", Type: "process", Action: "start", Target: "test-agent"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(s.Dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(root, r); err == nil {
		t.Fatal("existing run was overwritten")
	}
	after, err := os.ReadFile(filepath.Join(s.Dir, "events.jsonl"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("duplicate Create altered audit history: %v", err)
	}
}

func TestJSONLAuditRedactsSecretsAndKeepsPrivatePermissions(t *testing.T) {
	_, s, r := storeFixture(t)
	input := event.Event{
		ID: "event_one", RunID: r.ID, Source: "integration", Type: "network", Action: "connect",
		Target:   "https://fixture-user:fixture-password@example.invalid/path?token=fixture-query-secret",
		Metadata: map[string]any{"reason": "ghp_fixture1234567890123456", "count": 7, "source_code": "UNWANTED_SOURCE_BODY"},
	}
	if err := s.Append(input); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(event.Event{ID: "event_two", RunID: r.ID, Source: "filesystem", Type: "file", Action: "write", Target: "normal.txt"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(s.Dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"fixture-user", "fixture-password", "fixture-query-secret", "ghp_fixture1234567890123456", "UNWANTED_SOURCE_BODY"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("audit log leaked fixture value %q", secret)
		}
	}
	var entries []event.Event
	scan := bufio.NewScanner(bytes.NewReader(b))
	for scan.Scan() {
		var e event.Event
		if err := json.Unmarshal(scan.Bytes(), &e); err != nil {
			t.Fatalf("invalid JSONL record: %v", err)
		}
		entries = append(entries, e)
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].ID != "event_one" || entries[1].ID != "event_two" {
		t.Fatalf("append order or record boundaries lost: %+v", entries)
	}
	if entries[0].Metadata["count"] != float64(7) {
		t.Error("safe diagnostic metadata was lost")
	}
	if input.Metadata["source_code"] != "UNWANTED_SOURCE_BODY" {
		t.Error("Append mutated the producer's event")
	}
	assertPrivateMode(t, s.Dir, 0700)
	assertPrivateMode(t, filepath.Join(s.Dir, "events.jsonl"), 0600)
	assertPrivateMode(t, filepath.Join(s.Dir, "run.json"), 0600)
}

func TestSaveLocateAndFinalSummaryStayComplete(t *testing.T) {
	root, s, r := storeFixture(t)
	stop, done, firstRead := make(chan struct{}), make(chan struct{}), make(chan struct{})
	readErrors := make(chan error, 1)
	go func() {
		defer close(done)
		first := true
		for {
			_, got, err := Locate(root, r.ID)
			if first {
				close(firstRead)
				first = false
			}
			if err != nil || got.Warnings != got.Events+1 {
				readErrors <- fmt.Errorf("reader saw incomplete/inconsistent record: %+v, %v", got, err)
				return
			}
			select {
			case <-stop:
				return
			default:
				runtime.Gosched()
			}
		}
	}()
	<-firstRead
	var saveErr error
	for i := 1; i <= 20; i++ {
		r.Events, r.Warnings = i, i+1
		if saveErr = s.Save(r, false); saveErr != nil {
			break
		}
	}
	close(stop)
	<-done
	if saveErr != nil {
		t.Fatal(saveErr)
	}
	select {
	case err := <-readErrors:
		t.Fatal(err)
	default:
	}
	finished := r.Started.Add(time.Minute)
	r.Status, r.Finished, r.ExitCode = "completed", &finished, 0
	if err := s.Save(r, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(r, true); err != nil {
		t.Fatal(err)
	}
	dir, got, err := Locate(root, "")
	if err != nil || dir != s.Dir || got.Status != "completed" || got.Finished == nil || !got.Finished.Equal(finished) {
		t.Fatalf("final run cannot be located: %+v, %v", got, err)
	}
	manifest, err := os.ReadFile(filepath.Join(s.Dir, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := os.ReadFile(filepath.Join(s.Dir, "summary.json"))
	if err != nil || !bytes.Equal(manifest, summary) {
		t.Fatalf("final summary differs from run manifest: %v", err)
	}
	files, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), ".record-") {
			t.Errorf("temporary record was left behind: %s", f.Name())
		}
	}
	assertPrivateMode(t, filepath.Join(s.Dir, "summary.json"), 0600)
}

func assertPrivateMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %04o, want %04o", path, got, want)
	}
}
