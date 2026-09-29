package dockerwatch

import (
	"fmt"
	"github.com/odbgrowth/saga-watchdog/internal/event"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJournalLockRotationAndConfigIdentity(t *testing.T) {
	c := testConfig(t)
	j, err := OpenJournal(c.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if other, err := OpenJournal(c.StateDir); err == nil {
		other.Close()
		t.Fatal("two observers acquired the same state")
	}
	j.maxBytes = 350
	for n := 0; n < 30; n++ {
		if err := j.Append(event.Event{Action: fmt.Sprintf("event-%d", n)}); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(filepath.Join(c.StateDir, "events.jsonl*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatal(files)
	}
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 350 {
			t.Fatalf("unbounded log %s: %d", f, info.Size())
		}
	}
	var history strings.Builder
	if err := CopyHistory(c.StateDir, &history); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(history.String(), "event-29") || strings.Contains(history.String(), `"event-0"`) {
		t.Fatal(history.String())
	}
	if err := j.Save(Snapshot{Version: 1, ConfigID: c.ID()}); err != nil {
		t.Fatal(err)
	}
	c.Targets[0].ID = otherID
	if _, err := ReadSnapshot(c); err == nil {
		t.Fatal("wrong configuration accepted")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if err := j.Append(event.Event{}); err == nil {
		t.Fatal("closed log accepted write")
	}
	j, err = OpenJournal(c.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	j.Close()
}

func TestStateRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(dest, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "state")
	if err := os.Symlink(dest, link); err != nil {
		t.Skip(err)
	}
	if j, err := OpenJournal(link); err == nil {
		j.Close()
		t.Fatal("symlink state accepted")
	}
}
