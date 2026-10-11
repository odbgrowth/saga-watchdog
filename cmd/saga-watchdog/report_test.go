//go:build linux || darwin

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/integrations/claudecode"
	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
	"github.com/odbgrowth/saga-watchdog/internal/store"
)

func TestReportSummarizesARun(t *testing.T) {
	root := fixture(t, "version: 1\nmode: enforce\nrun:\n  max_duration: 10s\n  stop_grace_period: 50ms\nnetwork:\n  deny: [blocked.example]\n")
	// A configured hook that never checks in must be called out.
	if _, err := claudecode.Setup(filepath.Join(root, ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}
	r, done, out, send := liveRun(t, root, "sleep 8")
	send("check", socket.Input{Type: "network", Action: "connect", Target: "allowed.example", Producer: "codex", Tool: "Bash"})
	send("check", socket.Input{Type: "network", Action: "connect", Target: "blocked.example", Producer: "codex", Tool: "Bash"})
	// The persisted snapshot lags the supervisor by up to a second; an active
	// run is reported from the live state.
	live, liveOut := cliCommand(t, root, "report")
	if code := exitCode(live.Run()); code != 0 || !strings.Contains(liveOut.String(), "Status    paused") || !strings.Contains(liveOut.String(), "(still running)") {
		t.Fatalf("live report %d: %s", code, liveOut)
	}
	send("resume", socket.Input{})
	send("emit", socket.Input{Type: "file", Action: "write", Target: "a.txt", Result: "success"})
	// A post-action report with a check-like result is still a report: it
	// must neither count as a check nor imply preventive coverage.
	send("emit", socket.Input{Type: "file", Action: "write", Target: "b.txt", Result: "allowed", Producer: "claude-code", Tool: "Edit"})
	send("kill", socket.Input{})
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("kill did not stop run: %s", out)
	}
	cmd, text := cliCommand(t, root, "report")
	if code := exitCode(cmd.Run()); code != 0 {
		t.Fatalf("report exit %d: %s", code, text)
	}
	for _, want := range []string{
		"Run       " + r.ID,
		"Status    killed by watchdog",
		"Hooks     .claude/settings.json",
		"Ended by  human-stop",
		"checks 2 (allowed 1, denied 1); reports 2",
		"pauses 1; kills 1",
		"network-denied",
		"last: blocked.example",
		"network connect blocked.example",
		"codex                checks    2  reports    0",
		"check/emit CLI       checks    0  reports    1",
		"claude-code          checks    0  reports    1",
		"policy pause",
		"operator resume",
		"operator kill",
		"WARNING   .claude/settings.json carried the Claude Code hook but no pre-action check arrived",
	} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	cmd, raw := cliCommand(t, root, "report", "--json", "--run", r.ID)
	if code := exitCode(cmd.Run()); code != 0 {
		t.Fatalf("report --json exit %d: %s", code, raw)
	}
	var rep Report
	if err := json.Unmarshal(raw.Bytes(), &rep); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	if rep.Run.ID != r.ID || rep.Counts.Checks != 2 || rep.Counts.Denied != 1 || rep.Counts.Reports != 2 || len(rep.Rules) != 1 || rep.Rules[0].Rule != "network-denied" || len(rep.Denied) != 1 || rep.Denied[0].Producer != "codex" || len(rep.Warnings) != 1 || len(rep.Timeline) != 3 {
		t.Fatalf("%+v", rep)
	}
	_, final, err := store.Locate(root, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	dir, _, _ := store.Locate(root, r.ID)
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte("not json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if rep, err := buildReport(dir, final); err != nil || len(rep.Warnings) < 1 || rep.Warnings[0] != "audit log contains an unreadable line" {
		t.Fatalf("%v %+v", err, rep.Warnings)
	}
}
