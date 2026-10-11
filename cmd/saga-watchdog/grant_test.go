//go:build linux || darwin

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
	"github.com/odbgrowth/saga-watchdog/internal/store"
)

func TestGrantAuthorizesUnlistedTargetsForOneRun(t *testing.T) {
	root := fixture(t, "version: 1\nmode: enforce\nrun:\n  max_duration: 10s\n  stop_grace_period: 50ms\nnetwork:\n  mode: allowlist\n  allow: [allowed.example]\ntools:\n  mode: allowlist\n  allow: ['github/*']\n")
	r, done, out, send := liveRun(t, root, "sleep 8")
	if d := send("check", socket.Input{Type: "network", Action: "connect", Target: "allowed.example"}); !d.Allowed {
		t.Fatalf("listed host denied: %+v", d)
	}
	unlisted := send("check", socket.Input{Type: "network", Action: "connect", Target: "https://New.Example/path"})
	if unlisted.Allowed || unlisted.Decision.RuleID != "network-unlisted" || !strings.Contains(unlisted.Decision.Reason, "saga-watchdog grant network new.example") {
		t.Fatalf("unlisted host: %+v", unlisted)
	}
	if status := send("status", socket.Input{}); status.Run.Status != "paused" {
		t.Fatalf("not paused: %+v", status)
	}
	// The operator answers with a grant through the CLI, then resumes.
	cmd, text := cliCommand(t, root, "grant", "network", "new.example")
	if code := exitCode(cmd.Run()); code != 0 || !strings.Contains(text.String(), "Grants    network new.example") || !strings.Contains(text.String(), "saga-watchdog resume "+r.ID) {
		t.Fatalf("grant %d: %s", code, text)
	}
	cmd, text = cliCommand(t, root, "grant", "tool", "payments/charge")
	if code := exitCode(cmd.Run()); code != 0 {
		t.Fatalf("tool grant %d: %s", code, text)
	}
	for _, bad := range [][]string{{"grant", "file", "x"}, {"grant", "network"}, {"grant", "network", "a", "b"}} {
		if cmd, _ := cliCommand(t, root, bad...); exitCode(cmd.Run()) == 0 {
			t.Fatalf("accepted %v", bad)
		}
	}
	send("resume", socket.Input{})
	if d := send("check", socket.Input{Type: "network", Action: "connect", Target: "new.example"}); !d.Allowed {
		t.Fatalf("granted host still denied: %+v", *d.Decision)
	}
	if d := send("check", socket.Input{Type: "tool", Action: "call", Target: "payments/charge"}); !d.Allowed {
		t.Fatalf("granted tool still denied: %+v", *d.Decision)
	}
	if d := send("check", socket.Input{Type: "tool", Action: "call", Target: "payments/refund"}); d.Allowed || d.Decision.RuleID != "tool-unlisted" {
		t.Fatalf("other tool allowed: %+v", d)
	}
	send("resume", socket.Input{})
	cmd, text = cliCommand(t, root, "status")
	if code := exitCode(cmd.Run()); code != 0 || !strings.Contains(text.String(), "Grants    network new.example, tool payments/charge") {
		t.Fatalf("status %d: %s", code, text)
	}
	send("kill", socket.Input{})
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("kill did not stop run: %s", out)
	}
	_, final, err := store.Locate(root, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Grants) != 2 {
		t.Fatalf("grants not persisted: %+v", final)
	}
	events, _ := readEvents(t, root, r.ID)
	granted := 0
	for _, e := range events {
		if e.Source == "control" && e.Action == "grant" {
			granted++
		}
	}
	if granted != 2 {
		t.Fatalf("grants not audited: %d", granted)
	}
	cmd, text = cliCommand(t, root, "report")
	if code := exitCode(cmd.Run()); code != 0 || !strings.Contains(text.String(), "operator grant") || !strings.Contains(text.String(), "network-unlisted") {
		t.Fatalf("report %d: %s", code, text)
	}
}
