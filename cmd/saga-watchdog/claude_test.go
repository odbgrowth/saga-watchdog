//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/claudecode"
	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
	"github.com/odbgrowth/saga-watchdog/internal/store"
)

// hookScript lets a supervised shell play Claude Code: each call pipes one
// hook event into `claude hook` through this test binary and records the exit
// code under a label.
const hookScript = `
h() { printf '%s' "$1" | "$SAGA_TEST_BIN" -test.run='^TestCLIHelper$' -- claude hook >hook.out 2>hook.err; echo "$2=$?" >> codes.txt; cat hook.out >> all.out; cat hook.err >> all.err; }
pre() { printf '{"hook_event_name":"PreToolUse","session_id":"sess-1","tool_name":"%s","tool_input":%s,"tool_use_id":"toolu_%s"%s}' "$1" "$2" "$3" "$4"; }
`

func claudeFixture(t *testing.T, mode string) string {
	t.Helper()
	root := fixture(t, "version: 1\nprofile: coding-agent\nmode: "+mode+"\nrun:\n  max_duration: 20s\n  stop_grace_period: 50ms\n")
	if _, err := claudecode.Setup(filepath.Join(root, ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}
	return root
}

func readEvents(t *testing.T, root, id string) ([]event.Event, string) {
	t.Helper()
	dir, _, err := store.Locate(root, id)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var events []event.Event
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var e event.Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	return events, string(data)
}

func find(events []event.Event, source, typ, target string) *event.Event {
	for i := range events {
		if events[i].Source == source && events[i].Type == typ && events[i].Target == target {
			return &events[i]
		}
	}
	return nil
}

func codes(t *testing.T, root string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "codes.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return m
}

func TestClaudeHookEnforceBlocksPausesAndKills(t *testing.T) {
	root := claudeFixture(t, "enforce")
	script := hookScript + `
h "$(pre Write '{"file_path":"'"$PWD"'/src/ok.go","content":"BODY-SECRET"}' 1 '')" write-ok
h "$(printf '{"hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"%s/src/ok.go","content":"BODY-SECRET"},"tool_response":{"ok":true},"tool_use_id":"toolu_1"}' "$PWD")" post-ok
h "$(pre Bash '{"command":"curl -H \"Authorization: Bearer TOPSECRET\" https://x"}' 2 '')" bash
h "$(pre mcp__github__get_issue '{"api_key":"MCPSECRET"}' 3 ',"agent_id":"agent-7","agent_type":"reviewer"')" mcp
h "$(pre WebFetch '{"url":"https://user:pw@api.example.com/p?token=QUERYSECRET"}' 4 '')" fetch
h "$(pre Edit '{"file_path":"'"$PWD"'/.env","old_string":"a","new_string":"EDIT-SECRET"}' 5 ',"agent_id":"agent-7","agent_type":"reviewer"')" env-blocked
h "$(pre Write '{"file_path":"'"$PWD"'/.claude/settings.json","content":"{}"}' 6 '')" hook-tamper
sleep 5
echo survived=1 >> codes.txt
`
	cmd, out := cliCommand(t, root, "run", "--", "bash", "-c", script)
	cmd.Env = append(cmd.Env, "SAGA_TEST_BIN="+os.Args[0])
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var r store.Run
	deadline := time.After(8 * time.Second)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
paused:
	for {
		select {
		case <-deadline:
			t.Fatalf("run never paused: %s", out)
		case err := <-done:
			t.Fatalf("early exit %v: %s", err, out)
		case <-ticker.C:
			_, found, err := store.Locate(root, "")
			if err != nil || found.Control == "" {
				continue
			}
			live, err := socket.Send(found.Control, socket.Request{Operation: "status", RunID: found.ID})
			if err == nil && live.Run != nil && live.Run.Status == "paused" {
				r = *live.Run
				break paused
			}
		}
	}
	if r.Rule != "protected-path" {
		t.Fatalf("paused for %s, want protected-path", r.Rule)
	}
	if _, err := socket.Send(r.Control, socket.Request{Operation: "resume", RunID: r.ID}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if exitCode(err) != 125 {
			t.Fatalf("exit %v, want 125: %s", err, out)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("hook-tamper did not stop the run: %s", out)
	}
	got := codes(t, root)
	// The hook-tamper check returns kill: the supervisor terminates the group,
	// so the script may not live long enough to record that exit code.
	for label, want := range map[string]string{"write-ok": "0", "post-ok": "0", "bash": "0", "mcp": "0", "fetch": "0", "env-blocked": "2"} {
		if got[label] != want {
			t.Errorf("%s exit %q, want %s (%v)", label, got[label], want, got)
		}
	}
	if _, ok := got["survived"]; ok {
		t.Fatal("agent continued after hook-tamper kill")
	}
	_, final, err := store.Locate(root, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Rule != "hook-tamper" || len(final.Controls) != 1 || final.Controls[0] != ".claude/settings.json" {
		t.Fatalf("run record: %+v", final)
	}
	events, raw := readEvents(t, root, r.ID)
	for _, secret := range []string{"BODY-SECRET", "TOPSECRET", "MCPSECRET", "QUERYSECRET", "EDIT-SECRET", "pw@", "tool_input"} {
		if strings.Contains(raw, secret) {
			t.Errorf("audit log contains %q", secret)
		}
	}
	for _, leak := range []string{"BODY-SECRET", "TOPSECRET", "MCPSECRET", "QUERYSECRET", "EDIT-SECRET"} {
		for _, name := range []string{"all.out", "all.err"} {
			if data, _ := os.ReadFile(filepath.Join(root, name)); strings.Contains(string(data), leak) || strings.Contains(out.String(), leak) {
				t.Errorf("%s or terminal output contains %q", name, leak)
			}
		}
	}
	ok := find(events, "integration", "file", "src/ok.go")
	if ok == nil || ok.Result != "allowed" || ok.Metadata["tool_name"] != "Write" || ok.Metadata["producer"] != "claude-code" || ok.Metadata["tool_use_id"] != "toolu_1" || ok.Metadata["session_id"] != "sess-1" {
		t.Fatalf("allowed write audit: %+v", ok)
	}
	env := find(events, "integration", "file", ".env")
	if env == nil || env.Result != "denied" || env.RuleID != "protected-path" || env.Severity != "high" || env.Metadata["agent_id"] != "agent-7" || env.Metadata["agent_type"] != "reviewer" || env.Metadata["decision"] != "pause" {
		t.Fatalf("denied subagent write audit: %+v", env)
	}
	if e := find(events, "integration", "process", "Bash"); e == nil || e.Action != "execute" || e.Result != "allowed" {
		t.Fatalf("bash audit: %+v", e)
	}
	if e := find(events, "integration", "tool", "github/get_issue"); e == nil || e.Metadata["agent_id"] != "agent-7" {
		t.Fatalf("mcp audit: %+v", e)
	}
	if e := find(events, "integration", "network", "api.example.com"); e == nil || e.Action != "connect" {
		t.Fatalf("network audit: %+v", e)
	}
	if e := find(events, "integration", "file", ".claude/settings.json"); e == nil || e.RuleID != "hook-tamper" || e.Severity != "critical" || e.Result != "denied" {
		t.Fatalf("hook-tamper audit: %+v", e)
	}
	if !strings.Contains(string(mustRead(t, filepath.Join(root, "all.err"))), "Rule: protected-path") {
		t.Fatal("blocked call did not explain the rule to Claude")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestClaudeHookObserveModeAndFailClosedPaths(t *testing.T) {
	root := claudeFixture(t, "observe")
	script := hookScript + `
h "$(pre Edit '{"file_path":"'"$PWD"'/.env","old_string":"a","new_string":"b"}' 1 ',"agent_id":"agent-9","agent_type":"custom"')" env-observed
h '{"hook_event_name":"ConfigChange","source":"project_settings","file_path":"'"$PWD"'/.claude/settings.json"}' config-observed
h "$(pre FooBar '{"anything":"ARG-SECRET"}' 2 '')" unknown
h '{"hook_event_name":"ConfigChange","source":"local_settings","file_path":"'"$PWD"'/.claude/settings.local.json"}' local-observed
h "$(pre Write '{"file_path":"'"$PWD"'/sub/../.saga-watchdog.yaml","content":"x"}' 3 '')" policy-observed
SAGA_WATCHDOG_RUN_ID=run_wrong_identifier_0 h "$(pre Write '{"file_path":"'"$PWD"'/a","content":"x"}' 4 '')" wrong-run
SAGA_WATCHDOG_SOCKET=/nonexistent/events.sock h "$(pre Write '{"file_path":"'"$PWD"'/a","content":"x"}' 5 '')" dead-socket
h '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"content":"RAW-SECRET"' malformed
h '{"hook_event_name":"SessionStart","source":"startup"}' unsupported
`
	cmd, out := cliCommand(t, root, "run", "--", "bash", "-c", script)
	cmd.Env = append(cmd.Env, "SAGA_TEST_BIN="+os.Args[0])
	if got := exitCode(cmd.Run()); got != 0 {
		t.Fatalf("observe run exit %d: %s", got, out)
	}
	got := codes(t, root)
	for label, want := range map[string]string{"env-observed": "0", "config-observed": "0", "unknown": "0", "local-observed": "0", "policy-observed": "0", "wrong-run": "2", "dead-socket": "2", "malformed": "2", "unsupported": "0"} {
		if got[label] != want {
			t.Errorf("%s exit %q, want %s", label, got[label], want)
		}
	}
	stderr := string(mustRead(t, filepath.Join(root, "all.err")))
	for _, want := range []string{"does not match", "unavailable", "not valid JSON"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("fail-closed reason %q missing in %s", want, stderr)
		}
	}
	if strings.Contains(stderr, "RAW-SECRET") || strings.Contains(stderr, "ARG-SECRET") {
		t.Fatal("hook stderr echoed payload")
	}
	stdout := string(mustRead(t, filepath.Join(root, "all.out")))
	for _, want := range []string{"observe mode: would pause [protected-path]", "would kill [hook-tamper]", "would pause [agent-config-modification]", "would kill [policy-tamper]"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("observe mode did not report %q: %s", want, stdout)
		}
	}
	events, raw := readEvents(t, root, "")
	if strings.Contains(raw, "ARG-SECRET") || strings.Contains(raw, "RAW-SECRET") {
		t.Fatal("audit log contains tool arguments")
	}
	env := find(events, "integration", "file", ".env")
	if env == nil || env.Result != "allowed" || env.Metadata["decision"] != "pause" || env.Metadata["mode"] != "observe" || env.RuleID != "protected-path" || env.Metadata["agent_id"] != "agent-9" {
		t.Fatalf("observe audit: %+v", env)
	}
	if e := find(events, "integration", "file", ".claude/settings.json"); e == nil || e.Metadata["decision"] != "kill" || e.RuleID != "hook-tamper" || e.Result != "allowed" {
		t.Fatalf("config change audit: %+v", e)
	}
	if e := find(events, "integration", "file", ".claude/settings.local.json"); e == nil || e.Metadata["decision"] != "pause" || e.RuleID != "agent-config-modification" || e.Result != "allowed" {
		t.Fatalf("local settings change audit: %+v", e)
	}
	// An unknown tool after a denial is the documented "alternate tool"
	// follow-up: the second related event warns, the call itself is allowed.
	if e := find(events, "integration", "tool", "FooBar"); e == nil || e.Action != "call" || e.Result != "allowed" || e.Metadata["decision"] != "warn" || e.RuleID != "failure-escalation" {
		t.Fatalf("unknown tool audit: %+v", e)
	}
	if !strings.Contains(stdout, "warning [failure-escalation]") {
		t.Fatalf("warning not surfaced to the operator: %s", stdout)
	}
	// The absolute traversal path is evaluated as submitted and recorded by
	// its project-relative name.
	if e := find(events, "integration", "file", ".saga-watchdog.yaml"); e == nil || e.RuleID != "policy-tamper" || e.Metadata["decision"] != "kill" || e.Result != "allowed" {
		t.Fatalf("traversal to policy not evaluated: %+v", e)
	}
	if find(events, "integration", "file", "a") != nil {
		t.Fatal("request with a wrong run ID was recorded")
	}
}

func TestHookConfigChangeIsCaughtAtExit(t *testing.T) {
	root := claudeFixture(t, "enforce")
	// A shell write bypasses the PreToolUse hook; the observer or the exit
	// fingerprint must still report it as hook tampering.
	cmd, out := cliCommand(t, root, "run", "--", "sh", "-c", "printf ' ' >> .claude/settings.json")
	if got := exitCode(cmd.Run()); got != 125 {
		t.Fatalf("exit %d: %s", got, out)
	}
	_, r, err := store.Locate(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Rule != "hook-tamper" {
		t.Fatalf("rule %s: %s", r.Rule, out)
	}
}

func TestSiblingSettingsChangeIsCaughtAtExit(t *testing.T) {
	root := claudeFixture(t, "enforce")
	// The hook lives in settings.json; the sibling can disable it and is
	// fingerprinted as well, so a missed notification still surfaces at exit.
	cmd, out := cliCommand(t, root, "run", "--", "sh", "-c", "printf '{}' > .claude/settings.local.json")
	if got := exitCode(cmd.Run()); got != 125 {
		t.Fatalf("exit %d: %s", got, out)
	}
	_, r, err := store.Locate(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Rule != "agent-config-modification" {
		t.Fatalf("rule %s: %s", r.Rule, out)
	}
}

func TestClaudeSetupConfigAndDoctorCLI(t *testing.T) {
	root := fixture(t, config.DefaultYAML)
	bin := t.TempDir()
	for name, body := range map[string]string{"claude": "#!/bin/sh\necho '2.1.296 (Claude Code)'\n", "saga-watchdog": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	withPath := func(args ...string) (int, string) {
		cmd, out := cliCommand(t, root, args...)
		cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		return exitCode(cmd.Run()), out.String()
	}
	if code, out := withPath("claude", "doctor"); code != 2 || !strings.Contains(out, "no SAGA hook") {
		t.Fatalf("doctor before setup: %d %s", code, out)
	}
	if code, out := withPath("claude", "config"); code != 0 || !strings.Contains(out, `"PreToolUse"`) {
		t.Fatalf("config: %d %s", code, out)
	}
	if code, out := withPath("claude", "setup"); code != 0 || !strings.Contains(out, "Updated") {
		t.Fatalf("setup: %d %s", code, out)
	}
	if code, out := withPath("claude", "setup"); code != 0 || !strings.Contains(out, "Already configured") {
		t.Fatalf("second setup: %d %s", code, out)
	}
	if code, out := withPath("claude", "doctor"); code != 0 || !strings.Contains(out, "runs the SAGA PreToolUse hook with onFailure: block") || !strings.Contains(out, "2.1.296 supports") {
		t.Fatalf("doctor after setup: %d %s", code, out)
	}
	if code, out := withPath("doctor"); code != 0 || !strings.Contains(out, "Claude Code preventive hook configured") {
		t.Fatalf("generic doctor: %d %s", code, out)
	}
	if err := os.Chmod(filepath.Join(root, ".claude", "settings.json"), 0666); err != nil {
		t.Fatal(err)
	}
	if code, out := withPath("claude", "doctor"); code != 2 || !strings.Contains(out, "writable by group or others") {
		t.Fatalf("doctor permissions: %d %s", code, out)
	}
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\necho '2.0.9 (Claude Code)'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, out := withPath("claude", "doctor"); !strings.Contains(out, "predates") {
		t.Fatalf("old version not flagged: %s", out)
	}
	if code, out := withPath("claude", "setup", "--local"); code != 0 || !strings.Contains(out, "settings.local.json") {
		t.Fatalf("local setup: %d %s", code, out)
	}
}

func TestUnattendedRunDeniesWithoutStopping(t *testing.T) {
	root := fixture(t, "version: 1\nprofile: coding-agent\nmode: enforce\nrun:\n  max_duration: 20s\n  stop_grace_period: 50ms\n  unattended: true\n")
	if _, err := claudecode.Setup(filepath.Join(root, ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}
	script := hookScript + `
h "$(pre Edit '{"file_path":"'"$PWD"'/.env","old_string":"a","new_string":"b"}' 1 '')" env-blocked
echo alive=1 >> codes.txt
h "$(pre Write '{"file_path":"'"$PWD"'/src/ok.go","content":"x"}' 2 '')" after-pause
`
	cmd, out := cliCommand(t, root, "run", "--", "bash", "-c", script)
	cmd.Env = append(cmd.Env, "SAGA_TEST_BIN="+os.Args[0])
	if got := exitCode(cmd.Run()); got != 0 {
		t.Fatalf("unattended run exit %d: %s", got, out)
	}
	got := codes(t, root)
	for label, want := range map[string]string{"env-blocked": "2", "alive": "1", "after-pause": "2"} {
		if got[label] != want {
			t.Errorf("%s = %q, want %s (%v)", label, got[label], want, got)
		}
	}
	if stderr := string(mustRead(t, filepath.Join(root, "all.err"))); !strings.Contains(stderr, "run is paused") {
		t.Fatalf("later check not denied as paused: %s", stderr)
	}
	if !strings.Contains(out.String(), "Unattended run") {
		t.Fatalf("unattended pause not announced: %s", out)
	}
	_, r, err := store.Locate(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Pauses != 1 || r.Status != "completed" {
		t.Fatalf("run record: %+v", r)
	}
}

func TestClaudeRemoveCLI(t *testing.T) {
	root := fixture(t, config.DefaultYAML)
	run := func(args ...string) (int, string) {
		cmd, out := cliCommand(t, root, args...)
		return exitCode(cmd.Run()), out.String()
	}
	if code, out := run("claude", "setup"); code != 0 {
		t.Fatalf("setup: %d %s", code, out)
	}
	if code, out := run("claude", "remove"); code != 0 || !strings.Contains(out, "Removed the SAGA hooks") {
		t.Fatalf("remove: %d %s", code, out)
	}
	if data := mustRead(t, filepath.Join(root, ".claude", "settings.json")); strings.Contains(string(data), claudecode.Command) {
		t.Fatalf("hook still present: %s", data)
	}
	if code, out := run("claude", "remove"); code != 0 || !strings.Contains(out, "No SAGA hooks") {
		t.Fatalf("second remove: %d %s", code, out)
	}
	if code, out := run("claude", "remove", "--local"); code != 0 || !strings.Contains(out, "No SAGA hooks") {
		t.Fatalf("remove --local on a missing file: %d %s", code, out)
	}
}
