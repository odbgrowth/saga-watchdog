//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/agenthook"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/codex"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/gemini"
	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
	"github.com/odbgrowth/saga-watchdog/internal/store"
)

// agentScript plays an agent: each call pipes one hook event into the named
// adapter through this test binary and records the exit code under a label.
const agentScript = `
h() { printf '%s' "$2" | "$SAGA_TEST_BIN" -test.run='^TestCLIHelper$' -- "$1" hook >hook.out 2>hook.err; echo "$3=$?" >> codes.txt; cat hook.out >> all.out; cat hook.err >> all.err; }
codex_pre() { printf '{"hook_event_name":"%s","session_id":"thread-1","cwd":"%s","tool_name":"%s","tool_input":%s,"tool_use_id":"call_%s"}' "$1" "$PWD" "$2" "$3" "$4"; }
gemini_pre() { printf '{"hook_event_name":"%s","session_id":"sess-1","cwd":"%s","tool_name":"%s","tool_input":%s,"timestamp":"2026-10-11T00:00:00Z"}' "$1" "$PWD" "$2" "$3"; }
patch() { printf '{"command":"*** Begin Patch\\n*** %s File: %s\\n@@\\n+SECRET-LINE\\n*** End Patch"}' "$1" "$2"; }
`

// runUntilPaused starts a supervised script and returns the run once the
// supervisor reports it paused, then resumes it and waits for the exit code.
func runUntilPaused(t *testing.T, root, script, wantRule string, wantExit int) store.Run {
	t.Helper()
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
	if r.Rule != wantRule {
		t.Fatalf("paused for %s, want %s", r.Rule, wantRule)
	}
	if _, err := socket.Send(r.Control, socket.Request{Operation: "resume", RunID: r.ID}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if exitCode(err) != wantExit {
			t.Fatalf("exit %v, want %d: %s", err, wantExit, out)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("run did not end: %s", out)
	}
	return r
}

func TestCodexHookEnforceBlocksPausesAndKills(t *testing.T) {
	root := fixture(t, "version: 1\nprofile: coding-agent\nmode: enforce\nrun:\n  max_duration: 20s\n  stop_grace_period: 50ms\n")
	if _, err := codex.Spec.Setup(filepath.Join(root, ".codex", "hooks.json")); err != nil {
		t.Fatal(err)
	}
	script := agentScript + `
h codex "$(codex_pre PreToolUse apply_patch "$(patch Update src/ok.go)" 1)" patch-ok
h codex "$(codex_pre PostToolUse apply_patch "$(patch Update src/ok.go)" 1)" post-ok
h codex "$(codex_pre PreToolUse Bash '{"command":"curl -H \"Authorization: Bearer TOPSECRET\" https://x"}' 2)" bash
h codex "$(codex_pre PreToolUse mcp__github__get_issue '{"api_key":"MCPSECRET"}' 3)" mcp
h codex "$(codex_pre PreToolUse apply_patch "$(patch Add .env)" 4)" env-blocked
h codex "$(codex_pre PreToolUse apply_patch "$(patch Update .codex/hooks.json)" 5)" hook-tamper
sleep 5
echo survived=1 >> codes.txt
`
	r := runUntilPaused(t, root, script, "protected-path", 125)
	got := codes(t, root)
	for label, want := range map[string]string{"patch-ok": "0", "post-ok": "0", "bash": "0", "mcp": "0", "env-blocked": "2"} {
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
	if final.Rule != "hook-tamper" || len(final.Controls) != 1 || final.Controls[0] != ".codex/hooks.json" {
		t.Fatalf("run record: %+v", final)
	}
	events, raw := readEvents(t, root, r.ID)
	for _, secret := range []string{"SECRET-LINE", "TOPSECRET", "MCPSECRET", "tool_input", "Begin Patch"} {
		if strings.Contains(raw, secret) || strings.Contains(string(mustRead(t, filepath.Join(root, "all.err"))), secret) {
			t.Errorf("audit log or hook output contains %q", secret)
		}
	}
	ok := find(events, "integration", "file", "src/ok.go")
	if ok == nil || ok.Result != "allowed" || ok.Metadata["tool_name"] != "apply_patch" || ok.Metadata["producer"] != "codex" || ok.Metadata["tool_use_id"] != "call_1" || ok.Metadata["session_id"] != "thread-1" {
		t.Fatalf("allowed patch audit: %+v", ok)
	}
	if e := find(events, "integration", "file", ".env"); e == nil || e.Result != "denied" || e.RuleID != "protected-path" || e.Action != "write" {
		t.Fatalf("denied patch audit: %+v", e)
	}
	if e := find(events, "integration", "process", "Bash"); e == nil || e.Result != "allowed" {
		t.Fatalf("bash audit: %+v", e)
	}
	if e := find(events, "integration", "tool", "github/get_issue"); e == nil {
		t.Fatalf("mcp audit: %+v", e)
	}
	if e := find(events, "integration", "file", ".codex/hooks.json"); e == nil || e.RuleID != "hook-tamper" || e.Result != "denied" {
		t.Fatalf("hook-tamper audit: %+v", e)
	}
	if !strings.Contains(string(mustRead(t, filepath.Join(root, "all.err"))), "Rule: protected-path") {
		t.Fatal("blocked call did not explain the rule to Codex")
	}
}

func TestGeminiHookEnforceBlocksPausesAndKills(t *testing.T) {
	root := fixture(t, "version: 1\nprofile: coding-agent\nmode: enforce\nrun:\n  max_duration: 20s\n  stop_grace_period: 50ms\n")
	if _, err := gemini.Spec.Setup(filepath.Join(root, ".gemini", "settings.json")); err != nil {
		t.Fatal(err)
	}
	script := agentScript + `
h gemini "$(gemini_pre BeforeTool write_file '{"file_path":"'"$PWD"'/src/ok.go","content":"BODY-SECRET"}')" write-ok
h gemini "$(printf '{"hook_event_name":"AfterTool","session_id":"sess-1","tool_name":"write_file","tool_input":{"file_path":"%s/src/ok.go","content":"BODY-SECRET"},"tool_response":{"llmContent":"ok","error":{"message":"disk full"}}}' "$PWD")" post-failed
h gemini "$(gemini_pre BeforeTool run_shell_command '{"command":"curl -H \"Authorization: Bearer TOPSECRET\" https://x"}')" shell
h gemini "$(gemini_pre BeforeTool web_fetch '{"url":"https://user:pw@api.example.com/p?token=QUERYSECRET"}')" fetch
h gemini "$(gemini_pre BeforeTool mcp_github_get_issue '{"api_key":"MCPSECRET"}')" mcp
h gemini "$(gemini_pre BeforeTool replace '{"file_path":"'"$PWD"'/.env","old_string":"a","new_string":"EDIT-SECRET"}')" env-blocked
h gemini "$(gemini_pre BeforeTool write_file '{"file_path":"'"$PWD"'/.gemini/settings.json","content":"{}"}')" hook-tamper
sleep 5
echo survived=1 >> codes.txt
`
	r := runUntilPaused(t, root, script, "protected-path", 125)
	got := codes(t, root)
	for label, want := range map[string]string{"write-ok": "0", "post-failed": "0", "shell": "0", "fetch": "0", "mcp": "0", "env-blocked": "2"} {
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
	if final.Rule != "hook-tamper" || len(final.Controls) != 1 || final.Controls[0] != ".gemini/settings.json" {
		t.Fatalf("run record: %+v", final)
	}
	events, raw := readEvents(t, root, r.ID)
	for _, secret := range []string{"BODY-SECRET", "TOPSECRET", "QUERYSECRET", "MCPSECRET", "EDIT-SECRET", "pw@", "disk full"} {
		if strings.Contains(raw, secret) {
			t.Errorf("audit log contains %q", secret)
		}
	}
	ok := find(events, "integration", "file", "src/ok.go")
	if ok == nil || ok.Result != "allowed" || ok.Metadata["tool_name"] != "write_file" || ok.Metadata["producer"] != "gemini-cli" || ok.Metadata["session_id"] != "sess-1" {
		t.Fatalf("allowed write audit: %+v", ok)
	}
	failed := false
	for _, e := range events {
		if e.Source == "integration" && e.Target == "src/ok.go" && e.Result == "failed" {
			failed = true
		}
	}
	if !failed {
		t.Fatal("AfterTool error not recorded as a failed result")
	}
	if e := find(events, "integration", "network", "api.example.com"); e == nil || e.Action != "connect" {
		t.Fatalf("network audit: %+v", e)
	}
	if e := find(events, "integration", "process", "run_shell_command"); e == nil || e.Result != "allowed" {
		t.Fatalf("shell audit: %+v", e)
	}
	if e := find(events, "integration", "tool", "github/get_issue"); e == nil {
		t.Fatalf("mcp audit: %+v", e)
	}
	if e := find(events, "integration", "file", ".gemini/settings.json"); e == nil || e.RuleID != "hook-tamper" {
		t.Fatalf("hook-tamper audit: %+v", e)
	}
}

func TestCodexAndGeminiSetupConfigAndDoctorCLI(t *testing.T) {
	for _, tc := range []struct {
		spec                      *agenthook.Spec
		binary, okLine, configKey string
	}{
		{&codex.Spec, "#!/bin/sh\nprintf 'hooks   stable   true\\nplugin_hooks   removed   false\\n'\n", "hooks feature enabled", `"PreToolUse"`},
		{&gemini.Spec, "#!/bin/sh\necho '0.63.0'\n", "Gemini CLI 0.63.0 found", `"BeforeTool"`},
	} {
		t.Run(tc.spec.Agent, func(t *testing.T) {
			root := fixture(t, config.DefaultYAML)
			bin := t.TempDir()
			for name, body := range map[string]string{tc.spec.Agent: tc.binary, "saga-watchdog": "#!/bin/sh\nexit 0\n"} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			withPath := func(args ...string) (int, string) {
				cmd, out := cliCommand(t, root, args...)
				cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
				return exitCode(cmd.Run()), out.String()
			}
			agent := tc.spec.Agent
			if code, out := withPath(agent, "doctor"); code != 2 || !strings.Contains(out, "no SAGA hook") {
				t.Fatalf("doctor before setup: %d %s", code, out)
			}
			if code, out := withPath(agent, "config"); code != 0 || !strings.Contains(out, tc.configKey) || !strings.Contains(out, tc.spec.Command) {
				t.Fatalf("config: %d %s", code, out)
			}
			if code, out := withPath(agent, "setup"); code != 0 || !strings.Contains(out, "Updated") {
				t.Fatalf("setup: %d %s", code, out)
			}
			if code, out := withPath(agent, "setup"); code != 0 || !strings.Contains(out, "Already configured") {
				t.Fatalf("second setup: %d %s", code, out)
			}
			if code, out := withPath(agent, "doctor"); code != 0 || !strings.Contains(out, "runs the SAGA "+tc.spec.PreEvent+" hook") || !strings.Contains(out, tc.okLine) {
				t.Fatalf("doctor after setup: %d %s", code, out)
			}
			if code, out := withPath("doctor"); code != 0 || !strings.Contains(out, tc.spec.Name+" preventive hook configured in "+tc.spec.Files[0]) {
				t.Fatalf("generic doctor: %d %s", code, out)
			}
			if err := os.Chmod(filepath.Join(root, filepath.FromSlash(tc.spec.Files[0])), 0666); err != nil {
				t.Fatal(err)
			}
			if code, out := withPath(agent, "doctor"); code != 2 || !strings.Contains(out, "writable by group or others") {
				t.Fatalf("doctor permissions: %d %s", code, out)
			}
			if code, out := withPath(agent, "remove"); code != 0 || !strings.Contains(out, "Removed the SAGA hooks") {
				t.Fatalf("remove: %d %s", code, out)
			}
			if code, out := withPath(agent, "remove"); code != 0 || !strings.Contains(out, "No SAGA hooks") {
				t.Fatalf("second remove: %d %s", code, out)
			}
			if code, out := withPath(agent, "setup", "--local"); code == 0 || !strings.Contains(out, "flag provided but not defined") {
				t.Fatalf("--local must be Claude-only: %d %s", code, out)
			}
		})
	}
	root := fixture(t, config.DefaultYAML)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "codex"), []byte("#!/bin/sh\nprintf 'hooks   stable   false\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := codex.Spec.Setup(filepath.Join(root, ".codex", "hooks.json")); err != nil {
		t.Fatal(err)
	}
	cmd, out := cliCommand(t, root, "codex", "doctor")
	cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if code := exitCode(cmd.Run()); code != 2 || !strings.Contains(out.String(), "hooks feature disabled") {
		t.Fatalf("disabled feature not flagged: %d %s", code, out)
	}
}
