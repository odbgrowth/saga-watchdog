//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/claudecode"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/codex"
	"github.com/odbgrowth/saga-watchdog/internal/store"
)

// hardenedPolicy is the shipped example with a run budget that fits a test.
func hardenedPolicy(t *testing.T, unattended bool) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "hardened-coding-agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(data), "max_duration: 1h", "max_duration: 20s", 1)
	s = strings.Replace(s, "stop_grace_period: 5s", "stop_grace_period: 50ms", 1)
	if unattended {
		s = strings.Replace(s, "unattended: false", "unattended: true", 1)
	}
	if !strings.Contains(s, "max_duration: 20s") || (unattended && !strings.Contains(s, "unattended: true")) {
		t.Fatal("example changed shape; update hardenedPolicy")
	}
	return s
}

// fakeAgents puts stand-ins for the agents and the hook command on PATH. The
// agent executables answer their version or feature query and otherwise run
// their arguments as a shell script, so a supervised "claude -c ..." plays
// Claude Code through the hook script.
func fakeAgents(t *testing.T, claudeVersion string) []string {
	t.Helper()
	bin := t.TempDir()
	for name, body := range map[string]string{
		"claude":        "#!/bin/sh\ncase \"$1\" in --version) echo '" + claudeVersion + " (Claude Code)'; exit 0;; esac\nexec bash \"$@\"\n",
		"codex":         "#!/bin/sh\ncase \"$1\" in features) printf 'hooks   stable   true\\n'; exit 0;; esac\nexec bash \"$@\"\n",
		"gemini":        "#!/bin/sh\ncase \"$1\" in --version) echo '0.63.0'; exit 0;; esac\nexec bash \"$@\"\n",
		"saga-watchdog": "#!/bin/sh\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "SAGA_TEST_BIN=" + os.Args[0]}
}

// Scenarios 1 to 7: run.require_preventive_hook admits only the launched
// agent's own, ready hook and reports every other case as what it is.
func TestRequirePreventiveHookAdmitsOnlyTheMatchingReadyHook(t *testing.T) {
	env := fakeAgents(t, "2.1.296")
	root := fixture(t, hardenedPolicy(t, false))
	refused := func(args []string, wants ...string) {
		t.Helper()
		code, out := runCLI(t, root, env, args...)
		if code != 2 || !strings.Contains(out, "run.require_preventive_hook") {
			t.Fatalf("%v: exit %d, want refusal: %s", args, code, out)
		}
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Errorf("%v: refusal lacks %q: %s", args, want, out)
			}
		}
		if strings.Contains(out, "Starting ") {
			t.Errorf("%v: refusal started the agent: %s", args, out)
		}
	}
	// 3: a known agent without its hook. 4: a generic command cannot be
	// verified and is never called protected.
	refused([]string{"run", "--", "codex", "-c", "true"}, "Codex CLI preventive hook is not ready", "no SAGA hook in .codex/hooks.json")
	refused([]string{"run", "--", "bash", "-c", "true"}, `cannot be verified for "bash"`, "supported agents are claude, codex, gemini", "supervised and observed after the fact only")
	if _, _, err := store.Locate(root, ""); err == nil {
		t.Fatal("a refused run left a run record")
	}
	// 1: Claude with its valid hook starts, and the banner says what the
	// hook covers and how it fails.
	if _, err := claudecode.Setup(filepath.Join(root, ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, root, env, "run", "--", "claude", "-c", "true")
	for _, want := range []string{"Coverage", "Pre-action checks: Claude Code hook in .claude/settings.json", "Hook failure: fail-closed on both sides", "Network: cooperative checks of reported hosts (allowlist mode)", "Authority correlation: this run only", "Starting claude"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("claude with its hook: exit %d, want %q: %s", code, want, out)
		}
	}
	// 2: the Claude hook does not count for Codex or Gemini.
	refused([]string{"run", "--", "codex", "-c", "true"}, "no SAGA hook in .codex/hooks.json")
	refused([]string{"run", "--", "gemini", "-c", "true"}, "Gemini CLI preventive hook is not ready", "no SAGA hook in .gemini/settings.json")
	// 6: a disabled hook, an incompatible agent and a hook that cannot block.
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.local.json"), []byte(`{"disableAllHooks":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	refused([]string{"run", "--", "claude", "-c", "true"}, ".claude/settings.local.json disables hooks")
	if err := os.Remove(filepath.Join(root, ".claude", "settings.local.json")); err != nil {
		t.Fatal(err)
	}
	old := fakeAgents(t, "2.0.9")
	code, out = runCLI(t, root, old, "run", "--", "claude", "-c", "true")
	if code != 2 || !strings.Contains(out, "predates "+claudecode.MinimumVersion) {
		t.Fatalf("old Claude: exit %d: %s", code, out)
	}
	post := `{"hooks":{"PostToolUse":[{"matcher":"` + claudecode.Matcher + `","hooks":[{"type":"command","command":"` + claudecode.Command + `"}]}]}}`
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(post), 0600); err != nil {
		t.Fatal(err)
	}
	refused([]string{"run", "--", "claude", "-c", "true"}, "PreToolUse is missing, uses another matcher or cannot block")
	// 7: Codex runs with its own hook, and neither the banner nor the doctor
	// claims it fails closed on the agent side.
	if _, err := codex.Spec.Setup(filepath.Join(root, ".codex", "hooks.json")); err != nil {
		t.Fatal(err)
	}
	code, out = runCLI(t, root, env, "run", "--", "codex", "-c", "true")
	if code != 0 || !strings.Contains(out, "Pre-action checks: Codex CLI hook in .codex/hooks.json") || !strings.Contains(out, "Codex CLI lets the call proceed when the hook cannot start or times out; not fail-closed on the agent side") || strings.Contains(out, "fail-closed on both sides") {
		t.Fatalf("codex banner: exit %d: %s", code, out)
	}
	code, out = runCLI(t, root, env, "codex", "doctor")
	if code != 0 || !strings.Contains(out, "OK run.require_preventive_hook") || !strings.Contains(out, "not fail-closed on the agent side") || strings.Contains(out, "fail-closed on both sides") || !strings.Contains(out, "Core protection level: LOCAL") {
		t.Fatalf("codex doctor: exit %d: %s", code, out)
	}
	// 5: a legacy policy without the setting runs anything, as before, and
	// 18: the banner says that nothing is prevented without a hook.
	legacy := fixture(t, "version: 1\nprofile: coding-agent\nmode: enforce\nrun:\n  max_duration: 20s\n  stop_grace_period: 50ms\n")
	code, out = runCLI(t, legacy, env, "run", "--", "bash", "-c", "true")
	if code != 0 || !strings.Contains(out, "Pre-action checks: none; without a hook or a cooperative check call nothing is prevented") {
		t.Fatalf("legacy generic run: exit %d: %s", code, out)
	}
	if code, out := runCLI(t, legacy, env, "run", "--", "codex", "-c", "true"); code != 0 || !strings.Contains(out, "Hooks    none") {
		t.Fatalf("legacy codex run without hook: exit %d: %s", code, out)
	}
	if code, out := runCLI(t, legacy, env, "doctor"); code != 0 || strings.Contains(out, "require_preventive_hook") || !strings.Contains(out, "Coverage") {
		t.Fatalf("legacy doctor: exit %d: %s", code, out)
	}
}

// Scenarios 14 to 17 end to end: through the Claude Code hook under the
// hardened example, a read-only MCP tool is allowed, a publication tool is
// refused before execution, and in a later run and model session an
// alternative tool with the same declared effect continues that restriction.
func TestRestrictedToolsAreBlockedBeforeExecutionAndCorrelated(t *testing.T) {
	env := fakeAgents(t, "2.1.296")
	root := fixture(t, hardenedPolicy(t, true))
	t.Setenv("SAGA_WATCHDOG_OPERATOR", "human:onno")
	if _, err := claudecode.Setup(filepath.Join(root, ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}
	first := hookScript + `
h "$(pre mcp__github__get_issue '{"owner":"o","repo":"r"}' 1 '')" read-ok
h "$(pre mcp__github__list_pull_requests '{}' 2 '')" list-ok
h "$(pre Write '{"file_path":"'"$PWD"'/src/ok.go","content":"x"}' 3 '')" write-ok
h "$(pre mcp__github__create_repository '{"name":"leak","private":false}' 4 ',"session_id":"sess-1"')" publish-blocked
`
	code, out := runCLI(t, root, env, "run", "--", "claude", "-c", first)
	if code != 0 {
		t.Fatalf("first run exit %d: %s", code, out)
	}
	got := codes(t, root)
	for label, want := range map[string]string{"read-ok": "0", "list-ok": "0", "write-ok": "0", "publish-blocked": "2"} {
		if got[label] != want {
			t.Errorf("%s exit %q, want %s (%v)", label, got[label], want, got)
		}
	}
	if errs := string(mustRead(t, filepath.Join(root, "all.err"))); !strings.Contains(errs, "Rule: tool-unlisted") || !strings.Contains(errs, "Target: github/create_repository") {
		t.Fatalf("blocked publication not explained to the agent: %s", errs)
	}
	_, runA, err := store.Locate(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if runA.Warnings != 0 || runA.Violations != 1 || runA.Rule != "tool-unlisted" {
		t.Fatalf("ordinary calls escalated or the denial was lost: %+v", runA)
	}
	events, _ := readEvents(t, root, runA.ID)
	if e := find(events, "integration", "tool", "github/get_issue"); e == nil || e.Result != "allowed" || e.RuleID != "" || e.Metadata["trust"] != "trusted-integration" {
		t.Fatalf("read-only tool audit: %+v", e)
	}
	if e := find(events, "integration", "tool", "github/create_repository"); e == nil || e.Result != "denied" || e.RuleID != "tool-unlisted" || e.Metadata["decision"] != "pause" || e.Metadata["operation"] != "check" {
		t.Fatalf("publication audit: %+v", e)
	}
	if code, text := runCLI(t, root, env, "authority", "status"); code != 0 || !strings.Contains(text, "tool-unlisted") || !strings.Contains(text, "github/create_repository") {
		t.Fatalf("restriction not persisted %d: %s", code, text)
	}
	// A new run, a new model session, another publication tool: correlated
	// by the declared effect, not by the tool name.
	if err := os.Remove(filepath.Join(root, "codes.txt")); err != nil {
		t.Fatal(err)
	}
	second := hookScript + `
h "$(pre mcp__npm__publish '{"package":"leak"}' 5 ',"session_id":"sess-2"')" alt-blocked
h "$(pre mcp__github__get_issue '{}' 6 ',"session_id":"sess-2"')" read-after
`
	code, out = runCLI(t, root, env, "run", "--", "claude", "-c", second)
	if code != 0 {
		t.Fatalf("second run exit %d: %s", code, out)
	}
	got = codes(t, root)
	if got["alt-blocked"] != "2" || got["read-after"] != "2" {
		t.Fatalf("alternative route or paused follow-up not blocked: %v", got)
	}
	_, runB, err := store.Locate(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if runB.ID == runA.ID {
		t.Fatal("second run not found")
	}
	events, _ = readEvents(t, root, runB.ID)
	e := find(events, "integration", "tool", "npm/publish")
	if e == nil || e.Result != "denied" || e.RuleID != "authority-expansion-after-denial" || e.Metadata["correlation"] != "alternate route to effect public.publish" || e.Metadata["original_run_id"] != runA.ID || e.Metadata["session_id"] != "sess-2" {
		t.Fatalf("alternative route audit: %+v", e)
	}
	if code, text := runCLI(t, root, env, "report", "--run", runB.ID); code != 0 || !strings.Contains(text, "Authority trajectory") || !strings.Contains(text, runA.ID) || !strings.Contains(text, "claude-code") {
		t.Fatalf("report %d: %s", code, text)
	}
	// Legacy expectation: the stand-alone policy parses what the test fed it.
	if _, err := config.Parse(strings.NewReader(hardenedPolicy(t, true))); err != nil {
		t.Fatal(err)
	}
}
