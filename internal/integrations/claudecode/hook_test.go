package claudecode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/policy"
	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
)

func pre(tool, input string) string {
	return `{"hook_event_name":"PreToolUse","session_id":"sess-1","cwd":"/project","permission_mode":"default","tool_name":"` + tool + `","tool_input":` + input + `,"tool_use_id":"toolu_1"}`
}

func parse(t *testing.T, raw string) Input {
	t.Helper()
	var in Input
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatalf("test fixture: %v", err)
	}
	return in
}

func TestNormalizeMapping(t *testing.T) {
	for name, tc := range map[string]struct{ raw, op, typ, action, target, result string }{
		"write":      {pre("Write", `{"file_path":"/project/src/a.go","content":"BODY"}`), "check", "file", "write", "/project/src/a.go", ""},
		"edit":       {pre("Edit", `{"file_path":"/project/.env","old_string":"a","new_string":"b","replace_all":false}`), "check", "file", "write", "/project/.env", ""},
		"multiedit":  {pre("MultiEdit", `{"file_path":"/project/x","edits":[{"old_string":"a","new_string":"b"}]}`), "check", "file", "write", "/project/x", ""},
		"notebook":   {pre("NotebookEdit", `{"notebook_path":"/project/n.ipynb","new_source":"x","cell_id":"c"}`), "check", "file", "write", "/project/n.ipynb", ""},
		"outside":    {pre("Write", `{"file_path":"/etc/passwd"}`), "check", "file", "write", "/etc/passwd", ""},
		"fetch":      {pre("WebFetch", `{"url":"https://User:PW@API.Example.com:8443/p?token=Q#f","prompt":"p"}`), "check", "network", "connect", "api.example.com", ""},
		"bash":       {pre("Bash", `{"command":"rm -rf /","description":"x","timeout":1000}`), "check", "process", "execute", "Bash", ""},
		"mcp":        {pre("mcp__github__get_issue", `{"owner":"o","repo":"r"}`), "check", "tool", "call", "github/get_issue", ""},
		"mcp-plugin": {pre("mcp__plugin_my-plugin_db__query", `{}`), "check", "tool", "call", "plugin_my-plugin_db/query", ""},
		"mcp-odd":    {pre("mcp__broken", `{}`), "check", "tool", "call", "mcp__broken", ""},
		"unknown":    {pre("FooBar", `{"anything":"x"}`), "check", "tool", "call", "FooBar", ""},
		"no-input":   {`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`, "check", "process", "execute", "Bash", ""},
		"post":       {strings.Replace(pre("Write", `{"file_path":"/project/a"}`), "PreToolUse", "PostToolUse", 1), "emit", "file", "write", "/project/a", "success"},
		"failure":    {strings.Replace(pre("Bash", `{"command":"x"}`), "PreToolUse", "PostToolUseFailure", 1), "emit", "process", "execute", "Bash", "failed"},
		"config":     {`{"hook_event_name":"ConfigChange","source":"project_settings","file_path":"/project/.claude/settings.json"}`, "check", "file", "write", "/project/.claude/settings.json", ""},
		"config-sub": {`{"hook_event_name":"ConfigChange","source":"local_settings","file_path":"/project/.claude/settings.local.json"}`, "check", "file", "write", "/project/.claude/settings.local.json", ""},
		"config-out": {`{"hook_event_name":"ConfigChange","source":"local_settings","file_path":"/elsewhere/settings.local.json"}`, "check", "file", "write", "/elsewhere/settings.local.json", ""},
	} {
		t.Run(name, func(t *testing.T) {
			r, skip, err := Normalize(parse(t, tc.raw))
			if err != nil || skip {
				t.Fatalf("skip=%v err=%v", skip, err)
			}
			if r.Operation != tc.op || r.Event.Type != tc.typ || r.Event.Action != tc.action || r.Event.Target != tc.target || r.Event.Result != tc.result {
				t.Fatalf("got %+v, want %s %s/%s/%s result %q", r, tc.op, tc.typ, tc.action, tc.target, tc.result)
			}
			if r.Event.Producer != Producer {
				t.Fatalf("producer %q", r.Event.Producer)
			}
			if err := socket.Validate(r, false); err != nil {
				t.Fatalf("not a valid socket request: %v", err)
			}
		})
	}
}

func TestNormalizeSkipsAndRejects(t *testing.T) {
	for name, raw := range map[string]string{
		"session-start": `{"hook_event_name":"SessionStart","source":"startup"}`,
		"user-config":   `{"hook_event_name":"ConfigChange","source":"user_settings"}`,
		"policy-config": `{"hook_event_name":"ConfigChange","source":"policy_settings"}`,
		"unknown-event": `{"hook_event_name":"Nope","tool_name":"Write","tool_input":{"file_path":"/p/a"}}`,
		"empty":         `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, skip, err := Normalize(parse(t, raw)); !skip || err != nil {
				t.Fatalf("expected skip, got skip=%v err=%v", skip, err)
			}
		})
	}
	for name, raw := range map[string]string{
		"no-tool":          `{"hook_event_name":"PreToolUse","tool_input":{"file_path":"/p/a"}}`,
		"blank-tool":       pre("   ", `{}`),
		"write-no-path":    pre("Write", `{"content":"SECRETCONTENT"}`),
		"notebook-no-path": pre("NotebookEdit", `{"file_path":"/p/x"}`),
		"fetch-no-host":    pre("WebFetch", `{"url":"not a url"}`),
		"fetch-relative":   pre("WebFetch", `{"url":"/relative/path"}`),
		"fetch-missing":    pre("WebFetch", `{"prompt":"SECRETPROMPT"}`),
		"input-array":      pre("Write", `[1,2]`),
		"input-scalar":     pre("Edit", `"SECRETSTRING"`),
		"config-nopath":    `{"hook_event_name":"ConfigChange","source":"local_settings"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, skip, err := Normalize(parse(t, raw))
			if err == nil || skip {
				t.Fatalf("expected error, got skip=%v err=%v", skip, err)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("error leaks input: %v", err)
			}
		})
	}
}

func TestLineageIsBoundedAndSubagentsAreVisible(t *testing.T) {
	raw := `{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/p/a"},"tool_use_id":"toolu_9","agent_id":"agent 1\né","agent_type":"my-plugin:reviewer","session_id":"` + strings.Repeat("s", 300) + `"}`
	r, _, err := Normalize(parse(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	got := r.Event.Lineage()
	want := map[string]string{"producer": Producer, "tool_name": "Write", "tool_use_id": "toolu_9", "agent_id": "agent1", "agent_type": "my-plugin:reviewer", "session_id": strings.Repeat("s", 128)}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %q, want %q", key, got[key], value)
		}
	}
	if err := socket.Validate(r, false); err != nil {
		t.Fatalf("bounded lineage rejected: %v", err)
	}
	// A main-agent call carries no agent fields; the decision path is identical.
	main, _, _ := Normalize(parse(t, pre("Write", `{"file_path":"/p/a"}`)))
	if _, ok := main.Event.Lineage()["agent_id"]; ok {
		t.Fatal("main agent fabricated an agent_id")
	}
	main.Event.AgentID, main.Event.AgentType, main.Event.CallID, main.Event.SessionID = "", "", "", ""
	r.Event.AgentID, r.Event.AgentType, r.Event.CallID, r.Event.SessionID = "", "", "", ""
	if main.Event != r.Event {
		t.Fatalf("subagent event differs beyond lineage: %+v vs %+v", main.Event, r.Event)
	}
}

func TestNormalizeNeverCarriesPayload(t *testing.T) {
	secrets := []string{"BODY-SECRET", "TOPSECRET", "QUERYSECRET", "pw-secret", "MCPSECRET", "EDIT-SECRET", "PROMPT-SECRET", "-----BEGIN"}
	for _, raw := range []string{
		pre("Write", `{"file_path":"/p/a","content":"BODY-SECRET\n-----BEGIN PRIVATE KEY-----"}`),
		pre("Bash", `{"command":"curl -H 'Authorization: Bearer TOPSECRET' https://x/?k=QUERYSECRET"}`),
		pre("WebFetch", `{"url":"https://u:pw-secret@h.example/x?k=QUERYSECRET#TOPSECRET","prompt":"PROMPT-SECRET"}`),
		pre("mcp__db__query", `{"api_key":"MCPSECRET","sql":"select TOPSECRET"}`),
		pre("Edit", `{"file_path":"/p/a","old_string":"BODY-SECRET","new_string":"EDIT-SECRET"}`),
		pre("Agent", `{"prompt":"PROMPT-SECRET","description":"x"}`),
	} {
		r, skip, err := Normalize(parse(t, raw))
		if err != nil || skip {
			t.Fatalf("%s: skip=%v err=%v", raw[:40], skip, err)
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			if bytes.Contains(encoded, []byte(s)) {
				t.Errorf("request carries %q: %s", s, encoded)
			}
		}
	}
}

type fake struct {
	calls []socket.Request
	path  string
	resp  socket.Response
	err   error
}

func (f *fake) send(path string, r socket.Request) (socket.Response, error) {
	f.path = path
	f.calls = append(f.calls, r)
	return f.resp, f.err
}

func runHook(t *testing.T, stdin string, opts Options) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(strings.NewReader(stdin), &out, &errb, opts)
	return code, out.String(), errb.String()
}

func TestRunFailsClosed(t *testing.T) {
	deny := socket.Response{Allowed: false, Decision: &policy.Decision{Action: "pause", RuleID: "protected-path", Reason: "protected project path changed", Severity: "high"}}
	kill := socket.Response{Allowed: false, Decision: &policy.Decision{Action: "kill", RuleID: "hook-tamper", Reason: "x", Severity: "critical"}}
	write := pre("Write", `{"file_path":"/project/.env","content":"SECRETCONTENT"}`)
	for _, tc := range []struct {
		name, stdin string
		f           *fake
		opts        Options
		want        int
		stderrHas   string
		sent        bool
	}{
		{"no environment", write, &fake{}, Options{}, 2, "SAGA_WATCHDOG_SOCKET", false},
		{"no run id", write, &fake{}, Options{Socket: "/s"}, 2, "SAGA_WATCHDOG_RUN_ID", false},
		{"unreachable", write, &fake{err: errors.New("watchdog unavailable: dial unix /s: connect: no such file")}, Options{Socket: "/s", RunID: "run_x"}, 2, "unavailable", true},
		{"run id mismatch", write, &fake{err: errors.New("run ID does not match this supervisor")}, Options{Socket: "/s", RunID: "run_x"}, 2, "does not match", true},
		{"no decision", write, &fake{resp: socket.Response{Allowed: true}}, Options{Socket: "/s", RunID: "run_x"}, 2, "no decision", true},
		{"empty decision", write, &fake{resp: socket.Response{Allowed: true, Decision: &policy.Decision{}}}, Options{Socket: "/s", RunID: "run_x"}, 2, "no decision", true},
		{"denied", write, &fake{resp: deny}, Options{Socket: "/s", RunID: "run_x"}, 2, "Rule: protected-path", true},
		{"killed", write, &fake{resp: kill}, Options{Socket: "/s", RunID: "run_x"}, 2, "being stopped", true},
		{"malformed", `{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"content":"SECRETCONTENT"`, &fake{}, Options{Socket: "/s", RunID: "run_x"}, 2, "not valid JSON", false},
		{"not an object", `[1,2,3]`, &fake{}, Options{Socket: "/s", RunID: "run_x"}, 2, "not valid JSON", false},
		{"uninterpretable", pre("Write", `{"content":"SECRETCONTENT"}`), &fake{}, Options{Socket: "/s", RunID: "run_x"}, 2, "has no path", false},
		{"config change", `{"hook_event_name":"ConfigChange","source":"project_settings","file_path":"/project/.claude/settings.json"}`, &fake{resp: kill}, Options{Socket: "/s", RunID: "run_x"}, 2, "Rule: hook-tamper", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Send = tc.f.send
			code, out, errs := runHook(t, tc.stdin, tc.opts)
			if code != tc.want {
				t.Fatalf("exit %d, want %d\n%s", code, tc.want, errs)
			}
			if !strings.Contains(errs, tc.stderrHas) {
				t.Fatalf("stderr %q lacks %q", errs, tc.stderrHas)
			}
			if (len(tc.f.calls) > 0) != tc.sent {
				t.Fatalf("sent=%v, want %v", len(tc.f.calls) > 0, tc.sent)
			}
			if strings.Contains(errs+out, "SECRETCONTENT") {
				t.Fatalf("payload leaked: %s%s", out, errs)
			}
			if out != "" {
				t.Fatalf("blocked call wrote stdout: %s", out)
			}
			if tc.name == "denied" && !strings.Contains(errs, "saga-watchdog resume run_x") {
				t.Fatalf("pause hint missing: %s", errs)
			}
		})
	}
	if code, _, errs := runHook(t, strings.Repeat(" ", maxInput+1), Options{Socket: "/s", RunID: "run_x", Send: (&fake{}).send}); code != 2 || !strings.Contains(errs, "exceeds") {
		t.Fatalf("oversized input: %d %s", code, errs)
	}
}

func TestRunAllowsAndReports(t *testing.T) {
	allow := socket.Response{Allowed: true, Decision: &policy.Decision{Action: "allow", Severity: "info"}}
	f := &fake{resp: allow}
	code, out, errs := runHook(t, pre("Write", `{"file_path":"/project/src/a.go","content":"BODY"}`), Options{Socket: "/sock", RunID: "run_x", Send: f.send})
	if code != 0 || out != "" || errs != "" {
		t.Fatalf("allow: %d %q %q", code, out, errs)
	}
	if f.path != "/sock" || len(f.calls) != 1 || f.calls[0].RunID != "run_x" || f.calls[0].Operation != "check" {
		t.Fatalf("request not forwarded: %s %+v", f.path, f.calls)
	}
	for _, tc := range []struct{ action, has string }{{"warn", "warning [failure-escalation]"}, {"pause", "observe mode: would pause"}, {"kill", "observe mode: would kill"}} {
		f := &fake{resp: socket.Response{Allowed: true, Decision: &policy.Decision{Action: tc.action, RuleID: "failure-escalation", Reason: "r"}}}
		code, out, _ := runHook(t, pre("Bash", `{"command":"x"}`), Options{Socket: "/s", RunID: "run_x", Send: f.send})
		var message map[string]string
		if code != 0 || json.Unmarshal([]byte(out), &message) != nil || !strings.Contains(message["systemMessage"], tc.has) {
			t.Fatalf("%s: %d %q", tc.action, code, out)
		}
		if _, ok := message["hookSpecificOutput"]; ok {
			t.Fatal("adapter must never emit a permission decision of its own")
		}
	}
	for _, tc := range []struct {
		name string
		f    *fake
		want int
	}{
		{"post ok", &fake{resp: allow}, 0},
		{"post without decision", &fake{resp: socket.Response{Allowed: true}}, 0},
		{"post unreachable", &fake{err: errors.New("watchdog unavailable")}, 2},
	} {
		code, out, errs := runHook(t, strings.Replace(pre("Write", `{"file_path":"/project/a"}`), "PreToolUse", "PostToolUse", 1), Options{Socket: "/s", RunID: "run_x", Send: tc.f.send})
		if code != tc.want || out != "" {
			t.Fatalf("%s: %d %q %q", tc.name, code, out, errs)
		}
		if len(tc.f.calls) != 1 || tc.f.calls[0].Operation != "emit" || tc.f.calls[0].Event.Result != "success" {
			t.Fatalf("%s: %+v", tc.name, tc.f.calls)
		}
	}
	// Events SAGA does not evaluate never block and never contact the socket.
	f = &fake{}
	if code, out, errs := runHook(t, `{"hook_event_name":"SessionStart"}`, Options{Send: f.send}); code != 0 || out != "" || errs != "" || len(f.calls) != 0 {
		t.Fatalf("unsupported event: %d %q %q %+v", code, out, errs, f.calls)
	}
}

// stubSupervisor answers every valid request with allow, like a quiet run.
func stubSupervisor(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan socket.Call, 64)
	s, err := socket.Start(ctx, calls)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() { cancel(); s.Close() })
	go func() {
		for {
			select {
			case call := <-calls:
				call.Reply <- socket.Response{Allowed: true, Decision: &policy.Decision{Action: "allow", Severity: "info"}}
			case <-ctx.Done():
				return
			}
		}
	}()
	return s.Events
}

func TestHookLatencyReport(t *testing.T) {
	if os.Getenv("SAGA_LATENCY") == "" {
		t.Skip("set SAGA_LATENCY=1 to measure in-process hook round trips")
	}
	path := stubSupervisor(t)
	input := pre("Write", `{"file_path":"/project/src/a.go","content":"`+strings.Repeat("x", 4096)+`"}`)
	const n = 1000
	samples := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		if code, _, errs := runHook(t, input, Options{Socket: path, RunID: "run_latency_test"}); code != 0 {
			t.Fatalf("round trip failed: %d %s", code, errs)
		}
		samples = append(samples, time.Since(start))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("in-process hook round trip over %d calls: median %s, p95 %s, max %s", n, samples[n/2], samples[n*95/100], samples[n-1])
}

func BenchmarkHookRoundTrip(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := make(chan socket.Call, 64)
	s, err := socket.Start(ctx, calls)
	if err != nil {
		b.Skip(err)
	}
	defer s.Close()
	go func() {
		for {
			select {
			case call := <-calls:
				call.Reply <- socket.Response{Allowed: true, Decision: &policy.Decision{Action: "allow", Severity: "info"}}
			case <-ctx.Done():
				return
			}
		}
	}()
	input := pre("Write", `{"file_path":"/project/src/a.go","content":"body"}`)
	var out, errs bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if code := Run(strings.NewReader(input), &out, &errs, Options{Socket: s.Events, RunID: "run_latency_test"}); code != 0 {
			b.Fatal(errs.String())
		}
	}
}
