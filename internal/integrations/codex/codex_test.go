package codex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parse(t *testing.T, raw string) Input {
	t.Helper()
	var in Input
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}
	return in
}

func pre(tool, input string) string {
	return `{"hook_event_name":"PreToolUse","session_id":"thread-1","cwd":"/proj/sub","tool_name":"` + tool + `","tool_input":` + input + `,"tool_use_id":"call_1","agent_id":"agent-2","agent_type":"explorer"}`
}

func TestNormalizeMapping(t *testing.T) {
	patch := "*** Begin Patch\n*** Update File: src/a.go\n@@\n-old\n+*** Add File: not-a-header\n*** Add File: /abs/b.txt\n*** Delete File: old.txt\n*** Update File: docs/x.md\n*** Move to: docs/y.md\n*** End Patch"
	raw, _ := json.Marshal(map[string]string{"command": patch})
	requests, err := Normalize(parse(t, pre("apply_patch", string(raw))))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"write /proj/sub/src/a.go", "write /abs/b.txt", "delete /proj/sub/old.txt", "write /proj/sub/docs/x.md", "write /proj/sub/docs/y.md"}
	if len(requests) != len(want) {
		t.Fatalf("got %d requests: %+v", len(requests), requests)
	}
	for i, r := range requests {
		e := r.Event
		if r.Operation != "check" || e.Type != "file" || e.Action+" "+e.Target != want[i] || e.Tool != "apply_patch" || e.CallID != "call_1" || e.AgentID != "agent-2" || e.AgentType != "explorer" || e.SessionID != "thread-1" || e.Producer != Producer {
			t.Errorf("request %d: %+v", i, r)
		}
	}
	for name, tc := range map[string]struct{ raw, typ, action, target string }{
		"bash":    {pre("Bash", `{"command":"rm -rf / # SECRET"}`), "process", "execute", "Bash"},
		"mcp":     {pre("mcp__github__get_issue", `{"token":"MCPSECRET"}`), "tool", "call", "github/get_issue"},
		"agent":   {pre("spawn_agent", `{"prompt":"PROMPTSECRET"}`), "tool", "call", "spawn_agent"},
		"unknown": {pre("request_permissions", `{}`), "tool", "call", "request_permissions"},
	} {
		t.Run(name, func(t *testing.T) {
			requests, err := Normalize(parse(t, tc.raw))
			if err != nil || len(requests) != 1 {
				t.Fatalf("%v %+v", err, requests)
			}
			e := requests[0].Event
			if e.Type != tc.typ || e.Action != tc.action || e.Target != tc.target {
				t.Fatalf("%+v", e)
			}
			if b, _ := json.Marshal(requests); strings.Contains(string(b), "SECRET") {
				t.Fatal("payload leaked into the request")
			}
		})
	}
}

func TestNormalizePostSkipAndRejects(t *testing.T) {
	post := strings.Replace(pre("Bash", `{"command":"ls"}`), "PreToolUse", "PostToolUse", 1)
	requests, err := Normalize(parse(t, post))
	if err != nil || len(requests) != 1 || requests[0].Operation != "emit" || requests[0].Event.Result != "success" {
		t.Fatalf("%v %+v", err, requests)
	}
	for _, raw := range []string{`{"hook_event_name":"SessionStart"}`, `{"hook_event_name":"Stop","tool_name":"Bash"}`} {
		if requests, err := Normalize(parse(t, raw)); err != nil || len(requests) != 0 {
			t.Fatalf("%s: %v %+v", raw, err, requests)
		}
	}
	many := "*** Begin Patch\n" + strings.Repeat("*** Add File: f.txt\n", maxPatchFiles+1)
	manyRaw, _ := json.Marshal(map[string]string{"command": many})
	for name, raw := range map[string]string{
		"no tool":        `{"hook_event_name":"PreToolUse"}`,
		"patch no files": pre("apply_patch", `{"command":"*** Begin Patch\n*** End Patch"}`),
		"patch not json": pre("apply_patch", `[]`),
		"too many files": pre("apply_patch", string(manyRaw)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Normalize(parse(t, raw)); err == nil || strings.Contains(err.Error(), "f.txt") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestSpecSetupAndInspect(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".codex", "hooks.json")
	if changed, err := Spec.Setup(path); err != nil || !changed {
		t.Fatalf("%v %t", err, changed)
	}
	s := Spec.Inspect(root)
	if len(s) != 1 || !s[0].Configured || !s[0].Preventive || s[0].Disabled || s[0].Err != nil {
		t.Fatalf("%+v", s)
	}
	data, _ := os.ReadFile(path)
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatal(err)
	}
	hooks := obj["hooks"].(map[string]any)
	if len(hooks) != 2 || hooks["PreToolUse"] == nil || hooks["PostToolUse"] == nil {
		t.Fatalf("%v", hooks)
	}
	if controls := Spec.Controls(root); len(controls) != 1 || controls[0] != ".codex/hooks.json" {
		t.Fatalf("%v", controls)
	}
	// A background hook cannot block.
	if err := os.WriteFile(path, []byte(`{"hooks":{"PreToolUse":[{"matcher":"`+Matcher+`","hooks":[{"type":"command","command":"`+Command+`","async":true}]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if s := Spec.Inspect(root); !s[0].Configured || s[0].Preventive {
		t.Fatalf("%+v", s)
	}
	if changed, err := Spec.Remove(path); err != nil || !changed {
		t.Fatalf("%v %t", err, changed)
	}
	if s := Spec.Inspect(root); s[0].Configured {
		t.Fatalf("%+v", s)
	}
}
