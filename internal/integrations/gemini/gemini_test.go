package gemini

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

func before(tool, input string) string {
	return `{"hook_event_name":"BeforeTool","session_id":"sess-9","cwd":"/proj","tool_name":"` + tool + `","tool_input":` + input + `,"timestamp":"2026-10-11T00:00:00Z"}`
}

func TestNormalizeMapping(t *testing.T) {
	for name, tc := range map[string]struct{ raw, typ, action, target string }{
		"write":  {before("write_file", `{"file_path":"/proj/src/a.go","content":"BODY-SECRET"}`), "file", "write", "/proj/src/a.go"},
		"edit":   {before("replace", `{"file_path":"/proj/.env","old_string":"a","new_string":"EDIT-SECRET"}`), "file", "write", "/proj/.env"},
		"shell":  {before("run_shell_command", `{"command":"curl -H 'Authorization: TOPSECRET' x"}`), "process", "execute", "run_shell_command"},
		"fetch":  {before("web_fetch", `{"url":"https://user:pw@API.example.com/p?token=QUERYSECRET"}`), "network", "connect", "api.example.com"},
		"prompt": {before("web_fetch", `{"prompt":"summarize https://example.com/PROMPTSECRET"}`), "tool", "call", "web_fetch"},
		"search": {before("google_web_search", `{"query":"QUERYSECRET"}`), "tool", "call", "google_web_search"},
		"mcp":    {before("mcp_github_get_issue_by_id", `{"token":"MCPSECRET"}`), "tool", "call", "github/get_issue_by_id"},
		"agent":  {before("invoke_agent", `{"prompt":"PROMPTSECRET"}`), "tool", "call", "invoke_agent"},
	} {
		t.Run(name, func(t *testing.T) {
			r, skip, err := Normalize(parse(t, tc.raw))
			if err != nil || skip || r.Operation != "check" {
				t.Fatalf("%v %t %+v", err, skip, r)
			}
			e := r.Event
			if e.Type != tc.typ || e.Action != tc.action || e.Target != tc.target || e.Producer != Producer || e.SessionID != "sess-9" {
				t.Fatalf("%+v", e)
			}
			if b, _ := json.Marshal(r); strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "pw@") {
				t.Fatal("payload leaked into the request")
			}
		})
	}
}

func TestNormalizeAfterSkipAndRejects(t *testing.T) {
	after := func(response string) string {
		return `{"hook_event_name":"AfterTool","session_id":"s","tool_name":"write_file","tool_input":{"file_path":"/p/a"},"tool_response":` + response + `}`
	}
	for name, tc := range map[string]struct{ raw, result string }{
		"success":    {after(`{"llmContent":"ok","returnDisplay":"ok"}`), "success"},
		"null error": {after(`{"llmContent":"ok","error":null}`), "success"},
		"failed":     {after(`{"llmContent":"x","error":{"message":"denied","type":"E"}}`), "failed"},
	} {
		t.Run(name, func(t *testing.T) {
			r, skip, err := Normalize(parse(t, tc.raw))
			if err != nil || skip || r.Operation != "emit" || r.Event.Result != tc.result {
				t.Fatalf("%v %t %+v", err, skip, r)
			}
		})
	}
	for _, raw := range []string{`{"hook_event_name":"SessionStart","source":"startup"}`, `{"hook_event_name":"BeforeAgent","prompt":"x"}`} {
		if _, skip, err := Normalize(parse(t, raw)); !skip || err != nil {
			t.Fatalf("%s: %t %v", raw, skip, err)
		}
	}
	for name, raw := range map[string]string{
		"no tool":      `{"hook_event_name":"BeforeTool"}`,
		"no path":      before("write_file", `{"content":"x"}`),
		"bad url":      before("web_fetch", `{"url":"not a url"}`),
		"bad input":    before("replace", `"string"`),
		"bad response": after(`"text"`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Normalize(parse(t, raw)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestSpecInspectDetectsDisabledHooks(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"theme":"dark","hooksConfig":{"disabled":["other"]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if changed, err := Spec.Setup(path); err != nil || !changed {
		t.Fatalf("%v %t", err, changed)
	}
	s := Spec.Inspect(root)
	if len(s) != 1 || !s[0].Configured || !s[0].Preventive || s[0].Disabled {
		t.Fatalf("%+v", s)
	}
	data, _ := os.ReadFile(path)
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["theme"] != "dark" {
		t.Fatalf("existing settings lost: %v", obj)
	}
	group := obj["hooks"].(map[string]any)["BeforeTool"].([]any)[0].(map[string]any)
	hook := group["hooks"].([]any)[0].(map[string]any)
	if group["matcher"] != Matcher || hook["name"] != HookName || hook["timeout"] != float64(10000) {
		t.Fatalf("%v", group)
	}
	for _, cfg := range []string{`{"enabled":false}`, `{"disabled":["saga-watchdog"]}`} {
		obj["hooksConfig"] = json.RawMessage(cfg)
		raw, _ := json.Marshal(obj)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if s := Spec.Inspect(root); !s[0].Disabled {
			t.Fatalf("%s not detected: %+v", cfg, s)
		}
	}
}
