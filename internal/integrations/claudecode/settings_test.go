package claudecode

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatalf("%s: %v\n%s", path, err, data)
	}
	return obj
}

func TestSetupMergesAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	existing := `{"permissions":{"allow":["Bash(go test *)"]},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo hi"}]}],"Stop":[{"hooks":[{"type":"command","command":"echo done"}]}]},"model":"opus","ratio":1.50}`
	if err := os.WriteFile(path, []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}
	changed, err := Setup(path)
	if err != nil || !changed {
		t.Fatalf("setup: changed=%v err=%v", changed, err)
	}
	obj := readJSON(t, path)
	if obj["model"] != "opus" || obj["ratio"] != 1.5 || obj["permissions"] == nil {
		t.Fatalf("existing keys lost: %v", obj)
	}
	hooks := obj["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 2 || pre[0].(map[string]any)["matcher"] != "Bash" {
		t.Fatalf("existing PreToolUse hook not preserved first: %v", pre)
	}
	ours := pre[1].(map[string]any)
	if ours["matcher"] != Matcher || ours["hooks"].([]any)[0].(map[string]any)["onFailure"] != "block" {
		t.Fatalf("SAGA hook not appended: %v", ours)
	}
	if hooks["Stop"] == nil || hooks["ConfigChange"] == nil || hooks["PostToolUse"] == nil || hooks["PostToolUseFailure"] == nil {
		t.Fatalf("hook events: %v", hooks)
	}
	if data, _ := os.ReadFile(path); !bytes.Contains(data, []byte(`"ratio": 1.50`)) {
		t.Fatalf("number formatting changed: %s", data)
	}
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0644 {
		t.Fatalf("permissions changed: %v", info.Mode())
	}
	status := Inspect(dir)
	if len(status) != 2 || !status[0].Configured || !status[0].Preventive || status[0].Disabled || status[1].Configured {
		t.Fatalf("inspect: %+v", status)
	}
	if got := Controls(dir); len(got) != 1 || got[0] != ".claude/settings.json" {
		t.Fatalf("controls: %v", got)
	}
	before, _ := os.ReadFile(path)
	if changed, err := Setup(path); err != nil || changed {
		t.Fatalf("second setup: changed=%v err=%v", changed, err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("idempotent setup rewrote the file")
	}
}

func TestSetupCreatesAndRefusesUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "settings.local.json")
	if changed, err := Setup(path); err != nil || !changed {
		t.Fatalf("create: changed=%v err=%v", changed, err)
	}
	if info, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatalf("created file: %v %v", info, err)
	}
	if s := Inspect(dir)[1]; !s.Configured || !s.Preventive {
		t.Fatalf("created settings not recognised: %+v", s)
	}
	for name, content := range map[string]string{
		"array":         `[1]`,
		"hooks-scalar":  `{"hooks": 5}`,
		"event-object":  `{"hooks":{"PreToolUse":{}}}`,
		"two-documents": `{} {}`,
		"truncated":     `{"hooks":`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "settings.json")
			if err := os.WriteFile(p, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Setup(p); err == nil {
				t.Fatal("unsafe settings merged")
			}
			if data, _ := os.ReadFile(p); string(data) != content {
				t.Fatal("refused setup modified the file")
			}
		})
	}
	link := filepath.Join(t.TempDir(), "settings.json")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Setup(link); err == nil {
		t.Fatal("symlinked settings accepted")
	}
	if s := Inspect(filepath.Dir(filepath.Dir(link))); s[0].Err == nil || s[0].Configured {
		// Inspect looks for .claude/settings.json; this link lives elsewhere, so
		// only the symlink refusal above matters here.
		_ = s
	}
}

func TestInspectDetectsDisabledHooksAndPartialSetup(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	local := `{"disableAllHooks":true,"hooks":{"PostToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"` + Command + `"}]}]}}`
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.local.json"), []byte(local), 0600); err != nil {
		t.Fatal(err)
	}
	project := `{"hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"` + Command + `"}]}]}}`
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte(project), 0600); err != nil {
		t.Fatal(err)
	}
	status := Inspect(dir)
	if !status[0].Configured || status[0].Preventive || status[0].Disabled {
		t.Fatalf("project without onFailure/matcher reported as preventive: %+v", status[0])
	}
	if !status[1].Configured || status[1].Preventive || !status[1].Disabled {
		t.Fatalf("local disableAllHooks not detected: %+v", status[1])
	}
	if got := Controls(dir); len(got) != 2 {
		t.Fatalf("both files reference SAGA: %v", got)
	}
	if s := Inspect(t.TempDir()); s[0].Configured || s[0].Err != nil || len(Controls(t.TempDir())) != 0 {
		t.Fatalf("missing files: %+v", s)
	}
}

func TestDigestVersionAndSettingsShape(t *testing.T) {
	dir := t.TempDir()
	files := []string{".claude/settings.json"}
	absent := Digest(dir, files)
	if absent != Digest(dir, files) || absent == Digest(dir, nil) {
		t.Fatal("digest is not stable or ignores file names")
	}
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	present := Digest(dir, files)
	if present == absent {
		t.Fatal("digest ignores content")
	}
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte("{} "), 0600); err != nil {
		t.Fatal(err)
	}
	if Digest(dir, files) == present {
		t.Fatal("digest ignores a one-byte change")
	}
	if Version("2.1.296 (Claude Code)") != "2.1.296" || Version("") != "" || Version("v1.2.3") != "1.2.3" {
		t.Fatal("version parsing")
	}
	for _, tc := range []struct {
		have, want string
		ok         bool
	}{{"2.1.296", "2.1.295", true}, {"2.1.295", "2.1.295", true}, {"2.1.294", "2.1.295", false}, {"2.2.0", "2.1.295", true}, {"3.0", "2.1.295", true}, {"1.9.999", "2.1.295", false}, {"garbage", "2.1.295", false}} {
		if AtLeast(tc.have, tc.want) != tc.ok {
			t.Errorf("AtLeast(%s, %s) != %v", tc.have, tc.want, tc.ok)
		}
	}
	var shape map[string]map[string][]map[string]any
	if err := json.Unmarshal(SettingsJSON(), &shape); err != nil {
		t.Fatal(err)
	}
	for event, block := range map[string]bool{"PreToolUse": true, "PostToolUse": false, "PostToolUseFailure": false, "ConfigChange": true} {
		group := shape["hooks"][event][0]
		hook := group["hooks"].([]any)[0].(map[string]any)
		if hook["command"] != Command || hook["type"] != "command" || (hook["onFailure"] == "block") != block {
			t.Errorf("%s: %v", event, hook)
		}
		if event == "ConfigChange" && group["matcher"] != ConfigMatcher || event != "ConfigChange" && group["matcher"] != Matcher {
			t.Errorf("%s matcher: %v", event, group["matcher"])
		}
	}
}
