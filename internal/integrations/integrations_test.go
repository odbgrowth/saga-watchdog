package integrations

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/odbgrowth/saga-watchdog/internal/integrations/claudecode"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/codex"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/gemini"
)

func write(t *testing.T, root, name, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

// A file that references the SAGA command without an effective preventive
// hook must not count as a control: it would silence the unattended warning
// and claim protection that no hook provides.
func TestControlsRequireAnEffectivePreventiveHook(t *testing.T) {
	claudeHook := func(event, extra string) string {
		return `{"hooks":{"` + event + `":[{"matcher":"` + claudecode.Matcher + `","hooks":[{"type":"command","command":"` + claudecode.Command + `"` + extra + `}]}]}}`
	}
	for name, tc := range map[string]struct {
		files map[string]string
		want  []string
	}{
		"claude preventive":       {map[string]string{".claude/settings.json": claudeHook("PreToolUse", `,"onFailure":"block"`)}, []string{".claude/settings.json"}},
		"claude post-action only": {map[string]string{".claude/settings.json": claudeHook("PostToolUse", ``)}, nil},
		"claude no onFailure":     {map[string]string{".claude/settings.json": claudeHook("PreToolUse", ``)}, nil},
		"claude async":            {map[string]string{".claude/settings.json": claudeHook("PreToolUse", `,"onFailure":"block","async":true`)}, nil},
		"claude disabled by sibling": {map[string]string{
			".claude/settings.json":       claudeHook("PreToolUse", `,"onFailure":"block"`),
			".claude/settings.local.json": `{"disableAllHooks":true}`,
		}, nil},
		"codex preventive":       {map[string]string{".codex/hooks.json": `{"hooks":{"PreToolUse":[{"matcher":"` + codex.Matcher + `","hooks":[{"type":"command","command":"` + codex.Command + `"}]}]}}`}, []string{".codex/hooks.json"}},
		"codex post-action only": {map[string]string{".codex/hooks.json": `{"hooks":{"PostToolUse":[{"matcher":"` + codex.Matcher + `","hooks":[{"type":"command","command":"` + codex.Command + `"}]}]}}`}, nil},
		"gemini preventive":      {map[string]string{".gemini/settings.json": `{"hooks":{"BeforeTool":[{"matcher":"` + gemini.Matcher + `","hooks":[{"name":"saga-watchdog","type":"command","command":"` + gemini.Command + `"}]}]}}`}, []string{".gemini/settings.json"}},
		"gemini disabled":        {map[string]string{".gemini/settings.json": `{"hooksConfig":{"enabled":false},"hooks":{"BeforeTool":[{"matcher":"` + gemini.Matcher + `","hooks":[{"name":"saga-watchdog","type":"command","command":"` + gemini.Command + `"}]}]}}`}, nil},
		"gemini name disabled":   {map[string]string{".gemini/settings.json": `{"hooksConfig":{"disabled":["saga-watchdog"]},"hooks":{"BeforeTool":[{"matcher":"` + gemini.Matcher + `","hooks":[{"name":"saga-watchdog","type":"command","command":"` + gemini.Command + `"}]}]}}`}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for file, body := range tc.files {
				write(t, root, file, body)
			}
			got := Controls(root)
			if len(got) != len(tc.want) {
				t.Fatalf("controls %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("controls %v, want %v", got, tc.want)
				}
			}
		})
	}
	root := t.TempDir()
	write(t, root, ".claude/settings.json", claudeHook("PreToolUse", `,"onFailure":"block"`))
	write(t, root, ".codex/hooks.json", `{"hooks":{"PreToolUse":[{"matcher":"`+codex.Matcher+`","hooks":[{"type":"command","command":"`+codex.Command+`"}]}]}}`)
	if got := Controls(root); len(got) != 2 || got[0] != ".claude/settings.json" || got[1] != ".codex/hooks.json" {
		t.Fatalf("%v", got)
	}
	if files := Files(); len(files) != 4 || files[0] != ".claude/settings.json" || files[3] != ".gemini/settings.json" {
		t.Fatalf("%v", files)
	}
}
