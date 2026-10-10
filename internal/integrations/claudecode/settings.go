package claudecode

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Files are the project-scoped Claude Code settings files that can carry the
// SAGA hook or disable it. User-level ~/.claude/settings.json is outside the
// project and outside SAGA's observation.
var Files = []string{".claude/settings.json", ".claude/settings.local.json"}

const maxSettings = 1 << 20

// Settings returns the hook configuration SAGA installs. PreToolUse and
// ConfigChange carry onFailure: "block" so Claude Code itself blocks when the
// adapter is missing, crashes or times out; the adapter additionally fails
// closed on its own. Post-action hooks cannot block and only report.
func Settings() map[string]any {
	hook := func(block bool) map[string]any {
		h := map[string]any{"type": "command", "command": Command, "timeout": 10, "statusMessage": "SAGA Watchdog check"}
		if block {
			h["onFailure"] = "block"
		}
		return h
	}
	group := func(matcher string, block bool) []any {
		return []any{map[string]any{"matcher": matcher, "hooks": []any{hook(block)}}}
	}
	return map[string]any{"hooks": map[string]any{
		"PreToolUse":         group(Matcher, true),
		"PostToolUse":        group(Matcher, false),
		"PostToolUseFailure": group(Matcher, false),
		"ConfigChange":       group(ConfigMatcher, true),
	}}
}

// SettingsJSON renders Settings for inspection or manual installation.
func SettingsJSON() []byte {
	b, _ := json.MarshalIndent(Settings(), "", "  ")
	return append(b, '\n')
}

func readObject(path string) (map[string]any, os.FileMode, error) {
	// A symlinked .claude directory would let setup write, and the observer
	// miss, a file outside the project such as ~/.claude/settings.json.
	if info, err := os.Lstat(filepath.Dir(path)); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, fmt.Errorf("%s: parent directory must be a real directory, not a symlink", path)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, 0600, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%s must be a regular file, not a symlink", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSettings+1))
	if err != nil {
		return nil, 0, err
	}
	if len(data) > maxSettings {
		return nil, 0, fmt.Errorf("%s exceeds 1 MiB", path)
	}
	obj := map[string]any{}
	if len(bytes.TrimSpace(data)) == 0 {
		return obj, info.Mode().Perm(), nil
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&obj); err != nil {
		return nil, 0, fmt.Errorf("%s is not a JSON object: %w", path, err)
	}
	if obj == nil {
		return nil, 0, fmt.Errorf("%s is not a JSON object: null", path)
	}
	// More() ignores a stray closing delimiter; a second decode does not.
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, 0, fmt.Errorf("%s must contain one JSON object", path)
	}
	return obj, info.Mode().Perm(), nil
}

// references reports whether a hook group list contains the SAGA command.
func references(groups any) bool {
	list, _ := groups.([]any)
	for _, g := range list {
		group, _ := g.(map[string]any)
		hooks, _ := group["hooks"].([]any)
		for _, h := range hooks {
			hook, _ := h.(map[string]any)
			if hook["command"] == Command {
				return true
			}
		}
	}
	return false
}

// Setup merges the SAGA hooks into one Claude settings file, creating it when
// missing. Existing keys, hooks and permissions are preserved; a hook event
// that already references SAGA is left untouched. It reports whether the file
// changed.
func Setup(path string) (bool, error) {
	obj, perm, err := readObject(path)
	if err != nil {
		return false, err
	}
	hooks, ok := obj["hooks"].(map[string]any)
	if obj["hooks"] != nil && !ok {
		return false, fmt.Errorf("%s: \"hooks\" is not an object; fix it by hand", path)
	}
	if hooks == nil {
		hooks = map[string]any{}
	}
	changed := false
	for name, groups := range Settings()["hooks"].(map[string]any) {
		existing, ok := hooks[name].([]any)
		if hooks[name] != nil && !ok {
			return false, fmt.Errorf("%s: hooks.%s is not an array; fix it by hand", path, name)
		}
		if references(existing) {
			continue
		}
		hooks[name] = append(existing, groups.([]any)...)
		changed = true
	}
	if !changed {
		return false, nil
	}
	obj["hooks"] = hooks
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), path)
}

// Status describes one settings file's relationship to the SAGA hook.
type Status struct {
	File       string
	Configured bool // some hook event runs the SAGA command
	Preventive bool // PreToolUse runs it with onFailure: "block" and the expected matcher
	Disabled   bool // disableAllHooks is true
	Err        error
}

// Inspect reads each project settings file. It is a lexical check of the file
// contents, not proof that Claude Code loaded them.
func Inspect(root string) []Status {
	var out []Status
	for _, name := range Files {
		s := Status{File: name}
		obj, _, err := readObject(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			s.Err = err
			out = append(out, s)
			continue
		}
		s.Disabled = obj["disableAllHooks"] == true
		hooks, _ := obj["hooks"].(map[string]any)
		for _, groups := range hooks {
			if references(groups) {
				s.Configured = true
			}
		}
		pre, _ := hooks["PreToolUse"].([]any)
		for _, g := range pre {
			group, _ := g.(map[string]any)
			list, _ := group["hooks"].([]any)
			for _, h := range list {
				hook, _ := h.(map[string]any)
				// A background (async) hook cannot block, so it is not preventive.
				if hook["command"] == Command && hook["type"] == "command" && hook["onFailure"] == "block" && hook["async"] != true && group["matcher"] == Matcher {
					s.Preventive = true
				}
			}
		}
		out = append(out, s)
	}
	return out
}

// Controls returns the settings files that currently reference the SAGA hook.
// They are the files whose change during a run must count as tampering.
func Controls(root string) []string {
	var files []string
	for _, s := range Inspect(root) {
		if s.Configured {
			files = append(files, s.File)
		}
	}
	return files
}

// Digest fingerprints the named files so the supervisor can confirm at exit
// that no control changed unnoticed. A missing file hashes as absent.
func Digest(root string, files []string) string {
	h := sha256.New()
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			data = []byte("absent")
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Version extracts the leading dotted version from `claude --version` output.
func Version(output string) string {
	field := strings.Fields(output)
	if len(field) == 0 {
		return ""
	}
	return strings.TrimPrefix(field[0], "v")
}

// AtLeast compares two dotted numeric versions.
func AtLeast(have, want string) bool {
	h, w := strings.Split(have, "."), strings.Split(want, ".")
	for i := 0; i < len(w); i++ {
		var a, b int
		if i < len(h) {
			fmt.Sscanf(h[i], "%d", &a)
		}
		fmt.Sscanf(w[i], "%d", &b)
		if a != b {
			return a > b
		}
	}
	return true
}
