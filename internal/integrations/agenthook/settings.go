package agenthook

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
)

const maxSettings = 1 << 20

// Spec describes one agent's hook configuration: the project files that can
// carry or disable the hook, what SAGA installs there and how to recognize an
// installed hook that blocks before execution. Every adapter exports one.
type Spec struct {
	Name     string   // display name, such as "Claude Code"
	Agent    string   // executable name, such as "claude"
	Producer string   // audit metadata producer
	Command  string   // shell-form hook command SAGA installs
	Matcher  string   // tool matcher on the pre-action event
	PreEvent string   // pre-action hook event name
	Files    []string // project-relative files; the first is the setup default
	// AgentFailsClosed reports that the agent itself blocks the tool call
	// when the hook command cannot start, crashes or times out, under its
	// documented contract. The adapter always fails closed on its own side;
	// without this the agent lets such a call proceed.
	AgentFailsClosed bool
	// Hooks returns the event groups SAGA installs under the file's "hooks" key.
	Hooks func() map[string]any
	// Preventive adds agent-specific conditions for a pre-action entry to count
	// as blocking before execution. nil means the matcher and command suffice.
	Preventive func(group, hook map[string]any) bool
	// Disabled reports whether the file as a whole turns hooks off. nil means
	// the file has no such switch.
	Disabled func(obj map[string]any) bool
}

// Settings returns the complete configuration object SAGA installs.
func (s *Spec) Settings() map[string]any { return map[string]any{"hooks": s.Hooks()} }

// SettingsJSON renders Settings for inspection or manual installation.
func (s *Spec) SettingsJSON() []byte {
	b, _ := json.MarshalIndent(s.Settings(), "", "  ")
	return append(b, '\n')
}

func readObject(path string) (map[string]any, os.FileMode, error) {
	// A symlinked configuration directory would let setup write, and the
	// observer miss, a file outside the project such as ~/.claude/settings.json.
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
func (s *Spec) references(groups any) bool {
	list, _ := groups.([]any)
	for _, g := range list {
		group, _ := g.(map[string]any)
		hooks, _ := group["hooks"].([]any)
		for _, h := range hooks {
			hook, _ := h.(map[string]any)
			if hook["command"] == s.Command {
				return true
			}
		}
	}
	return false
}

// Setup merges the SAGA hooks into one configuration file, creating it when
// missing. Existing keys, hooks and permissions are preserved; a hook event
// that already references SAGA is left untouched. It reports whether the file
// changed.
func (s *Spec) Setup(path string) (bool, error) {
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
	for name, groups := range s.Hooks() {
		existing, ok := hooks[name].([]any)
		if hooks[name] != nil && !ok {
			return false, fmt.Errorf("%s: hooks.%s is not an array; fix it by hand", path, name)
		}
		if s.references(existing) {
			continue
		}
		hooks[name] = append(existing, groups.([]any)...)
		changed = true
	}
	if !changed {
		return false, nil
	}
	obj["hooks"] = hooks
	return true, writeObject(path, obj, perm)
}

// Remove deletes every hook entry that runs the SAGA command from one
// configuration file. Other hooks in the same group, other groups and all
// other keys are kept; emptied groups and an emptied "hooks" object are
// dropped. A missing or unconfigured file is reported as unchanged.
func (s *Spec) Remove(path string) (bool, error) {
	obj, perm, err := readObject(path)
	if err != nil {
		return false, err
	}
	hooks, ok := obj["hooks"].(map[string]any)
	if !ok {
		return false, nil
	}
	changed := false
	for name, groups := range hooks {
		list, ok := groups.([]any)
		if !ok {
			continue
		}
		var kept []any
		for _, g := range list {
			group, _ := g.(map[string]any)
			entries, _ := group["hooks"].([]any)
			var keptHooks []any
			for _, h := range entries {
				hook, _ := h.(map[string]any)
				if hook["command"] == s.Command {
					changed = true
					continue
				}
				keptHooks = append(keptHooks, h)
			}
			if len(entries) > 0 && len(keptHooks) == 0 {
				continue
			}
			if len(keptHooks) != len(entries) {
				group["hooks"] = keptHooks
			}
			kept = append(kept, g)
		}
		if len(kept) == 0 {
			delete(hooks, name)
		} else {
			hooks[name] = kept
		}
	}
	if !changed {
		return false, nil
	}
	if len(hooks) == 0 {
		delete(obj, "hooks")
	} else {
		obj["hooks"] = hooks
	}
	return true, writeObject(path, obj, perm)
}

// writeObject replaces path atomically with the indented JSON of obj, keeping
// the file mode it was read with.
func writeObject(path string, obj map[string]any, perm os.FileMode) error {
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Status describes one configuration file's relationship to the SAGA hook.
type Status struct {
	File       string
	Configured bool // some hook event runs the SAGA command
	Preventive bool // the pre-action event runs it with the expected matcher and blocking options
	Disabled   bool // the file turns hooks off as a whole
	Err        error
}

// Inspect reads each project configuration file. It is a lexical check of the
// file contents, not proof that the agent loaded them.
func (s *Spec) Inspect(root string) []Status {
	var out []Status
	for _, name := range s.Files {
		st := Status{File: name}
		obj, _, err := readObject(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			st.Err = err
			out = append(out, st)
			continue
		}
		if s.Disabled != nil {
			st.Disabled = s.Disabled(obj)
		}
		hooks, _ := obj["hooks"].(map[string]any)
		for _, groups := range hooks {
			if s.references(groups) {
				st.Configured = true
			}
		}
		pre, _ := hooks[s.PreEvent].([]any)
		for _, g := range pre {
			group, _ := g.(map[string]any)
			list, _ := group["hooks"].([]any)
			for _, h := range list {
				hook, _ := h.(map[string]any)
				if hook["command"] == s.Command && hook["type"] == "command" && group["matcher"] == s.Matcher && (s.Preventive == nil || s.Preventive(group, hook)) {
					st.Preventive = true
				}
			}
		}
		out = append(out, st)
	}
	return out
}

// Controls returns the configuration files that currently carry an effective
// preventive hook: one that runs the SAGA command, can block before execution
// and is not switched off by any of the agent's project files. They are the
// files whose change during a run must count as tampering. A file that merely
// references the command (post-action only, background, or disabled) protects
// nothing and is therefore not a control; the doctor reports such files.
func (s *Spec) Controls(root string) []string {
	statuses := s.Inspect(root)
	for _, st := range statuses {
		if st.Disabled {
			return nil
		}
	}
	var files []string
	for _, st := range statuses {
		if st.Configured && st.Preventive {
			files = append(files, st.File)
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
