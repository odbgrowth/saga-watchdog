package claudecode

import (
	"fmt"
	"strings"

	"github.com/odbgrowth/saga-watchdog/internal/integrations/agenthook"
)

// Files are the project-scoped Claude Code settings files that can carry the
// SAGA hook or disable it. User-level ~/.claude/settings.json is outside the
// project and outside SAGA's observation.
var Files = []string{".claude/settings.json", ".claude/settings.local.json"}

// Spec is the Claude Code hook configuration.
var Spec = agenthook.Spec{
	Name: "Claude Code", Agent: "claude", Producer: Producer, Command: Command, Matcher: Matcher, PreEvent: "PreToolUse", Files: Files,
	Hooks: hooks,
	// A background (async) hook cannot block, so it is not preventive.
	Preventive: func(_, hook map[string]any) bool { return hook["onFailure"] == "block" && hook["async"] != true },
	Disabled:   func(obj map[string]any) bool { return obj["disableAllHooks"] == true },
}

// hooks returns the hook groups SAGA installs. PreToolUse and ConfigChange
// carry onFailure: "block" so Claude Code itself blocks when the adapter is
// missing, crashes or times out; the adapter additionally fails closed on its
// own. Post-action hooks cannot block and only report.
func hooks() map[string]any {
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
	return map[string]any{
		"PreToolUse":         group(Matcher, true),
		"PostToolUse":        group(Matcher, false),
		"PostToolUseFailure": group(Matcher, false),
		"ConfigChange":       group(ConfigMatcher, true),
	}
}

// Status describes one settings file's relationship to the SAGA hook.
type Status = agenthook.Status

// Settings returns the hook configuration SAGA installs.
func Settings() map[string]any { return Spec.Settings() }

// SettingsJSON renders Settings for inspection or manual installation.
func SettingsJSON() []byte { return Spec.SettingsJSON() }

// Setup merges the SAGA hooks into one Claude settings file; see agenthook.Spec.Setup.
func Setup(path string) (bool, error) { return Spec.Setup(path) }

// Remove deletes the SAGA hooks from one Claude settings file; see agenthook.Spec.Remove.
func Remove(path string) (bool, error) { return Spec.Remove(path) }

// Inspect reads each project settings file; see agenthook.Spec.Inspect.
func Inspect(root string) []Status { return Spec.Inspect(root) }

// Controls returns the settings files that currently reference the SAGA hook.
func Controls(root string) []string { return Spec.Controls(root) }

// Digest fingerprints the named files; see agenthook.Digest.
func Digest(root string, files []string) string { return agenthook.Digest(root, files) }

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
