// Package integrations lists the agent hook adapters so the supervisor and
// the doctor treat every preventive hook alike.
package integrations

import (
	"path/filepath"

	"github.com/odbgrowth/saga-watchdog/internal/integrations/agenthook"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/claudecode"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/codex"
	"github.com/odbgrowth/saga-watchdog/internal/integrations/gemini"
)

// Specs are the supported agents in the order they are reported.
var Specs = []*agenthook.Spec{&claudecode.Spec, &codex.Spec, &gemini.Spec}

// Files lists every project file that can carry or disable a SAGA hook.
func Files() []string {
	var files []string
	for _, s := range Specs {
		files = append(files, s.Files...)
	}
	return files
}

// Controls lists the files that currently carry an effective preventive SAGA
// hook; see agenthook.Spec.Controls.
func Controls(root string) []string {
	var files []string
	for _, s := range Specs {
		files = append(files, s.Controls(root)...)
	}
	return files
}

// ForAgent returns the integration of the agent an executable starts, by its
// base name, or nil for an executable without a supported hook.
func ForAgent(executable string) *agenthook.Spec {
	name := filepath.Base(executable)
	for _, s := range Specs {
		if s.Agent == name {
			return s
		}
	}
	return nil
}
