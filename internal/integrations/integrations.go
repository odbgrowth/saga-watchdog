// Package integrations lists the agent hook adapters so the supervisor and
// the doctor treat every preventive hook alike.
package integrations

import (
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

// Controls lists the files that currently reference a SAGA hook.
func Controls(root string) []string {
	var files []string
	for _, s := range Specs {
		files = append(files, s.Controls(root)...)
	}
	return files
}
