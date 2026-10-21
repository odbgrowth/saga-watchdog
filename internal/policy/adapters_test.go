package policy_test

import (
	"testing"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
	"github.com/odbgrowth/saga-watchdog/internal/integrations"
	"github.com/odbgrowth/saga-watchdog/internal/policy"
)

// The engine keeps its own list of agent configuration files because it must
// not depend on the adapters. Every file an adapter can carry its hook in has
// to be on that list, or a new adapter would lose the agent-config pause and
// the shield against ignore patterns without anyone noticing.
func TestAgentSettingsCoverEveryAdapter(t *testing.T) {
	files := integrations.Files()
	e := policy.New(config.Default(), t.TempDir(), files[0])
	for _, name := range files {
		d := e.Evaluate(event.Event{Type: "file", Action: "write", Target: name})
		if d.RuleID != "hook-tamper" && d.RuleID != "agent-config-modification" {
			t.Errorf("%s is not an agent configuration file to the engine: %+v", name, d)
		}
		if policy.Ignored(name, []string{"**"}) {
			t.Errorf("%s can be hidden by an ignore pattern", name)
		}
	}
}
