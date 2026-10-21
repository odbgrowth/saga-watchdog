package config

import (
	"os"
	"strings"
	"testing"
)

// The shipped examples must parse, and the hardened one must hold the
// settings its name promises.
func TestExamplesParse(t *testing.T) {
	for _, name := range []string{"minimal", "coding-agent", "hardened-coding-agent"} {
		f, err := os.Open("../../examples/" + name + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := Parse(f)
		f.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "hardened-coding-agent" && (!cfg.Run.RequirePreventiveHook || cfg.Mode != "enforce" || cfg.Network.Mode != "allowlist" || cfg.Tools.Mode != "allowlist" || cfg.SecurityContext.AuthorizationContext == "" || len(cfg.Effects) == 0 || cfg.Replication.SameHostWorkers != 0) {
			t.Fatalf("hardened example is not hardened: %+v", cfg)
		}
	}
	// Legacy policies do not know the setting; it stays off.
	cfg, err := Parse(strings.NewReader(DefaultYAML))
	if err != nil || cfg.Run.RequirePreventiveHook {
		t.Fatalf("legacy default: %+v %v", cfg.Run, err)
	}
}
