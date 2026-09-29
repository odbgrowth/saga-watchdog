package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestProjectNamesRejectControlCharacters(t *testing.T) {
	// Cover ASCII controls, DEL and C1 controls, including terminal escapes.
	for r := 0; r <= 0x9f; r++ {
		if r >= 0x20 && r < 0x7f {
			continue
		}
		t.Run(fmt.Sprintf("U+%04X", r), func(t *testing.T) {
			input := fmt.Sprintf("project:\n  name: \"demo\\u%04Xname\"\n", r)
			if _, err := Parse(strings.NewReader(input)); err == nil {
				t.Fatal("project name containing a control character was accepted")
			}
		})
	}
	for _, name := range []string{"", "Customer project", "Boekhouding België", "顧客プロジェクト"} {
		cfg := Default()
		cfg.Project.Name = name
		if err := cfg.Validate(); err != nil {
			t.Errorf("valid project name %q rejected: %v", name, err)
		}
	}
}

func TestMinimalAndOverrides(t *testing.T) {
	cfg, err := Parse(strings.NewReader(DefaultYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Run.MaxDuration != 2*time.Hour || cfg.Escalation.KillAfter != 5 || cfg.Filesystem.DeleteThreshold != 100 {
		t.Fatalf("defaults missing: %+v", cfg)
	}
	cfg, err = Parse(strings.NewReader("version: 1\nprofile: coding-agent\nmode: observe\nrun:\n  max_duration: 20m\nnetwork:\n  deny: [production.example.com]\n"))
	if err != nil || cfg.Mode != "observe" || cfg.Run.MaxDuration != 20*time.Minute || cfg.Run.StopGracePeriod != 5*time.Second {
		t.Fatalf("overrides/default merge: %+v, %v", cfg, err)
	}
}

func TestRejectInvalidConfiguration(t *testing.T) {
	for name, input := range map[string]string{
		"empty": "", "list": "- version\n", "syntax": "[", "unknown": "version: 1\npermit_everything: true\n",
		"nested unknown": "run:\n  timeout: 2h\n", "duplicate": "mode: enforce\nmode: observe\n",
		"documents": "version: 1\n---\nmode: observe\n", "trailing empty document": "version: 1\n---\n",
		"duration": "run:\n  max_duration: someday\n", "duration numeric": "run:\n  max_duration: 200\n",
		"duration zero": "run:\n  max_duration: 0s\n", "grace negative": "run:\n  stop_grace_period: -1s\n",
		"mode": "mode: disabled\n", "version": "version: 2\n", "profile": "profile: magic\n",
		"threshold": "escalation:\n  pause_after: 2\n", "window": "escalation:\n  window: 0s\n",
		"deletions": "filesystem:\n  delete_threshold: 0\n", "invalid glob": "filesystem:\n  protect: ['[']\n",
		"absolute glob": "filesystem:\n  ignore: ['/etc/**']\n", "traversal glob": "filesystem:\n  protect: ['../a']\n",
		"null": "mode: null\n", "alias": "project: &p\n  name: sample\nrun: *p\n",
		"network URL":         "network:\n  deny: ['https://example.com']\n",
		"network empty label": "network:\n  deny: ['..']\n",
		"bad branch glob":     "git:\n  protected_branches: ['release/[']\n",
		"oversized":           strings.Repeat("# comment\n", 10000),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(input)); err == nil {
				t.Fatal("invalid policy was accepted")
			}
		})
	}
}

func TestDefaultsAreIndependent(t *testing.T) {
	a := Default()
	a.Filesystem.Protect[0] = "wrong"
	a.Git.ProtectedBranches[0] = "wrong"
	b := Default()
	if b.Filesystem.Protect[0] != Filename || b.Git.ProtectedBranches[0] != "main" {
		t.Fatal("default slices were shared")
	}
}
