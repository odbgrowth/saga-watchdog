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

func TestToolsDenyAndUnattended(t *testing.T) {
	c, err := Parse(strings.NewReader("version: 1\nprofile: coding-agent\nmode: enforce\nrun:\n  unattended: true\ntools:\n  deny: [github/delete_repository, 'payments/*']\n"))
	if err != nil || !c.Run.Unattended || len(c.Tools.Deny) != 2 {
		t.Fatalf("unattended/tools.deny not parsed: %+v %v", c, err)
	}
	if Default().Run.Unattended || len(Default().Tools.Deny) != 0 {
		t.Fatal("defaults must be attended with an empty tools.deny")
	}
	for _, bad := range []string{"tools:\n  deny: ['/abs']\n", "tools:\n  deny: ['a/../b']\n", "tools:\n  deny: ['']\n", "tools:\n  deny: 'x'\n"} {
		if _, err := Parse(strings.NewReader("version: 1\nprofile: coding-agent\nmode: enforce\n" + bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestAllowListModes(t *testing.T) {
	c, err := Parse(strings.NewReader("version: 1\nprofile: coding-agent\nmode: enforce\nnetwork:\n  mode: allowlist\n  allow: [api.github.com, .pypi.org]\n  deny: [evil.example]\ntools:\n  mode: allowlist\n  allow: ['github/*', filesystem/read_file]\n"))
	if err != nil || c.Network.Mode != "allowlist" || len(c.Network.Allow) != 2 || c.Tools.Mode != "allowlist" || len(c.Tools.Allow) != 2 {
		t.Fatalf("allow lists not parsed: %+v %v", c, err)
	}
	if d := Default(); d.Network.Mode != "denylist" || d.Tools.Mode != "denylist" || len(d.Network.Allow) != 0 {
		t.Fatalf("defaults must be denylist mode: %+v", d)
	}
	for _, bad := range []string{
		"network:\n  mode: open\n",
		"tools:\n  mode: allow\n",
		"network:\n  allow: ['*.example.com']\n",
		"network:\n  allow: ['https://example.com']\n",
		"network:\n  deny: ['.example.com']\n",
		"tools:\n  allow: ['/abs']\n",
	} {
		if _, err := Parse(strings.NewReader("version: 1\nprofile: coding-agent\nmode: enforce\n" + bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestShellFollowUpAndRedirectorDefaults(t *testing.T) {
	if d := Default(); !d.Escalation.ShellFollowUp || !d.Network.DenyRedirectors {
		t.Fatalf("defaults must count shell follow-ups and deny redirectors: %+v", d)
	}
	c, err := Parse(strings.NewReader("version: 1\nprofile: coding-agent\nmode: enforce\nescalation:\n  shell_follow_up: false\nnetwork:\n  deny_redirectors: false\n"))
	if err != nil || c.Escalation.ShellFollowUp || c.Network.DenyRedirectors {
		t.Fatalf("overrides not parsed: %+v %v", c, err)
	}
}

func TestSecurityContextEffectsAndReplication(t *testing.T) {
	base := "version: 1\nprofile: coding-agent\nmode: enforce\n"
	c, err := Parse(strings.NewReader(base + "security_context:\n  authorization_context: dev-local\n  retention: 12h\neffects:\n  production.deploy: ['network:deploy.example.com', 'network:.vercel.com', 'tool:vercel/*']\nreplication:\n  same_host_workers: 2\n  allow_agents: [claude]\n  inference_endpoints: ['127.0.0.1:8000']\n  remote_hosts: [build-01]\n"))
	if err != nil || c.SecurityContext.AuthorizationContext != "dev-local" || c.SecurityContext.Retention != 12*time.Hour || c.SecurityContext.SeriousRetention != 7*24*time.Hour || len(c.Effects["production.deploy"]) != 3 || c.Replication.SameHostWorkers != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	d := Default()
	if d.SecurityContext.AuthorizationContext != "" || d.Replication.SameHostWorkers != 0 || len(d.Replication.AllowAgents) != 0 || len(d.Effects) != 0 {
		t.Fatalf("defaults must keep persistence off and replication closed: %+v", d)
	}
	for _, bad := range []string{
		"security_context:\n  authorization_context: Dev Local\n",
		"security_context:\n  retention: 10s\n",
		"security_context:\n  retention: 48h\n  serious_retention: 24h\n",
		"effects:\n  deploy: ['shell:rm']\n",
		"effects:\n  deploy: ['network:*.example.com']\n",
		"effects:\n  Deploy: ['tool:x']\n",
		"effects:\n  deploy: []\n",
		"replication:\n  same_host_workers: -1\n",
		"replication:\n  remote_hosts: ['host with space']\n",
		"replication:\n  allow_agents: ['/abs']\n",
	} {
		if _, err := Parse(strings.NewReader(base + bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, op := range []string{"human:onno", "service:ci-bot", "human:onno@example.com"} {
		if !OperatorID.MatchString(op) {
			t.Errorf("rejected %s", op)
		}
	}
	for _, op := range []string{"onno", "human:", "human:on no", "HUMAN:onno"} {
		if OperatorID.MatchString(op) {
			t.Errorf("accepted %s", op)
		}
	}
}
