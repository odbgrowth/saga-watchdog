package dockerwatch

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const otherID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{Version: 1, Mode: "observe", Socket: "/var/run/docker.sock", StateDir: t.TempDir() + "/state", PollInterval: time.Second, RequestTimeout: time.Second, Targets: []Target{{Name: "agent", ID: testID}}}
}

func TestConfigRejectsUnsupportedAuthority(t *testing.T) {
	valid := fmt.Sprintf("version: 1\nmode: observe\nstate_dir: /tmp/saga-test-state\ntargets:\n  - name: agent\n    container_id: %s\n", testID)
	for name, text := range map[string]string{
		"valid":            valid,
		"enforce":          strings.Replace(valid, "observe", "enforce", 1),
		"name-as-id":       strings.Replace(valid, testID, "my-agent", 1),
		"short-id":         strings.Replace(valid, testID, testID[:12], 1),
		"unknown":          valid + "auto_stop: true\n",
		"duplicate":        valid + "mode: observe\n",
		"null":             strings.Replace(valid, "observe", "null", 1),
		"extra-document":   valid + "---\nmode: observe\n",
		"alias":            valid + "alias: &x 1\nother: *x\n",
		"poll-zero":        valid + "poll_interval: 0s\n",
		"no-targets":       "version: 1\nmode: observe\nstate_dir: /tmp/saga-state\n",
		"relative-state":   strings.Replace(valid, "/tmp/saga-test-state", "relative", 1),
		"duplicate-target": valid + "  - name: second\n    container_id: " + testID + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			c, err := Parse(strings.NewReader(text))
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if c.PollInterval != 10*time.Second {
					t.Fatal("missing defaults")
				}
			} else if err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}

func TestAgentImagesConfig(t *testing.T) {
	base := fmt.Sprintf("version: 1\nmode: observe\nstate_dir: /tmp/saga-test-state\ntargets:\n  - name: agent\n    container_id: %s\n", testID)
	if c, err := Parse(strings.NewReader(base + "agent_images:\n  - image: ghcr.io/acme/agent\n    runtime_type: agent\n")); err != nil || len(c.AgentImages) != 1 {
		t.Fatalf("%v %+v", err, c)
	}
	plain, err := Parse(strings.NewReader(base))
	if err != nil {
		t.Fatal(err)
	}
	// The identity hash covers the JSON form; an unset field must not appear,
	// or every existing observer state would belong to "another config".
	if b, _ := json.Marshal(plain); strings.Contains(string(b), "agent_images") || strings.Contains(string(b), "AgentImages") {
		t.Fatalf("config identity of existing configurations changed: %s", b)
	}
	for _, bad := range []string{
		"agent_images:\n  - image: 'ghcr.io/acme/agent; rm'\n    runtime_type: agent\n",
		"agent_images:\n  - image: ghcr.io/acme/agent\n    runtime_type: root\n",
		"agent_images:\n  - image: ghcr.io/acme/agent\n    runtime_type: agent\n    auto_stop: true\n",
	} {
		if _, err := Parse(strings.NewReader(base + bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
