package dockerwatch

import (
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
