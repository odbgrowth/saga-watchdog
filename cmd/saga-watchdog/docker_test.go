package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerCommandsDoNotRequireGit(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	path := filepath.Join(dir, "docker.yaml")
	text := fmt.Sprintf("version: 1\nmode: observe\nstate_dir: %q\nsocket: %q\ntargets:\n  - name: agent\n    container_id: %s\n", filepath.Join(dir, "state"), filepath.Join(dir, "docker.sock"), strings.Repeat("a", 64))
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if code := cli([]string{"docker", "validate", "--config", path}); code != 0 {
		t.Fatal(code)
	}
	for _, args := range [][]string{{"docker"}, {"docker", "kill", "--config", path}, {"docker", "watch", "--config", path, "unexpected"}, {"docker", "validate", "--config", path, "--once"}, {"docker", "status", "--config", path}} {
		if code := cli(args); code != 2 {
			t.Fatalf("%v returned %d", args, code)
		}
	}
}
