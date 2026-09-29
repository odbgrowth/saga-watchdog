package dockerwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Opt-in: creates only disposable, uniquely named fixture containers and removes
// exactly their returned IDs. No existing workload is listed or controlled.
func TestDockerIntegration(t *testing.T) {
	socket := os.Getenv("SAGA_DOCKER_TEST_SOCKET")
	if socket == "" {
		t.Skip("set SAGA_DOCKER_TEST_SOCKET to run the disposable-container acceptance test")
	}
	image := os.Getenv("SAGA_DOCKER_TEST_IMAGE")
	if image == "" {
		image = "alpine:3.22"
	}
	c := NewClient(socket, 3*time.Second)
	defer c.Close()
	api, err := c.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, body any) []byte {
		t.Helper()
		var input io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			input = bytes.NewReader(b)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, err := http.NewRequestWithContext(ctx, method, c.base+api+path, input)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			t.Fatalf("fixture request %s %s returned HTTP %d (test image must already be available)", method, path, resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	name := fmt.Sprintf("saga-observer-test-%d", time.Now().UnixNano())
	var created []string
	t.Cleanup(func() {
		for _, id := range created {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			r, _ := http.NewRequestWithContext(ctx, http.MethodDelete, c.base+api+"/containers/"+id+"?force=true", nil)
			resp, err := c.http.Do(r)
			if err != nil {
				t.Error("fixture cleanup:", err)
			} else {
				resp.Body.Close()
				if resp.StatusCode != 204 && resp.StatusCode != 404 {
					t.Errorf("fixture cleanup HTTP %d", resp.StatusCode)
				}
			}
			cancel()
		}
	})
	create := func() string {
		b := request(http.MethodPost, "/containers/create?name="+url.QueryEscape(name), map[string]any{
			"Image": image, "Cmd": []string{"sh", "-c", "while :; do sleep 1; done"},
			"Labels":      map[string]string{"saga-watchdog.test": name},
			"HostConfig":  map[string]any{"NetworkMode": "none"},
			"Healthcheck": map[string]any{"Test": []string{"CMD-SHELL", "test ! -e /tmp/unhealthy"}, "Interval": int64(time.Second), "Timeout": int64(time.Second), "Retries": 1},
		})
		var v struct {
			ID string `json:"Id"`
		}
		if err := json.Unmarshal(b, &v); err != nil || !fullID.MatchString(v.ID) {
			t.Fatalf("fixture identity: %v", err)
		}
		created = append(created, v.ID)
		request(http.MethodPost, "/containers/"+v.ID+"/start", nil)
		return v.ID
	}
	id := create()
	type fixtureState struct {
		RestartCount int
		State        struct {
			Running   bool
			StartedAt string
		}
	}
	inspect := func() fixtureState {
		var v fixtureState
		if err := json.Unmarshal(request(http.MethodGet, "/containers/"+id+"/json", nil), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	baseline := inspect()
	cfg := testConfig(t)
	cfg.Socket = socket
	cfg.Targets[0].ID = id
	cfg.RequestTimeout = 3 * time.Second
	wait := func(description string, test func(Snapshot) bool) {
		t.Helper()
		until := time.Now().Add(15 * time.Second)
		var last Snapshot
		for time.Now().Before(until) {
			s, err := ReadSnapshot(cfg)
			if err == nil {
				last = s
				if test(s) {
					return
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s: %+v", description, last)
	}
	start := func() func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, cfg, c, false) }()
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Error("observer did not stop")
			}
		}
		t.Cleanup(stop)
		wait("live observations", func(s Snapshot) bool {
			return s.Observer == "running" && s.EventStream == "connected" && s.Targets[0].Availability == "present" && s.Targets[0].Resources != nil
		})
		return stop
	}
	stop := start()
	wait("health and CPU sample", func(s Snapshot) bool {
		return s.Targets[0].Health == "healthy" && s.Targets[0].Resources != nil && s.Targets[0].Resources.CPUPercent != nil
	})
	stop()
	if got := inspect(); !got.State.Running || got.State.StartedAt != baseline.State.StartedAt || got.RestartCount != baseline.RestartCount {
		t.Fatal("observation or shutdown changed the fixture lifecycle")
	}
	t.Log("attach and observer shutdown leave fixture running without restart")
	stop = start()
	if got := inspect(); !got.State.Running || got.State.StartedAt != baseline.State.StartedAt || got.RestartCount != baseline.RestartCount {
		t.Fatal("restarting observer changed the fixture lifecycle")
	}
	t.Log("observer restart leaves fixture running without restart")
	b := request(http.MethodPost, "/containers/"+id+"/exec", map[string]any{"Cmd": []string{"sh", "-c", "touch /tmp/unhealthy"}})
	var exec struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(b, &exec); err != nil || !fullID.MatchString(exec.ID) {
		t.Fatal("fixture exec identity invalid")
	}
	request(http.MethodPost, "/exec/"+exec.ID+"/start", map[string]any{"Detach": true})
	wait("unhealthy fixture", func(s Snapshot) bool { return s.Targets[0].Health == "unhealthy" })
	t.Log("live health failure observed")
	request(http.MethodDelete, "/containers/"+id+"?force=true", nil)
	replacement := create()
	wait("removed ID remains missing after same-name replacement", func(s Snapshot) bool { return s.Targets[0].Availability == "missing" })
	s, err := ReadSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Targets) != 1 || s.Targets[0].ID != id {
		t.Fatal("observer silently adopted a replacement")
	}
	stop()
	var history strings.Builder
	if err := CopyHistory(cfg.StateDir, &history); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(history.String(), replacement) || strings.Count(history.String(), `"action":"observer-start"`) != 2 {
		t.Fatal("history mixed replacement or lost earlier session")
	}
	t.Log("same-name replacement is not adopted; both observer sessions retained")
}
