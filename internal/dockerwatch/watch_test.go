package dockerwatch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestObservationRestartRetainsHistoryAndNeverMutates(t *testing.T) {
	cfg := testConfig(t)
	c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			fmt.Fprint(w, `{"ApiVersion":"1.56","MinAPIVersion":"1.44"}`)
		case "/v1.56/containers/" + testID + "/json":
			fmt.Fprintf(w, `{"Id":%q,"RestartCount":3,"State":{"Status":"running","Health":{"Status":"unhealthy","Log":[{"Output":"application-secret"}]}},"Config":{"Env":["TOKEN=application-secret"]}}`, testID)
		case "/v1.56/containers/" + testID + "/stats":
			fmt.Fprintf(w, `{"id":%q,"read":"2026-09-29T09:00:00Z","memory_stats":{"usage":4096,"limit":8192}}`, testID)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	var lastSession string
	for n := 0; n < 2; n++ {
		if err := Run(context.Background(), cfg, c, true); err != nil {
			t.Fatal(err)
		}
		s, err := ReadSnapshot(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if s.Observer != "stopped" || s.Targets[0].Health != "unhealthy" || s.Targets[0].Resources.MemoryBytes != 4096 || s.Targets[0].RestartCount != 3 || s.SessionID == lastSession {
			t.Fatalf("unexpected status %+v", s)
		}
		lastSession = s.SessionID
	}
	var b strings.Builder
	if err := CopyHistory(cfg.StateDir, &b); err != nil {
		t.Fatal(err)
	}
	if strings.Count(b.String(), `"action":"observer-start"`) != 2 || strings.Contains(b.String(), "application-secret") {
		t.Fatal("history was lost or secrets were retained")
	}
}

func TestPollReportsMissingUnknownAndResourceFailures(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		status                 int
		endpoint, availability string
	}{
		{"removed", 404, "json", "missing"}, {"lost-daemon", 503, "version", "unknown"}, {"stats-failure", 503, "stats", "present"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, tc.endpoint) {
					w.WriteHeader(tc.status)
					return
				}
				if r.URL.Path == "/version" {
					fmt.Fprint(w, `{"ApiVersion":"1.56"}`)
					return
				}
				fmt.Fprintf(w, `{"Id":%q,"State":{"Status":"running"}}`, testID)
			})
			s, _ := poll(context.Background(), c, []Target{{Name: "agent", ID: testID}}, []*resourceSample{nil})
			if s[0].Availability != tc.availability || s[0].Resources != nil {
				t.Fatalf("%+v", s[0])
			}
			if tc.name == "stats-failure" && (s[0].StatsError == "" || s[0].Health != "none") {
				t.Fatal("missing health/stats coverage hidden")
			}
		})
	}
}

func TestCPUSamplesAndCounterReset(t *testing.T) {
	c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/json") {
			fmt.Fprintf(w, `{"Id":%q,"State":{"Status":"running"}}`, testID)
			return
		}
		fmt.Fprintf(w, `{"id":%q,"read":"2026-09-29T09:00:00Z","cpu_stats":{"cpu_usage":{"total_usage":300},"system_cpu_usage":2000,"online_cpus":2}}`, testID)
	})
	p := &resourceSample{}
	p.CPU.Usage.Total = 200
	p.CPU.System = 1000
	s, _ := inspectTarget(context.Background(), c, "/v1.56", Target{ID: testID}, p)
	if s.Resources.CPUPercent == nil || *s.Resources.CPUPercent != 20 {
		t.Fatalf("%+v", s.Resources)
	}
	p.CPU.Usage.Total = 400
	s, _ = inspectTarget(context.Background(), c, "/v1.56", Target{ID: testID}, p)
	if s.Resources.CPUPercent != nil {
		t.Fatal("counter reset produced misleading CPU sample")
	}
}

func TestCPUBaselineIsReplacedAfterRestart(t *testing.T) {
	restarts, total, system := 2, 300, 2000
	c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/version":
			fmt.Fprint(w, `{"ApiVersion":"1.56"}`)
		case strings.HasSuffix(r.URL.Path, "/json"):
			fmt.Fprintf(w, `{"Id":%q,"RestartCount":%d,"State":{"Status":"running"}}`, testID, restarts)
		case strings.HasSuffix(r.URL.Path, "/stats"):
			fmt.Fprintf(w, `{"id":%q,"read":"2026-09-29T09:00:00Z","cpu_stats":{"cpu_usage":{"total_usage":%d},"system_cpu_usage":%d,"online_cpus":2}}`, testID, total, system)
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(404)
		}
	})
	targets := []Target{{Name: "agent", ID: testID}}
	_, previous := poll(context.Background(), c, targets, []*resourceSample{nil})
	// A restarted workload can exceed the old CPU total before the next poll.
	restarts, total, system = 3, 400, 3000
	statuses, next := poll(context.Background(), c, targets, previous)
	if statuses[0].Resources == nil || statuses[0].Resources.CPUPercent != nil || next[0].RestartCount != 3 {
		t.Fatalf("cross-restart CPU sample was used: %+v", statuses[0])
	}
	total, system = 500, 4000
	statuses, _ = poll(context.Background(), c, targets, next)
	if statuses[0].Resources.CPUPercent == nil || *statuses[0].Resources.CPUPercent != 20 {
		t.Fatalf("CPU did not resume with the new baseline: %+v", statuses[0].Resources)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStreamBackoffRequiresAHealthyConnection(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []time.Duration
	}{
		{"empty", []time.Duration{1, 2, 4, 8, 16, 30, 30}},
		{"event", []time.Duration{1, 2, 1, 2}},
		{"idle", []time.Duration{1, 2, 31, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var attempts []time.Time
				transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.Method != http.MethodGet {
						t.Fatalf("unexpected mutation: %s", r.Method)
					}
					body := io.NopCloser(strings.NewReader(`{"ApiVersion":"1.56"}`))
					if strings.HasSuffix(r.URL.Path, "/events") {
						attempts = append(attempts, time.Now())
						body = io.NopCloser(strings.NewReader(""))
						if len(attempts) == 3 {
							switch tc.name {
							case "event":
								body = io.NopCloser(strings.NewReader(fmt.Sprintf("{\"Type\":\"container\",\"Action\":\"oom\",\"Actor\":{\"ID\":%q}}\n", testID)))
							case "idle":
								reader, writer := io.Pipe()
								body = reader
								go func() { time.Sleep(30 * time.Second); writer.Close() }()
							}
						}
						if len(attempts) > len(tc.want) {
							cancel()
						}
					}
					return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
				})
				c := &Client{http: &http.Client{Transport: transport}, base: "http://docker", timeout: time.Second}
				stream(ctx, c, []string{testID}, make(chan streamMessage, 64))
				if len(attempts) != len(tc.want)+1 {
					t.Fatalf("unexpected connection attempts: %d", len(attempts))
				}
				for n, want := range tc.want {
					if got := attempts[n+1].Sub(attempts[n]); got != want*time.Second {
						t.Errorf("reconnect %d waited %v, want %v", n+1, got, want*time.Second)
					}
				}
			})
		})
	}
}

func TestStreamReconnectAndObserverCancellation(t *testing.T) {
	cfg := testConfig(t)
	var connections atomic.Int32
	c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/version":
			fmt.Fprint(w, `{"ApiVersion":"1.56"}`)
		case strings.HasSuffix(r.URL.Path, "/json"):
			fmt.Fprintf(w, `{"Id":%q,"State":{"Status":"running"}}`, testID)
		case strings.HasSuffix(r.URL.Path, "/stats"):
			fmt.Fprintf(w, `{"id":%q,"read":"2026-09-29T09:00:00Z"}`, testID)
		case strings.HasSuffix(r.URL.Path, "/events"):
			n := connections.Add(1)
			fmt.Fprintf(w, "{\"Type\":\"container\",\"Action\":\"oom\",\"Actor\":{\"ID\":%q}}\n", testID)
			w.(http.Flusher).Flush()
			if n > 1 {
				<-r.Context().Done()
			}
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(404)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, c, false) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s, err := ReadSnapshot(cfg)
		if err == nil && connections.Load() >= 2 && s.EventStream == "connected" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if connections.Load() < 2 {
		t.Fatal("event stream did not reconnect")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		done <- nil
	case <-time.After(3 * time.Second):
		t.Fatal("observer did not stop promptly")
	}
	s, err := ReadSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Observer != "stopped" {
		t.Fatal(s.Observer)
	}
	b, err := os.ReadFile(filepath.Join(cfg.StateDir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"action":"oom"`, `"result":"disconnected"`, `"result":"connected"`, `"action":"observer-stop"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing %s", want)
		}
	}
}

func TestStatusCannotRemainFreshAfterCrash(t *testing.T) {
	c := testConfig(t)
	s := Snapshot{Observer: "running", UpdatedAt: time.Now().Add(-time.Minute), Targets: []TargetStatus{{Availability: "present"}}}
	s.Refresh(c, time.Now())
	if s.Observer != "stale" || s.Targets[0].Availability != "unknown" {
		t.Fatal(s)
	}
}
