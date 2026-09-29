package socket

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/policy"
)

func TestDecodeRequestsAndRejectOverrides(t *testing.T) {
	for _, input := range []string{
		`{"operation":"check","event":{"type":"network","action":"connect","target":"example.com"}}`,
		`{"operation":"emit","event":{"type":"network","action":"connect","target":"example.com","result":"denied"}}`,
	} {
		if _, err := Decode([]byte(input), false); err != nil {
			t.Errorf("valid request rejected: %v", err)
		}
	}
	for name, input := range map[string]string{
		"malformed": `{"operation":`,
		"trailing": `{"operation":"check","event":{"type":"file","action":"write","target":"a"}} {}`,
		"unknown": `{"operation":"check","allow":true,"event":{"type":"file","action":"write","target":"a"}}`,
		"override": `{"operation":"check","event":{"type":"file","action":"write","target":"a","ignore_policy":true}}`,
		"timestamp": `{"operation":"emit","event":{"type":"network","action":"connect","target":"a","timestamp":"2000-01-01"}}`,
		"check result": `{"operation":"check","event":{"type":"file","action":"write","target":"a","result":"allowed"}}`,
		"metadata": `{"operation":"emit","event":{"type":"network","action":"connect","target":"a","metadata":{"mode":"observe"}}}`,
		"control": `{"operation":"resume"}`,
		"type": `{"operation":"emit","event":{"type":"model-says-safe","action":"allow","target":"a"}}`,
		"newline": `{"operation":"check","event":{"type":"file","action":"write","target":"a\nb"}}`,
		"missing target": `{"operation":"check","event":{"type":"file","action":"write"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(input), false); err == nil {
				t.Fatal("unsafe or invalid request accepted")
			}
		})
	}
	if _, err := Decode([]byte(`{"operation":"resume"}`), true); err != nil {
		t.Fatalf("human control rejected: %v", err)
	}
	if _, err := Decode([]byte(`{"operation":"check","event":{"type":"file","action":"write","target":"a"}}`), true); err == nil {
		t.Fatal("event accepted at control endpoint")
	}
	if err := Validate(Request{Operation: "check", Event: Input{Type: "file", Action: "write", Target: strings.Repeat("x", 4097)}}, false); err == nil {
		t.Fatal("oversized target accepted")
	}
}

func startTestServer(t *testing.T) (*Server, chan Call, context.CancelFunc) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket integration is supported on Linux and macOS")
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan Call, 64)
	s, err := Start(ctx, calls)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := s.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	})
	return s, calls, cancel
}

func TestSocketRequestsPermissionsAndDisconnect(t *testing.T) {
	s, calls, _ := startTestServer(t)
	for path, want := range map[string]os.FileMode{s.Dir: 0700, s.Events: 0600, s.Control: 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("permissions for %s: %v, %v", path, info, err)
		}
	}
	requests := []Request{
		{Operation: "check", Event: Input{Type: "file", Action: "write", Target: "ordinary.go"}},
		{Operation: "emit", Event: Input{Type: "network", Action: "connect", Target: "denied.example", Result: "denied"}},
	}
	for _, request := range requests {
		response := make(chan error, 1)
		go func(request Request) {
			got, err := Send(s.Events, request)
			if err == nil && (!got.Allowed || got.Decision == nil || got.Decision.Action != "allow") {
				err = &unexpectedResponse{response: got}
			}
			response <- err
		}(request)
		select {
		case call := <-calls:
			if call.Request != request {
				t.Fatalf("request altered: %+v", call.Request)
			}
			call.Reply <- Response{Allowed: true, Decision: &policy.Decision{Action: "allow", Severity: "info"}}
		case <-time.After(5*time.Second):
			t.Fatal("valid request not delivered")
		}
		if err := <-response; err != nil {
			t.Fatal(err)
		}
	}
	// Disconnects before a request must not poison subsequent connections.
	c, err := net.Dial("unix", s.Events)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c, err = net.Dial("unix", s.Events)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5*time.Second))
	if _, err := c.Write([]byte("{broken-json}\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var rejected Response
	if err := json.Unmarshal(line, &rejected); err != nil || rejected.Error == "" {
		t.Fatalf("malformed request not rejected: %s, %v", line, err)
	}
	select {
	case call := <-calls:
		t.Fatalf("malformed request reached policy: %+v", call)
	default:
	}
}

type unexpectedResponse struct { response Response }
func (e *unexpectedResponse) Error() string { return "unexpected policy response" }

func TestConcurrentClientsAndCancelledHandlers(t *testing.T) {
	s, calls, cancel := startTestServer(t)
	const clients = 8
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Send(s.Events, Request{Operation: "check", Event: Input{Type: "network", Action: "connect", Target: "example.com"}})
			errs <- err
		}()
	}
	for i := 0; i < clients; i++ {
		select {
		case call := <-calls:
			call.Reply <- Response{Allowed: true}
		case <-time.After(5*time.Second):
			t.Fatal("concurrent request stalled")
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// A handler awaiting a supervisor reply exits when its run is cancelled.
	pending := make(chan error, 1)
	go func() {
		_, err := Send(s.Events, Request{Operation: "emit", Event: Input{Type: "tool", Action: "attempt", Target: "alternate-tool"}})
		pending <- err
	}()
	select {
	case <-calls:
	case <-time.After(5*time.Second):
		t.Fatal("pending request never reached supervisor")
	}
	cancel()
	select {
	case err := <-pending:
		if err == nil {
			t.Fatal("cancelled request unexpectedly succeeded")
		}
	case <-time.After(5*time.Second):
		t.Fatal("cancelled handler leaked")
	}
}
