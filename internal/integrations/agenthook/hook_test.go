package agenthook

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/odbgrowth/saga-watchdog/internal/policy"
	"github.com/odbgrowth/saga-watchdog/internal/sources/socket"
)

func TestRunEvaluatesEveryRequestAndStopsAtTheFirstDenial(t *testing.T) {
	var seen []string
	send := func(_ string, r socket.Request) (socket.Response, error) {
		seen = append(seen, r.Event.Target)
		if r.Event.Target == ".env" {
			return socket.Response{Allowed: false, Decision: &policy.Decision{Action: "pause", RuleID: "protected-path", Reason: "protected"}}, nil
		}
		return socket.Response{Allowed: true, Decision: &policy.Decision{Action: "warn", RuleID: "rule-" + r.Event.Target, Reason: "careful"}}, nil
	}
	normalize := func([]byte) ([]socket.Request, error) {
		var out []socket.Request
		for _, target := range strings.Split("a b .env c", " ") {
			out = append(out, socket.Request{Operation: "check", Event: socket.Input{Type: "file", Action: "write", Target: target}})
		}
		return out, nil
	}
	var stdout, stderr bytes.Buffer
	code := Run(strings.NewReader("{}"), &stdout, &stderr, Options{Socket: "/s", RunID: "run_test_1", Send: send}, "codex", normalize)
	if code != 2 || strings.Join(seen, ",") != "a,b,.env" || !strings.Contains(stderr.String(), "Rule: protected-path") || !strings.Contains(stderr.String(), "saga-watchdog resume run_test_1") {
		t.Fatalf("code %d seen %v stderr %s", code, seen, stderr.String())
	}
	seen, stdout, stderr = nil, bytes.Buffer{}, bytes.Buffer{}
	normalize = func([]byte) ([]socket.Request, error) {
		return []socket.Request{
			{Operation: "check", Event: socket.Input{Type: "file", Action: "write", Target: "a"}},
			{Operation: "emit", Event: socket.Input{Type: "file", Action: "write", Target: "a", Result: "success"}},
			{Operation: "check", Event: socket.Input{Type: "file", Action: "write", Target: "b"}},
		}, nil
	}
	if code := Run(strings.NewReader("{}"), &stdout, &stderr, Options{Socket: "/s", RunID: "run_test_1", Send: send}, "codex", normalize); code != 0 || len(seen) != 3 {
		t.Fatalf("code %d seen %v", code, seen)
	}
	if out := stdout.String(); !strings.Contains(out, `"systemMessage"`) || !strings.Contains(out, "[rule-a]") || !strings.Contains(out, "[rule-b]") || strings.Count(out, "\n") != 1 {
		t.Fatalf("warnings not merged into one JSON line: %q", out)
	}
	stderr.Reset()
	normalize = func([]byte) ([]socket.Request, error) { return nil, errors.New("unreadable") }
	if code := Run(strings.NewReader("{}"), &stdout, &stderr, Options{Socket: "/s", RunID: "run_test_1", Send: send}, "gemini", normalize); code != 2 || !strings.Contains(stderr.String(), "saga-watchdog run -- gemini") {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
}

func TestHelpers(t *testing.T) {
	if got := Identifier("a b\tc\x00d" + strings.Repeat("x", 200)); strings.ContainsAny(got, " \t\x00") || len(got) != 128 {
		t.Fatalf("%q", got)
	}
	if host, ok := Host("https://User:pw@Example.COM:8443/p?q=1"); !ok || host != "example.com" {
		t.Fatalf("%q %t", host, ok)
	}
	if _, ok := Host("not a url"); ok {
		t.Fatal("accepted a URL without host")
	}
	for name, tc := range map[string]struct {
		in, prefix, sep, want string
		ok                    bool
	}{
		"claude": {"mcp__github__get_issue", "mcp__", "__", "github/get_issue", true},
		"gemini": {"mcp_github_get_issue_by_id", "mcp_", "_", "github/get_issue_by_id", true},
		"plain":  {"Write", "mcp__", "__", "", false},
		"empty":  {"mcp____x", "mcp__", "__", "", false},
	} {
		if got, ok := MCPTarget(tc.in, tc.prefix, tc.sep); got != tc.want || ok != tc.ok {
			t.Errorf("%s: %q %t", name, got, ok)
		}
	}
}
