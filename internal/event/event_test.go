package event

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRedact(t *testing.T) {
	for _, test := range []struct{ input, secret string }{
		{"password=hunter2", "hunter2"},
		{"token: 'a private value'", "a private value"},
		{"Authorization: Bearer very-sensitive-credential", "very-sensitive-credential"},
		{"Cookie=sessionabc123", "sessionabc123"},
		{"https://user:password@example.com/path?access_token=topsecret#private", "topsecret"},
		{"ghp_1234567890abcdef", "ghp_1234567890abcdef"},
		{"sk-1234567890abcdef", "sk-1234567890abcdef"},
		{"-----BEGIN OPENSSH PRIVATE KEY-----\nsecretmaterial\n-----END OPENSSH PRIVATE KEY-----", "secretmaterial"},
	} {
		if got := Redact(test.input); strings.Contains(got, test.secret) {
			t.Errorf("secret remains in %q", got)
		}
	}
	if Redact("src/main.go") != "src/main.go" {
		t.Fatal("ordinary paths must remain readable")
	}
}

func TestSanitizedCopy(t *testing.T) {
	original := Event{Target: strings.Repeat("é", 2000), Metadata: map[string]any{
		"prompt": "never collect me", "token": "secret", "reason": "token=sensitive", "count": 3,
		"branch": map[string]any{"secret": "hidden"},
	}}
	clean := original.Sanitized()
	if !utf8.ValidString(clean.Target) || len(clean.Target) > 1030 || clean.Metadata["count"] != 3 {
		t.Fatalf("bad bounded metadata: %+v", clean)
	}
	for _, key := range []string{"prompt", "token", "branch"} {
		if _, ok := clean.Metadata[key]; ok {
			t.Errorf("unexpected metadata key %s", key)
		}
	}
	encoded, err := json.Marshal(clean)
	if err != nil || strings.Contains(string(encoded), "sensitive") {
		t.Fatalf("secret remains: %s, %v", encoded, err)
	}
	clean.Metadata["count"] = 10
	if original.Metadata["count"] != 3 {
		t.Fatal("sanitization mutates producer metadata")
	}
}

func TestUniqueIDs(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := NewID("event")
		if seen[id] || !strings.HasPrefix(id, "event_") {
			t.Fatalf("bad identifier %s", id)
		}
		seen[id] = true
	}
}

func TestSanitizedKeepsBoundedLineageOnly(t *testing.T) {
	clean := Event{Metadata: map[string]any{
		"producer": "claude-code", "tool_name": "Edit", "agent_id": "agent-1", "agent_type": "custom",
		"tool_use_id": "toolu_01", "session_id": "sess-1",
		"tool_input": map[string]any{"content": "secret body"}, "command": "curl -H 'Authorization: Bearer x'",
	}}.Sanitized()
	for _, key := range []string{"producer", "tool_name", "agent_id", "agent_type", "tool_use_id", "session_id"} {
		if _, ok := clean.Metadata[key]; !ok {
			t.Errorf("lineage key %s dropped", key)
		}
	}
	for _, key := range []string{"tool_input", "command"} {
		if _, ok := clean.Metadata[key]; ok {
			t.Errorf("payload key %s persisted", key)
		}
	}
}
