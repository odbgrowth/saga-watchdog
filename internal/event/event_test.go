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
