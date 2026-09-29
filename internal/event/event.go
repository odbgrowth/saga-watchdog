// Package event defines the small, redacted audit envelope shared by all sources.
package event

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

type Event struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	ProjectID string         `json:"project_id"`
	RunID     string         `json:"run_id"`
	Source    string         `json:"source"`
	Type      string         `json:"type"`
	Action    string         `json:"action"`
	Target    string         `json:"target"`
	Result    string         `json:"result"`
	Severity  string         `json:"severity"`
	RuleID    string         `json:"rule_id,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// NewID returns a timestamp-prefixed identifier with 128 bits of randomness.
// Failing to obtain randomness is fatal rather than silently issuing weak IDs.
func NewID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("generate event ID: %w", err))
	}
	return fmt.Sprintf("%s_%013d_%s", prefix, time.Now().UTC().UnixMilli(), hex.EncodeToString(b[:]))
}

var (
	assignments = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key)\s*[:=]\s*("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`)
	bearer      = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[a-z0-9._~+/=-]+`)
	knownToken  = regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,}|sk-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16})\b`)
	urls        = regexp.MustCompile(`https?://[^\s<>"']+`)
	privateKey  = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)`)
	headers     = regexp.MustCompile(`(?im)\b(authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]*`)
)

// Redact is defense in depth, not a promise to recognize arbitrary secrets.
// Callers must avoid collecting file bodies, command output, and environment values.
func Redact(s string) string {
	s = privateKey.ReplaceAllString(s, "[redacted-private-key]")
	s = headers.ReplaceAllString(s, "$1=[redacted]")
	s = urls.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return "[redacted-url]"
		}
		u.User = nil
		if u.RawQuery != "" {
			u.RawQuery = "redacted"
		}
		if u.Fragment != "" {
			u.Fragment = "redacted"
		}
		return u.String()
	})
	s = bearer.ReplaceAllString(s, "$1 [redacted]")
	s = assignments.ReplaceAllString(s, "$1=[redacted]")
	s = knownToken.ReplaceAllString(s, "[redacted]")
	return s
}

func safe(s string, limit int) string {
	s = strings.ToValidUTF8(Redact(s), "�")
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}

// Sanitized creates an independent bounded audit copy. Arbitrary client metadata
// is intentionally discarded; only these non-secret scalar diagnostic keys survive.
func (e Event) Sanitized() Event {
	e.ID = safe(e.ID, 128)
	e.ProjectID = safe(e.ProjectID, 128)
	e.RunID = safe(e.RunID, 128)
	e.Source = safe(e.Source, 64)
	e.Type = safe(e.Type, 64)
	e.Action = safe(e.Action, 64)
	e.Target = safe(e.Target, 1024)
	e.Result = safe(e.Result, 64)
	e.Severity = safe(e.Severity, 32)
	e.RuleID = safe(e.RuleID, 128)
	var metadata map[string]any
	for _, key := range []string{"reason", "branch", "exit_code", "count", "policy_action", "decision", "mode", "enforced", "duration_ms", "signal", "would_action"} {
		value, ok := e.Metadata[key]
		if !ok {
			continue
		}
		if metadata == nil {
			metadata = make(map[string]any)
		}
		switch v := value.(type) {
		case string:
			metadata[key] = safe(v, 512)
		case bool, int, int64, uint64, float64:
			metadata[key] = v
		}
	}
	e.Metadata = metadata
	return e
}
