// Package policy makes deterministic decisions over observable events. It does
// not enforce OS permissions or infer intent from model output.
package policy

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
)

type Decision struct {
	Action   string `json:"action"`
	RuleID   string `json:"rule_id,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Severity string `json:"severity"`
}

type observation struct {
	at     time.Time
	typeID string
	target string
}

// Engine is owned by one serialized supervisor loop. Config and its slices are
// copied at construction; later caller mutations cannot expand active authority.
type Engine struct {
	cfg       config.Config
	root      string
	last      time.Time
	denials   []observation
	deletions []observation
}

func New(cfg config.Config, root string) *Engine {
	cfg.Git.ProtectedBranches = append([]string(nil), cfg.Git.ProtectedBranches...)
	cfg.Filesystem.Protect = append([]string(nil), cfg.Filesystem.Protect...)
	cfg.Filesystem.Ignore = append([]string(nil), cfg.Filesystem.Ignore...)
	cfg.Network.Deny = append([]string(nil), cfg.Network.Deny...)
	return &Engine{cfg: cfg, root: root}
}

func decide(action, rule, reason string) Decision {
	severity := map[string]string{"allow": "info", "warn": "warning", "pause": "high", "kill": "critical"}[action]
	return Decision{Action: action, RuleID: rule, Reason: reason, Severity: severity}
}

// Evaluate leaves observe/enforce handling to the supervisor: audit decisions
// must retain the exact action that would have been applied in enforce mode.
// Timestamp must be assigned by the supervisor, never accepted from a client.
func (e *Engine) Evaluate(ev event.Event) Decision {
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(e.last) {
		now = e.last
	}
	e.last = now
	e.denials = recent(e.denials, now.Add(-e.cfg.Escalation.Window))
	e.deletions = recent(e.deletions, now.Add(-e.cfg.Filesystem.DeleteWindow))

	base := decide("allow", "", "")
	if ev.Type == "file" {
		base = e.file(ev, now)
	} else if ev.Type == "policy" && (ev.Action == "tamper" || ev.Action == "write" || ev.Action == "disable") {
		base = decide("kill", "policy-tamper", "effective policy cannot be changed during a run")
	} else if ev.Type == "git" && (ev.Action == "branch" || ev.Action == "branch-change" || ev.Action == "checkout" || ev.Action == "switch") && !e.cfg.Git.AllowProtected {
		for _, branch := range e.cfg.Git.ProtectedBranches {
			if Match(branch, ev.Target) {
				base = decide("pause", "protected-branch", "agent entered a protected branch")
				break
			}
		}
	} else if ev.Type == "network" {
		for _, host := range e.cfg.Network.Deny {
			if strings.EqualFold(strings.TrimSuffix(host, "."), networkHost(ev.Target)) {
				base = decide("pause", "network-denied", "target hostname is denied by project policy")
				break
			}
		}
	}
	if base.Action == "kill" {
		return base
	}
	denied := ev.Result == "denied" || ev.Result == "blocked" || (ev.Type == "policy" && ev.Action == "denied")
	if base.Action == "pause" {
		denied = true
	}
	escalation := e.escalate(ev, now, denied)
	if rank(escalation.Action) > rank(base.Action) || (base.RuleID == "" && escalation.RuleID != "") {
		return escalation
	}
	return base
}

func (e *Engine) file(ev event.Event, now time.Time) Decision {
	if ev.Action != "write" && ev.Action != "create" && ev.Action != "rename" && ev.Action != "delete" && ev.Action != "chmod" {
		return decide("allow", "", "")
	}
	// Check the policy's lexical name as well as its resolved name. Replacing
	// it with an external or dangling symlink is itself policy tampering.
	if lexicalRootFile(e.root, ev.Target, config.Filename) {
		return decide("kill", "policy-tamper", config.Filename+" changed during an active run")
	}
	target, err := Normalize(e.root, ev.Target)
	if err != nil {
		return decide("pause", "unsafe-path", err.Error())
	}
	if target == config.Filename {
		return decide("kill", "policy-tamper", config.Filename+" changed during an active run")
	}
	lexical, err := normalize(e.root, ev.Target, false)
	if err != nil {
		return decide("pause", "unsafe-path", err.Error())
	}
	removed := ev.Action == "delete" || ev.Action == "rename"
	if removed && target == "." {
		return decide("kill", "policy-tamper", "project root containing active policy was removed or renamed")
	}
	for _, name := range []string{lexical, target} {
		if name == ".git" || name == ".git/config" || Match(".git/hooks/**", name) {
			return decide("pause", "git-security-modification", "Git security configuration changed")
		}
		if Match(".github/workflows/**", name) || (removed && name == ".github") {
			return decide("pause", "ci-workflow-modification", "CI workflow changed")
		}
		for _, pattern := range e.cfg.Filesystem.Protect {
			if Match(pattern, name) {
				return decide("pause", "protected-path", "protected project path changed")
			}
		}
	}
	if Ignored(target, e.cfg.Filesystem.Ignore) {
		return decide("allow", "", "")
	}
	if ev.Action == "delete" || ev.Action == "rename" {
		// Count unique paths within the window; duplicated watcher notifications
		// for one removed path must not look like a large deletion burst.
		found := false
		for _, deletion := range e.deletions {
			if deletion.target == target {
				found = true
				break
			}
		}
		if !found {
			e.deletions = appendBounded(e.deletions, observation{at: now, target: target}, e.cfg.Filesystem.DeleteThreshold+1)
		}
		if len(e.deletions) > e.cfg.Filesystem.DeleteThreshold {
			return decide("pause", "mass-deletion", fmt.Sprintf("more than %d distinct paths removed or renamed within %s", e.cfg.Filesystem.DeleteThreshold, e.cfg.Filesystem.DeleteWindow))
		}
	}
	return decide("allow", "", "")
}

func (e *Engine) escalate(ev event.Event, now time.Time, denied bool) Decision {
	count := denied
	if !count && len(e.denials) > 0 {
		// Credential or alternate tool attempts following a denial are explicit
		// observable signals. Network/git retries must share a prior category.
		if ev.Type == "credential" || ev.Type == "tool" {
			count = true
		} else if ev.Type == "network" || ev.Type == "git" {
			for _, prior := range e.denials {
				if prior.typeID == ev.Type {
					count = true
					break
				}
			}
		}
	}
	if !count {
		return decide("allow", "", "")
	}
	e.denials = appendBounded(e.denials, observation{at: now, typeID: ev.Type, target: ev.Target}, e.cfg.Escalation.KillAfter)
	n := len(e.denials)
	reason := fmt.Sprintf("%d denied or related follow-up actions within %s", n, e.cfg.Escalation.Window)
	switch {
	case n >= e.cfg.Escalation.KillAfter:
		return decide("kill", "failure-escalation", reason)
	case n >= e.cfg.Escalation.PauseAfter:
		return decide("pause", "failure-escalation", reason)
	case n >= e.cfg.Escalation.WarnAfter:
		return decide("warn", "failure-escalation", reason)
	default:
		return decide("allow", "denial-observed", "first denial recorded; no process intervention")
	}
}

func recent(items []observation, cutoff time.Time) []observation {
	i := 0
	for i < len(items) && !items[i].at.After(cutoff) {
		i++
	}
	if i == len(items) {
		return items[:0]
	}
	if i > 0 {
		copy(items, items[i:])
		items = items[:len(items)-i]
	}
	return items
}

func appendBounded(items []observation, item observation, limit int) []observation {
	if limit < 1 {
		limit = 1
	}
	if len(items) >= limit {
		copy(items, items[1:])
		items[len(items)-1] = item
		return items
	}
	return append(items, item)
}

func rank(action string) int {
	switch action {
	case "warn":
		return 1
	case "pause":
		return 2
	case "kill":
		return 3
	default:
		return 0
	}
}

func networkHost(target string) string {
	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		target = u.Hostname()
	} else if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}
	return strings.ToLower(strings.TrimSuffix(target, "."))
}
