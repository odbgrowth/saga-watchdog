// Package policy makes deterministic decisions over observable events. It does
// not enforce OS permissions or infer intent from model output.
package policy

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"sort"
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
	// Authorization names the trusted policy entry that authorized a new
	// agent instance or runtime, such as replication.allow_agents. It is
	// provenance, kept even when escalation raises the action.
	Authorization string `json:"authorization,omitempty"`
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
	controls  []string
	last      time.Time
	denials   []observation
	deletions []observation
	grants    map[string]struct{}
	// shellCounted records that the shell follow-up for the latest genuine
	// denial has been counted; only a new denial makes the shell count again.
	shellCounted bool
	// workers holds the same-host worker instances, by target, that this run
	// started and has not reported stopped. It never exceeds
	// replication.same_host_workers. A check and the report that follows it
	// name the same instance and count once.
	workers map[string]bool
}

// maxGrants bounds operator grants for one run. With targets bounded by the
// control socket, the persisted list stays far below the run record's reader
// limit.
const maxGrants = 64

// New builds an engine for one run. controls are project-relative files that
// configure an active preventive integration (for example the Claude Code hook
// settings). Changing one during the run is treated like policy tampering.
func New(cfg config.Config, root string, controls ...string) *Engine {
	cfg.Git.ProtectedBranches = append([]string(nil), cfg.Git.ProtectedBranches...)
	cfg.Filesystem.Protect = append([]string(nil), cfg.Filesystem.Protect...)
	cfg.Filesystem.Ignore = append([]string(nil), cfg.Filesystem.Ignore...)
	cfg.Network.Deny = append([]string(nil), cfg.Network.Deny...)
	cfg.Network.Allow = append([]string(nil), cfg.Network.Allow...)
	cfg.Tools.Deny = append([]string(nil), cfg.Tools.Deny...)
	cfg.Tools.Allow = append([]string(nil), cfg.Tools.Allow...)
	cfg.Replication.AllowAgents = append([]string(nil), cfg.Replication.AllowAgents...)
	cfg.Replication.InferenceEndpoints = append([]string(nil), cfg.Replication.InferenceEndpoints...)
	cfg.Replication.RemoteHosts = append([]string(nil), cfg.Replication.RemoteHosts...)
	effects := make(map[string][]string, len(cfg.Effects))
	for name, patterns := range cfg.Effects {
		effects[name] = append([]string(nil), patterns...)
	}
	cfg.Effects = effects
	return &Engine{cfg: cfg, root: root, controls: append([]string(nil), controls...), grants: map[string]struct{}{}, workers: map[string]bool{}}
}

// Grant authorizes one network host or tool identifier for the rest of the
// run in allowlist mode. It never overrides a deny entry. ok is false for an
// unsupported type or when the bound is reached; added is false for a grant
// that already existed, which is a successful no-op.
func (e *Engine) Grant(typeID, target string) (added, ok bool) {
	switch typeID {
	case "network":
		target = networkHost(target)
	case "tool":
	default:
		return false, false
	}
	if target == "" {
		return false, false
	}
	key := typeID + "\x00" + target
	if _, exists := e.grants[key]; exists {
		return false, true
	}
	if len(e.grants) >= maxGrants {
		return false, false
	}
	e.grants[key] = struct{}{}
	return true, true
}

func (e *Engine) granted(typeID, target string) bool {
	_, ok := e.grants[typeID+"\x00"+target]
	return ok
}

// hostListed reports whether host matches an entry: exactly, or, for an entry
// with a leading dot, as that domain or one of its subdomains.
func hostListed(entries []string, host string) bool {
	for _, entry := range entries {
		entry = strings.ToLower(strings.TrimSuffix(entry, "."))
		if suffix, ok := strings.CutPrefix(entry, "."); ok {
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				return true
			}
			continue
		}
		if host == entry {
			return true
		}
	}
	return false
}

// Decide builds a decision with the severity that belongs to its action.
func Decide(action, rule, reason string) Decision { return decide(action, rule, reason) }

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
		host := networkHost(ev.Target)
		authorized := hostListed(e.cfg.Network.Allow, host) || e.granted("network", host)
		if hostListed(e.cfg.Network.Deny, host) {
			base = decide("pause", "network-denied", "target hostname is denied by project policy")
		} else if !authorized && e.cfg.Network.DenyRedirectors && hostListed(Redirectors, host) {
			base = decide("pause", "network-redirector", "URL shortener or redirector host; allow or grant it explicitly, or set network.deny_redirectors: false")
		} else if !authorized && e.cfg.Network.Mode == "allowlist" {
			// Every host outside the allow list needs a human decision for this
			// run: authority expands only through an explicit grant.
			base = decide("pause", "network-unlisted", "host is not on the network allow list; authorize it for this run with: saga-watchdog grant network "+host)
		}
	} else if ev.Type == "tool" {
		// Canonical tool identifiers are path-like ("server/tool" for MCP), so
		// the same segment globs as paths apply: "github/*", "*/delete_*".
		denied := false
		for _, pattern := range e.cfg.Tools.Deny {
			if Match(pattern, ev.Target) {
				base = decide("pause", "tool-denied", "tool is denied by project policy")
				denied = true
				break
			}
		}
		if !denied && e.cfg.Tools.Mode == "allowlist" && !e.granted("tool", ev.Target) {
			listed := false
			for _, pattern := range e.cfg.Tools.Allow {
				if Match(pattern, ev.Target) {
					listed = true
					break
				}
			}
			if !listed {
				base = decide("pause", "tool-unlisted", "tool is not on the tools allow list; authorize it for this run with: saga-watchdog grant tool "+ev.Target)
			}
		}
	}
	if ReplicationType(ev.Type) {
		base = e.replication(ev)
		if base.RuleID == "unauthorized-agent-replication" && len(e.denials) > 0 {
			// Replication right after a denial is the route around it.
			base = decide("kill", base.RuleID, base.Reason+"; attempted after a denial in this run")
		}
	} else if ev.Type == "authority" {
		// No event can clear, reset or approve security state. An attempt from
		// inside a run is itself a security event.
		base = decide("pause", "authority-self-clear", "security history can only be cleared by an operator outside the run")
	}
	if base.Action == "kill" {
		return base
	}
	denied := ev.Result == "denied" || ev.Result == "blocked" || (ev.Type == "policy" && ev.Action == "denied")
	if base.Action == "pause" {
		denied = true
	}
	escalation := e.escalate(ev, now, denied)
	d := base
	if rank(escalation.Action) > rank(base.Action) || (base.RuleID == "" && escalation.RuleID != "") {
		escalation.Authorization = base.Authorization
		d = escalation
	}
	e.reserveWorker(ev, d)
	return d
}

// reserveWorker takes a worker slot for an authorized worker start that was
// neither denied nor reported as failed. Slots are keyed by instance, so a
// pre-action check and its post-action report occupy one slot.
func (e *Engine) reserveWorker(ev event.Event, d Decision) {
	if d.Authorization != "replication.same_host_workers" || rank(d.Action) >= rank("pause") {
		return
	}
	switch ev.Result {
	case "failed", "denied", "blocked":
		return
	}
	e.workers[ev.Target] = true
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
		for _, control := range e.controls {
			// Removing or renaming an ancestor (mv .claude .claude.bak) takes the
			// control with it and yields no event for the file itself.
			if name == control || (removed && strings.HasPrefix(control, name+"/")) {
				return decide("kill", "hook-tamper", control+" configures an active preventive integration and changed during the run")
			}
		}
		if len(e.controls) > 0 {
			// The sibling settings file can disable or loosen the hook. A change
			// there (including Claude's own "always allow" save) is reviewed by a
			// human rather than treated as proof of tampering.
			for _, settings := range agentSettings {
				if name == settings || (removed && strings.HasPrefix(settings, name+"/")) {
					return decide("pause", "agent-config-modification", settings+" changed while a preventive integration is active")
				}
			}
		}
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
	// A URL and its bare hostname are the same network target, not an
	// alternative route.
	target := ev.Target
	if ev.Type == "network" {
		target = networkHost(target)
	}
	count := denied
	if !count && len(e.denials) > 0 {
		// Credential or alternate tool attempts following a denial are explicit
		// observable signals. Network/git retries must share a prior category.
		// A follow-up only counts once per distinct target: repeating the same
		// allowed operation is ordinary work, not an alternative target.
		related, repeated := false, false
		for _, prior := range e.denials {
			if prior.typeID == ev.Type {
				related = true
				if prior.target == target {
					repeated = true
				}
			}
		}
		switch {
		case ev.Type == "credential" || ev.Type == "tool" || Expansion(ev.Type, ev.Action):
			// A new agent instance, runtime or host after a denial is an
			// alternative route as well.
			count = !repeated
		case ev.Type == "network" || ev.Type == "git":
			count = related && !repeated
		case ev.Type == "process" && e.cfg.Escalation.ShellFollowUp:
			// The shell is the route around a denied tool or host. It counts
			// once per genuine denial: ordinary follow-on commands are not
			// repeated evidence, and neither tool nor credential follow-ups
			// make the shell eligible again. Only the next denial does.
			count = !e.shellCounted
			e.shellCounted = true
		}
	}
	if !count {
		return decide("allow", "", "")
	}
	if denied {
		e.shellCounted = false
	}
	e.denials = appendBounded(e.denials, observation{at: now, typeID: ev.Type, target: target}, e.cfg.Escalation.KillAfter)
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

// ReplicationType reports the event types decided by replication policy.
func ReplicationType(typeID string) bool {
	return typeID == "agent" || typeID == "runtime" || typeID == "inference" || typeID == "remote"
}

// Expansion reports events that create or reach another agent instance,
// runtime, endpoint or host. Stopping an instance reduces authority and a
// discovery reports one the run did not create; neither is an expansion.
func Expansion(typeID, action string) bool {
	return ReplicationType(typeID) && !strings.HasSuffix(action, ".stop") && !strings.HasSuffix(action, ".discovered")
}

// persistable are the rules whose denials outlive a run when persistent
// authority correlation is enabled: each denies a concrete target or effect.
// Derived rules (failure-escalation, run-paused, authority-expansion-after-
// denial) and run lifecycle rules are not restrictions in their own right.
var persistable = map[string]bool{
	"network-denied": true, "network-unlisted": true, "network-redirector": true,
	"tool-denied": true, "tool-unlisted": true,
	"protected-path": true, "unsafe-path": true, "protected-branch": true,
	"git-security-modification": true, "ci-workflow-modification": true, "agent-config-modification": true,
	"hook-tamper": true, "policy-tamper": true,
	"unauthorized-agent-replication": true, "cross-host-authority-expansion": true, "authority-self-clear": true,
}

// Persistable reports whether a pause or kill decision becomes a restriction
// that survives the run.
func Persistable(d Decision) bool {
	return (d.Action == "pause" || d.Action == "kill") && persistable[d.RuleID]
}

// NetworkHost normalizes a host, host:port or URL target to its lowercase host.
func NetworkHost(target string) string { return networkHost(target) }

// Stronger returns the decision with the higher intervention; a tie keeps a.
func Stronger(a, b Decision) Decision {
	if rank(b.Action) > rank(a.Action) {
		return b
	}
	return a
}

// replication decides events that create, discover or stop agent instances,
// runtimes and inference endpoints, or execute on another host. Nothing is
// authorized unless trusted policy lists it: authority does not replicate.
// runtime_type, host_id and remote come from the supervisor's normalization
// of the reported event; they can only narrow what policy allows.
func (e *Engine) replication(ev event.Event) Decision {
	host, _ := ev.Metadata["host_id"].(string)
	remote, _ := ev.Metadata["remote"].(bool)
	runtimeType, _ := ev.Metadata["runtime_type"].(string)
	r := e.cfg.Replication
	hostAllowed := slices.Contains(r.RemoteHosts, host)
	listed := func(patterns []string) bool {
		for _, p := range patterns {
			if Match(p, ev.Target) {
				return true
			}
		}
		return false
	}
	switch ev.Type + "." + ev.Action {
	case "agent.instance.stop":
		// Only a stop naming a counted worker frees its slot.
		delete(e.workers, ev.Target)
		return decide("allow", "", "")
	case "agent.instance.discovered", "inference.endpoint.discovered":
		if listed(r.AllowAgents) || slices.Contains(r.InferenceEndpoints, ev.Target) {
			return decide("allow", "", "")
		}
		return decide("warn", "unattributed-agent-instance", "agent instance or endpoint discovered without known provenance; it holds no authority from this run")
	case "remote.execution.attempt":
		if !remote {
			return decide("allow", "", "")
		}
		if hostAllowed {
			return Decision{Action: "allow", Authorization: "replication.remote_hosts", Severity: "info", Reason: "remote host authorized by replication.remote_hosts"}
		}
		return decide("pause", "cross-host-authority-expansion", "execution on host "+host+" is not authorized by replication.remote_hosts")
	}
	// Everything else creates a runtime: agent.instance.start,
	// agent.replication.attempt, runtime.deploy|copy|start,
	// inference.endpoint.start.
	if remote {
		if hostAllowed {
			return Decision{Action: "allow", Authorization: "replication.remote_hosts", Severity: "info", Reason: "remote host authorized by replication.remote_hosts"}
		}
		return decide("kill", "cross-host-authority-expansion", "agent runtime created on host "+host+" without authorization; cross-host execution is a privileged effect")
	}
	if ev.Type == "inference" {
		if slices.Contains(r.InferenceEndpoints, ev.Target) {
			return Decision{Action: "allow", Authorization: "replication.inference_endpoints", Severity: "info", Reason: "endpoint authorized by replication.inference_endpoints"}
		}
		return decide("pause", "unauthorized-agent-replication", "inference endpoint "+ev.Target+" is not listed in replication.inference_endpoints")
	}
	if runtimeType == "worker" && (e.workers[ev.Target] || len(e.workers) < r.SameHostWorkers) {
		inUse := len(e.workers)
		if !e.workers[ev.Target] {
			inUse++
		}
		return Decision{Action: "allow", Authorization: "replication.same_host_workers", Severity: "info", Reason: fmt.Sprintf("worker %s authorized by replication.same_host_workers (%d of %d)", ev.Target, inUse, r.SameHostWorkers)}
	}
	if listed(r.AllowAgents) {
		return Decision{Action: "allow", Authorization: "replication.allow_agents", Severity: "info", Reason: "runtime authorized by replication.allow_agents"}
	}
	return decide("pause", "unauthorized-agent-replication", "starting another autonomous runtime ("+ev.Target+") is not authorized by replication policy")
}

// Effects returns the named effects an event reaches, sorted. Effects are
// declared by trusted policy; they group targets that achieve the same
// restricted outcome, such as several deployment APIs.
func (e *Engine) Effects(ev event.Event) []string {
	target := ev.Target
	switch ev.Type {
	case "network":
		target = networkHost(target)
	case "file":
		normalized, err := normalize(e.root, target, false)
		if err != nil {
			return nil
		}
		target = normalized
	}
	var names []string
	for name, patterns := range e.cfg.Effects {
		for _, entry := range patterns {
			typ, pattern, _ := strings.Cut(entry, ":")
			if typ != ev.Type {
				continue
			}
			if (typ == "network" && hostListed([]string{pattern}, target)) || (typ != "network" && Match(pattern, target)) {
				names = append(names, name)
				break
			}
		}
	}
	sort.Strings(names)
	return names
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

// Redirectors are well-known public URL shorteners and redirectors. A leading
// dot covers subdomains. The list is a tripwire for a reported technique, not
// a catalogue; projects can allow or grant any entry explicitly.
var Redirectors = []string{
	".bit.ly", ".bitly.com", ".tinyurl.com", ".t.co", ".goo.gl", ".is.gd", ".v.gd", ".ow.ly", ".buff.ly", ".rb.gy",
	".cutt.ly", ".tiny.cc", ".shorturl.at", ".rebrand.ly", ".bl.ink", ".s.id", ".t.ly", ".lnkd.in", ".tr.im", ".soo.gd",
	".u.to", ".x.co", ".shorte.st", ".adf.ly", ".bc.vc", ".clck.ru", ".surl.li", ".urlz.fr", ".dub.sh", ".short.io", ".snip.ly",
}

func networkHost(target string) string {
	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		target = u.Hostname()
	} else if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}
	return strings.ToLower(strings.TrimSuffix(target, "."))
}
