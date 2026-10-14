package authority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/event"
	"github.com/odbgrowth/saga-watchdog/internal/policy"
)

// Bounds keep the state file small enough to reread on every change. With
// targets bounded by storedTarget and identifiers bounded by the control
// socket, a full state stays below maxStateBytes (see the worst-case test);
// the writer still refuses to install anything larger, so the reader never
// rejects Watchdog's own output. Every trajectory step is also in the audit
// log, so the rolling window of related steps loses no evidence.
const (
	maxRestrictions = 256
	maxRelated      = 8
	maxTargetBytes  = 256
	maxStateBytes   = 8 << 20
	maxLogBytes     = 1 << 20
)

// ErrFull reports that a context holds the maximum number of unresolved
// restrictions. Nothing is evicted to make room: an unresolved restriction
// ends only by expiry, a trusted grant or an operator clearing it.
var ErrFull = errors.New("authority state is full; review it with: saga-watchdog authority status")

// storedTarget bounds a target for storage. A short printable-ASCII target is
// kept as is. Any other keeps a readable prefix and a digest of the whole, so
// equal targets still match exactly and the stored form is at most
// maxTargetBytes of printable ASCII.
func storedTarget(t string) string {
	printable := !strings.ContainsFunc(t, func(c rune) bool { return c < 0x20 || c > 0x7e })
	if len(t) <= maxTargetBytes && printable {
		return t
	}
	sum := sha256.Sum256([]byte(t))
	suffix := "...sha256:" + hex.EncodeToString(sum[:16])
	prefix := []byte(t[:min(len(t), maxTargetBytes-len(suffix))])
	for i, c := range prefix {
		if c < 0x20 || c > 0x7e {
			prefix[i] = '?'
		}
	}
	return string(prefix) + suffix
}

// Restriction is an unresolved denial that outlives its run. It holds
// metadata only: rule, target, identifiers and times.
type Restriction struct {
	ID         string    `json:"id"`
	Rule       string    `json:"rule"`
	Decision   string    `json:"decision"`
	Type       string    `json:"type"`
	Target     string    `json:"target"`
	Effects    []string  `json:"effects,omitempty"`
	RunID      string    `json:"run_id"`
	EventID    string    `json:"event_id"`
	InstanceID string    `json:"instance_id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	HostID     string    `json:"host_id,omitempty"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
	Attempts   int       `json:"attempts"`
	Related    []Link    `json:"related,omitempty"`
}

// Link is one later step in a restriction's trajectory.
type Link struct {
	At          time.Time `json:"at"`
	RunID       string    `json:"run_id"`
	EventID     string    `json:"event_id"`
	InstanceID  string    `json:"instance_id,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	HostID      string    `json:"host_id,omitempty"`
	Type        string    `json:"type"`
	Target      string    `json:"target"`
	Correlation string    `json:"correlation"`
}

// State is the persistent security state of one context.
type State struct {
	Version      int           `json:"version"`
	Context      Context       `json:"context"`
	Restrictions []Restriction `json:"restrictions"`
	Updated      time.Time     `json:"updated"`
	// PendingAudit holds audit records committed with the state transition
	// they describe but not yet in the audit log. The next update writes
	// them, so the log can repeat a record but never lose one.
	PendingAudit []event.Event `json:"pending_audit,omitempty"`
}

// Attempt describes an event that may continue an earlier trajectory.
type Attempt struct {
	Type, Action, Target                  string
	Effects                               []string
	EventID, RunID, InstanceID, SessionID string
	HostID                                string
}

// Match ties an attempt to the restriction it continues.
type Match struct {
	Restriction Restriction
	Correlation string
}

// Correlate finds the unexpired restriction an attempt continues, if any. Only
// observable policy facts count: the same target in another run, a target in
// the same declared effect, or a new agent instance, runtime, endpoint or host
// while any restriction is unresolved. Intent is never inferred. Stopping an
// instance or discovering one the run did not create continues nothing.
func (s State) Correlate(a Attempt, now time.Time) (Match, bool) {
	if policy.ReplicationType(a.Type) && !policy.Expansion(a.Type, a.Action) {
		return Match{}, false
	}
	target := storedTarget(a.Target)
	var best Match
	priority := 0
	for _, r := range s.Restrictions {
		if !r.Expires.After(now) || r.EventID == a.EventID {
			continue
		}
		p, kind := 0, ""
		switch {
		case r.Type == a.Type && r.Target == target && r.RunID == a.RunID:
			// Retries inside the run that earned the restriction are the base
			// rule's and the in-run window's concern, by any correlation.
		case r.Type == a.Type && r.Target == target:
			p, kind = 3, "retry in a new run"
		case shared(r.Effects, a.Effects) != "":
			p, kind = 2, "alternate route to effect "+shared(r.Effects, a.Effects)
		case policy.Expansion(a.Type, a.Action):
			p, kind = 1, "new "+a.Type+" after denial"
		}
		if p > priority || (p == priority && p > 0 && r.Created.After(best.Restriction.Created)) {
			best, priority = Match{Restriction: r, Correlation: kind}, p
		}
	}
	return best, priority > 0
}

func shared(a, b []string) string {
	for _, x := range a {
		if slices.Contains(b, x) {
			return x
		}
	}
	return ""
}

// Store keeps one context's state in the project's private state directory,
// next to its runs. Writes are atomic and serialized with a file lock so a
// parent run and a nested child run can share it.
type Store struct {
	ctx                Context
	path, log, lock    string
	retention, serious time.Duration
	cached             State
	stamp              time.Time
	size               int64
}

// Open loads or creates the state of ctx under dir (the project state
// directory) and expires stale restrictions. A corrupt file is reported as
// ErrCorrupt and never replaced silently.
func Open(dir string, ctx Context, retention, serious time.Duration) (*Store, error) {
	if !ctx.Complete() {
		return nil, errors.New("security context is incomplete")
	}
	// Every restriction must expire after it was created.
	if retention <= 0 || serious < retention {
		return nil, errors.New("retention must be positive and at most serious retention")
	}
	dir = filepath.Join(dir, "contexts")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("context state directory must be a real directory")
	}
	id := ctx.ID()
	s := &Store{ctx: ctx, path: filepath.Join(dir, id+".json"), log: filepath.Join(dir, id+".events.jsonl"), lock: filepath.Join(dir, id+".lock"), retention: retention, serious: serious}
	if _, err := s.update(time.Now().UTC(), func(*State, *[]auditNote) error { return nil }); err != nil {
		return nil, err
	}
	return s, nil
}

// Context returns the context this store belongs to.
func (s *Store) Context() Context { return s.ctx }

func (s *Store) read() (State, error) {
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return State{Version: 1, Context: s.ctx}, nil
	}
	if err != nil {
		return State{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return State{}, err
	}
	// Decode into a zero value and require every field Watchdog writes: a
	// file that parses but lacks them, such as {}, is corrupt, never an
	// empty state.
	var fields map[string]json.RawMessage
	var st State
	if len(data) > maxStateBytes || json.Unmarshal(data, &fields) != nil || json.Unmarshal(data, &st) != nil || !s.valid(fields, st) {
		return State{}, fmt.Errorf("%w: %s", ErrCorrupt, s.path)
	}
	return st, nil
}

// valid reports whether a decoded state carries every field the writer
// emits. An empty restriction list is written as null, so only its key is
// required.
func (s *Store) valid(fields map[string]json.RawMessage, st State) bool {
	for _, key := range []string{"version", "context", "restrictions", "updated"} {
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	if st.Version != 1 || st.Context.ID() != s.ctx.ID() || st.Updated.IsZero() || len(st.Restrictions) > maxRestrictions {
		return false
	}
	for _, r := range st.Restrictions {
		// The writer always expires a restriction after it was created.
		if r.ID == "" || !restrictable(r) || r.Created.IsZero() || !r.Expires.After(r.Created) || r.Attempts < 1 || len(r.Related) > maxRelated {
			return false
		}
		for _, l := range r.Related {
			if !linkable(l) {
				return false
			}
		}
	}
	return true
}

// restrictable reports whether r carries what every restriction records:
// the rule and its pause or kill decision, the type and target it denied,
// and the run and event that earned it. Add refuses anything less, so the
// reader never rejects Watchdog's own output.
func restrictable(r Restriction) bool {
	return r.Rule != "" && (r.Decision == "pause" || r.Decision == "kill") && r.Type != "" && r.Target != "" && r.RunID != "" && r.EventID != ""
}

// linkable reports whether l carries what every trajectory step records.
// Attempt refuses anything less.
func linkable(l Link) bool {
	return !l.At.IsZero() && l.RunID != "" && l.EventID != "" && l.Type != "" && l.Target != "" && l.Correlation != ""
}

func (s *Store) write(st State) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(st); err != nil {
		return err
	}
	data := buf.Bytes()
	if len(data) > maxStateBytes {
		return ErrFull
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".state-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return rename(f.Name(), s.path)
}

// rename installs a written state file; tests replace it to simulate a
// failed commit.
var rename = os.Rename

// Current returns the state, rereading the file only when it changed. Expired
// restrictions are ignored by Correlate even before they are pruned.
func (s *Store) Current() (State, error) {
	info, err := os.Stat(s.path)
	if err == nil && info.ModTime().Equal(s.stamp) && info.Size() == s.size {
		return s.cached, nil
	}
	unlock, err := lockPath(s.lock)
	if err != nil {
		return s.cached, err
	}
	defer unlock()
	st, err := s.read()
	if err != nil {
		return s.cached, err
	}
	s.remember(st)
	return st, nil
}

func (s *Store) remember(st State) {
	s.cached = st
	if info, err := os.Stat(s.path); err == nil {
		s.stamp, s.size = info.ModTime(), info.Size()
	}
}

// auditNote is one audit record of an update, written once the state it
// describes is committed.
type auditNote struct {
	action      string
	restriction Restriction
	who, reason string
}

// update applies fn under the lock, expires stale restrictions and writes the
// result atomically. The expiries and the notes fn records reach the audit log
// only after the state commits, so history never claims a transition that did
// not happen. It returns the restrictions it expired.
func (s *Store) update(now time.Time, fn func(*State, *[]auditNote) error) ([]Restriction, error) {
	unlock, err := lockPath(s.lock)
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := s.read()
	if err != nil {
		return nil, err
	}
	var expired []Restriction
	kept := st.Restrictions[:0]
	for _, r := range st.Restrictions {
		if r.Expires.After(now) {
			kept = append(kept, r)
		} else {
			expired = append(expired, r)
		}
	}
	st.Restrictions = kept
	var notes []auditNote
	for _, r := range expired {
		notes = append(notes, auditNote{"expired", r, "", "retention elapsed"})
	}
	if err := fn(&st, &notes); err != nil {
		return nil, err
	}
	for _, n := range notes {
		st.PendingAudit = append(st.PendingAudit, s.record(now, n.action, n.restriction, n.who, n.reason))
	}
	st.Updated = now
	// The transition and its audit records commit together.
	if err := s.write(st); err != nil {
		return nil, err
	}
	s.remember(st)
	if len(st.PendingAudit) == 0 {
		return expired, nil
	}
	if err := s.appendLog(st.PendingAudit...); err != nil {
		return expired, err
	}
	st.PendingAudit = nil
	if err := s.write(st); err != nil {
		return expired, err
	}
	s.remember(st)
	return expired, nil
}

// Add records a denial as a restriction unless an unexpired one with the same
// rule and target already exists; a kill upgrades an existing pause.
// Serious (kill) restrictions are kept longer.
// A full state refuses the new restriction with ErrFull, audited, and keeps
// every unresolved one; the caller fails closed.
func (s *Store) Add(now time.Time, r Restriction) error {
	if !restrictable(r) {
		return errors.New("restriction needs a rule, a pause or kill decision, a type, a target, a run ID and an event ID")
	}
	r.Target = storedTarget(r.Target)
	r.Created = now
	r.Attempts = 1
	_, err := s.update(now, func(st *State, notes *[]auditNote) error {
		for i := range st.Restrictions {
			existing := &st.Restrictions[i]
			if existing.Rule != r.Rule || existing.Type != r.Type || existing.Target != r.Target {
				continue
			}
			// The same denial enforced more strongly later upgrades the
			// restriction: its decision and its serious retention.
			if r.Decision == "kill" && existing.Decision != "kill" {
				existing.Decision = "kill"
				if expires := now.Add(s.serious); expires.After(existing.Expires) {
					existing.Expires = expires
				}
				*notes = append(*notes, auditNote{"escalated", *existing, "", r.Rule + " enforced as kill for " + r.Type + " " + r.Target})
			}
			return nil
		}
		if len(st.Restrictions) >= maxRestrictions {
			return ErrFull
		}
		r.ID = event.NewID("rst")
		r.Expires = now.Add(s.retention)
		if r.Decision == "kill" {
			r.Expires = now.Add(s.serious)
		}
		st.Restrictions = append(st.Restrictions, r)
		*notes = append(*notes, auditNote{"restricted", r, "", r.Rule + " denied " + r.Type + " " + r.Target})
		return nil
	})
	if errors.Is(err, ErrFull) {
		// Nothing changed; the refusal itself is the event.
		r.ID = ""
		err = errors.Join(err, s.audit(now, "refused", r, "", "state full: "+r.Rule+" denied "+r.Type+" "+r.Target))
	}
	return err
}

// Attempt appends a correlated step to a restriction's trajectory and
// returns the attempt count after it. The count is taken under the state
// lock, so concurrent runs in one context each get their own number and none
// skips a threshold. 0 means the restriction ended meanwhile.
func (s *Store) Attempt(now time.Time, id string, l Link) (int, error) {
	attempts := 0
	_, err := s.update(now, func(st *State, notes *[]auditNote) error {
		for i := range st.Restrictions {
			r := &st.Restrictions[i]
			if r.ID != id {
				continue
			}
			if !linkable(l) {
				return errors.New("trajectory step needs a time, a run ID, an event ID, a type, a target and a correlation")
			}
			r.Attempts++
			attempts = r.Attempts
			l.Target = storedTarget(l.Target)
			r.Related = append(r.Related, l)
			if len(r.Related) > maxRelated {
				r.Related = r.Related[len(r.Related)-maxRelated:]
			}
			*notes = append(*notes, auditNote{"correlated", *r, "", l.Correlation + ": " + l.Type + " " + l.Target + " in run " + l.RunID})
			return nil
		}
		return nil
	})
	return attempts, err
}

// Escalate upgrades a restriction to kill, with serious retention, after a
// kill took effect on its trajectory. The upgrade is audited as escalated.
func (s *Store) Escalate(now time.Time, id, runID string) error {
	_, err := s.update(now, func(st *State, notes *[]auditNote) error {
		for i := range st.Restrictions {
			r := &st.Restrictions[i]
			if r.ID != id || r.Decision == "kill" {
				continue
			}
			r.Decision = "kill"
			if expires := now.Add(s.serious); expires.After(r.Expires) {
				r.Expires = expires
			}
			*notes = append(*notes, auditNote{"escalated", *r, "", "trajectory enforced as kill in run " + runID})
		}
		return nil
	})
	return err
}

// Clear removes restrictions on an operator's request: one by ID, or all when
// id is empty. who and reason are recorded for every removed restriction.
func (s *Store) Clear(now time.Time, id, who, reason string) ([]Restriction, error) {
	var cleared []Restriction
	_, err := s.update(now, func(st *State, notes *[]auditNote) error {
		kept := st.Restrictions[:0]
		for _, r := range st.Restrictions {
			if id == "" || r.ID == id {
				cleared = append(cleared, r)
				*notes = append(*notes, auditNote{"cleared", r, who, reason})
				continue
			}
			kept = append(kept, r)
		}
		st.Restrictions = kept
		return nil
	})
	return cleared, err
}

// Resolve removes restrictions on one exact target after a trusted operator
// grant for it. Effects and other targets stay restricted.
func (s *Store) Resolve(now time.Time, typeID, target, who, reason string) ([]Restriction, error) {
	var resolved []Restriction
	_, err := s.update(now, func(st *State, notes *[]auditNote) error {
		kept := st.Restrictions[:0]
		for _, r := range st.Restrictions {
			if r.Type == typeID && r.Target == storedTarget(target) {
				resolved = append(resolved, r)
				*notes = append(*notes, auditNote{"resolved", r, who, reason})
				continue
			}
			kept = append(kept, r)
		}
		st.Restrictions = kept
		return nil
	})
	return resolved, err
}

// Peek reads a context's state without creating or changing anything. A
// missing file is an empty state.
func Peek(dir string, ctx Context) (State, error) {
	s := &Store{ctx: ctx, path: filepath.Join(dir, "contexts", ctx.ID()+".json")}
	return s.read()
}

// QuarantineCorrupt moves an unreadable state file aside on an operator's
// explicit request, so a fresh state can start. The move is audited.
func QuarantineCorrupt(dir string, ctx Context, who, reason string) (string, error) {
	s := &Store{ctx: ctx, path: filepath.Join(dir, "contexts", ctx.ID()+".json"), log: filepath.Join(dir, "contexts", ctx.ID()+".events.jsonl"), lock: filepath.Join(dir, "contexts", ctx.ID()+".lock")}
	unlock, err := lockPath(s.lock)
	if err != nil {
		return "", err
	}
	defer unlock()
	now := time.Now().UTC()
	moved := s.path + ".corrupt-" + now.Format("20060102T150405Z")
	// Keep a copy aside first, then replace the corrupt state with a fresh
	// one that carries the audit record of this clear, in one atomic write:
	// the clear and its record commit together, as in update.
	if err := copyFile(s.path, moved); err != nil {
		return "", err
	}
	record := s.record(now, "cleared", Restriction{ID: "all", Type: "state", Target: filepath.Base(moved)}, who, "corrupt state moved aside: "+reason)
	st := State{Version: 1, Context: ctx, Updated: now, PendingAudit: []event.Event{record}}
	if err := s.write(st); err != nil {
		return "", err
	}
	if err := s.appendLog(record); err != nil {
		return moved, err
	}
	st.PendingAudit = nil
	return moved, s.write(st)
}

// copyFile copies src to a new private file dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err == nil {
		err = out.Sync()
	}
	return errors.Join(err, out.Close())
}

// audit appends one context-level event outside a state update.
func (s *Store) audit(now time.Time, action string, r Restriction, who, reason string) error {
	return s.appendLog(s.record(now, action, r, who, reason))
}

// appendLog appends audit records to the context log, which rotates once at
// 1 MiB.
func (s *Store) appendLog(records ...event.Event) error {
	if info, err := os.Stat(s.log); err == nil && info.Size() > maxLogBytes {
		if err := os.Rename(s.log, s.log+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(s.log, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, e := range records {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err = f.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return f.Sync()
}

// record builds one sanitized context-level audit event: restricted,
// escalated, correlated, expired, resolved, cleared or refused.
func (s *Store) record(now time.Time, action string, r Restriction, who, reason string) event.Event {
	e := event.Event{ID: event.NewID("evt"), Timestamp: now, ProjectID: s.ctx.Project, RunID: r.RunID, Source: "authority", Type: "authority_state", Action: action, Target: r.ID, Result: "recorded", Severity: "info", RuleID: r.Rule,
		Metadata: map[string]any{"reason": reason, "context_id": s.ctx.ID(), "operator_id": s.ctx.OperatorID, "authorization_context_id": s.ctx.AuthorizationContextID, "original_event_id": r.EventID, "attempts": r.Attempts}}
	if who != "" {
		e.Metadata["who"] = who
	}
	return e.Sanitized()
}

// History copies the context audit log, oldest rotation first, followed by
// committed records the log has not received yet.
func History(dir string, ctx Context, w io.Writer) error {
	base := filepath.Join(dir, "contexts", ctx.ID()+".events.jsonl")
	for _, name := range []string{base + ".1", base} {
		f, err := os.Open(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		_, err = io.Copy(w, f)
		f.Close()
		if err != nil {
			return err
		}
	}
	// A state that cannot be read has no records to add; the log above is
	// still the operator's evidence for deciding what to do with it.
	st, err := Peek(dir, ctx)
	if err != nil {
		return nil
	}
	for _, e := range st.PendingAudit {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err = w.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return nil
}
