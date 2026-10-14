package authority

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/event"
	"github.com/odbgrowth/saga-watchdog/internal/policy"
)

const (
	maxRestrictions = 256
	maxRelated      = 16
	maxStateBytes   = 1 << 20
	maxLogBytes     = 1 << 20
)

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
}

// Attempt describes an event that may continue an earlier trajectory.
type Attempt struct {
	Type, Target                          string
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
// while any restriction is unresolved. Intent is never inferred.
func (s State) Correlate(a Attempt, now time.Time) (Match, bool) {
	var best Match
	priority := 0
	for _, r := range s.Restrictions {
		if !r.Expires.After(now) || r.EventID == a.EventID {
			continue
		}
		p, kind := 0, ""
		switch {
		case r.Type == a.Type && r.Target == a.Target && r.RunID != a.RunID:
			// Retries inside the run that earned the restriction are the base
			// rule's and the in-run window's concern.
			p, kind = 3, "retry in a new run"
		case shared(r.Effects, a.Effects) != "":
			p, kind = 2, "alternate route to effect "+shared(r.Effects, a.Effects)
		case policy.Expansion(a.Type):
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
	dir = filepath.Join(dir, "contexts")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("context state directory must be a real directory")
	}
	id := ctx.ID()
	s := &Store{ctx: ctx, path: filepath.Join(dir, id+".json"), log: filepath.Join(dir, id+".events.jsonl"), lock: filepath.Join(dir, id+".lock"), retention: retention, serious: serious}
	if _, err := s.Update(time.Now().UTC(), func(*State) error { return nil }); err != nil {
		return nil, err
	}
	return s, nil
}

// Context returns the context this store belongs to.
func (s *Store) Context() Context { return s.ctx }

func (s *Store) read() (State, error) {
	st := State{Version: 1, Context: s.ctx}
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return st, err
	}
	if len(data) > maxStateBytes || json.Unmarshal(data, &st) != nil || st.Version != 1 || st.Context.ID() != s.ctx.ID() {
		return st, fmt.Errorf("%w: %s", ErrCorrupt, s.path)
	}
	return st, nil
}

func (s *Store) write(st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
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
	return os.Rename(f.Name(), s.path)
}

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

// Update applies fn under the lock, expires stale restrictions (audited) and
// writes the result atomically. It returns the restrictions it expired.
func (s *Store) Update(now time.Time, fn func(*State) error) ([]Restriction, error) {
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
	for _, r := range expired {
		if err := s.audit(now, "expired", r, "", "retention elapsed"); err != nil {
			return nil, err
		}
	}
	if err := fn(&st); err != nil {
		return expired, err
	}
	st.Updated = now
	if err := s.write(st); err != nil {
		return expired, err
	}
	s.remember(st)
	return expired, nil
}

// Add records a denial as a restriction unless an unexpired one with the same
// rule and target already exists. Serious (kill) restrictions are kept longer.
func (s *Store) Add(now time.Time, r Restriction) error {
	_, err := s.Update(now, func(st *State) error {
		for _, existing := range st.Restrictions {
			if existing.Rule == r.Rule && existing.Type == r.Type && existing.Target == r.Target {
				return nil
			}
		}
		r.ID = event.NewID("rst")
		r.Created = now
		r.Attempts = 1
		r.Expires = now.Add(s.retention)
		if r.Decision == "kill" {
			r.Expires = now.Add(s.serious)
		}
		st.Restrictions = append(st.Restrictions, r)
		if len(st.Restrictions) > maxRestrictions {
			sort.Slice(st.Restrictions, func(i, j int) bool { return st.Restrictions[i].Created.Before(st.Restrictions[j].Created) })
			st.Restrictions = st.Restrictions[len(st.Restrictions)-maxRestrictions:]
		}
		return s.audit(now, "restricted", r, "", r.Rule+" denied "+r.Type+" "+r.Target)
	})
	return err
}

// Attempt appends a correlated step to a restriction's trajectory.
func (s *Store) Attempt(now time.Time, id string, l Link) error {
	_, err := s.Update(now, func(st *State) error {
		for i := range st.Restrictions {
			r := &st.Restrictions[i]
			if r.ID != id {
				continue
			}
			r.Attempts++
			r.Related = append(r.Related, l)
			if len(r.Related) > maxRelated {
				r.Related = r.Related[len(r.Related)-maxRelated:]
			}
			return s.audit(now, "correlated", *r, "", l.Correlation+": "+l.Type+" "+l.Target+" in run "+l.RunID)
		}
		return nil
	})
	return err
}

// Clear removes restrictions on an operator's request: one by ID, or all when
// id is empty. who and reason are recorded for every removed restriction.
func (s *Store) Clear(now time.Time, id, who, reason string) ([]Restriction, error) {
	var cleared []Restriction
	_, err := s.Update(now, func(st *State) error {
		kept := st.Restrictions[:0]
		for _, r := range st.Restrictions {
			if id == "" || r.ID == id {
				cleared = append(cleared, r)
				if err := s.audit(now, "cleared", r, who, reason); err != nil {
					return err
				}
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
	_, err := s.Update(now, func(st *State) error {
		kept := st.Restrictions[:0]
		for _, r := range st.Restrictions {
			if r.Type == typeID && r.Target == target {
				resolved = append(resolved, r)
				if err := s.audit(now, "resolved", r, who, reason); err != nil {
					return err
				}
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
	if err := os.Rename(s.path, moved); err != nil {
		return "", err
	}
	return moved, s.audit(now, "cleared", Restriction{ID: "all", Type: "state", Target: filepath.Base(moved)}, who, "corrupt state moved aside: "+reason)
}

// audit appends one context-level event: restricted, correlated, expired,
// resolved or cleared. The log rotates once at 1 MiB.
func (s *Store) audit(now time.Time, action string, r Restriction, who, reason string) error {
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
	e := event.Event{ID: event.NewID("evt"), Timestamp: now, ProjectID: s.ctx.Project, RunID: r.RunID, Source: "authority", Type: "authority_state", Action: action, Target: r.ID, Result: "recorded", Severity: "info", RuleID: r.Rule,
		Metadata: map[string]any{"reason": reason, "context_id": s.ctx.ID(), "operator_id": s.ctx.OperatorID, "authorization_context_id": s.ctx.AuthorizationContextID, "original_event_id": r.EventID, "attempts": r.Attempts}}
	if who != "" {
		e.Metadata["who"] = who
	}
	b, err := json.Marshal(e.Sanitized())
	if err != nil {
		return err
	}
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// History copies the context audit log, oldest rotation first.
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
	return nil
}
