package authority

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/event"
)

var epoch = time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)

func testContext() Context {
	return Context{OperatorID: "human:onno", ProjectID: "abc123", Project: "demo", AuthorizationContextID: "dev-local"}
}

func TestResolveNeverGuessesIdentity(t *testing.T) {
	for name, tc := range map[string]struct {
		operator, authz, project string
		ok                       bool
	}{
		"complete":        {"human:onno", "dev-local", "p1", true},
		"no operator":     {"", "dev-local", "p1", false},
		"bad operator":    {"onno", "dev-local", "p1", false},
		"no authz":        {"human:onno", "", "p1", false},
		"no project":      {"human:onno", "dev-local", "", false},
		"injected spaces": {"human:onno smith", "dev-local", "p1", false},
	} {
		t.Run(name, func(t *testing.T) {
			c, why := Resolve(tc.operator, tc.authz, tc.project, "demo")
			if (why == "") != tc.ok || c.Complete() != tc.ok && tc.ok {
				t.Fatalf("%+v %q", c, why)
			}
		})
	}
	// The context ID depends on operator, project and authorization context
	// only; there is no session, model or process component to vary.
	a := testContext()
	b := a
	b.Project = "renamed display name"
	if a.ID() != b.ID() {
		t.Fatal("display name changed the security identity")
	}
	for _, mutate := range []func(*Context){
		func(c *Context) { c.OperatorID = "human:other" },
		func(c *Context) { c.ProjectID = "other" },
		func(c *Context) { c.AuthorizationContextID = "production-readonly" },
	} {
		c := a
		mutate(&c)
		if c.ID() == a.ID() {
			t.Fatalf("distinct context shares an ID: %+v", c)
		}
	}
}

// Tests 1, 2, 3, 8 and 9 at the store level: correlation, deterministic
// expiry, operator clearing and the audit trail.
func TestRestrictionsPersistCorrelateExpireAndClear(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, testContext(), time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(epoch, Restriction{Rule: "network-denied", Decision: "pause", Type: "network", Target: "deploy.example.com", Effects: []string{"production.deploy"}, RunID: "run_a", EventID: "evt_1", SessionID: "sess-1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(epoch, Restriction{Rule: "network-denied", Decision: "pause", Type: "network", Target: "deploy.example.com", RunID: "run_a", EventID: "evt_2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(epoch, Restriction{Rule: "hook-tamper", Decision: "kill", Type: "file", Target: ".claude/settings.json", RunID: "run_a", EventID: "evt_3"}); err != nil {
		t.Fatal(err)
	}
	// A second store (another run, another process) sees the same state.
	other, err := Open(dir, testContext(), time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st, err := other.Current()
	if err != nil || len(st.Restrictions) != 2 {
		t.Fatalf("duplicate not suppressed or state not shared: %v %+v", err, st.Restrictions)
	}
	pause, kill := st.Restrictions[0], st.Restrictions[1]
	if !pause.Expires.Equal(epoch.Add(time.Hour)) || !kill.Expires.Equal(epoch.Add(24*time.Hour)) {
		t.Fatalf("retention: %v %v", pause.Expires, kill.Expires)
	}
	now := epoch.Add(time.Minute)
	for name, tc := range map[string]struct {
		a    Attempt
		kind string
	}{
		"retry in a new run, new session": {Attempt{Type: "network", Target: "deploy.example.com", RunID: "run_b", SessionID: "sess-2"}, "retry in a new run"},
		"alternate route to the effect":   {Attempt{Type: "tool", Target: "vercel/deploy", Effects: []string{"production.deploy"}, RunID: "run_b"}, "alternate route to effect production.deploy"},
		"new agent instance":              {Attempt{Type: "agent", Action: "instance.start", Target: "codex", RunID: "run_b"}, "new agent after denial"},
		"new host":                        {Attempt{Type: "remote", Action: "execution.attempt", Target: "deploy-agent", RunID: "run_b", HostID: "build-02"}, "new remote after denial"},
	} {
		t.Run(name, func(t *testing.T) {
			m, ok := st.Correlate(tc.a, now)
			if !ok || m.Correlation != tc.kind {
				t.Fatalf("%v %+v", ok, m)
			}
		})
	}
	for name, a := range map[string]Attempt{
		"unrelated download":        {Type: "network", Target: "pypi.org", RunID: "run_b"},
		"same run retry":            {Type: "network", Target: "deploy.example.com", RunID: "run_a"},
		"the denial event itself":   {Type: "network", Target: "deploy.example.com", RunID: "run_b", EventID: "evt_1"},
		"unrelated tool, no effect": {Type: "tool", Target: "github/get_issue", RunID: "run_b"},
		"worker stop":               {Type: "agent", Action: "instance.stop", Target: "codex", RunID: "run_b"},
		"discovered endpoint":       {Type: "inference", Action: "endpoint.discovered", Target: "0.0.0.0:8000", RunID: "run_b"},
	} {
		if m, ok := st.Correlate(a, now); ok && !(name == "the denial event itself" && m.Restriction.EventID != "evt_1") {
			t.Errorf("%s correlated: %+v", name, m)
		}
	}
	if err := other.Attempt(now, pause.ID, Link{At: now, RunID: "run_b", EventID: "evt_9", SessionID: "sess-2", Type: "tool", Target: "vercel/deploy", Correlation: "alternate route"}); err != nil {
		t.Fatal(err)
	}
	st, _ = s.Current()
	if st.Restrictions[0].Attempts != 2 || len(st.Restrictions[0].Related) != 1 || st.Restrictions[0].Related[0].SessionID != "sess-2" {
		t.Fatalf("trajectory not recorded: %+v", st.Restrictions[0])
	}
	// Expiry is deterministic: Correlate ignores it at once, Update prunes it
	// and audits the expiry.
	later := epoch.Add(2 * time.Hour)
	if _, ok := st.Correlate(Attempt{Type: "network", Target: "deploy.example.com", RunID: "run_c"}, later); ok {
		t.Fatal("expired restriction correlated")
	}
	expired, err := s.update(later, func(*State, *[]auditNote) error { return nil })
	if err != nil || len(expired) != 1 || expired[0].ID != pause.ID {
		t.Fatalf("expiry: %v %+v", err, expired)
	}
	cleared, err := s.Clear(later, "", "human:onno", "reviewed the hook change")
	if err != nil || len(cleared) != 1 || cleared[0].ID != kill.ID {
		t.Fatalf("clear: %v %+v", err, cleared)
	}
	var history strings.Builder
	if err := History(dir, testContext(), &history); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"action":"restricted"`, `"action":"correlated"`, `"action":"expired"`, `"action":"cleared"`, `"who":"human:onno"`, `"reason":"reviewed the hook change"`} {
		if !strings.Contains(history.String(), want) {
			t.Errorf("history lacks %s", want)
		}
	}
}

func TestResolveByGrantAndBounds(t *testing.T) {
	s, err := Open(t.TempDir(), testContext(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxRestrictions+10; i++ {
		target := "host" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + "-" + time.Duration(i).String()
		err := s.Add(epoch.Add(time.Duration(i)*time.Second), Restriction{Rule: "network-denied", Decision: "pause", Type: "network", Target: target, RunID: "run_a", EventID: "evt"})
		// A full state refuses new restrictions and evicts none: the oldest
		// unresolved denial must still correlate.
		if (i < maxRestrictions && err != nil) || (i >= maxRestrictions && !errors.Is(err, ErrFull)) {
			t.Fatalf("restriction %d: %v", i, err)
		}
	}
	if st, _ := s.Current(); st.Restrictions[0].Target != "hosta-0s" {
		t.Fatalf("oldest unresolved restriction evicted: %+v", st.Restrictions[0])
	}
	// A repeat of a recorded target is still deduplicated, not refused.
	if err := s.Add(epoch, Restriction{Rule: "network-denied", Decision: "pause", Type: "network", Target: "hosta-0s", RunID: "run_b", EventID: "evt"}); err != nil {
		t.Fatalf("dedupe on a full state: %v", err)
	}
	var history strings.Builder
	if err := History(filepath.Dir(filepath.Dir(s.path)), testContext(), &history); err != nil || !strings.Contains(history.String(), `"action":"refused"`) {
		t.Fatalf("refusal not audited: %v", err)
	}
	st, _ := s.Current()
	if len(st.Restrictions) != maxRestrictions {
		t.Fatalf("unbounded: %d", len(st.Restrictions))
	}
	keep := st.Restrictions[0]
	resolved, err := s.Resolve(epoch.Add(time.Minute), "network", keep.Target, "human:onno", "operator grant")
	if err != nil || len(resolved) != 1 {
		t.Fatalf("%v %+v", err, resolved)
	}
	if resolved, _ := s.Resolve(epoch.Add(time.Minute), "tool", keep.Target, "human:onno", "grant"); len(resolved) != 0 {
		t.Fatal("grant for another type resolved a restriction")
	}
}

func TestCorruptStateIsRefusedNotReplaced(t *testing.T) {
	dir := t.TempDir()
	ctx := testContext()
	if err := os.MkdirAll(filepath.Join(dir, "contexts"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "contexts", ctx.ID()+".json")
	for name, body := range map[string]string{"garbage": "{not json", "other context": `{"version":1,"context":{"operator_id":"human:mallory","project_id":"abc123","authorization_context_id":"dev-local"},"restrictions":[]}`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, ctx, time.Hour, time.Hour); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s: %v", name, err)
		}
		if data, _ := os.ReadFile(path); string(data) != body {
			t.Fatalf("%s: corrupt state was overwritten", name)
		}
	}
	moved, err := QuarantineCorrupt(dir, ctx, "human:onno", "restore after disk error")
	if err != nil || !strings.Contains(moved, ".corrupt-") {
		t.Fatalf("%v %s", err, moved)
	}
	if _, err := Open(dir, ctx, time.Hour, time.Hour); err != nil {
		t.Fatalf("fresh state after quarantine: %v", err)
	}
}

func TestConcurrentRunsShareStateSafely(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			s, err := Open(dir, testContext(), time.Hour, time.Hour)
			if err != nil {
				t.Error(err)
				return
			}
			for j := 0; j < 10; j++ {
				if err := s.Add(epoch, Restriction{Rule: "tool-denied", Decision: "pause", Type: "tool", Target: "srv/t" + string(rune('a'+i)) + string(rune('a'+j)), RunID: "run_x", EventID: "evt"}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	st, err := Peek(dir, testContext())
	if err != nil || len(st.Restrictions) != 80 {
		t.Fatalf("lost updates: %v %d", err, len(st.Restrictions))
	}
}

func TestHostClassification(t *testing.T) {
	h := LocalHost()
	for _, local := range []string{"", "localhost", "127.0.0.1", "::1", h.ID} {
		if id, remote := h.Classify(local); remote || id != h.ID {
			t.Errorf("%q classified remote", local)
		}
	}
	if id, remote := h.Classify("Build-02."); !remote || id != "build-02" {
		t.Fatalf("%s %t", id, remote)
	}
}

// Long or non-printable targets are stored bounded and still match exactly.
func TestStoredTargetsAreBoundedAndExact(t *testing.T) {
	long := "https://deploy.example.com/" + strings.Repeat("a", 4000)
	other := "https://deploy.example.com/" + strings.Repeat("a", 3999) + "b"
	for _, target := range []string{long, other, "file\nwith\x00control", "caf\u00e9/config"} {
		got := storedTarget(target)
		if len(got) > maxTargetBytes || strings.ContainsFunc(got, func(c rune) bool { return c < 0x20 || c > 0x7e }) {
			t.Fatalf("unbounded stored target %q", got)
		}
	}
	if storedTarget(long) == storedTarget(other) || storedTarget("api.example.com") != "api.example.com" {
		t.Fatal("stored targets do not preserve equality")
	}
	s, err := Open(t.TempDir(), testContext(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(epoch, Restriction{Rule: "network-denied", Decision: "pause", Type: "network", Target: long, RunID: "run_a", EventID: "evt_1"}); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Current()
	if _, ok := st.Correlate(Attempt{Type: "network", Target: long, RunID: "run_b"}, epoch); !ok {
		t.Fatal("long target retry not correlated")
	}
	if m, ok := st.Correlate(Attempt{Type: "network", Target: other, RunID: "run_b"}, epoch); ok {
		t.Fatalf("different long target correlated: %+v", m)
	}
	if resolved, err := s.Resolve(epoch, "network", long, "human:onno", "grant"); err != nil || len(resolved) != 1 {
		t.Fatalf("grant of a long target: %v %+v", err, resolved)
	}
}

// The largest state the bounds allow fits under the reader's limit, so the
// writer never installs a file the next run would refuse as corrupt.
func TestWorstCaseStateFitsTheReader(t *testing.T) {
	s, err := Open(t.TempDir(), testContext(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	quoted := func(n int) string { return strings.Repeat(`"`, n) } // escapes to two bytes each
	var effects []string
	for i := range 64 {
		effects = append(effects, fmt.Sprintf("%02d", i)+strings.Repeat("e", 62))
	}
	st := State{Version: 1, Context: testContext(), Updated: epoch}
	for range maxRestrictions {
		r := Restriction{ID: event.NewID("rst"), Rule: "cross-host-authority-expansion", Decision: "kill", Type: "inference", Target: storedTarget(quoted(4096)), Effects: effects,
			RunID: event.NewID("run"), EventID: event.NewID("evt"), InstanceID: NewInstanceID(), SessionID: quoted(128), HostID: quoted(253), Created: epoch, Expires: epoch, Attempts: 1 << 30}
		for range maxRelated {
			r.Related = append(r.Related, Link{At: epoch, RunID: event.NewID("run"), EventID: event.NewID("evt"), InstanceID: NewInstanceID(), SessionID: quoted(128), HostID: quoted(253), Type: "inference", Target: storedTarget(quoted(4096)), Correlation: "alternate route to effect " + effects[0]})
		}
		st.Restrictions = append(st.Restrictions, r)
	}
	if err := s.write(st); err != nil {
		t.Fatalf("worst-case state refused: %v", err)
	}
	if _, err := s.read(); err != nil {
		t.Fatalf("worst-case state unreadable: %v", err)
	}
	info, _ := os.Stat(s.path)
	t.Logf("worst-case state: %d bytes of %d", info.Size(), maxStateBytes)
}

// History never records a transition whose state write failed: a failed
// clear leaves the restriction active and unaudited.
func TestAuditFollowsCommittedState(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, testContext(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(epoch, Restriction{Rule: "network-denied", Decision: "pause", Type: "network", Target: "deploy.example.com", RunID: "run_a", EventID: "evt_1"}); err != nil {
		t.Fatal(err)
	}
	failed := errors.New("disk full")
	rename = func(string, string) error { return failed }
	t.Cleanup(func() { rename = os.Rename })
	if _, err := s.Clear(epoch, "", "human:onno", "reviewed"); !errors.Is(err, failed) {
		t.Fatalf("clear with a failed commit: %v", err)
	}
	if err := s.Add(epoch, Restriction{Rule: "tool-denied", Decision: "pause", Type: "tool", Target: "vercel/deploy", RunID: "run_a", EventID: "evt_2"}); !errors.Is(err, failed) {
		t.Fatalf("add with a failed commit: %v", err)
	}
	rename = os.Rename
	st, err := Peek(dir, testContext())
	if err != nil || len(st.Restrictions) != 1 {
		t.Fatalf("state changed without a commit: %v %+v", err, st.Restrictions)
	}
	var history strings.Builder
	if err := History(dir, testContext(), &history); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(history.String(), `"action":"cleared"`) || strings.Contains(history.String(), "vercel/deploy") {
		t.Fatalf("history claims an uncommitted transition: %s", history.String())
	}
}

// A denial persisted as a pause and later enforced as a kill becomes a kill
// restriction with serious retention, and the upgrade is audited.
func TestRepeatedDenialUpgradesToKill(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, testContext(), time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := Restriction{Rule: "unauthorized-agent-replication", Decision: "pause", Type: "agent", Target: "codex", RunID: "run_a", EventID: "evt_1"}
	if err := s.Add(epoch, r); err != nil {
		t.Fatal(err)
	}
	r.Decision, r.EventID = "kill", "evt_2"
	if err := s.Add(epoch.Add(time.Minute), r); err != nil {
		t.Fatal(err)
	}
	r.Decision, r.EventID = "pause", "evt_3"
	if err := s.Add(epoch.Add(2*time.Minute), r); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Current()
	if len(st.Restrictions) != 1 || st.Restrictions[0].Decision != "kill" || !st.Restrictions[0].Expires.Equal(epoch.Add(time.Minute+24*time.Hour)) {
		t.Fatalf("not upgraded, or downgraded again: %+v", st.Restrictions)
	}
	var history strings.Builder
	if err := History(dir, testContext(), &history); err != nil || strings.Count(history.String(), `"action":"escalated"`) != 1 {
		t.Fatalf("upgrade not audited once: %v %s", err, history.String())
	}
}

// A transition whose audit append fails keeps its record with the committed
// state, and the next update writes it: history never loses a transition.
func TestAuditRecordsSurviveALogFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, testContext(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(epoch, Restriction{Rule: "network-denied", Decision: "pause", Type: "network", Target: "deploy.example.com", RunID: "run_a", EventID: "evt_1"}); err != nil {
		t.Fatal(err)
	}
	// A directory in place of the log makes every append fail, even as root.
	if err := os.Remove(s.log); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.log, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Clear(epoch, "", "human:onno", "reviewed"); err == nil {
		t.Fatal("clear reported success without its audit record")
	}
	st, err := Peek(dir, testContext())
	if err != nil || len(st.Restrictions) != 0 || len(st.PendingAudit) != 1 || st.PendingAudit[0].Action != "cleared" {
		t.Fatalf("committed clear lost its record: %v %+v", err, st)
	}
	if err := os.Remove(s.log); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(epoch, Restriction{Rule: "tool-denied", Decision: "pause", Type: "tool", Target: "vercel/deploy", RunID: "run_b", EventID: "evt_2"}); err != nil {
		t.Fatal(err)
	}
	var history strings.Builder
	if err := History(dir, testContext(), &history); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(history.String(), `"action":"cleared"`) || !strings.Contains(history.String(), "vercel/deploy") {
		t.Fatalf("pending record not written by the next update: %s", history.String())
	}
	if st, _ := Peek(dir, testContext()); len(st.PendingAudit) != 0 {
		t.Fatalf("flushed records still pending: %+v", st.PendingAudit)
	}
}
