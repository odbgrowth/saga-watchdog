package authority

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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
		"new agent instance":              {Attempt{Type: "agent", Target: "codex", RunID: "run_b"}, "new agent after denial"},
		"new host":                        {Attempt{Type: "remote", Target: "deploy-agent", RunID: "run_b", HostID: "build-02"}, "new remote after denial"},
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
	expired, err := s.Update(later, func(*State) error { return nil })
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
		if err := s.Add(epoch.Add(time.Duration(i)*time.Second), Restriction{Rule: "network-denied", Decision: "pause", Type: "network", Target: target, RunID: "run_a", EventID: "evt"}); err != nil {
			t.Fatal(err)
		}
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
