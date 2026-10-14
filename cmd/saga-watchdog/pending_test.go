package main

import (
	"testing"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/authority"
)

// Concurrent checks of one action each pair with one report, in order; an
// abandoned check expires instead of pairing with a later action; the bound
// holds.
func TestPendingChecks(t *testing.T) {
	now := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	p := newPendingChecks(time.Minute, 3)
	first, second := &authority.Instance{ID: "a"}, &authority.Instance{ID: "b"}
	p.add("start", now, first)
	p.add("start", now.Add(time.Second), second)
	if c, ok := p.take("start", now.Add(2*time.Second)); !ok || c.instance != first {
		t.Fatalf("first report: %v %+v", ok, c)
	}
	if c, ok := p.take("start", now.Add(3*time.Second)); !ok || c.instance != second {
		t.Fatalf("second report: %v %+v", ok, c)
	}
	if _, ok := p.take("start", now.Add(4*time.Second)); ok {
		t.Fatal("a third report paired with no check")
	}
	// A check whose report never came does not pair after the window.
	p.add("start", now, first)
	if _, ok := p.take("start", now.Add(2*time.Minute)); ok || p.count != 0 {
		t.Fatalf("abandoned check paired or kept: %d", p.count)
	}
	// Full: expired checks make room; unexpired ones are never evicted.
	for _, key := range []string{"a", "b", "c"} {
		p.add(key, now, nil)
	}
	p.add("d", now.Add(time.Second), nil)
	if _, ok := p.take("d", now.Add(time.Second)); ok {
		t.Fatal("bound exceeded")
	}
	p.add("d", now.Add(2*time.Minute), nil)
	if _, ok := p.take("d", now.Add(2*time.Minute)); !ok || p.count != 0 {
		t.Fatalf("expired checks not pruned when full: %d", p.count)
	}
}
