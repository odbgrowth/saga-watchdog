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
	p.add("start", now, "trusted-integration", first, false)
	p.add("start", now.Add(time.Second), "trusted-integration", second, false)
	if _, ok := p.take("start", now.Add(2*time.Second), "self-reported"); ok {
		t.Fatal("a self-reported report took a trusted check")
	}
	if c, ok := p.take("start", now.Add(2*time.Second), "trusted-integration"); !ok || c.instance != first {
		t.Fatalf("first report: %v %+v", ok, c)
	}
	if c, ok := p.take("start", now.Add(3*time.Second), "trusted-integration"); !ok || c.instance != second {
		t.Fatalf("second report: %v %+v", ok, c)
	}
	if _, ok := p.take("start", now.Add(4*time.Second), "trusted-integration"); ok {
		t.Fatal("a third report paired with no check")
	}
	// A check whose report never came does not pair after the window.
	p.add("start", now, "trusted-integration", first, false)
	if _, ok := p.take("start", now.Add(2*time.Minute), "trusted-integration"); ok || p.count != 0 {
		t.Fatalf("abandoned check paired or kept: %d", p.count)
	}
	// Full: expired checks make room; unexpired ones are never evicted.
	for _, key := range []string{"a", "b", "c"} {
		p.add(key, now, "self-reported", nil, false)
	}
	p.add("d", now.Add(time.Second), "self-reported", nil, false)
	if _, ok := p.take("d", now.Add(time.Second), "self-reported"); ok {
		t.Fatal("bound exceeded")
	}
	p.add("d", now.Add(2*time.Minute), "self-reported", nil, false)
	if _, ok := p.take("d", now.Add(2*time.Minute), "self-reported"); !ok || p.count != 0 {
		t.Fatalf("expired checks not pruned when full: %d", p.count)
	}
	// A check holding a worker reservation is kept even when the queue is
	// full of unexpired checks, so its report confirms the reservation.
	for _, key := range []string{"a", "b", "c"} {
		p.add(key, now, "self-reported", nil, false)
	}
	p.add("worker", now, "trusted-integration", first, true)
	if c, ok := p.take("worker", now.Add(time.Second), "trusted-integration"); !ok || c.instance != first {
		t.Fatalf("a reserved worker check was dropped when full: %v %+v", ok, c)
	}
}
