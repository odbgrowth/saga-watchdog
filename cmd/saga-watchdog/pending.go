package main

import (
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/authority"
)

// pendingChecks holds allowed pre-action checks until the reports of their
// actions arrive: per action, oldest first, with the time of the check, its
// trust and the instance a start was given. A report takes the oldest
// unexpired check of its action with the same trust, so concurrent checks
// each pair with one report, and a self-reported report never takes over a
// trusted check's instance. Entries
// expire after the window, so an abandoned check never pairs with a later
// action. The total is bounded; a check beyond it pairs with nothing, and its
// report then counts as its own action: once more, never less. A check that
// holds a worker reservation is always kept and never expires, so its report,
// however late, confirms or releases that reservation; the worker ledger
// bounds those. Releasing the reservation on expiry instead would free budget
// for a worker that runs without reporting.
type pendingChecks struct {
	window time.Duration
	max    int
	queues map[string][]pendingCheck
	count  int
}

type pendingCheck struct {
	at       time.Time
	trust    string
	instance *authority.Instance
	reserved bool
}

func newPendingChecks(window time.Duration, max int) *pendingChecks {
	return &pendingChecks{window: window, max: max, queues: map[string][]pendingCheck{}}
}

func (p *pendingChecks) add(key string, now time.Time, trust string, instance *authority.Instance, reserved bool) {
	if p.count >= p.max {
		for k := range p.queues {
			p.expire(k, now)
		}
	}
	if p.count >= p.max && !reserved {
		return
	}
	p.queues[key] = append(p.queues[key], pendingCheck{at: now, trust: trust, instance: instance, reserved: reserved})
	p.count++
}

// take removes and returns the oldest unexpired check of key with trust. A
// report that names its instance takes exactly that instance's check, or
// none.
func (p *pendingChecks) take(key string, now time.Time, trust, instance string) (pendingCheck, bool) {
	p.expire(key, now)
	q := p.queues[key]
	for i, c := range q {
		if c.trust != trust || (instance != "" && (c.instance == nil || c.instance.ID != instance)) {
			continue
		}
		p.count--
		if len(q) == 1 {
			delete(p.queues, key)
		} else {
			p.queues[key] = append(q[:i:i], q[i+1:]...)
		}
		return c, true
	}
	return pendingCheck{}, false
}

// expire drops the checks of key older than the window, except those that
// hold a worker reservation.
func (p *pendingChecks) expire(key string, now time.Time) {
	var kept []pendingCheck
	for _, c := range p.queues[key] {
		if !c.reserved && now.Sub(c.at) > p.window {
			p.count--
			continue
		}
		kept = append(kept, c)
	}
	if len(kept) == 0 {
		delete(p.queues, key)
	} else {
		p.queues[key] = kept
	}
}
