package main

import (
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/authority"
)

// pendingChecks holds allowed pre-action checks until the reports of their
// actions arrive: per action, oldest first, with the time of the check and
// the instance a start was given. A report takes the oldest unexpired check
// of its action, so concurrent checks each pair with one report. Entries
// expire after the window, so an abandoned check never pairs with a later
// action. The total is bounded; a check beyond it pairs with nothing, and its
// report then counts as its own action: once more, never less.
type pendingChecks struct {
	window time.Duration
	max    int
	queues map[string][]pendingCheck
	count  int
}

type pendingCheck struct {
	at       time.Time
	instance *authority.Instance
}

func newPendingChecks(window time.Duration, max int) *pendingChecks {
	return &pendingChecks{window: window, max: max, queues: map[string][]pendingCheck{}}
}

func (p *pendingChecks) add(key string, now time.Time, instance *authority.Instance) {
	if p.count >= p.max {
		for k := range p.queues {
			p.expire(k, now)
		}
	}
	if p.count >= p.max {
		return
	}
	p.queues[key] = append(p.queues[key], pendingCheck{at: now, instance: instance})
	p.count++
}

// take removes and returns the oldest unexpired check of key.
func (p *pendingChecks) take(key string, now time.Time) (pendingCheck, bool) {
	p.expire(key, now)
	q := p.queues[key]
	if len(q) == 0 {
		return pendingCheck{}, false
	}
	p.count--
	if len(q) == 1 {
		delete(p.queues, key)
	} else {
		p.queues[key] = q[1:]
	}
	return q[0], true
}

// expire drops the checks of key older than the window; a queue is in time
// order.
func (p *pendingChecks) expire(key string, now time.Time) {
	q := p.queues[key]
	for len(q) > 0 && now.Sub(q[0].at) > p.window {
		q = q[1:]
		p.count--
	}
	if len(q) == 0 {
		delete(p.queues, key)
	} else {
		p.queues[key] = q
	}
}
