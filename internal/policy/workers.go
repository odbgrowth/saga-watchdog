package policy

// slot is the state of one worker slot.
type slot int

const (
	reserved slot = iota + 1
	running
)

// maxWorkers bounds tracked workers; beyond the configured budget every new
// worker is refused anyway.
const maxWorkers = 256

// workerLedger holds one slot per same-host worker instance, by target:
// reserved by an allowed pre-action check, or running once a report confirms
// it. Several workers may share a target name; each holds its own slot.
type workerLedger struct {
	slots map[string][]slot
	count int
	// untracked counts refused workers that started beyond maxWorkers. They
	// cannot be identified when they stop, so they hold budget until the run
	// ends: fail closed.
	untracked int
}

func (w *workerLedger) inUse() int { return w.count + w.untracked }

func (w *workerLedger) has(target string, s slot) bool {
	for _, have := range w.slots[target] {
		if have == s {
			return true
		}
	}
	return false
}

// add takes a slot, or reports false when the ledger is full.
func (w *workerLedger) add(target string, s slot) bool {
	if w.count >= maxWorkers {
		return false
	}
	if w.slots == nil {
		w.slots = map[string][]slot{}
	}
	w.slots[target] = append(w.slots[target], s)
	w.count++
	return true
}

// remove frees one slot of target in state s.
func (w *workerLedger) remove(target string, s slot) bool {
	q := w.slots[target]
	for i, have := range q {
		if have != s {
			continue
		}
		if len(q) == 1 {
			delete(w.slots, target)
		} else {
			w.slots[target] = append(q[:i:i], q[i+1:]...)
		}
		w.count--
		return true
	}
	return false
}

// promote confirms one reservation of target as running.
func (w *workerLedger) promote(target string) bool {
	for i, have := range w.slots[target] {
		if have == reserved {
			w.slots[target][i] = running
			return true
		}
	}
	return false
}
