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

// workerLedger holds one slot per same-host worker instance, by the instance
// ID the supervisor assigned: reserved by an allowed pre-action check, or
// running once a report confirms it. Workers sharing a target name each hold
// their own slot, and an event about one instance never touches another.
type workerLedger struct {
	slots map[string]slot
	// untracked counts workers that started without a slot of their own:
	// beyond maxWorkers or without an instance ID. They cannot be identified
	// when they stop, so they hold budget until the run ends: fail closed.
	untracked int
}

func (w *workerLedger) inUse() int { return len(w.slots) + w.untracked }

func (w *workerLedger) has(id string, s slot) bool { return id != "" && w.slots[id] == s }

// add takes a slot for a new instance, or reports false when the instance
// cannot be tracked.
func (w *workerLedger) add(id string, s slot) bool {
	if _, taken := w.slots[id]; id == "" || taken || len(w.slots) >= maxWorkers {
		return false
	}
	if w.slots == nil {
		w.slots = map[string]slot{}
	}
	w.slots[id] = s
	return true
}

// remove frees the slot of instance id while it is in state s. Any later
// event about that instance finds nothing to free.
func (w *workerLedger) remove(id string, s slot) bool {
	if !w.has(id, s) {
		return false
	}
	delete(w.slots, id)
	return true
}

// promote confirms the reservation of instance id as running.
func (w *workerLedger) promote(id string) bool {
	if !w.has(id, reserved) {
		return false
	}
	w.slots[id] = running
	return true
}
