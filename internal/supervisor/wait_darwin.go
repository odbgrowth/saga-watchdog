//go:build darwin

package supervisor

import (
	"errors"

	"golang.org/x/sys/unix"
)

const (
	terminalGetAttrs = unix.TIOCGETA
	terminalSetAttrs = unix.TIOCSETA
)

func waitExited(pid int) error {
	// NOTE_EXIT observes termination without reaping. Unlike Darwin waitid,
	// it does not confuse a stopped child with an exited child.
	fd, err := unix.Kqueue()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	unix.CloseOnExec(fd)
	changes := []unix.Kevent_t{{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}}
	events := make([]unix.Kevent_t, 1)
	for {
		n, err := unix.Kevent(fd, changes, events, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ESRCH) {
			return nil // The owned child exited before registration; still unreaped.
		}
		if err != nil {
			return err
		}
		changes = nil
		if n == 0 {
			continue
		}
		if events[0].Flags&unix.EV_ERROR != 0 {
			err = unix.Errno(events[0].Data)
			if errors.Is(err, unix.ESRCH) {
				return nil
			}
			return err
		}
		if events[0].Fflags&unix.NOTE_EXIT != 0 {
			return nil
		}
	}
}
