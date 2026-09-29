//go:build linux

package supervisor

import (
	"errors"

	"golang.org/x/sys/unix"
)

const (
	terminalGetAttrs = unix.TCGETS
	terminalSetAttrs = unix.TCSETS
)

func waitExited(pid int) error {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}
