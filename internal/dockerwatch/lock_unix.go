//go:build linux || darwin

package dockerwatch

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func lockFile(f *os.File) error {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("observer state is already in use, or filesystem locking is unavailable")
	}
	return nil
}
