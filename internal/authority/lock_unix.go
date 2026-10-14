//go:build linux || darwin

package authority

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// lockPath takes an exclusive advisory lock that serializes runs sharing a
// context. It blocks briefly; state updates are small.
func lockPath(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, errors.New("cannot lock persistent authority state")
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
