//go:build linux

package supervisor

import "golang.org/x/sys/unix"

func signalOwnedGroup(pgid int, sig unix.Signal) error {
	return unix.Kill(-pgid, sig)
}
