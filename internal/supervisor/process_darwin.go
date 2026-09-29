//go:build darwin

package supervisor

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func signalOwnedGroup(pgid int, sig unix.Signal) error {
	err := unix.Kill(-pgid, sig)
	if !errors.Is(err, unix.EPERM) {
		return err
	}
	// Darwin's killpg excludes zombies and reports EPERM when none remain
	// signalable. Our unreaped leader deliberately keeps its group ID reserved.
	// Confirm there are no live members before treating that error as success;
	// a real permission failure must still reach the caller.
	// See XNU bsd/kern/kern_sig.c, killpg1.
	members, inspectErr := unix.SysctlKinfoProcSlice("kern.proc.pgrp", pgid)
	if inspectErr != nil {
		return errors.Join(err, fmt.Errorf("inspect owned process group: %w", inspectErr))
	}
	const zombie = 5 // SZOMB in Darwin sys/proc.h.
	for _, member := range members {
		if member.Proc.P_stat != zombie {
			return err
		}
	}
	return nil
}
