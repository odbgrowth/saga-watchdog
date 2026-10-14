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
	if anyLive(members) {
		return err
	}
	return nil
}

// anyLive reports whether a process group member can still run user code. A
// zombie cannot, and neither can a process already in exit: XNU marks it
// P_LEXIT before it drops the references killpg needs and long before it
// becomes a zombie, so killpg skips it and reports EPERM. kern.proc.pgrp
// exports P_LEXIT as P_WEXIT (bsd/kern/kern_sysctl.c, fill_user64_externproc).
func anyLive(members []unix.KinfoProc) bool {
	const (
		zombie  = 5          // SZOMB in Darwin sys/proc.h.
		exiting = 0x00002000 // P_WEXIT in Darwin sys/proc.h.
	)
	for _, member := range members {
		if member.Proc.P_stat != zombie && member.Proc.P_flag&exiting == 0 {
			return true
		}
	}
	return false
}
