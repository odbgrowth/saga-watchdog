//go:build darwin

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"
)

// A member that is exiting or already a zombie never runs user code again,
// so an EPERM from killpg with only such members left means the group is gone.
func TestExitingGroupMembersAreNotLive(t *testing.T) {
	member := func(stat int8, flag int32) unix.KinfoProc {
		var p unix.KinfoProc
		p.Proc.P_stat, p.Proc.P_flag = stat, flag
		return p
	}
	const (
		running = 2 // SRUN
		zombie  = 5 // SZOMB
		exiting = 0x00002000
	)
	for name, tc := range map[string]struct {
		members []unix.KinfoProc
		live    bool
	}{
		"empty group":            {nil, false},
		"zombie leader":          {[]unix.KinfoProc{member(zombie, 0)}, false},
		"exiting leader":         {[]unix.KinfoProc{member(running, exiting)}, false},
		"exiting and zombie":     {[]unix.KinfoProc{member(zombie, exiting), member(running, exiting)}, false},
		"running member":         {[]unix.KinfoProc{member(running, 0)}, true},
		"running beside exiting": {[]unix.KinfoProc{member(running, exiting), member(running, 0)}, true},
	} {
		if got := anyLive(tc.members); got != tc.live {
			t.Errorf("%s: anyLive = %v, want %v", name, got, tc.live)
		}
	}
}
