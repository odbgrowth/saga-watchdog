//go:build linux || darwin

package supervisor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

type terminalState struct {
	file  *os.File
	group int
	attrs *unix.Termios
}

var terminalRestoreMu sync.Mutex

func prepareTerminal(stdin io.Reader, attr *syscall.SysProcAttr) (*terminalState, error) {
	file, ok := stdin.(*os.File)
	if !ok || file == nil {
		return nil, nil
	}
	fd := int(file.Fd())
	group, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if errors.Is(err, unix.ENOTTY) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect agent terminal: %w", err)
	}
	if group != unix.Getpgrp() {
		return nil, errors.New("watchdog must be in the terminal foreground to start an interactive agent")
	}
	attrs, err := unix.IoctlGetTermios(fd, terminalGetAttrs)
	if err != nil {
		return nil, fmt.Errorf("save agent terminal settings: %w", err)
	}
	// The child will own the foreground group. Keep supervisor diagnostics
	// writable even when the caller enabled `stty tostop`; otherwise the first
	// stderr write can suspend the watchdog itself with SIGTTOU. Save the
	// original settings above and restore them on every exit, including an
	// exec failure. Do not ignore SIGTTOU across exec: the agent must retain its
	// ordinary job-control signal disposition.
	if attrs.Lflag&unix.TOSTOP != 0 {
		active := *attrs
		active.Lflag &^= unix.TOSTOP
		if err := unix.IoctlSetTermios(fd, terminalSetAttrs, &active); err != nil {
			return nil, fmt.Errorf("prepare agent terminal settings: %w", err)
		}
	}
	// Go performs this handoff in the forked child before exec while signals
	// remain blocked, avoiding the race between first input and tcsetpgrp.
	attr.Foreground, attr.Ctty = true, fd
	return &terminalState{file: file, group: group, attrs: attrs}, nil
}

func (t *terminalState) restore() error {
	if t == nil {
		return nil
	}
	terminalRestoreMu.Lock()
	defer terminalRestoreMu.Unlock()
	// Watchdog is temporarily a background process while the child owns the
	// terminal. Ignore SIGTTOU only across the handoff and preserve an inherited
	// ignored disposition. The CLI must not install a separate SIGTTOU handler.
	ignored := signal.Ignored(syscall.SIGTTOU)
	signal.Ignore(syscall.SIGTTOU)
	defer func() {
		if !ignored {
			signal.Reset(syscall.SIGTTOU)
		}
	}()
	fd := int(t.file.Fd())
	groupErr := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, t.group)
	attrsErr := unix.IoctlSetTermios(fd, terminalSetAttrs, t.attrs)
	if err := errors.Join(groupErr, attrsErr); err != nil {
		return fmt.Errorf("restore terminal: %w", err)
	}
	return nil
}
