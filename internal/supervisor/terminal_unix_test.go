//go:build linux || darwin

package supervisor

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func runTTYHelper(mode string) {
	if mode == "tty-read" {
		attrs, err := unix.IoctlGetTermios(0, terminalGetAttrs)
		if err != nil {
			os.Exit(81)
		}
		attrs.Lflag &^= unix.ECHO
		if err := unix.IoctlSetTermios(0, terminalSetAttrs, attrs); err != nil {
			os.Exit(82)
		}
		fmt.Fprintln(os.Stdout, "TTY ready")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "hello" {
			os.Exit(83)
		}
		os.Exit(0)
	}
	if mode != "tty-owner" && mode != "tty-owner-tostop" && mode != "tty-owner-start-failure" {
		os.Exit(84)
	}
	before, err := unix.IoctlGetTermios(0, terminalGetAttrs)
	if err != nil {
		os.Exit(85)
	}
	if mode != "tty-owner" {
		before.Lflag |= unix.TOSTOP
		if err := unix.IoctlSetTermios(0, terminalSetAttrs, before); err != nil {
			os.Exit(90)
		}
	}
	exe, _ := os.Executable()
	argv := []string{exe, "-test.run=^TestSupervisorHelper$", "--", "tty-read"}
	if mode == "tty-owner-start-failure" {
		argv = []string{"/saga-watchdog-test/missing-executable"}
	}
	p, err := Start(argv,
		"", os.Environ(), os.Stdin, os.Stdout, os.Stderr)
	if mode == "tty-owner-start-failure" {
		if err == nil || p != nil {
			os.Exit(91)
		}
	} else if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(86)
	} else {
		// Bounds the test even if an implementation bug leaves the child stopped
		// by SIGTTIN while attempting to read from a background process group.
		timer := time.AfterFunc(4*time.Second, func() { _ = p.Stop(0) })
		// The child owns the foreground. A caller's TOSTOP setting must not
		// suspend the watchdog when it reports a policy decision to stderr.
		fmt.Fprintln(os.Stderr, "TTY watchdog diagnostic")
		r := <-p.Done()
		timer.Stop()
		if r.ExitCode != 0 || r.Err != nil {
			fmt.Fprintln(os.Stderr, r.Err)
			os.Exit(87)
		}
	}
	group, err := unix.IoctlGetInt(0, unix.TIOCGPGRP)
	if err != nil || group != unix.Getpgrp() {
		os.Exit(88)
	}
	after, err := unix.IoctlGetTermios(0, terminalGetAttrs)
	if err != nil || before.Lflag != after.Lflag {
		os.Exit(89)
	}
	fmt.Fprintln(os.Stdout, "TTY restored")
	os.Exit(0)
}
