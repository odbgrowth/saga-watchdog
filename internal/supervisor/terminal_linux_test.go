//go:build linux

package supervisor

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestInteractiveTerminalHandoffAndRestore(t *testing.T) {
	masterFD, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("PTY unavailable in test environment: %v", err)
	}
	master := os.NewFile(uintptr(masterFD), "pty-master")
	defer master.Close()
	if err := unix.IoctlSetPointerInt(masterFD, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	index, err := unix.IoctlGetInt(masterFD, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slaveFD, err := unix.Open(fmt.Sprintf("/dev/pts/%d", index), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	slave := os.NewFile(uintptr(slaveFD), "pty-slave")
	defer slave.Close()
	argv := helperArgv(t, "tty-owner")
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "SAGA_SUPERVISOR_TEST_HELPER=1", "GORACE=atexit_sleep_ms=0")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	slave.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	lines := make(chan string, 16)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(master)
		for scanner.Scan() {
			lines <- strings.TrimSpace(scanner.Text())
		}
	}()
	waitLine := func(want string) {
		t.Helper()
		timer := time.NewTimer(8 * time.Second)
		defer timer.Stop()
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					t.Fatalf("terminal closed before %q", want)
				}
				if line == want {
					return
				}
				t.Logf("terminal: %s", line)
			case <-timer.C:
				t.Fatalf("timed out waiting for %q", want)
			}
		}
	}
	waitLine("TTY ready")
	if _, err := master.WriteString("hello\n"); err != nil {
		t.Fatal(err)
	}
	waitLine("TTY restored")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminal helper did not exit")
	}
}
