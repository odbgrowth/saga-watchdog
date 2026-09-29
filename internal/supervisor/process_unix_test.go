//go:build linux || darwin

package supervisor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func helperArgv(t *testing.T, mode string, args ...string) []string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return append([]string{exe, "-test.run=^TestSupervisorHelper$", "--", mode}, args...)
}

func startHelper(t *testing.T, mode string, dir string, output io.Writer, args ...string) *Process {
	t.Helper()
	env := append(os.Environ(), "SAGA_SUPERVISOR_TEST_HELPER=1", "GORACE=atexit_sleep_ms=0")
	p, err := Start(helperArgv(t, mode, args...), dir, env, nil, output, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Stop(0); err != nil {
			t.Errorf("cleanup stop: %v", err)
		}
		select {
		case <-p.Done():
		case <-time.After(5 * time.Second):
			t.Error("supervisor did not finish cleanup")
		}
	})
	return p
}

func result(t *testing.T, p *Process) Result {
	t.Helper()
	select {
	case r, ok := <-p.Done():
		if !ok {
			t.Fatal("exit result already consumed")
		}
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for supervised process")
		return Result{}
	}
}

func eventually(t *testing.T, description string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", description)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return info.Size()
}

func TestNormalAndNonzeroExit(t *testing.T) {
	for _, code := range []int{0, 17} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			var output bytes.Buffer
			p := startHelper(t, "exit", t.TempDir(), &output, strconv.Itoa(code))
			r := result(t, p)
			if r.ExitCode != code {
				t.Fatalf("exit=%d, want %d (%v)", r.ExitCode, code, r.Err)
			}
			if code == 0 && r.Err != nil {
				t.Fatal(r.Err)
			}
			if code != 0 {
				var exitErr *exec.ExitError
				if !errors.As(r.Err, &exitErr) {
					t.Fatalf("missing exit error: %v", r.Err)
				}
			}
			if output.String() != "agent output" {
				t.Fatalf("stdout=%q", output.String())
			}
			if err := p.Pause(); !errors.Is(err, ErrFinished) {
				t.Fatalf("pause finished process: %v", err)
			}
		})
	}
}

func TestCommandValidation(t *testing.T) {
	for _, argv := range [][]string{nil, {""}, {filepath.Join(t.TempDir(), "missing-executable")}} {
		if p, err := Start(argv, "", nil, nil, io.Discard, io.Discard); err == nil || p != nil {
			t.Fatalf("Start(%q) = %v, %v", argv, p, err)
		}
	}
}

func TestWorkingDirectoryAndEnvironment(t *testing.T) {
	var output bytes.Buffer
	dir := t.TempDir()
	p, err := Start(helperArgv(t, "context"), dir,
		append(os.Environ(), "SAGA_SUPERVISOR_TEST_HELPER=1", "GORACE=atexit_sleep_ms=0", "SAGA_SUPERVISOR_CONTEXT=passed"),
		nil, &output, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if r := result(t, p); r.Err != nil {
		t.Fatal(r.Err)
	}
	// macOS may canonicalize /var to /private/var for the process cwd.
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if output.String() != realDir+"|passed" {
		t.Fatalf("context=%q, want %q", output.String(), realDir+"|passed")
	}
}

func TestGracefulStopWhilePaused(t *testing.T) {
	dir := t.TempDir()
	p := startHelper(t, "graceful", dir, io.Discard, dir)
	eventually(t, "agent ready", func() bool { return exists(filepath.Join(dir, "ready")) })
	if err := p.Pause(); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(300 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	r := result(t, p)
	if r.ExitCode != 0 || r.Err != nil || !exists(filepath.Join(dir, "terminated")) {
		t.Fatalf("graceful termination failed: %#v", r)
	}
}

func TestForcedStopAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	p := startHelper(t, "stubborn", dir, io.Discard, dir)
	eventually(t, "agent ready", func() bool { return exists(filepath.Join(dir, "ready")) })
	const grace = 150 * time.Millisecond
	started := time.Now()
	if err := p.Stop(grace); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < grace {
		t.Fatal("forced stop skipped grace period")
	}
	if r := result(t, p); r.ExitCode != 128+int(syscall.SIGKILL) {
		t.Fatalf("forced exit=%d (%v)", r.ExitCode, r.Err)
	}
	if err := p.Stop(time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestPauseResume(t *testing.T) {
	dir := t.TempDir()
	p := startHelper(t, "stubborn", dir, io.Discard, dir)
	heartbeat := filepath.Join(dir, "heartbeat")
	eventually(t, "agent heartbeat", func() bool { return fileSize(heartbeat) > 2 })
	if err := p.Pause(); err != nil {
		t.Fatal(err)
	}
	// Allow an in-flight write to finish before checking for a stable pause.
	time.Sleep(60 * time.Millisecond)
	pausedSize := fileSize(heartbeat)
	time.Sleep(100 * time.Millisecond)
	if got := fileSize(heartbeat); got != pausedSize {
		t.Fatalf("paused process still writing: %d -> %d", pausedSize, got)
	}
	select {
	case r := <-p.Done():
		t.Fatalf("pause was mistaken for exit: %#v", r)
	default:
	}
	if err := p.Resume(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "resumed heartbeat", func() bool { return fileSize(heartbeat) > pausedSize })
}

func TestGroupCleanupAfterLeaderExit(t *testing.T) {
	for _, natural := range []bool{false, true} {
		t.Run(fmt.Sprintf("natural=%v", natural), func(t *testing.T) {
			dir := t.TempDir()
			p := startHelper(t, "leader", dir, io.Discard, dir)
			eventually(t, "leader and descendant ready", func() bool { return exists(filepath.Join(dir, "ready")) })
			childHeartbeat := filepath.Join(dir, "child", "heartbeat")
			eventually(t, "descendant heartbeat", func() bool { return fileSize(childHeartbeat) > 1 })
			// An independent owned group must remain unaffected by the first stop.
			otherDir := t.TempDir()
			other := startHelper(t, "stubborn", otherDir, io.Discard, otherDir)
			otherHeartbeat := filepath.Join(otherDir, "heartbeat")
			eventually(t, "independent heartbeat", func() bool { return fileSize(otherHeartbeat) > 1 })
			if natural {
				if err := os.WriteFile(filepath.Join(dir, "exit"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := p.Stop(200 * time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if r := result(t, p); r.ExitCode != 0 || r.Err != nil {
				t.Fatalf("leader did not exit gracefully: %#v", r)
			}
			time.Sleep(60 * time.Millisecond)
			stoppedSize := fileSize(childHeartbeat)
			otherSize := fileSize(otherHeartbeat)
			time.Sleep(100 * time.Millisecond)
			if got := fileSize(childHeartbeat); got != stoppedSize {
				t.Fatalf("descendant survived leader cleanup: %d -> %d", stoppedSize, got)
			}
			eventually(t, "independent group still running", func() bool { return fileSize(otherHeartbeat) > otherSize })
			select {
			case r := <-other.Done():
				t.Fatalf("unrelated group stopped: %#v", r)
			default:
			}
		})
	}
}

// These subprocesses have no shell dependency, and signal handling is installed
// before their ready marker so tests never race startup against termination.
func TestSupervisorHelper(t *testing.T) {
	if os.Getenv("SAGA_SUPERVISOR_TEST_HELPER") != "1" {
		return
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		os.Exit(90)
	}
	switch args[0] {
	case "exit":
		code, _ := strconv.Atoi(args[1])
		fmt.Fprint(os.Stdout, "agent output")
		os.Exit(code)
	case "context":
		cwd, _ := os.Getwd()
		cwd, _ = filepath.EvalSymlinks(cwd)
		fmt.Fprintf(os.Stdout, "%s|%s", cwd, os.Getenv("SAGA_SUPERVISOR_CONTEXT"))
		os.Exit(0)
	case "graceful":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM)
		helperWrite(filepath.Join(args[1], "ready"))
		<-signals
		helperWrite(filepath.Join(args[1], "terminated"))
		os.Exit(0)
	case "stubborn":
		signal.Ignore(syscall.SIGTERM)
		if err := os.MkdirAll(args[1], 0700); err != nil {
			os.Exit(91)
		}
		file, err := os.Create(filepath.Join(args[1], "heartbeat"))
		if err != nil {
			os.Exit(92)
		}
		helperWrite(filepath.Join(args[1], "ready"))
		for {
			if _, err := file.WriteString("."); err != nil {
				os.Exit(93)
			}
			time.Sleep(10 * time.Millisecond)
		}
	case "leader":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM)
		exe, _ := os.Executable()
		childDir := filepath.Join(args[1], "child")
		child := exec.Command(exe, "-test.run=^TestSupervisorHelper$", "--", "stubborn", childDir)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(94)
		}
		deadline := time.Now().Add(4 * time.Second)
		for !exists(filepath.Join(childDir, "ready")) {
			if time.Now().After(deadline) {
				os.Exit(95)
			}
			time.Sleep(10 * time.Millisecond)
		}
		helperWrite(filepath.Join(args[1], "ready"))
		for {
			select {
			case <-signals:
				os.Exit(0)
			case <-time.After(10 * time.Millisecond):
				if exists(filepath.Join(args[1], "exit")) {
					os.Exit(0)
				}
			}
		}
	default:
		if strings.HasPrefix(args[0], "tty-") {
			runTTYHelper(args[0])
		}
		os.Exit(96)
	}
}

func helperWrite(path string) {
	if err := os.WriteFile(path, []byte("ready"), 0600); err != nil {
		os.Exit(97)
	}
}
