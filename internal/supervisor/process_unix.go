//go:build linux || darwin

package supervisor

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Process owns a single child and its original process group. Descendants
// that create another group or session are outside this control boundary.
// Methods may be called concurrently; PID is informational, never an input
// to a control operation.
type Process struct {
	cmd         *exec.Cmd
	pid         int
	tty         *terminalState
	done        chan Result
	mu          sync.Mutex
	terminating bool
	finished    bool
	stopOnce    sync.Once
	stopErr     error
}

func Supported() bool { return true }

// Start executes argv directly, without adding a shell. A nil env inherits
// the parent's environment. Terminal-backed stdin is handed to the child
// process group before exec, so interactive programs can read without SIGTTIN.
func Start(argv []string, dir string, env []string, stdin io.Reader, stdout, stderr io.Writer) (*Process, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, errors.New("agent command is required")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir, cmd.Env = dir, env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// A detached descendant must not keep a copied output pipe open forever.
	cmd.WaitDelay = time.Second
	tty, err := prepareTerminal(stdin, cmd.SysProcAttr)
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, errors.Join(fmt.Errorf("start agent: %w", err), tty.restore())
	}
	p := &Process{cmd: cmd, pid: cmd.Process.Pid, tty: tty, done: make(chan Result, 1)}
	go p.wait()
	return p, nil
}

func (p *Process) PID() int { return p.pid }

// Done publishes exactly one result, after group cleanup and terminal restore,
// then closes. It is intended to have one consumer.
func (p *Process) Done() <-chan Result { return p.done }

func (p *Process) Pause() error  { return p.control(unix.SIGSTOP) }
func (p *Process) Resume() error { return p.control(unix.SIGCONT) }

func (p *Process) control(sig unix.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return ErrFinished
	}
	if p.terminating {
		return ErrTerminating
	}
	return p.signalGroup(sig)
}

// Stop is idempotent. It sends TERM, resumes paused members so they can handle
// TERM, waits the requested grace period, and sends KILL to the entire group.
// It deliberately does not return early when just the group leader exits.
// Done reports the final exit after reaping; Stop itself waits for escalation.
func (p *Process) Stop(grace time.Duration) error {
	p.stopOnce.Do(func() {
		p.mu.Lock()
		if p.finished {
			p.mu.Unlock()
			return
		}
		p.terminating = true
		termErr := p.signalGroup(unix.SIGTERM)
		contErr := p.signalGroup(unix.SIGCONT)
		p.mu.Unlock()
		if grace > 0 {
			timer := time.NewTimer(grace)
			<-timer.C
		}
		p.mu.Lock()
		var killErr error
		if !p.finished {
			killErr = p.signalGroup(unix.SIGKILL)
		}
		p.mu.Unlock()
		p.stopErr = errors.Join(termErr, contErr, killErr)
	})
	return p.stopErr
}

func (p *Process) signalGroup(sig unix.Signal) error {
	// The leader remains unreaped until the final group signal. Retaining its
	// PID prevents group-ID reuse from redirecting a signal to an unrelated run.
	if p.pid <= 1 {
		return errors.New("invalid owned process group")
	}
	err := unix.Kill(-p.pid, sig)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("signal agent group: %w", err)
	}
	return nil
}

func (p *Process) wait() {
	// Do not call cmd.Wait before cleanup: it reaps the leader, allowing its
	// numeric PID to be reused during a delayed group kill.
	observeErr := waitExited(p.pid)
	if errors.Is(observeErr, unix.ECHILD) {
		// An unexpected external reaper invalidates our PID ownership. Never
		// send another group signal after receiving that evidence.
		p.mu.Lock()
		p.finished = true
		p.mu.Unlock()
	}
	grace := 250 * time.Millisecond
	if observeErr != nil {
		grace = 0
	}
	stopErr := p.Stop(grace)
	p.mu.Lock()
	p.finished = true
	p.mu.Unlock()
	waitErr := p.cmd.Wait()
	code := 1
	if p.cmd.ProcessState != nil {
		code = p.cmd.ProcessState.ExitCode()
		if status, ok := p.cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			code = 128 + int(status.Signal())
		}
	}
	if observeErr != nil {
		observeErr = fmt.Errorf("observe agent exit: %w", observeErr)
	}
	result := Result{ExitCode: code, Err: errors.Join(waitErr, observeErr, stopErr, p.tty.restore())}
	p.done <- result
	close(p.done)
}
