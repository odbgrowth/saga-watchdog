// Package supervisor controls only the process group created by Start.
package supervisor

import "errors"

var (
	ErrUnsupported = errors.New("process supervision requires Linux or macOS")
	ErrFinished    = errors.New("supervised process has finished")
	ErrTerminating = errors.New("supervised process is terminating")
)

// Result describes the agent's exit. Signal exits use the shell convention
// 128 + signal number. Err also reports supervision or terminal cleanup errors.
type Result struct {
	ExitCode int
	Err      error
}
