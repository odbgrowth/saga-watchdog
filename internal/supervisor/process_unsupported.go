//go:build !linux && !darwin

package supervisor

import (
	"io"
	"time"
)

type Process struct{}

func Supported() bool { return false }
func Start([]string, string, []string, io.Reader, io.Writer, io.Writer) (*Process, error) {
	return nil, ErrUnsupported
}
func (*Process) PID() int                 { return 0 }
func (*Process) Done() <-chan Result      { return nil }
func (*Process) Pause() error             { return ErrUnsupported }
func (*Process) Resume() error            { return ErrUnsupported }
func (*Process) Stop(time.Duration) error { return ErrUnsupported }
