// Package socket provides local, bounded JSON requests. It is not a security
// boundary against another process running under the same user account.
package socket

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/policy"
	"github.com/odbgrowth/saga-watchdog/internal/store"
)

type Input struct {
	Type   string `json:"type"`
	Action string `json:"action"`
	Target string `json:"target"`
	Result string `json:"result,omitempty"`
}
type Request struct {
	Operation string `json:"operation"`
	RunID     string `json:"run_id,omitempty"`
	Event     Input  `json:"event,omitempty"`
}
type Response struct {
	Allowed  bool             `json:"allowed"`
	Decision *policy.Decision `json:"decision,omitempty"`
	Run      *store.Run       `json:"run,omitempty"`
	Error    string           `json:"error,omitempty"`
}
type Call struct {
	Request Request
	Reply   chan Response
}
type Server struct {
	Dir, Events, Control string
	events, control      net.Listener
	wg                   sync.WaitGroup
	stop                 context.CancelFunc
}

func Validate(r Request, controls bool) error {
	if r.RunID != "" && !store.ValidID(r.RunID) {
		return errors.New("invalid run ID")
	}
	if controls {
		switch r.Operation {
		case "status", "pause", "resume", "kill":
		default:
			return errors.New("unsupported control operation")
		}
		if r.Event != (Input{}) {
			return errors.New("control request must not contain an event")
		}
		return nil
	}
	if r.Operation != "check" && r.Operation != "emit" {
		return errors.New("events endpoint accepts only check and emit")
	}
	switch r.Event.Type {
	case "file", "network", "credential", "tool", "policy", "git", "process":
	default:
		return errors.New("invalid event type")
	}
	if r.Event.Action == "" || len(r.Event.Action) > 64 || len(r.Event.Target) > 4096 || r.Event.Target == "" {
		return errors.New("action and target are required and must fit their limits")
	}
	if strings.ContainsAny(r.Event.Action+r.Event.Target, "\x00\r\n") {
		return errors.New("event contains control characters")
	}
	if r.Operation == "check" && r.Event.Result != "" {
		return errors.New("check cannot supply a result")
	}
	switch r.Event.Result {
	case "", "allowed", "denied", "blocked", "failed", "success":
	default:
		return errors.New("invalid event result")
	}
	return nil
}

func Decode(b []byte, controls bool) (Request, error) {
	var r Request
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return r, errors.New("expected one JSON object")
	}
	return r, Validate(r, controls)
}

func Start(ctx context.Context, calls chan<- Call) (*Server, error) {
	dir, err := os.MkdirTemp("", "saga-")
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		os.Remove(dir)
		return nil, err
	}
	s := &Server{Dir: dir, Events: filepath.Join(dir, "events.sock"), Control: filepath.Join(dir, "control.sock")}
	ctx, s.stop = context.WithCancel(ctx)
	s.events, err = net.Listen("unix", s.Events)
	if err != nil {
		os.Remove(dir)
		return nil, err
	}
	s.control, err = net.Listen("unix", s.Control)
	if err != nil {
		s.events.Close()
		os.Remove(s.Events)
		os.Remove(dir)
		return nil, err
	}
	for _, p := range []string{s.Events, s.Control} {
		if err = os.Chmod(p, 0600); err != nil {
			s.Close()
			return nil, err
		}
	}
	// The semaphore bounds concurrent clients and in-flight request memory.
	sem := make(chan struct{}, 32)
	for idx, l := range []net.Listener{s.events, s.control} {
		s.wg.Add(1)
		go func(l net.Listener, controls bool) {
			defer s.wg.Done()
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				select {
				case sem <- struct{}{}:
				default:
					c.Close()
					continue
				}
				s.wg.Add(1)
				go func() {
					defer s.wg.Done()
					defer func() { <-sem }()
					defer c.Close()
					s.handle(ctx, c, calls, controls)
				}()
			}
		}(l, idx == 1)
	}
	return s, nil
}

func (s *Server) handle(ctx context.Context, c net.Conn, calls chan<- Call, controls bool) {
	c.SetDeadline(time.Now().Add(3 * time.Second))
	scan := bufio.NewScanner(c)
	scan.Buffer(make([]byte, 4096), 65536)
	if !scan.Scan() {
		return
	}
	r, err := Decode(scan.Bytes(), controls)
	if err != nil {
		json.NewEncoder(c).Encode(Response{Error: "invalid request: " + err.Error()})
		return
	}
	call := Call{Request: r, Reply: make(chan Response, 1)}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	select {
	case calls <- call:
	case <-ctx.Done():
		return
	case <-deadline.C:
		return
	}
	select {
	case response := <-call.Reply:
		json.NewEncoder(c).Encode(response)
	case <-ctx.Done():
		return
	case <-deadline.C:
		return
	}
}

func (s *Server) Close() error {
	if s.stop != nil {
		s.stop()
	}
	if s.events != nil {
		s.events.Close()
	}
	if s.control != nil {
		s.control.Close()
	}
	s.wg.Wait()
	// Remove only this server's private directory and exact socket files.
	os.Remove(s.Events)
	os.Remove(s.Control)
	return os.Remove(s.Dir)
}

func Send(path string, r Request) (Response, error) {
	var response Response
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return response, fmt.Errorf("watchdog unavailable: %w", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	if err = json.NewEncoder(c).Encode(r); err != nil {
		return response, err
	}
	if err = json.NewDecoder(io.LimitReader(c, 65536)).Decode(&response); err != nil {
		return response, err
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}
