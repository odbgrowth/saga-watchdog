package dockerwatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/event"
)

func (c Config) ID() string {
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Resources struct {
	At               time.Time `json:"observed_at"`
	MemoryBytes      uint64    `json:"memory_bytes"`
	MemoryLimitBytes uint64    `json:"memory_limit_bytes"`
	CPUPercent       *float64  `json:"cpu_percent,omitempty"`
}

type TargetStatus struct {
	Target
	Availability string     `json:"availability"`
	State        string     `json:"state"`
	Health       string     `json:"health"`
	OOMKilled    bool       `json:"oom_killed"`
	RestartCount int        `json:"restart_count"`
	ObservedAt   *time.Time `json:"observed_at,omitempty"`
	Error        string     `json:"error,omitempty"`
	Resources    *Resources `json:"resources,omitempty"`
	StatsError   string     `json:"stats_error,omitempty"`
}

type Snapshot struct {
	Version     int            `json:"version"`
	ConfigID    string         `json:"config_id"`
	SessionID   string         `json:"session_id"`
	Observer    string         `json:"observer"`
	UpdatedAt   time.Time      `json:"updated_at"`
	EventStream string         `json:"event_stream"`
	StreamError string         `json:"stream_error,omitempty"`
	Targets     []TargetStatus `json:"targets"`
}

// Freshness is computed by readers, so a crashed observer cannot leave an
// indefinitely healthy-looking status file. The file is a last observation.
func (s *Snapshot) Refresh(c Config, now time.Time) {
	if s.Observer == "running" && now.Sub(s.UpdatedAt) > 2*c.PollInterval+3*c.RequestTimeout {
		s.Observer = "stale"
		s.EventStream = "unknown"
		for i := range s.Targets {
			s.Targets[i].Availability = "unknown"
		}
	}
}

type streamMessage struct {
	state string
	err   error
	event *DockerEvent
}

func stream(ctx context.Context, c *Client, ids []string, ch chan<- streamMessage) {
	send := func(m streamMessage) bool {
		select {
		case ch <- m:
			return true
		case <-ctx.Done():
			return false
		}
	}
	backoff := time.Second
	for ctx.Err() == nil {
		api, err := c.Version(ctx)
		if err == nil {
			var connectedAt time.Time
			received := false
			err = c.Events(ctx, api, ids, func() {
				connectedAt = time.Now()
				send(streamMessage{state: "connected"})
			}, func(e DockerEvent) error {
				select {
				case ch <- streamMessage{event: &e}:
					received = true
					return nil
				case <-ctx.Done():
					return ctx.Err()
				default:
					return errors.New("event queue full; some events may be missing")
				}
			})
			// A successful HTTP handshake alone may immediately end in EOF.
			// Reset only after useful events or a sustained (possibly idle) stream.
			if received || (!connectedAt.IsZero() && time.Since(connectedAt) >= 30*time.Second) {
				backoff = time.Second
			}
		}
		if ctx.Err() != nil || !send(streamMessage{state: "disconnected", err: err}) {
			return
		}
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	s := event.Redact(err.Error())
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}

type resourceSample struct {
	Stats
	RestartCount int
}

func inspectTarget(ctx context.Context, c *Client, api string, t Target, previous *resourceSample) (TargetStatus, *resourceSample) {
	s := TargetStatus{Target: t, Availability: "unknown", State: "unknown", Health: "unknown"}
	i, err := c.Inspect(ctx, api, t.ID)
	if err != nil {
		if errors.Is(err, ErrMissing) {
			s.Availability = "missing"
		}
		s.Error = safeError(err)
		return s, nil
	}
	switch i.State.Status {
	case "created", "running", "paused", "restarting", "removing", "exited", "dead":
		s.State = i.State.Status
	default:
		s.Error = "Docker returned an unknown container state"
		return s, nil
	}
	s.Health = "none"
	if i.State.Health != nil {
		switch i.State.Health.Status {
		case "healthy", "unhealthy", "starting":
			s.Health = i.State.Health.Status
		default:
			s.Health = "unknown"
		}
	}
	now := time.Now().UTC()
	s.Availability = "present"
	s.ObservedAt = &now
	s.OOMKilled = i.State.OOMKilled
	s.RestartCount = i.RestartCount
	if s.State != "running" && s.State != "paused" {
		return s, nil
	}
	stats, err := c.Stats(ctx, api, t.ID)
	if err != nil {
		s.StatsError = safeError(err)
		return s, nil
	}
	r := &Resources{At: stats.Read.UTC(), MemoryBytes: stats.Memory.Usage, MemoryLimitBytes: stats.Memory.Limit}
	if previous != nil && previous.RestartCount == s.RestartCount && stats.CPU.System > previous.CPU.System && stats.CPU.Usage.Total >= previous.CPU.Usage.Total {
		cpus := stats.CPU.Online
		if cpus == 0 {
			cpus = uint64(len(stats.CPU.Usage.PerCPU))
		}
		if cpus > 0 {
			p := float64(stats.CPU.Usage.Total-previous.CPU.Usage.Total) / float64(stats.CPU.System-previous.CPU.System) * float64(cpus) * 100
			r.CPUPercent = &p
		}
	}
	s.Resources = r
	return s, &resourceSample{Stats: stats, RestartCount: s.RestartCount}
}

func poll(ctx context.Context, c *Client, targets []Target, previous []*resourceSample) ([]TargetStatus, []*resourceSample) {
	out := make([]TargetStatus, len(targets))
	next := make([]*resourceSample, len(targets))
	api, err := c.Version(ctx)
	if err != nil {
		for n, t := range targets {
			out[n] = TargetStatus{Target: t, Availability: "unknown", State: "unknown", Health: "unknown", Error: safeError(err)}
		}
		return out, next
	}
	var wg sync.WaitGroup
	for n, t := range targets {
		wg.Go(func() { out[n], next[n] = inspectTarget(ctx, c, api, t, previous[n]) })
	}
	wg.Wait()
	return out, next
}

func signature(t TargetStatus) string {
	return fmt.Sprintf("%s/%s/%s/restarts=%d/oom=%t/%s/stats=%s", t.Availability, t.State, t.Health, t.RestartCount, t.OOMKilled, t.Error, t.StatsError)
}

// Run never creates or controls an agent. Cancelling the observer stops only
// its own API requests and journaling. There is no implicit timeout/kill policy.
func Run(ctx context.Context, cfg Config, client *Client, once bool) (err error) {
	if err = cfg.Validate(); err != nil {
		return err
	}
	j, err := OpenJournal(cfg.StateDir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, j.Close()) }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := Snapshot{Version: 1, ConfigID: cfg.ID(), SessionID: event.NewID("observe"), Observer: "running", EventStream: "connecting"}
	for _, t := range cfg.Targets {
		s.Targets = append(s.Targets, TargetStatus{Target: t, Availability: "unknown", State: "unknown", Health: "unknown"})
	}
	if once {
		s.EventStream = "not_requested"
	}
	save := func() error { s.UpdatedAt = time.Now().UTC(); return j.Save(s) }
	audit := func(action, target, result, severity, reason string) error {
		return j.Append(event.Event{ID: event.NewID("evt"), Timestamp: time.Now().UTC(), RunID: s.SessionID, Source: "docker", Type: "container", Action: action, Target: target, Result: result, Severity: severity, Metadata: map[string]any{"reason": reason, "mode": "observe", "enforced": false}})
	}
	if err = audit("observer-start", "observer", "running", "info", "observations only; no container lifecycle ownership"); err != nil {
		return err
	}
	if err = save(); err != nil {
		return err
	}
	defer func() {
		s.Observer = "stopped"
		s.EventStream = "disconnected"
		if err != nil {
			s.Observer = "failed"
		}
		err = errors.Join(err, audit("observer-stop", "observer", s.Observer, "info", "selected containers were not modified"), save())
	}()
	var previous = make([]*resourceSample, len(cfg.Targets))
	refresh := func() error {
		var next []TargetStatus
		next, previous = poll(ctx, client, cfg.Targets, previous)
		if ctx.Err() != nil {
			return nil
		}
		for n, t := range next {
			if signature(t) != signature(s.Targets[n]) {
				severity := "info"
				if t.Availability != "present" || t.Health == "unhealthy" || t.State == "dead" || t.OOMKilled || t.StatsError != "" {
					severity = "warning"
				}
				if err := audit("state", t.ID, t.Availability, severity, signature(t)); err != nil {
					return err
				}
			}
		}
		s.Targets = next
		return save()
	}
	if once {
		return refresh()
	}
	ids := make([]string, len(cfg.Targets))
	for n, t := range cfg.Targets {
		ids[n] = t.ID
	}
	messages := make(chan streamMessage, 256)
	done := make(chan struct{})
	go func() { defer close(done); stream(ctx, client, ids, messages) }()
	defer func() { cancel(); <-done }()
	if err = refresh(); err != nil {
		return err
	}
	tick := time.NewTicker(cfg.PollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if err = refresh(); err != nil {
				return err
			}
		case m := <-messages:
			if m.event != nil {
				e := m.event
				severity := "info"
				if e.Action == "oom" || e.Action == "health_status: unhealthy" {
					severity = "warning"
				}
				if err = audit(e.Action, e.Actor.ID, "observed", severity, "runtime event; application actions are not observed"); err != nil {
					return err
				}
			} else {
				reason := safeError(m.err)
				if m.state != s.EventStream || reason != s.StreamError {
					severity := "info"
					if m.state != "connected" {
						severity = "warning"
					}
					if err = audit("event-stream", "observer", m.state, severity, reason); err != nil {
						return err
					}
				}
				s.EventStream = m.state
				s.StreamError = reason
			}
			// Only polls update the heartbeat. A busy event stream must not keep
			// stale container observations looking fresh after polling stalls.
			if err = j.Save(s); err != nil {
				return err
			}
		}
	}
}
