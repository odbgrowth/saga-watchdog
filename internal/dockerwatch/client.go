package dockerwatch

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrMissing = errors.New("configured container no longer exists; select its replacement explicitly")

// Client deliberately exposes only reads of selected containers and events. A
// Docker socket still grants administrative access at the OS permission level.
type Client struct {
	http    *http.Client
	base    string
	timeout time.Duration
}

func NewClient(socket string, timeout time.Duration) *Client {
	t := &http.Transport{ResponseHeaderTimeout: timeout, MaxIdleConnsPerHost: 32,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", socket)
		}}
	return &Client{http: &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Docker API redirects are not allowed") }}, base: "http://docker", timeout: timeout}
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(req.URL.Path, "/events") {
		req.Header.Set("Accept", "application/x-ndjson")
	}
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusOK {
		r.Body.Close()
		if r.StatusCode == http.StatusNotFound {
			return nil, ErrMissing
		}
		// Never copy Docker error bodies: they may contain application details.
		return nil, fmt.Errorf("Docker API returned HTTP %d", r.StatusCode)
	}
	return r, nil
}

func (c *Client) read(ctx context.Context, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	r, err := c.get(ctx, path)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024+1))
	if err != nil {
		return err
	}
	if len(b) > 4*1024*1024 {
		return errors.New("Docker response exceeds 4 MiB")
	}
	if err := json.Unmarshal(b, out); err != nil {
		return errors.New("invalid Docker JSON response")
	}
	return nil
}

// Use the daemon's supported API range, capped at the schema reviewed here.
// one-shot stats need >= 1.41. A future incompatible minimum fails explicitly.
func (c *Client) Version(ctx context.Context) (string, error) {
	var v struct {
		API string `json:"ApiVersion"`
		Min string `json:"MinAPIVersion"`
	}
	if err := c.read(ctx, "/version", &v); err != nil {
		return "", err
	}
	parse := func(s string) (int, error) {
		parts := strings.Split(s, ".")
		if len(parts) != 2 || parts[0] != "1" || len(parts[1]) > 3 {
			return 0, errors.New("unsupported Docker API version")
		}
		n, err := strconv.Atoi(parts[1])
		return n, err
	}
	max, err := parse(v.API)
	if err != nil {
		return "", err
	}
	min := 0
	if v.Min != "" {
		min, err = parse(v.Min)
		if err != nil {
			return "", err
		}
	}
	if max < 41 || min > 56 || min > max {
		return "", errors.New("Docker API range does not overlap supported versions 1.41-1.56")
	}
	if max > 56 {
		max = 56
	}
	return fmt.Sprintf("/v1.%d", max), nil
}

type Inspection struct {
	ID           string `json:"Id"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Status    string `json:"Status"`
		OOMKilled bool   `json:"OOMKilled"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
}

func (c *Client) Inspect(ctx context.Context, api, id string) (Inspection, error) {
	var v Inspection
	if !fullID.MatchString(id) {
		return v, errors.New("full container ID required")
	}
	err := c.read(ctx, api+"/containers/"+id+"/json", &v)
	if err == nil && v.ID != id {
		err = errors.New("Docker returned a different container identity")
	}
	return v, err
}

type CPU struct {
	Usage struct {
		Total  uint64   `json:"total_usage"`
		PerCPU []uint64 `json:"percpu_usage"`
	} `json:"cpu_usage"`
	System uint64 `json:"system_cpu_usage"`
	Online uint64 `json:"online_cpus"`
}
type Stats struct {
	ID     string    `json:"id"`
	Read   time.Time `json:"read"`
	CPU    CPU       `json:"cpu_stats"`
	Memory struct {
		Usage uint64 `json:"usage"`
		Limit uint64 `json:"limit"`
	} `json:"memory_stats"`
}

func (c *Client) Stats(ctx context.Context, api, id string) (Stats, error) {
	var s Stats
	if !fullID.MatchString(id) {
		return s, errors.New("full container ID required")
	}
	err := c.read(ctx, api+"/containers/"+id+"/stats?stream=false&one-shot=true", &s)
	// Older daemons omit id/name on the one-shot path (for example Moby
	// v28.0.4 daemon/stats.go). The endpoint still contains the full ID and
	// Inspect verified it first. An explicit conflicting ID is never accepted.
	if err == nil && s.ID != "" && s.ID != id {
		err = errors.New("Docker stats returned a different container identity")
	}
	if err == nil && s.Read.IsZero() {
		err = errors.New("Docker returned no resource sample; container may have stopped between requests")
	}
	return s, err
}

type DockerEvent struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID string `json:"ID"`
	} `json:"Actor"`
}

func (c *Client) Events(ctx context.Context, api string, ids []string, connected func(), receive func(DockerEvent) error) error {
	allowed := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !fullID.MatchString(id) {
			return errors.New("full container ID required")
		}
		allowed[id] = true
	}
	if len(ids) == 0 {
		return errors.New("event stream requires selected containers")
	}
	filter, _ := json.Marshal(map[string][]string{"type": {"container"}, "container": ids})
	r, err := c.get(ctx, api+"/events?"+url.Values{"filters": {string(filter)}}.Encode())
	if err != nil {
		return err
	}
	defer r.Body.Close()
	connected()
	s := bufio.NewScanner(r.Body)
	s.Buffer(make([]byte, 4096), 64*1024)
	for s.Scan() {
		var e DockerEvent
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			return errors.New("invalid Docker event JSON")
		}
		if e.Type != "container" || !allowed[e.Actor.ID] {
			continue
		}
		switch e.Action {
		case "start", "stop", "die", "restart", "destroy", "kill", "oom", "pause", "unpause", "health_status: healthy", "health_status: unhealthy", "health_status: starting":
			if err := receive(e); err != nil {
				return err
			}
		}
	}
	if err := s.Err(); err != nil {
		return err
	}
	return errors.New("Docker event stream ended; events may be missing until reconnection")
}
