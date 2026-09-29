package dockerwatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fixtureClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("mutation request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(405)
			return
		}
		h(w, r)
	}))
	t.Cleanup(s.Close)
	return &Client{http: s.Client(), base: s.URL, timeout: time.Second}
}

func TestVersionNegotiation(t *testing.T) {
	for _, tc := range []struct{ max, min, want string }{{"1.56", "1.44", "/v1.56"}, {"1.99", "1.44", "/v1.56"}, {"1.41", "1.24", "/v1.41"}, {"1.40", "1.24", ""}, {"1.99", "1.57", ""}, {"garbage", "", ""}, {"1.50", "1.51", ""}} {
		t.Run(tc.max+"-"+tc.min, func(t *testing.T) {
			c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/version" {
					t.Error(r.URL.Path)
				}
				fmt.Fprintf(w, `{"ApiVersion":%q,"MinAPIVersion":%q}`, tc.max, tc.min)
			})
			got, err := c.Version(context.Background())
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestSelectedIdentityAndResponseBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       error
	}{
		{"identity", `{"Id":"` + otherID + `"}`, 200, nil},
		{"missing", "", 404, ErrMissing},
		{"daemon-error", `{"message":"token=secret-never-copy"}`, 500, nil},
		{"malformed", `{"broken"`, 200, nil},
		{"oversized", strings.Repeat("x", 4*1024*1024+1), 200, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1.56/containers/"+testID+"/json" {
					t.Error(r.URL.Path)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			_, err := c.Inspect(context.Background(), "/v1.56", testID)
			if err == nil || strings.Contains(err.Error(), "secret-never-copy") {
				t.Fatalf("unsafe error: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		})
	}
}

func TestEventsFilterAndDiscardUnselectedOrSecretFields(t *testing.T) {
	c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.56/events" {
			t.Error(r.URL.Path)
		}
		var filter map[string][]string
		if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filter); err != nil {
			t.Error(err)
		}
		if len(filter["container"]) != 1 || filter["container"][0] != testID || filter["type"][0] != "container" {
			t.Error(filter)
		}
		fmt.Fprintf(w, "{\"Type\":\"container\",\"Action\":\"oom\",\"Actor\":{\"ID\":%q}}\n", otherID)
		fmt.Fprintf(w, "{\"Type\":\"container\",\"Action\":\"exec_start: command-with-secret\",\"Actor\":{\"ID\":%q}}\n", testID)
		fmt.Fprintf(w, "{\"Type\":\"container\",\"Action\":\"oom\",\"Actor\":{\"ID\":%q,\"Attributes\":{\"secret\":\"do-not-log\"}}}\n", testID)
	})
	var got []DockerEvent
	connected := false
	err := c.Events(context.Background(), "/v1.56", []string{testID}, func() { connected = true }, func(e DockerEvent) error { got = append(got, e); return nil })
	if err == nil || !connected || len(got) != 1 || got[0].Action != "oom" {
		t.Fatalf("%v %v %+v", err, connected, got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "do-not-log") {
		t.Fatal("attributes retained")
	}
}

func TestProductionTransportRefusesRedirects(t *testing.T) {
	c := NewClient("/unused.sock", time.Second)
	defer c.Close()
	if c.http.CheckRedirect(&http.Request{}, nil) == nil {
		t.Fatal("redirect would be followed")
	}
}
