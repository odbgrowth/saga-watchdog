// Package dockerwatch observes explicitly selected existing containers. It does
// not own their lifecycle and never sends Docker mutation requests.
package dockerwatch

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/config"
)

type Target struct {
	Name string `yaml:"name" json:"name"`
	ID   string `yaml:"container_id" json:"container_id"`
}

type Config struct {
	Version        int           `yaml:"version"`
	Mode           string        `yaml:"mode"`
	Socket         string        `yaml:"socket"`
	StateDir       string        `yaml:"state_dir"`
	PollInterval   time.Duration `yaml:"poll_interval"`
	RequestTimeout time.Duration `yaml:"request_timeout"`
	Targets        []Target      `yaml:"targets"`
}

var fullID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var targetName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func Parse(r io.Reader) (Config, error) {
	c := Config{Socket: "/var/run/docker.sock", PollInterval: 10 * time.Second, RequestTimeout: 5 * time.Second}
	if err := config.DecodeStrict(r, &c); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func Load(path string) (Config, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Config{}, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0) {
		return Config{}, errors.New("Docker config must be a regular file, not writable by group or others")
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	return Parse(f)
}

func (c Config) Validate() error {
	if c.Version != 1 || c.Mode != "observe" {
		return errors.New("Docker config requires version: 1 and mode: observe; enforcement is not supported")
	}
	if !filepath.IsAbs(c.Socket) || !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) == string(filepath.Separator) {
		return errors.New("socket and state_dir must be absolute paths; state_dir must be a dedicated directory")
	}
	if c.PollInterval < time.Second || c.PollInterval > time.Minute {
		return errors.New("poll_interval must be between 1s and 1m")
	}
	if c.RequestTimeout < time.Second || c.RequestTimeout > 30*time.Second {
		return errors.New("request_timeout must be between 1s and 30s")
	}
	if len(c.Targets) == 0 || len(c.Targets) > 32 {
		return errors.New("configure between 1 and 32 targets")
	}
	names, ids := map[string]bool{}, map[string]bool{}
	for _, t := range c.Targets {
		if !targetName.MatchString(t.Name) || !fullID.MatchString(t.ID) {
			return errors.New("each target needs a simple name (1-64 letters/digits/._-) and a full lowercase 64-character container ID")
		}
		if names[t.Name] || ids[t.ID] {
			return fmt.Errorf("duplicate target name or container ID: %s", t.Name)
		}
		names[t.Name], ids[t.ID] = true, true
	}
	return nil
}
