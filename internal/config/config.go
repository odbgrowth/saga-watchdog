// Package config loads a small, strictly validated per-project policy.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const Filename = ".saga-watchdog.yaml"
const DefaultYAML = "version: 1\nprofile: coding-agent\nmode: enforce\n"

type Config struct {
	Version    int        `yaml:"version"`
	Profile    string     `yaml:"profile"`
	Mode       string     `yaml:"mode"`
	Project    Project    `yaml:"project"`
	Run        Run        `yaml:"run"`
	Git        Git        `yaml:"git"`
	Filesystem Filesystem `yaml:"filesystem"`
	Escalation Escalation `yaml:"escalation"`
	Network    Network    `yaml:"network"`
}

type Project struct {
	Name string `yaml:"name"`
}
type Run struct {
	MaxDuration     time.Duration `yaml:"max_duration"`
	StopGracePeriod time.Duration `yaml:"stop_grace_period"`
}
type Git struct {
	ProtectedBranches []string `yaml:"protected_branches"`
	AllowProtected    bool     `yaml:"allow_protected"`
}
type Filesystem struct {
	Protect         []string      `yaml:"protect"`
	Ignore          []string      `yaml:"ignore"`
	DeleteThreshold int           `yaml:"delete_threshold"`
	DeleteWindow    time.Duration `yaml:"delete_window"`
}
type Escalation struct {
	Window     time.Duration `yaml:"window"`
	WarnAfter  int           `yaml:"warn_after"`
	PauseAfter int           `yaml:"pause_after"`
	KillAfter  int           `yaml:"kill_after"`
}
type Network struct {
	Deny []string `yaml:"deny"`
}

// Default returns fresh slices so one project's overrides cannot change another.
func Default() Config {
	return Config{
		Version: 1, Profile: "coding-agent", Mode: "enforce",
		Run: Run{MaxDuration: 2 * time.Hour, StopGracePeriod: 5 * time.Second},
		Git: Git{ProtectedBranches: []string{"main", "master"}},
		Filesystem: Filesystem{
			Protect:         []string{Filename, ".git/config", ".git/hooks/**", ".github/workflows/**", "**/.env", "**/.env.*", "**/credentials*", "**/secrets*", "**/*.pem", "**/*.key"},
			Ignore:          []string{"**/node_modules/**", "**/vendor/**", ".git/objects/**", "**/dist/**", "**/build/**"},
			DeleteThreshold: 100, DeleteWindow: 10 * time.Second,
		},
		Escalation: Escalation{Window: 120 * time.Second, WarnAfter: 2, PauseAfter: 3, KillAfter: 5},
	}
}

func Load(filename string) (Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return Config{}, fmt.Errorf("open policy %s: %w", filename, err)
	}
	defer f.Close()
	return Parse(io.LimitReader(f, 64*1024+1))
}

// Parse accepts exactly one mapping document, with no unknown fields, duplicate
// keys, aliases, or null values. Bounded input prevents accidental huge policies.
func Parse(r io.Reader) (Config, error) {
	cfg := Default()
	if err := DecodeStrict(r, &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// DecodeStrict shares the bounded YAML syntax rules across the separate CLI and
// service configurations. Each caller validates its own schema and defaults.
func DecodeStrict(r io.Reader, target any) error {
	data, err := io.ReadAll(io.LimitReader(r, 64*1024+1))
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	if len(data) > 64*1024 {
		return errors.New("policy exceeds 64 KiB")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse policy YAML: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("policy must be a non-empty YAML mapping")
	}
	if err := validateNode(&doc); err != nil {
		return err
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("parse policy YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("policy must contain exactly one YAML document")
	}
	return nil
}

func validateNode(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Tag == "!!null" {
		return fmt.Errorf("policy line %d: aliases and null values are not supported", n.Line)
	}
	for _, child := range n.Content {
		if err := validateNode(child); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) Validate() error {
	if c.Version != 1 {
		return errors.New("version must be 1")
	}
	if c.Profile != "coding-agent" {
		return errors.New("profile must be coding-agent")
	}
	if c.Mode != "observe" && c.Mode != "enforce" {
		return errors.New("mode must be observe or enforce")
	}
	if len(c.Project.Name) > 128 || strings.ContainsAny(c.Project.Name, "\x00\r\n") {
		return errors.New("project.name must be at most 128 bytes without control characters")
	}
	if c.Run.MaxDuration <= 0 || c.Run.MaxDuration > 7*24*time.Hour {
		return errors.New("run.max_duration must be greater than 0 and at most 168h")
	}
	if c.Run.StopGracePeriod <= 0 || c.Run.StopGracePeriod > time.Minute {
		return errors.New("run.stop_grace_period must be greater than 0 and at most 1m")
	}
	if c.Filesystem.DeleteWindow <= 0 || c.Filesystem.DeleteWindow > time.Hour {
		return errors.New("filesystem.delete_window must be greater than 0 and at most 1h")
	}
	if c.Filesystem.DeleteThreshold < 1 || c.Filesystem.DeleteThreshold > 100000 {
		return errors.New("filesystem.delete_threshold must be between 1 and 100000")
	}
	if c.Escalation.Window <= 0 || c.Escalation.Window > time.Hour {
		return errors.New("escalation.window must be greater than 0 and at most 1h")
	}
	if c.Escalation.WarnAfter < 2 || c.Escalation.PauseAfter <= c.Escalation.WarnAfter || c.Escalation.KillAfter <= c.Escalation.PauseAfter || c.Escalation.KillAfter > 100000 {
		return errors.New("escalation thresholds must satisfy 2 <= warn_after < pause_after < kill_after <= 100000")
	}
	for field, patterns := range map[string][]string{"filesystem.protect": c.Filesystem.Protect, "filesystem.ignore": c.Filesystem.Ignore} {
		if len(patterns) > 256 {
			return fmt.Errorf("%s supports at most 256 patterns", field)
		}
		for _, pattern := range patterns {
			if err := validPattern(pattern); err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
		}
	}
	for _, branch := range c.Git.ProtectedBranches {
		if len(branch) > 256 {
			return errors.New("git.protected_branches patterns must be at most 256 bytes")
		}
		if err := validPattern(branch); err != nil {
			return fmt.Errorf("git.protected_branches: %w", err)
		}
	}
	if len(c.Network.Deny) > 256 {
		return errors.New("network.deny supports at most 256 hostnames")
	}
	for _, host := range c.Network.Deny {
		if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\*?@:#\r\n\t") {
			return errors.New("network.deny must contain exact hostnames without ports, URL schemes, or wildcards")
		}
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return errors.New("network.deny contains an invalid hostname label")
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' {
					return errors.New("network.deny hostnames must use ASCII letters, digits and hyphens (use punycode for international names)")
				}
			}
		}
	}
	return nil
}

func validPattern(pattern string) error {
	if pattern == "" || len(pattern) > 1024 || strings.HasPrefix(pattern, "/") || strings.ContainsAny(pattern, "\\:\x00\r\n") {
		return fmt.Errorf("invalid project-relative glob %q", pattern)
	}
	for _, segment := range strings.Split(pattern, "/") {
		if segment == ".." || segment == "." || segment == "" {
			return fmt.Errorf("glob %q contains an empty or traversal segment", pattern)
		}
		if segment == "**" {
			continue
		}
		if _, err := path.Match(segment, "test"); err != nil {
			return fmt.Errorf("invalid glob %q: %w", pattern, err)
		}
	}
	return nil
}
